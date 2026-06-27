import { describe, expect, it } from "vitest";
import {
  StateStore,
  type StateEntry,
} from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { hmacSha256 } from "../../src/core/hashing.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";

const STATE_EXPORT_BUNDLE_MAC_PURPOSE = "state-export-bundle-mac-v1";
const STATE_EXPORT_BUNDLE_MAC_DOMAIN = "sanctuary.state-export-bundle.v1\n";
const STATE_EXPORT_BUNDLE_MAC_COVERAGE =
  "sanctuary-v1-body-and-completeness-manifest";
const LEGACY_REJECT_MESSAGE =
  "export predates completeness verification; re-export, or re-run with allow_unverified_legacy to import without completeness guarantees";

interface TestBundle {
  sanctuary_export_version?: number;
  format?: string;
  exported_at?: string;
  namespaces?: string[];
  data: Record<string, Array<{ key: string; entry: StateEntry }>>;
  completeness_manifest?: {
    schema_version: number;
    format: string;
    exported_at: string;
    namespaces: string[];
    namespace_count: number;
    total_keys: number;
    namespace_items: Record<
      string,
      { item_count: number; content_sha256: string }
    >;
  };
  bundle_integrity?: Record<string, unknown>;
  facade_hidden_markers?: unknown;
}

function decodeBundle(bundleBase64: string): TestBundle {
  return JSON.parse(bytesToString(fromBase64url(bundleBase64))) as TestBundle;
}

function encodeBundle(bundle: TestBundle): string {
  return toBase64url(stringToBytes(JSON.stringify(bundle)));
}

function stripCurrentCompleteness(bundle: TestBundle): TestBundle {
  delete bundle.completeness_manifest;
  delete bundle.bundle_integrity;
  return bundle;
}

function stripToLegacyBundle(bundle: TestBundle): TestBundle {
  stripCurrentCompleteness(bundle);
  delete bundle.format;
  delete bundle.sanctuary_export_version;
  return bundle;
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }

  const record = value as Record<string, unknown>;
  const canonical: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    const item = record[key];
    if (item !== undefined) {
      canonical[key] = canonicalize(item);
    }
  }
  return canonical;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function createBundleIntegrity(
  bundle: TestBundle,
  masterKey: Uint8Array
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    sanctuary_export_version: bundle.sanctuary_export_version,
    format: bundle.format,
    exported_at: bundle.exported_at,
    namespaces: bundle.namespaces,
    data: bundle.data,
    completeness_manifest: bundle.completeness_manifest,
  };
  if (bundle.facade_hidden_markers !== undefined) {
    payload.facade_hidden_markers = bundle.facade_hidden_markers;
  }
  const mac = hmacSha256(
    derivePurposeKey(masterKey, STATE_EXPORT_BUNDLE_MAC_PURPOSE),
    stringToBytes(STATE_EXPORT_BUNDLE_MAC_DOMAIN + canonicalJson(payload))
  );

  return {
    schema_version: 1,
    algo: "HMAC-SHA256",
    coverage: STATE_EXPORT_BUNDLE_MAC_COVERAGE,
    mac: toBase64url(mac),
  };
}

function createFixture() {
  const masterKey = generateRandomKey();
  const storage = new MemoryStorage();
  const stateStore = new StateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const identity = createIdentity(
    "manifest-test",
    identityEncKey,
    "recovery-key"
  );
  const publicKey = fromBase64url(identity.storedIdentity.public_key);
  const resolver = (kid: string): Uint8Array | null =>
    kid === identity.storedIdentity.identity_id ? publicKey : null;

  return {
    masterKey,
    storage,
    stateStore,
    identity,
    identityEncKey,
    publicKey,
    resolver,
  };
}

async function writeEntry(
  stateStore: StateStore,
  identity: ReturnType<typeof createIdentity>,
  identityEncKey: Uint8Array,
  namespace: string,
  key: string,
  value: string
) {
  await stateStore.write(
    namespace,
    key,
    value,
    identity.storedIdentity.identity_id,
    identity.storedIdentity.encrypted_private_key,
    identityEncKey
  );
}

describe("state export completeness manifest", () => {
  it("exports a manifest and verifies it before round-trip import", async () => {
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "a",
      "alpha"
    );
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "b",
      "bravo"
    );
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "tasks",
      "c",
      "charlie"
    );

    const exported = await fixture.stateStore.exportNamespaces([
      "notes",
      "tasks",
    ]);
    const decoded = decodeBundle(exported.bundle);

    expect(decoded.completeness_manifest).toBeDefined();
    expect(decoded.bundle_integrity).toBeDefined();
    expect(decoded.completeness_manifest).toEqual(
      exported.completeness_manifest
    );
    expect(decoded.completeness_manifest?.schema_version).toBe(1);
    expect(decoded.completeness_manifest?.format).toBe("sanctuary-v1");
    expect(decoded.completeness_manifest?.exported_at).toBe(
      exported.exported_at
    );
    expect(decoded.completeness_manifest?.namespaces).toEqual([
      "notes",
      "tasks",
    ]);
    expect(decoded.completeness_manifest?.namespace_count).toBe(2);
    expect(decoded.completeness_manifest?.total_keys).toBe(3);
    expect(
      decoded.completeness_manifest?.namespace_items["notes"]?.item_count
    ).toBe(2);
    expect(
      decoded.completeness_manifest?.namespace_items["tasks"]?.item_count
    ).toBe(1);

    const freshStore = new StateStore(new MemoryStorage(), fixture.masterKey);
    const imported = await freshStore.import(
      exported.bundle,
      "skip",
      fixture.resolver
    );
    expect(imported.imported_keys).toBe(3);
    expect(imported.completeness_verification).toBe("verified");

    const readBack = await freshStore.read("notes", "a", fixture.publicKey);
    expect(readBack?.value).toBe("alpha");
  });

  it("rejects item tampering before any import write", async () => {
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "a",
      "alpha"
    );
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "b",
      "bravo"
    );

    const exported = await fixture.stateStore.exportNamespaces(["notes"]);
    const decoded = decodeBundle(exported.bundle);
    const ct = decoded.data["notes"]![0]!.entry.payload.ct;
    decoded.data["notes"]![0]!.entry.payload.ct =
      (ct[0] === "A" ? "B" : "A") + ct.slice(1);

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, fixture.masterKey);
    await expect(
      freshStore.import(encodeBundle(decoded), "skip", fixture.resolver)
    ).rejects.toThrow("State export bundle failed integrity verification");
    await expect(freshStorage.list("notes")).resolves.toHaveLength(0);
  });

  it("rejects a dropped namespace before any import write", async () => {
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "a",
      "alpha"
    );
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "tasks",
      "b",
      "bravo"
    );

    const exported = await fixture.stateStore.exportNamespaces([
      "notes",
      "tasks",
    ]);
    const decoded = decodeBundle(exported.bundle);
    delete decoded.data["tasks"];
    decoded.namespaces = ["notes"];

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, fixture.masterKey);
    await expect(
      freshStore.import(encodeBundle(decoded), "skip", fixture.resolver)
    ).rejects.toThrow("State export bundle failed integrity verification");
    await expect(freshStorage.list("notes")).resolves.toHaveLength(0);
    await expect(freshStorage.list("tasks")).resolves.toHaveLength(0);
  });

  it("rejects a wrong manifest count before any import write", async () => {
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "a",
      "alpha"
    );

    const exported = await fixture.stateStore.exportNamespaces(["notes"]);
    const decoded = decodeBundle(exported.bundle);
    decoded.completeness_manifest!.namespace_items["notes"]!.item_count = 2;

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, fixture.masterKey);
    await expect(
      freshStore.import(encodeBundle(decoded), "skip", fixture.resolver)
    ).rejects.toThrow("State export bundle failed integrity verification");
    await expect(freshStorage.list("notes")).resolves.toHaveLength(0);
  });

  it("rejects current bundles with completeness fields stripped unless explicitly importing unverified legacy", async () => {
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "a",
      "alpha"
    );

    const exported = await fixture.stateStore.exportNamespaces(["notes"]);
    const downgradedBundle = encodeBundle(
      stripCurrentCompleteness(decodeBundle(exported.bundle))
    );

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, fixture.masterKey);
    await expect(
      freshStore.import(downgradedBundle, "skip", fixture.resolver)
    ).rejects.toThrow(LEGACY_REJECT_MESSAGE);
    await expect(freshStorage.list("notes")).resolves.toHaveLength(0);

    const imported = await freshStore.import(
      downgradedBundle,
      "skip",
      fixture.resolver,
      { allowUnverifiedLegacy: true }
    );
    expect(imported.imported_keys).toBe(1);
    expect(imported.completeness_verification).toBe(
      "unverified-completeness-legacy-bundle"
    );
    expect(imported.completeness_verification).not.toBe("verified");
  });

  it("rejects genuine legacy bundles by default and imports them only with explicit unverified opt-in", async () => {
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "a",
      "alpha"
    );

    const exported = await fixture.stateStore.exportNamespaces(["notes"]);
    const legacyBundle = encodeBundle(
      stripToLegacyBundle(decodeBundle(exported.bundle))
    );

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, fixture.masterKey);
    await expect(
      freshStore.import(legacyBundle, "skip", fixture.resolver)
    ).rejects.toThrow(LEGACY_REJECT_MESSAGE);
    await expect(freshStorage.list("notes")).resolves.toHaveLength(0);

    const imported = await freshStore.import(
      legacyBundle,
      "skip",
      fixture.resolver,
      { allowUnverifiedLegacy: true }
    );
    expect(imported.imported_keys).toBe(1);
    expect(imported.completeness_verification).toBe(
      "unverified-completeness-legacy-bundle"
    );
  });

  it("rejects a MAC-valid current bundle with a malformed exported_at timestamp", async () => {
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "a",
      "alpha"
    );

    const exported = await fixture.stateStore.exportNamespaces(["notes"]);
    const decoded = decodeBundle(exported.bundle);
    decoded.exported_at = "not-a-timestamp";
    decoded.completeness_manifest!.exported_at = "not-a-timestamp";
    decoded.bundle_integrity = createBundleIntegrity(
      decoded,
      fixture.masterKey
    );

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, fixture.masterKey);
    await expect(
      freshStore.import(encodeBundle(decoded), "skip", fixture.resolver)
    ).rejects.toThrow("State export bundle exported_at timestamp is malformed");
    await expect(freshStorage.list("notes")).resolves.toHaveLength(0);
  });

  it("rejects newer manifest schema versions fail closed", async () => {
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "a",
      "alpha"
    );

    const exported = await fixture.stateStore.exportNamespaces(["notes"]);
    const decoded = decodeBundle(exported.bundle);
    decoded.completeness_manifest!.schema_version = 2;

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, fixture.masterKey);
    await expect(
      freshStore.import(encodeBundle(decoded), "skip", fixture.resolver)
    ).rejects.toThrow(
      "State export bundle completeness schema version is newer than this build supports"
    );
    await expect(freshStorage.list("notes")).resolves.toHaveLength(0);
  });

  it("does not return decrypted user data in export, import, or errors", async () => {
    const secretValue = "portable-secret-value";
    const fixture = createFixture();
    await writeEntry(
      fixture.stateStore,
      fixture.identity,
      fixture.identityEncKey,
      "notes",
      "secret",
      secretValue
    );

    const exported = await fixture.stateStore.exportNamespaces(["notes"]);
    expect(JSON.stringify(exported)).not.toContain(secretValue);
    expect(bytesToString(fromBase64url(exported.bundle))).not.toContain(
      secretValue
    );

    const freshStore = new StateStore(new MemoryStorage(), fixture.masterKey);
    const imported = await freshStore.import(
      exported.bundle,
      "skip",
      fixture.resolver
    );
    expect(JSON.stringify(imported)).not.toContain(secretValue);

    const decoded = decodeBundle(exported.bundle);
    decoded.data["notes"]![0]!.entry.integrity_hash = "tampered";
    let message = "";
    try {
      await freshStore.import(encodeBundle(decoded), "skip", fixture.resolver);
    } catch (error) {
      message = String(error);
    }
    expect(message).not.toContain(secretValue);
  });
});
