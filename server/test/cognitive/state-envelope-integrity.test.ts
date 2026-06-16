import { describe, expect, it } from "vitest";
import { encrypt } from "../../src/core/encryption.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { createIdentity, sign } from "../../src/core/identity.js";
import { hashToString } from "../../src/core/hashing.js";
import { deriveNamespaceKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  StateStore,
  StateVerificationError,
  type StateEntry,
} from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";

type ToolResult = { content: Array<{ type: string; text: string }> };
type Tool = {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<ToolResult>;
};

async function callTool(
  tools: Tool[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

function makeStateRig() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const identity = createIdentity("writer", identityEncKey, "recovery-key");
  const stateStore = new StateStore(storage, masterKey);

  return { storage, masterKey, identityEncKey, identity, stateStore };
}

async function readEntry(
  storage: MemoryStorage,
  namespace: string,
  key: string
): Promise<StateEntry> {
  const raw = await storage.read(namespace, key);
  if (!raw) throw new Error(`missing state entry: ${namespace}/${key}`);
  return JSON.parse(bytesToString(raw)) as StateEntry;
}

async function writeEntry(
  storage: MemoryStorage,
  namespace: string,
  key: string,
  entry: StateEntry
): Promise<void> {
  await storage.write(namespace, key, stringToBytes(JSON.stringify(entry)));
}

async function writeLegacyEntry(args: {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  identity: ReturnType<typeof createIdentity>;
  identityEncKey: Uint8Array;
  namespace: string;
  key: string;
  value: string;
  ver?: number;
}): Promise<void> {
  const plaintext = stringToBytes(args.value);
  const payload = encrypt(
    plaintext,
    deriveNamespaceKey(args.masterKey, args.namespace)
  );
  const signature = sign(
    fromBase64url(payload.ct),
    args.identity.storedIdentity.encrypted_private_key,
    args.identityEncKey
  );
  const now = new Date().toISOString();
  const entry: StateEntry = {
    v: 1,
    payload,
    ver: args.ver ?? 1,
    sig: toBase64url(signature),
    kid: args.identity.storedIdentity.identity_id,
    integrity_hash: hashToString(plaintext),
    metadata: {
      written_at: now,
    },
  };

  await writeEntry(args.storage, args.namespace, args.key, entry);
}

describe("state envelope integrity", () => {
  it("round trips with default envelope verification", async () => {
    const { stateStore, identity, identityEncKey } = makeStateRig();

    await stateStore.write(
      "memory",
      "profile",
      "trusted value",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    const read = await stateStore.read("memory", "profile");

    expect(read?.value).toBe("trusted value");
    expect(read?.version).toBe(1);
    expect(read?.signature_verified).toBe(true);
  });

  it("detects namespace metadata tampering after write", async () => {
    const { storage, masterKey, stateStore, identity, identityEncKey } = makeStateRig();

    await stateStore.write(
      "memory",
      "profile",
      "trusted value",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    const entry = await readEntry(storage, "memory", "profile");
    entry.envelope!.namespace = "memory-tampered";
    await writeEntry(storage, "memory", "profile", entry);

    const freshStore = new StateStore(storage, masterKey);
    await expect(freshStore.read("memory", "profile")).rejects.toMatchObject({
      name: "StateVerificationError",
      classification: "schema_mismatch",
    } satisfies Partial<StateVerificationError>);
  });

  it("detects version rollback after restart", async () => {
    const { storage, masterKey, stateStore, identity, identityEncKey } = makeStateRig();

    await stateStore.write(
      "memory",
      "profile",
      "v1",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    const versionOne = await storage.read("memory", "profile");

    await stateStore.write(
      "memory",
      "profile",
      "v2",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    await storage.write("memory", "profile", versionOne!);

    const freshStore = new StateStore(storage, masterKey);
    await expect(freshStore.read("memory", "profile")).rejects.toMatchObject({
      name: "StateVerificationError",
      classification: "rollback_detected",
    } satisfies Partial<StateVerificationError>);
  });

  it("detects a wrong public key for the writer kid", async () => {
    const { storage, masterKey, stateStore, identity, identityEncKey } = makeStateRig();
    const otherIdentity = createIdentity("other", identityEncKey, "recovery-key");

    await stateStore.write(
      "memory",
      "profile",
      "trusted value",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    await storage.write(
      "_meta",
      "state-envelope-public-keys-v1",
      stringToBytes(
        JSON.stringify({
          [identity.storedIdentity.identity_id]: otherIdentity.publicIdentity.public_key,
        })
      )
    );

    const freshStore = new StateStore(storage, masterKey);
    await expect(freshStore.read("memory", "profile")).rejects.toMatchObject({
      name: "StateVerificationError",
      classification: "signature_mismatch",
    } satisfies Partial<StateVerificationError>);
  });

  it("loads legacy schema-1 entries with a warning", async () => {
    const { storage, masterKey, identity, identityEncKey } = makeStateRig();
    await writeLegacyEntry({
      storage,
      masterKey,
      identity,
      identityEncKey,
      namespace: "legacy",
      key: "k",
      value: "legacy value",
    });

    const freshStore = new StateStore(storage, masterKey);
    const read = await freshStore.read("legacy", "k");

    expect(read?.value).toBe("legacy value");
    expect(read?.signature_verified).toBe(false);
    expect(read?.warnings?.[0]?.name).toBe("LegacyEnvelopeWarning");
  });

  it("state_read returns an error on verification failure", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new StateStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog
    );
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", { label: "writer" });

    await callTool(tools, "state_write", {
      namespace: "memory",
      key: "profile",
      value: "trusted value",
      identity_id: identity.identity_id,
    });

    const entry = await readEntry(storage, "memory", "profile");
    entry.envelope!.key = "profile-tampered";
    await writeEntry(storage, "memory", "profile", entry);

    const read = await callTool(tools, "state_read", {
      namespace: "memory",
      key: "profile",
    });

    expect(read.error).toBe("state_verification_failed");
    expect(read.classification).toBe("schema_mismatch");
  });

  it("rejects a legacy (v1) entry that leapfrogs an established anchor (F1)", async () => {
    const { storage, masterKey, stateStore, identity, identityEncKey } = makeStateRig();

    // Establish an anchor with a genuine v2 write.
    await stateStore.write(
      "memory",
      "balance",
      "current-v2",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    await stateStore.read("memory", "balance"); // persists the version anchor

    // Forge a v1 entry replaying OLD state at a version ABOVE the anchor. Its
    // legacy signature covers only the ciphertext, so the signature check would
    // pass — the version-anchor guard is what must catch it.
    await writeLegacyEntry({
      storage,
      masterKey,
      identity,
      identityEncKey,
      namespace: "memory",
      key: "balance",
      value: "OLD-SECRET",
      ver: 11,
    });

    const freshStore = new StateStore(storage, masterKey);
    await expect(freshStore.read("memory", "balance")).rejects.toMatchObject({
      name: "StateVerificationError",
      classification: "rollback_detected",
    } satisfies Partial<StateVerificationError>);
  });

  it("still re-reads a genuine legacy (v1) entry at its own anchor (no over-rejection)", async () => {
    const { storage, masterKey, identity, identityEncKey } = makeStateRig();
    await writeLegacyEntry({
      storage,
      masterKey,
      identity,
      identityEncKey,
      namespace: "legacy",
      key: "k",
      value: "legacy value",
    });

    // First read establishes the anchor at the v1 entry's own version (1).
    const first = await new StateStore(storage, masterKey).read("legacy", "k");
    expect(first?.value).toBe("legacy value");

    // A subsequent read with the anchor now set (== the entry's version) must
    // still succeed — the F1 guard only rejects a v1 entry ABOVE the anchor.
    const second = await new StateStore(storage, masterKey).read("legacy", "k");
    expect(second?.value).toBe("legacy value");
  });

  it("rejects an in-place LOWERING of the MAC-authenticated version anchor (F1)", async () => {
    const { storage, masterKey, stateStore, identity, identityEncKey } = makeStateRig();
    // Two v2 writes -> balance at version 2, MAC'd anchor = 2.
    await stateStore.write(
      "memory",
      "balance",
      "v2-a",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    await stateStore.write(
      "memory",
      "balance",
      "v2-b",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    await stateStore.read("memory", "balance"); // persists the MAC'd anchor (=2)

    // Filesystem adversary edits the anchor IN PLACE to lower the floor (so an
    // older entry could later read as "current"), keeping the now-stale MAC.
    const anchorsKey = "state-envelope-version-anchors-v1";
    const obj = JSON.parse(
      bytesToString((await storage.read("_meta", anchorsKey))!)
    ) as { __sanctuary_meta_mac_v1: boolean; data: Record<string, number>; mac: string };
    obj.data["memory/balance"] = 1; // lower the floor; the stored MAC is now stale
    await storage.write("_meta", anchorsKey, stringToBytes(JSON.stringify(obj)));

    // The edit is detected on load (recomputed MAC over the new data != stored MAC).
    const freshStore = new StateStore(storage, masterKey);
    await expect(freshStore.read("memory", "balance")).rejects.toMatchObject({
      name: "StateVerificationError",
      classification: "integrity_hash_mismatch",
    } satisfies Partial<StateVerificationError>);
  });

  it("ignores a marker-stripped version-anchor record — its bogus floor is not trusted (F1)", async () => {
    const { storage, masterKey, identity, identityEncKey } = makeStateRig();
    const seed = new StateStore(storage, masterKey);
    // Existing key at version 2.
    await seed.write(
      "memory",
      "balance",
      "v2-a",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    await seed.write(
      "memory",
      "balance",
      "v2-b",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    // Attacker strips the marker and writes a BOGUS inflated floor (99), trying
    // to influence version computation. A marker-stripped record is untrusted:
    // its value must be ignored (and it must not be blessed with a MAC).
    const anchorsKey = "state-envelope-version-anchors-v1";
    await storage.write(
      "_meta",
      anchorsKey,
      stringToBytes(JSON.stringify({ "memory/balance": 99 }))
    );

    // A fresh-process legit write derives the floor from the authenticated
    // on-disk entry (version 2), NOT the bogus 99 -> the next version is 3.
    const freshStore = new StateStore(storage, masterKey);
    const result = await freshStore.write(
      "memory",
      "balance",
      "v2-c",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    expect(result.version).toBe(3);
  });

  it("preserves the monotonic version on a cold-process write with a legacy/ignored anchor (F1 upgrade path)", async () => {
    const { storage, masterKey, identity, identityEncKey } = makeStateRig();
    const seed = new StateStore(storage, masterKey);
    for (const v of ["a", "b", "c"]) {
      await seed.write(
        "memory",
        "counter",
        v,
        identity.storedIdentity.identity_id,
        identity.storedIdentity.encrypted_private_key,
        identityEncKey
      );
    }
    // Downgrade the anchor record to the legacy bare format (pre-F1 fortress).
    const anchorsKey = "state-envelope-version-anchors-v1";
    const wrapped = JSON.parse(
      bytesToString((await storage.read("_meta", anchorsKey))!)
    ) as { data: Record<string, unknown> };
    await storage.write(
      "_meta",
      anchorsKey,
      stringToBytes(JSON.stringify(wrapped.data))
    );

    // Fresh process (cold cache) + bare (ignored) anchor: a write to the
    // existing key must NOT reset the version. It reads the on-disk version (3)
    // and advances to 4, never clobbering the higher version with 1.
    const freshStore = new StateStore(storage, masterKey);
    const result = await freshStore.write(
      "memory",
      "counter",
      "d",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    expect(result.version).toBe(4);
  });

  it("readUnverified works for explicit legacy migration paths", async () => {
    const { storage, stateStore, identity, identityEncKey } = makeStateRig();

    await stateStore.write(
      "memory",
      "profile",
      "trusted value",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    const entry = await readEntry(storage, "memory", "profile");
    entry.envelope!.namespace = "tampered";
    await writeEntry(storage, "memory", "profile", entry);

    await expect(stateStore.read("memory", "profile")).rejects.toMatchObject({
      classification: "schema_mismatch",
    });

    const unverified = await stateStore.readUnverified("memory", "profile");
    expect(unverified?.value).toBe("trusted value");
    expect(unverified?.signature_verified).toBe(false);
  });
});
