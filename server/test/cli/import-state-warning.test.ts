import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";

import { runExitCommand } from "../../src/exit/cli.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import {
  deriveMasterKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { createIdentity, sign as identitySign } from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { hash } from "../../src/core/hashing.js";
import { canonicalize, canonicalizeToBytes } from "../../src/mesh/canonical-json.js";

class StringWritable extends Writable {
  chunks: string[] = [];

  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }

  get text(): string {
    return this.chunks.join("");
  }
}

const SOURCE_PASSPHRASE = "source-passphrase-for-import-state-warning";
const DESTINATION_PASSPHRASE = "destination-passphrase-for-import-state-warning";

interface Fortress {
  storagePath: string;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  identityEncryptionKey: Uint8Array;
  identity: StoredIdentity;
}

function sha256Hex(bytes: Uint8Array): string {
  return Array.from(hash(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function jsonBytes(value: unknown): Uint8Array {
  return stringToBytes(JSON.stringify(value, null, 2) + "\n");
}

async function patchArtifactAndResign(
  bundleDir: string,
  source: Fortress,
  artifactKind: string,
  mutate: (artifact: Record<string, unknown>) => Record<string, unknown>,
): Promise<void> {
  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    body: {
      artifacts: Array<{
        kind: string;
        path: string;
        hash: string;
        size_bytes: number;
      }>;
      artifacts_aggregate_hash: string;
    };
    signature: string;
  };
  const manifestEntry = manifest.body.artifacts.find(
    (entry) => entry.kind === artifactKind,
  );
  if (!manifestEntry) {
    throw new Error(`missing artifact kind ${artifactKind}`);
  }

  const artifactPath = join(bundleDir, manifestEntry.path);
  const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as Record<
    string,
    unknown
  >;
  const updated = mutate(artifact);
  const bytes = jsonBytes(updated);
  await writeFile(artifactPath, bytes);

  for (const entry of manifest.body.artifacts) {
    const artifactBytes = new Uint8Array(await readFile(join(bundleDir, entry.path)));
    entry.hash = sha256Hex(artifactBytes);
    entry.size_bytes = artifactBytes.length;
  }
  manifest.body.artifacts_aggregate_hash = sha256Hex(
    stringToBytes(canonicalize(manifest.body.artifacts)),
  );
  manifest.signature = toBase64url(
    identitySign(
      canonicalizeToBytes(manifest.body),
      source.identity.encrypted_private_key,
      source.identityEncryptionKey,
    ),
  );
  await writeFile(manifestPath, jsonBytes(manifest));
}

async function addReservedStateEntryAndResign(
  bundleDir: string,
  source: Fortress,
): Promise<void> {
  await patchArtifactAndResign(bundleDir, source, "encrypted_state", (artifact) => {
    const entries = artifact.entries as Array<Record<string, unknown>>;
    const first = entries[0];
    if (!first) throw new Error("expected encrypted_state entry");
    entries.push({
      ...first,
      namespace: "_identities",
      key: "crafted-reserved-entry",
    });
    artifact.total_keys = entries.length;
    artifact.namespaces = [
      ...new Set([...(artifact.namespaces as string[]), "_identities"]),
    ].sort();
    return artifact;
  });
}

/**
 * Codex gate finding (2026-08-22): distinct from
 * addReservedStateEntryAndResign - THIS entry is structurally well-formed
 * (passes the pre-staging gate), it just carries a `kid` no public-identity
 * artifact key resolves. rekeyState's per-entry loop skips it and counts it
 * (skipped_unknown_kid), which is the post-staging, all-or-nothing
 * "state import incomplete" path the reserved-namespace test above no
 * longer exercises (F4 moved reserved-namespace to the pre-staging gate).
 */
async function addUnknownKidStateEntryAndResign(
  bundleDir: string,
  source: Fortress,
): Promise<void> {
  await patchArtifactAndResign(bundleDir, source, "encrypted_state", (artifact) => {
    const entries = artifact.entries as Array<Record<string, unknown>>;
    const first = entries[0];
    if (!first) throw new Error("expected encrypted_state entry");
    const firstEntry = first.entry as Record<string, unknown>;
    entries.push({
      ...first,
      key: "crafted-unknown-kid-entry",
      entry: { ...firstEntry, kid: "did:key:z6MkUnknownKidNeverIssued" },
    });
    artifact.total_keys = entries.length;
    return artifact;
  });
}

async function addRotationHistoryAndResign(
  bundleDir: string,
  source: Fortress,
): Promise<void> {
  await patchArtifactAndResign(bundleDir, source, "public_identity", (artifact) => {
    const bundle = artifact.bundle as Record<string, unknown>;
    bundle.rotation_history = [
      {
        old_public_key: source.identity.public_key,
        new_public_key: source.identity.public_key,
        rotation_event: toBase64url(stringToBytes("signed-rotation-event")),
        rotated_at: "2026-08-08T00:00:00.000Z",
      },
    ];
    artifact.signature = toBase64url(
      identitySign(
        canonicalizeToBytes(bundle),
        source.identity.encrypted_private_key,
        source.identityEncryptionKey,
      ),
    );
    return artifact;
  });
}

async function bootstrapFortress(
  passphrase: string,
  label: string,
): Promise<Fortress> {
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-cli-import-"));
  const stateStoragePath = join(storagePath, "state");
  await mkdir(stateStoragePath, { recursive: true, mode: 0o700 });

  const storage = new FilesystemStorage(stateStoragePath);
  const { key: masterKey, params } = await deriveMasterKey(passphrase);
  await storage.write(
    "_meta",
    "key-params",
    stringToBytes(JSON.stringify(params)),
  );

  const identityEncryptionKey = derivePurposeKey(
    masterKey,
    "identity-encryption",
  );
  const identity = createIdentity(label, identityEncryptionKey, "passphrase");
  const identityManager = new IdentityManager(storage, masterKey);
  await identityManager.save(identity.storedIdentity);

  return {
    storagePath,
    storage,
    masterKey,
    identityEncryptionKey,
    identity: identity.storedIdentity,
  };
}

describe("exit import state warning", () => {
  const cleanup: string[] = [];
  let originalStoragePath: string | undefined;

  beforeEach(() => {
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  });

  afterEach(async () => {
    if (originalStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    }
    for (const path of cleanup.splice(0)) {
      await rm(path, { recursive: true, force: true });
    }
  });

  async function exportBundle(
    source: Fortress,
    stateNamespaces: string[] = [],
  ): Promise<string> {
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-cli-bundle-"));
    cleanup.push(bundleDir);
    process.env.SANCTUARY_STORAGE_PATH = source.storagePath;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "export",
        "--out",
        bundleDir,
        "--yes",
        ...stateNamespaces.flatMap((namespace) => [
          "--state-namespace",
          namespace,
        ]),
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: SOURCE_PASSPHRASE },
    });

    expect(code).toBe(0);
    return bundleDir;
  }

  it("warns loudly when --activate imports no state", async () => {
    const source = await bootstrapFortress(SOURCE_PASSPHRASE, "source");
    cleanup.push(source.storagePath);
    const destination = await mkdtemp(join(tmpdir(), "sanctuary-cli-dest-"));
    cleanup.push(destination);
    const bundleDir = await exportBundle(source);

    process.env.SANCTUARY_STORAGE_PATH = destination;
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: ["import", bundleDir, "--activate", "--yes"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: DESTINATION_PASSPHRASE },
    });

    expect(code).toBe(0);
    expect(out.text).toContain("verdict: PASS");
    expect(out.text).toContain("activated: true");
    expect(out.text).toContain("state_imported_keys: 0");
    expect(err.text).toContain(
      "WARNING: Bundle activated but NO STATE was imported to the target fortress.",
    );
    expect(err.text).toContain(
      "To import state, re-run with: sanctuary exit import <dir> --activate --import-state",
    );
  });

  it("imports state when --import-state and source credentials are provided", async () => {
    const source = await bootstrapFortress(SOURCE_PASSPHRASE, "source");
    cleanup.push(source.storagePath);
    const stateStore = new StateStore(source.storage, source.masterKey);
    await stateStore.write(
      "agent-memory",
      "handoff",
      "durable state survives CLI import",
      source.identity.identity_id,
      source.identity.encrypted_private_key,
      source.identityEncryptionKey,
    );
    const bundleDir = await exportBundle(source, ["agent-memory"]);

    const destination = await bootstrapFortress(
      DESTINATION_PASSPHRASE,
      "destination",
    );
    cleanup.push(destination.storagePath);
    process.env.SANCTUARY_STORAGE_PATH = destination.storagePath;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "import",
        bundleDir,
        "--activate",
        "--import-state",
        "--source-passphrase",
        SOURCE_PASSPHRASE,
        "--destination-identity-id",
        destination.identity.identity_id,
        "--force-rebind",
        "--yes",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: DESTINATION_PASSPHRASE },
    });

    expect(code).toBe(0);
    expect(out.text).toContain("state_imported_keys: 1");
    expect(out.text).toContain("state_skipped_keys: 0");
    expect(out.text).toContain("state_skipped_invalid_sig: 0");
    expect(out.text).toContain("state_skipped_unknown_kid: 0");
    expect(err.text).not.toContain("NO STATE was imported");
    expect(err.text).not.toContain("state import incomplete");

    const destinationState = new StateStore(
      destination.storage,
      destination.masterKey,
    );
    const imported = await destinationState.read("agent-memory", "handoff");
    expect(imported?.value).toBe("durable state survives CLI import");
    expect(imported?.written_by).toBe(destination.identity.identity_id);
  });

  it("does NOT false-freeze a legitimate import as an anti-rollback splice (#506 regression)", async () => {
    // #506 anti-rollback Stage 1 wired `enforceCustodyFloor` to a head-anchor
    // SPLICE probe (probeAuditHeadAnchor). During a legitimate exit-bundle
    // import into a fresh epoch-0 destination, the activation path emits its
    // audit entries fire-and-forget; before the fix, the trust-bearing-write
    // gate (reputation import / state re-key) could probe the audit store in
    // the window where an entry is on disk but its head anchor write is still
    // in flight. probeAuditHeadAnchor read that transient "entries-but-no-anchor"
    // state as the custody-splice signature and raised a FALSE
    // CustodyRollbackFrozenError, failing the import (exit 1). A fresh fortress
    // establishing itself for the first time has no prior lineage to roll back
    // to - it is not a splice. This asserts the freeze did NOT fire, distinctly
    // from the success-path assertions above (which only check exit code +
    // imported-key count), so a regression that re-introduces the race is caught
    // by its rollback-specific symptom rather than only by a flaky exit code.
    const source = await bootstrapFortress(SOURCE_PASSPHRASE, "source");
    cleanup.push(source.storagePath);
    const stateStore = new StateStore(source.storage, source.masterKey);
    await stateStore.write(
      "agent-memory",
      "handoff",
      "no false rollback freeze on legitimate import",
      source.identity.identity_id,
      source.identity.encrypted_private_key,
      source.identityEncryptionKey,
    );
    const bundleDir = await exportBundle(source, ["agent-memory"]);

    const destination = await bootstrapFortress(
      DESTINATION_PASSPHRASE,
      "destination",
    );
    cleanup.push(destination.storagePath);
    process.env.SANCTUARY_STORAGE_PATH = destination.storagePath;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "import",
        bundleDir,
        "--activate",
        "--import-state",
        "--source-passphrase",
        SOURCE_PASSPHRASE,
        "--destination-identity-id",
        destination.identity.identity_id,
        "--force-rebind",
        "--yes",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: DESTINATION_PASSPHRASE },
    });

    expect(code).toBe(0);
    // The anti-rollback freeze must NOT have fired on a legitimate import.
    expect(err.text).not.toContain("SUSPECTED CUSTODY ROLLBACK");
    expect(err.text).not.toContain("refusing to persist trust-bearing state");
    expect(out.text).toContain("state_imported_keys: 1");

    // And no freeze marker was persisted on the destination fortress: a genuine
    // rollback would have written `_meta/custody-rollback-freeze-v1`.
    const { isRollbackFrozen } = await import("../../src/core/anti-rollback.js");
    const freeze = await isRollbackFrozen(
      destination.storage,
      destination.masterKey,
    );
    expect(freeze.frozen).toBe(false);
  });

  it("refuses a reserved-namespace entry BEFORE staging, with a named error (F4, Exit V2 drill D1, 2026-08-22)", async () => {
    const source = await bootstrapFortress(SOURCE_PASSPHRASE, "source");
    cleanup.push(source.storagePath);
    const stateStore = new StateStore(source.storage, source.masterKey);
    await stateStore.write(
      "agent-memory",
      "handoff",
      "partial imports must not look successful",
      source.identity.identity_id,
      source.identity.encrypted_private_key,
      source.identityEncryptionKey,
    );
    const bundleDir = await exportBundle(source, ["agent-memory"]);
    await addReservedStateEntryAndResign(bundleDir, source);

    const destination = await bootstrapFortress(
      DESTINATION_PASSPHRASE,
      "destination",
    );
    cleanup.push(destination.storagePath);
    process.env.SANCTUARY_STORAGE_PATH = destination.storagePath;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "import",
        bundleDir,
        "--activate",
        "--import-state",
        "--source-passphrase",
        SOURCE_PASSPHRASE,
        "--destination-identity-id",
        destination.identity.identity_id,
        "--force-rebind",
        "--yes",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: DESTINATION_PASSPHRASE },
    });

    // F4 (Exit V2 drill D1): before the fix, this scenario staged every
    // artifact, hit the reserved-namespace entry inside `rekeyState`, and
    // only THEN reported `state_skipped_keys: 1` / "state import
    // incomplete" and rolled back. The fix moves the SAME refusal to the
    // shared pre-staging gate (checkEncryptedStateStructure,
    // verifier.ts/bundle.ts), so it never gets that far: a NAMED error, not
    // a late-stage skip counter.
    expect(code).toBe(1);
    expect(out.text).not.toContain("verdict: PASS");
    expect(err.text).toContain("ENCRYPTED_STATE_RESERVED_NAMESPACE_ENTRY");
    expect(err.text).toContain("reserved namespace");
    expect(err.text).not.toContain("state_skipped_keys");

    const destinationState = new StateStore(
      destination.storage,
      destination.masterKey,
    );
    const imported = await destinationState.read("agent-memory", "handoff");
    expect(imported).toBeNull();
  });

  it("Codex gate finding (2026-08-22): an unknown-kid entry is skipped post-staging, reports skip counters, and reports state import incomplete", async () => {
    const source = await bootstrapFortress(SOURCE_PASSPHRASE, "source");
    cleanup.push(source.storagePath);
    const stateStore = new StateStore(source.storage, source.masterKey);
    await stateStore.write(
      "agent-memory",
      "handoff",
      "partial imports must not look successful",
      source.identity.identity_id,
      source.identity.encrypted_private_key,
      source.identityEncryptionKey,
    );
    const bundleDir = await exportBundle(source, ["agent-memory"]);
    await addUnknownKidStateEntryAndResign(bundleDir, source);

    const destination = await bootstrapFortress(
      DESTINATION_PASSPHRASE,
      "destination",
    );
    cleanup.push(destination.storagePath);
    process.env.SANCTUARY_STORAGE_PATH = destination.storagePath;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "import",
        bundleDir,
        "--activate",
        "--import-state",
        "--source-passphrase",
        SOURCE_PASSPHRASE,
        "--destination-identity-id",
        destination.identity.identity_id,
        "--force-rebind",
        "--yes",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: DESTINATION_PASSPHRASE },
    });

    expect(code).toBe(1);
    expect(out.text).not.toContain("verdict: PASS");
    expect(err.text).toContain("state_skipped_keys: 1");
    expect(err.text).toContain("state_skipped_invalid_sig: 0");
    expect(err.text).toContain("state_skipped_unknown_kid: 1");
    expect(err.text).toContain("state import incomplete");

    const destinationState = new StateStore(
      destination.storage,
      destination.masterKey,
    );
    const imported = await destinationState.read("agent-memory", "handoff");
    expect(imported).toBeNull();
  });

  it("refuses rotated-fortress bundles before writing destination state", async () => {
    const source = await bootstrapFortress(SOURCE_PASSPHRASE, "source");
    cleanup.push(source.storagePath);
    const stateStore = new StateStore(source.storage, source.masterKey);
    await stateStore.write(
      "agent-memory",
      "handoff",
      "rotation history cannot be silently dropped",
      source.identity.identity_id,
      source.identity.encrypted_private_key,
      source.identityEncryptionKey,
    );
    const bundleDir = await exportBundle(source, ["agent-memory"]);
    await addRotationHistoryAndResign(bundleDir, source);

    const destination = await bootstrapFortress(
      DESTINATION_PASSPHRASE,
      "destination",
    );
    cleanup.push(destination.storagePath);
    process.env.SANCTUARY_STORAGE_PATH = destination.storagePath;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "import",
        bundleDir,
        "--activate",
        "--import-state",
        "--source-passphrase",
        SOURCE_PASSPHRASE,
        "--destination-identity-id",
        destination.identity.identity_id,
        "--force-rebind",
        "--yes",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: DESTINATION_PASSPHRASE },
    });

    expect(code).toBe(1);
    expect(out.text).not.toContain("verdict: PASS");
    expect(err.text).toContain("ROTATION_CHAIN_UNVERIFIABLE");
    expect(err.text).toContain("rotation chain unverifiable");
    expect(err.text).toContain(source.identity.identity_id);

    const destinationState = new StateStore(
      destination.storage,
      destination.masterKey,
    );
    const imported = await destinationState.read("agent-memory", "handoff");
    expect(imported).toBeNull();
  });

  it("rejects --import-state without source credentials, fail-closed", async () => {
    // F-1.3.1-N-003 follow-through: encrypted source state can only be
    // re-keyed with a source credential, so --import-state alone can never
    // import. The gate must reject up front rather than silently no-op.
    const source = await bootstrapFortress(SOURCE_PASSPHRASE, "source");
    cleanup.push(source.storagePath);
    const bundleDir = await exportBundle(source);

    const destination = await mkdtemp(join(tmpdir(), "sanctuary-cli-dest-"));
    cleanup.push(destination);
    process.env.SANCTUARY_STORAGE_PATH = destination;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: ["import", bundleDir, "--activate", "--import-state", "--yes"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: DESTINATION_PASSPHRASE },
    });

    expect(code).toBe(2);
    expect(err.text).toContain(
      "--import-state requires --source-passphrase or --source-recovery-key",
    );
    // The gate fires before any import/activation work runs.
    expect(out.text).not.toContain("verdict:");
    expect(err.text).not.toContain("NO STATE was imported");
  });
});
