/**
 * Exit-bundle re-key under custody-envelope fortresses (#496 follow-on).
 *
 * The legacy bundle format embedded `_meta/key-params` so import could
 * re-derive the source master as Argon2id(passphrase). Under the custody
 * envelope (master-custody.ts) the master is random and stored only as AEAD
 * wraps, so that mechanism is legacy-only. These tests cover the
 * envelope-era design:
 *
 *  - export mints a one-time BUNDLE RE-KEY KEY (full-entropy 32 bytes,
 *    disclosed to the operator, never written into the bundle) and embeds
 *    only a wrap of the source master under it — fortress credentials
 *    (passphrase wraps, fortress recovery keys, keychain wraps) never
 *    travel, so the bundle carries no offline passphrase oracle;
 *  - import recovers the source master by unwrapping (GCM-authenticated),
 *    failing closed on a wrong key — no legacy-derivation fallback;
 *  - legacy bundles still import via the explicit legacy branch, but a
 *    derived master that decrypts nothing now fails closed
 *    (SOURCE_KEY_MISMATCH) instead of silently skipping every entry;
 *  - tampering with the embedded wrap fails bundle verification (the
 *    artifact is hash-pinned in the Ed25519-signed manifest).
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import {
  establishMaster,
  readCustodyEnvelope,
} from "../../src/core/master-custody.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  verifyExitBundle,
  ExitBundleImportError,
  type ExitEncryptedStateBundle,
  type ExportExitBundleResult,
} from "../../src/exit/index.js";

const SOURCE_PASSPHRASE = "correct horse battery fortress";

async function callTool(
  tools: Array<{
    name: string;
    handler: (args: Record<string, unknown>) => Promise<{
      content: Array<{ type: string; text: string }>;
    }>;
  }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function buildHarness(storage: MemoryStorage, masterKey: Uint8Array) {
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "passphrase",
    auditLog
  );
  await identityManager.load();
  const { tools: l4Tools, reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog
  );
  return {
    storage,
    masterKey,
    auditLog,
    stateStore,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools],
  };
}

/** Envelope-custody source fortress: random master, passphrase + minted recovery wraps. */
async function makeEnvelopeSource() {
  const storage = new MemoryStorage();
  const established = await establishMaster({
    storage,
    passphrase: SOURCE_PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey: true },
  });
  const harness = await buildHarness(storage, established.masterKey);
  const identity = await callTool(harness.tools, "identity_create", {
    label: "envelope-source",
  });
  const identityId = identity.identity_id as string;
  await callTool(harness.tools, "state_write", {
    namespace: "agent-memory",
    key: "handoff",
    value: "envelope custody survives exit",
    identity_id: identityId,
  });
  return {
    ...harness,
    identityId,
    mintedRecoveryKey: established.mintedRecoveryKey!,
  };
}

/** Pre-envelope (legacy) fortress: bare random master, no envelope artifacts. */
async function makeLegacySource() {
  const storage = new MemoryStorage();
  const harness = await buildHarness(storage, generateRandomKey());
  const identity = await callTool(harness.tools, "identity_create", {
    label: "legacy-source",
  });
  const identityId = identity.identity_id as string;
  await callTool(harness.tools, "state_write", {
    namespace: "agent-memory",
    key: "handoff",
    value: "legacy custody bundle",
    identity_id: identityId,
  });
  return { ...harness, identityId };
}

async function makeDestination() {
  const harness = await buildHarness(new MemoryStorage(), generateRandomKey());
  const identity = await callTool(harness.tools, "identity_create", {
    label: "destination-signer",
  });
  return { ...harness, identityId: identity.identity_id as string };
}

type Harness = Awaited<ReturnType<typeof buildHarness>>;

async function exportBundle(
  source: Harness,
  bundleDir: string,
  opts?: { mint?: boolean }
): Promise<ExportExitBundleResult> {
  return exportExitBundle({
      unpartitionedLegacyExport: true,
    bundleDir,
    storage: source.storage,
    masterKey: source.masterKey,
    identityManager: source.identityManager,
    auditLog: source.auditLog,
    reputationStore: source.reputationStore,
    policy: DEFAULT_POLICY,
    config: defaultConfig(),
    stateNamespaces: ["agent-memory"],
    keySource: "passphrase",
    mintStateRekeyKey: opts?.mint ?? true,
  });
}

async function readEncryptedStateArtifact(
  bundleDir: string
): Promise<ExitEncryptedStateBundle> {
  return JSON.parse(
    await readFile(join(bundleDir, "artifacts", "encrypted_state.json"), "utf8")
  ) as ExitEncryptedStateBundle;
}

describe("exit bundle under custody-envelope fortresses", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function newBundleDir(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-exit-envelope-"));
    tempDirs.push(dir);
    return dir;
  }

  it("export mints a bundle re-key wrap; fortress credentials never travel", async () => {
    const source = await makeEnvelopeSource();
    const bundleDir = await newBundleDir();
    const result = await exportBundle(source, bundleDir);

    expect(result.state_rekey_key).toBeDefined();

    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.source_custody?.format).toBe(
      "SANCTUARY_EXIT_SOURCE_CUSTODY_V1"
    );
    // Exactly one bundle-scoped recovery-key wrap; no passphrase wraps
    // (offline-oracle ban), no keychain wraps, no fortress wrap copies.
    expect(artifact.source_custody!.wraps).toHaveLength(1);
    expect(artifact.source_custody!.wraps[0]!.type).toBe("recovery-key");
    const fortressWrapIds = (await readCustodyEnvelope(source.storage))!.wraps.map(
      (wrap) => wrap.id
    );
    expect(fortressWrapIds).not.toContain(artifact.source_custody!.wraps[0]!.id);
    // No key material in the bundle.
    const text = JSON.stringify(artifact);
    expect(text).not.toContain(SOURCE_PASSPHRASE);
    expect(text).not.toContain(source.mintedRecoveryKey);
    expect(text).not.toContain(result.state_rekey_key!);
    // Envelope-era bundles carry no legacy KDF params either.
    expect(artifact.source_key_derivation).toBeUndefined();
  });

  it("re-keys state via the bundle re-key key", async () => {
    const source = await makeEnvelopeSource();
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir);

    const destination = await makeDestination();
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceRecoveryKey: exported.state_rekey_key!,
      destinationSignerIdentityId: destination.identityId,
    });
    expect(result.state.status).toBe("rekeyed");
    expect(result.state.imported_keys).toBe(1);
    const read = await destination.stateStore.read("agent-memory", "handoff");
    expect(read?.value).toBe("envelope custody survives exit");
    expect(read?.written_by).toBe(destination.identityId);
  });

  it("source passphrase cannot re-key an envelope-era bundle (no offline oracle)", async () => {
    const source = await makeEnvelopeSource();
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);

    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourcePassphrase: SOURCE_PASSPHRASE,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "SOURCE_PASSPHRASE_UNSUPPORTED" });
    expect(await destination.storage.list("_exit_imports")).toEqual([]);
  });

  it("the fortress's own recovery key does NOT unlock the bundle (credentials don't travel)", async () => {
    const source = await makeEnvelopeSource();
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);

    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: source.mintedRecoveryKey,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "SOURCE_CREDENTIAL_INVALID" });
  });

  it("fails closed on a wrong bundle key and rolls back staged artifacts", async () => {
    const source = await makeEnvelopeSource();
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);

    const destination = await makeDestination();
    let caught: unknown;
    try {
      await importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: toBase64url(generateRandomKey()),
        destinationSignerIdentityId: destination.identityId,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ExitBundleImportError);
    expect((caught as ExitBundleImportError).code).toBe(
      "SOURCE_CREDENTIAL_INVALID"
    );
    // No silent fallback to the legacy raw-key-as-master path, no state
    // written, and the staged artifacts were rolled back (fail-closed
    // refusal, not a partial import).
    expect(await destination.storage.list("_exit_imports")).toEqual([]);
    expect(await destination.storage.list("_exit_public_identities")).toEqual([]);
    expect(
      await destination.stateStore.read("agent-memory", "handoff")
    ).toBeNull();
  });

  it("tampering with the embedded wrap fails bundle verification", async () => {
    const source = await makeEnvelopeSource();
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);

    const artifactPath = join(bundleDir, "artifacts", "encrypted_state.json");
    const artifact = await readEncryptedStateArtifact(bundleDir);
    const wrap = artifact.source_custody!.wraps[0]!;
    // Deterministic tamper: flip the FIRST base64url char (it carries the top
    // 6 bits of byte 0, so any change mutates the decrypted ciphertext). The
    // old `slice(0,-2) + "AA"` was a no-op whenever the last 2 chars were
    // already "AA" (base64 tail-bit alignment made that ~1/N flaky on CI), so
    // the tamper occasionally left ct unchanged and verification passed.
    const originalCt = wrap.payload.ct;
    wrap.payload.ct = (originalCt[0] === "A" ? "B" : "A") + originalCt.slice(1);
    expect(wrap.payload.ct).not.toBe(originalCt); // guarantee the tamper bit
    await writeFile(artifactPath, JSON.stringify(artifact, null, 2) + "\n");

    const verification = await verifyExitBundle(bundleDir);
    expect(verification.passed).toBe(false);
  });

  it("export without minting carries no source_custody (persisted-result callers)", async () => {
    const source = await makeEnvelopeSource();
    const bundleDir = await newBundleDir();
    const result = await exportBundle(source, bundleDir, { mint: false });
    expect(result.state_rekey_key).toBeUndefined();
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.source_custody).toBeUndefined();
  });

  it("legacy bundle: passphrase with no embedded key material fails closed", async () => {
    const source = await makeLegacySource();
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: false });

    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.source_custody).toBeUndefined();
    expect(artifact.source_key_derivation).toBeUndefined();

    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourcePassphrase: SOURCE_PASSPHRASE,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "SOURCE_KEY_UNAVAILABLE" });
    expect(await destination.storage.list("_exit_imports")).toEqual([]);
  });

  it("legacy bundle: divergent key-params master fails closed instead of silently skipping", async () => {
    const source = await makeLegacySource();
    // Dual-path damage signature: key-params exist but derive a master that
    // is NOT the one the data is encrypted under (the 2026-06-12 F2 class).
    const { params } = await deriveMasterKey("a different passphrase");
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: false });

    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.source_key_derivation).toBeDefined();

    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourcePassphrase: "a different passphrase",
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "SOURCE_KEY_MISMATCH" });
    // Rollback: nothing imported, staged artifacts removed.
    expect(await destination.storage.list("_exit_imports")).toEqual([]);
    expect(
      await destination.stateStore.read("agent-memory", "handoff")
    ).toBeNull();
  });

  it("migrated fortress: legacy passphrase path AND bundle re-key key both work", async () => {
    // Simulate a #496-migrated passphrase fortress: master =
    // Argon2id(passphrase, key-params), envelope wraps that same master,
    // legacy markers kept.
    const storage = new MemoryStorage();
    const { key: expectedMaster, params } = await deriveMasterKey(
      SOURCE_PASSPHRASE
    );
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const established = await establishMaster({
      storage,
      passphrase: SOURCE_PASSPHRASE,
    });
    expect(established.origin).toBe("migrated-passphrase");
    expect(Buffer.from(established.masterKey)).toEqual(
      Buffer.from(expectedMaster)
    );

    const source = await buildHarness(storage, established.masterKey);
    const identity = await callTool(source.tools, "identity_create", {
      label: "migrated-source",
    });
    await callTool(source.tools, "state_write", {
      namespace: "agent-memory",
      key: "handoff",
      value: "migrated fortress state",
      identity_id: identity.identity_id as string,
    });

    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir);
    const artifact = await readEncryptedStateArtifact(bundleDir);
    // Both present: source_custody for the new path, key-params keeps the
    // legacy passphrase path working on migrated-fortress bundles (the
    // oracle already exists there; nothing new is exposed).
    expect(artifact.source_custody).toBeDefined();
    expect(artifact.source_key_derivation).toBeDefined();

    // Legacy passphrase path.
    const dest1 = await makeDestination();
    const viaPassphrase = await importExitBundle({
      bundleDir,
      storage: dest1.storage,
      masterKey: dest1.masterKey,
      identityManager: dest1.identityManager,
      auditLog: dest1.auditLog,
      reputationStore: dest1.reputationStore,
      activate: true,
      forceRebind: true,
      sourcePassphrase: SOURCE_PASSPHRASE,
      destinationSignerIdentityId: dest1.identityId,
    });
    expect(viaPassphrase.state.status).toBe("rekeyed");
    expect(viaPassphrase.state.imported_keys).toBe(1);

    // Bundle re-key key path.
    const dest2 = await makeDestination();
    const viaBundleKey = await importExitBundle({
      bundleDir,
      storage: dest2.storage,
      masterKey: dest2.masterKey,
      identityManager: dest2.identityManager,
      auditLog: dest2.auditLog,
      reputationStore: dest2.reputationStore,
      activate: true,
      forceRebind: true,
      sourceRecoveryKey: exported.state_rekey_key!,
      destinationSignerIdentityId: dest2.identityId,
    });
    expect(viaBundleKey.state.status).toBe("rekeyed");
    expect(viaBundleKey.state.imported_keys).toBe(1);
  });
});
