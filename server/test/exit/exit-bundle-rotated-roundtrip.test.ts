import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { hash } from "../../src/core/hashing.js";
import {
  sign as identitySign,
  verify as identityVerify,
  type StoredIdentity,
} from "../../src/core/identity.js";
import { canonicalize, canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import {
  StateStore,
  STATE_META_PUBLIC_KEYS_KEY,
  type StateEntry,
} from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  inspectExitBundle,
  verifyExitBundle,
  ExitBundleImportError,
} from "../../src/exit/index.js";
import type {
  ExitBundleArtifactEntry,
  ExitBundleManifest,
} from "../../src/contracts/v1.1/exit-bundle-manifest.js";

interface ToolDef {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
  }>;
}

async function callTool(
  tools: ToolDef[],
  name: string,
  args: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function makeHarness() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog,
  );
  await identityManager.load();
  const { tools: l4Tools, reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog,
  );
  return {
    storage,
    masterKey,
    auditLog,
    stateStore,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools] as ToolDef[],
  };
}

async function createIdentity(harness: Awaited<ReturnType<typeof makeHarness>>) {
  const created = await callTool(harness.tools, "identity_create", {
    label: "rotated-source",
  });
  return created.identity_id as string;
}

async function exportBundle(
  source: Awaited<ReturnType<typeof makeHarness>>,
  bundleDir: string,
) {
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
    stateNamespaces: ["notes"],
    keySource: "recovery-key",
    mintStateRekeyKey: true,
  });
}

async function readStateEntry(
  storage: MemoryStorage,
  namespace: string,
  key: string,
): Promise<StateEntry> {
  const raw = await storage.read(namespace, key);
  if (!raw) throw new Error(`missing state entry ${namespace}/${key}`);
  return JSON.parse(bytesToString(raw)) as StateEntry;
}

async function readStoredIdentity(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  identityId: string,
): Promise<StoredIdentity> {
  const raw = await storage.read("_identities", identityId);
  if (!raw) throw new Error(`missing identity ${identityId}`);
  const encrypted = JSON.parse(bytesToString(raw));
  const { decrypt } = await import("../../src/core/encryption.js");
  return JSON.parse(
    bytesToString(decrypt(encrypted, derivePurposeKey(masterKey, "identity-encryption"))),
  ) as StoredIdentity;
}

async function rewriteArtifact(
  bundleDir: string,
  source: Awaited<ReturnType<typeof makeHarness>>,
  kind: ExitBundleArtifactEntry["kind"],
  path: string,
  mutate: (artifact: Record<string, unknown>) => Record<string, unknown>,
): Promise<void> {
  const artifactPath = join(bundleDir, path);
  const manifestPath = join(bundleDir, "manifest.json");
  const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as Record<
    string,
    unknown
  >;
  const mutated = mutate(artifact);
  const identity = source.identityManager.getDefault();
  if (!identity) throw new Error("missing source identity");
  if (kind === "public_identity") {
    const body = (mutated.bundle ?? {}) as Record<string, unknown>;
    mutated.signature = toBase64url(
      identitySign(
        canonicalizeToBytes(body),
        identity.encrypted_private_key,
        derivePurposeKey(source.masterKey, "identity-encryption"),
      ),
    );
  }
  const artifactBytes = stringToBytes(JSON.stringify(mutated, null, 2) + "\n");
  await writeFile(artifactPath, artifactBytes);

  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ExitBundleManifest;
  const publicIdentityEntry = manifest.body.artifacts.find(
    (entry) => entry.kind === kind,
  ) as ExitBundleArtifactEntry | undefined;
  if (!publicIdentityEntry) throw new Error(`missing ${kind} entry`);
  publicIdentityEntry.hash = Array.from(hash(artifactBytes))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  publicIdentityEntry.size_bytes = artifactBytes.length;
  manifest.body.artifacts_aggregate_hash = Array.from(
    hash(stringToBytes(canonicalize(manifest.body.artifacts))),
  )
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  manifest.signature = toBase64url(
    identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      derivePurposeKey(source.masterKey, "identity-encryption"),
    ),
  );
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

async function rewritePublicIdentityArtifact(
  bundleDir: string,
  source: Awaited<ReturnType<typeof makeHarness>>,
  mutate: (artifact: Record<string, unknown>) => Record<string, unknown>,
): Promise<void> {
  await rewriteArtifact(
    bundleDir,
    source,
    "public_identity",
    "artifacts/public_identity.json",
    mutate,
  );
}

describe("rotated exit-bundle import", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not retain the pre-B4 rotation-history unsupported refusal", async () => {
    const source = await readFile(
      join(process.cwd(), "src", "exit", "bundle.ts"),
      "utf8",
    );

    expect(source).not.toContain("ROTATION_HISTORY_UNSUPPORTED");
  });

  it("imports state and reputation signed before identity rotations", async () => {
    const source = await makeHarness();
    const sourceIdentityId = await createIdentity(source);
    await callTool(source.tools, "state_write", {
      namespace: "notes",
      key: "s1",
      value: "before first rotation",
      identity_id: sourceIdentityId,
    });
    await callTool(source.tools, "reputation_record", {
      interaction_id: "rotated-reputation-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 91 },
      },
      context: "rotated-exit",
      identity_id: sourceIdentityId,
    });
    await callTool(source.tools, "identity_rotate", {
      identity_id: sourceIdentityId,
      reason: "routine one",
    });
    await callTool(source.tools, "state_write", {
      namespace: "notes",
      key: "s2",
      value: "after first rotation",
      identity_id: sourceIdentityId,
    });
    await callTool(source.tools, "identity_rotate", {
      identity_id: sourceIdentityId,
      reason: "routine two",
    });
    await callTool(source.tools, "state_write", {
      namespace: "notes",
      key: "s3",
      value: "after second rotation",
      identity_id: sourceIdentityId,
    });
    const finalSourceIdentity = source.identityManager.getDefault();
    if (!finalSourceIdentity) throw new Error("missing final source identity");
    const retiredKeys = finalSourceIdentity.rotation_history.map(
      (hop) => hop.old_public_key,
    );

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-rotated-exit-"));
    tempDirs.push(bundleDir);
    const exported = await exportBundle(source, bundleDir);
    expect(exported.state_rekey_key).toBeDefined();
    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(true);
    expect(verified.identity?.rotation?.chain_signature_verified).toBe(true);
    expect(verified.identity?.rotation?.hop_count).toBe(2);
    expect(verified.reputation?.verified_attestations).toBe(1);
    const inspected = await inspectExitBundle(bundleDir);
    expect(inspected.rotation).toMatchObject({
      hop_count: 2,
      chain_signature_verified: true,
      terminates_at_current: true,
      compromised_hops: 0,
    });

    const destination = await makeHarness();
    const destinationIdentityId = await createIdentity(destination);
    const imported = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceRecoveryKey: exported.state_rekey_key,
      destinationSignerIdentityId: destinationIdentityId,
    });

    expect(imported.state).toMatchObject({
      imported_keys: 3,
      skipped_invalid_sig: 0,
      skipped_unknown_kid: 0,
      skipped_keys: 0,
    });
    expect(imported.reputation.imported_attestations).toBe(1);
    expect(imported.rotation).toMatchObject({
      hop_count: 2,
      chain_signature_verified: true,
      entries_admitted_by_retired_key: 2,
      entries_admitted_by_current_key: 1,
    });
    await expect(destination.stateStore.read("notes", "s1")).resolves.toMatchObject({
      value: "before first rotation",
      signature_verified: true,
    });
    await expect(destination.stateStore.read("notes", "s2")).resolves.toMatchObject({
      value: "after first rotation",
      signature_verified: true,
    });
    await expect(destination.stateStore.read("notes", "s3")).resolves.toMatchObject({
      value: "after second rotation",
      signature_verified: true,
    });

    const destinationIdentity = destination.identityManager.getDefault();
    if (!destinationIdentity) throw new Error("missing destination identity");
    const destinationPublicKey = fromBase64url(destinationIdentity.public_key);
    const registryRaw = await destination.storage.read(
      "_meta",
      STATE_META_PUBLIC_KEYS_KEY,
    );
    expect(registryRaw).not.toBeNull();
    const registryText = bytesToString(registryRaw!);
    for (const retired of retiredKeys) {
      expect(registryText).not.toContain(retired);
    }
    const storedDestinationIdentity = await readStoredIdentity(
      destination.storage,
      destination.masterKey,
      destinationIdentity.identity_id,
    );
    for (const retired of retiredKeys) {
      expect(JSON.stringify(storedDestinationIdentity)).not.toContain(retired);
    }
    for (const key of ["s1", "s2", "s3"]) {
      const entry = await readStateEntry(destination.storage, "notes", key);
      expect(
        identityVerify(
          fromBase64url(entry.payload.ct),
          fromBase64url(entry.sig),
          destinationPublicKey,
        ),
      ).toBe(true);
      for (const retired of retiredKeys) {
        expect(
          identityVerify(
            fromBase64url(entry.payload.ct),
            fromBase64url(entry.sig),
            fromBase64url(retired),
          ),
        ).toBe(false);
      }
      expect(entry.metadata.tags).toContain("exit-import");
      if (key !== "s3") {
        expect(entry.metadata.tags?.some((tag) => tag.startsWith("source-key:retired-"))).toBe(true);
      }
    }
    const audit = await destination.auditLog.query({ limit: 50 });
    const rotationAudit = audit.entries.find(
      (entry) => entry.operation === "exit_bundle_rotation_chain_consumed",
    );
    expect(rotationAudit?.details).toMatchObject({
      hop_count: 2,
      entries_admitted_by_retired_key: 2,
      entries_admitted_by_current_key: 1,
      compromised_hops: 0,
    });
  });

  it("refuses an unverifiable chain before destination writes", async () => {
    const source = await makeHarness();
    const sourceIdentityId = await createIdentity(source);
    await callTool(source.tools, "state_write", {
      namespace: "notes",
      key: "s1",
      value: "invalid chain must not import",
      identity_id: sourceIdentityId,
    });
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-invalid-chain-"));
    tempDirs.push(bundleDir);
    const exported = await exportBundle(source, bundleDir);
    await rewritePublicIdentityArtifact(bundleDir, source, (artifact) => {
      const bundle = artifact.bundle as Record<string, unknown>;
      bundle.rotation_history = [
        {
          old_public_key: bundle.publicKey,
          new_public_key: bundle.publicKey,
          rotation_event: toBase64url(stringToBytes("not a signed event")),
          rotated_at: "2026-08-09T00:00:00.000Z",
        },
      ];
      return artifact;
    });
    const inspected = await inspectExitBundle(bundleDir);
    expect(inspected.rotation.chain_signature_verified).toBe(false);
    expect(inspected.rotation.invalid_reason).toBe("rotation_chain_repeated_key");
    // EXIT-PASS-01: verify/inspect must FAIL on an invalid rotation chain, not
    // report PASS while quietly carrying chain_signature_verified: false. Both
    // commands derive their exit status from the verifier `passed` boolean.
    expect(inspected.verdict).toBe("FAIL");
    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(false);
    expect(verified.failure_class).toBe("rotation_chain_invalid");

    const destination = await makeHarness();
    const destinationIdentityId = await createIdentity(destination);
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
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destinationIdentityId,
      }),
    ).rejects.toMatchObject({
      code: "ROTATION_CHAIN_UNVERIFIABLE",
    } satisfies Partial<ExitBundleImportError>);
    await expect(destination.stateStore.read("notes", "s1")).resolves.toBeNull();
  });

  it("refuses and rolls back when a verified chain cannot verify a state entry", async () => {
    const source = await makeHarness();
    const sourceIdentityId = await createIdentity(source);
    await callTool(source.tools, "state_write", {
      namespace: "notes",
      key: "s1",
      value: "signed before rotation",
      identity_id: sourceIdentityId,
    });
    await callTool(source.tools, "identity_rotate", {
      identity_id: sourceIdentityId,
      reason: "routine",
    });
    await callTool(source.tools, "state_write", {
      namespace: "notes",
      key: "s2",
      value: "signed after rotation",
      identity_id: sourceIdentityId,
    });
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-invalid-entry-"));
    tempDirs.push(bundleDir);
    const exported = await exportBundle(source, bundleDir);
    await rewriteArtifact(
      bundleDir,
      source,
      "encrypted_state",
      "artifacts/encrypted_state.json",
      (artifact) => {
        const entries = artifact.entries as Array<{ entry: StateEntry }>;
        entries[0]!.entry.sig = toBase64url(new Uint8Array(64));
        return artifact;
      },
    );

    const destination = await makeHarness();
    const destinationIdentityId = await createIdentity(destination);
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
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destinationIdentityId,
      }),
    ).rejects.toMatchObject({
      code: "STATE_IMPORT_INCOMPLETE",
    } satisfies Partial<ExitBundleImportError>);
    await expect(destination.stateStore.read("notes", "s1")).resolves.toBeNull();
    await expect(destination.stateStore.read("notes", "s2")).resolves.toBeNull();
  });

  it("refuses compromised retired keys by default and imports with opt-in", async () => {
    const source = await makeHarness();
    const sourceIdentityId = await createIdentity(source);
    await callTool(source.tools, "state_write", {
      namespace: "notes",
      key: "before-compromise",
      value: "operator wants this back",
      identity_id: sourceIdentityId,
    });
    await callTool(source.tools, "identity_rotate", {
      identity_id: sourceIdentityId,
      reason: "compromised",
    });
    await callTool(source.tools, "state_write", {
      namespace: "notes",
      key: "after-compromise",
      value: "signed by current key",
      identity_id: sourceIdentityId,
    });
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-compromised-chain-"));
    tempDirs.push(bundleDir);
    const exported = await exportBundle(source, bundleDir);

    const refusedDestination = await makeHarness();
    const refusedDestinationIdentityId = await createIdentity(refusedDestination);
    await expect(
      importExitBundle({
        bundleDir,
        storage: refusedDestination.storage,
        masterKey: refusedDestination.masterKey,
        identityManager: refusedDestination.identityManager,
        auditLog: refusedDestination.auditLog,
        reputationStore: refusedDestination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: refusedDestinationIdentityId,
      }),
    ).rejects.toMatchObject({
      code: "COMPROMISED_ROTATION_KEY_REFUSED",
    } satisfies Partial<ExitBundleImportError>);
    await expect(
      refusedDestination.stateStore.read("notes", "before-compromise"),
    ).resolves.toBeNull();

    const acceptedDestination = await makeHarness();
    const acceptedDestinationIdentityId = await createIdentity(acceptedDestination);
    const imported = await importExitBundle({
      bundleDir,
      storage: acceptedDestination.storage,
      masterKey: acceptedDestination.masterKey,
      identityManager: acceptedDestination.identityManager,
      auditLog: acceptedDestination.auditLog,
      reputationStore: acceptedDestination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceRecoveryKey: exported.state_rekey_key,
      destinationSignerIdentityId: acceptedDestinationIdentityId,
      acceptCompromisedRotationKeys: true,
    });

    expect(imported.state.imported_keys).toBe(2);
    expect(imported.rotation).toMatchObject({
      compromised_hops: 1,
      entries_admitted_by_compromised_retired_key: 1,
    });
    const entry = await readStateEntry(
      acceptedDestination.storage,
      "notes",
      "before-compromise",
    );
    expect(entry.metadata.tags).toContain("source-key:compromised-rotation");
  });
});
