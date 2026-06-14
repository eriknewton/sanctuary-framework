import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { createL4Tools } from "../../src/l4-reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  verifyExitBundle,
  ExitBundleImportError,
} from "../../src/exit/index.js";
import { sign as identitySign } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  canonicalize,
  canonicalizeToBytes,
} from "../../src/mesh/canonical-json.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hash as sha256 } from "../../src/core/hashing.js";

interface ToolDef {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
  }>;
}

async function callTool(
  tools: ToolDef[],
  name: string,
  args: Record<string, unknown> = {}
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
    tools: [...l1Tools, ...l4Tools] as ToolDef[],
  };
}

async function exportFromSource(
  source: Awaited<ReturnType<typeof makeHarness>>,
  bundleDir: string,
  stateNamespaces: string[] = []
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
    stateNamespaces,
    keySource: "recovery-key",
  });
}

describe("Exit bundle hardening (full-sweep #54 + #55)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("#54: refuses identity overwrite without forceRebind, allows it with forceRebind, records audit", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "source-agent" });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-hardening-54-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    const destination = await makeHarness();
    await callTool(destination.tools, "identity_create", { label: "dest-default" });

    // First import: destination has a different identity, so forceRebind is
    // required (Finding RRR guard fires on mismatched active identity).
    const firstImport = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
    });
    expect(firstImport.activated).toBe(true);
    expect(firstImport.staged_artifacts).toContain("public_identity");

    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
      })
    ).rejects.toThrow(ExitBundleImportError);

    let caught: ExitBundleImportError | null = null;
    try {
      await importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
      });
    } catch (err) {
      caught = err as ExitBundleImportError;
    }
    expect(caught).toBeInstanceOf(ExitBundleImportError);
    expect(caught?.code).toBe("IDENTITY_OVERWRITE_REFUSED");

    const dryRun = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: false,
    });
    expect(dryRun.conflicts.public_identity_exists).toBe(true);
    expect(dryRun.activated).toBe(false);

    const forced = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
    });
    expect(forced.verified).toBe(true);
    expect(forced.activated).toBe(true);
    expect(forced.conflicts.public_identity_exists).toBe(true);
    expect(forced.staged_artifacts).toContain("public_identity");

    await destination.auditLog.flush();
    const audit = await destination.auditLog.query({
      operation_type: "exit_bundle_force_rebind",
      limit: 10,
    });
    expect(audit.total).toBeGreaterThanOrEqual(1);
  });

  it("#55: verifier fails bundle when an attestation has an unverifiable signer; passes with explicit opt-in", async () => {
    const source = await makeHarness();
    const primary = await callTool(source.tools, "identity_create", {
      label: "source-default",
    });
    const secondary = await callTool(source.tools, "identity_create", {
      label: "source-secondary",
    });
    const secondaryIdentityId = secondary.identity_id as string;

    await callTool(source.tools, "reputation_record", {
      interaction_id: "bundle-laundering-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 100 },
      },
      context: "exit-hardening",
      identity_id: secondaryIdentityId,
    });

    expect(typeof primary.identity_id).toBe("string");

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-hardening-55-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    const strict = await verifyExitBundle(bundleDir);
    expect(strict.passed).toBe(false);
    // Full-sweep #77 narrowed this from generic "other" to the
    // specific class so importers can branch without parsing warnings.
    expect(strict.failure_class).toBe("reputation_unverifiable_attestations");
    expect(strict.reputation?.unverifiable_attestations).toBe(1);
    expect(strict.warnings.some((w) => /accept-unverifiable-attestations/.test(w))).toBe(
      true
    );

    const relaxed = await verifyExitBundle(bundleDir, {
      acceptUnverifiableAttestations: true,
    });
    expect(relaxed.passed).toBe(true);
    expect(relaxed.reputation?.unverifiable_attestations).toBe(1);

    const destination = await makeHarness();
    const importStrict = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
    });
    expect(importStrict.verified).toBe(false);
    expect(importStrict.activated).toBe(false);
    expect(importStrict.staged_artifacts).toEqual([]);

    const destination2 = await makeHarness();
    const importRelaxed = await importExitBundle({
      bundleDir,
      storage: destination2.storage,
      masterKey: destination2.masterKey,
      identityManager: destination2.identityManager,
      auditLog: destination2.auditLog,
      reputationStore: destination2.reputationStore,
      activate: true,
      acceptUnverifiableAttestations: true,
    });
    expect(importRelaxed.verified).toBe(true);
    expect(importRelaxed.activated).toBe(true);
    expect(importRelaxed.reputation.unverifiable_attestations).toBe(1);
  });

  // Per full-sweep #77: helpers for tampering with internal artifact
  // signatures while keeping the per-file artifact hash + manifest
  // aggregate hash + manifest signature consistent. These tests verify
  // the verifier surfaces the *specific* failure class instead of the
  // generic "other".
  function sha256Hex(bytes: Uint8Array): string {
    return Array.from(sha256(bytes))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function jsonBytes(value: unknown): Uint8Array {
    return stringToBytes(JSON.stringify(value, null, 2) + "\n");
  }

  async function tamperArtifactInternalField(
    bundleDir: string,
    artifactKind: string,
    mutate: (parsed: Record<string, unknown>) => Record<string, unknown>,
    source: Awaited<ReturnType<typeof makeHarness>>
  ): Promise<void> {
    const manifestPath = join(bundleDir, "manifest.json");
    const rawManifest = await readFile(manifestPath, "utf8");
    const manifest = JSON.parse(rawManifest) as {
      body: {
        artifacts: Array<{
          kind: string;
          path: string;
          hash_alg: string;
          hash: string;
          size_bytes: number;
        }>;
        artifacts_aggregate_hash: string;
      };
      signature: string;
    };
    const entry = manifest.body.artifacts.find(
      (artifact) => artifact.kind === artifactKind
    );
    if (!entry) {
      throw new Error(
        `tamperArtifactInternalField: no artifact of kind ${artifactKind}`
      );
    }
    const artifactPath = join(bundleDir, entry.path);
    const parsed = JSON.parse(await readFile(artifactPath, "utf8")) as Record<
      string,
      unknown
    >;
    const tampered = mutate(parsed);
    const newBytes = jsonBytes(tampered);
    await writeFile(artifactPath, newBytes);
    entry.hash = sha256Hex(newBytes);
    entry.size_bytes = newBytes.length;
    manifest.body.artifacts_aggregate_hash = sha256Hex(
      stringToBytes(canonicalize(manifest.body.artifacts))
    );
    const identity = source.identityManager.getDefault();
    if (!identity) throw new Error("no default identity");
    const identityEncryptionKey = derivePurposeKey(
      source.masterKey,
      "identity-encryption"
    );
    const signature = identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      identityEncryptionKey
    );
    manifest.signature = toBase64url(signature);
    await writeFile(manifestPath, jsonBytes(manifest));
  }

  it("#77: verifier surfaces identity_signature_invalid when public_identity signature is tampered", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "tampered-id" });
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-77-identity-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    // Replace the inner `signature` with a syntactically-valid but
    // cryptographically-wrong base64url string. The artifact-hash
    // check still passes because we recompute the artifact hash;
    // only the signature verification at line ~238 of verifier.ts
    // should fail, surfacing identity_signature_invalid.
    await tamperArtifactInternalField(
      bundleDir,
      "public_identity",
      (parsed) => ({
        ...parsed,
        signature: toBase64url(new Uint8Array(64)),
      }),
      source
    );

    const result = await verifyExitBundle(bundleDir);
    expect(result.passed).toBe(false);
    expect(result.failure_class).toBe("identity_signature_invalid");
    expect(result.identity?.signature_valid).toBe(false);
  });

  it("#77: verifier surfaces reputation_bundle_signature_invalid when reputation bundle signature is tampered", async () => {
    const source = await makeHarness();
    const created = await callTool(source.tools, "identity_create", {
      label: "tampered-rep",
    });
    const identityId = created.identity_id as string;
    await callTool(source.tools, "reputation_record", {
      interaction_id: "rep-tamper-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 50 },
      },
      context: "rep-tamper",
      identity_id: identityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-77-rep-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    // Replace bundle_signature with a wrong-but-well-formed base64url
    // value. Per the verifier flow, attestations whose signer DID is
    // present in publicKeysByDid still verify successfully; only the
    // bundle-level signature fails, isolating the
    // reputation_bundle_signature_invalid path.
    await tamperArtifactInternalField(
      bundleDir,
      "reputation_bundle",
      (parsed) => ({
        ...parsed,
        bundle_signature: toBase64url(new Uint8Array(64)),
      }),
      source
    );

    const result = await verifyExitBundle(bundleDir);
    expect(result.passed).toBe(false);
    expect(result.failure_class).toBe("reputation_bundle_signature_invalid");
    expect(result.reputation?.bundle_signature_valid).toBe(false);
  });

  it("#55: verifier still passes clean bundles with no unverifiable attestations", async () => {
    const source = await makeHarness();
    const primary = await callTool(source.tools, "identity_create", {
      label: "source-default",
    });
    const primaryIdentityId = primary.identity_id as string;

    await callTool(source.tools, "reputation_record", {
      interaction_id: "clean-bundle-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 75 },
      },
      context: "happy-path",
      identity_id: primaryIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-hardening-clean-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(true);
    expect(verified.reputation?.unverifiable_attestations).toBe(0);
    expect(verified.reputation?.verified_attestations).toBe(1);
  });
});
