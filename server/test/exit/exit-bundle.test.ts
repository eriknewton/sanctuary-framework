import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { ReputationStore } from "../../src/reputation/reputation-store.js";
import { CommitmentStore, createCommitment } from "../../src/disclosure/commitments.js";
import { PrivacyPlaceholderVault } from "../../src/operational/privacy-filter.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { fromBase64url } from "../../src/core/encoding.js";
import {
  exportExitBundle,
  importExitBundle,
  verifyExitBundle,
  exitBundleManifestShape,
} from "../../src/exit/index.js";

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
    tools: [...l1Tools, ...l4Tools],
  };
}

describe("SANCTUARY_EXIT_BUNDLE_V1", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exports, verifies, imports, and re-keys a harness migration drill", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;

    await callTool(source.tools, "state_write", {
      namespace: "agent-memory",
      key: "handoff",
      value: "durable state survives exit",
      identity_id: sourceIdentityId,
      metadata: { tags: ["drill"] },
    });
    await callTool(source.tools, "reputation_record", {
      interaction_id: "exit-drill-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 100 },
      },
      context: "exit-drill",
      identity_id: sourceIdentityId,
    });

    const commitments = new CommitmentStore(source.storage, source.masterKey);
    await commitments.store(createCommitment("sensitive commitment value"), "sensitive commitment value");
    const vault = new PrivacyPlaceholderVault(source.storage, source.masterKey);
    await vault.placeholderFor("email", "operator@example.com", sourceIdentityId);

    await source.auditLog.append("l1", "exit_drill_source_unwrap", sourceIdentityId, {
      harness: "source",
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-bundle-"));
    tempDirs.push(bundleDir);
    const exported = await exportExitBundle({
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
      keySource: "recovery-key",
    });

    expect(exported.manifest.body.manifest_version).toBe("SANCTUARY_EXIT_BUNDLE_V1");
    expect(exported.manifest.body.artifacts.map((a) => a.kind).sort()).toEqual([
      "audit_receipts",
      "commitments",
      "encrypted_state",
      // Exit V2 drill F2 (2026-08-22/23): new, additive, always-emitted
      // artifact kind (see EXIT_BUNDLE_ARTIFACT_KINDS's doc comment).
      "known_signers",
      "placeholder_vault_metadata",
      "policy_set",
      "public_identity",
      "reputation_bundle",
    ]);

    const publicIdentityText = await readFile(
      join(bundleDir, "artifacts", "public_identity.json"),
      "utf8"
    );
    expect(publicIdentityText).not.toContain("encrypted_private_key");
    expect(publicIdentityText).not.toContain("passphrase");
    const encryptedStateText = await readFile(
      join(bundleDir, "artifacts", "encrypted_state.json"),
      "utf8"
    );
    expect(encryptedStateText).not.toContain("encrypted_private_key");
    expect(encryptedStateText).not.toContain("passphrase");

    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(true);
    expect(verified.reputation?.bundle_signature_valid).toBe(true);
    expect(verified.reputation?.completeness).toBe("verified");
    expect(verified.reputation?.verified_attestations).toBe(1);
    expect(verified.audit?.individual_signatures_verified).toBe(false);
    expect(verified.unsupported_artifacts.join("\n")).toContain(
      "legacy L2 audit log"
    );
    const auditReceipts = JSON.parse(
      await readFile(join(bundleDir, "artifacts", "audit_receipts.json"), "utf8")
    ) as {
      recovery_semantics: string;
      normal_audit_query_continuity: boolean;
      entries: Array<{ operation: string }>;
    };
    expect(auditReceipts.recovery_semantics).toBe("archive_only");
    expect(auditReceipts.normal_audit_query_continuity).toBe(false);
    expect(auditReceipts.entries.map((entry) => entry.operation)).toContain(
      "exit_drill_source_unwrap"
    );

    const destination = await makeHarness();
    const destinationIdentity = await callTool(
      destination.tools,
      "identity_create",
      { label: "destination-import-signer" }
    );
    const destinationIdentityId = destinationIdentity.identity_id as string;

    const planned = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: false,
    });
    expect(planned.verified).toBe(true);
    expect(planned.activated).toBe(false);
    expect(planned.conflicts.state_conflicts).toEqual([]);

    // forceRebind required: destination has its own identity (Finding RRR).
    const imported = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceMasterKey: source.masterKey,
      destinationSignerIdentityId: destinationIdentityId,
    });
    expect(imported.verified).toBe(true);
    expect(imported.activated).toBe(true);
    expect(imported.state.status).toBe("rekeyed");
    expect(imported.state.imported_keys).toBe(1);
    expect(imported.reputation.imported_attestations).toBe(1);
    expect(imported.staged_artifacts).toContain("public_identity");
    expect(imported.staged_artifacts).toContain("audit_receipts");
    expect(imported.staged_artifacts).toContain("placeholder_vault_metadata");

    const read = await destination.stateStore.read("agent-memory", "handoff");
    expect(read?.value).toBe("durable state survives exit");
    expect(read?.written_by).toBe(destinationIdentityId);

    const sourcePub = source.identityManager.get(sourceIdentityId)!.public_key;
    const sourcePubBytes = fromBase64url(sourcePub);
    await expect(
      destination.stateStore.read("agent-memory", "handoff", sourcePubBytes)
    ).rejects.toThrow(/Signature verification failed/);

    const reputationStore = new ReputationStore(destination.storage, destination.masterKey);
    const reputation = await reputationStore.query({ context: "exit-drill" });
    expect(reputation.total_interactions).toBe(1);
    expect(reputation.completed).toBe(1);

    const publicIdentityEntries = await destination.storage.list("_exit_public_identities");
    expect(publicIdentityEntries.map((entry) => entry.key)).toContain(sourceIdentityId);
    const auditReceiptEntries = await destination.storage.list("_exit_audit_receipts");
    expect(auditReceiptEntries.length).toBe(1);
    const importedSourceAudit = await destination.auditLog.query({
      operation_type: "exit_drill_source_unwrap",
      limit: 10,
    });
    expect(importedSourceAudit.total).toBe(0);

    await destination.auditLog.append("l1", "exit_drill_destination_wrap", destinationIdentityId, {
      imported_identity_id: sourceIdentityId,
    });
    await destination.auditLog.flush();
    const destinationAudit = await destination.auditLog.query({
      operation_type: "exit_drill_destination_wrap",
      limit: 10,
    });
    expect(destinationAudit.total).toBe(1);
  });

  it("reports the stable manifest shape for dashboard/API consumers", () => {
    const shape = exitBundleManifestShape();
    expect(shape).toMatchObject({
      manifest_version: "SANCTUARY_EXIT_BUNDLE_V1",
      hash_alg: "sha256",
      signature_scheme: "ed25519-v1",
      required_top_level_file: "manifest.json",
    });
    expect(shape.artifacts).toContain("public_identity");
    expect(shape.artifacts).toContain("placeholder_vault_metadata");
  });

  it("refuses staged _exit artifact conflicts without explicit overwrite", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;
    await callTool(source.tools, "state_write", {
      namespace: "agent-memory",
      key: "handoff",
      value: "durable state survives exit",
      identity_id: sourceIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-repeat-"));
    tempDirs.push(bundleDir);
    await exportExitBundle({
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
      keySource: "recovery-key",
    });
    const manifest = JSON.parse(
      await readFile(join(bundleDir, "manifest.json"), "utf8"),
    ) as {
      body: {
        exported_at: string;
        identity_binding: { identity_id: string };
      };
    };
    const importId = `${manifest.body.identity_binding.identity_id}-${manifest.body.exported_at.replace(/[^0-9a-zA-Z_.-]/g, "_")}`;

    const destination = await makeHarness();
    await destination.storage.write(
      "_exit_policy_sets",
      importId,
      new TextEncoder().encode("{}"),
    );
    const commonImport = {
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      sourceMasterKey: source.masterKey,
    };
    await expect(importExitBundle(commonImport)).rejects.toMatchObject({
      code: "STAGED_ARTIFACT_CONFLICT",
    });
    const destinationIdentity = await callTool(destination.tools, "identity_create", {
      label: "destination-import-signer",
    });
    await expect(
      importExitBundle({
        ...commonImport,
        forceRebind: true,
        conflictResolution: "overwrite",
        destinationSignerIdentityId: destinationIdentity.identity_id as string,
      }),
    ).resolves.toMatchObject({ activated: true });
    expect((await destination.storage.list("_exit_policy_sets")).length).toBe(1);
  });

  it("derives the fallback export_approval_audit_id from the injected clock, so the signed manifest is reproducible across runs", async () => {
    const fixedNow = () => new Date("2026-01-01T00:00:00.000Z");
    const expectedAuditId = `exit-export-${fixedNow().getTime()}`;

    async function exportWithFixedClock(): Promise<{
      export_approval_audit_id: string;
      exported_at: string;
    }> {
      const source = await makeHarness();
      const sourceIdentity = await callTool(source.tools, "identity_create", {
        label: "source-agent",
      });
      const sourceIdentityId = sourceIdentity.identity_id as string;
      await callTool(source.tools, "state_write", {
        namespace: "agent-memory",
        key: "handoff",
        value: "durable state survives exit",
        identity_id: sourceIdentityId,
      });

      const bundleDir = await mkdtemp(
        join(tmpdir(), "sanctuary-exit-clock-determinism-")
      );
      tempDirs.push(bundleDir);
      const exported = await exportExitBundle({
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
        keySource: "recovery-key",
        now: fixedNow,
        // exportApprovalAuditId intentionally omitted: this exercises the
        // internally-generated fallback id, which must derive from the
        // injected clock rather than a fresh ambient wall-clock read.
      });
      return {
        export_approval_audit_id: exported.manifest.body.export_approval_audit_id,
        exported_at: exported.manifest.body.exported_at,
      };
    }

    const runOne = await exportWithFixedClock();
    const runTwo = await exportWithFixedClock();

    // Fail-before: prior to the fix, the fallback export_approval_audit_id
    // came from a bare `Date.now()` call, so two runs (even with the same
    // injected `now`) produced different ids and the SIGNED manifest body
    // was not reproducible despite the caller pinning the export clock.
    expect(runOne.export_approval_audit_id).toBe(expectedAuditId);
    expect(runTwo.export_approval_audit_id).toBe(expectedAuditId);
    expect(runOne.export_approval_audit_id).toBe(
      runTwo.export_approval_audit_id
    );
    expect(runOne.exported_at).toBe(runTwo.exported_at);
  });
});
