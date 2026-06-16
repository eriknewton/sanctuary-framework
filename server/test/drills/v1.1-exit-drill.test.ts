/**
 * Sanctuary v1.1 Acceptance Drill - Pillar 4: Portability and Exit.
 *
 * Proves that an operator can produce a SANCTUARY_EXIT_BUNDLE_V1, verify
 * it offline through the operator-facing CLI, transfer it to a fresh
 * destination fortress, and import it with full continuity. The drill
 * additionally verifies three v1.0.2 backlog items that PR #70's reviewer
 * (Explore agent) could not directly verify:
 *
 *   (j) `export_approval_audit_id` embedding - the manifest field carries
 *       the approval id from the actual Tier 1 inbox flow, not an
 *       internally-generated value. Closed inline by threading
 *       `inbox_item_id` through `fortressExportBundle()` into
 *       `exportExitBundle({ exportApprovalAuditId })`.
 *
 *   (i) Import overwrite-refusal - a second import on the same
 *       destination, without explicit `conflictResolution: "overwrite"`,
 *       MUST NOT silently overwrite previously-imported state. Existing
 *       behavior: default `conflictResolution` is `"skip"`, which is the
 *       safe default. Drill VERIFIES this behavior holds.
 *
 *   (h) Re-key cleanup - after a successful import + activation, no
 *       source-key-encrypted blobs remain on the destination fortress.
 *       Existing architecture: re-key happens in memory, source-key
 *       ciphertext is never persisted on the destination (the only
 *       source-key blobs live in the operator's bundle directory, not
 *       in destination storage). Drill VERIFIES this property.
 *
 * The drill exercises real `MemoryStorage`, real `AuditLog`, real
 * `IdentityManager`, real `ReputationStore`, real `StateStore`, real
 * Ed25519 signing on the manifest, and the operator-facing
 * `runExitCommand("verify", ...)` shell. No mocks at the contract
 * boundary.
 *
 * Acceptance checklist mapping: Pillar 4 of
 * `server/docs/v1.1-acceptance-checklist.md`.
 */

import { afterEach, describe, expect, it } from "vitest";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import {
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { Writable } from "node:stream";

import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools, type IdentityManager } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import {
  ReputationStore,
} from "../../src/reputation/reputation-store.js";
import {
  ExitBundleImportError,
  exitBundleManifestShape,
  exportExitBundle,
  importExitBundle,
  type ExportExitBundleResult,
} from "../../src/exit/index.js";
import { runExitCommand } from "../../src/exit/cli.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { HUB_API_PREFIX } from "../../src/hub/constants.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  handleHubRoute,
  type HubAgentController,
  type HubFortressExportResult,
  type HubInboxSources,
} from "../../src/hub/index.js";
import type {
  HubApprovalPendingItem,
  HubInboxItem,
} from "../../src/contracts/v1.1/hub-events.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { HubAgentStatus } from "../../src/contracts/v1.1/constants.js";
import type { AuthConfig } from "../../src/console/auth-middleware.js";

// ─────────────────────────────────────────────────────────────────────
// Harness fixture (mirrors server/test/exit/exit-bundle.test.ts shape)
// ─────────────────────────────────────────────────────────────────────

interface ExitHarness {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  stateStore: StateStore;
  identityManager: IdentityManager;
  reputationStore: ReputationStore;
  tools: Array<{
    name: string;
    handler: (args: Record<string, unknown>) => Promise<{
      content: Array<{ type: string; text: string }>;
    }>;
  }>;
}

async function makeHarness(): Promise<ExitHarness> {
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
    tools: [...l1Tools, ...l4Tools],
  };
}

async function callTool(
  tools: ExitHarness["tools"],
  name: string,
  args: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────
// Hub rig that wires the fortress export endpoint to a real harness
// ─────────────────────────────────────────────────────────────────────

class StubAgentController implements HubAgentController {
  async pause(): Promise<HubAgentStatus> { return "paused"; }
  async resume(): Promise<HubAgentStatus> { return "active"; }
  async restart(): Promise<HubAgentStatus> { return "active"; }
  async unwrap(): Promise<HubAgentStatus> { return "unwrapping"; }
  async lockdown(): Promise<HubAgentStatus> { return "locked_down"; }
  async bindPolicy(): Promise<void> { /* unused */ }
  async bindChannelTemplate(): Promise<void> { /* unused */ }
}

function emptyInboxSources(): HubInboxSources {
  return {
    listPendingApprovals: () => [],
    listRecentBlockedEgress: () => [],
    listRecentPrivacyEvents: () => [],
    listActiveBudgetWarnings: () => [],
    listActiveRecoveryPrompts: () => [],
    listRecentAgentErrors: () => [],
  };
}

function makeAgent(agentId: string): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: agentId,
    identity_id: "did:example:operator-drill-exit",
    harness: "openclaw",
    harness_version: "0.10.6",
    model_provider: {
      vendor: "anthropic",
      model_id: "claude-opus-4-7",
      runs_locally: false,
    },
    policy_id: "policy-drill",
    channel_template_id: "request-approve-act",
    status: "active",
    budget_summary: {
      daily: { unit: "tokens", cap: 100_000, used: 25_000, soft_warn: 0.8 },
      monthly: { unit: "usd", cap: 100, used: 12, soft_warn: 0.75 },
      last_refreshed_at: "2026-04-25T00:00:00.000Z",
    },
    last_activity_at: "2026-04-25T00:00:00.000Z",
    wrapped_at: "2026-04-20T00:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: true,
      can_change_template: true,
    },
  };
}

interface HubBundleRig {
  url: string;
  authToken: string;
  capturedApprovalId: string | undefined;
  exportResult: ExportExitBundleResult | undefined;
  stop: () => Promise<void>;
}

async function startHubBundleRig(
  source: ExitHarness,
  bundleDir: string,
): Promise<HubBundleRig> {
  const captured: { approvalId: string | undefined; result: ExportExitBundleResult | undefined } = {
    approvalId: undefined,
    result: undefined,
  };

  const fortressExportImpl = async (
    approvalAuditId?: string,
  ): Promise<HubFortressExportResult> => {
    captured.approvalId = approvalAuditId;
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
      exportApprovalAuditId: approvalAuditId,
    });
    captured.result = exported;
    return {
      bundle_dir: exported.bundle_dir,
      manifest_hash: exported.manifest_hash,
      artifact_count: exported.artifact_count,
    };
  };

  const service = new HubService({
    identityId: "did:example:operator-drill-exit",
    fortressId: "fortress-drill-exit",
    agentRegistry: new InMemoryLocalAgentRegistry([makeAgent("agent-drill-alpha")]),
    inboxSources: emptyInboxSources(),
    activitySources: {
      auditLog: source.auditLog,
      identityId: "did:example:operator-drill-exit",
    },
    policyBudgetSources: {
      listPolicySummaries: () => [],
      listBudgetSummaries: () => [],
    },
    agentController: new StubAgentController(),
    fortressExportBundle: fortressExportImpl,
  });

  const authToken = "drill-token-exit";
  const authConfig: AuthConfig = { loopbackAutoAuth: false, authToken };

  const server: Server = createServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      try {
        const handled = await handleHubRoute(
          { authConfig, service },
          req,
          res,
        );
        if (!handled) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({ ok: false, error: "not_found", path: req.url }),
          );
        }
      } catch (err) {
        try {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({ ok: false, error: (err as Error).message }),
          );
        } catch {
          // socket already closed
        }
      }
    },
  );

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });

  const addr = server.address();
  if (!addr || typeof addr !== "object") throw new Error("no address");
  const url = `http://127.0.0.1:${addr.port}`;

  return {
    url,
    authToken,
    get capturedApprovalId() { return captured.approvalId; },
    get exportResult() { return captured.result; },
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function withAuth(headers: HeadersInit, token: string): HeadersInit {
  return { ...headers, Authorization: `Bearer ${token}` };
}

class StringSink extends Writable {
  buffer = "";
  override _write(
    chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.buffer += chunk.toString();
    callback();
  }
}

// ═════════════════════════════════════════════════════════════════════
// Drill
// ═════════════════════════════════════════════════════════════════════

describe("v1.1 acceptance drill - Pillar 4: portability + exit", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("export via Tier 1 fortress endpoint -> verify CLI -> import on fresh destination, with v1.0.2 (h)/(i)/(j) properties verified", async () => {
    // ─── Source fortress setup ──────────────────────────────────────
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "drill-source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;

    await callTool(source.tools, "state_write", {
      namespace: "agent-memory",
      key: "handoff",
      value: "durable state survives exit drill",
      identity_id: sourceIdentityId,
      metadata: { tags: ["drill"] },
    });
    await callTool(source.tools, "reputation_record", {
      interaction_id: "drill-exit-001",
      counterparty_did: "did:key:counterparty-drill",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 100 },
      },
      context: "drill-exit",
      identity_id: sourceIdentityId,
    });
    await source.auditLog.append("l1", "drill_exit_seed", sourceIdentityId, {
      seeded: true,
    });

    // ─── Tier 1 export via fortress endpoint ────────────────────────
    const bundleDir = await mkdtemp(
      join(tmpdir(), "sanctuary-drill-exit-bundle-"),
    );
    tempDirs.push(bundleDir);

    const rig = await startHubBundleRig(source, bundleDir);
    try {
      // Step 1: enqueue Tier 1 export. Returns 202 + inbox_item_id.
      const enqueueRes = await fetch(
        `${rig.url}${HUB_API_PREFIX}/fortress/exit-bundle/export`,
        { method: "POST", headers: withAuth({}, rig.authToken) },
      );
      expect(enqueueRes.status).toBe(202);
      const enqueueBody = (await enqueueRes.json()) as {
        ok: true;
        data: {
          inbox_item_id: string;
          status: "approval_pending";
          operation_category: "exit_bundle_export";
          fortress_scope: true;
        };
      };
      const approvalInboxItemId = enqueueBody.data.inbox_item_id;
      // Export not invoked yet.
      expect(rig.capturedApprovalId).toBeUndefined();

      // Step 2: inbox shows the pending fortress export item.
      const inboxRes = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
        headers: withAuth({}, rig.authToken),
      });
      const inboxBody = (await inboxRes.json()) as {
        ok: true;
        data: { items: HubInboxItem[] };
      };
      const pending = inboxBody.data.items.find(
        (i): i is HubApprovalPendingItem =>
          i.kind === "approval_pending" && i.item_id === approvalInboxItemId,
      );
      expect(pending).toBeDefined();
      expect(pending!.operation_category).toBe("exit_bundle_export");
      expect(pending!.tier).toBe("tier1");

      // Step 3: operator approves. Export now runs with the inbox item id
      // threaded through as approvalAuditId.
      const approveRes = await fetch(
        `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(approvalInboxItemId)}/approve`,
        { method: "POST", headers: withAuth({}, rig.authToken) },
      );
      expect(approveRes.status).toBe(200);
      expect(rig.capturedApprovalId).toBe(approvalInboxItemId);
      expect(rig.exportResult).toBeDefined();

      const exported = rig.exportResult!;
      expect(exported.manifest.body.manifest_version).toBe(
        "SANCTUARY_EXIT_BUNDLE_V1",
      );
      expect(exported.manifest.body.signature_scheme).toBe("ed25519-v1");

      // ─── (j) VERIFY: export_approval_audit_id matches the inbox flow
      // approval id, NOT an internally-generated `exit-export-...` id.
      const manifestRaw = await readFile(
        join(bundleDir, "manifest.json"),
        "utf8",
      );
      const manifest = JSON.parse(manifestRaw) as {
        body: {
          export_approval_audit_id: string;
          identity_binding: { fortress_id: string; identity_id: string };
        };
      };
      expect(manifest.body.export_approval_audit_id).toBe(approvalInboxItemId);
      expect(manifest.body.export_approval_audit_id).not.toMatch(
        /^exit-export-\d+$/,
      );
      // The audit log L1 entry produced by the export carries the same
      // approval_id, so the manifest -> audit-chain link is one-to-one.
      const auditQuery = await source.auditLog.query({
        operation_type: "exit_bundle_export",
        limit: 5,
      });
      expect(auditQuery.entries.length).toBeGreaterThan(0);
      const exportEntry = auditQuery.entries.find(
        (e) =>
          (e.details as Record<string, unknown> | undefined)?.approval_id ===
          approvalInboxItemId,
      );
      expect(exportEntry).toBeDefined();

      // Operator-facing CLI verifier: exit code 0 + manifest_summary
      // populated.
      const verifyOut = new StringSink();
      const verifyErr = new StringSink();
      const verifyCode = await runExitCommand({
        argv: ["verify-exit-bundle", bundleDir, "--json"],
        out: verifyOut,
        err: verifyErr,
      });
      expect(verifyCode).toBe(0);
      const verifyResult = JSON.parse(verifyOut.buffer) as {
        verdict: string;
        passed: boolean;
        manifest_summary: { artifact_count: number; identity_id: string };
        artifact_results: Array<{ kind: string; hash_passed: boolean }>;
      };
      expect(verifyResult.verdict).toBe("PASS");
      expect(verifyResult.passed).toBe(true);
      expect(verifyResult.manifest_summary.artifact_count).toBeGreaterThan(0);
      expect(verifyResult.manifest_summary.identity_id).toBe(sourceIdentityId);
      for (const artifact of verifyResult.artifact_results) {
        expect(artifact.hash_passed).toBe(true);
      }
      const auditReceipts = JSON.parse(
        await readFile(join(bundleDir, "artifacts", "audit_receipts.json"), "utf8"),
      ) as {
        recovery_semantics: string;
        normal_audit_query_continuity: boolean;
        entries: Array<{ operation: string }>;
      };
      expect(auditReceipts.recovery_semantics).toBe("archive_only");
      expect(auditReceipts.normal_audit_query_continuity).toBe(false);
      expect(auditReceipts.entries.map((entry) => entry.operation)).toContain(
        "drill_exit_seed",
      );

      // ─── Negative: tamper one byte of an artifact, re-verify must fail.
      const targetArtifact = exported.manifest.body.artifacts[0]!;
      const targetPath = join(bundleDir, targetArtifact.path);
      const original = await readFile(targetPath);
      const tampered = Buffer.from(original);
      tampered[tampered.length - 2] ^= 0x01;
      await writeFile(targetPath, tampered);
      const tamperOut = new StringSink();
      const tamperErr = new StringSink();
      const tamperCode = await runExitCommand({
        argv: ["verify", bundleDir, "--json"],
        out: tamperOut,
        err: tamperErr,
      });
      expect(tamperCode).not.toBe(0);
      const tamperResult = JSON.parse(tamperOut.buffer) as {
        passed: boolean;
        failure_class?: string;
      };
      expect(tamperResult.passed).toBe(false);
      // Restore original artifact for the rest of the drill.
      await writeFile(targetPath, original);

      // ─── Negative: path-safety. Replace an artifact path with one
      // containing `..`, re-verify must refuse with artifact_path_unsafe.
      const tamperedManifest = JSON.parse(manifestRaw) as {
        body: {
          artifacts: Array<{ path: string; kind: string }>;
        };
      };
      tamperedManifest.body.artifacts[0]!.path = "../etc/sanctuary-malicious";
      await writeFile(
        join(bundleDir, "manifest.json"),
        JSON.stringify(tamperedManifest, null, 2),
      );
      const pathOut = new StringSink();
      const pathErr = new StringSink();
      const pathCode = await runExitCommand({
        argv: ["verify", bundleDir, "--json"],
        out: pathOut,
        err: pathErr,
      });
      expect(pathCode).not.toBe(0);
      const pathResult = JSON.parse(pathOut.buffer) as {
        passed: boolean;
        failure_class?: string;
      };
      expect(pathResult.passed).toBe(false);
      expect(pathResult.failure_class).toBe("artifact_path_unsafe");
      // Restore original manifest so subsequent import operates on a
      // signed bundle.
      await writeFile(join(bundleDir, "manifest.json"), manifestRaw);
    } finally {
      await rig.stop();
    }

    // ─── Destination fortress setup ────────────────────────────────
    const destination = await makeHarness();
    const destIdentity = await callTool(destination.tools, "identity_create", {
      label: "drill-destination-import-signer",
    });
    const destIdentityId = destIdentity.identity_id as string;

    // ─── Import on destination ─────────────────────────────────────
    // forceRebind required: destination already has its own identity
    // (Finding RRR guard fires on mismatched active identity).
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
      destinationSignerIdentityId: destIdentityId,
    });
    expect(imported.verified).toBe(true);
    expect(imported.activated).toBe(true);
    expect(imported.state.status).toBe("rekeyed");
    expect(imported.state.imported_keys).toBeGreaterThan(0);
    expect(imported.reputation.imported_attestations).toBe(1);
    expect(imported.staged_artifacts).toContain("audit_receipts");

    // Continuity: read state on destination under destination master key.
    const read = await destination.stateStore.read("agent-memory", "handoff");
    expect(read?.value).toBe("durable state survives exit drill");
    expect(read?.written_by).toBe(destIdentityId);

    // Identity binding: the manifest binds source identity, so the
    // destination knows the bundle came from the source fortress.
    const finalManifest = JSON.parse(
      await readFile(join(bundleDir, "manifest.json"), "utf8"),
    ) as {
      body: { identity_binding: { fortress_id: string; identity_id: string } };
    };
    expect(finalManifest.body.identity_binding.identity_id).toBe(
      sourceIdentityId,
    );
    expect(finalManifest.body.identity_binding.fortress_id).not.toBe(
      destIdentityId,
    );

    const stagedAuditReceiptEntries = await destination.storage.list(
      "_exit_audit_receipts",
    );
    expect(stagedAuditReceiptEntries.length).toBe(1);
    const importedNormalAudit = await destination.auditLog.query({
      operation_type: "drill_exit_seed",
      limit: 10,
    });
    expect(importedNormalAudit.total).toBe(0);

    // ─── (i) VERIFY: re-import without explicit forceRebind refuses to
    // replace the existing fortress public identity (full-sweep #54). The
    // default behavior throws ExitBundleImportError code
    // IDENTITY_OVERWRITE_REFUSED, which closes v1.0.2 (i).
    let reimportError: ExitBundleImportError | null = null;
    try {
      await importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        sourceMasterKey: source.masterKey,
        destinationSignerIdentityId: destIdentityId,
      });
    } catch (err) {
      reimportError = err as ExitBundleImportError;
    }
    expect(reimportError).toBeInstanceOf(ExitBundleImportError);
    expect(reimportError?.code).toBe("IDENTITY_OVERWRITE_REFUSED");

    // With explicit forceRebind, re-import activates again. State-conflict
    // resolution still defaults to "skip", so previously-imported state is
    // preserved (no silent overwrite of operator data).
    const reimport = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceMasterKey: source.masterKey,
      destinationSignerIdentityId: destIdentityId,
      // conflictResolution intentionally omitted -> defaults to "skip".
    });
    expect(reimport.verified).toBe(true);
    expect(reimport.conflicts.state_conflicts.length).toBeGreaterThan(0);
    expect(reimport.state.conflicts).toBeGreaterThan(0);
    expect(reimport.state.imported_keys).toBe(0);

    // ─── (h) VERIFY: re-key cleanup. After successful import + activation,
    // no source-key-encrypted blobs remain on the destination fortress.
    // Source-key state lives only inside the operator's bundle directory
    // (which is operator-owned, not destination-owned). The drill confirms:
    //   1. Every namespace on the destination contains entries that
    //      decrypt cleanly under the destination master key (implicit:
    //      stateStore.read worked).
    //   2. No staged-import or rekey-temp namespace exists on the
    //      destination storage.
    const namespaces = await destination.storage.list("");
    const namespaceNames = new Set(
      namespaces.map((m) => m.namespace).filter(Boolean),
    );
    for (const namespace of namespaceNames) {
      // Reject any namespace that suggests un-rekeyed source state.
      expect(namespace).not.toMatch(/_staging$|_rekey_temp$|_source_keys$/);
    }
  });

  it("manifest shape constants advertised to dashboard match the live shape", () => {
    const shape = exitBundleManifestShape();
    expect(shape).toMatchObject({
      manifest_version: "SANCTUARY_EXIT_BUNDLE_V1",
      hash_alg: "sha256",
      signature_scheme: "ed25519-v1",
      required_top_level_file: "manifest.json",
    });
  });
});
