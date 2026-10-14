import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { createIdentity } from "../../src/core/identity.js";
import {
  derivePurposeKey,
  IDENTITY_ENCRYPTION_PURPOSE,
} from "../../src/core/key-derivation.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { SentinelDispatcher } from "../../src/sentinel/sentinel-dispatcher.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import { SentinelRegistry } from "../../src/sentinel/sentinel-registry.js";
import type { SentinelFinding } from "../../src/sentinel/types.js";
import { upsertPersistedLocalAgent } from "../../src/hub/agent-registry-persistence.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../src/dashboard/v1_1/wiring.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import type {
  ApprovalRequest,
  PrincipalPolicy,
} from "../../src/principal-policy/types.js";
import type { BaselineTracker } from "../../src/principal-policy/baseline.js";

const DEFAULT_PORT = 3517;
const HOST = "127.0.0.1";
const DEMO_PASSPHRASE_ENV = "SANCTUARY_PASSPHRASE";

export interface SeedDemoFortressOptions {
  home?: string;
  storagePath?: string;
  passphrase: string;
  port?: number;
  authToken?: string;
  startDashboard?: boolean;
  removeOnStop?: boolean;
  now?: () => Date;
}

export interface SeededDemoItem {
  item: string;
  producedBy: string;
  readPath: string;
  status: "seeded" | "not_available";
  note?: string;
}

export interface SeedDemoFortressResult {
  home: string;
  storagePath: string;
  port: number;
  host: string;
  fortressId: string;
  dashboardUrl: string;
  apiBaseUrl: string;
  authToken: string;
  agentIds: string[];
  pendingApprovalIds: string[];
  findingId: string;
  seededItems: SeededDemoItem[];
  touchedPaths: string[];
  stop: () => Promise<void>;
}

interface DemoEnvSnapshot {
  HOME?: string;
  SANCTUARY_STORAGE_PATH?: string;
  SANCTUARY_DASHBOARD_AUTO_OPEN?: string;
  SANCTUARY_PASSPHRASE?: string;
}

function snapshotEnv(): DemoEnvSnapshot {
  return {
    HOME: process.env.HOME,
    SANCTUARY_STORAGE_PATH: process.env.SANCTUARY_STORAGE_PATH,
    SANCTUARY_DASHBOARD_AUTO_OPEN: process.env.SANCTUARY_DASHBOARD_AUTO_OPEN,
    SANCTUARY_PASSPHRASE: process.env.SANCTUARY_PASSPHRASE,
  };
}

function restoreEnv(snapshot: DemoEnvSnapshot): void {
  for (const key of Object.keys(snapshot) as Array<keyof DemoEnvSnapshot>) {
    const value = snapshot[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}

function demoPolicy(): PrincipalPolicy {
  return {
    identities: {},
    tiers: {
      l1_cognitive: { require_human_approval: true },
      l2_operational: { require_human_approval: true },
      l3_substrate: { require_human_approval: false },
    },
    rules: [],
    approval_channels: [],
  } as unknown as PrincipalPolicy;
}

function demoBaseline(): BaselineTracker {
  return {
    isAnomalous: () => false,
    record: () => undefined,
  } as unknown as BaselineTracker;
}

function assertInside(root: string, candidate: string): void {
  const resolvedRoot = resolve(root);
  const resolvedCandidate = resolve(candidate);
  if (
    resolvedCandidate !== resolvedRoot &&
    !resolvedCandidate.startsWith(`${resolvedRoot}/`)
  ) {
    throw new Error(`demo seed path escaped temp root: ${resolvedCandidate}`);
  }
}

function makeAgentRecord(
  index: number,
  identityId: string,
  fortressId: string,
  nowIso: string,
): LocalAgentRecord {
  const harnesses: LocalAgentRecord["harness"][] = [
    "claude_code",
    "cursor",
    "openclaw",
    "hermes",
  ];
  const models = [
    "gpt-5.5-high-demo",
    "claude-opus-demo",
    "qwen-local-demo",
    "gemini-pro-demo",
  ];
  const agentId = `demo-agent-${index + 1}`;
  return {
    version: "1.1",
    agent_id: agentId,
    protection_subject: `${fortressId}/uid-50${index + 1}`,
    identity_id: identityId,
    harness: harnesses[index] ?? "other",
    harness_version: "demo-fixture",
    model_provider: {
      vendor: index === 2 ? "local" : "demo",
      model_id: models[index] ?? "demo-model",
      runs_locally: index === 2,
    },
    policy_id: "demo-policy/tiered-operator-gates",
    channel_template_id: index === 0 ? "demo-template/review" : undefined,
    status: index === 2 ? "locked_down" : "active",
    status_reason_class: index === 2 ? "operator_lockdown" : undefined,
    budget_summary: {
      daily: { unit: "usd", cap: 5, used: 0.25 + index * 0.1, soft_warn: 0.8 },
      monthly: { unit: "usd", cap: 50, used: 4 + index, soft_warn: 0.8 },
      last_refreshed_at: nowIso,
    },
    last_activity_at: nowIso,
    wrapped_at: nowIso,
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

function makeApprovalRequests(nowIso: string): ApprovalRequest[] {
  return [
    {
      operation: "demo_agent_unwrap_request",
      tier: 1,
      reason: "Demo fixture: operator must approve removing protection.",
      context: { agent_id: "demo-agent-1", demo_fixture: true },
      timestamp: nowIso,
      args_binding: "demo-agent-1:unwrap",
    },
    {
      operation: "demo_policy_template_change",
      tier: 1,
      reason: "Demo fixture: operator must approve changing the channel template.",
      context: { agent_id: "demo-agent-2", demo_fixture: true },
      timestamp: nowIso,
      args_binding: "demo-agent-2:template",
    },
  ];
}

export async function seedDemoFortress(
  options: SeedDemoFortressOptions,
): Promise<SeedDemoFortressResult> {
  if (!options.passphrase) {
    throw new Error(`${DEMO_PASSPHRASE_ENV} is required for the demo fortress.`);
  }

  const envSnapshot = snapshotEnv();
  const home =
    options.home ?? (await mkdtemp(join(tmpdir(), "sanctuary-demo-fortress-")));
  const storagePath = options.storagePath ?? join(home, ".sanctuary");
  assertInside(home, storagePath);
  await mkdir(storagePath, { recursive: true, mode: 0o700 });

  process.env.HOME = home;
  process.env.SANCTUARY_STORAGE_PATH = storagePath;
  process.env.SANCTUARY_DASHBOARD_AUTO_OPEN = "false";
  process.env.SANCTUARY_PASSPHRASE = options.passphrase;

  const storage = new FilesystemStorage(join(storagePath, "state"));
  const custody = await establishMaster({
    storage,
    passphrase: options.passphrase,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
    storagePathHint: storagePath,
  });
  const masterKey = custody.masterKey;
  let stopped = false;
  let dashboard: DashboardApprovalChannel | null = null;
  let dispatcher: SentinelDispatcher | null = null;

  try {
    const auditLog = new AuditLog(storage, masterKey);
    const identityManager = new IdentityManager(storage, masterKey);
    await identityManager.load();
    const now = options.now ?? (() => new Date());
    const nowIso = now().toISOString();
    const fortressId = `demo-${fortressIdFromStoragePath(storagePath)}`;
    const authToken =
      options.authToken ?? `demo-${randomBytes(16).toString("hex")}`;
    const identities = [];
    const identityEncryptionKey = derivePurposeKey(
      masterKey,
      IDENTITY_ENCRYPTION_PURPOSE,
    );
    for (const label of [
      "demo operator",
      "demo reviewer agent",
      "demo local agent",
      "demo watcher agent",
    ]) {
      const { storedIdentity: identity } = createIdentity(
        label,
        identityEncryptionKey,
        "passphrase",
      );
      await identityManager.saveNew(identity);
      await auditLog.appendCritical({
        layer: "l1",
        operation: "identity_create",
        identity_id: identity.identity_id,
        result: "success",
        details: { demo_fixture: true, label },
      });
      identities.push(identity);
    }
    const operatorIdentityId = identities[0]?.identity_id;
    if (!operatorIdentityId) throw new Error("demo identity creation failed");

    const agentRecords = identities.map((_, index) =>
      makeAgentRecord(index, operatorIdentityId, fortressId, nowIso),
    );
    for (const record of agentRecords) {
      upsertPersistedLocalAgent(storagePath, record);
      await auditLog.appendCritical({
        layer: "l2",
        operation: "demo_agent_registered",
        identity_id: record.identity_id,
        result: "success",
        details: {
          demo_fixture: true,
          agent_id: record.agent_id,
          harness: record.harness,
          fortress_id: fortressId,
        },
      });
    }

    const findingStore = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId,
      auditLog,
      now,
    });
    dispatcher = new SentinelDispatcher({
      registry: new SentinelRegistry(),
      findingStore,
      auditLog,
      fortressId,
      identityId: operatorIdentityId,
      now,
      tickIntervalMs: 0,
    });
    const finding = await dispatcher.reportFinding("demo-sentinel", {
      finding_id: "",
      sentinel_id: "demo-sentinel",
      severity: "warn",
      agent_id: "demo-agent-3",
      summary: "Demo sentinel flagged a protected-agent burst.",
      details: {
        source: "scripts/demo/seed-fortress-lib",
        signal: "demo_fixture",
      },
      observed_at: nowIso,
      evidence_audit_ids: [`${nowIso}:demo_agent_registered`],
      fortress_id: fortressId,
    } satisfies SentinelFinding);

    await auditLog.flush();
    const chainRead = await auditLog.query({ limit: 100 });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "demo_audit_chain_verified",
      identity_id: operatorIdentityId,
      result: chainRead.integrity_findings.length === 0 ? "success" : "failure",
      details: {
        demo_fixture: true,
        entries_seen: chainRead.entries.length,
        integrity_findings: chainRead.integrity_findings.length,
      },
    });
    await auditLog.flush();

    const port = options.port ?? DEFAULT_PORT;
    const apiBaseUrl = `http://${HOST}:${port}`;
    let pendingApprovalIds: string[] = [];

    if (options.startDashboard !== false) {
      dashboard = new DashboardApprovalChannel({
        port,
        host: HOST,
        timeout_seconds: 60 * 60,
        auth_token: authToken,
        auto_open: false,
        shutdown_grace_ms: 250,
      });
      dashboard.setDependencies({
        policy: demoPolicy(),
        baseline: demoBaseline(),
        auditLog,
        identityManager,
        storage,
      });
      dashboard.setSentinelDispatcher(dispatcher);
      dashboard.setV11Bindings(
        buildV11Bindings({
          identityId: operatorIdentityId,
          fortressId,
          auditLog,
          storagePath,
          storage,
          masterKey,
          identityManager,
          policy: demoPolicy(),
          sentinelFindingStore: findingStore,
        }),
      );
      await dashboard.start();
      const holds = makeApprovalRequests(nowIso).map((request) => {
        const promise = dashboard!.requestApproval(request);
        void promise.catch(() => undefined);
        return request;
      });
      await auditLog.appendCritical({
        layer: "l1",
        operation: "demo_pending_approvals_opened",
        identity_id: operatorIdentityId,
        result: "success",
        details: {
          demo_fixture: true,
          count: holds.length,
        },
      });
      await auditLog.flush();
      const pendingResponse = await fetch(`${apiBaseUrl}/api/pending`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (pendingResponse.ok) {
        const pending = (await pendingResponse.json()) as Array<{ id?: unknown }>;
        pendingApprovalIds = pending
          .map((item) => item.id)
          .filter((id): id is string => typeof id === "string");
      }
    }

    const result: SeedDemoFortressResult = {
      home,
      storagePath,
      port,
      host: HOST,
      fortressId,
      dashboardUrl: `${apiBaseUrl}/v1.1`,
      apiBaseUrl,
      authToken,
      agentIds: agentRecords.map((record) => record.agent_id),
      pendingApprovalIds,
      findingId: finding.finding_id,
      touchedPaths: [home, storagePath, join(storagePath, "state")],
      seededItems: [
        {
          item: "four protected agents",
          producedBy: "upsertPersistedLocalAgent, the same hub registry path that protecting an agent uses",
          readPath: "GET /api/hub/agents",
          status: "seeded",
        },
        {
          item: "two pending approvals",
          producedBy: "DashboardApprovalChannel.requestApproval",
          readPath: "GET /api/pending",
          status: "seeded",
        },
        {
          item: "one Sentinel finding",
          producedBy: "SentinelDispatcher.reportFinding",
          readPath: "GET /api/sentinels/findings",
          status: "seeded",
        },
        {
          item: "verified audit chain marker",
          producedBy: "AuditLog.query over the persisted chain, then AuditLog.appendCritical",
          readPath: "GET /api/audit-log",
          status: "seeded",
        },
        {
          item: "blocked egress event",
          producedBy: "No macOS kernel-enforcer verdict is minted by this fixture",
          readPath: "GET /api/audit-log",
          status: "not_available",
          note: "The demo reports this honestly instead of fabricating an OS egress verdict.",
        },
      ],
      stop: async () => {
        if (stopped) return;
        stopped = true;
        try {
          await dashboard?.stop();
          await dispatcher?.dispose();
          await auditLog.flush();
        } finally {
          const barrier = custody.masterWriteBarrier;
          if (barrier) await barrier.release();
          restoreEnv(envSnapshot);
          if (options.removeOnStop === true) {
            await rm(home, { recursive: true, force: true });
          }
        }
      },
    };
    return result;
  } catch (error) {
    try {
      await dashboard?.stop();
      await dispatcher?.dispose();
      const barrier = custody.masterWriteBarrier;
      if (barrier) await barrier.release();
    } finally {
      restoreEnv(envSnapshot);
      if (options.removeOnStop === true) {
        await rm(home, { recursive: true, force: true });
      }
    }
    throw error;
  }
}

export const DEMO_SEED_DEFAULT_PORT = DEFAULT_PORT;
