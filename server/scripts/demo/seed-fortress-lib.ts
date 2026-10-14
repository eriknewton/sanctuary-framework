import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
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
import { buildLocalAgentRecord } from "../../src/wrap/cli.js";
import type { AgentPlatform } from "../../src/wrap/config-reader.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../src/dashboard/v1_1/wiring.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { loadPrincipalPolicy } from "../../src/principal-policy/loader.js";

export const DEMO_TEMP_PREFIX = "sdf-";
// 3517 = the operator dashboard default plus 16, close enough for demos while avoiding the real menubar endpoint.
const DEFAULT_PORT = 3517;
const HOST = "127.0.0.1";
const DEMO_PASSPHRASE_ENV = "SANCTUARY_PASSPHRASE";
const CUSTODY_LOCK_ROOT_ENV = "SANCTUARY_CUSTODY_LOCK_ROOT";
// Must match DEFAULT_FORTRESS_ENDPOINT in menubar/src/main.ts.
export const OPERATOR_DASHBOARD_PORT = 3501;
const MAX_TCP_PORT = 65_535;
// 16 random bytes render as 32 hex chars, enough entropy for a local disposable bearer.
const DEMO_AUTH_TOKEN_RANDOM_BYTES = 16;
// The demo keeps two holds open for one hour; the README states this auto-deny bound.
const DEMO_APPROVAL_TIMEOUT_SECONDS = 60 * 60;
// Dashboard stop already closes local sockets; this short grace keeps test teardown fast.
const DEMO_DASHBOARD_SHUTDOWN_GRACE_MS = 250;
const DEMO_STORAGE_BASENAME = "demo-fortress";
// One-letter leaf keeps the composed socket path under KERNEL_SOCKET_PATH_MAX_BYTES in server/src/storage/cross-process-lock.ts.
const DEMO_CUSTODY_LOCK_BASENAME = "c";
const DEMO_OPERATOR_TOKEN_FILE_BASENAME = "operator-token.txt";
const OPERATOR_TOKEN_FILE_MODE = 0o600;
export const DEMO_STATE_EXPORT_OPERATION = "demo_state_export_request";
export const DEMO_POLICY_TEMPLATE_CHANGE_OPERATION =
  "demo_policy_template_change";
export const DEMO_AGENT_PLATFORMS: AgentPlatform[] = [
  "claude-code",
  "cursor",
  "openclaw",
  "hermes",
];

export interface SeedDemoFortressOptions {
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
  authTokenPath: string;
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
  SANCTUARY_CUSTODY_LOCK_ROOT?: string;
}

function snapshotEnv(): DemoEnvSnapshot {
  return {
    HOME: process.env.HOME,
    SANCTUARY_STORAGE_PATH: process.env.SANCTUARY_STORAGE_PATH,
    SANCTUARY_DASHBOARD_AUTO_OPEN: process.env.SANCTUARY_DASHBOARD_AUTO_OPEN,
    SANCTUARY_PASSPHRASE: process.env.SANCTUARY_PASSPHRASE,
    SANCTUARY_CUSTODY_LOCK_ROOT: process.env.SANCTUARY_CUSTODY_LOCK_ROOT,
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
  storagePath: string,
): LocalAgentRecord {
  return buildLocalAgentRecord({
    storagePath,
    platform: DEMO_AGENT_PLATFORMS[index] ?? "generic",
  });
}

export function demoTempParent(): string {
  return process.platform === "darwin" ? "/private/tmp" : tmpdir();
}

function makeApprovalRequests(nowIso: string, agentRecords: LocalAgentRecord[]): ApprovalRequest[] {
  const firstAgentId = agentRecords[0]?.agent_id ?? "fortress";
  const secondAgentId = agentRecords[1]?.agent_id ?? "fortress";
  return [
    {
      operation: DEMO_STATE_EXPORT_OPERATION,
      tier: 1,
      reason: "Demo fixture: operator must approve exporting demo state.",
      context: { agent_id: firstAgentId, demo_fixture: true },
      timestamp: nowIso,
      args_binding: `${firstAgentId}:state-export`,
    },
    {
      operation: DEMO_POLICY_TEMPLATE_CHANGE_OPERATION,
      tier: 1,
      reason: "Demo fixture: operator must approve changing the channel template.",
      context: { agent_id: secondAgentId, demo_fixture: true },
      timestamp: nowIso,
      args_binding: `${secondAgentId}:template`,
    },
  ];
}

function assertValidPort(port: number): void {
  if (
    !Number.isInteger(port) ||
    port < 1 ||
    port > MAX_TCP_PORT ||
    port === OPERATOR_DASHBOARD_PORT
  ) {
    throw new Error(
      `demo port must be a whole integer from 1 to ${MAX_TCP_PORT} and must not be ${OPERATOR_DASHBOARD_PORT}`,
    );
  }
}

export function parseDemoPort(raw: string | undefined): number {
  if (raw === undefined) return DEFAULT_PORT;
  if (!/^[0-9]+$/.test(raw)) {
    throw new Error("demo port must be a whole decimal integer");
  }
  const port = Number(raw);
  assertValidPort(port);
  return port;
}

export function seededItemsForDemo(): SeededDemoItem[] {
  return [
    {
      item: "four protected-agent registry entries",
      producedBy: "buildLocalAgentRecord plus upsertPersistedLocalAgent, matching a wrap without a confinement outcome",
      readPath: "GET /api/hub/agents",
      status: "seeded",
    },
    {
      item: "two pending approvals",
      producedBy: `DashboardApprovalChannel.requestApproval for ${DEMO_STATE_EXPORT_OPERATION} and ${DEMO_POLICY_TEMPLATE_CHANGE_OPERATION}`,
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
      item: "blocked egress event",
      producedBy: "No kernel-enforcer verdict is minted by this fixture",
      readPath: "GET /api/audit-log",
      status: "not_available",
      note: "The demo reports this honestly instead of fabricating an OS egress verdict.",
    },
    {
      item: "locked-down agent",
      producedBy: "No approval or verified enforcement probe is run by this fixture",
      readPath: "GET /api/hub/agents",
      status: "not_available",
      note: "Registry-only demo agents have no enforcer-produced lockdown state.",
    },
  ];
}

async function releaseResources(resources: {
  dashboard: DashboardApprovalChannel | null;
  dispatcher: SentinelDispatcher | null;
  auditLog: AuditLog | null;
  custody: Awaited<ReturnType<typeof establishMaster>> | null;
}): Promise<void> {
  const errors: unknown[] = [];
  try {
    await resources.dashboard?.stop();
  } catch (error) {
    errors.push(error);
  }
  try {
    await resources.dispatcher?.dispose();
  } catch (error) {
    errors.push(error);
  }
  try {
    await resources.auditLog?.flush();
  } catch (error) {
    errors.push(error);
  }
  try {
    const barrier = resources.custody?.masterWriteBarrier;
    if (barrier) await barrier.release();
  } catch (error) {
    errors.push(error);
  }
  if (errors.length > 0) {
    throw errors[0];
  }
}

export async function seedDemoFortress(
  options: SeedDemoFortressOptions,
): Promise<SeedDemoFortressResult> {
  if (!options.passphrase) {
    throw new Error(`${DEMO_PASSPHRASE_ENV} is required for the demo fortress.`);
  }
  const port = options.port ?? DEFAULT_PORT;
  assertValidPort(port);

  const envSnapshot = snapshotEnv();
  let home: string | null = null;
  let storagePath = "";
  let custody: Awaited<ReturnType<typeof establishMaster>> | null = null;
  let auditLog: AuditLog | null = null;
  let stopped = false;
  let dashboard: DashboardApprovalChannel | null = null;
  let dispatcher: SentinelDispatcher | null = null;

  try {
    home = await mkdtemp(join(demoTempParent(), DEMO_TEMP_PREFIX));
    storagePath = join(home, DEMO_STORAGE_BASENAME);
    const custodyLockRoot = join(home, DEMO_CUSTODY_LOCK_BASENAME);
    const authTokenPath = join(home, DEMO_OPERATOR_TOKEN_FILE_BASENAME);
    assertInside(home, storagePath);
    assertInside(home, custodyLockRoot);
    await mkdir(storagePath, { recursive: true, mode: 0o700 });
    await mkdir(custodyLockRoot, { recursive: true, mode: 0o700 });

    process.env.HOME = home;
    process.env.SANCTUARY_STORAGE_PATH = storagePath;
    process.env.SANCTUARY_DASHBOARD_AUTO_OPEN = "false";
    process.env.SANCTUARY_PASSPHRASE = options.passphrase;
    process.env[CUSTODY_LOCK_ROOT_ENV] = custodyLockRoot;

    const storage = new FilesystemStorage(join(storagePath, "state"));
    custody = await establishMaster({
      storage,
      passphrase: options.passphrase,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
      storagePathHint: storagePath,
    });
    const masterKey = custody.masterKey;
    auditLog = new AuditLog(storage, masterKey);
    const identityManager = new IdentityManager(storage, masterKey);
    await identityManager.load();
    const policy = await loadPrincipalPolicy(storagePath);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();
    const now = options.now ?? (() => new Date());
    const nowIso = now().toISOString();
    const fortressId = `demo-${fortressIdFromStoragePath(storagePath)}`;
    const authToken =
      options.authToken ?? `demo-${randomBytes(DEMO_AUTH_TOKEN_RANDOM_BYTES).toString("hex")}`;
    await writeFile(authTokenPath, `${authToken}\n`, { mode: OPERATOR_TOKEN_FILE_MODE });
    await chmod(authTokenPath, OPERATOR_TOKEN_FILE_MODE);
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

    const agentRecords = DEMO_AGENT_PLATFORMS.map((_, index) =>
      makeAgentRecord(index, storagePath),
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
      agent_id: agentRecords[2]?.agent_id ?? "fortress",
      summary: "Demo sentinel flagged a protected-agent burst.",
      details: {
        source: "scripts/demo/seed-fortress-lib",
        signal: "demo_fixture",
      },
      observed_at: nowIso,
      evidence_audit_ids: [],
      fortress_id: fortressId,
    } satisfies SentinelFinding);

    await auditLog.flush();
    const apiBaseUrl = `http://${HOST}:${port}`;
    let pendingApprovalIds: string[] = [];

    if (options.startDashboard !== false) {
      dashboard = new DashboardApprovalChannel({
        port,
        host: HOST,
        timeout_seconds: DEMO_APPROVAL_TIMEOUT_SECONDS,
        auth_token: authToken,
        auto_open: false,
        shutdown_grace_ms: DEMO_DASHBOARD_SHUTDOWN_GRACE_MS,
      });
      dashboard.setDependencies({
        policy,
        baseline,
        auditLog,
        identityManager,
        storage,
      });
      dashboard.setSentinelDispatcher(dispatcher);
      dashboard.setV11Bindings(
        buildV11Bindings({
          identityId: agentRecords[0]?.identity_id ?? operatorIdentityId,
          fortressId,
          auditLog,
          storagePath,
          storage,
          masterKey,
          identityManager,
          policy,
          sentinelFindingStore: findingStore,
        }),
      );
      await dashboard.start();
      const holds = makeApprovalRequests(nowIso, agentRecords).map((request) => {
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

    const mintedHome = home;
    const result: SeedDemoFortressResult = {
      home: mintedHome,
      storagePath,
      port,
      host: HOST,
      fortressId,
      dashboardUrl: `${apiBaseUrl}/v1.1`,
      apiBaseUrl,
      authToken,
      authTokenPath,
      agentIds: agentRecords.map((record) => record.agent_id),
      pendingApprovalIds,
      findingId: finding.finding_id,
      touchedPaths: [
        mintedHome,
        storagePath,
        join(storagePath, "state"),
        custodyLockRoot,
        authTokenPath,
      ],
      seededItems: seededItemsForDemo(),
      stop: async () => {
        if (stopped) return;
        stopped = true;
        let releaseError: unknown;
        try {
          await releaseResources({ dashboard, dispatcher, auditLog, custody });
        } catch (error) {
          releaseError = error;
        } finally {
          restoreEnv(envSnapshot);
          if (options.removeOnStop === true) {
            await rm(mintedHome, { recursive: true, force: true });
          }
        }
        if (releaseError) throw releaseError;
      },
    };
    return result;
  } catch (error) {
    let releaseError: unknown;
    try {
      await releaseResources({ dashboard, dispatcher, auditLog, custody });
    } catch (err) {
      releaseError = err;
    } finally {
      restoreEnv(envSnapshot);
      if (home) {
        await rm(home, { recursive: true, force: true });
      }
    }
    if (releaseError && error instanceof Error) {
      (error as Error & { teardownError?: unknown }).teardownError = releaseError;
    }
    throw error;
  }
}

export const DEMO_SEED_DEFAULT_PORT = DEFAULT_PORT;
