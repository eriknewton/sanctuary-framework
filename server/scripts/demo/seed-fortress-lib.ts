import { randomBytes } from "node:crypto";
import { chmodSync, constants as fsConstants, mkdtempSync, rmSync } from "node:fs";
import { chmod, link, mkdir, open, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

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
import { buildLocalAgentRecord, wrappedAgentId } from "../../src/wrap/cli.js";
import type { AgentPlatform } from "../../src/wrap/config-reader.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../src/dashboard/v1_1/wiring.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import type { GateResult, PrincipalPolicy } from "../../src/principal-policy/types.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { loadPrincipalPolicy } from "../../src/principal-policy/loader.js";

export const DEMO_TEMP_PREFIX = "sdf-";
// 3517 = the operator dashboard default plus 16, close enough for demos while avoiding the real menubar endpoint.
export const DEMO_SEED_DEFAULT_PORT = 3517;
// Only the operator may traverse the disposable root and its private directories.
export const DEMO_DIRECTORY_MODE = 0o700;
// Zero disables periodic Sentinel evaluation; this fixture reports one finding explicitly.
const DEMO_SENTINEL_TICK_INTERVAL_MS = 0;
/** Prefix consumers can use to identify the served demo fortress label. */
export const DEMO_LABEL_PREFIX = "demo-";
/** Shared by the seed writer and CLI teardown reader in seed-fortress.ts. */
export const DEMO_PID_FILE_BASENAME = "demo.pid";
// Owner read/write only, matching the operator token file permissions.
const DEMO_PID_FILE_MODE = 0o600;
const HOST = "127.0.0.1";
const DEMO_PASSPHRASE_ENV = "SANCTUARY_PASSPHRASE";
const CUSTODY_LOCK_ROOT_ENV = "SANCTUARY_CUSTODY_LOCK_ROOT";
// Must match DEFAULT_FORTRESS_ENDPOINT in menubar/src/main.ts.
export const OPERATOR_DASHBOARD_PORT = 3501;
const MAX_TCP_PORT = 65_535;
// 16 random bytes provide 128 bits of entropy for a local disposable bearer.
const DEMO_AUTH_TOKEN_RANDOM_BYTES = 16;
// base64url carries 6 bits per character with no padding, so 16 bytes encode to ceil(128 / 6) = 22 characters.
const BASE64URL_BITS_PER_CHAR = 6;
const BITS_PER_BYTE = 8;
const DEMO_AUTH_TOKEN_MIN_CHARS = Math.ceil(
  (DEMO_AUTH_TOKEN_RANDOM_BYTES * BITS_PER_BYTE) / BASE64URL_BITS_PER_CHAR,
);
// A reused token is base64url and at least as strong as a minted one; anything else is not a demo token file.
const DEMO_AUTH_TOKEN_PATTERN = new RegExp(`^[A-Za-z0-9_-]{${DEMO_AUTH_TOKEN_MIN_CHARS},}$`);
// 1 KiB is far above one token plus a newline, so a larger file is the wrong path, and it is never read whole.
const DEMO_TOKEN_FILE_MAX_BYTES = 1024;
// 8 random bytes (16 hex characters) make a token temp name unique next to the pid.
const DEMO_TOKEN_TEMP_RANDOM_BYTES = 8;
// Group and other permission bits; a reused token file must have none of them set.
const GROUP_OTHER_MODE_BITS = 0o077;
// The demo keeps two holds open for one hour; the README states this auto-deny bound.
const DEMO_APPROVAL_TIMEOUT_SECONDS = 60 * 60;
// Dashboard stop already closes local sockets; this short grace keeps test teardown fast.
const DEMO_DASHBOARD_SHUTDOWN_GRACE_MS = 250;
const DEMO_STORAGE_BASENAME = "demo-fortress";
// One-letter leaf keeps the composed socket path under KERNEL_SOCKET_PATH_MAX_BYTES in server/src/storage/cross-process-lock.ts.
const DEMO_CUSTODY_LOCK_BASENAME = "c";
const DEMO_OPERATOR_TOKEN_FILE_BASENAME = "operator-token.txt";
const OPERATOR_TOKEN_FILE_MODE = 0o600;
/**
 * The held operations are real tool names classified by the real gate, so the
 * cards show real categories and a decision writes the gate's own audit row.
 * `state_export` is Tier 1 in DEFAULT_POLICY (`tier1_always_approve` in
 * server/src/principal-policy/loader.ts).
 */
export const DEMO_TIER1_OPERATION = "state_export";
/**
 * `state_write` is Tier 3 in DEFAULT_POLICY, and a write to a namespace the
 * session baseline has not seen is a Tier 2 anomaly under the default
 * `new_namespace_access: approve`, so this hold is Tier 2 for the same reason
 * a real agent's first write to a new namespace would be.
 */
export const DEMO_TIER2_OPERATION = "state_write";
const DEMO_TIER1_ARGS = { namespace: "project-notes" };
const DEMO_TIER2_ARGS = {
  namespace: "customer-notes",
  key: "renewal-plan",
  value: "Draft renewal terms for the operator to review.",
};
// Operation name of the one seeding marker the fixture writes on the Charter layer.
export const DEMO_APPROVALS_SEEDED_OPERATION = "demo_approvals_seeded";
// Charter is layer l3; must match EVIDENCE_LAYER_NAMES in server/src/dashboard/v1_1/client.ts.
const CHARTER_AUDIT_LAYER = "l3";
// Holds register within one event-loop turn of the call; 100 polls 20 ms apart bound the wait at 2 seconds.
const DEMO_HOLD_WAIT_ATTEMPTS = 100;
const DEMO_HOLD_WAIT_INTERVAL_MS = 20;
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
  /** Cancellation waits for in-flight work before releasing resources and the root. */
  signal?: AbortSignal;
  /**
   * Awaited once, after the seeded fortress records are written and before the dashboard is constructed;
   * the two pending approvals are opened after the dashboard starts, so they are not yet written here.
   * The CLI uses it to hold seeding open for a signal so interruption is reachable on purpose.
   */
  holdBeforeDashboard?: () => Promise<void>;
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

interface DemoHeldCall {
  platform: AgentPlatform;
  operation: string;
  args: Record<string, unknown>;
}

/** One held call per seeded agent; index i is raised as DEMO_AGENT_PLATFORMS[i]. */
function demoHeldCalls(): DemoHeldCall[] {
  return [
    { platform: DEMO_AGENT_PLATFORMS[0]!, operation: DEMO_TIER1_OPERATION, args: DEMO_TIER1_ARGS },
    { platform: DEMO_AGENT_PLATFORMS[1]!, operation: DEMO_TIER2_OPERATION, args: DEMO_TIER2_ARGS },
  ];
}

/**
 * Raise each held call through a real ApprovalGate, as the named agent's MCP
 * server would. Each gate is given the agent's wrap-time id through the same
 * `currentAgentId` supplier production wires from SANCTUARY_AGENT_ID, so the
 * card's requester comes from the gate, not from anything this fixture writes
 * into the hold. Production wraps the channel in AggregatorBackedChannel, whose
 * default (redirect off) path passes straight through to this same channel.
 * The decision audit row is written by the gate when the operator decides, or
 * when the hold times out or the dashboard stops; this fixture writes none.
 */
function raiseHeldCalls(input: {
  policy: PrincipalPolicy;
  baseline: BaselineTracker;
  channel: DashboardApprovalChannel;
  auditLog: AuditLog;
  storagePath: string;
}): Promise<GateResult>[] {
  return demoHeldCalls().map((call) => {
    const gate = new ApprovalGate(input.policy, input.baseline, input.channel, input.auditLog, undefined, undefined, undefined, {
      currentAgentId: () => wrappedAgentId(call.platform, input.storagePath),
    });
    return gate.evaluate(call.operation, call.args);
  });
}

async function waitForHeldCalls(apiBaseUrl: string, authToken: string, expected: number): Promise<string[]> {
  for (let attempt = 0; attempt < DEMO_HOLD_WAIT_ATTEMPTS; attempt++) {
    const response = await fetch(`${apiBaseUrl}/api/pending`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    if (response.ok) {
      const pending = (await response.json()) as Array<{ id?: unknown }>;
      const ids = pending
        .map((item) => item.id)
        .filter((id): id is string => typeof id === "string");
      if (ids.length >= expected) return ids;
    } else {
      await response.body?.cancel();
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, DEMO_HOLD_WAIT_INTERVAL_MS));
  }
  throw new Error(`demo approvals did not reach the queue: expected ${expected}`);
}

/** A fresh demo bearer token: DEMO_AUTH_TOKEN_RANDOM_BYTES of randomness, base64url. */
export function mintDemoAuthToken(): string {
  return randomBytes(DEMO_AUTH_TOKEN_RANDOM_BYTES).toString("base64url");
}

/**
 * Reuse the demo token stored at `path`, or mint one and publish it there.
 *
 * A reused file must be a regular file (not a symlink) owned by this user with
 * no group or other permission bits, and must hold one base64url token at least
 * as long as a minted one; anything else, including an empty file, is refused
 * without echoing its contents. This never writes into an existing file: a new
 * token is published whole, so it never overwrites a token or a file it did not
 * create, and concurrent first runs all end up with the one token that won.
 */
export async function loadOrCreateDemoTokenFile(path: string): Promise<{ token: string; reused: boolean }> {
  const token = mintDemoAuthToken();
  // Atomic publish: the token is written in full to a private temp file in the
  // same directory, then hard-linked to `path`. link() never replaces or follows
  // an existing entry (a file, symlink, dangling symlink or FIFO all give EEXIST),
  // so exactly one concurrent first run publishes, and a reader can never see a
  // partial token because the name appears only after the write completed.
  const tempPath = join(dirname(path), `${basename(path)}.${process.pid}.${randomBytes(DEMO_TOKEN_TEMP_RANDOM_BYTES).toString("hex")}.tmp`);
  let published = false;
  try {
    const temp = await open(
      tempPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      OPERATOR_TOKEN_FILE_MODE,
    );
    try {
      // The umask may have narrowed the create mode; the published file is exactly owner read/write.
      await temp.chmod(OPERATOR_TOKEN_FILE_MODE);
      await temp.writeFile(`${token}\n`);
    } finally {
      await temp.close();
    }
    await link(tempPath, path).then(
      () => { published = true; },
      (error: NodeJS.ErrnoException) => { if (error.code !== "EEXIST") throw error; },
    );
  } finally {
    await unlink(tempPath).catch(() => undefined);
  }
  if (published) return { token, reused: false };
  return readExistingDemoToken(path);
}

async function readExistingDemoToken(path: string): Promise<{ token: string; reused: boolean }> {
  // One open, and every decision after it is made on that descriptor, never on
  // the path, so the file validated is the file read (no check-then-use window).
  // O_NOFOLLOW refuses a symlink at the final component with ELOOP, so nothing
  // is read through one; O_NONBLOCK keeps a FIFO planted at the path from
  // blocking the open (the regular-file check then refuses it).
  const handle = await open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
  ).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ELOOP") throw new Error(`refusing demo token file that is not a regular file: ${path}`);
    throw error;
  });
  try {
    const existing = await handle.stat();
    if (!existing.isFile()) {
      throw new Error(`refusing demo token file that is not a regular file: ${path}`);
    }
    if (typeof process.getuid === "function" && existing.uid !== process.getuid()) {
      throw new Error(`refusing demo token file owned by another user: ${path}`);
    }
    if ((existing.mode & GROUP_OTHER_MODE_BITS) !== 0) {
      throw new Error(`refusing demo token file readable by group or others (chmod 600 it): ${path}`);
    }
    if (existing.size > DEMO_TOKEN_FILE_MAX_BYTES) {
      throw new Error(`refusing demo token file larger than ${DEMO_TOKEN_FILE_MAX_BYTES} bytes: ${path}`);
    }
    // Bounded read through the validated descriptor: one byte past the cap is
    // requested, so a file that grew after the size check is refused, never read whole.
    const buffer = Buffer.alloc(DEMO_TOKEN_FILE_MAX_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > DEMO_TOKEN_FILE_MAX_BYTES) {
      throw new Error(`refusing demo token file larger than ${DEMO_TOKEN_FILE_MAX_BYTES} bytes: ${path}`);
    }
    const stored = buffer.subarray(0, bytesRead).toString("utf8").trim();
    if (!DEMO_AUTH_TOKEN_PATTERN.test(stored)) {
      throw new Error(`refusing demo token file that does not hold a demo token: ${path}`);
    }
    return { token: stored, reused: true };
  } finally {
    await handle.close();
  }
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
  if (raw === undefined) return DEMO_SEED_DEFAULT_PORT;
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
      item: "four registry agents",
      producedBy: "buildLocalAgentRecord plus upsertPersistedLocalAgent, matching a wrap without a confinement outcome",
      readPath: "GET /api/hub/agents",
      status: "seeded",
    },
    {
      item: "two pending approvals",
      producedBy: `ApprovalGate.evaluate for ${DEMO_TIER1_OPERATION} (Tier 1) and ${DEMO_TIER2_OPERATION} to a new namespace (Tier 2), each raised as a seeded agent`,
      readPath: "GET /api/hub/inbox",
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
  heldCalls: Promise<GateResult>[];
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
  // Stopping the dashboard auto-denies any open hold; the gate then writes its decision row,
  // exactly as on a production shutdown, so wait for those writes before the final flush.
  await Promise.allSettled(resources.heldCalls);
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

// Only roots minted here can enter the seeding phase; callers cannot redirect writes to an existing home.
const unseededRoots = new Set<string>();

/** Create an empty private root synchronously so the caller can install handlers before yielding. */
export function createDemoRoot(): string {
  // demoTempParent keeps macOS custody sockets within KERNEL_SOCKET_PATH_MAX_BYTES.
  const home = mkdtempSync(join(demoTempParent(), DEMO_TEMP_PREFIX));
  try {
    chmodSync(home, DEMO_DIRECTORY_MODE);
    unseededRoots.add(home);
    return home;
  } catch (error) {
    rmSync(home, { recursive: true, force: true });
    throw error;
  }
}

/** Seed a root returned by createDemoRoot; stop removes it unless removeOnStop is explicitly false. */
export async function seedDemoFortress(
  home: string,
  options: SeedDemoFortressOptions,
): Promise<SeedDemoFortressResult> {
  if (!unseededRoots.delete(home)) {
    throw new Error("demo seeding requires a fresh root from createDemoRoot");
  }
  const envSnapshot = snapshotEnv();
  const port = options.port ?? DEMO_SEED_DEFAULT_PORT;
  let storagePath = "";
  let custody: Awaited<ReturnType<typeof establishMaster>> | null = null;
  let auditLog: AuditLog | null = null;
  let stopped = false;
  let dashboard: DashboardApprovalChannel | null = null;
  let dispatcher: SentinelDispatcher | null = null;
  let heldCalls: Promise<GateResult>[] = [];

  try {
    if (!options.passphrase) {
      throw new Error(`${DEMO_PASSPHRASE_ENV} is required for the demo fortress.`);
    }
    assertValidPort(port);
    options.signal?.throwIfAborted();
    // Must match the DEMO_PID_FILE_BASENAME reader in seed-fortress.ts; liveness protects active roots.
    await writeFile(join(home, DEMO_PID_FILE_BASENAME), `${process.pid}\n`, { mode: DEMO_PID_FILE_MODE });
    storagePath = join(home, DEMO_STORAGE_BASENAME);
    const custodyLockRoot = join(home, DEMO_CUSTODY_LOCK_BASENAME);
    const authTokenPath = join(home, DEMO_OPERATOR_TOKEN_FILE_BASENAME);
    assertInside(home, storagePath);
    assertInside(home, custodyLockRoot);
    await mkdir(storagePath, { recursive: true, mode: DEMO_DIRECTORY_MODE });
    await mkdir(custodyLockRoot, { recursive: true, mode: DEMO_DIRECTORY_MODE });

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
    options.signal?.throwIfAborted();
    const masterKey = custody.masterKey;
    auditLog = new AuditLog(storage, masterKey);
    const identityManager = new IdentityManager(storage, masterKey);
    await identityManager.load();
    const policy = await loadPrincipalPolicy(storagePath);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();
    const now = options.now ?? (() => new Date());
    const nowIso = now().toISOString();
    const fortressId = `${DEMO_LABEL_PREFIX}${fortressIdFromStoragePath(storagePath)}`;
    const authToken = options.authToken ?? mintDemoAuthToken();
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
      tickIntervalMs: DEMO_SENTINEL_TICK_INTERVAL_MS,
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

    await options.holdBeforeDashboard?.();
    options.signal?.throwIfAborted();
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
      options.signal?.throwIfAborted();
      heldCalls = raiseHeldCalls({ policy, baseline, channel: dashboard, auditLog, storagePath });
      // Settlement is observed by stop(); this only keeps a rejected evaluation from going unhandled.
      for (const held of heldCalls) void held.catch(() => undefined);
      pendingApprovalIds = await waitForHeldCalls(apiBaseUrl, authToken, heldCalls.length);
      // A fixture marker, named as one; the approval decision itself is audited by the gate.
      await auditLog.appendCritical({
        layer: CHARTER_AUDIT_LAYER,
        operation: DEMO_APPROVALS_SEEDED_OPERATION,
        identity_id: operatorIdentityId,
        result: "success",
        details: {
          demo_fixture: true,
          count: heldCalls.length,
        },
      });
      await auditLog.flush();
    }

    // Cancellation is checked after the final awaited write/read so cleanup cannot race late seeding work.
    options.signal?.throwIfAborted();
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
          await releaseResources({ dashboard, heldCalls, dispatcher, auditLog, custody });
        } catch (error) {
          releaseError = error;
        } finally {
          restoreEnv(envSnapshot);
          if (options.removeOnStop !== false) {
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
      await releaseResources({ dashboard, heldCalls, dispatcher, auditLog, custody });
    } catch (err) {
      releaseError = err;
    } finally {
      restoreEnv(envSnapshot);
      if (options.removeOnStop !== false) {
        try {
          await rm(home, { recursive: true, force: true });
        } catch (err) {
          releaseError ??= err;
        }
      }
    }
    if (releaseError && error instanceof Error) {
      (error as Error & { teardownError?: unknown }).teardownError = releaseError;
    }
    throw error;
  }
}

