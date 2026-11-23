/**
 * Startup arming for the local task tool. The worker starts only when the
 * server owns its filesystem storage, and under Vitest only on an explicit
 * opt-in; on any other condition or any failure the tool is built disarmed
 * with its cause and answers every valid call with the fixed unavailable
 * response. Nothing here ever runs a job in the server process.
 */
import { platform } from "node:os";
import type { StoredIdentity } from "../core/identity.js";
import type { AuditEntryInput } from "../operational/audit-log.js";
import type { PrincipalPolicy } from "../principal-policy/types.js";
import type { ToolDefinition } from "../router.js";
import { resolveCustodyLockRoot } from "../storage/cross-process-lock.js";
import { LocalAuthority } from "./authority.js";
import { LOCAL_TASK_SURFACE, type LocalBindingSource } from "./binding.js";
import type { LocalDashboardSurface } from "./dashboard-routes.js";
import { ensureLocalStores } from "./ensure-stores.js";
import { LocalOplog } from "./oplog.js";
import { LocalOperatorStores } from "./operator-surface.js";
import { deriveLocalStoreKeys } from "./store-keys.js";
import {
  createLocalTaskTool,
  defaultRequestId,
  routerSeat,
  type LocalTaskDisarmCause,
  type LocalTaskHandlerState,
} from "./tool.js";
import { LocalWorkerClient, type WorkerClientEvent, type WorkerSpawn } from "./worker-client.js";
import { WORKER_READY_TIMEOUT_MS, type WorkerLimits } from "./worker-protocol.js";
import type { LocalStoreBackend } from "./store-record.js";

/** Test-only composition seams; index.ts honours them only when process.env.VITEST is set. */
export interface LocalTaskTestSeams {
  /** Opt in to starting the worker under Vitest; a function replaces the fork call. */
  spawnWorker?: boolean | WorkerSpawn;
  idSource?: () => string;
  clock?: () => number;
  callHook?: (state: LocalTaskHandlerState) => void;
  /** Shortened per-call timeout and job deadline for fault tests; the protocol refuses longer values. */
  workerLimits?: WorkerLimits;
}

export interface LocalTaskStatus {
  readonly armed: boolean;
  readonly cause: LocalTaskDisarmCause | null;
  workerPid(): number | undefined;
  workerState(): string;
  queueDepth(): number;
}

export interface ComposedLocalTask {
  tool: ToolDefinition;
  status: LocalTaskStatus;
  /** Operator-only surface for the dashboard; never handed to an agent-facing path. */
  operator: LocalDashboardSurface;
  /** Stop the worker and zero the server's copies of the store keys; safe to call more than once. */
  close(): Promise<void>;
}

export interface ComposeLocalTaskInput {
  /** True only when the boot path built the storage itself (no injected backend). */
  bootOwnsStorage: boolean;
  storage: LocalStoreBackend;
  storageRoot: string;
  masterKey: Uint8Array;
  auditLog: { appendCritical(entry: AuditEntryInput): Promise<void> };
  binding: LocalBindingSource;
  policy: Readonly<PrincipalPolicy>;
  identities: () => readonly StoredIdentity[];
  underVitest: boolean;
  test?: LocalTaskTestSeams;
}

function modelTagOf(binding: LocalBindingSource): () => string | null {
  return () => {
    const described = binding.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE);
    return described.ok ? described.descriptor.runtime_tag : null;
  };
}

function disarmed(
  cause: LocalTaskDisarmCause,
  binding: LocalBindingSource,
  test?: LocalTaskTestSeams,
  stores: LocalOperatorStores | null = null,
): ComposedLocalTask {
  // Operator-side only: the agent sees the fixed unavailable response whatever the cause.
  process.stderr.write(`Sanctuary local tasks disarmed: ${cause}\n`);
  const status: LocalTaskStatus = { armed: false, cause, workerPid: () => undefined, workerState: () => "state_CLOSED", queueDepth: () => 0 };
  return {
    tool: createLocalTaskTool({ armed: false, cause }, test?.callHook ? { callHook: test.callHook } : {}),
    status,
    operator: { status, modelTag: modelTagOf(binding), stores },
    close: async () => {
      stores?.close();
    },
  };
}

/** Resolve after the worker reports ready; reject on a death, a fault or the ready deadline. */
function awaitReady(subscribe: (listener: (event: WorkerClientEvent) => void) => () => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("worker ready timeout")), WORKER_READY_TIMEOUT_MS);
    timer.unref();
    const unsubscribe = subscribe((event) => {
      if (event.type === "state" && event.state === "state_READY") finish();
      else if (event.type === "fault" || (event.type === "state" && event.state === "state_DEAD")) finish(new Error("worker died"));
    });
    function finish(error?: Error): void {
      clearTimeout(timer);
      unsubscribe();
      if (error) reject(error);
      else resolve();
    }
  });
}

export async function composeLocalTask(input: ComposeLocalTaskInput): Promise<ComposedLocalTask> {
  const test = input.test;
  if (!input.bootOwnsStorage) return disarmed("storage_injected", input.binding, test);
  // Under Vitest the worker starts only on an explicit opt-in, so an ordinary test server never forks one.
  if (input.underVitest && test?.spawnWorker === undefined) return disarmed("test_runtime", input.binding, test);
  if (input.underVitest && test?.spawnWorker === false) return disarmed("test_runtime", input.binding, test);

  let lockRoot: string;
  try {
    if (typeof process.getuid !== "function") throw new Error("no uid");
    // The server's own lock root, resolved once; the worker is handed exactly this root.
    lockRoot = resolveCustodyLockRoot(process.getuid(), { env: process.env, platform: platform() });
  } catch {
    return disarmed("lock_root_unavailable", input.binding, test);
  }

  const keys = deriveLocalStoreKeys(input.masterKey);
  let client: LocalWorkerClient | undefined;
  let dropLog: LocalOplog | undefined;
  let operatorStores: LocalOperatorStores | undefined;
  try {
    const ensured = await ensureLocalStores(input.storage, keys, {
      oplog: { runtimeRoot: lockRoot },
      results: { runtimeRoot: lockRoot },
    });
    if (!ensured.ok) return disarmed("stores_unavailable", input.binding, test);
    // The operator surface reads the verified stores even when the worker later fails to start.
    operatorStores = new LocalOperatorStores(input.storage, keys, { runtimeRoot: lockRoot });

    const authority = new LocalAuthority({
      binding: input.binding,
      policy: input.policy,
      masterKey: input.masterKey,
      identities: input.identities,
    });
    authority.arm();
    dropLog = new LocalOplog(input.storage, keys.oplogKey, { runtimeRoot: lockRoot });

    const listeners = new Set<(event: WorkerClientEvent) => void>();
    let queueDepth = 0;
    const spawn: WorkerSpawn | undefined = typeof test?.spawnWorker === "function" ? test.spawnWorker : undefined;
    client = new LocalWorkerClient({
      storageRoot: input.storageRoot,
      custodyLockRoot: lockRoot,
      oplogKey: keys.oplogKey,
      resultsKey: keys.resultsKey,
      ...(spawn ? { spawn } : {}),
      ...(test?.workerLimits ? { limits: test.workerLimits } : {}),
      answerAuthority: (requestId) => authority.reply(requestId),
      onEvent: (event) => {
        if (event.type === "status") queueDepth = event.status.queue_depth;
        for (const listener of listeners) listener(event);
      },
    });
    const ready = awaitReady((listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    });
    client.start();
    await ready;

    const armedClient = client;
    const armedDropLog = dropLog;
    const armedOperatorStores = operatorStores;
    let closed = false;
    const tool = createLocalTaskTool(
      {
        armed: true,
        bundle: {
          workerClient: armedClient,
          auditLog: input.auditLog,
          authority,
          dropLog: armedDropLog,
          clock: test?.clock ?? Date.now,
          idSource: test?.idSource ?? defaultRequestId,
          seat: routerSeat,
        },
      },
      test?.callHook ? { callHook: test.callHook } : {},
    );
    const status: LocalTaskStatus = {
      armed: true,
      cause: null,
      workerPid: () => armedClient.pid,
      workerState: () => armedClient.state,
      queueDepth: () => queueDepth,
    };
    return {
      tool,
      status,
      operator: { status, modelTag: modelTagOf(input.binding), stores: armedOperatorStores },
      close: async () => {
        if (closed) return;
        closed = true;
        try {
          await armedClient.close();
        } finally {
          armedDropLog.close();
          armedOperatorStores.close();
        }
      },
    };
  } catch {
    await client?.close().catch(() => undefined);
    dropLog?.close();
    return disarmed("worker_unavailable", input.binding, test, operatorStores ?? null);
  } finally {
    // The client and the drop log hold their own copies; the derived bytes are zeroed here.
    keys.oplogKey.fill(0);
    keys.resultsKey.fill(0);
  }
}
