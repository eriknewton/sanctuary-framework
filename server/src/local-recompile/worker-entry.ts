/**
 * The local job worker process. It holds only the two derived store keys,
 * opens the operator log and results store over the fortress storage, runs
 * results housekeeping, and answers over the IPC channel. Its import graph
 * must not reach the shared audit log, the substrate selector, any substrate
 * client or a master-key holder (test/structure/local-recompile-worker-import-graph.test.ts).
 *
 * Built as dist/local-recompile-worker.js; must match the entry in
 * server/tsup.config.ts and the row in server/scripts/sealed-cli-runtime-entries.mjs.
 */
import { FilesystemStorage } from "../storage/filesystem.js";
import { LocalOplog } from "./oplog.js";
import { HOUSEKEEPING_INTERVAL_MS, LocalResultsStore } from "./results-store.js";
import {
  acceptMessage,
  assertSendable,
  type WorkerFaultKind,
  type WorkerMessage,
  type WorkerState,
} from "./worker-protocol.js";

// state_SPAWNING until the stores open, state_READY after, and state_DEAD once a shutdown or a fault
// is taken. state_DEAD is terminal: nothing more is sent, no message is acted on, and an init or sweep
// that resumes from an await stops there. The worker never relies on when Node emits disconnect.
let state: WorkerState = "state_SPAWNING";
let oplog: LocalOplog | undefined;
let results: LocalResultsStore | undefined;
let housekeeping: ReturnType<typeof setInterval> | undefined;
let sweeping = false;

function terminal(): boolean {
  return state === "state_DEAD";
}

function send(message: WorkerMessage): void {
  // Nothing leaves a terminal worker, whatever resumes after the shutdown or fault.
  if (terminal()) return;
  // Every outgoing message passes the shared schema and size cap first.
  assertSendable("to_parent", message);
  process.send?.(message);
}

function status(): WorkerMessage {
  return {
    type: "status",
    state,
    env_names: Object.keys(process.env).sort(),
    exec_argv: [...process.execArgv],
    queue_depth: 0,
  };
}

function closeStores(): void {
  if (housekeeping !== undefined) clearInterval(housekeeping);
  housekeeping = undefined;
  results?.close();
  oplog?.close();
  results = undefined;
  oplog = undefined;
}

/** Enter state_DEAD: the stores close and the channel is released. Runs once. */
function stop(): void {
  state = "state_DEAD";
  closeStores();
  // A channel the parent already closed is not disconnected again: Node reports that as an error,
  // which would turn a clean shutdown into an uncaught failure.
  if (process.connected) process.disconnect?.();
}

function fault(kind: WorkerFaultKind): void {
  // One fault per worker: a later failure in work that resumes after the first is not reported again.
  if (terminal()) return;
  try {
    send({ type: "fault", kind });
  } finally {
    process.exitCode = 1;
    stop();
  }
}

async function sweep(): Promise<void> {
  // One sweep at a time: a tick that finds one running skips rather than queueing behind its lock.
  if (sweeping || terminal()) return;
  sweeping = true;
  try {
    await results?.sweep();
    send(status());
  } catch {
    // A sweep cut short by a shutdown is not a housekeeping fault; fault() is a no-op once terminal.
    fault("housekeeping");
  } finally {
    sweeping = false;
  }
}

async function init(storageRoot: string, oplogKey: Uint8Array, resultsKey: Uint8Array): Promise<void> {
  if (oplog !== undefined) {
    // A second init's key bytes are zeroed before the fault, the same as the first's.
    oplogKey.fill(0);
    resultsKey.fill(0);
    fault("init_invalid");
    return;
  }
  try {
    const storage = new FilesystemStorage(storageRoot);
    const log = new LocalOplog(storage, oplogKey);
    const store = new LocalResultsStore(storage, resultsKey, log);
    // Published before the first await, so a shutdown or fault taken meanwhile closes them.
    oplog = log;
    results = store;
    await log.ensure();
    if (terminal()) return;
    await store.ensure();
  } catch {
    fault("store_open");
    return;
  } finally {
    // The stores hold their own copies; the received bytes are zeroed at once.
    oplogKey.fill(0);
    resultsKey.fill(0);
  }
  if (terminal()) return;
  state = "state_READY";
  send({ type: "ready" });
  await sweep();
  if (terminal()) return;
  housekeeping = setInterval(() => {
    sweep().catch(() => fault("housekeeping"));
  }, HOUSEKEEPING_INTERVAL_MS);
}

process.on("message", (raw: unknown) => {
  const message = acceptMessage("to_worker", raw);
  // A message outside the schema or the size cap is ignored, never interpreted.
  if (message === null) return;
  // A terminal worker acts on nothing more; key bytes that still arrive are zeroed unused.
  if (terminal()) {
    if (message.type === "init") {
      message.oplog_key.fill(0);
      message.results_key.fill(0);
    }
    if (message.type === "authority_reply" && message.outcome === "granted") for (const key of message.keys) key.fill(0);
    return;
  }
  if (message.type === "shutdown") {
    stop();
    return;
  }
  if (message.type === "authority_reply") {
    // No job is waiting on an authority reply yet; its key bytes are zeroed unused.
    if (message.outcome === "granted") for (const key of message.keys) key.fill(0);
    return;
  }
  init(message.storage_root, message.oplog_key, message.results_key).catch(() => fault("uncaught"));
});

// The worker never outlives its parent: a closed channel ends the process.
process.on("disconnect", () => {
  closeStores();
  process.exit();
});

// An uncaught failure always ends nonzero, including one that surfaces after the worker became terminal.
function uncaught(): void {
  process.exitCode = 1;
  fault("uncaught");
}
process.on("uncaughtException", uncaught);
process.on("unhandledRejection", uncaught);
