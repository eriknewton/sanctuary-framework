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

let state: WorkerState = "state_SPAWNING";
let oplog: LocalOplog | undefined;
let results: LocalResultsStore | undefined;
let housekeeping: ReturnType<typeof setInterval> | undefined;
let sweeping = false;
let malformed = 0;

function send(message: WorkerMessage): void {
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

function fault(kind: WorkerFaultKind): void {
  closeStores();
  state = "state_DEAD";
  try {
    send({ type: "fault", kind });
  } finally {
    process.exitCode = 1;
    process.disconnect?.();
  }
}

async function sweep(): Promise<void> {
  // One sweep at a time: a tick that finds one running skips rather than queueing behind its lock.
  if (sweeping) return;
  sweeping = true;
  try {
    await results?.sweep();
    send(status());
  } catch {
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
    oplog = new LocalOplog(storage, oplogKey);
    results = new LocalResultsStore(storage, resultsKey, oplog);
    await oplog.ensure();
    await results.ensure();
  } catch {
    fault("store_open");
    return;
  } finally {
    // The stores hold their own copies; the received bytes are zeroed at once.
    oplogKey.fill(0);
    resultsKey.fill(0);
  }
  state = "state_READY";
  send({ type: "ready" });
  await sweep();
  housekeeping = setInterval(() => {
    sweep().catch(() => fault("housekeeping"));
  }, HOUSEKEEPING_INTERVAL_MS);
}

process.on("message", (raw: unknown) => {
  const message = acceptMessage("to_worker", raw);
  // A message outside the schema or the size cap is ignored and counted, never interpreted.
  if (message === null) {
    malformed += 1;
    return;
  }
  if (message.type === "shutdown") {
    closeStores();
    process.disconnect?.();
    return;
  }
  init(message.storage_root, message.oplog_key, message.results_key).catch(() => fault("uncaught"));
});

// The worker never outlives its parent: a closed channel ends the process.
process.on("disconnect", () => {
  closeStores();
  process.exit();
});

process.on("uncaughtException", () => fault("uncaught"));
process.on("unhandledRejection", () => fault("uncaught"));
