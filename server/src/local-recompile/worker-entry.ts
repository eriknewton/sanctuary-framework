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
import { LOCAL_CALL_TIMEOUT_MS, SensitiveGenerationClient } from "../intelligence/sensitive-generation-client.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { LocalJobQueue } from "./job-queue.js";
import { JOB_DEADLINE_MS } from "./limits.js";
import { LocalOplog, type OplogAppendKind, type OplogBodies } from "./oplog.js";
import { HOUSEKEEPING_INTERVAL_MS, LocalResultsStore } from "./results-store.js";
import { runSummarizeJob } from "./summarize-job.js";
import {
  WORKER_READY_TIMEOUT_MS,
  acceptMessage,
  assertSendable,
  type AuthorityReply,
  type JobState,
  type LocalTaskJob,
  type WorkerFaultKind,
  type WorkerLimits,
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
let storage: FilesystemStorage | undefined;
let queue: LocalJobQueue | undefined;
let limits: { callTimeoutMs: number; jobDeadlineMs: number } = { callTimeoutMs: LOCAL_CALL_TIMEOUT_MS, jobDeadlineMs: JOB_DEADLINE_MS };
// Every operator-log append from this process runs in call order, so a job's rows appear in the order it wrote them.
let appendChain: Promise<unknown> = Promise.resolve();
// Authority requests awaiting the server's reply, one per running job; bounded by the one running job.
const awaitingAuthority = new Map<string, (reply: AuthorityReply | null) => void>();

function appendRow<K extends OplogAppendKind>(kind: K, body: OplogBodies[K]): Promise<unknown> {
  const log = oplog;
  const next = appendChain.then(() => {
    if (log === undefined || terminal()) throw new Error("operator log closed");
    return log.append(kind, body);
  });
  appendChain = next.catch(() => undefined);
  return next;
}

function requestAuthority(requestId: string): Promise<AuthorityReply | null> {
  return new Promise((resolve) => {
    // A server that never answers ends the job as refused rather than holding the queue.
    const timer = setTimeout(() => settle(null), WORKER_READY_TIMEOUT_MS);
    const settle = (reply: AuthorityReply | null) => {
      clearTimeout(timer);
      awaitingAuthority.delete(requestId);
      resolve(reply);
    };
    awaitingAuthority.set(requestId, settle);
    try {
      send({ type: "authority_request", request_id: requestId });
    } catch {
      settle(null);
    }
  });
}

function acceptAuthorityReply(reply: AuthorityReply): void {
  const waiting = awaitingAuthority.get(reply.request_id);
  if (waiting === undefined) {
    // An unsolicited or late reply's key bytes are zeroed unused.
    if (reply.outcome === "granted") for (const key of reply.keys) key.fill(0);
    return;
  }
  waiting(reply);
}

/** Tell the server a job reached a state; a terminal state ends the server's watch for that job. */
function reportJobState(requestId: string, jobState: JobState): void {
  try {
    send({ type: "job_state", request_id: requestId, state: jobState });
  } catch {
    // The live view is best effort; the operator log is the record.
  }
}

function acceptJob(job: LocalTaskJob): void {
  const jobs = queue;
  // Every job this worker reads ends with an operator row: one that arrives before the queue is open
  // is dropped with a fixed cause, never ignored.
  if (jobs === undefined || state !== "state_READY") {
    appendRow("job_dropped", { request_id: job.request_id, cause: "worker_unavailable" }).catch(() => undefined);
    reportJobState(job.request_id, "state_REFUSED");
    return;
  }
  const offered = jobs.offer(job);
  // A full queue or seat drops the job on the operator side only; the agent was answered long ago.
  if (!offered.queued) {
    appendRow("job_dropped", { request_id: job.request_id, cause: offered.cause }).catch(() => undefined);
    reportJobState(job.request_id, "state_REFUSED");
    return;
  }
  appendRow("job_queued", { request_id: job.request_id, queue_depth: offered.depth }).catch(() => undefined);
  reportJobState(job.request_id, "state_QUEUED");
  try {
    // The operator's live view of the queue depth follows each accepted job, not only the sweep.
    send(status());
  } catch {
    // Best effort, as every live-view message.
  }
}

function startQueue(): void {
  const store = storage;
  const results_ = results;
  if (store === undefined || results_ === undefined) return;
  queue = new LocalJobQueue((entry) =>
    runSummarizeJob(entry, {
      readRecord: (namespace, key, maxBytes) => store.readBounded(namespace, key, maxBytes),
      log: appendRow,
      putPending: (input) => results_.putPending(input),
      markCommitted: (requestId, body, committedRow) => results_.markCommitted(requestId, body, { committedRow }),
      requestAuthority,
      reportState: reportJobState,
      // The only model client this job can build: the loopback transport over the descriptor's literal address.
      makeClient: (target, timeoutMs) => new SensitiveGenerationClient(target, { timeoutMs }),
      callTimeoutMs: limits.callTimeoutMs,
      jobDeadlineMs: limits.jobDeadlineMs,
      now: Date.now,
      setTimer: (callback, ms) => setTimeout(callback, ms),
      clearTimer: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
    }).then(() => undefined));
}

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
    queue_depth: queue?.depth ?? 0,
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

async function init(storageRoot: string, lockRoot: string, oplogKey: Uint8Array, resultsKey: Uint8Array, initLimits?: WorkerLimits): Promise<void> {
  if (oplog !== undefined) {
    // A second init's key bytes are zeroed before the fault, the same as the first's.
    oplogKey.fill(0);
    resultsKey.fill(0);
    fault("init_invalid");
    return;
  }
  try {
    if (initLimits !== undefined) limits = { callTimeoutMs: initLimits.call_timeout_ms, jobDeadlineMs: initLimits.job_deadline_ms };
    storage = new FilesystemStorage(storageRoot);
    // Every store lock rendezvouses under the server's resolved root, so both processes take the same kernel lock.
    const log = new LocalOplog(storage, oplogKey, { runtimeRoot: lockRoot });
    const store = new LocalResultsStore(storage, resultsKey, log, { runtimeRoot: lockRoot });
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
  startQueue();
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
    acceptAuthorityReply(message);
    return;
  }
  if (message.type === "job") {
    acceptJob(message);
    return;
  }
  init(message.storage_root, message.custody_lock_root, message.oplog_key, message.results_key, message.limits).catch(() => fault("uncaught"));
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
