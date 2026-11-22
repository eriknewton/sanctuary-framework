/**
 * Server-side client for the local job worker: spawns it with a scrubbed
 * environment and a heap cap, hands it the two derived store keys, and
 * respawns it with capped exponential backoff. A dead worker never causes
 * work to run in the server process: `send` simply refuses.
 *
 * Modelled on DarwinDirectoryCapabilityClient in storage/filesystem.ts.
 */
import { fork, type ChildProcess, type ForkOptions } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { copyStoreKey } from "./store-record.js";
import {
  WORKER_ENV_NAMES,
  WORKER_HEAP_MAX_MB,
  WORKER_READY_TIMEOUT_MS,
  WORKER_RESPAWN_INITIAL_MS,
  WORKER_RESPAWN_MAX_MS,
  acceptMessage,
  assertSendable,
  type ParentMessage,
  type WorkerFaultKind,
  type WorkerMessage,
  type WorkerState,
} from "./worker-protocol.js";

export interface WorkerTimers {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export type WorkerSpawn = (modulePath: string, args: string[], options: ForkOptions) => ChildProcess;

export type WorkerClientEvent =
  | { type: "state"; state: WorkerState | "state_CLOSED"; pid?: number }
  | { type: "status"; status: Extract<WorkerMessage, { type: "status" }> }
  | { type: "fault"; kind: WorkerFaultKind }
  | { type: "respawn_scheduled"; delay_ms: number };

export interface LocalWorkerClientOptions {
  /** Fortress storage root the worker opens; required. */
  storageRoot: string;
  /** Derived operator-log key; required. The master key is never accepted. */
  oplogKey: Uint8Array;
  /** Derived results-store key; required. */
  resultsKey: Uint8Array;
  timers?: WorkerTimers;
  spawn?: WorkerSpawn;
  onEvent?: (event: WorkerClientEvent) => void;
}

const realTimers: WorkerTimers = {
  setTimeout: (callback, ms) => {
    const handle = setTimeout(callback, ms);
    handle.unref();
    return handle;
  },
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** Resolve the worker module: the TypeScript source in development, the built file in a package. */
export function resolveWorkerModule(): { modulePath: string; execArgv: string[] } {
  const sourceWorker = fileURLToPath(new URL("./worker-entry.ts", import.meta.url));
  // Must match the "local-recompile-worker" entry in server/tsup.config.ts, built beside dist/index.js.
  const builtWorker = fileURLToPath(new URL("./local-recompile-worker.js", import.meta.url));
  const fromSource = existsSync(sourceWorker);
  // The loader is resolved against this package, never from the worker's cwd or environment.
  const loader = fromSource ? createRequire(import.meta.url).resolve("tsx") : undefined;
  return { modulePath: fromSource ? sourceWorker : builtWorker, execArgv: loader ? ["--import", loader] : [] };
}

export class LocalWorkerClient {
  private readonly oplogKey: Uint8Array;
  private readonly resultsKey: Uint8Array;
  private readonly storageRoot: string;
  private readonly timers: WorkerTimers;
  private readonly spawnWorker: WorkerSpawn;
  private readonly onEvent: (event: WorkerClientEvent) => void;
  private child: ChildProcess | undefined;
  private currentState: WorkerState | "state_CLOSED" = "state_DEAD";
  private backoffMs = WORKER_RESPAWN_INITIAL_MS;
  private readyTimer: unknown;
  private stableTimer: unknown;
  private respawnTimer: unknown;
  /** The child that sent an accepted `ready` and has not faulted, exited or been closed; the only one `send` writes to. */
  private readyChild: ChildProcess | undefined;
  private backlogged = false;
  /** Identifies the write whose queued delivery clears the backlog; earlier deliveries never do. */
  private backlogWrite = 0;
  private writes = 0;
  private closing = false;
  malformedMessages = 0;

  constructor(options: LocalWorkerClientOptions) {
    if (typeof options.storageRoot !== "string" || options.storageRoot.length === 0) {
      throw new TypeError("local worker requires a storage root");
    }
    this.storageRoot = options.storageRoot;
    // Required, exactly 32 bytes each, copied so the caller can zero its own.
    this.oplogKey = copyStoreKey(options.oplogKey);
    this.resultsKey = copyStoreKey(options.resultsKey);
    // The init every spawn sends is checked against the shared schema once here, so a root the
    // worker would refuse fails at construction instead of driving a respawn loop.
    try {
      assertSendable("to_worker", this.initMessage(this.oplogKey, this.resultsKey));
    } catch (error) {
      // A refused construction keeps no key material: both copies are zeroed before the refusal.
      this.oplogKey.fill(0);
      this.resultsKey.fill(0);
      throw error;
    }
    this.timers = options.timers ?? realTimers;
    this.spawnWorker = options.spawn ?? fork;
    this.onEvent = options.onEvent ?? (() => undefined);
  }

  get state(): WorkerState | "state_CLOSED" {
    return this.currentState;
  }

  get pid(): number | undefined {
    return this.child?.pid;
  }

  start(): void {
    if (this.closing || this.child !== undefined) return;
    this.spawn();
  }

  /**
   * Hand one message to a ready worker. Never blocks: false when the worker is
   * not ready or the channel has a backlog, and the caller treats that as an
   * operator-side drop.
   */
  send(message: ParentMessage): boolean {
    assertSendable("to_worker", message);
    const child = this.child;
    // Only the ready child that has not faulted receives work, and nothing is sent once close begins.
    if (this.closing || this.currentState !== "state_READY" || child === undefined || child !== this.readyChild) return false;
    if (!child.connected || this.backlogged) return false;
    return this.write(child, message);
  }

  /** Ask the worker to stop, then SIGKILL after WORKER_READY_TIMEOUT_MS; resolves once it has exited. */
  async close(): Promise<void> {
    this.closing = true;
    this.readyChild = undefined;
    for (const timer of [this.readyTimer, this.stableTimer, this.respawnTimer]) {
      if (timer !== undefined) this.timers.clearTimeout(timer);
    }
    this.readyTimer = this.stableTimer = this.respawnTimer = undefined;
    const child = this.child;
    // A spawn that failed has no pid and may never emit exit; there is no process to wait for.
    if (child !== undefined && child.pid !== undefined && child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      if (child.connected) this.write(child, { type: "shutdown" });
      // SIGKILL guarantees the exit this waits for; the injected timers bound it like every other deadline here.
      const kill = this.timers.setTimeout(() => child.kill("SIGKILL"), WORKER_READY_TIMEOUT_MS);
      await exited;
      this.timers.clearTimeout(kill);
    }
    this.oplogKey.fill(0);
    this.resultsKey.fill(0);
    this.setState("state_CLOSED");
  }

  /**
   * True when Node took the message: it was written or queued. A closed
   * channel queues nothing and reads false. When Node queues behind a backlog,
   * further sends refuse until this write is delivered to the same child.
   */
  private write(child: ChildProcess, message: ParentMessage): boolean {
    if (!child.connected) return false;
    const id = (this.writes += 1);
    let accepted = false;
    let delivered = false;
    try {
      accepted = child.send(message, (error: Error | null) => {
        if (error != null) return;
        delivered = true;
        // Only a delivered write, to the current child, that raised the backlog clears it.
        if (child === this.child && id === this.backlogWrite) this.backlogged = false;
      });
    } catch {
      return false;
    }
    // A write already delivered when send returns (its callback ran first) leaves nothing queued, so it
    // never raises the backlog, whatever order the transport reports the two in.
    if (!accepted && !delivered) {
      this.backlogged = true;
      this.backlogWrite = id;
    }
    return true;
  }

  private initMessage(oplogKey: Uint8Array, resultsKey: Uint8Array): ParentMessage {
    return { type: "init", storage_root: this.storageRoot, oplog_key: oplogKey, results_key: resultsKey };
  }

  private setState(state: WorkerState | "state_CLOSED"): void {
    this.currentState = state;
    this.onEvent({ type: "state", state, ...(this.child?.pid === undefined ? {} : { pid: this.child.pid }) });
  }

  private spawn(): void {
    const { modulePath, execArgv } = resolveWorkerModule();
    const env: NodeJS.ProcessEnv = {};
    // Only the named variables cross: no SANCTUARY_* credential and no proxy setting reaches the worker.
    for (const name of WORKER_ENV_NAMES) {
      const value = process.env[name];
      if (value !== undefined) env[name] = value;
    }
    const child = this.spawnWorker(modulePath, [], {
      env,
      execArgv: [...execArgv, `--max-old-space-size=${WORKER_HEAP_MAX_MB}`],
      stdio: ["ignore", "ignore", "ignore", "ipc"],
      // Advanced serialization carries the keys as bytes that can be zeroed, not as strings.
      serialization: "advanced",
    });
    this.child = child;
    this.readyChild = undefined;
    this.backlogged = false;
    this.setState("state_SPAWNING");
    // The worker never keeps the server alive.
    child.unref();
    (child as ChildProcess & { channel?: { unref?: () => void } }).channel?.unref?.();
    child.on("message", (raw: unknown) => this.onMessage(child, raw));
    child.once("exit", () => this.onExit(child));
    child.once("error", () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      // A spawn that never started may emit no exit event; treat it as a death so backoff still runs.
      if (child.pid === undefined) this.onExit(child);
    });
    this.readyTimer = this.timers.setTimeout(() => {
      // A worker that cannot open its stores in time is treated as dead.
      if (this.child === child && this.currentState === "state_SPAWNING") child.kill("SIGKILL");
    }, WORKER_READY_TIMEOUT_MS);
    const oplogKey = Uint8Array.from(this.oplogKey);
    const resultsKey = Uint8Array.from(this.resultsKey);
    try {
      // Keys are re-sent on every spawn, then the transient copies are zeroed.
      const init = this.initMessage(oplogKey, resultsKey);
      assertSendable("to_worker", init);
      this.write(child, init);
    } finally {
      oplogKey.fill(0);
      resultsKey.fill(0);
    }
  }

  private onMessage(child: ChildProcess, raw: unknown): void {
    // A superseded child, a child that faulted (state_DEAD until its exit), or any child once close has
    // begun is not listened to: a ready or status it had already sent is dropped.
    if (child !== this.child || this.closing || this.currentState === "state_DEAD") return;
    // Received messages pass the same schema and size cap as sent ones.
    const message = acceptMessage("to_parent", raw);
    if (message === null) {
      this.malformedMessages += 1;
      return;
    }
    if (message.type === "ready") {
      // state_SPAWNING is the only state a ready moves on from; a duplicate is refused and counted.
      if (this.currentState !== "state_SPAWNING") {
        this.malformedMessages += 1;
        return;
      }
      if (this.readyTimer !== undefined) this.timers.clearTimeout(this.readyTimer);
      this.readyTimer = undefined;
      this.readyChild = child;
      this.setState("state_READY");
      this.stableTimer = this.timers.setTimeout(() => {
        this.backoffMs = WORKER_RESPAWN_INITIAL_MS;
      }, WORKER_RESPAWN_MAX_MS);
    } else if (message.type === "status") {
      this.onEvent({ type: "status", status: message });
    } else {
      // A fault ends the child's turn at once, before its exit arrives: it gets no more work, leaves
      // state_SPAWNING or state_READY for state_DEAD, and its ready and stable timers stop, so it can
      // neither become ready nor reset the backoff. It is killed, and its exit drives the usual respawn.
      this.readyChild = undefined;
      for (const timer of [this.readyTimer, this.stableTimer]) {
        if (timer !== undefined) this.timers.clearTimeout(timer);
      }
      this.readyTimer = this.stableTimer = undefined;
      this.setState("state_DEAD");
      this.onEvent({ type: "fault", kind: message.kind });
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
  }

  private onExit(child: ChildProcess): void {
    if (child !== this.child) return;
    this.readyChild = undefined;
    for (const timer of [this.readyTimer, this.stableTimer]) {
      if (timer !== undefined) this.timers.clearTimeout(timer);
    }
    this.readyTimer = this.stableTimer = undefined;
    this.child = undefined;
    if (this.closing) return;
    this.setState("state_DEAD");
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.backoffMs * 2, WORKER_RESPAWN_MAX_MS);
    this.setState("state_BACKOFF");
    this.onEvent({ type: "respawn_scheduled", delay_ms: delay });
    this.respawnTimer = this.timers.setTimeout(() => {
      this.respawnTimer = undefined;
      if (!this.closing) this.spawn();
    }, delay);
  }
}
