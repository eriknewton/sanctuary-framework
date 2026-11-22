// fail-before-exempt: new worker process module, no base behaviour.
import { afterEach, describe, expect, it } from "vitest";
import { fork, type ChildProcess, type ForkOptions } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { LocalOplog } from "../../src/local-recompile/oplog.js";
import { LocalResultsStore } from "../../src/local-recompile/results-store.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { LocalWorkerClient, resolveWorkerModule, type WorkerClientEvent, type WorkerTimers } from "../../src/local-recompile/worker-client.js";
import {
  IPC_MESSAGE_MAX_BYTES,
  WORKER_ENV_NAMES,
  WORKER_HEAP_MAX_MB,
  WORKER_RESPAWN_INITIAL_MS,
  WORKER_RESPAWN_MAX_MS,
  assertSendable,
  WorkerProtocolError,
} from "../../src/local-recompile/worker-protocol.js";
import { SHORT_SOCKET_TMP_PARENT } from "../helpers/short-socket-tmp-parent.js";
import { FIXTURE_SEAT, fixtureRequestId } from "./__fixtures__/strict-memory-storage.js";

const MASTER_KEY_BYTES = 32; // AES-256 master key
const STORE_KEY_BYTES = 32;
// Bounded graceful wait before SIGKILL when reaping a fixture child.
const REAP_GRACE_MS = 2_000;
// Upper bound for one real worker to start under tsx and open its stores.
const WORKER_EVENT_TIMEOUT_MS = 30_000;

const cleanups: Array<() => Promise<void> | void> = [];
const children = new Set<ChildProcess>();
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  for (const child of children) await reap(child);
  children.clear();
});

async function reap(child: ChildProcess): Promise<void> {
  if (child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit");
    const timer = setTimeout(() => child.kill("SIGKILL"), REAP_GRACE_MS);
    child.kill("SIGTERM");
    await exited;
    clearTimeout(timer);
  }
  expect(isAlive(child.pid)).toBe(false);
}

function isAlive(pid: number | undefined): boolean {
  if (pid === undefined) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function fortress() {
  const base = await realpath(await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "lrw-")));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const master = crypto.getRandomValues(new Uint8Array(MASTER_KEY_BYTES));
  const keys = deriveLocalStoreKeys(master);
  const storageRoot = join(base, "state");
  return { base, master, keys, storageRoot };
}

/** Real fork that records every child and every message the client sends it. */
function recordingSpawn(sent: unknown[][]) {
  return (modulePath: string, args: string[], options: ForkOptions): ChildProcess => {
    const child = fork(modulePath, args, options);
    children.add(child);
    const messages: unknown[] = [];
    sent.push(messages);
    const original = child.send.bind(child) as (...input: unknown[]) => boolean;
    (child as { send: unknown }).send = (message: unknown, ...rest: unknown[]) => {
      messages.push(structuredClone(message));
      return original(message, ...rest);
    };
    return child;
  };
}

function nextEvent(events: EventEmitter, predicate: (event: WorkerClientEvent) => boolean): Promise<WorkerClientEvent> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("worker event timed out")), WORKER_EVENT_TIMEOUT_MS);
    const listener = (event: WorkerClientEvent) => {
      if (!predicate(event)) return;
      clearTimeout(timer);
      events.off("event", listener);
      resolve(event);
    };
    events.on("event", listener);
  });
}

function startClient(storageRoot: string, keys: { oplogKey: Uint8Array; resultsKey: Uint8Array }, extra: { timers?: WorkerTimers; sent?: unknown[][] } = {}) {
  const events = new EventEmitter();
  const client = new LocalWorkerClient({
    storageRoot,
    oplogKey: keys.oplogKey,
    resultsKey: keys.resultsKey,
    spawn: recordingSpawn(extra.sent ?? []),
    onEvent: (event) => events.emit("event", event),
    ...(extra.timers ? { timers: extra.timers } : {}),
  });
  cleanups.push(() => client.close());
  return { client, events };
}

function keyBuffers(value: unknown, out: Uint8Array[] = []): Uint8Array[] {
  if (value instanceof Uint8Array) out.push(value);
  else if (value !== null && typeof value === "object") for (const item of Object.values(value)) keyBuffers(item, out);
  return out;
}

describe("local job worker process", () => {
  it("the worker starts with only the allowed environment names and the heap limit", async () => {
    const { keys, storageRoot } = await fortress();
    const saved = { agent: process.env.SANCTUARY_AGENT_ID, http: process.env.HTTP_PROXY, https: process.env.HTTPS_PROXY, env: process.env.NODE_USE_ENV_PROXY };
    process.env.SANCTUARY_AGENT_ID = "fixture-agent";
    process.env.HTTP_PROXY = "http://127.0.0.1:9";
    process.env.HTTPS_PROXY = "http://127.0.0.1:9";
    process.env.NODE_USE_ENV_PROXY = "1";
    try {
      const { client, events } = startClient(storageRoot, keys);
      const status = nextEvent(events, (event) => event.type === "status");
      client.start();
      const event = (await status) as Extract<WorkerClientEvent, { type: "status" }>;
      expect(event.status.env_names.filter((name) => !(WORKER_ENV_NAMES as readonly string[]).includes(name))).toEqual([]);
      expect(event.status.exec_argv).toContain(`--max-old-space-size=${WORKER_HEAP_MAX_MB}`);
      expect(event.status.state).toBe("state_READY");
    } finally {
      for (const [name, value] of [["SANCTUARY_AGENT_ID", saved.agent], ["HTTP_PROXY", saved.http], ["HTTPS_PROXY", saved.https], ["NODE_USE_ENV_PROXY", saved.env]] as const) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  }, 60_000);

  it("init carries the two store keys and never the master key", async () => {
    const { master, keys, storageRoot } = await fortress();
    const sent: unknown[][] = [];
    const { client, events } = startClient(storageRoot, keys, { sent });
    const ready = nextEvent(events, (event) => event.type === "state" && event.state === "state_READY");
    client.start();
    await ready;
    const buffers = keyBuffers(sent.flat());
    expect(buffers).toHaveLength(2);
    expect(buffers.every((buffer) => buffer.length === STORE_KEY_BYTES)).toBe(true);
    expect(buffers.some((buffer) => Buffer.from(buffer).equals(Buffer.from(master)))).toBe(false);
    expect(buffers.map((buffer) => Buffer.from(buffer).toString("hex")).sort()).toEqual(
      [keys.oplogKey, keys.resultsKey].map((key) => Buffer.from(key).toString("hex")).sort(),
    );
  }, 60_000);

  it("a message over the size cap is refused at the sender", () => {
    const oversized = { type: "status", state: "state_READY", env_names: [], exec_argv: Array.from({ length: 32 }, () => "x".repeat(4_000)), queue_depth: 0 };
    expect(32 * 4_000).toBeGreaterThan(IPC_MESSAGE_MAX_BYTES);
    expect(() => assertSendable("to_parent", oversized)).toThrow(WorkerProtocolError);
    expect(() => assertSendable("to_parent", { ...oversized, exec_argv: ["--max-old-space-size=512"] })).not.toThrow();
  });

  it("a malformed message is ignored and counted", async () => {
    const { keys } = await fortress();
    const fake = new FakeChild();
    const client = new LocalWorkerClient({ storageRoot: "/fixture", ...keys, spawn: () => fake as unknown as ChildProcess, timers: manualTimers().timers });
    client.start();
    fake.emit("message", { type: "ready", extra: true });
    fake.emit("message", "not an object");
    expect(client.malformedMessages).toBe(2);
    expect(client.state).toBe("state_SPAWNING");
    fake.emit("message", { type: "ready" });
    expect(client.state).toBe("state_READY");
    expect(() => client.send({ type: "bogus" } as never)).toThrow(WorkerProtocolError);
    await client.close();
  });

  it("the real worker ignores a malformed message and still initialises", async () => {
    const { keys, storageRoot } = await fortress();
    const { modulePath, execArgv } = resolveWorkerModule();
    const child = fork(modulePath, [], { execArgv, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "advanced" });
    children.add(child);
    const ready = once(child, "message");
    child.send({ type: "init", storage_root: "relative/path", oplog_key: keys.oplogKey, results_key: keys.resultsKey });
    child.send({ type: "nonsense" });
    child.send({ type: "init", storage_root: storageRoot, oplog_key: keys.oplogKey, results_key: keys.resultsKey });
    expect((await ready)[0]).toEqual({ type: "ready" });
  }, 60_000);

  it("a killed worker is respawned with doubling backoff capped at 60 seconds, and keys are re-sent", async () => {
    const { keys } = await fortress();
    const fakes: FakeChild[] = [];
    const clock = manualTimers();
    const delays: number[] = [];
    const client = new LocalWorkerClient({
      storageRoot: "/fixture",
      ...keys,
      timers: clock.timers,
      spawn: () => { const child = new FakeChild(); fakes.push(child); return child as unknown as ChildProcess; },
      onEvent: (event) => { if (event.type === "respawn_scheduled") delays.push(event.delay_ms); },
    });
    client.start();
    const DEATHS = 8;
    for (let death = 0; death < DEATHS; death += 1) {
      const current = fakes.at(-1)!;
      current.emit("message", { type: "ready" });
      current.kill("SIGKILL");
      expect(client.state).toBe("state_BACKOFF");
      clock.fire(delays.at(-1)!);
    }
    const expected = Array.from({ length: DEATHS }, (_, index) => Math.min(WORKER_RESPAWN_INITIAL_MS * 2 ** index, WORKER_RESPAWN_MAX_MS));
    expect(delays).toEqual(expected);
    expect(fakes).toHaveLength(DEATHS + 1);
    for (const fake of fakes) {
      const init = fake.sent.find((message) => (message as { type?: string }).type === "init") as { oplog_key: Uint8Array; results_key: Uint8Array };
      expect(Buffer.from(init.oplog_key).equals(Buffer.from(keys.oplogKey))).toBe(true);
      expect(Buffer.from(init.results_key).equals(Buffer.from(keys.resultsKey))).toBe(true);
    }
    // A worker that stays ready for the cap resets the backoff.
    fakes.at(-1)!.emit("message", { type: "ready" });
    clock.fire(WORKER_RESPAWN_MAX_MS);
    fakes.at(-1)!.kill("SIGKILL");
    expect(delays.at(-1)).toBe(WORKER_RESPAWN_INITIAL_MS);
    await client.close();
  });

  it("a real worker killed with SIGKILL is respawned and receives the keys again", async () => {
    const { keys, storageRoot } = await fortress();
    const sent: unknown[][] = [];
    const clock = manualTimers();
    const { client, events } = startClient(storageRoot, keys, { sent, timers: clock.timers });
    const firstReady = nextEvent(events, (event) => event.type === "state" && event.state === "state_READY");
    client.start();
    await firstReady;
    const firstPid = client.pid!;
    const scheduled = nextEvent(events, (event) => event.type === "respawn_scheduled");
    process.kill(firstPid, "SIGKILL");
    expect(await scheduled).toEqual({ type: "respawn_scheduled", delay_ms: WORKER_RESPAWN_INITIAL_MS });
    const secondReady = nextEvent(events, (event) => event.type === "state" && event.state === "state_READY");
    clock.fire(WORKER_RESPAWN_INITIAL_MS);
    await secondReady;
    expect(client.pid).not.toBe(firstPid);
    expect(isAlive(firstPid)).toBe(false);
    expect(sent.map((messages) => messages.filter((message) => (message as { type?: string }).type === "init").length)).toEqual([1, 1]);
  }, 90_000);

  it("a worker whose parent disconnects exits", async () => {
    const { keys, storageRoot } = await fortress();
    const { modulePath, execArgv } = resolveWorkerModule();
    const child = fork(modulePath, [], { execArgv, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "advanced" });
    children.add(child);
    const ready = once(child, "message");
    child.send({ type: "init", storage_root: storageRoot, oplog_key: keys.oplogKey, results_key: keys.resultsKey });
    await ready;
    const exited = once(child, "exit");
    child.disconnect();
    await exited;
    expect(isAlive(child.pid)).toBe(false);
  }, 60_000);

  it("the worker runs results housekeeping", async () => {
    const { keys, storageRoot } = await fortress();
    const storage = new FilesystemStorage(storageRoot);
    const longAgo = Date.now() - 2 * 60 * 60 * 1_000; // two hours, past any deadline plus grace
    const oplog = new LocalOplog(storage, keys.oplogKey, { now: () => longAgo });
    const results = new LocalResultsStore(storage, keys.resultsKey, oplog, { now: () => longAgo });
    await oplog.ensure();
    await results.ensure();
    await results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline: longAgo + 60_000 });
    results.close();
    oplog.close();

    const { client, events } = startClient(storageRoot, keys);
    const swept = nextEvent(events, (event) => event.type === "status");
    client.start();
    await swept;
    const reader = new LocalOplog(storage, keys.oplogKey);
    const readerResults = new LocalResultsStore(storage, keys.resultsKey, reader);
    cleanups.push(() => { readerResults.close(); reader.close(); });
    expect(await readerResults.get(fixtureRequestId(1), { includeUncommitted: true })).toMatchObject({ state: "indeterminate" });
    const rows = await reader.readRows(0, 10);
    expect(rows.map((row) => row.kind)).toEqual(["genesis", "result_pending", "result_indeterminate"]);
  }, 60_000);

  it("a fault message carries a kind and no key bytes", async () => {
    const { base, keys } = await fortress();
    const notADirectory = join(base, "plain-file");
    await writeFile(notADirectory, "not a fortress");
    const { modulePath, execArgv } = resolveWorkerModule();
    const child = fork(modulePath, [], { execArgv, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "advanced" });
    children.add(child);
    const reply = once(child, "message");
    child.send({ type: "init", storage_root: join(notADirectory, "state"), oplog_key: keys.oplogKey, results_key: keys.resultsKey });
    const [message] = await reply;
    expect(message).toEqual({ type: "fault", kind: "store_open" });
    expect(keyBuffers(message)).toEqual([]);
    await once(child, "exit");
  }, 60_000);
});

class FakeChild extends EventEmitter {
  static nextPid = 1_000_000;
  readonly pid = FakeChild.nextPid++;
  connected = true;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  readonly sent: unknown[] = [];
  readonly channel = { unref: () => undefined };
  send(message: unknown, callback?: () => void): boolean {
    // The IPC channel serializes at send time, so the fake records a copy.
    this.sent.push(structuredClone(message));
    callback?.();
    return true;
  }
  kill(signal: NodeJS.Signals = "SIGTERM"): boolean {
    if (this.exitCode !== null || this.signalCode !== null) return false;
    this.signalCode = signal;
    this.connected = false;
    this.emit("exit", null, signal);
    return true;
  }
  unref(): void {}
}

/** Timers that run only when the test fires them, matched by requested delay. */
function manualTimers() {
  const pending = new Map<number, { ms: number; callback: () => void }>();
  let next = 1;
  const timers: WorkerTimers = {
    setTimeout: (callback, ms) => {
      const id = next++;
      pending.set(id, { ms, callback });
      return id;
    },
    clearTimeout: (handle) => { pending.delete(handle as number); },
  };
  return {
    timers,
    fire(ms: number) {
      for (const [id, timer] of [...pending]) {
        if (timer.ms !== ms) continue;
        pending.delete(id);
        timer.callback();
      }
    },
  };
}
