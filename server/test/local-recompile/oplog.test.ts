// fail-before-exempt: new operator-log module, no base behaviour.
import { afterEach, describe, expect, it } from "vitest";
import { fork, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  LocalOplog,
  OPLOG_MAX_BYTES,
  OPLOG_MAX_ROWS,
  OPLOG_PRUNE_MAX_PER_APPEND,
  OPLOG_ROW_MAX_BYTES,
  oplogRowKey,
  type OplogOptions,
} from "../../src/local-recompile/oplog.js";
import { LOCAL_OPLOG_NAMESPACE, LocalStoreError } from "../../src/local-recompile/store-record.js";
import { SHORT_SOCKET_TMP_PARENT } from "../helpers/short-socket-tmp-parent.js";
import { StrictMemoryStorage, fixtureStoreKeys } from "./__fixtures__/strict-memory-storage.js";

const FIXED_NOW = Date.UTC(2026, 0, 1);
const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  // Each cleanup runs even when an earlier one throws, so a failed reap never skips the rest.
  const failures: unknown[] = [];
  for (const cleanup of cleanups.splice(0).reverse()) {
    try {
      await cleanup();
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) throw failures[0];
});

async function openLog(options: OplogOptions = {}, storage = new StrictMemoryStorage()) {
  const keys = fixtureStoreKeys();
  const log = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW, ...options });
  cleanups.push(() => {
    log.close();
    keys.oplogKey.fill(0);
    keys.resultsKey.fill(0);
  });
  await log.ensure();
  return { storage, keys, log };
}

function rowDeletes(storage: StrictMemoryStorage, from = 0): number {
  return storage.calls.slice(from).filter((call) => call.op === "delete" && call.key?.startsWith("row/")).length;
}

describe("operator log chain", () => {
  it("appended rows verify from base to head", async () => {
    const { log } = await openLog();
    await log.append("worker_spawned", { pid: 4242 });
    await log.append("worker_died", { pid: 4242, cause: "signal" });
    expect(await log.verifyChain()).toEqual({ ok: true, base_seq: 0, head_seq: 2 });
    expect((await log.readRows(0, 3)).map((row) => row.kind)).toEqual(["genesis", "worker_spawned", "worker_died"]);
  });

  it.each(["reordered", "edited", "removed"] as const)("a %s row is reported at its seq", async (damage) => {
    const { storage, log } = await openLog();
    await log.append("worker_spawned", { pid: 4242 });
    await log.append("worker_died", { pid: 4242, cause: "exit" });
    const first = (await storage.read(LOCAL_OPLOG_NAMESPACE, oplogRowKey(1)))!;
    if (damage === "reordered") {
      const second = (await storage.read(LOCAL_OPLOG_NAMESPACE, oplogRowKey(2)))!;
      await storage.write(LOCAL_OPLOG_NAMESPACE, oplogRowKey(1), second);
      await storage.write(LOCAL_OPLOG_NAMESPACE, oplogRowKey(2), first);
    } else if (damage === "edited") {
      const envelope = JSON.parse(Buffer.from(first).toString("utf8")) as { ct: string };
      envelope.ct = (envelope.ct.startsWith("A") ? "B" : "A") + envelope.ct.slice(1);
      await storage.write(LOCAL_OPLOG_NAMESPACE, oplogRowKey(1), Buffer.from(JSON.stringify(envelope)));
    } else {
      await storage.delete(LOCAL_OPLOG_NAMESPACE, oplogRowKey(1));
    }
    const verdict = await log.verifyChain();
    expect(verdict).toMatchObject({ ok: false, seq: 1 });
  });

  it("an append interrupted after its row write is rolled forward by the next append", async () => {
    let interrupt = false;
    const { storage, keys, log } = await openLog({
      onAppendState: (state) => {
        if (state === "state_ROW_WRITTEN" && interrupt) {
          interrupt = false;
          throw new Error("fixture interruption");
        }
      },
    });
    interrupt = true;
    await expect(log.append("worker_spawned", { pid: 1 })).rejects.toMatchObject({ kind: "io" });
    expect((await log.status()).head_seq).toBe(0);
    const resumed = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW });
    cleanups.push(() => resumed.close());
    expect((await resumed.append("worker_spawned", { pid: 2 })).seq).toBe(2);
    expect(await resumed.verifyChain()).toEqual({ ok: true, base_seq: 0, head_seq: 2 });
    expect((await resumed.readRows(1, 2)).map((row) => row.body)).toEqual([{ pid: 1 }, { pid: 2 }]);
  });

  it("a row that names a different predecessor is refused, never linked", async () => {
    const { storage, keys, log } = await openLog();
    await log.append("worker_spawned", { pid: 1 });
    // Same key, so the planted row authenticates; only its link is foreign.
    const otherStorage = new StrictMemoryStorage();
    const other = new LocalOplog(otherStorage, keys.oplogKey, { now: () => FIXED_NOW });
    cleanups.push(() => other.close());
    await other.ensure();
    await other.append("worker_spawned", { pid: 9 });
    await other.append("worker_spawned", { pid: 9 });
    const foreign = (await otherStorage.read(LOCAL_OPLOG_NAMESPACE, oplogRowKey(2)))!;
    await storage.write(LOCAL_OPLOG_NAMESPACE, oplogRowKey(2), foreign);
    await expect(log.append("worker_spawned", { pid: 1 })).rejects.toMatchObject({ kind: "invalid_record" });
  });

  it("an oplog append whose write hangs holds the lock and a second writer refuses after the acquire timeout", async () => {
    const { storage, keys, log } = await openLog({ timeoutMs: OPLOG_ACQUIRE_TIMEOUT_FIXTURE_MS });
    let releaseWrite!: () => void;
    const writeStalled = new Promise<void>((resolve) => { releaseWrite = resolve; });
    let reachedWrite!: () => void;
    const atWrite = new Promise<void>((resolve) => { reachedWrite = resolve; });
    storage.beforeMutation = async (call) => {
      if (call.op === "create") {
        reachedWrite();
        await writeStalled;
      }
    };
    let elapseAcquireWait!: () => void;
    const requested: number[] = [];
    storage.acquireWait = (ms) => {
      requested.push(ms);
      return new Promise<void>((resolve) => { elapseAcquireWait = resolve; });
    };
    const hung = log.append("worker_spawned", { pid: 1 });
    await atWrite;
    const second = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW, timeoutMs: OPLOG_ACQUIRE_TIMEOUT_FIXTURE_MS });
    cleanups.push(() => second.close());
    const contender = second.append("worker_spawned", { pid: 2 });
    await waitFor(() => requested.length === 1);
    expect(requested).toEqual([OPLOG_ACQUIRE_TIMEOUT_FIXTURE_MS]);
    elapseAcquireWait();
    await expect(contender).rejects.toMatchObject({ kind: "lock" });
    storage.beforeMutation = () => undefined;
    releaseWrite();
    expect((await hung).seq).toBe(1);
    expect(await log.verifyChain()).toEqual({ ok: true, base_seq: 0, head_seq: 1 });
  });
});

// The fixture acquire bound; the real default is CROSS_PROCESS_LOCK_TIMEOUT_MS.
const OPLOG_ACQUIRE_TIMEOUT_FIXTURE_MS = 250;

async function waitFor(condition: () => boolean): Promise<void> {
  while (!condition()) await new Promise((resolve) => setImmediate(resolve));
}

describe("operator log retention", () => {
  it("pins the production retention constants", () => {
    expect(OPLOG_MAX_ROWS).toBe(50_000);
    expect(OPLOG_MAX_BYTES).toBe(32 * 1024 * 1024);
    expect(OPLOG_ROW_MAX_BYTES).toBe(4 * 1024);
    expect(OPLOG_PRUNE_MAX_PER_APPEND).toBe(64);
  });

  it("appends past the caps keep at most the row cap and the byte cap, and each append prunes at most the per-append bound", async () => {
    const caps = { maxRows: 40, maxBytes: 40 * 700, prunePerAppend: 4 };
    // Twenty times the row cap: the steady state is reached and held many times over.
    const appends = caps.maxRows * 20;
    const { storage, log } = await openLog({ caps });
    for (let index = 0; index < appends; index += 1) {
      const before = storage.calls.length;
      await log.append("worker_spawned", { pid: index + 1 });
      expect(rowDeletes(storage, before)).toBeLessThanOrEqual(caps.prunePerAppend);
      const status = await log.status();
      expect(status.rows).toBeLessThanOrEqual(caps.maxRows);
      expect(status.total_bytes).toBeLessThanOrEqual(caps.maxBytes);
    }
    expect(await log.verifyChain()).toMatchObject({ ok: true, head_seq: appends });
  });

  it("the byte cap alone bounds retention when the row cap is far away", async () => {
    const probe = await openLog();
    await probe.log.append("worker_spawned", { pid: 1 });
    const one = (await probe.log.status()).total_bytes;
    await probe.log.append("worker_spawned", { pid: 2 });
    const rowBytes = (await probe.log.status()).total_bytes - one;
    // Ten rows' worth of bytes, with a row cap a hundred times higher, so only the byte cap can bind.
    const BYTE_CAP_ROWS = 10;
    const caps = { maxRows: BYTE_CAP_ROWS * 100, maxBytes: BYTE_CAP_ROWS * rowBytes, prunePerAppend: 4 };
    const appends = BYTE_CAP_ROWS * 20;
    expect(appends * rowBytes).toBeGreaterThan(caps.maxBytes);
    const { storage, log } = await openLog({ caps });
    for (let index = 0; index < appends; index += 1) {
      await log.append("worker_spawned", { pid: index + 1 });
      const status = await log.status();
      expect(status.total_bytes).toBeLessThanOrEqual(caps.maxBytes);
      // The head's byte count is the stored row bytes, measured directly.
      let stored = 0;
      for (const key of await storage.listKeys(LOCAL_OPLOG_NAMESPACE, "row/")) stored += (await storage.read(LOCAL_OPLOG_NAMESPACE, key))!.length;
      expect(stored).toBe(status.total_bytes);
    }
    const status = await log.status();
    expect(status.rows).toBeLessThan(caps.maxRows);
    expect(status.rows).toBeLessThanOrEqual(BYTE_CAP_ROWS + 1);
    expect(await log.verifyChain()).toMatchObject({ ok: true, head_seq: appends });
  });

  it("a prune interrupted after its intent and before its anchor still verifies, and the next append completes it", async () => {
    const { storage, keys, log } = await openLog({ caps: { maxRows: 3 } });
    for (let index = 0; index < 3; index += 1) await log.append("worker_spawned", { pid: index + 1 });
    const baseBefore = (await log.status()).base_seq;
    let intentWritten = false;
    storage.beforeMutation = (call) => {
      if (call.op === "write" && call.key === "prune") intentWritten = true;
      else if (intentWritten && call.op === "write" && call.key === "anchor") throw new Error("fixture crash before the anchor moves");
    };
    await expect(log.append("worker_spawned", { pid: 9 })).rejects.toBeInstanceOf(LocalStoreError);
    storage.beforeMutation = () => undefined;
    expect(intentWritten).toBe(true);
    const resumed = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW, caps: { maxRows: 3 } });
    cleanups.push(() => resumed.close());
    // No row has left yet, so the chain still verifies from the base it had before the interrupted prune.
    expect(await resumed.verifyChain()).toMatchObject({ ok: true, base_seq: baseBefore, head_seq: 4 });
    await resumed.append("worker_spawned", { pid: 10 });
    expect(await resumed.verifyChain()).toMatchObject({ ok: true, head_seq: 5 });
    expect((await resumed.status()).rows).toBeLessThanOrEqual(3);
  });

  it("a backlog above the cap drains at most the per-append bound per append", async () => {
    const backlog = OPLOG_PRUNE_MAX_PER_APPEND * 3;
    const { storage, keys, log } = await openLog();
    for (let index = 0; index < backlog; index += 1) await log.append("worker_spawned", { pid: index + 1 });
    const capped = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW, caps: { maxRows: 2 } });
    cleanups.push(() => capped.close());
    const drained: number[] = [];
    while ((await capped.status()).rows > 2) {
      const before = storage.calls.length;
      await capped.append("worker_spawned", { pid: 1 });
      drained.push(rowDeletes(storage, before));
    }
    expect(Math.max(...drained)).toBe(OPLOG_PRUNE_MAX_PER_APPEND);
    expect(await capped.verifyChain()).toMatchObject({ ok: true });
  });

  it("the anchor is written before any delete", async () => {
    const { storage, log } = await openLog({ caps: { maxRows: 3 } });
    for (let index = 0; index < 3; index += 1) await log.append("worker_spawned", { pid: index + 1 });
    const before = storage.calls.length;
    await log.append("worker_spawned", { pid: 9 });
    const calls = storage.calls.slice(before);
    const anchorWrite = calls.findIndex((call) => call.op === "write" && call.key === "anchor");
    const firstDelete = calls.findIndex((call) => call.op === "delete" && call.key?.startsWith("row/"));
    expect(firstDelete).toBeGreaterThan(-1);
    expect(anchorWrite).toBeGreaterThan(-1);
    expect(anchorWrite).toBeLessThan(firstDelete);
    expect(await log.verifyChain()).toMatchObject({ ok: true, base_seq: 2 });
  });

  it("a prune interrupted after its anchor is completed by the next append", async () => {
    const { storage, keys, log } = await openLog({ caps: { maxRows: 3 } });
    for (let index = 0; index < 3; index += 1) await log.append("worker_spawned", { pid: index + 1 });
    storage.beforeMutation = (call) => {
      if (call.op === "delete" && call.key?.startsWith("row/")) throw new Error("fixture crash mid-prune");
    };
    await expect(log.append("worker_spawned", { pid: 9 })).rejects.toBeInstanceOf(LocalStoreError);
    storage.beforeMutation = () => undefined;
    const resumed = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW, caps: { maxRows: 3 } });
    cleanups.push(() => resumed.close());
    expect(await resumed.verifyChain()).toMatchObject({ ok: true });
    await resumed.append("worker_spawned", { pid: 10 });
    expect(await resumed.verifyChain()).toMatchObject({ ok: true, head_seq: 5 });
    expect((await resumed.status()).rows).toBeLessThanOrEqual(3);
  });

  it("an undecryptable row stops the prune before its delete and records one prune_blocked row", async () => {
    const { storage, log } = await openLog({ caps: { maxRows: 3 } });
    for (let index = 0; index < 2; index += 1) await log.append("worker_spawned", { pid: index + 1 });
    await storage.write(LOCAL_OPLOG_NAMESPACE, oplogRowKey(0), Buffer.from("{\"not\":\"sealed\"}"));
    const before = storage.calls.length;
    await log.append("worker_spawned", { pid: 3 });
    await log.append("worker_spawned", { pid: 4 });
    expect(rowDeletes(storage, before)).toBe(0);
    const status = await log.status();
    expect(status).toMatchObject({ base_seq: 0, prune_blocked: true, over_cap: true });
    const rows = await log.readRows(1, status.head_seq);
    expect(rows.filter((row) => row.kind === "prune_blocked").map((row) => row.body)).toEqual([{ base_seq: 0 }]);
  });
});

describe("operator log boot refusals", () => {
  it("a head whose anchor is gone refuses at ensure", async () => {
    const { storage, keys, log } = await openLog();
    await log.append("worker_spawned", { pid: 1 });
    await storage.delete(LOCAL_OPLOG_NAMESPACE, "anchor");
    const reopened = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW });
    cleanups.push(() => reopened.close());
    await expect(reopened.ensure()).rejects.toMatchObject({ kind: "invalid_record" });
  });

  it("rows past genesis with no head or anchor refuse at ensure rather than re-initialize", async () => {
    const { storage, keys, log } = await openLog();
    await log.append("worker_spawned", { pid: 1 });
    await log.append("worker_spawned", { pid: 2 });
    await storage.delete(LOCAL_OPLOG_NAMESPACE, "head");
    await storage.delete(LOCAL_OPLOG_NAMESPACE, "anchor");
    const reopened = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW });
    cleanups.push(() => reopened.close());
    await expect(reopened.ensure()).rejects.toMatchObject({ kind: "invalid_record" });
  });

  it("after retention removed genesis, a lost head and anchor refuse at ensure rather than re-initialize", async () => {
    const { storage, keys, log } = await openLog({ caps: { maxRows: 3 } });
    for (let pid = 1; pid <= 6; pid += 1) await log.append("worker_spawned", { pid });
    // Retention has pruned row/0 and row/1, so the surviving suffix starts later.
    expect(await storage.read(LOCAL_OPLOG_NAMESPACE, oplogRowKey(0))).toBeNull();
    expect(await storage.read(LOCAL_OPLOG_NAMESPACE, oplogRowKey(1))).toBeNull();
    await storage.delete(LOCAL_OPLOG_NAMESPACE, "head");
    await storage.delete(LOCAL_OPLOG_NAMESPACE, "anchor");
    const surviving = await storage.listKeys(LOCAL_OPLOG_NAMESPACE, "row/");
    const reopened = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW, caps: { maxRows: 3 } });
    cleanups.push(() => reopened.close());
    await expect(reopened.ensure()).rejects.toMatchObject({ kind: "invalid_record" });
    // Nothing was written over the suffix: no new genesis, head or anchor.
    expect(await storage.listKeys(LOCAL_OPLOG_NAMESPACE, "row/")).toEqual(surviving);
    expect(await storage.read(LOCAL_OPLOG_NAMESPACE, "head")).toBeNull();
  });

  it("a prune record with no head or anchor refuses at ensure", async () => {
    const { storage, keys, log } = await openLog();
    await storage.delete(LOCAL_OPLOG_NAMESPACE, "head");
    await storage.delete(LOCAL_OPLOG_NAMESPACE, "anchor");
    // Any prune record is evidence of a log that once had a head.
    await storage.write(LOCAL_OPLOG_NAMESPACE, "prune", new TextEncoder().encode("left by a prune"));
    log.close();
    const reopened = new LocalOplog(storage, keys.oplogKey, { now: () => FIXED_NOW });
    cleanups.push(() => reopened.close());
    await expect(reopened.ensure()).rejects.toMatchObject({ kind: "invalid_record" });
  });
});

describe("operator log capability refusals", () => {
  it("a backend without the strict lock refuses at construction", () => {
    const keys = fixtureStoreKeys();
    const plain = { read: async () => null } as unknown as StrictMemoryStorage;
    expect(() => new LocalOplog(plain, keys.oplogKey)).toThrow(LocalStoreError);
  });

  it("a key that is not 32 bytes refuses", () => {
    const SHORT_KEY_BYTES = 16; // half an AES-256 key
    expect(() => new LocalOplog(new StrictMemoryStorage(), new Uint8Array(SHORT_KEY_BYTES))).toThrow(LocalStoreError);
  });

  it("an append before the store exists refuses rather than creating one", async () => {
    const keys = fixtureStoreKeys();
    const log = new LocalOplog(new StrictMemoryStorage(), keys.oplogKey);
    cleanups.push(() => log.close());
    await expect(log.append("worker_spawned", { pid: 1 })).rejects.toMatchObject({ kind: "not_found" });
  });

  it("a body field outside the kind's schema is refused before the lock", async () => {
    const { storage, log } = await openLog();
    const before = storage.calls.length;
    await expect(log.append("worker_spawned", { pid: 1, note: "text" } as never)).rejects.toMatchObject({ kind: "invalid_record" });
    expect(storage.calls.length).toBe(before);
  });
});

describe("operator log across processes", () => {
  const CHILD_APPENDS = 50;
  const PARENT_APPENDS = 50;

  it("two processes append to one log without a gap or a fork", async () => {
    const base = await realpath(await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "lro-")));
    cleanups.push(() => rm(base, { recursive: true, force: true }));
    const root = join(base, "state");
    const runtimeRoot = await realpath(await mkdtemp(join(base, "r")));
    const storage = new FilesystemStorage(root);
    const keys = fixtureStoreKeys();
    const log = new LocalOplog(storage, keys.oplogKey, { runtimeRoot });
    cleanups.push(() => log.close());
    await log.ensure();
    const childPath = fileURLToPath(new URL("./__fixtures__/oplog-append-child.ts", import.meta.url));
    const child: ChildProcess = fork(childPath, [root, runtimeRoot, String(CHILD_APPENDS)], {
      execArgv: ["--import", import.meta.resolve("tsx")],
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    cleanups.push(() => reap(child));
    const reply = replyOrExit(child);
    child.send({ key: Buffer.from(keys.oplogKey).toString("base64") });
    for (let index = 0; index < PARENT_APPENDS; index += 1) await log.append("worker_spawned", { pid: process.pid });
    const [message] = (await reply) as [{ done: boolean }];
    expect(message).toEqual({ done: true });
    expect(await log.verifyChain()).toEqual({ ok: true, base_seq: 0, head_seq: CHILD_APPENDS + PARENT_APPENDS });
    const rows = await log.readRows(0, CHILD_APPENDS + PARENT_APPENDS + 1);
    expect(rows.map((row) => row.seq)).toEqual(Array.from({ length: CHILD_APPENDS + PARENT_APPENDS + 1 }, (_, seq) => seq));
    expect(rows.filter((row) => row.kind === "worker_spawned" && row.body.pid === child.pid)).toHaveLength(CHILD_APPENDS);
  }, 120_000);
});

// Bounded graceful wait before SIGKILL when reaping a fixture child.
const REAP_GRACE_MS = 2_000;

async function reap(child: ChildProcess): Promise<void> {
  if (child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit");
    const timer = setTimeout(() => child.kill("SIGKILL"), REAP_GRACE_MS);
    child.kill("SIGTERM");
    await exited;
    clearTimeout(timer);
  }
  // Checked on every path, including a child that had already exited.
  expect(isAlive(child.pid)).toBe(false);
}

/** The child's first message, or a refusal as soon as it exits without one, so an early crash fails fast. */
function replyOrExit(child: ChildProcess): Promise<unknown[]> {
  return new Promise((resolve, reject) => {
    const onMessage = (...message: unknown[]) => {
      child.off("exit", onExit);
      resolve(message);
    };
    const onExit = () => {
      child.off("message", onMessage);
      reject(new Error("append child exited before replying"));
    };
    child.once("message", onMessage);
    child.once("exit", onExit);
  });
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
