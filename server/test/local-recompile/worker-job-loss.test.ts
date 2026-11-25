// Every accepted job ends with an operator row, through the real server and worker processes.
import { fork, type ChildProcess, type ForkOptions } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocalOplog, type OplogRow } from "../../src/local-recompile/oplog.js";
import { LocalResultsStore } from "../../src/local-recompile/results-store.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { LocalWorkerClient, resolveWorkerModule } from "../../src/local-recompile/worker-client.js";
import { acceptMessage } from "../../src/local-recompile/worker-protocol.js";
import { LOCAL_RESULTS_NAMESPACE, withLocalStoreLock } from "../../src/local-recompile/store-record.js";
import { CROSS_PROCESS_LOCK_TIMEOUT_MS, resolveCustodyLockRoot } from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { openWorld, operatorRows, type World } from "./helpers/armed-world.js";
import { isAlive, localTaskPid, VALID_ARGS } from "./helpers/local-task-server.js";

vi.mock("../../src/intelligence/model-manifest.js", async (original) => {
  // Must match Q5E_PRIVATE_KEY in test/intelligence/q5e-fixtures.ts, which imports this module and so cannot be imported here.
  const { ed25519 } = await import("@noble/curves/ed25519");
  const key = ed25519.getPublicKey(new Uint8Array(32).fill(41));
  return { ...await original<typeof import("../../src/intelligence/model-manifest.js")>(), loadPinnedModelManifestKey: () => Uint8Array.from(key) };
});

// Long enough for a worker death and its drop rows on a loaded machine.
const ROW_WAIT_MS = 30_000;
const POLL_MS = 100;
// Released well before the worker's own wait for the results lock times out.
const LOCK_HOLD_MAX_MS = CROSS_PROCESS_LOCK_TIMEOUT_MS / 2;
const TEST_TIMEOUT_MS = 180_000;
const LOCK_ROOT = resolveCustodyLockRoot(process.getuid!(), { env: process.env, platform: process.platform });
const RECORD = { namespace: "notes", key: "one", value: "short note about the plan" };
const DROP_CHILD = fileURLToPath(new URL("./__fixtures__/worker-drop-child.ts", import.meta.url));
// Long enough for a terminal state the worker sent to reach the server, and for a late duplicate row to land.
const SETTLE_MS = 1_000;

const env = { ...process.env };
const worlds: World[] = [];
const children: ChildProcess[] = [];
const dirs: string[] = [];
afterEach(async () => {
  const failures: unknown[] = [];
  vi.restoreAllMocks();
  for (const world of worlds.splice(0).reverse()) {
    const workerPid = localTaskPid(world.server.runtime);
    try {
      await world.close();
      expect(isAlive(workerPid)).toBe(false);
      expect(isAlive(world.fake.pid)).toBe(false);
    } catch (error) {
      failures.push(error);
    }
  }
  for (const child of children.splice(0)) {
    try {
      if (child.exitCode === null && child.signalCode === null) {
        const exited = once(child, "exit");
        child.kill("SIGKILL");
        await exited;
      }
      expect(isAlive(child.pid)).toBe(false);
    } catch (error) {
      failures.push(error);
    }
  }
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }).catch((error) => failures.push(error));
  process.env = { ...env };
  if (failures.length > 0) throw failures[0];
});

async function world(options: Parameters<typeof openWorld>[0] = {}): Promise<World> {
  const opened = await openWorld(options);
  worlds.push(opened);
  return opened;
}

async function submit(w: World): Promise<string> {
  const answer = await w.server.call(VALID_ARGS);
  const parsed = JSON.parse(answer.text) as { status: string; request_id: string };
  expect(parsed.status).toBe("submitted");
  return parsed.request_id;
}

async function endRow(w: World, requestId: string): Promise<OplogRow> {
  const deadline = Date.now() + ROW_WAIT_MS;
  for (;;) {
    const row = (await operatorRows(w)).find((candidate) =>
      "request_id" in candidate.body && candidate.body.request_id === requestId &&
      ["job_committed", "job_refused", "job_failed", "job_dropped"].includes(candidate.kind));
    if (row !== undefined) return row;
    if (Date.now() > deadline) throw new Error(`no end row for ${requestId}`);
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + ROW_WAIT_MS;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}

/** The worker spawn seam, running the real worker under the drop fixture in `mode`. */
async function dropChild(mode: "hold" | "fail" | "plain"): Promise<{ marker: string; spawnWorker: (modulePath: string, args: string[], options: ForkOptions) => ChildProcess }> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "lr1b-drop-")));
  dirs.push(dir);
  const marker = join(dir, "drop-started");
  return { marker, spawnWorker: (_modulePath, _args, options) => fork(DROP_CHILD, [mode, marker], options) };
}

async function dropRows(w: World, requestId: string): Promise<OplogRow[]> {
  return (await operatorRows(w)).filter((row) => row.kind === "job_dropped" && "request_id" in row.body && row.body.request_id === requestId);
}

/** The job's drop rows once at least one is durable, or none after ROW_WAIT_MS; then a settle for late duplicates. */
async function settledDropRows(w: World, requestId: string): Promise<OplogRow[]> {
  const deadline = Date.now() + ROW_WAIT_MS;
  while ((await dropRows(w, requestId)).length === 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
  await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
  return dropRows(w, requestId);
}

type WriteFn = (child: ChildProcess, message: { type: string }) => boolean;
function spyOnAuthorityWrites(replace: (original: WriteFn, child: ChildProcess, message: { type: string }) => boolean): void {
  const prototype = LocalWorkerClient.prototype as unknown as { write: WriteFn };
  const original = prototype.write;
  vi.spyOn(prototype, "write").mockImplementation(function (this: unknown, child: ChildProcess, message: { type: string }) {
    if (message.type !== "authority_reply") return original.call(this, child, message);
    return replace((c, m) => original.call(this, c, m), child, message);
  });
}

describe("an accepted job always ends with an operator row", () => {
  it("a job sent to a worker that dies before reading it is recorded as dropped", async () => {
    const w = await world({ unarmed: true });
    const pid = localTaskPid(w.server.runtime)!;
    // The worker cannot read the job: it is stopped when the job is written, then killed.
    process.kill(pid, "SIGSTOP");
    const id = await submit(w);
    process.kill(pid, "SIGKILL");
    expect(await endRow(w, id)).toMatchObject({ kind: "job_dropped", body: { request_id: id, cause: "worker_unavailable" } });
  }, TEST_TIMEOUT_MS);

  it("a job the worker reads before its queue is open is recorded as dropped", async () => {
    const base = await realpath(await mkdtemp(join(tmpdir(), "lr1b-loss-")));
    dirs.push(base);
    const storageRoot = join(base, "state");
    const master = crypto.getRandomValues(new Uint8Array(32));
    const keys = deriveLocalStoreKeys(master);
    const storage = new FilesystemStorage(storageRoot);
    const oplog = new LocalOplog(storage, Uint8Array.from(keys.oplogKey), { runtimeRoot: LOCK_ROOT });
    const results = new LocalResultsStore(storage, Uint8Array.from(keys.resultsKey), oplog, { runtimeRoot: LOCK_ROOT });
    await oplog.ensure();
    await results.ensure();
    results.close();
    const { modulePath, execArgv } = resolveWorkerModule();
    const child = fork(modulePath, [], { execArgv, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "advanced" });
    children.push(child);
    const id = "ab".repeat(16);
    let drop: OplogRow | undefined;
    // The test holds the results lock, so the worker cannot finish opening its stores: it is still
    // starting when the job arrives, whatever the machine's load. The hold ends before the lock timeout.
    // "results.lock" must match RESULTS_LOCK in src/local-recompile/results-store.ts.
    await withLocalStoreLock(storage, LOCAL_RESULTS_NAMESPACE, "results.lock", async () => {
      child.send({ type: "init", storage_root: storageRoot, custody_lock_root: LOCK_ROOT, oplog_key: Uint8Array.from(keys.oplogKey), results_key: Uint8Array.from(keys.resultsKey) });
      child.send({ type: "job", request_id: id, seat: "agent:early", kind: "summarize", refs: [{ namespace: "notes", key: "one" }], instruction: "x" });
      const deadline = Date.now() + LOCK_HOLD_MAX_MS;
      while (drop === undefined && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, POLL_MS));
        const status = await oplog.status();
        drop = (await oplog.readRows(status.base_seq, status.rows)).find((row) => row.kind === "job_dropped");
      }
    }, { runtimeRoot: LOCK_ROOT });
    if (drop === undefined) throw new Error("no drop row");
    expect(drop.body).toEqual({ request_id: id, cause: "worker_unavailable" });
    oplog.close();
  }, TEST_TIMEOUT_MS);

  it("an authority reply whose write throws leaves the server running, refuses the job and records it", async () => {
    const w = await world({ unarmed: true });
    const firstPid = localTaskPid(w.server.runtime);
    spyOnAuthorityWrites(() => {
      throw new Error("injected write failure");
    });
    const id = await submit(w);
    expect(await endRow(w, id)).toMatchObject({ kind: "job_dropped", body: { request_id: id, cause: "worker_unavailable" } });
    // The server answered the failure by treating the worker as dead, and a new one replaces it.
    await until(() => w.server.runtime.localTask.workerState() === "state_READY" && localTaskPid(w.server.runtime) !== firstPid, "respawn");
    vi.restoreAllMocks();
    expect(JSON.parse((await w.server.call(VALID_ARGS)).text).status).toBe("submitted");
  }, TEST_TIMEOUT_MS);

  it("an authority reply whose write is refused leaves the server running, refuses the job and records it", async () => {
    const w = await world({ unarmed: true });
    spyOnAuthorityWrites(() => false);
    const id = await submit(w);
    expect(await endRow(w, id)).toMatchObject({ kind: "job_dropped", body: { request_id: id, cause: "worker_unavailable" } });
    await until(() => w.server.runtime.localTask.workerState() === "state_READY", "respawn");
    vi.restoreAllMocks();
    expect(JSON.parse((await w.server.call(VALID_ARGS)).text).status).toBe("submitted");
  }, TEST_TIMEOUT_MS);

  it("a reply that cannot be written is replaced by the refusal when the channel still takes it", async () => {
    const w = await world({ unarmed: true });
    let first = true;
    spyOnAuthorityWrites((original, child, message) => {
      if (first) {
        first = false;
        throw new Error("injected write failure");
      }
      return original(child, message);
    });
    const id = await submit(w);
    expect(await endRow(w, id)).toMatchObject({ kind: "job_refused", body: { request_id: id, cause: "request_unknown" } });
  }, TEST_TIMEOUT_MS);
});

describe("a terminal state is reported only after its operator row has settled", () => {
  it("the job_state shape carries row_written only as a boolean", () => {
    const base = { type: "job_state", request_id: "ab".repeat(16), state: "state_REFUSED" };
    expect(acceptMessage("to_parent", base)).toEqual(base);
    expect(acceptMessage("to_parent", { ...base, row_written: false })).toEqual({ ...base, row_written: false });
    expect(acceptMessage("to_parent", { ...base, row_written: true })).toEqual({ ...base, row_written: true });
    expect(acceptMessage("to_parent", { ...base, row_written: "false" })).toBeNull();
    expect(acceptMessage("to_parent", { ...base, row_written: false, extra: 1 })).toBeNull();
  });

  it("a drop whose row is still in flight when the worker dies is held by the server and written on exit", async () => {
    const drop = await dropChild("hold");
    const w = await world({ unarmed: true, seams: { spawnWorker: drop.spawnWorker } });
    const id = await submit(w);
    await until(() => existsSync(drop.marker), "the drop append to start");
    // A terminal state the worker had sent would reach the server in this time.
    await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
    process.kill(localTaskPid(w.server.runtime)!, "SIGKILL");
    expect((await settledDropRows(w, id)).map((row) => row.body)).toEqual([{ request_id: id, cause: "worker_unavailable" }]);
  }, TEST_TIMEOUT_MS);

  it("a drop whose row fails is written once by the server", async () => {
    const drop = await dropChild("fail");
    const w = await world({ unarmed: true, seams: { spawnWorker: drop.spawnWorker } });
    const id = await submit(w);
    expect((await settledDropRows(w, id)).map((row) => row.body)).toEqual([{ request_id: id, cause: "worker_unavailable" }]);
  }, TEST_TIMEOUT_MS);

  it("a drop whose row is durable is written once, by the worker, and not again when the worker dies", async () => {
    const drop = await dropChild("plain");
    const w = await world({ unarmed: true, seams: { spawnWorker: drop.spawnWorker } });
    const firstPid = localTaskPid(w.server.runtime);
    const id = await submit(w);
    expect((await settledDropRows(w, id)).map((row) => row.body)).toEqual([{ request_id: id, cause: "queue_full" }]);
    process.kill(firstPid!, "SIGKILL");
    await until(() => w.server.runtime.localTask.workerState() === "state_READY" && localTaskPid(w.server.runtime) !== firstPid, "respawn");
    expect((await settledDropRows(w, id)).map((row) => row.body)).toEqual([{ request_id: id, cause: "queue_full" }]);
  }, TEST_TIMEOUT_MS);
});

describe("the live status", () => {
  it("the queue depth returns to zero when the worker dies", async () => {
    const w = await world({ records: [RECORD], fakeScript: { mode: "stall" } });
    const status = w.server.runtime.localTask;
    await submit(w);
    await submit(w);
    await until(() => status.queueDepth() > 0, "a queued job");
    process.kill(localTaskPid(w.server.runtime)!, "SIGKILL");
    await until(() => status.workerState() !== "state_READY", "the death");
    expect(status.queueDepth()).toBe(0);
  }, TEST_TIMEOUT_MS);

  it("a boot whose binding is not armed reports the cause, not ready", async () => {
    const w = await world({ unarmed: true });
    expect(w.server.runtime.localTask.armed).toBe(true);
    expect(w.server.runtime.localTask.authorityCause()).toBe("unarmed");
  }, TEST_TIMEOUT_MS);
});
