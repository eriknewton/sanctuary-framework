// fail-before-exempt: startup arming of a tool absent on base; the response tests carry the fail-before evidence.
import { fork } from "node:child_process";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FORTRESS_STATE_DIRECTORY } from "../../src/core/custody-markers.js";
import { createSanctuaryServer } from "../../src/index.js";
import { LocalOplog } from "../../src/local-recompile/oplog.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import { bootLocalTaskServer, isAlive, prepareFortress, VALID_ARGS, type LocalTaskServer } from "./helpers/local-task-server.js";

// Must match UNAVAILABLE_TEXT in src/local-recompile/responses.ts.
const A3 = '{"status":"unavailable"}';
const SUBMITTED = /^\{"status":"submitted","request_id":"[0-9a-f]{32}","note":"Submitted\. Any result appears only in the user's Sanctuary dashboard\."\}$/;
// Long enough for a worker started under tsx to report ready again after its one-second respawn backoff.
const RESPAWN_WAIT_MS = 30_000;

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  vi.restoreAllMocks();
  const failures: unknown[] = [];
  for (const step of cleanups.splice(0).reverse()) {
    try { await step(); } catch (error) { failures.push(error); }
  }
  if (failures.length > 0) throw failures[0];
});

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("condition not reached");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function submissionRows(server: LocalTaskServer): Promise<number> {
  await server.runtime.auditLog.flush();
  const { entries } = await server.runtime.auditLog.query({ limit: 1_000 });
  return entries.filter((entry) => entry.operation === "local_request_submitted").length;
}

async function oplogRows(storagePath: string, masterKey: Uint8Array) {
  const keys = deriveLocalStoreKeys(masterKey);
  const oplog = new LocalOplog(new FilesystemStorage(join(storagePath, FORTRESS_STATE_DIRECTORY)), keys.oplogKey);
  try {
    return await oplog.readRows(0, 1_000);
  } finally {
    oplog.close();
    keys.oplogKey.fill(0);
    keys.resultsKey.fill(0);
  }
}

function captureStderr(): string[] {
  const lines: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string | Uint8Array, ...rest: unknown[]) => {
    lines.push(String(chunk));
    return (original as (...args: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write);
  return lines;
}

async function expectDisarmed(server: LocalTaskServer, cause: string, stderr: string[]): Promise<void> {
  const listed = await server.client.listTools();
  expect(listed.tools.some((tool) => tool.name === "sanctuary_local_task")).toBe(true);
  expect(server.runtime.localTask).toMatchObject({ armed: false, cause });
  for (let i = 0; i < 3; i += 1) expect((await server.call(VALID_ARGS)).text).toBe(A3);
  expect(await submissionRows(server)).toBe(0);
  expect(stderr.join("")).toContain(`Sanctuary local tasks disarmed: ${cause}`);
}

describe("local task startup", () => {
  it("an armed server lists the tool and runs its worker in a separate live process", async () => {
    const server = await bootLocalTaskServer();
    cleanups.push(() => server.close());
    expect(server.runtime.localTask.armed).toBe(true);
    const pid = server.runtime.localTask.workerPid();
    expect(pid).toBeDefined();
    expect(pid).not.toBe(process.pid);
    expect(isAlive(pid)).toBe(true);
    await server.close();
    expect(isAlive(pid)).toBe(false);
  }, 120_000);

  it("a killed worker still yields the acknowledgement, and the drop is recorded after the response", async () => {
    const server = await bootLocalTaskServer();
    cleanups.push(() => server.close());
    const pid = server.runtime.localTask.workerPid()!;
    process.kill(pid, "SIGKILL");
    await waitFor(() => server.runtime.localTask.workerState() !== "state_READY", 10_000);
    const append = vi.spyOn(LocalOplog.prototype, "append");
    const handler = (server.runtime.server as unknown as {
      _requestHandlers: Map<string, (request: unknown, extra: unknown) => Promise<{ content: Array<{ text: string }> }>>;
    })._requestHandlers.get("tools/call")!;
    const before = await submissionRows(server);
    const result = await handler({ method: "tools/call", params: { name: "sanctuary_local_task", arguments: VALID_ARGS } }, {});
    // The handler has returned and no drop append has started yet.
    const appendsAtResponse = append.mock.calls.length;
    expect(result.content[0]!.text).toMatch(SUBMITTED);
    expect(appendsAtResponse).toBe(0);
    await waitFor(() => append.mock.calls.length > 0, 10_000);
    await Promise.all(append.mock.results.map((entry) => entry.value));
    expect(append.mock.calls[0]![0]).toBe("job_dropped");
    const requestId = JSON.parse(result.content[0]!.text).request_id as string;
    expect(append.mock.calls[0]![1]).toEqual({ request_id: requestId, cause: "worker_unavailable" });
    expect((await submissionRows(server)) - before).toBe(1);
    const rows = await oplogRows(server.storagePath, server.runtime.masterKey);
    expect(rows.filter((row) => row.kind === "job_dropped").map((row) => row.body)).toEqual([
      { request_id: requestId, cause: "worker_unavailable" },
    ]);
    // The worker respawns as a new process.
    await waitFor(() => server.runtime.localTask.workerState() === "state_READY", RESPAWN_WAIT_MS);
    expect(server.runtime.localTask.workerPid()).not.toBe(pid);
    expect(isAlive(pid)).toBe(false);
  }, 120_000);

  it("startup failures disarm the tool: undecryptable local store", async () => {
    const fortress = await prepareFortress();
    cleanups.push(fortress.cleanup);
    const first = await bootLocalTaskServer({ storagePath: fortress.storagePath });
    await first.close();
    const storage = new FilesystemStorage(join(fortress.storagePath, FORTRESS_STATE_DIRECTORY));
    await storage.write("_local_oplog", "head", new TextEncoder().encode("not a sealed record"));
    const stderr = captureStderr();
    const server = await bootLocalTaskServer({ storagePath: fortress.storagePath });
    cleanups.push(() => server.close());
    await expectDisarmed(server, "stores_unavailable", stderr);
  }, 120_000);

  it("startup failures disarm the tool: worker spawn failing", async () => {
    const stderr = captureStderr();
    const server = await bootLocalTaskServer({
      seams: { spawnWorker: (_path, args, options) => fork(join(__dirname, "missing-worker-entry.mjs"), args, options) },
    });
    cleanups.push(() => server.close());
    await expectDisarmed(server, "worker_unavailable", stderr);
  }, 120_000);

  it("startup failures disarm the tool: injected memory storage", async () => {
    const home = await createTempHome("local-task-memory");
    cleanups.push(home.cleanup);
    const stderr = captureStderr();
    const runtime = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: TEST_PASSPHRASE,
      __testLocalTask: { spawnWorker: true },
    });
    cleanups.push(() => runtime.cleanup());
    expect(runtime.localTask).toMatchObject({ armed: false, cause: "storage_injected" });
    expect(stderr.join("")).toContain("Sanctuary local tasks disarmed: storage_injected");
  }, 120_000);

  it("under the test runner the worker starts only on an explicit opt-in", async () => {
    const fortress = await prepareFortress();
    cleanups.push(fortress.cleanup);
    const runtime = await createSanctuaryServer({
      passphrase: TEST_PASSPHRASE,
      approvalCallback: async () => ({ decision: "approve", decided_at: new Date().toISOString(), decided_by: "human" }),
    });
    cleanups.push(() => runtime.cleanup());
    expect(runtime.localTask).toMatchObject({ armed: false, cause: "test_runtime" });
    expect(runtime.localTask.workerPid()).toBeUndefined();
  }, 120_000);
});
