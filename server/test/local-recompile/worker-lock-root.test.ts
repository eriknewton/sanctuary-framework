// Fails on base by assertion: the worker there resolves its lock root from its own scrubbed environment.
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { LOCAL_OPLOG_NAMESPACE } from "../../src/local-recompile/store-record.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { LocalWorkerClient, type WorkerClientEvent } from "../../src/local-recompile/worker-client.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { isAlive } from "./helpers/local-task-server.js";

// The operator log's append lock file; must match APPEND_LOCK in src/local-recompile/oplog.ts.
const OPLOG_APPEND_LOCK = "append.lock";
const MASTER_KEY_BYTES = 32; // AES-256 master key
// Held for well under the worker's lock acquire timeout, long enough for an unblocked worker to report ready.
const HOLD_MS = 2_000;
const READY_WAIT_MS = 30_000;

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const step of cleanups.splice(0).reverse()) await step();
});

describe("local worker lock root", () => {
  it("the worker takes its store locks under the lock root the server resolved, which it learns only from init", async () => {
    // A short root under /tmp keeps the composed socket path under the kernel limit.
    const parent = await realpath(await mkdtemp("/tmp/lr1b-"));
    cleanups.push(() => rm(parent, { recursive: true, force: true }));
    const lockRoot = join(parent, "l");
    const fortress = await realpath(await mkdtemp("/tmp/lr1b-state-"));
    cleanups.push(() => rm(fortress, { recursive: true, force: true }));
    const storageRoot = join(fortress, "state");
    const storage = new FilesystemStorage(storageRoot);
    const keys = deriveLocalStoreKeys(new Uint8Array(MASTER_KEY_BYTES).fill(7));

    const events: WorkerClientEvent[] = [];
    let readyAt: number | undefined;
    const client = new LocalWorkerClient({
      storageRoot,
      custodyLockRoot: lockRoot,
      oplogKey: keys.oplogKey,
      resultsKey: keys.resultsKey,
      onEvent: (event) => {
        events.push(event);
        if (event.type === "state" && event.state === "state_READY" && readyAt === undefined) readyAt = Date.now();
      },
    });
    let pid: number | undefined;
    cleanups.push(async () => {
      await client.close();
      expect(isAlive(pid)).toBe(false);
    });

    // This process holds the operator log's append lock under the override root while the worker starts.
    let releasedAt = 0;
    await storage.withStrictNamespaceLock(LOCAL_OPLOG_NAMESPACE, OPLOG_APPEND_LOCK, async () => {
      client.start();
      pid = client.pid;
      await new Promise((resolve) => setTimeout(resolve, HOLD_MS));
      releasedAt = Date.now();
    }, { kernelBacked: true, runtimeRoot: lockRoot });

    const deadline = Date.now() + READY_WAIT_MS;
    while (readyAt === undefined && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    // The worker could open its stores only after this process released the same kernel lock.
    expect(readyAt).toBeDefined();
    expect(readyAt!).toBeGreaterThanOrEqual(releasedAt);
    expect(events.some((event) => event.type === "fault")).toBe(false);
  }, 60_000);
});
