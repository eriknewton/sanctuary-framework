/** Opt-in audit process fencing and default-path compatibility. Job 996. */
import { mkdir, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditLog, type AuditLogConfig } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";

const DEADLINE_MS = 200; // Short fixture hold/load deadline; no production override.
const OBSERVE_MS = DEADLINE_MS * 3;
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const entry = (operation: string) => ({ layer: "l1" as const, operation, identity_id: "fixture", result: "success" as const });
class ControlledStorage extends FilesystemStorage {
  writeCalls = 0;
  readonly pendingWrites = new Set<Promise<void>>();
  hangWrite = false;
  hangRead = false;
  private releaseGate!: () => void;
  readonly gate = new Promise<void>(resolve => { this.releaseGate = resolve; });
  release() { this.hangRead = false; this.hangWrite = false; this.releaseGate(); }
  override async read(namespace: string, key: string) {
    if (this.hangRead) await this.gate;
    return super.read(namespace, key);
  }
  override writeDurable(namespace: string, key: string, bytes: Uint8Array): Promise<void> {
    const pending = this.writeControlled(namespace, key, bytes);
    this.pendingWrites.add(pending);
    void pending.then(() => this.pendingWrites.delete(pending), () => this.pendingWrites.delete(pending));
    return pending;
  }
  private async writeControlled(namespace: string, key: string, bytes: Uint8Array) {
    if (key.startsWith("entry-")) {
      this.writeCalls++;
      if (this.hangWrite) { this.hangWrite = false; await this.gate; }
    }
    await super.writeDurable(namespace, key, bytes);
  }
}
const roots: string[] = [];
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });
async function fixture(config: AuditLogConfig = {}) {
  const root = await mkdtemp("/tmp/j996-audit-"); roots.push(root);
  const storage = new ControlledStorage(join(root, "state"));
  const namespace = join(root, "state", "_audit");
  await mkdir(namespace, { recursive: true, mode: 0o700 });
  const log = new AuditLog(storage, generateRandomKey(), { checkpointInterval: 0, writeLockHoldDeadlineMs: DEADLINE_MS, ...config });
  return { root, namespace, storage, log, lock: join(namespace, ".audit-write.lock") };
}

describe("audit process exit fence", () => {
  it("holds the lock and serializes the next append when a recorder returns", async () => {
    const exit = vi.fn();
    const f = await fixture({ processExitFence: { firstLoadDeadlineMs: OBSERVE_MS, exit } });
    f.storage.hangWrite = true;
    const first = f.log.appendCritical(entry("first"));
    const second = f.log.appendCritical(entry("second"));
    let settled = false;
    void first.then(() => { settled = true; }, () => { settled = true; });
    void second.catch(() => undefined);
    try {
      await sleep(OBSERVE_MS);
      expect(exit).toHaveBeenCalledExactlyOnceWith({ fence: "fence_HOLD_DEADLINE_LAPSED", lockPath: f.lock, deadlineMs: DEADLINE_MS });
      expect(settled).toBe(false);
      expect((await stat(f.lock)).isFile()).toBe(true);
      expect(f.storage.writeCalls).toBe(1);
      expect(f.log.getWriteLockRecoveryCount()).toBe(0);
      f.storage.release();
      await Promise.all([first, second]);
      const query = await f.log.query({});
      expect(query.integrity_findings).toEqual([]);
      expect(query.entries.map(value => value.operation).sort()).toEqual(["first", "second"]);
      const files = (await readdir(f.namespace)).filter(name => name.startsWith("entry-")).sort();
      const sequences = await Promise.all(files.map(async file => JSON.parse(await readFile(join(f.namespace, file), "utf8")).sequence));
      expect(sequences).toEqual([1, 2]);
    } finally {
      f.storage.release();
      await Promise.allSettled([first, second]);
      await Promise.allSettled([...f.storage.pendingWrites]);
    }
  });

  it.each(["append", "query", "eager"] as const)("fences the first unsettled load through %s without requesting a write lock", async path => {
    const exit = vi.fn();
    const f = await fixture({ processExitFence: { firstLoadDeadlineMs: DEADLINE_MS, exit } });
    f.storage.hangRead = true;
    const lock = vi.spyOn(f.log as unknown as { withAuditWriteLock: (...args: unknown[]) => Promise<unknown> }, "withAuditWriteLock");
    const operation = path === "append" ? f.log.appendCritical(entry("loaded")) : path === "query" ? f.log.query({}) : f.log.queryEager({});
    void operation.catch(() => undefined);
    try {
      await sleep(OBSERVE_MS);
      expect(exit).toHaveBeenCalledExactlyOnceWith({ fence: "fence_FIRST_LOAD_UNSETTLED", deadlineMs: DEADLINE_MS });
      expect(lock).not.toHaveBeenCalled();
      await expect(stat(f.lock)).rejects.toMatchObject({ code: "ENOENT" });
    } finally { f.storage.release(); await operation; lock.mockRestore(); }
  });

  it("clears the first-load timer and never fires while an already loaded log is idle", async () => {
    const exit = vi.fn();
    const f = await fixture({ processExitFence: { firstLoadDeadlineMs: DEADLINE_MS, exit } });
    await f.log.query({});
    await sleep(OBSERVE_MS);
    expect(exit).not.toHaveBeenCalled();
    await f.log.queryEager({});
    await sleep(OBSERVE_MS);
    expect(exit).not.toHaveBeenCalled();
  });

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])("rejects invalid first-load deadline %s", async deadline => {
    await expect(fixture({ processExitFence: { firstLoadDeadlineMs: deadline, exit: vi.fn() } })).rejects.toThrow("positive finite");
  });

  it("default AuditLog has no process exit fence", async () => {
    const { log } = await fixture();
    expect(log.processExitFence).toBeUndefined();
    await log.appendCritical(entry("default"));
    expect((await log.query({})).integrity_findings).toEqual([]);
  });
});
