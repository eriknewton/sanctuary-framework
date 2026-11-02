import { mkdtemp, mkdir, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { withPathLock, CrossProcessLockError } from "../../src/storage/cross-process-lock.js";
const roots: string[] = [];
afterEach(async () => { vi.useRealTimers(); vi.unstubAllEnvs(); for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });
it.each([100, 300])("kernel acquisition respects the earlier bound when caller budget is %s ms", async callerBudget => {
  const root = await mkdtemp(join(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "mono-")); roots.push(root); vi.stubEnv("HOME", root);
  const target = join(root, "d"); await mkdir(target, { mode: 0o700 });
  const runtimeRoot = join(root, "g");
  let clock = 0; let attempts = 0; let entered = false;
  vi.useFakeTimers({ toFake: ["Date"] });
  await withPathLock(target, ".test", async () => {
    await expect(withPathLock(target, ".test", async () => { entered = true; }, {
      kernelBacked: true, runtimeRoot, timeoutMs: 200, monotonicDeadlineMs: callerBudget,
      __testMonotonicNow: () => clock, retryMs: 1,
      onContended: () => { clock += 50; attempts++; vi.setSystemTime(attempts % 2 ? 0 : 4_000_000_000_000); },
    })).rejects.toMatchObject({ kind: "contention" });
  }, { kernelBacked: true, runtimeRoot });
  expect(clock).toBe(Math.min(200, callerBudget)); expect(entered).toBe(false);
  expect((await readdir(runtimeRoot)).filter(n => n.endsWith(".sock"))).toEqual([]);
});
it("an acquisition that exhausts its deadline during bind releases and never admits a late callback", async () => {
  const root = await mkdtemp(join(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "mono-")); roots.push(root); vi.stubEnv("HOME", root);
  const runtimeRoot = join(root, "g"); let clock = 0; let entered = false;
  await expect(withPathLock(join(root, "d"), ".test", async () => { entered = true; }, {
    kernelBacked: true, runtimeRoot, monotonicDeadlineMs: 100,
    __testMonotonicNow: () => clock, __testAfterKernelSocketAcquired: () => { clock = 100; },
  })).rejects.toBeInstanceOf(CrossProcessLockError);
  expect(entered).toBe(false);
  expect((await readdir(runtimeRoot)).filter(n => n.endsWith(".sock"))).toEqual([]);
});
