/** Kernel admissions honor cancellation and reuse directory filesystem verdicts. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as fs from "node:fs/promises";
import * as childProcess from "node:child_process";
vi.mock("node:fs/promises", async importOriginal => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, statfs: vi.fn(actual.statfs), lstat: vi.fn(actual.lstat), stat: vi.fn(actual.stat) };
});
vi.mock("node:child_process", async importOriginal => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CROSS_PROCESS_LOCK_RETRY_MS } from "../../src/storage/cross-process-lock.js";

let directory: string;
let locks: typeof import("../../src/storage/cross-process-lock.js");
const pending: Promise<unknown>[] = [];
const releases: Array<() => void> = [];
beforeEach(async () => {
  // Each test starts a process-lifetime cache independently; directory inodes can be reused after teardown.
  vi.resetModules();
  // Factory mocks retain implementations across restoreAllMocks; each fault schedule must start with real I/O.
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  vi.mocked(fs.stat).mockReset().mockImplementation(actual.stat);
  vi.mocked(fs.lstat).mockReset().mockImplementation(actual.lstat);
  vi.mocked(fs.statfs).mockReset().mockImplementation(actual.statfs);
  locks = await import("../../src/storage/cross-process-lock.js");
  directory = await fs.mkdtemp(join(tmpdir(), "kernel-admission-"));
});
afterEach(async () => {
  for (const release of releases.splice(0)) release();
  await Promise.allSettled(pending.splice(0));
  vi.restoreAllMocks();
  await fs.rm(directory, { recursive: true, force: true });
});

it("aborts kernel contention within one retry interval", async () => {
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const held = new Promise<void>(resolve => { release = resolve; });
  releases.push(release);
  const holder = locks.withPathLock(directory, "admission.lock", async () => { entered(); await held; }, { kernelBacked: true });
  pending.push(holder);
  await ready;
  const controller = new AbortController();
  let abortedAt = 0;
  let ran = false;
  const contender = locks.withPathLock(directory, "admission.lock", async () => { ran = true; }, {
    kernelBacked: true,
    // Ten retries leave room to distinguish cancellation from the lock timeout.
    timeoutMs: CROSS_PROCESS_LOCK_RETRY_MS * 10,
    onContended: () => { queueMicrotask(() => { abortedAt = performance.now(); controller.abort(); }); },
    abortSignal: controller.signal,
  });
  pending.push(contender);
  await expect(contender).rejects.toMatchObject({ kind: "operation_aborted" });
  expect(performance.now() - abortedAt).toBeLessThan(CROSS_PROCESS_LOCK_RETRY_MS);
  expect(ran).toBe(false);
});

it("checks filesystem locality once across many admissions for each directory", async () => {
  vi.mocked(fs.statfs).mockClear();
  vi.mocked(childProcess.spawn).mockClear();
  const checkedPaths = () => process.platform === "darwin"
    ? vi.mocked(childProcess.spawn).mock.calls.filter(([command]) => command === "/bin/df").map(([, args]) => String(args![1]))
    : vi.mocked(fs.statfs).mock.calls.map(([path]) => String(path));
  const admissions = 10; // A burst on one directory should reuse one locality verdict.
  for (let n = 0; n < admissions; n++) {
    await locks.withPathLock(directory, "admission.lock", async () => {}, { kernelBacked: true });
  }
  expect(checkedPaths().filter(path => path === directory)).toHaveLength(1);
  const paths = checkedPaths();
  expect(new Set(paths).size).toBe(paths.length);
  // A different directory inode must receive its own verdict.
  const other = join(directory, "other");
  await locks.withPathLock(other, "admission.lock", async () => {}, { kernelBacked: true });
  expect(checkedPaths().filter(path => path === other)).toHaveLength(1);
});


it("bounds pending filesystem verdicts and releases failed identities", async () => {
  const stats = await fs.stat(directory, { bigint: true });
  let inode = stats.ino;
  vi.mocked(fs.stat).mockImplementation(async () => ({ ...stats, ino: ++inode }) as never);
  // Must match MAX_LOCK_FILESYSTEM_VERDICTS in storage/cross-process-lock.ts: 64 scopes times 64 directories.
  const cap = 64 * 64;
  let filled!: () => void, rejectProbes!: (error: Error) => void;
  const atCapacity = new Promise<void>(resolve => { filled = resolve; });
  const probes = new Promise<never>((_resolve, reject) => { rejectProbes = reject; });
  releases.push(() => rejectProbes(new Error("refused filesystem probe")));
  const check = vi.mocked(fs.statfs).mockImplementation(() => {
    if (check.mock.calls.length === cap) filled();
    return probes;
  });
  check.mockClear();
  const acquire = () => locks.withPathLock(directory, "admission.lock", async () => {}, { kernelBacked: true, __testPlatform: "linux" });
  for (let n = 0; n < cap; n++) pending.push(expect(acquire()).rejects.toThrow("refused filesystem probe"));
  await atCapacity;
  const waves = 3; // Repeated identities beyond capacity cannot start inspection or grow retained state.
  for (let n = 0; n < waves; n++) await expect(acquire()).rejects.toMatchObject({ kind: "capability" });
  expect(check).toHaveBeenCalledTimes(cap);
  rejectProbes(new Error("refused filesystem probe"));
  await Promise.all(pending);
  // Rejected identities leave the map, so a new identity probes instead of staying at capacity.
  await expect(acquire()).rejects.toThrow("refused filesystem probe");
  expect(check).toHaveBeenCalledTimes(cap + 1);
});

it.skipIf(process.platform !== "linux")("reprobes the directory when a proc descriptor number is reused", async () => {
  const other = join(directory, "other");
  await fs.mkdir(other, { mode: 0o700 }); // Kernel custody directories are private to the invoking uid.
  let handle = await fs.open(directory, "r");
  try {
    const fd = handle.fd;
    const path = `/proc/self/fd/${fd}`;
    vi.mocked(fs.statfs).mockClear();
    await locks.withPathLock(path, "admission.lock", async () => {}, { kernelBacked: true });
    expect(vi.mocked(fs.statfs).mock.calls.filter(([value]) => value === path)).toHaveLength(1);
    await handle.close();
    handle = await fs.open(other, "r");
    expect(handle.fd).toBe(fd);
    // Refuse the second target so inherited admission cannot hide behind two successful local probes.
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    vi.mocked(fs.statfs).mockImplementation(async (value, options) => {
      if (value === path) throw new Error("second directory probe refused");
      return actual.statfs(value, options as never) as never;
    });
    await expect(locks.withPathLock(path, "admission.lock", async () => {}, { kernelBacked: true }))
      .rejects.toThrow("second directory probe refused");
    expect(vi.mocked(fs.statfs).mock.calls.filter(([value]) => value === path)).toHaveLength(2);
  } finally { await handle.close(); }
});

it.skipIf(process.platform !== "linux")("retries a rejected filesystem probe on the next kernel acquisition", async () => {
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  let probes = 0;
  vi.mocked(fs.statfs).mockImplementation(async (path, options) => {
    if (path === directory && ++probes === 1) throw new Error("transient statfs failure");
    return actual.statfs(path, options as never) as never;
  });
  const acquire = () => locks.withPathLock(directory, "admission.lock", async () => "acquired", { kernelBacked: true });
  await expect(acquire()).rejects.toThrow("transient statfs failure");
  await expect(acquire()).resolves.toBe("acquired");
  expect(probes).toBe(2);
});
