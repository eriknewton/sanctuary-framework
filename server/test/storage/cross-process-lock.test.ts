/**
 * Unit tests for the cross-process advisory lock used to serialize a
 * read-modify-write across processes (the federation sync-state lost-update
 * close). Verifies: serialized critical sections on a filesystem backend, a
 * fail-CLOSED throw when a live holder keeps the lock past the bounded timeout,
 * stale-lock behavior, and explicit in-process serialization on a
 * non-filesystem backend.
 *
 * Deterministic temp-dir filesystem only; no sockets, no keychain.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, linkSync, mkdirSync, renameSync } from "node:fs";
import {
  chmod,
  mkdtemp,
  lstat,
  readdir,
  readFile,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { isMainThread } from "node:worker_threads";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  acquireMasterWriteBarrier,
  withCrossProcessLock,
  withPathLock,
  withRequiredCrossProcessLock,
  CrossProcessLockError,
  resetKernelLockPoisonForTests,
  __testSweepUnusedBarrierScaffolds,
} from "../../src/storage/cross-process-lock.js";

const NS = "_lock_test";
const LOCK = ".unit.lock";
// 8 old pairs: enough that a missing sweep leaves far more than the bound, few enough that one
// capped sweep pass clears them on a slow runner (measured ~37 ms per helper at load 10).
const DISTINCT_BARRIER_FORTRESS_COUNT = 8;
const OVER_CEILING_IGNORED_ENTRY_COUNT = 3_500;
const OVER_CEILING_SCAFFOLD_PAIR_COUNT = 300;
const OVER_CEILING_CUSTODY_REAPER_COUNT = 4;
// 128 = MAX_BARRIER_READER_SOCKETS (4,096) / 32 in src/storage/cross-process-lock.ts.
const UNUSED_BARRIER_SCAFFOLD_SWEEP_LIMIT = 128;
// 4,352 = MAX_BARRIER_READER_SOCKETS (4,096) plus two scaffold names for each
// unused-scaffold sweep helper cap (128 * 2) in src/storage/cross-process-lock.ts.
const UNUSED_BARRIER_SCAFFOLD_READDIR_ENTRY_CAP =
  4_096 + UNUSED_BARRIER_SCAFFOLD_SWEEP_LIMIT * 2;
// 2 = one `.reaper` plus one `.reader-reaper` pair for the most recent identity.
const MAX_SCAFFOLDS_AFTER_SWEEP = 2;
// 1_000 ms = one second, short enough for unit tests and long enough for a local socket bind.
const SHORT_KERNEL_TEST_TIMEOUT_MS = 1_000;
// 2_100 ms is just past the production 2_000 ms stale-reaper deadline.
const SCAFFOLD_STALE_SETTLE_MS = 2_100;
const SHORT_SOCKET_TMP_PARENT =
  process.platform === "darwin" ? "/private/tmp" : tmpdir();
// Cross-file contract: must match BARRIER_SCAFFOLD_DIGEST_HEX_CHARS in
// src/storage/cross-process-lock.ts, the filename width this test plants.
const BARRIER_SCAFFOLD_DIGEST_HEX_CHARS = 40;
const SECURE_SCAFFOLD_MODE = 0o600;
const CROSS_PROCESS_LOCK_MODULE_URL = new URL(
  "../../src/storage/cross-process-lock.ts",
  import.meta.url,
).href;
// 10_000 ms = 5 stale-reaper helper deadlines; enough for a child probe to
// finish or be killed without overlapping the next test.
const CHILD_PROBE_TIMEOUT_MS = 5 * 2_000;
// 4_500 ms = 2 helper deadlines plus 500 ms scheduling slack. A pass that
// spawns more than one hung helper exceeds the bound and fails the test.
const SLOW_SWEEP_PASS_TEST_BOUND_MS = 2 * 2_000 + 500;
const SLOW_SWEEP_PAIR_COUNT = 3;
const SLOW_SWEEP_DIGEST_SEED = 30;
const SLOW_SWEEP_ACTIVE_DIGEST_SEED = 100;
const ACTIVE_SWEEP_DIGEST_SEED = 40;

function scaffoldDigest(seed: number): string {
  return seed.toString(16).padStart(BARRIER_SCAFFOLD_DIGEST_HEX_CHARS, "0");
}

async function countReaperScaffolds(root: string): Promise<number> {
  return (await readdir(root)).filter(
    (name) => name.endsWith(".reaper") || name.endsWith(".reader-reaper"),
  ).length;
}

async function writeSecureScaffold(path: string): Promise<void> {
  await writeFile(path, "");
  await chmod(path, SECURE_SCAFFOLD_MODE);
}

async function scaffoldModes(root: string): Promise<Map<string, number>> {
  const modes = new Map<string, number>();
  for (const name of await readdir(root)) {
    if (!name.endsWith(".reaper") && !name.endsWith(".reader-reaper")) continue;
    const stats = await lstat(join(root, name));
    modes.set(name, stats.mode & 0o777);
  }
  return modes;
}

async function runChildProbe(
  script: string,
  env: Record<string, string>,
): Promise<{ stdout: string; stderr: string }> {
  const child = spawn(process.execPath, ["--import", "tsx", "-e", script], {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  return await new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`child probe exceeded ${CHILD_PROBE_TIMEOUT_MS}ms: ${stderr}`));
    }, CHILD_PROBE_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => { stdout += String(chunk); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      reject(new Error(`child probe failed (${signal ?? code}): ${stderr}`));
    });
  });
}

function reaperLockCommand(host: NodeJS.Platform): string {
  if (host === "darwin") return "/usr/bin/lockf";
  if (host === "linux") return "/usr/bin/flock";
  throw new Error(`unsupported reaper-lock host ${host}`);
}

async function spawnScaffoldLockHolder(
  scaffoldPath: string,
  host: NodeJS.Platform,
): Promise<ChildProcess> {
  const script = "process.stdout.write('locked\\n'); process.stdin.resume();";
  const args =
    host === "darwin"
      ? ["-k", "-t", "0", scaffoldPath, process.execPath, "-e", script]
      : ["-n", scaffoldPath, process.execPath, "-e", script];
  const child = spawn(reaperLockCommand(host), args, {
    stdio: ["pipe", "pipe", "pipe"],
  });
  await new Promise<void>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.once("error", reject);
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
      if (stdout.includes("locked")) resolve();
    });
    child.once("exit", (code, signal) => {
      reject(new Error(`scaffold lock holder exited early (${signal ?? code}): ${stderr}`));
    });
  });
  return child;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

describe("withCrossProcessLock", () => {
  let base: string;
  let storage: FilesystemStorage;

  // Lock ops a test starts but whose settlement is timing-dependent (a live
  // holder that blocks until released, a contender that rejects on timeout) are
  // registered here so teardown can settle them BEFORE the temp dir is removed.
  // Otherwise a still-pending holder/contender can outlive its test: when a
  // later assertion throws before the test's own cleanup runs, the orphaned
  // op releases (or times out) against a deleted dir and surfaces as an
  // unhandled `CrossProcessLockError` in a *different* test's error channel
  // (the "leaks its contender promise past teardown" flake).
  let pending: Promise<unknown>[] = [];
  let releasers: Array<() => void> = [];

  // Real OS processes (kernel-lock holder/contender fixtures) spawned by a
  // test. A test that spawns one kills it on its own happy path, but a
  // failing assertion or timeout thrown before that kill leaves the child
  // running: it keeps a socket pinned in the shared
  // `/tmp/sanctuary-custody-locks-<uid>` dir and poisons later tests/runs.
  // Tracked here so afterEach can SIGKILL anything still alive regardless of
  // how the test exited.
  let spawnedChildren: ChildProcess[] = [];

  /** Register a blocking holder's release fn + its promise for teardown. */
  function track<T>(promise: Promise<T>, release?: () => void): Promise<T> {
    pending.push(promise);
    if (release) releasers.push(release);
    return promise;
  }

  /** Register a spawned child process for forced teardown. */
  function trackChild<T extends ChildProcess>(child: T): T {
    spawnedChildren.push(child);
    return child;
  }

  beforeEach(async () => {
    resetKernelLockPoisonForTests();
    base = await mkdtemp(join(tmpdir(), "xproc-lock-"));
    storage = new FilesystemStorage(join(base, "state"));
    pending = [];
    releasers = [];
    spawnedChildren = [];
  });

  afterEach(async () => {
    // Release any still-held lock so its holder proceeds to its `finally`
    // unlink, then swallow every tracked promise's outcome so a leaked
    // rejection can never surface after the test. Only then remove the dir.
    for (const release of releasers) release();
    await Promise.allSettled(pending);
    // Reap every spawned child that is still alive (killed==false and no
    // exit/signal recorded yet) before the temp dir goes away, so a failed
    // assertion earlier in the test can never strand a live process.
    for (const child of spawnedChildren) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
    }
    await Promise.all(spawnedChildren.map((child) =>
      child.exitCode !== null || child.signalCode !== null
        ? Promise.resolve()
        : new Promise<void>((resolve) => child.once("close", () => resolve()))));
    await rm(base, { recursive: true, force: true });
  });

  it("serializes overlapping critical sections on a filesystem backend", async () => {
    const trace: string[] = [];
    const section = (id: string) => async () => {
      trace.push(`enter:${id}`);
      await sleep(30);
      trace.push(`exit:${id}`);
    };

    await Promise.all([
      withCrossProcessLock(storage, NS, LOCK, section("A")),
      withCrossProcessLock(storage, NS, LOCK, section("B")),
    ]);

    // Whichever ran first must fully exit before the other entered: no interleave.
    expect(trace.length).toBe(4);
    expect(trace[0]!.startsWith("enter:")).toBe(true);
    expect(trace[1]).toBe(`exit:${trace[0]!.slice("enter:".length)}`);
  });

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "bounds unused master-barrier scaffolds across distinct fortresses",
    async () => {
      const previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      // macOS `sun_path` is 104 bytes including the terminator; the resolver's
      // reviewed 100-byte cap leaves room only when the test root is short.
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = runtimeRoot;
      try {
        for (let index = 0; index < DISTINCT_BARRIER_FORTRESS_COUNT; index += 1) {
          const fortress = await mkdtemp(join(base, `barrier-fortress-${index}-`));
          const lease = await acquireMasterWriteBarrier(
            new FilesystemStorage(join(fortress, "state")),
            "_meta",
            `scaffold-sweep-test-${index}`,
            { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
          );
          await lease.release();
        }
        await sleep(SCAFFOLD_STALE_SETTLE_MS);
        const freshDigest = "f".repeat(BARRIER_SCAFFOLD_DIGEST_HEX_CHARS);
        const freshScaffolds = [
          `${freshDigest}.reaper`,
          `${freshDigest}.reader-reaper`,
        ];
        for (const scaffold of freshScaffolds) {
          await writeSecureScaffold(join(runtimeRoot, scaffold));
        }
        const triggerFortress = await mkdtemp(join(base, "barrier-trigger-"));
        const triggerLease = await acquireMasterWriteBarrier(
          new FilesystemStorage(join(triggerFortress, "state")),
          "_meta",
          "scaffold-sweep-trigger-test",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        await triggerLease.release();
        const scaffolds = (await readdir(runtimeRoot)).filter(
          (name) => name.endsWith(".reaper") || name.endsWith(".reader-reaper"),
        );
        for (const scaffold of freshScaffolds) {
          expect(scaffolds).toContain(scaffold);
        }
        expect(scaffolds.length).toBeLessThanOrEqual(
          MAX_SCAFFOLDS_AFTER_SWEEP + freshScaffolds.length,
        );
      } finally {
        if (previousRoot === undefined) {
          delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
        } else {
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
        }
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "keeps an exclusive scaffold while its own reaper authority is held",
    async () => {
      const previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      const host = process.platform as "darwin" | "linux";
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = runtimeRoot;
      let holder: ChildProcess | undefined;
      try {
        const digest = "e".repeat(BARRIER_SCAFFOLD_DIGEST_HEX_CHARS);
        const exclusiveScaffold = join(runtimeRoot, `${digest}.reaper`);
        const readerScaffold = join(runtimeRoot, `${digest}.reader-reaper`);
        await writeSecureScaffold(exclusiveScaffold);
        await writeSecureScaffold(readerScaffold);
        await sleep(SCAFFOLD_STALE_SETTLE_MS);
        holder = trackChild(await spawnScaffoldLockHolder(exclusiveScaffold, host));

        const triggerFortress = await mkdtemp(join(base, "barrier-trigger-"));
        const triggerLease = await acquireMasterWriteBarrier(
          new FilesystemStorage(join(triggerFortress, "state")),
          "_meta",
          "scaffold-sweep-test",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        await triggerLease.release();

        const names = await readdir(runtimeRoot);
        expect(names).toContain(`${digest}.reaper`);
        expect(names).toContain(`${digest}.reader-reaper`);
      } finally {
        holder?.stdin?.end();
        holder?.kill("SIGTERM");
        if (previousRoot === undefined) {
          delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
        } else {
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
        }
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "settles overlapping shared master-barrier releases once",
    async () => {
      const previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = runtimeRoot;
      try {
        const fortress = await mkdtemp(join(base, "barrier-overlap-"));
        const lease = await acquireMasterWriteBarrier(
          new FilesystemStorage(join(fortress, "state")),
          "_meta",
          "overlap-release-test",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        await expect(Promise.all([lease.release(), lease.release()])).resolves.toEqual([
          undefined,
          undefined,
        ]);
        expect(lease.signal.aborted).toBe(true);
        await expect(lease.release()).resolves.toBeUndefined();
      } finally {
        if (previousRoot === undefined) {
          delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
        } else {
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
        }
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "keeps live and active identity scaffolds across the amortized sweep",
    async () => {
      const previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = runtimeRoot;
      try {
        const liveFortress = await mkdtemp(join(base, "barrier-live-"));
        const liveStorage = new FilesystemStorage(join(liveFortress, "state"));
        const liveLease = await acquireMasterWriteBarrier(
          liveStorage,
          "_meta",
          "scaffold-live-held-test",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        const liveBefore = (await readdir(runtimeRoot)).filter(
          (name) => name.endsWith(".reaper") || name.endsWith(".reader-reaper"),
        );
        await sleep(SCAFFOLD_STALE_SETTLE_MS);

        for (let index = 0; index < DISTINCT_BARRIER_FORTRESS_COUNT; index += 1) {
          const fortress = await mkdtemp(join(base, `barrier-other-${index}-`));
          const lease = await acquireMasterWriteBarrier(
            new FilesystemStorage(join(fortress, "state")),
            "_meta",
            "scaffold-sweep-test",
            { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
          );
          await lease.release();
        }
        const nonActiveTrigger = await mkdtemp(join(base, "barrier-non-active-"));
        const reacquired = await acquireMasterWriteBarrier(
          new FilesystemStorage(join(nonActiveTrigger, "state")),
          "_meta",
          "scaffold-sweep-trigger-test",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        await reacquired.release();

        const after = await readdir(runtimeRoot);
        for (const scaffold of liveBefore) {
          expect(after).toContain(scaffold);
        }
        await liveLease.release();
      } finally {
        if (previousRoot === undefined) {
          delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
        } else {
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
        }
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "sweeps a bounded batch from an over-ceiling runtime directory",
    async () => {
      const previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = runtimeRoot;
      try {
        for (let index = 0; index < OVER_CEILING_IGNORED_ENTRY_COUNT; index += 1) {
          await writeFile(join(runtimeRoot, `ignored-${index}`), "");
        }
        for (let index = 0; index < OVER_CEILING_SCAFFOLD_PAIR_COUNT; index += 1) {
          const digest = scaffoldDigest(index);
          await writeSecureScaffold(join(runtimeRoot, `${digest}.reaper`));
          await writeSecureScaffold(join(runtimeRoot, `${digest}.reader-reaper`));
        }
        for (let index = 0; index < OVER_CEILING_CUSTODY_REAPER_COUNT; index += 1) {
          const digest = scaffoldDigest(OVER_CEILING_SCAFFOLD_PAIR_COUNT + index);
          await writeSecureScaffold(join(runtimeRoot, `${digest}.reaper`));
        }
        await sleep(SCAFFOLD_STALE_SETTLE_MS);

        const before = await countReaperScaffolds(runtimeRoot);
        const firstTriggerFortress = await mkdtemp(join(base, "barrier-over-ceiling-a-"));
        const firstTriggerLease = await acquireMasterWriteBarrier(
          new FilesystemStorage(join(firstTriggerFortress, "state")),
          "_meta",
          "scaffold-sweep-trigger-a",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        await firstTriggerLease.release();
        const afterFirst = await countReaperScaffolds(runtimeRoot);
        expect(afterFirst).toBeLessThan(before);
        expect(before - afterFirst).toBeLessThanOrEqual(
          UNUSED_BARRIER_SCAFFOLD_SWEEP_LIMIT * 2,
        );

        const secondTriggerFortress = await mkdtemp(join(base, "barrier-over-ceiling-b-"));
        const secondTriggerLease = await acquireMasterWriteBarrier(
          new FilesystemStorage(join(secondTriggerFortress, "state")),
          "_meta",
          "scaffold-sweep-trigger-b",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        await secondTriggerLease.release();
        const afterSecond = await countReaperScaffolds(runtimeRoot);
        expect(afterSecond).toBeLessThan(afterFirst);
        expect(afterFirst - afterSecond).toBeLessThanOrEqual(
          UNUSED_BARRIER_SCAFFOLD_SWEEP_LIMIT * 2,
        );
      } finally {
        if (previousRoot === undefined) {
          delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
        } else {
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
        }
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "sweeps complete scaffold pairs while leaving custody-only scaffolds inert",
    async () => {
      const previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = runtimeRoot;
      try {
        const custodyDigest = scaffoldDigest(1);
        const pairDigest = scaffoldDigest(2);
        await writeSecureScaffold(join(runtimeRoot, `${custodyDigest}.reaper`));
        await writeSecureScaffold(join(runtimeRoot, `${pairDigest}.reaper`));
        await writeSecureScaffold(join(runtimeRoot, `${pairDigest}.reader-reaper`));
        await sleep(SCAFFOLD_STALE_SETTLE_MS);

        const triggerFortress = await mkdtemp(join(base, "barrier-complete-pair-"));
        const triggerLease = await acquireMasterWriteBarrier(
          new FilesystemStorage(join(triggerFortress, "state")),
          "_meta",
          "scaffold-complete-pair-trigger",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        await triggerLease.release();

        const names = await readdir(runtimeRoot);
        expect(names).toContain(`${custodyDigest}.reaper`);
        expect(names).not.toContain(`${custodyDigest}.reader-reaper`);
        expect(names).not.toContain(`${pairDigest}.reaper`);
        expect(names).not.toContain(`${pairDigest}.reader-reaper`);
      } finally {
        if (previousRoot === undefined) {
          delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
        } else {
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
        }
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  // process.umask() cannot be set inside a worker thread (the Stryker thread pool); the
  // child-process umask tests below are the load-bearing witnesses, this one is main-thread coverage.
  it.runIf((process.platform === "darwin" || process.platform === "linux") && isMainThread)(
    "keeps scaffold modes secure under a restrictive process umask",
    async () => {
      const previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      const previousUmask = process.umask(0o027);
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = runtimeRoot;
      try {
        const custodyDigest = scaffoldDigest(10);
        const pairDigest = scaffoldDigest(11);
        await writeSecureScaffold(join(runtimeRoot, `${custodyDigest}.reaper`));
        await writeSecureScaffold(join(runtimeRoot, `${pairDigest}.reaper`));
        await writeSecureScaffold(join(runtimeRoot, `${pairDigest}.reader-reaper`));
        await sleep(SCAFFOLD_STALE_SETTLE_MS);

        const firstFortress = await mkdtemp(join(base, "barrier-umask-a-"));
        const secondFortress = await mkdtemp(join(base, "barrier-umask-b-"));
        const [firstLease, secondLease] = await Promise.all([
          acquireMasterWriteBarrier(
            new FilesystemStorage(join(firstFortress, "state")),
            "_meta",
            "scaffold-umask-a",
            { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
          ),
          acquireMasterWriteBarrier(
            new FilesystemStorage(join(secondFortress, "state")),
            "_meta",
            "scaffold-umask-b",
            { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
          ),
        ]);
        await firstLease.release();
        await secondLease.release();

        for (const mode of (await scaffoldModes(runtimeRoot)).values()) {
          expect(mode).toBe(SECURE_SCAFFOLD_MODE);
        }

        const laterFortress = await mkdtemp(join(base, "barrier-umask-later-"));
        const laterLease = await acquireMasterWriteBarrier(
          new FilesystemStorage(join(laterFortress, "state")),
          "_meta",
          "scaffold-umask-later",
          { timeoutMs: SHORT_KERNEL_TEST_TIMEOUT_MS },
        );
        await expect(laterLease.release()).resolves.toBeUndefined();
      } finally {
        process.umask(previousUmask);
        if (previousRoot === undefined) {
          delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
        } else {
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
        }
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "creates rechecked sweep scaffolds at secure mode under a restrictive umask",
    async () => {
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      try {
        const digest = scaffoldDigest(12);
        await writeSecureScaffold(join(runtimeRoot, `${digest}.reaper`));
        await writeSecureScaffold(join(runtimeRoot, `${digest}.reader-reaper`));
        await sleep(SCAFFOLD_STALE_SETTLE_MS);
        await runChildProbe(`
          const { lstat } = await import("node:fs/promises");
          const { join } = await import("node:path");
          const mod = await import(process.env.MODULE_URL);
          process.umask(0o027);
          const root = process.env.RUNTIME_ROOT;
          const digest = process.env.DIGEST;
          await mod.__testSweepOneUnusedBarrierScaffoldAfterRemovingPair(
            root,
            digest,
            process.platform,
          );
          for (const suffix of [".reaper", ".reader-reaper"]) {
            const mode = (await lstat(join(root, digest + suffix))).mode & 0o777;
            if (mode !== 0o600) {
              console.error(String(mode.toString(8)));
              process.exit(1);
            }
          }
        `, {
          MODULE_URL: CROSS_PROCESS_LOCK_MODULE_URL,
          RUNTIME_ROOT: runtimeRoot,
          DIGEST: digest,
        });
      } finally {
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "creates stale-socket reaper scaffolds at secure mode under a restrictive umask",
    async () => {
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      try {
        await runChildProbe(`
          const { linkSync } = await import("node:fs");
          const { chmod, lstat } = await import("node:fs/promises");
          const { createServer } = await import("node:net");
          const { join } = await import("node:path");
          const mod = await import(process.env.MODULE_URL);
          process.umask(0o027);
          const root = process.env.RUNTIME_ROOT;
          const source = join(root, "stale-source.sock");
          const socketPath = join(root, "stale.sock");
          const scaffoldPath = join(root, "stale.reaper");
          const stale = createServer((socket) => socket.destroy());
          await new Promise((resolve, reject) => {
            stale.once("error", reject);
            // port-discipline: ignore - source is a private Unix-domain socket path, not a TCP port
            stale.listen(source, resolve);
          });
          linkSync(source, socketPath);
          await new Promise((resolve) => stale.close(() => resolve()));
          await chmod(socketPath, 0o600);
          const socketStats = await lstat(socketPath, { bigint: true });
          await mod.__testReapStaleSocketWithSerializedAuthority(
            socketPath,
            { dev: String(socketStats.dev), ino: String(socketStats.ino) },
            scaffoldPath,
            process.platform,
          );
          const mode = (await lstat(scaffoldPath)).mode & 0o777;
          if (mode !== 0o600) {
            console.error(String(mode.toString(8)));
            process.exit(1);
          }
        `, {
          MODULE_URL: CROSS_PROCESS_LOCK_MODULE_URL,
          RUNTIME_ROOT: runtimeRoot,
        });
      } finally {
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "stops spawning unused-scaffold helpers after the pass cap",
    async () => {
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      try {
        const helperLog = join(base, "slow-sweep-helper.log");
        for (let index = 0; index < SLOW_SWEEP_PAIR_COUNT; index += 1) {
          const digest = scaffoldDigest(SLOW_SWEEP_DIGEST_SEED + index);
          await writeSecureScaffold(join(runtimeRoot, `${digest}.reaper`));
          await writeSecureScaffold(join(runtimeRoot, `${digest}.reader-reaper`));
        }
        await sleep(SCAFFOLD_STALE_SETTLE_MS);
        const slowHelperScript = `
          const fs = require("node:fs");
          const [runtimeDir, digest] = process.argv.slice(1);
          void runtimeDir;
          fs.appendFileSync(${JSON.stringify(helperLog)}, digest + "\\n");
          setInterval(() => undefined, 1_000);
        `;
        const started = Date.now();
        await __testSweepUnusedBarrierScaffolds(
          runtimeRoot,
          scaffoldDigest(SLOW_SWEEP_ACTIVE_DIGEST_SEED),
          process.platform,
          { helperScript: slowHelperScript },
        );
        expect(Date.now() - started).toBeLessThan(SLOW_SWEEP_PASS_TEST_BOUND_MS);
        const log = await readFile(helperLog, "utf8");
        expect(log.trim().split("\n")).toHaveLength(1);
        await __testSweepUnusedBarrierScaffolds(
          runtimeRoot,
          scaffoldDigest(SLOW_SWEEP_ACTIVE_DIGEST_SEED),
          process.platform,
          { helperScript: slowHelperScript },
        );
        const afterThrottledPass = await readFile(helperLog, "utf8");
        expect(afterThrottledPass.trim().split("\n")).toHaveLength(1);
      } finally {
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "keeps the active scaffold digest out of the unused-pair sweep",
    async () => {
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      try {
        const activeDigest = scaffoldDigest(ACTIVE_SWEEP_DIGEST_SEED);
        await writeSecureScaffold(join(runtimeRoot, `${activeDigest}.reaper`));
        await writeSecureScaffold(join(runtimeRoot, `${activeDigest}.reader-reaper`));
        await sleep(SCAFFOLD_STALE_SETTLE_MS);

        await __testSweepUnusedBarrierScaffolds(
          runtimeRoot,
          activeDigest,
          process.platform,
        );

        const names = await readdir(runtimeRoot);
        expect(names).toContain(`${activeDigest}.reaper`);
        expect(names).toContain(`${activeDigest}.reader-reaper`);
      } finally {
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "stops the unused-scaffold sweep when the runtime directory exceeds the scan cap",
    async () => {
      const runtimeRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "xplk-"));
      try {
        const helperLog = join(base, "capped-sweep-helper.log");
        for (
          let index = 0;
          index <= UNUSED_BARRIER_SCAFFOLD_READDIR_ENTRY_CAP;
          index += 1
        ) {
          await writeFile(join(runtimeRoot, `ignored-${index}`), "");
        }
        const digest = scaffoldDigest(SLOW_SWEEP_DIGEST_SEED);
        await writeSecureScaffold(join(runtimeRoot, `${digest}.reaper`));
        await writeSecureScaffold(join(runtimeRoot, `${digest}.reader-reaper`));
        await sleep(SCAFFOLD_STALE_SETTLE_MS);
        const helperScript = `
          const fs = require("node:fs");
          fs.appendFileSync(${JSON.stringify(helperLog)}, "started\\n");
        `;

        await __testSweepUnusedBarrierScaffolds(
          runtimeRoot,
          scaffoldDigest(SLOW_SWEEP_ACTIVE_DIGEST_SEED),
          process.platform,
          { helperScript },
        );

        await expect(readFile(helperLog, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
        expect(await countReaperScaffolds(runtimeRoot)).toBe(2);
      } finally {
        await rm(runtimeRoot, { recursive: true, force: true });
      }
    },
  );

  it("removes the lockfile after the operation (even when it throws)", async () => {
    await expect(
      withCrossProcessLock(storage, NS, LOCK, async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");

    // A subsequent acquire must succeed (the failed op did not leave a stale lock).
    let ran = false;
    await withCrossProcessLock(storage, NS, LOCK, async () => {
      ran = true;
    });
    expect(ran).toBe(true);
  });

  it("FAILS CLOSED when a live holder keeps the lock past the timeout", async () => {
    // Hold the lock with a long-running op, then try to acquire with a short timeout.
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    // Track the holder + its release so teardown always settles it, even if the
    // assertion below throws before we reach the explicit release/await.
    const holder = track(
      withCrossProcessLock(storage, NS, LOCK, async () => {
        await held;
      }),
      release,
    );
    // Give the holder a beat to take the lock.
    await sleep(20);

    // Track the contender too: its rejection is asserted inline here, but
    // registering it guarantees no unhandled rejection can outlive the test.
    const contention = track(
      withCrossProcessLock(storage, NS, LOCK, async () => undefined, {
        timeoutMs: 80,
        retryMs: 10,
      }),
    );
    await expect(contention).rejects.toBeInstanceOf(CrossProcessLockError);
    await expect(contention).rejects.toThrow(
      "Never remove this lock while a holder may still be alive; some ceremonies hold it for minutes.",
    );

    release();
    await holder;
  });

  it("aborts a contended wait before the operation can write", async () => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const holder = track(
      withCrossProcessLock(storage, NS, LOCK, async () => {
        await held;
      }),
      release,
    );
    await sleep(20);

    const controller = new AbortController();
    let ran = false;
    const contender = track(
      withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => {
          ran = true;
          await storage.write(NS, "must-not-land", new Uint8Array([1]));
        },
        {
          timeoutMs: 500,
          retryMs: 10,
          abortSignal: controller.signal,
        },
      ),
    );
    controller.abort();

    await expect(contender).rejects.toMatchObject({
      kind: "operation_aborted",
      message: expect.stringContaining("wait aborted"),
    });
    expect(ran).toBe(false);
    await expect(storage.read(NS, "must-not-land")).resolves.toBeNull();

    release();
    await holder;
  });

  it("FIX 4: does NOT auto-break a stale lock (no read-then-unlink TOCTOU); fails CLOSED with a manual-rm hint", async () => {
    // Write a lockfile whose holder PID cannot exist (a never-allocated high PID),
    // simulating a crashed process that never released its lock. The OLD code
    // auto-broke this by reading the JSON then `rm`-ing it - a check-then-act
    // TOCTOU where two contenders can both decide "stale" and one deletes the
    // other's freshly-acquired LIVE lock (double-acquire). The fix removes the
    // auto-break: a stale lock is NOT broken; the acquire fails CLOSED with an
    // operator-facing `rm` recovery hint. Fail-safe-wedge > fail-open-double-acquire.
    const { mkdir } = await import("node:fs/promises");
    const dir = storage.namespacePath(NS);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const lockPath = join(dir, LOCK);
    await writeFile(
      lockPath,
      JSON.stringify({ pid: 2_147_483_646, acquired_at: new Date().toISOString() }),
    );

    let ran = false;
    await expect(
      withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => {
          ran = true;
        },
        { timeoutMs: 80, retryMs: 10 },
      ),
    ).rejects.toBeInstanceOf(CrossProcessLockError);
    // The operation NEVER ran (no auto-break, no double-acquire).
    expect(ran).toBe(false);
    // The error hint names the exact lockfile so an operator can clear a dead holder.
    await expect(
      withCrossProcessLock(storage, NS, LOCK, async () => undefined, {
        timeoutMs: 80,
        retryMs: 10,
      }),
    ).rejects.toThrow(new RegExp(`rm '${lockPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}'`));
    // The stale lock is left in place (we did NOT touch another process's inode).
    await expect(readFile(lockPath, "utf8")).resolves.toContain("2147483646");
  });

  it("clears cleanly once the stale lockfile is manually removed", async () => {
    // The documented recovery: an operator `rm`s the crashed holder's lockfile,
    // after which a fresh acquire succeeds normally.
    const { mkdir } = await import("node:fs/promises");
    const dir = storage.namespacePath(NS);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const lockPath = join(dir, LOCK);
    await writeFile(
      lockPath,
      JSON.stringify({ pid: 2_147_483_646, acquired_at: new Date().toISOString() }),
    );
    await rm(lockPath, { force: true }); // the operator's one-time manual clear

    let ran = false;
    await withCrossProcessLock(storage, NS, LOCK, async () => {
      ran = true;
    });
    expect(ran).toBe(true);
  });

  it("runs directly (no lockfile) on a non-filesystem backend", async () => {
    const memory = new MemoryStorage();
    let ran = false;
    await withCrossProcessLock(memory, NS, LOCK, async () => {
      ran = true;
    });
    expect(ran).toBe(true);
  });

  it("required namespace locks refuse a filesystem-only decorator", async () => {
    const memory = new MemoryStorage();
    const decorator = {
      read: (namespace: string, key: string) => memory.read(namespace, key),
      write: (namespace: string, key: string, data: Uint8Array) =>
        memory.write(namespace, key, data),
      delete: (namespace: string, key: string, secureOverwrite?: boolean) =>
        memory.delete(namespace, key, secureOverwrite),
      list: (namespace: string, prefix?: string) => memory.list(namespace, prefix),
      exists: (namespace: string, key: string) => memory.exists(namespace, key),
      totalSize: () => memory.totalSize(),
      namespacePath: (namespace: string) => join(base, namespace),
      writeDurable: (namespace: string, key: string, data: Uint8Array) =>
        memory.write(namespace, key, data),
    };
    let ran = false;
    await expect(withRequiredCrossProcessLock(
      decorator,
      NS,
      LOCK,
      async () => { ran = true; },
    )).rejects.toMatchObject({ kind: "capability" });
    expect(ran).toBe(false);
  });

  it("abort after path-lock acquisition refuses and removes this process lockfile", async () => {
    const dir = join(base, "abort-after-open");
    const lockPath = join(dir, LOCK);
    let abortedReads = 0;
    const signal = {
      get aborted(): boolean {
        abortedReads += 1;
        return abortedReads >= 2;
      },
      addEventListener() {},
      removeEventListener() {},
    } as unknown as AbortSignal;
    let ran = false;
    await expect(withPathLock(
      dir,
      LOCK,
      async () => { ran = true; },
      { abortSignal: signal },
    )).rejects.toMatchObject({ kind: "operation_aborted" });
    expect(ran).toBe(false);
    expect(existsSync(lockPath)).toBe(false);
  });

  it("abort during path-lock retry sleep refuses promptly without running", async () => {
    const dir = join(base, "abort-during-sleep");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const lockPath = join(dir, LOCK);
    await writeFile(lockPath, "held");
    const controller = new AbortController();
    let ran = false;
    const pending = withPathLock(
      dir,
      LOCK,
      async () => { ran = true; },
      { abortSignal: controller.signal, retryMs: 500, timeoutMs: 2_000 },
    ).then(
      () => "resolved" as const,
      (error) => error,
    );
    setTimeout(() => controller.abort(), 10);
    const result = await Promise.race([
      pending,
      new Promise<"TIMEOUT">((resolve) => setTimeout(() => resolve("TIMEOUT"), 100)),
    ]);
    expect(result).not.toBe("TIMEOUT");
    expect(result).toMatchObject({ kind: "operation_aborted" });
    expect(ran).toBe(false);
    await rm(lockPath, { force: true });
  });

  it("fails an unsupported kernel-lock host before creating its target layout", async () => {
    const target = join(base, "must-not-be-created", "_meta");
    await expect(withPathLock(
      target,
      LOCK,
      async () => undefined,
      { kernelBacked: true, __testPlatform: "win32" },
    )).rejects.toMatchObject({ kind: "capability" });
    await expect(lstat(target)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "repairs only the exact legacy 0644 custody scaffold before acquiring",
    async () => {
      const namespacePath = join(base, "state", NS);
      mkdirSync(namespacePath, { recursive: true, mode: 0o700 });
      const scaffold = join(namespacePath, LOCK);
      await writeFile(scaffold, "", { mode: 0o600 });
      await chmod(scaffold, 0o644);

      await withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async (lease) => lease.assertHeld(),
        { kernelBacked: true },
      );

      expect((await lstat(scaffold)).mode & 0o777).toBe(0o600);
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "refuses a non-legacy broad custody scaffold without changing it",
    async () => {
      const namespacePath = join(base, "state", NS);
      mkdirSync(namespacePath, { recursive: true, mode: 0o700 });
      const scaffold = join(namespacePath, LOCK);
      await writeFile(scaffold, "", { mode: 0o600 });
      await chmod(scaffold, 0o660);

      await expect(withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => undefined,
        { kernelBacked: true },
      )).rejects.toThrow(/only an exact legacy 0644 scaffold/i);
      expect((await lstat(scaffold)).mode & 0o777).toBe(0o660);
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "fences the live holder synchronously when its socket path is unlinked",
    async () => {
      let socketPath = "";
      const error = await withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async (lease) => {
          expect(socketPath).not.toBe("");
          await unlink(socketPath);
          expect(() => lease.assertHeld()).toThrowError(
            expect.objectContaining({ kind: "holder-lost" }),
          );
          throw new Error("operation-error-must-win");
        },
        {
          kernelBacked: true,
          __testAfterKernelSocketAcquired: (path) => { socketPath = path; },
        },
      ).catch((cause) => cause as unknown);
      expect(error).toBeInstanceOf(AggregateError);
      expect((error as AggregateError).errors.map(String)).toEqual([
        "Error: operation-error-must-win",
        expect.stringContaining("socket changed before release"),
      ]);
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "keeps ownership when the deliberately non-owning helper is killed",
    async () => {
      let holderPid = 0;
      const operation = withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async (lease) => {
          expect(holderPid).toBeGreaterThan(0);
          process.kill(holderPid, "SIGKILL");
          await sleep(30);
          lease.assertHeld();
          await expect(
            withCrossProcessLock(storage, NS, LOCK, async () => undefined, {
              kernelBacked: true,
              timeoutMs: 60,
              retryMs: 10,
            }),
          ).rejects.toMatchObject({ kind: "contention" });
        },
        {
          kernelBacked: true,
          __testAfterKernelHolderAcquired: (pid) => { holderPid = pid; },
        },
      );
      await expect(operation).resolves.toBeUndefined();
      await expect(
        withCrossProcessLock(storage, NS, LOCK, async (lease) => {
          lease.assertHeld();
        }, { kernelBacked: true }),
      ).resolves.toBeUndefined();
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "re-observes a transient unknown owner probe before preserving mutual exclusion",
    async () => {
      let release!: () => void;
      const held = new Promise<void>((resolve) => { release = resolve; });
      const trace: string[] = [];
      let holderAcquired!: () => void;
      const acquired = new Promise<void>((resolve) => { holderAcquired = resolve; });
      const holder = track(withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => {
          trace.push("holder:start");
          await held;
          trace.push("holder:end");
        },
        {
          kernelBacked: true,
          __testAfterKernelSocketAcquired: () => { holderAcquired(); },
        },
      ), release);
      await Promise.race([
        acquired,
        holder.then(() => { throw new Error("holder released before acquisition was observed"); }),
      ]);

      let forcedUnknowns = 0;
      let observeRealContention!: () => void;
      const realContention = new Promise<void>((resolve) => {
        observeRealContention = resolve;
      });
      const contender = track(withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => { trace.push("contender:start"); },
        {
          kernelBacked: true,
          timeoutMs: 500,
          retryMs: 5,
          __testForceKernelProbeUnknown: () => {
            forcedUnknowns += 1;
            return forcedUnknowns === 1;
          },
          onContended: (attempt) => {
            if (attempt === 2) observeRealContention();
          },
        },
      ));

      await realContention;
      expect(forcedUnknowns).toBeGreaterThanOrEqual(2);
      expect(trace).toEqual(["holder:start"]);
      release();
      await expect(Promise.all([holder, contender])).resolves.toEqual([undefined, undefined]);
      expect(trace).toEqual(["holder:start", "holder:end", "contender:start"]);
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "bounds persistent unknown owner probes without entering or reaping",
    async () => {
      let release!: () => void;
      const held = new Promise<void>((resolve) => { release = resolve; });
      let socketPath = "";
      let holderAcquired!: () => void;
      const acquired = new Promise<void>((resolve) => { holderAcquired = resolve; });
      const holder = track(withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => { await held; },
        {
          kernelBacked: true,
          __testAfterKernelSocketAcquired: (path) => {
            socketPath = path;
            holderAcquired();
          },
        },
      ), release);
      await Promise.race([
        acquired,
        holder.then(() => { throw new Error("holder released before acquisition was observed"); }),
      ]);
      const before = await lstat(socketPath);

      let operationRan = false;
      let reaperRan = false;
      let forcedUnknowns = 0;
      const contender = withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => { operationRan = true; },
        {
          kernelBacked: true,
          timeoutMs: 40,
          retryMs: 5,
          __testForceKernelProbeUnknown: () => {
            forcedUnknowns += 1;
            return true;
          },
          __testAfterStaleReaperStarted: () => { reaperRan = true; },
        },
      );
      await expect(contender).rejects.toMatchObject({
        kind: "io",
        message: expect.stringContaining("owner liveness is indeterminate"),
      });
      expect(forcedUnknowns).toBeGreaterThan(1);
      expect(operationRan).toBe(false);
      expect(reaperRan).toBe(false);
      const after = await lstat(socketPath);
      expect({ dev: after.dev, ino: after.ino }).toEqual({ dev: before.dev, ino: before.ino });

      release();
      await holder;
    },
  );

  it.runIf(process.platform === "darwin")(
    "fails closed without writing when the inode-bound directory worker dies",
    async () => {
      let capabilityPid = 0;
      const operation = withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async (lease) => {
          expect(capabilityPid).toBeGreaterThan(0);
          process.kill(capabilityPid, "SIGKILL");
          await new Promise((resolve) => setTimeout(resolve, 50));
          lease.assertHeld();
          await storage.write(NS, "must-not-land", new Uint8Array([1, 2, 3]));
        },
        {
          kernelBacked: true,
          __testAfterDirectoryCapabilityAcquired: (_storageRootPid, _fortressRootPid, namespacePid) => {
            capabilityPid = namespacePid!;
          },
        },
      );
      await expect(operation).rejects.toMatchObject({ kind: "holder-lost" });
      await expect(storage.read(NS, "must-not-land")).resolves.toBeNull();
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "pins the locked namespace inode when that child directory is replaced",
    async () => {
      const namespacePath = join(base, "state", NS);
      const displaced = join(base, "state", `${NS}.displaced`);
      const operation = withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async (lease) => {
          // Swap only after the callback's mandatory entry fence has passed.
          // The subsequent write must use the namespace capability captured
          // before this lexical replacement, then the explicit fence detects it.
          renameSync(namespacePath, displaced);
          mkdirSync(namespacePath, { recursive: true });
          await storage.write(NS, "bound-namespace-write", new Uint8Array([4, 2]));
          lease.assertHeld();
        },
        {
          kernelBacked: true,
        },
      );
      await expect(operation).rejects.toMatchObject({ kind: "holder-lost" });
      await expect(
        new FilesystemStorage(join(base, "state")).read(NS, "bound-namespace-write"),
      ).resolves.toBeNull();
      await expect(readFile(join(displaced, "bound-namespace-write.enc")))
        .resolves.toEqual(Buffer.from([4, 2]));
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "preserves the operation error and every namespace capability cleanup error in order",
    async () => {
      const error = await withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => {
          throw new Error("operation failed");
        },
        {
          kernelBacked: true,
          __testCloseNamespaceCapability: async (kind, close) => {
            await close();
            if (kind === "root-fd" || kind === "namespace-fd") {
              throw new Error(`${kind} close failed`);
            }
          },
        },
      ).catch((cause) => cause as unknown);

      expect(error).toBeInstanceOf(AggregateError);
      expect((error as AggregateError).errors.map(String)).toEqual([
        "Error: operation failed",
        "Error: root-fd close failed",
        "Error: namespace-fd close failed",
      ]);
      expect((error as AggregateError).cause).toEqual(new Error("operation failed"));
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "surfaces a lone descriptor cleanup error after a successful namespace operation",
    async () => {
      const error = await withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => "completed",
        {
          kernelBacked: true,
          __testCloseNamespaceCapability: async (kind, close) => {
            await close();
            if (kind === "parent-fd") throw new Error("parent-fd close failed");
          },
        },
      ).catch((cause) => cause as unknown);

      expect(error).toEqual(new Error("parent-fd close failed"));
    },
  );

  it.runIf(process.platform === "darwin")(
    "keeps a storage mutation on the acquired inode when the lexical root is replaced",
    async () => {
      const statePath = join(base, "state");
      const displaced = join(base, "state.displaced");
      let swapped = false;
      const operation = withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async (lease) => {
          // The capability is fully established and the entry fence has passed;
          // replace the lexical root immediately before the protected mutation.
          renameSync(statePath, displaced);
          mkdirSync(statePath, { recursive: true });
          swapped = true;
          await storage.write(NS, "bound-write", new Uint8Array([7, 8, 9]));
          lease.assertHeld();
        },
        {
          kernelBacked: true,
        },
      );
      await expect(operation).rejects.toMatchObject({ kind: "holder-lost" });
      expect(swapped).toBe(true);
      await expect(
        new FilesystemStorage(statePath).read(NS, "bound-write"),
      ).resolves.toBeNull();
      await expect(
        new FilesystemStorage(displaced).read(NS, "bound-write"),
      ).resolves.toEqual(new Uint8Array([7, 8, 9]));
    },
  );

  it.runIf(process.platform === "darwin")(
    "keeps non-locked namespace mutations on the acquired root inode and refuses the root namespace string",
    async () => {
      // NAMESPACE-DOT-PATH-ESCAPE-01
      const statePath = join(base, "state");
      const displaced = join(base, "state.displaced");
      const otherNamespace = "other";
      const operation = withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async (lease) => {
          await expect(
            storage.write(".", "root-string-write", new Uint8Array([3])),
          ).rejects.toThrow(/namespace/);

          await storage.write(otherNamespace, "before-swap", new Uint8Array([1]));
          renameSync(statePath, displaced);
          mkdirSync(join(statePath, otherNamespace), { recursive: true });
          await storage.write(otherNamespace, "after-swap", new Uint8Array([2]));
          lease.assertHeld();
        },
        {
          kernelBacked: true,
        },
      );

      const outcome = await operation.then(
        () => undefined,
        (error: unknown) => error,
      );
      if (outcome !== undefined) {
        expect(outcome).toMatchObject({ kind: "holder-lost" });
      }
      await expect(
        new FilesystemStorage(statePath).read(otherNamespace, "after-swap"),
      ).resolves.toBeNull();
      await expect(
        new FilesystemStorage(displaced).read(otherNamespace, "after-swap"),
      ).resolves.toEqual(new Uint8Array([2]));
    },
  );

  it.runIf(process.platform === "darwin")(
    "keeps the worker-bound namespace marker unavailable to caller namespaces",
    async () => {
      const statePath = join(base, "state");
      const formerInternalNamespace = "\0sanctuary-bound-namespace\0";
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const stateStore = new StateStore(storage, masterKey);
      const { tools, identityManager } = createCognitiveTools(
        stateStore,
        storage,
        masterKey,
        "passphrase",
        auditLog,
      );
      await identityManager.load();
      const identityTool = tools.find((tool) => tool.name === "identity_create");
      const writeTool = tools.find((tool) => tool.name === "state_write");
      if (!identityTool || !writeTool) throw new Error("test harness missing state tools");
      const identity = JSON.parse(
        (await identityTool.handler({ label: "worker-bound-marker" })).content[0]!.text,
      ) as { identity_id: string };

      await withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async (lease) => {
          await expect(
            storage.write(formerInternalNamespace, "direct", new Uint8Array([3])),
          ).rejects.toThrow(/namespace/);
          await expect(
            writeTool.handler({
              namespace: formerInternalNamespace,
              key: "tool",
              value: "value",
              identity_id: identity.identity_id,
            }),
          ).rejects.toThrow(/namespace/);
          lease.assertHeld();
        },
        {
          kernelBacked: true,
        },
      );

      await expect(new FilesystemStorage(statePath).read(NS, "direct")).resolves.toBeNull();
      await expect(new FilesystemStorage(statePath).read(NS, "tool")).resolves.toBeNull();
      expect(existsSync(join(statePath, "direct.enc"))).toBe(false);
      expect(existsSync(join(statePath, "tool.enc"))).toBe(false);
      await expect(
        new FilesystemStorage(statePath).read(formerInternalNamespace, "direct"),
      ).rejects.toThrow(/namespace/);
    },
  );

  it.runIf(process.platform === "darwin")(
    "bounds a stuck directory worker and leaves the target absent",
    async () => {
      let capabilityPid = 0;
      const operation = withCrossProcessLock(
        storage,
        NS,
        LOCK,
        async () => {
          process.kill(capabilityPid, "SIGSTOP");
          await storage.write(NS, "must-not-timeout-land", new Uint8Array([4, 5, 6]));
        },
        {
          kernelBacked: true,
          __testDirectoryCapabilityTimeoutMs: 40,
          __testAfterDirectoryCapabilityAcquired: (_storageRootPid, _fortressRootPid, namespacePid) => {
            capabilityPid = namespacePid!;
          },
        },
      );
      await expect(operation).rejects.toMatchObject({ kind: "holder-lost" });
      await expect(storage.read(NS, "must-not-timeout-land")).resolves.toBeNull();
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "retries bounded acquisition when one serialized stale reaper helper dies",
    async () => {
      const fixture = fileURLToPath(
        new URL("./kernel-lock-holder-loss-child.ts", import.meta.url),
      );
      const trace = join(base, "reaper-death-trace.txt");
      const holder = trackChild(spawn(
        process.execPath,
        ["--import", "tsx", fixture, base, "holder", "holder", trace],
        { stdio: ["ignore", "pipe", "pipe"] },
      ));
      let socketPath = "";
      await new Promise<void>((resolve, reject) => {
        let stdout = "";
        holder.once("error", reject);
        holder.stdout.on("data", (chunk: Buffer) => {
          stdout += chunk.toString("utf8");
          const match = /^SOCKET:(.+)$/mu.exec(stdout);
          if (match) socketPath = match[1]!;
          if (socketPath && stdout.includes("ACQUIRED\n")) resolve();
        });
      });
      holder.kill("SIGKILL");
      await new Promise<void>((resolve) => holder.once("close", () => resolve()));

      // Normalize host-specific process-exit behavior into one deterministic
      // stale socket: hard-link a live socket, then close the original name.
      // The linked socket inode remains but has no listener.
      await unlink(socketPath).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") throw error;
      });
      const source = `${socketPath}.synthetic-${process.pid}`;
      const stale = createServer((socket) => socket.destroy());
      await new Promise<void>((resolve, reject) => {
        stale.once("error", reject);
        // port-discipline: ignore - source is a private Unix-domain socket path, not a TCP port
        stale.listen(source, resolve);
      });
      linkSync(source, socketPath);
      await new Promise<void>((resolve) => stale.close(() => resolve()));
      await chmod(socketPath, 0o600);
      expect((await lstat(socketPath)).isSocket()).toBe(true);

      let reaperPid = 0;
      let killedOneReaper = false;
      await expect(withCrossProcessLock(
        storage,
        "_fatal_holder_loss",
        ".fatal.lock",
        async () => undefined,
        {
          kernelBacked: true,
          __testAfterStaleReaperStarted: (pid) => {
            reaperPid = pid;
            if (!killedOneReaper) {
              killedOneReaper = true;
              process.kill(pid, "SIGKILL");
            }
          },
        },
      )).resolves.toBeUndefined();
      expect(reaperPid).toBeGreaterThan(0);
      expect(killedOneReaper).toBe(true);
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "serializes two external contenders after the lock-owning mutator is killed",
    async () => {
      const fixture = fileURLToPath(
        new URL("./kernel-lock-holder-loss-child.ts", import.meta.url),
      );
      const trace = join(base, "kernel-trace.txt");
      const spawnFixture = (mode: string, id: string) =>
        trackChild(spawn(process.execPath, ["--import", "tsx", fixture, base, mode, id, trace], {
          stdio: ["ignore", "pipe", "pipe"],
        }));
      const holder = spawnFixture("holder", "holder");
      await new Promise<void>((resolve, reject) => {
        holder.once("error", reject);
        holder.stdout.once("data", (chunk) => {
          expect(chunk.toString("utf8")).toContain("ACQUIRED");
          resolve();
        });
      });
      const contenders = [spawnFixture("contender", "A"), spawnFixture("contender", "B")];
      await Promise.all(contenders.map((child) =>
        new Promise<void>((resolve, reject) => {
          child.once("error", reject);
          child.stdout.once("data", (chunk) => {
            expect(chunk.toString("utf8")).toContain("CONTENDED:");
            resolve();
          });
        }),
      ));
      const holderClosed = new Promise<void>((resolve) =>
        holder.once("close", () => resolve()),
      );
      holder.kill("SIGKILL");
      const results = await Promise.all(contenders.map((child) =>
        new Promise<{ code: number | null; stderr: string }>((resolve, reject) => {
          let stderr = "";
          child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
          child.once("error", reject);
          child.once("close", (code) => resolve({ code, stderr }));
        }),
      ));
      await holderClosed;
      expect(results.map((r) => r.code), results.map((r) => r.stderr).join("\n"))
        .toEqual([0, 0]);
      const lines = (await readFile(trace, "utf8")).trim().split("\n");
      expect(lines).toHaveLength(4);
      expect(lines[0]).toMatch(/^start:[AB]$/);
      expect(lines[1]).toBe(lines[0]!.replace("start:", "end:"));
      expect(lines[2]).toMatch(/^start:[AB]$/);
      expect(lines[3]).toBe(lines[2]!.replace("start:", "end:"));
      expect(lines[0]).not.toBe(lines[2]);
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "preserves a successor socket and both operation/release errors after holder displacement",
    async () => {
      let socketPath = "";
      const successor = createServer((socket) => socket.destroy());
      try {
        const outcome = withCrossProcessLock(
          storage,
          NS,
          LOCK,
          async () => {
            await unlink(socketPath);
            await new Promise<void>((resolve, reject) => {
              successor.once("error", reject);
              successor.listen({ path: socketPath, exclusive: true }, resolve);
            });
            throw new Error("operation-failed-after-displacement");
          },
          {
            kernelBacked: true,
            __testAfterKernelSocketAcquired: (path) => { socketPath = path; },
          },
        );
        const error = await outcome.catch((cause) => cause as unknown);
        expect(error).toBeInstanceOf(AggregateError);
        expect((error as AggregateError).errors).toHaveLength(2);
        expect(String((error as AggregateError).errors[0])).toContain(
          "operation-failed-after-displacement",
        );
        expect(String((error as AggregateError).errors[1])).toContain(
          "socket changed before release",
        );
        expect((await lstat(socketPath)).isSocket()).toBe(true);
        expect(successor.listening).toBe(true);
      } finally {
        if (successor.listening) {
          await new Promise<void>((resolve) => successor.close(() => resolve()));
        }
      }
    },
  );
});
