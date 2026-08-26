/**
 * Unit tests for the cross-process advisory lock used to serialize a
 * read-modify-write across processes (the federation sync-state lost-update
 * close). Verifies: serialized critical sections on a filesystem backend, a
 * fail-CLOSED throw when a live holder keeps the lock past the bounded timeout,
 * stale-lock break when the holder is provably dead/pre-boot, and a direct
 * (no-op-lock) pass-through on a non-filesystem backend.
 *
 * Deterministic temp-dir filesystem only; no sockets, no keychain.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  withCrossProcessLock,
  CrossProcessLockError,
} from "../../src/storage/cross-process-lock.js";

const NS = "_lock_test";
const LOCK = ".unit.lock";

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

  /** Register a blocking holder's release fn + its promise for teardown. */
  function track<T>(promise: Promise<T>, release?: () => void): Promise<T> {
    pending.push(promise);
    if (release) releasers.push(release);
    return promise;
  }

  beforeEach(async () => {
    base = await mkdtemp(join(tmpdir(), "xproc-lock-"));
    storage = new FilesystemStorage(join(base, "state"));
    pending = [];
    releasers = [];
  });

  afterEach(async () => {
    // Release any still-held lock so its holder proceeds to its `finally`
    // unlink, then swallow every tracked promise's outcome so a leaked
    // rejection can never surface after the test. Only then remove the dir.
    for (const release of releasers) release();
    await Promise.allSettled(pending);
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
});
