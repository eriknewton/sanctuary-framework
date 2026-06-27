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

  beforeEach(async () => {
    base = await mkdtemp(join(tmpdir(), "xproc-lock-"));
    storage = new FilesystemStorage(join(base, "state"));
  });

  afterEach(async () => {
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
    const holder = withCrossProcessLock(storage, NS, LOCK, async () => {
      await held;
    });
    // Give the holder a beat to take the lock.
    await sleep(20);

    await expect(
      withCrossProcessLock(storage, NS, LOCK, async () => undefined, {
        timeoutMs: 80,
        retryMs: 10,
      }),
    ).rejects.toBeInstanceOf(CrossProcessLockError);

    release();
    await holder;
  });

  it("breaks a provably-stale lock left by a dead holder PID", async () => {
    // Write a lockfile whose holder PID cannot exist (a never-allocated high PID),
    // simulating a crashed process that never released its lock.
    const { mkdir } = await import("node:fs/promises");
    const dir = storage.namespacePath(NS);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const lockPath = join(dir, LOCK);
    await writeFile(
      lockPath,
      JSON.stringify({ pid: 2_147_483_646, acquired_at: new Date().toISOString() }),
    );

    let ran = false;
    await withCrossProcessLock(
      storage,
      NS,
      LOCK,
      async () => {
        ran = true;
      },
      { timeoutMs: 1_000, retryMs: 10 },
    );
    expect(ran).toBe(true);
    // The lock is released again after the operation.
    await expect(readFile(lockPath, "utf8")).rejects.toThrow();
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
