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
import { linkSync, mkdirSync, renameSync } from "node:fs";
import {
  chmod,
  mkdtemp,
  lstat,
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

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  withCrossProcessLock,
  withPathLock,
  CrossProcessLockError,
  resetKernelLockPoisonForTests,
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
