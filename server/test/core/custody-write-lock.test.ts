import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import {
  CrossProcessLockError,
  kernelBackedCrossProcessLockPlatformSupported,
  probeKernelBackedCrossProcessLockCapability,
} from "../../src/storage/cross-process-lock.js";
import {
  CUSTODY_ENVELOPE_KEY,
  CUSTODY_SENTINEL_KEY,
  CustodySnapshotChangedError,
  establishMaster,
  withCustodyWriteLock,
} from "../../src/core/master-custody.js";

describe("shared custody/master lock domain", () => {
  const cleanups: string[] = [];
  afterEach(async () => {
    await Promise.all(cleanups.splice(0).map((path) =>
      rm(path, { recursive: true, force: true })));
  });

  async function storage(label: string): Promise<FilesystemStorage> {
    const root = await mkdtemp(join(tmpdir(), `custody-lock-${label}-`));
    cleanups.push(root);
    return new FilesystemStorage(join(root, "state"));
  }

  it("advertises kernel custody locking only on implemented platforms", () => {
    expect(kernelBackedCrossProcessLockPlatformSupported("darwin")).toBe(true);
    expect(kernelBackedCrossProcessLockPlatformSupported("linux")).toBe(true);
    expect(kernelBackedCrossProcessLockPlatformSupported("win32")).toBe(false);
  });

  it("reports the process-owned socket primitive and gates unsupported hosts", async () => {
    const available = await probeKernelBackedCrossProcessLockCapability(
      process.platform,
    );
    expect(available).toEqual({
      available: true,
      command: "process-owned-unix-domain-socket",
    });
    await expect(
      probeKernelBackedCrossProcessLockCapability("win32"),
    ).resolves.toMatchObject({ available: false, reason: expect.stringContaining("unsupported") });
  });

  it("refuses same-fortress re-entry through a different storage instance", async () => {
    const first = await storage("same");
    // A distinct backend object naming the same state path must still re-enter.
    const second = new FilesystemStorage(first.namespacePath("_meta").replace(/\/_meta$/, ""));
    await withCustodyWriteLock(first, async (outerLease) => {
      outerLease.assertHeld();
      await expect(
        withCustodyWriteLock(second, async () => undefined),
      ).rejects.toThrow(/different storage instance.*inode-bound capability/);
    });
  });

  it("re-enters through the same capability-bound FilesystemStorage instance", async () => {
    const store = await storage("same-instance");
    await withCustodyWriteLock(store, async (outerLease) => {
      await withCustodyWriteLock(store, async (innerLease) => {
        expect(innerLease).toBe(outerLease);
        await store.write("_meta", "same-instance", new Uint8Array([1]));
      });
    });
    expect(await store.read("_meta", "same-instance")).toEqual(new Uint8Array([1]));
  });

  it("refuses AB/BA lock order across two fortresses instead of deadlocking", async () => {
    const first = await storage("a");
    const second = await storage("b");
    await withCustodyWriteLock(first, async () => {
      await expect(
        withCustodyWriteLock(second, async () => undefined),
      ).rejects.toBeInstanceOf(CrossProcessLockError);
      await expect(
        withCustodyWriteLock(second, async () => undefined),
      ).rejects.toThrow(/lock-order violation/);
    });
  });

  it("refuses a storage decorator that fails to forward namespace locking", async () => {
    const base = new MemoryStorage();
    const wrapper: StorageBackend = {
      write: (...args) => base.write(...args),
      read: (...args) => base.read(...args),
      delete: (...args) => base.delete(...args),
      list: (...args) => base.list(...args),
      exists: (...args) => base.exists(...args),
      totalSize: () => base.totalSize(),
    };
    await expect(withCustodyWriteLock(wrapper, async () => undefined))
      .rejects.toMatchObject({ kind: "capability" });
  });

  it("unlocks an existing envelope through a read-only wrapper without requiring write-lock capability", async () => {
    const base = new MemoryStorage();
    const created = await establishMaster({
      storage: base,
      passphrase: "existing-envelope-passphrase",
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    created.masterKey.fill(0);
    const wrapper: StorageBackend = {
      write: async () => { throw new Error("read-only wrapper write reached"); },
      read: (...args) => base.read(...args),
      delete: async () => { throw new Error("read-only wrapper delete reached"); },
      list: (...args) => base.list(...args),
      exists: (...args) => base.exists(...args),
      totalSize: () => base.totalSize(),
    };
    const opened = await establishMaster({
      storage: wrapper,
      passphrase: "existing-envelope-passphrase",
    });
    expect(opened.origin).toBe("envelope");
    opened.masterKey.fill(0);
  });

  it("preserves authenticated Windows reads while fencing every master-derived filesystem write", async () => {
    const source = new MemoryStorage();
    const created = await establishMaster({
      storage: source,
      passphrase: "windows-read-only-passphrase",
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    created.masterKey.fill(0);
    const target = await storage("windows-read-only");
    await target.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      (await source.read("_meta", CUSTODY_ENVELOPE_KEY))!,
    );
    await target.write(
      "_meta",
      CUSTODY_SENTINEL_KEY,
      (await source.read("_meta", CUSTODY_SENTINEL_KEY))!,
    );
    const opened = await establishMaster({
      storage: target,
      passphrase: "windows-read-only-passphrase",
      __testMasterWriteBarrierOptions: { __testPlatform: "win32" },
    });
    expect(opened.origin).toBe("envelope");
    await expect(
      target.write("notes", "refused", new Uint8Array([1])),
    ).rejects.toMatchObject({ kind: "capability" });
    await expect(target.read("_meta", CUSTODY_ENVELOPE_KEY)).resolves.not.toBeNull();
    await opened.masterWriteBarrier?.release();
    opened.masterKey.fill(0);
  });

  it("rejects a lock-free unlock when the envelope vanishes during the authenticated read", async () => {
    const base = new MemoryStorage();
    const created = await establishMaster({
      storage: base,
      passphrase: "snapshot-change-passphrase",
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    created.masterKey.fill(0);
    let envelopeReads = 0;
    const racing: StorageBackend = {
      write: (...args) => base.write(...args),
      read: async (...args) => {
        const value = await base.read(...args);
        if (
          args[0] === "_meta" &&
          args[1] === CUSTODY_ENVELOPE_KEY &&
          ++envelopeReads === 1
        ) {
          await base.delete("_meta", CUSTODY_ENVELOPE_KEY);
        }
        return value;
      },
      delete: (...args) => base.delete(...args),
      list: (...args) => base.list(...args),
      exists: (...args) => base.exists(...args),
      totalSize: () => base.totalSize(),
    };
    await expect(establishMaster({
      storage: racing,
      passphrase: "snapshot-change-passphrase",
    })).rejects.toBeInstanceOf(CustodySnapshotChangedError);
  });

  it("serializes custody ceremonies on the in-memory backend", async () => {
    const base = new MemoryStorage();
    const trace: string[] = [];
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const first = withCustodyWriteLock(base, async () => {
      trace.push("first-enter");
      await blocked;
      trace.push("first-exit");
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    const second = withCustodyWriteLock(base, async () => { trace.push("second-enter"); });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(trace).toEqual(["first-enter"]);
    release();
    await Promise.all([first, second]);
    expect(trace).toEqual(["first-enter", "first-exit", "second-enter"]);
  });
});
