import { describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  closeCliMasterKeySession, establishMaster, resolveCliMasterKey,
  transferCliMasterKeySession, withCliMasterKeySession,
  CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME,
  type CliMasterKeySession,
} from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import * as custodyLocks from "../../src/storage/cross-process-lock.js";
import { kernelBackedCrossProcessLockPlatformSupported, withExclusiveMasterRotationBarrier } from "../../src/storage/cross-process-lock.js";

const passphrase = "cli-session-fixture-passphrase";
const supported = kernelBackedCrossProcessLockPlatformSupported(process.platform);
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
async function fixture(test: (session: CliMasterKeySession, exclusive: () => Promise<string>) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), "cli-session-"));
  let session: CliMasterKeySession | undefined;
  const leases: custodyLocks.MasterWriteBarrierLease[] = [];
  const acquire = custodyLocks.acquireMasterWriteBarrier;
  const acquisition = vi.spyOn(custodyLocks, "acquireMasterWriteBarrier").mockImplementation(async (...args) => {
    const lease = await acquire(...args);
    leases.push(lease);
    return lease;
  });
  try {
    vi.stubEnv("HOME", root);
    vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", join(root, "l"));
    const storage = new FilesystemStorage(join(root, "state"));
    session = await resolveCliMasterKey(storage, { passphrase, bootstrap: true, storagePathHint: root });
    await test(session, () => withExclusiveMasterRotationBarrier(
      new FilesystemStorage(join(root, "state")), CUSTODY_WRITE_LOCK_NAMESPACE,
      MASTER_ROTATION_BARRIER_NAME, async () => "entered", { timeoutMs: 0 },
    ));
  } finally {
    acquisition.mockRestore();
    try { for (const lease of leases) await lease.release(); }
    finally {
      vi.unstubAllEnvs();
      session?.masterKey?.fill(0);
      await rm(root, { recursive: true, force: true });
    }
  }
}

describe.skipIf(!supported)("CLI master session lifetime", () => {
  it("retains the real session until the caller releases it", async () => {
    await fixture(async (session, exclusive) => {
      expect(session.masterWriteBarrier).toBeDefined();
      expect(Object.keys(session)).not.toContain("masterWriteBarrier");
      expect(session.masterWriteBarrier!.signal.aborted).toBe(false);
      await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
      await closeCliMasterKeySession(session);
      expect(session.masterWriteBarrier!.signal.aborted).toBe(true);
      await expect(exclusive()).resolves.toBe("entered");
    });
  });

  it("retains custody and key material until a pending flush finishes", async () => {
    await fixture(async (session, exclusive) => {
      const entered = deferred();
      const finish = deferred();
      const closing = closeCliMasterKeySession(session, async () => { entered.resolve(); await finish.promise; });
      try {
        await entered.promise;
        expect(session.masterKey.some((byte) => byte !== 0)).toBe(true);
        expect(session.masterWriteBarrier!.signal.aborted).toBe(false);
        await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
      } finally {
        finish.resolve();
        await closing;
      }
      expect(session.masterKey.every((byte) => byte === 0)).toBe(true);
      expect(session.masterWriteBarrier!.signal.aborted).toBe(true);
      await expect(exclusive()).resolves.toBe("entered");
    });
  });

  it("attempts release after a rejecting flush", async () => {
    await fixture(async (session, exclusive) => {
      const flushError = new Error("flush rejected");
      await expect(closeCliMasterKeySession(session, async () => { throw flushError; })).rejects.toBe(flushError);
      expect(session.masterWriteBarrier!.signal.aborted).toBe(true);
      await expect(exclusive()).resolves.toBe("entered");
    });
  });

  it("repeated and concurrent finalization releases once and repeats the same rejection", async () => {
    await fixture(async (session, exclusive) => {
      const releaseError = new Error("release rejected");
      const lease = session.masterWriteBarrier!;
      const release = vi.fn(async () => { await lease.release(); throw releaseError; });
      const owned = { masterKey: session.masterKey, masterWriteBarrier: { ...lease, release } };
      const first = closeCliMasterKeySession(owned);
      const second = closeCliMasterKeySession(owned);
      expect(first).toBe(second);
      await expect(first).rejects.toBe(releaseError);
      await expect(second).rejects.toBe(releaseError);
      await expect(closeCliMasterKeySession(owned)).rejects.toBe(releaseError);
      expect(release).toHaveBeenCalledTimes(1);
      expect(lease.signal.aborted).toBe(true);
      await expect(exclusive()).resolves.toBe("entered");
    });
  });

  it.each([new Error("operation rejected"), undefined])("keeps the operation outcome %s alongside a release failure", async (operationError) => {
    await fixture(async (session, exclusive) => {
      const releaseError = new Error("release rejected");
      const lease = session.masterWriteBarrier!;
      const owned = { masterKey: session.masterKey, masterWriteBarrier: {
        ...lease, release: async () => { await lease.release(); throw releaseError; },
      } };
      await expect(withCliMasterKeySession(owned, async () => { throw operationError; }))
        .rejects.toMatchObject({ errors: [operationError, releaseError] });
      expect(lease.signal.aborted).toBe(true);
      await expect(exclusive()).resolves.toBe("entered");
    });
  });

  it("attempts release after a rejecting scrub and keeps both failures", async () => {
    await fixture(async (session, exclusive) => {
      const scrubError = new Error("scrub rejected");
      const releaseError = new Error("release rejected");
      const lease = session.masterWriteBarrier!;
      const fill = vi.spyOn(session.masterKey, "fill").mockImplementation(() => { throw scrubError; });
      const owned = { masterKey: session.masterKey, masterWriteBarrier: {
        ...lease, release: async () => { await lease.release(); throw releaseError; },
      } };
      try {
        await expect(closeCliMasterKeySession(owned)).rejects.toMatchObject({ errors: [scrubError, releaseError] });
        expect(lease.signal.aborted).toBe(true);
        await expect(exclusive()).resolves.toBe("entered");
      } finally { fill.mockRestore(); }
    });
  });

  it("keeps both a flush failure and a release failure", async () => {
    await fixture(async (session, exclusive) => {
      const flushError = new Error("flush rejected");
      const releaseError = new Error("release rejected");
      const lease = session.masterWriteBarrier!;
      const owned = { masterKey: session.masterKey, masterWriteBarrier: {
        ...lease, release: async () => { await lease.release(); throw releaseError; },
      } };
      await expect(closeCliMasterKeySession(owned, async () => { throw flushError; }))
        .rejects.toMatchObject({ errors: [flushError, releaseError] });
      await expect(exclusive()).resolves.toBe("entered");
    });
  });

  it.each([null, 1])("finalizes construction refusal %s before returning", async (refusal) => {
    await fixture(async (session, exclusive) => {
      await expect(transferCliMasterKeySession(session, async () => refusal)).resolves.toBe(refusal);
      expect(session.masterWriteBarrier!.signal.aborted).toBe(true);
      await expect(exclusive()).resolves.toBe("entered");
    });
  });

  it("finalizes failed construction and preserves its error", async () => {
    await fixture(async (session, exclusive) => {
      const error = new Error("construction rejected");
      await expect(transferCliMasterKeySession(session, async () => { throw error; })).rejects.toBe(error);
      expect(session.masterWriteBarrier!.signal.aborted).toBe(true);
      await expect(exclusive()).resolves.toBe("entered");
    });
  });

  it("transfers a constructed object while its session remains open", async () => {
    await fixture(async (session, exclusive) => {
      const context = await transferCliMasterKeySession(session, async () => ({ session }));
      expect(context.session).toBe(session);
      await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
      await closeCliMasterKeySession(context.session);
      await expect(exclusive()).resolves.toBe("entered");
    });
  });
});

it.each(["passphrase", "recovery key"])("returns the retained session for an existing envelope using %s", async (credential) => {
  const root = await mkdtemp(join(tmpdir(), "cli-session-memory-"));
  vi.stubEnv("HOME", root);
  const storage = new MemoryStorage();
  let seed: Awaited<ReturnType<typeof establishMaster>> | undefined;
  let session: CliMasterKeySession | undefined;
  try {
    seed = await establishMaster({ storage, passphrase, firstRun: { installMode: "headless", mintRecoveryKey: true } });
    const expected = Uint8Array.from(seed.masterKey);
    await seed.masterWriteBarrier?.release();
    seed.masterKey.fill(0);
    session = await resolveCliMasterKey(storage, credential === "passphrase" ? { passphrase } : { recoveryKey: seed.mintedRecoveryKey! });
    expect(session.masterKey).toEqual(expected);
    await closeCliMasterKeySession(session);
    expect(session.masterKey.every((byte) => byte === 0)).toBe(true);
    expected.fill(0);
  } finally {
    await seed?.masterWriteBarrier?.release();
    seed?.masterKey.fill(0);
    await session?.masterWriteBarrier?.release();
    session?.masterKey.fill(0);
    vi.unstubAllEnvs();
    await rm(root, { recursive: true, force: true });
  }
});
