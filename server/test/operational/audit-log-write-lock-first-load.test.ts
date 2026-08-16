// C9 (register, MEDIUM availability): `persistChainedEntry` used to run the
// mandatory first-load read-consistency retry (`ensureLoaded()`) INSIDE the
// cross-process audit write lock, so a torn read on an appending process's
// FIRST load held the lock for up to a second full decrypt+verify pass (see
// the (retired) KNOWN LATENCY EXPOSURE note on `loadPersistedEntriesWithReadConsistency`
// in src/operational/audit-log.ts). The fix moves that call to run BEFORE the
// lock is requested; this test proves the lock-hold window actually shrank,
// not merely that the code was moved, via an adversarial fault schedule: a
// deliberately delayed/torn first read races a second, independent writer
// that must be free to use the same cross-process lock while the first
// writer's load is still resolving, and the whole scenario must still end
// with a clean chain (no torn read admitted; AGENTS.md rule 12).
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageEntryMeta } from "../../src/storage/interface.js";

const AUDIT_NAMESPACE = "_audit";
const LOCK_FILE = ".audit-write.lock";

function entry(operation: string, n: number) {
  return {
    layer: "l2" as const,
    operation,
    identity_id: `id-${n}`,
    result: "success" as const,
    details: { n },
  };
}

function deferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

/**
 * Simulates a torn first read exactly like the existing
 * "retries through a transient torn listing" coverage in
 * audit-log-concurrent-write.test.ts (only the FIRST unprefixed `_audit`
 * listing is decimated, so the read-consistency retry must run once), but
 * additionally PAUSES that first call before it returns so the test can
 * inspect and act on the world while the retry is in flight — this is what
 * turns "the read is torn" into a deterministic fault-schedule test instead
 * of a timing-dependent one.
 */
class GatedTornListingStorage extends FilesystemStorage {
  private auditListCalls = 0;
  private readonly firstCallSeenGate = deferred<void>();
  private readonly releaseGate = deferred<void>();

  readonly firstCallSeen = this.firstCallSeenGate.promise;

  release(): void {
    this.releaseGate.resolve();
  }

  override async list(
    namespace: string,
    prefix?: string,
  ): Promise<StorageEntryMeta[]> {
    if (
      namespace === AUDIT_NAMESPACE &&
      prefix === undefined &&
      this.auditListCalls++ === 0
    ) {
      this.firstCallSeenGate.resolve();
      await this.releaseGate.promise;
      return []; // torn: empty listing despite real entries already on disk
    }
    return super.list(namespace, prefix);
  }
}

async function lockFileExists(lockPath: string): Promise<boolean> {
  try {
    await stat(lockPath);
    return true;
  } catch (err) {
    if (err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw err;
  }
}

describe("AuditLog write-lock hold window on first load (C9)", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const dir of dirs.splice(0)) {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it(
    "does not hold the write lock during a torn first-load retry, and admits no torn read",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-lock-firstload-"));
      dirs.push(root);
      const storagePath = join(root, "state");
      const lockPath = join(storagePath, AUDIT_NAMESPACE, LOCK_FILE);
      const masterKey = generateRandomKey();

      // Seed a real chain so the SUT's first load has genuine content to see
      // (and so a torn/empty listing against it produces the same
      // tail_anchor_invalid-shaped finding the existing torn-listing coverage
      // exercises, not a degenerate empty-store no-op).
      const seedCount = 5;
      const seeder = new AuditLog(new FilesystemStorage(storagePath), masterKey, {
        checkpointInterval: 10_000,
      });
      for (let i = 0; i < seedCount; i++) {
        await seeder.appendCritical(entry("seed", i));
      }
      await seeder.flush();

      const gatedStorage = new GatedTornListingStorage(storagePath);
      const sut = new AuditLog(gatedStorage, masterKey, { checkpointInterval: 10_000 });

      // Kick off the SUT's first-ever append. Its first load hits the gated,
      // torn (empty) listing and pauses there, before persistChainedEntry
      // ever calls withAuditWriteLock (per the C9 fix: ensureLoaded() now
      // runs before lock acquisition).
      const sutAppend = sut.appendCritical(entry("sut", 0));
      await gatedStorage.firstCallSeen;

      // PROOF 1: the write lock has not even been requested yet. Under the
      // pre-fix code (ensureLoaded() called INSIDE withAuditWriteLock), the
      // lock file would already exist at this exact point.
      expect(await lockFileExists(lockPath)).toBe(false);

      // PROOF 2 (adversarial fault schedule): a second, fully independent
      // writer must be free to acquire and release the SAME cross-process
      // lock while the SUT's first load is still stuck mid-retry. Under the
      // pre-fix code this would contend on the SUT's held lock and either
      // block for the full AUDIT_WRITE_LOCK_TIMEOUT_MS or throw
      // AuditLockContentionError; here it must complete promptly.
      const otherWriter = new AuditLog(new FilesystemStorage(storagePath), masterKey, {
        checkpointInterval: 10_000,
      });
      await otherWriter.appendCritical(entry("other-writer", 0));
      await otherWriter.flush();

      // Only now let the SUT's paused first listing call return (the torn,
      // empty result), which drives it into the read-consistency retry that
      // must recover once the listing changes to the real, current state.
      gatedStorage.release();
      await sutAppend;
      await sut.flush();

      // PROOF 3: no torn read was admitted. The SUT's append landed on top
      // of both the seed and the concurrent otherWriter append, the chain is
      // contiguous, and a fresh strict read reports zero integrity findings.
      const reader = new AuditLog(new FilesystemStorage(storagePath), masterKey, {
        checkpointInterval: 10_000,
      });
      const result = await reader.query({ limit: 100 });
      expect(result.integrity_findings).toEqual([]);
      expect(result.total).toBe(seedCount + 2);
      const ops = result.entries.map((e) => e.operation);
      expect(ops).toContain("sut");
      expect(ops).toContain("other-writer");
    },
    30_000,
  );

  // The test above proves the C9 bound holds for ONE stuck first-load wave.
  // AGENTS.md rule 12 requires proving a bounded critical section holds under
  // a genuine fault SCHEDULE -- repeated and overlapping admission waves, and
  // a wave completing late relative to the ones after it -- not just a single
  // instantaneous instance, because a per-wave-correct guard can still be
  // reachable only once a second or third stuck loader piles onto the same
  // cross-process lock, or once one wave's retry resolves out of order.
  it(
    "does not accumulate lock contention across repeated, overlapping first-load waves, and each independent write stays far under the lock timeout (AGENTS.md rule 12)",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-lock-firstload-waves-"));
      dirs.push(root);
      const storagePath = join(root, "state");
      const lockPath = join(storagePath, AUDIT_NAMESPACE, LOCK_FILE);
      const masterKey = generateRandomKey();

      const seedCount = 5;
      const seeder = new AuditLog(new FilesystemStorage(storagePath), masterKey, {
        checkpointInterval: 10_000,
      });
      for (let i = 0; i < seedCount; i++) {
        await seeder.appendCritical(entry("seed", i));
      }
      await seeder.flush();

      // Three independent "processes" (A, B, C), each with its OWN
      // GatedTornListingStorage instance, so each gates on its OWN first
      // `_audit` listing -- mirroring three separate appenders each hitting
      // their first-ever load -- started on an OVERLAPPING, staggered
      // schedule rather than one at a time.
      const waveA = new GatedTornListingStorage(storagePath);
      const waveB = new GatedTornListingStorage(storagePath);
      const waveC = new GatedTornListingStorage(storagePath);
      const sutA = new AuditLog(waveA, masterKey, { checkpointInterval: 10_000 });
      const sutB = new AuditLog(waveB, masterKey, { checkpointInterval: 10_000 });
      const sutC = new AuditLog(waveC, masterKey, { checkpointInterval: 10_000 });

      async function timedIndependentWrite(label: string): Promise<number> {
        const writer = new AuditLog(new FilesystemStorage(storagePath), masterKey, {
          checkpointInterval: 10_000,
        });
        const started = Date.now();
        await writer.appendCritical(entry(label, 0));
        await writer.flush();
        return Date.now() - started;
      }

      // Wave A begins and gets stuck on its torn first read.
      const appendA = sutA.appendCritical(entry("wave-a", 0));
      await waveA.firstCallSeen;
      expect(await lockFileExists(lockPath)).toBe(false);

      // Wave B begins WHILE wave A is still stuck: two independent
      // first-loads stuck on the same underlying lock at once.
      const appendB = sutB.appendCritical(entry("wave-b", 0));
      await waveB.firstCallSeen;
      expect(await lockFileExists(lockPath)).toBe(false);

      // An unrelated writer must still be free to use the lock while BOTH A
      // and B are stuck, and must complete far under the 5s contention
      // timeout (AUDIT_WRITE_LOCK_TIMEOUT_MS) -- proving the timeout budget
      // is never even approached, not merely that the append eventually
      // succeeds before it expires.
      const elapsed1 = await timedIndependentWrite("writer-1");
      expect(elapsed1).toBeLessThan(1_000);

      // Wave A's gate is released now but NOT awaited yet: its retry pass
      // (a second, non-gated listing plus decrypt/verify) keeps running
      // concurrently with wave C starting below, so wave A completes LATE
      // relative to wave C's admission rather than strictly before it.
      waveA.release();

      // Wave C begins while A is still finishing late and B is still stuck:
      // a THIRD overlapping first-load wave, proving the bound holds under a
      // three-deep pile-up, not just a pairwise one.
      const appendC = sutC.appendCritical(entry("wave-c", 0));
      await waveC.firstCallSeen;
      expect(await lockFileExists(lockPath)).toBe(false);

      const elapsed2 = await timedIndependentWrite("writer-2");
      expect(elapsed2).toBeLessThan(1_000);

      // Release the remaining waves and let all three settle in whatever
      // order their retries actually finish.
      waveB.release();
      waveC.release();
      await Promise.all([appendA, appendB, appendC]);
      await Promise.all([sutA.flush(), sutB.flush(), sutC.flush()]);

      // No wave admitted a torn read, no sequence collided across the
      // three-deep overlap, and the chain is contiguous across seed + 3
      // waves + 2 independent writers.
      const reader = new AuditLog(new FilesystemStorage(storagePath), masterKey, {
        checkpointInterval: 10_000,
      });
      const result = await reader.query({ limit: 100 });
      expect(result.integrity_findings).toEqual([]);
      expect(result.total).toBe(seedCount + 5);
      const ops = result.entries.map((e) => e.operation);
      for (const op of ["wave-a", "wave-b", "wave-c", "writer-1", "writer-2"]) {
        expect(ops).toContain(op);
      }
    },
    30_000,
  );
});
