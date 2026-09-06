/**
 * M2 (Grok re-gate residual): a READ verb on a LEGACY pre-envelope fortress
 * reaches `establishMaster` through `resolveCliMasterKey`, and `establishMaster`
 * performs a one-time custody MIGRATION WRITE (`writeCustodyEnvelope`) to wrap
 * the existing master under a custody envelope. This test proves that migration
 * write is fully serialized against a concurrent `rotate-master`, so the two
 * custody paths never overlap.
 *
 * Guarantee proven here: `establishMaster` acquires the SHARED
 * master-rotation barrier (`MASTER_ROTATION_BARRIER_NAME` in `_meta`, the same
 * barrier `rotateMaster` drains on its EXCLUSIVE side) BEFORE it runs any custody
 * path, and holds it unbroken THROUGH the migration write:
 *   (1) the migration write only SUCCEEDS on FilesystemStorage because the
 *       storage write-barrier hook (`assertStorageMasterWriteBarrierHeld`) passes,
 *       i.e. the barrier was provably held at write time — otherwise the write
 *       throws holder-lost; and
 *   (2) while the migration path holds that shared barrier, a concurrent
 *       exclusive rotation cannot drain the reader and fails closed (contention),
 *       so a rotate cannot interleave with the legacy read-migration.
 * A planted divergence (release the barrier first) shows the exclusive side then
 * proceeds, proving the block in (2) is caused by the held barrier and not by an
 * unrelated refusal.
 *
 * (AGENTS rule 12: a bounded critical section reachable from an untrusted caller,
 * proven under an adversarial fault schedule — rotation racing the migration.)
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  establishMaster,
  acquireFortressMasterWriteBarrier,
  readCustodyEnvelope,
} from "../../src/core/master-custody.js";
import {
  withExclusiveMasterRotationBarrier,
  CrossProcessLockError,
} from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";

const supported = process.platform === "darwin" || process.platform === "linux";
const NS = "_meta";
const BARRIER = "custody-master-rotation";
const PASSPHRASE = "legacy-migration-rotation-barrier-passphrase";

describe.skipIf(!supported)(
  "legacy read-migration is serialized by the shared rotation barrier (M2)",
  () => {
    const cleanup: string[] = [];
    afterEach(async () => {
      await Promise.all(
        cleanup.splice(0).map((p) => rm(p, { recursive: true, force: true })),
      );
    });

    /**
     * Seed a PURE-LEGACY passphrase fortress on a real FilesystemStorage: the
     * Argon2id `key-params` marker plus one encrypted identity as migration
     * evidence, and NO custody envelope. The seed writes are made under a
     * short-lived shared barrier (the same hook every fortress write crosses)
     * and the barrier is released, so the fortress is quiescent before the
     * migration-under-test runs.
     */
    async function seededLegacyFortress(): Promise<{
      storage: FilesystemStorage;
      root: string;
    }> {
      const root = await mkdtemp(join(tmpdir(), "legacy-migration-barrier-"));
      cleanup.push(root);
      const storage = new FilesystemStorage(join(root, "state"));
      const { key: master, params } = await deriveMasterKey(PASSPHRASE);
      const barrier = await acquireFortressMasterWriteBarrier(storage);
      try {
        await storage.write(
          "_meta",
          "key-params",
          stringToBytes(JSON.stringify(params)),
        );
        const idKey = derivePurposeKey(master, "identity-encryption");
        const payload = encrypt(stringToBytes('{"identity_id":"seed"}'), idKey);
        idKey.fill(0);
        await storage.write(
          "_identities",
          "seed",
          stringToBytes(JSON.stringify(payload)),
        );
      } finally {
        await barrier.release();
        master.fill(0);
      }
      return { storage, root };
    }

    async function tryExclusive(
      storage: FilesystemStorage,
      timeoutMs: number,
    ): Promise<"ran" | CrossProcessLockError> {
      try {
        let ran = false;
        await withExclusiveMasterRotationBarrier(
          storage,
          NS,
          BARRIER,
          async () => {
            ran = true;
          },
          { timeoutMs, retryMs: 20 },
        );
        return ran ? "ran" : ("ran" as const);
      } catch (error) {
        if (error instanceof CrossProcessLockError) return error;
        throw error;
      }
    }

    it("migrates under the barrier, blocks a concurrent rotate while held, then allows it after release", async () => {
      const { storage, root } = await seededLegacyFortress();

      // Pre-state: pure legacy, no envelope yet.
      expect(await readCustodyEnvelope(storage)).toBeNull();

      // The read-verb migration path: same shape resolveCliMasterKey drives
      // (read-only degrade). establishMaster holds the shared rotation barrier
      // from before any custody path THROUGH the migration write and attaches it
      // (non-enumerable) to the result; we do NOT release it yet.
      const migrated = await establishMaster({
        storage,
        passphrase: PASSPHRASE,
        barrierDegradeMode: "read-only",
        storagePathHint: root,
      });

      // The migration WRITE succeeded — which on FilesystemStorage is only
      // possible if the barrier was held at write time (the storage write hook
      // throws holder-lost otherwise). So the write is proven barrier-covered.
      expect(migrated.origin).toBe("migrated-passphrase");
      const envelope = await readCustodyEnvelope(storage);
      expect(envelope).not.toBeNull();
      expect(envelope?.install_mode).toBe("legacy-migrated");
      expect(migrated.masterWriteBarrier).toBeDefined();
      migrated.masterKey.fill(0);

      // While the migration path still holds the shared barrier, a concurrent
      // exclusive rotation cannot drain the reader and fails closed within its
      // bounded budget — a rotate cannot interleave with the read-migration.
      const blocked = await tryExclusive(storage, 300);
      expect(blocked).toBeInstanceOf(CrossProcessLockError);

      // Release the migration path's barrier: rotation now proceeds.
      await migrated.masterWriteBarrier!.release();
      const allowed = await tryExclusive(storage, 3000);
      expect(allowed).toBe("ran");
    });

    it("PLANTED DIVERGENCE: releasing the migration barrier first lets a rotate proceed", async () => {
      const { storage, root } = await seededLegacyFortress();

      const migrated = await establishMaster({
        storage,
        passphrase: PASSPHRASE,
        barrierDegradeMode: "read-only",
        storagePathHint: root,
      });
      expect(migrated.origin).toBe("migrated-passphrase");
      migrated.masterKey.fill(0);

      // Divergence: release BEFORE attempting the exclusive side. With no reader
      // held, the exclusive rotation drains immediately and runs — proving the
      // block in the primary test is caused by the held barrier, not an
      // unrelated refusal.
      await migrated.masterWriteBarrier!.release();
      const allowed = await tryExclusive(storage, 3000);
      expect(allowed).toBe("ran");
    });
  },
);
