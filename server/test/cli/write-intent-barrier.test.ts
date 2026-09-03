/**
 * S1: the write-capable memory verbs unlock through unlockLocalFortress, which
 * previously took NO master-rotation barrier — so a concurrent rotate-master
 * could re-encrypt while the verb kept writing OLD-master ciphertext. The fix
 * gives a `writeIntent` unlock the shared barrier, held until the verb's final
 * write. This test proves the property with the real barrier primitives: while a
 * writeIntent lease is held, the exclusive rotation side cannot drain and fails
 * closed (contention); once released, it proceeds. A planted divergence shows a
 * read-only (no-writeIntent) unlock holds NO barrier, so rotation is not blocked.
 *
 * (AGENTS rule 12: a bounded critical section reachable from an untrusted caller
 * proven under an adversarial fault schedule — here, rotation racing the writer.)
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { establishMaster } from "../../src/core/master-custody.js";
import { unlockLocalFortress } from "../../src/cli/local-fortress-unlock.js";
import {
  withExclusiveMasterRotationBarrier,
  CrossProcessLockError,
} from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const supported = process.platform === "darwin" || process.platform === "linux";
const NS = "_meta";
const BARRIER = "custody-master-rotation";
const PASSPHRASE = "write-intent-barrier-fortress-passphrase";

describe.skipIf(!supported)("writeIntent unlock holds the rotation barrier (S1)", () => {
  const cleanup: string[] = [];
  afterEach(async () => {
    await Promise.all(
      cleanup.splice(0).map((p) => rm(p, { recursive: true, force: true })),
    );
  });

  async function seededFortress(): Promise<{ storage: FilesystemStorage; root: string }> {
    const root = await mkdtemp(join(tmpdir(), "write-intent-barrier-"));
    cleanup.push(root);
    const storage = new FilesystemStorage(join(root, "state"));
    const est = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    // Release the establishment barrier so only the unlock-under-test holds one.
    await est.masterWriteBarrier?.release();
    est.masterKey.fill(0);
    return { storage, root };
  }

  async function tryExclusive(storage: FilesystemStorage, timeoutMs: number): Promise<"ran" | CrossProcessLockError> {
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

  it("blocks a concurrent rotation-exclusive while held, then allows it after release", async () => {
    const { storage, root } = await seededFortress();

    const unlocked = await unlockLocalFortress({
      storage,
      storagePath: root,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      writeIntent: true,
    });
    expect(unlocked.ok).toBe(true);
    if (!unlocked.ok) return;
    expect(unlocked.barrier).toBeDefined();
    unlocked.masterKey.fill(0);

    // While the writer barrier is held, the exclusive rotation side cannot drain
    // the reader and fails closed within its bounded budget (never proceeds to
    // re-encrypt underneath the writer).
    const blocked = await tryExclusive(storage, 300);
    expect(blocked).toBeInstanceOf(CrossProcessLockError);

    // Release the writer's barrier (its final write is done): rotation proceeds.
    await unlocked.barrier!.release();
    const allowed = await tryExclusive(storage, 3000);
    expect(allowed).toBe("ran");
  });

  it("PLANTED DIVERGENCE: a read-only unlock holds NO barrier, so rotation is not blocked", async () => {
    const { storage, root } = await seededFortress();

    const unlocked = await unlockLocalFortress({
      storage,
      storagePath: root,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      // no writeIntent → no barrier
    });
    expect(unlocked.ok).toBe(true);
    if (!unlocked.ok) return;
    expect(unlocked.barrier).toBeUndefined();
    unlocked.masterKey.fill(0);

    // No reader is held, so the exclusive side drains immediately and runs.
    const allowed = await tryExclusive(storage, 3000);
    expect(allowed).toBe("ran");
  });
});
