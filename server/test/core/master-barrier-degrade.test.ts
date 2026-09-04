/**
 * S5 / S5b: when the per-invoker master-rotation barrier cannot be acquired for
 * an ENVIRONMENTAL capability reason (a non-owner invoking uid — a root daemon
 * or `sudo` verb on an operator-owned fortress, a non-local filesystem, looser
 * perms), the barrier must degrade per the caller's declared intent instead of
 * bricking a path that opened before the barrier existed:
 *   - "read-only": reads proceed (assertSessionHeld), the first master-derived
 *     WRITE fails closed (assertHeld throws capability).
 *   - "inert": pre-barrier behavior (both proceed) — only for the already-proven
 *     unattended root-daemon boot whose reboot survival must not regress (S5b).
 *   - default (fail-closed): throw.
 *
 * The `__testGetuid` seam forces the owner-identity mismatch WITHOUT real uid 0,
 * so CI can assert the degrade-vs-refuse SHAPE. A planted divergence proves that
 * with the CORRECT uid a real write barrier is granted (assertHeld succeeds).
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  acquireMasterWriteBarrier,
  CrossProcessLockError,
} from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const supported = process.platform === "darwin" || process.platform === "linux";
const NS = "_meta";
const BARRIER = "custody-master-rotation";

describe.skipIf(!supported)("master-rotation barrier environmental degrade (S5/S5b)", () => {
  const cleanup: string[] = [];
  afterEach(async () => {
    await Promise.all(
      cleanup.splice(0).map((p) => rm(p, { recursive: true, force: true })),
    );
  });

  async function freshStorage(): Promise<FilesystemStorage> {
    const root = await mkdtemp(join(tmpdir(), "barrier-degrade-"));
    cleanup.push(root);
    return new FilesystemStorage(join(root, "state"));
  }

  const realUid = process.getuid?.() ?? 0;
  const wrongUid = realUid + 12345; // simulate a non-owner invoker (e.g. root daemon)

  it("fails CLOSED by default when the invoking uid is not the fortress owner", async () => {
    const storage = await freshStorage();
    await expect(
      acquireMasterWriteBarrier(storage, NS, BARRIER, {
        __testGetuid: () => wrongUid,
      }),
    ).rejects.toBeInstanceOf(CrossProcessLockError);
  });

  it("degrades READ-ONLY: reads proceed, the first write fails closed", async () => {
    const storage = await freshStorage();
    const lease = await acquireMasterWriteBarrier(storage, NS, BARRIER, {
      __testGetuid: () => wrongUid,
      degradeOnEnvironmentalLoss: "read-only",
    });
    // Read side is held (the unlock/read may proceed).
    expect(() => lease.assertSessionHeld()).not.toThrow();
    // Write side fails closed with a capability error naming the cause.
    expect(() => lease.assertHeld()).toThrow(CrossProcessLockError);
    try {
      lease.assertHeld();
    } catch (error) {
      expect((error as CrossProcessLockError).kind).toBe("capability");
      expect((error as Error).message).toMatch(/uid|barrier/i);
    }
    await lease.release();
  });

  it("degrades INERT: both reads and writes proceed (proven root-daemon boot)", async () => {
    const storage = await freshStorage();
    const lease = await acquireMasterWriteBarrier(storage, NS, BARRIER, {
      __testGetuid: () => wrongUid,
      degradeOnEnvironmentalLoss: "inert",
    });
    expect(() => lease.assertSessionHeld()).not.toThrow();
    expect(() => lease.assertHeld()).not.toThrow();
    await lease.release();
  });

  it("PLANTED DIVERGENCE: the correct owner uid grants a REAL write barrier", async () => {
    const storage = await freshStorage();
    const lease = await acquireMasterWriteBarrier(storage, NS, BARRIER, {
      __testGetuid: () => realUid,
      degradeOnEnvironmentalLoss: "read-only",
    });
    // Not degraded: the write side is authorized (no throw).
    expect(() => lease.assertHeld()).not.toThrow();
    await lease.release();
  });
});
