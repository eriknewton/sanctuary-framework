/**
 * S2: establishWrapCustody previously took the custody write lock and THEN let
 * establishMaster acquire the rotation barrier underneath it (custody-lock ->
 * barrier). rotateMaster takes barrier -> custody-lock, so the opposing orders
 * are a classic lock-order inversion that can deadlock or force-abort a rotation.
 * The fix acquires the SHARED barrier FIRST and hands it to establishMaster as
 * `heldBarrier`, so no second barrier is ever taken under the custody lock and
 * the order matches rotateMaster.
 *
 * This test proves two things without a full rotation:
 *   1. establishWrapCustody COMPLETES (no self-deadlock from the heldBarrier
 *      reuse + reordered locks).
 *   2. DURING the ceremony (a hook that runs while the custody lock is held), the
 *      shared rotation barrier is already held — a concurrent exclusive rotation
 *      cannot drain and fails closed. That is only true if the barrier was taken
 *      before/around the custody lock, i.e. the fixed order.
 * A planted divergence proves the exclusive side is otherwise free once the
 * ceremony (and its barrier) has finished.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { establishWrapCustody } from "../../src/wrap/custody-flow.js";
import {
  withExclusiveMasterRotationBarrier,
  CrossProcessLockError,
} from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const supported = process.platform === "darwin" || process.platform === "linux";
const NS = "_meta";
const BARRIER = "custody-master-rotation";

describe.skipIf(!supported)("establishWrapCustody barrier/lock order (S2)", () => {
  const cleanup: string[] = [];
  afterEach(async () => {
    await Promise.all(
      cleanup.splice(0).map((p) => rm(p, { recursive: true, force: true })),
    );
  });

  async function attemptExclusive(
    storage: FilesystemStorage,
    timeoutMs: number,
  ): Promise<"ran" | "blocked"> {
    try {
      await withExclusiveMasterRotationBarrier(
        storage,
        NS,
        BARRIER,
        async () => undefined,
        { timeoutMs, retryMs: 20 },
      );
      return "ran";
    } catch (error) {
      if (error instanceof CrossProcessLockError) return "blocked";
      throw error;
    }
  }

  it("holds the shared barrier across the ceremony and completes without deadlock", async () => {
    const root = await mkdtemp(join(tmpdir(), "wrap-barrier-order-"));
    cleanup.push(root);
    const storage = new FilesystemStorage(join(root, "state"));

    let barrierHeldDuringCeremony: "ran" | "blocked" | "not-checked" = "not-checked";

    const result = await establishWrapCustody({
      storagePath: root,
      passphrase: "wrap-barrier-order-fortress-passphrase",
      interactive: false,
      // Runs mid-ceremony while the custody write lock is held. If the barrier
      // was acquired first (the fixed order), an exclusive rotation is blocked.
      persistAuthenticatedPassphrase: async () => {
        barrierHeldDuringCeremony = await attemptExclusive(storage, 250);
        return { location: "test-only", source: "test" };
      },
    });

    // The ceremony finished (no self-deadlock).
    expect(result.masterKey.length).toBe(32);
    result.masterKey.fill(0);
    // The shared rotation barrier was held during the custody-locked ceremony.
    expect(barrierHeldDuringCeremony).toBe("blocked");

    // PLANTED DIVERGENCE: after the ceremony (barrier released), the exclusive
    // side is free — so the "blocked" above was the live barrier, not a
    // permanently wedged lock dir.
    expect(await attemptExclusive(storage, 3000)).toBe("ran");
  });
});
