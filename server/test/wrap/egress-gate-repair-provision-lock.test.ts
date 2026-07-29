/**
 * S5-7 fix-round-3: the `--repair-egress-gate` sequence runs UNDER the exclusive
 * provision lock (`PROVISION_LOCK_PATH`), the SAME single-source lock the arm
 * (`runProvisionFlow`) and unprotect (`withUnprotectLock`) CLI runners take, so
 * arm, repair, and unprotect are genuinely mutually exclusive.
 *
 * Before this fix `runEgressGateRepairForCli` called `runEgressGateRepair`
 * WITHOUT any provision-lock wrap, even though repair mutates the pf-anchor
 * registry (addOrUpdate re-arm + release-barrier bootstrap): a concurrent
 * `--repair-egress-gate` could re-arm / re-bootstrap a uid while an in-flight
 * `--unprotect-egress-gate` tore that same uid's gate/credential/policy down
 * (or vice versa). Three doc-comments already CLAIMED "arm, repair, and
 * unprotect are mutually exclusive"; the claim only becomes true with this wrap.
 *
 * The CLI runner itself is darwin/root-gated over real account ops (not
 * host-free drivable), so the lock behavior is extracted into
 * `runEgressGateRepairUnderProvisionLock` with an injectable `lockOps`
 * (production default `realLockOps`). These tests drive that helper directly
 * with an in-memory lock that mirrors the real O_EXCL EEXIST semantics.
 */

import { describe, it, expect, vi } from "vitest";

import { runEgressGateRepairUnderProvisionLock } from "../../src/wrap/auto-provision.js";
import {
  PROVISION_LOCK_PATH,
  type ProvisionLockOps,
} from "../../src/castle-wall/provision/index.js";
import type { EgressGateRepairOutcome } from "../../src/castle-wall/provision/exclusive-arm.js";

/**
 * An in-memory provision lock that mirrors the REAL `realLockOps` / `fsLockOps`
 * O_EXCL semantics: `acquire` of an already-held path rejects with an
 * `EEXIST`-coded error (exactly what Node's `open(path, "wx")` throws), which
 * `withProvisionLock` maps to `ProvisionLockHeldError`. Shared across the
 * simulated verbs so "another provisioning run holds the lock" is real
 * contention, not a stub.
 */
function inMemoryLock(): ProvisionLockOps & { held: Set<string>; acquires: string[] } {
  const held = new Set<string>();
  const acquires: string[] = [];
  return {
    held,
    acquires,
    async acquire(lockPath: string): Promise<void> {
      acquires.push(lockPath);
      if (held.has(lockPath)) {
        const err = new Error(`EEXIST: file already exists, open '${lockPath}'`) as NodeJS.ErrnoException;
        err.code = "EEXIST";
        throw err;
      }
      held.add(lockPath);
    },
    async release(lockPath: string): Promise<void> {
      held.delete(lockPath);
    },
  };
}

const repairedOutcome: EgressGateRepairOutcome = {
  kind: "repaired",
  generationId: 1,
};

describe("runEgressGateRepairUnderProvisionLock (S5-7 fix-round-3: arm/repair/unprotect mutual exclusion)", () => {
  it("lock is free: the repair sequence runs under PROVISION_LOCK_PATH and its outcome is returned (happy path unchanged)", async () => {
    const lock = inMemoryLock();
    const print = vi.fn();
    const runRepair = vi.fn(async () => repairedOutcome);

    const result = await runEgressGateRepairUnderProvisionLock(runRepair, print, lock);

    expect(result).toEqual({ locked: true, outcome: repairedOutcome });
    // Repair actually ran, and it ran under the SINGLE-SOURCE provision lock.
    expect(runRepair).toHaveBeenCalledTimes(1);
    expect(lock.acquires).toEqual([PROVISION_LOCK_PATH]);
    // Lock is released (not stranded) after a normal run.
    expect(lock.held.has(PROVISION_LOCK_PATH)).toBe(false);
    expect(print).not.toHaveBeenCalled();
  });

  it("a concurrent verb (arm/unprotect) already holds the provision lock: repair REFUSES fail-closed and mutates NOTHING", async () => {
    const lock = inMemoryLock();
    // Simulate an in-flight `protect --exclusive-egress` (arm) or
    // `--unprotect-egress-gate` holding the SAME single-source lock.
    await lock.acquire(PROVISION_LOCK_PATH);

    const print = vi.fn();
    const runRepair = vi.fn(async () => repairedOutcome);

    const result = await runEgressGateRepairUnderProvisionLock(runRepair, print, lock);

    expect(result).toEqual({ locked: false });
    // The critical assertion: the repair sequence NEVER ran, so it could not
    // re-arm / re-bootstrap the registry concurrently with the in-flight verb.
    expect(runRepair).not.toHaveBeenCalled();
    // Loud, operator-facing refusal was printed.
    expect(print).toHaveBeenCalledTimes(1);
    expect(print.mock.calls[0]![0]).toMatch(/Repair refused: another 'sanctuary protect' provisioning run/i);
    expect(print.mock.calls[0]![0]).toMatch(/made NO changes/i);
    // The concurrent verb still holds the lock -- repair did not steal or drop it.
    expect(lock.held.has(PROVISION_LOCK_PATH)).toBe(true);
  });

  it("serializes the other direction: while repair holds the lock, a concurrent unprotect/arm acquisition on the same path is refused", async () => {
    const lock = inMemoryLock();
    const print = vi.fn();
    let concurrentAcquireError: unknown;

    const runRepair = vi.fn(async () => {
      // Repair is now executing UNDER the lock. A concurrent unprotect/arm that
      // reaches the same single-source lock must be turned away, proving repair
      // holds PROVISION_LOCK_PATH for the whole sequence.
      try {
        await lock.acquire(PROVISION_LOCK_PATH);
      } catch (err) {
        concurrentAcquireError = err;
      }
      return repairedOutcome;
    });

    const result = await runEgressGateRepairUnderProvisionLock(runRepair, print, lock);

    expect(result).toEqual({ locked: true, outcome: repairedOutcome });
    expect(concurrentAcquireError).toBeDefined();
    expect((concurrentAcquireError as NodeJS.ErrnoException).code).toBe("EEXIST");
    // Released after the sequence completes.
    expect(lock.held.has(PROVISION_LOCK_PATH)).toBe(false);
  });

  it("a genuine (non-lock) failure inside the repair sequence PROPAGATES and the lock is released (never stranded, never swallowed)", async () => {
    const lock = inMemoryLock();
    const print = vi.fn();
    const boom = new Error("bring-up failed at release barrier");
    const runRepair = vi.fn(async () => {
      throw boom;
    });

    await expect(runEgressGateRepairUnderProvisionLock(runRepair, print, lock)).rejects.toBe(boom);

    // A real repair failure is NOT masked as a lock refusal.
    expect(print).not.toHaveBeenCalled();
    // The `withProvisionLock` finally released the lock despite the throw, so a
    // later arm/repair/unprotect is not permanently wedged.
    expect(lock.held.has(PROVISION_LOCK_PATH)).toBe(false);
  });
});
