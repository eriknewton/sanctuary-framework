import { lstat } from "node:fs/promises";

import { expect } from "vitest";

import type { EstablishMasterResult } from "../../src/core/master-custody.js";
import type { MasterWriteBarrierLease } from "../../src/storage/cross-process-lock.js";

/**
 * Take ownership of the custody lease that a successful `establishMaster`
 * transfers to its caller. The lease's reader socket lives in the shared
 * per-user runtime directory, not under the test's temporary HOME, so a fixture
 * that drops the lease leaves custody held after its namespace is deleted.
 * Callers release it after their last master-derived write through the same
 * storage and before they delete the namespace.
 */
export function takeCustodyLease(
  custody: Pick<EstablishMasterResult, "masterKey" | "masterWriteBarrier">,
): MasterWriteBarrierLease {
  const { masterWriteBarrier } = custody;
  if (!masterWriteBarrier) {
    custody.masterKey.fill(0);
    throw new Error("Seed establishment must return a custody lease");
  }
  return masterWriteBarrier;
}

/**
 * Release every tracked custody lease, attempting each one even after another
 * rejects. A lease leaves `leases` only once its release succeeds, so a lease
 * whose release rejected stays owned: the caller's teardown throws before it
 * deletes the namespace, and a later teardown retries it rather than treating
 * the namespace as free.
 */
export async function releaseCustodyLeases(leases: MasterWriteBarrierLease[]): Promise<void> {
  const failures: unknown[] = [];
  for (const lease of [...leases]) {
    try {
      await lease.release();
      leases.splice(leases.indexOf(lease), 1);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, "A custody lease release failed during teardown");
  }
}

/** Assert that a released custody lease no longer holds its reader socket. */
export async function expectReaderSocketReleased(
  readerSocketPath: string | undefined,
): Promise<void> {
  expect(readerSocketPath).toEqual(expect.any(String));
  await expect(lstat(readerSocketPath!)).rejects.toMatchObject({ code: "ENOENT" });
}
