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

/** Assert that a released custody lease no longer holds its reader socket. */
export async function expectReaderSocketReleased(
  readerSocketPath: string | undefined,
): Promise<void> {
  expect(readerSocketPath).toEqual(expect.any(String));
  await expect(lstat(readerSocketPath!)).rejects.toMatchObject({ code: "ENOENT" });
}
