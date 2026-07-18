/**
 * Auto-provision Step 2 (Build 1): lockfile around detect + create +
 * uid-selection (fix L1).
 *
 * Two concurrent `sanctuary protect` invocations (e.g. an operator re-runs
 * protect in a second terminal while the first is still provisioning) could
 * otherwise both observe "no dedicated account yet", both select the SAME
 * lowest-free uid, and race to create it -- one wins, one gets a confusing
 * `dscl`/`sysadminctl` failure, or worse, both partially succeed and leave
 * an inconsistent uid assignment. This module provides a simple
 * exclusive-lock primitive (O_EXCL create, matching the anti-rollback
 * lockfile discipline used elsewhere in this codebase for collision
 * detection) so the detect -> plan -> create -> uid-selection window is
 * exclusive to one in-flight provision at a time. Fail-loud on collision:
 * a second invocation refuses immediately rather than silently waiting or
 * silently proceeding.
 */

/**
 * The canonical exclusive provision-lock path. The auto-provision arm/repair
 * flows AND the S5-7 unprotect sequence take THIS lock, so arm, repair, and
 * unprotect are mutually exclusive and two unprotects serialize (S5-7
 * fix-round-2 HIGH-1: a lockless sibling snapshot let a concurrent
 * `protect --exclusive-egress` commit a sibling between the snapshot and the
 * teardown). Single source of truth so the two callers can never drift.
 */
export const PROVISION_LOCK_PATH = "/var/run/sanctuary-provision.lock";

/** Injected lock operations so this is unit-testable without touching the real filesystem. */
export interface ProvisionLockOps {
  /**
   * Attempt an exclusive create of the lock path. Must throw with a code the
   * caller can recognize as "already exists" (production: Node's `open`
   * with the `wx` flag rejects with `EEXIST`) when the lock is already held.
   */
  acquire(lockPath: string): Promise<void>;
  /** Release (remove) the lock. ENOENT is not an error (already released / never acquired). */
  release(lockPath: string): Promise<void>;
}

/** Thrown when the lock is already held by another in-flight provision. */
export class ProvisionLockHeldError extends Error {
  constructor(lockPath: string) {
    super(
      `Another sanctuary protect provisioning run appears to be in progress (lock held: ${lockPath}). ` +
        "Refusing to proceed to avoid two concurrent runs racing to create the same account. " +
        "If no other run is actually in progress, remove the lock file and retry.",
    );
    this.name = "ProvisionLockHeldError";
  }
}

/**
 * Run `fn` while holding the exclusive provision lock. Fail-loud: if the
 * lock is already held, throws {@link ProvisionLockHeldError} immediately
 * (never waits, never silently proceeds). Always releases the lock in a
 * `finally`, so a mid-flow failure inside `fn` does not strand the lock for
 * future runs.
 */
export async function withProvisionLock<T>(
  lockPath: string,
  ops: ProvisionLockOps,
  fn: () => Promise<T>,
): Promise<T> {
  try {
    await ops.acquire(lockPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === "EEXIST") {
      throw new ProvisionLockHeldError(lockPath);
    }
    throw err;
  }
  try {
    return await fn();
  } finally {
    await ops.release(lockPath);
  }
}
