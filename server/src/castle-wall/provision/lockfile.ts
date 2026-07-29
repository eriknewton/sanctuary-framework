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
 *
 * ALSO HOME (round-4 C1) to the fortress-scoped EGRESS-POLICY WRITER lock
 * shared by every mutator of `policy/egress/rules/` + `manifest.json` (the
 * provisioning publish/scrub/restore paths here AND the observe promote in
 * `cli/castle-wall-observe.ts`). Placed in this module -- not the CLI --
 * because provision code must never import the CLI layer.
 */

import { open, readFile, rm } from "node:fs/promises";
import { join } from "node:path";

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

// ─────────────────────────────────────────────────────────────────────────────
// The EGRESS-POLICY WRITER lock (2026-07-27 round-4 C1).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lockfile basename for the fortress-scoped EGRESS-POLICY WRITER mutual
 * exclusion. Lives directly under the fortress root, beside the observe
 * refresh lock. Writer-neutral by design: EVERY mutator of the shared
 * `policy/egress/rules/` directory + `policy/egress/manifest.json` pair
 * serializes on it -- the observe promote publish (which holds it across its
 * verified re-read, digest CAS, publish, and orphan-cleanup) AND the
 * provisioning write/revoke/restore paths (`provision/egress.ts`). Without
 * one shared lock, a provisioning revoke interleaved with a promote's
 * publish window could produce torn multi-file views of the rule source (the
 * promote's manifest-digest CAS sees only manifest.json, which provisioning
 * never touches). New in this PR's fix stack; no compatibility concern.
 */
export const EGRESS_POLICY_WRITER_LOCK_FILE = ".egress-policy.lock";

/** The `acquire()` contract shared with `observe/refresh.ts`'s RefreshLock (structural). */
export interface EgressPolicyWriterLock {
  acquire(): Promise<(() => Promise<void>) | null>;
}

/**
 * Cross-process egress-policy writer lock: O_EXCL create with pid metadata,
 * NEVER auto-broken (the same TOCTOU rationale as the observe refresh lock:
 * any read-check-unlink-retry breaker can unlink a peer's freshly-created
 * lock and let two writers run concurrently, which is exactly what this lock
 * exists to prevent). Contended => `acquire()` returns null and the caller
 * refuses loudly with nothing written.
 *
 * ROOT-VS-OPERATOR CONTEXT (stated, per the round-4 review): provisioning
 * runs as root, promote as the operator. A shared O_EXCL file at the
 * fortress root works for both: whoever acquires owns the file; the OTHER
 * writer's O_EXCL create fails EEXIST regardless of the owner uid, and
 * unlink permission is governed by the FORTRESS DIRECTORY (operator-owned;
 * root writes anywhere), so a stale root-owned lock is still removable by
 * the operator following the holder guidance.
 *
 * Release is BEST-EFFORT (round-3 L1 discipline): a failed unlink is noted
 * on stderr with the lock path and never thrown over the caller's outcome.
 */
export function egressPolicyWriterLock(
  fortressPath: string,
  onContention?: (holderDescription: string) => void,
): EgressPolicyWriterLock {
  const lockPath = join(fortressPath, EGRESS_POLICY_WRITER_LOCK_FILE);
  return {
    async acquire() {
      try {
        // 0644 (round-5 RC3a): the holder metadata is pid + timestamp, not
        // secret, and the two writers run as DIFFERENT users (provisioning
        // as root, promote as the operator). A 0600 root-owned lock left by
        // a crashed root holder was unreadable by the operator's
        // stale-holder description -- defeating the guidance in exactly its
        // target case. World-readable, owner-writable.
        const handle = await open(lockPath, "wx", 0o644);
        try {
          await handle.writeFile(
            JSON.stringify({ pid: process.pid, acquired_at: new Date().toISOString() }),
          );
          await handle.sync();
        } finally {
          await handle.close();
        }
        return async () => {
          try {
            await rm(lockPath, { force: true });
          } catch (releaseError) {
            process.stderr.write(
              `Warning: could not remove the lock file ${lockPath} (${(releaseError as Error).message}). ` +
                "The operation itself completed; remove the file manually or the next run will report it as held.\n",
            );
          }
        };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (onContention) onContention(await describeEgressPolicyLockHolder(lockPath));
        return null;
      }
    },
  };
}

/** True iff `pid` names a live process this user could signal. */
function isEgressLockHolderAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: the process exists but belongs to another user -- still alive
    // (the expected shape when root holds the lock and the operator probes).
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Best-effort description of who holds the writer lock. Never throws. */
async function describeEgressPolicyLockHolder(lockPath: string): Promise<string> {
  try {
    const parsed = JSON.parse(await readFile(lockPath, "utf8")) as {
      pid?: unknown;
      acquired_at?: unknown;
    };
    const pid = typeof parsed.pid === "number" ? parsed.pid : null;
    const at = typeof parsed.acquired_at === "string" ? parsed.acquired_at : "an unknown time";
    if (pid === null) return `held since ${at} by an unrecorded process`;
    return isEgressLockHolderAlive(pid)
      ? `held since ${at} by running process ${pid}`
      : `held since ${at} by process ${pid}, which is NO LONGER RUNNING -- this lock is almost ` +
          `certainly stale from a crashed run; verify with \`ps -p ${pid}\` and then remove ${lockPath}`;
  } catch {
    return `present but unreadable at ${lockPath}`;
  }
}
