/**
 * Cross-process advisory lock over a filesystem-backed storage namespace.
 *
 * Some security-critical state lives in ONE on-disk blob that more than one
 * process mutates out-of-band (for example the live federation daemon AND the
 * `rotate-root --compromised` CLI both rewrite the federation sync-state record).
 * An in-process write chain serializes writers WITHIN a process but does nothing
 * across processes, so a read-modify-write whose read and write straddle another
 * process's write can silently lose the other process's committed change (a
 * classic lost-update under genuine write OVERLAP, not just sequential completion).
 *
 * {@link withCrossProcessLock} serializes the WHOLE read-modify-write across
 * processes on filesystem backends. It is a PLAIN O_EXCL lock: an O_EXCL create
 * of a lockfile in the namespace directory, a bounded wait, and a fail-CLOSED
 * throw (with a manual-`rm` recovery hint) on sustained contention. It is NOT
 * reentrant within a single process; callers must already serialize their own
 * concurrent calls (the federation store does so with its in-process write chain)
 * so a process never blocks on a lock it itself holds.
 *
 * ── NO AUTO-STALE-BREAK (the #871 lock lesson) ──────────────────────────────
 * An earlier version auto-broke a "provably stale" lock (dead holder PID / a lock
 * acquired before the current boot) by reading the lockfile and then `rm`-ing it.
 * That read-then-unlink is a check-then-act TOCTOU (CodeQL `js/file-system-race`):
 * two contenders can BOTH read the same stale lock, BOTH decide to break it, and
 * the second `rm` can delete a DIFFERENT, freshly-acquired LIVE lock a winner
 * created in between - after which two writers enter the critical section and
 * interleave (a double-acquire). There is no POSIX primitive to make the unlink
 * conditional on the inode still being the exact stale one, so the race cannot be
 * closed while keeping the auto-break. Per the #871 resolution
 * (`anti-rollback-durability-and-lock-simplify`), the convergent CORRECT fix for a
 * millisecond-duration single-operator write path is to DELETE the auto-break and
 * FAIL CLOSED: a crashed holder wedging the path until a one-time manual `rm` is a
 * fail-SAFE tradeoff, strictly better than a fail-OPEN double-acquire on
 * security-critical state (revocation-list push, federation sync-state). The
 * thrown error names the exact lockfile so an operator can clear a genuinely-dead
 * holder with a single `rm`.
 *
 * Non-filesystem backends (single-process in-memory rigs and tests) have no
 * cross-process surface, so the lock degrades to running the operation directly.
 * Such rigs rely on the caller's monotonic merge for correctness, which is itself
 * sufficient when there is only one process.
 */

import { open, rm } from "node:fs/promises";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import type { StorageBackend } from "./interface.js";
import type { FilesystemStorageCapabilities } from "./interface.js";

/** Default bounded wait before a contended acquire fails closed. */
export const CROSS_PROCESS_LOCK_TIMEOUT_MS = 5_000;
/** Poll interval while waiting on a held lock. */
export const CROSS_PROCESS_LOCK_RETRY_MS = 100;

export class CrossProcessLockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CrossProcessLockError";
  }
}

export interface CrossProcessLockOptions {
  /** Bounded wait before failing closed (default {@link CROSS_PROCESS_LOCK_TIMEOUT_MS}). */
  timeoutMs?: number;
  /** Poll interval while a lock is held (default {@link CROSS_PROCESS_LOCK_RETRY_MS}). */
  retryMs?: number;
  /**
   * HIGH-B (Codex gate, 2026-08-22): merged into the lockfile's own JSON
   * alongside `pid`/`acquired_at`, purely for a human reading the file
   * during the manual-recovery path this module's header describes (there
   * is no auto-stale-break) - never read back or interpreted by this
   * module itself.
   */
  metadata?: Record<string, unknown>;
  /**
   * Observability seam: invoked each time an acquire OBSERVES the lock already
   * held (an `EEXIST` on the O_EXCL create) and is about to sleep and retry.
   * `attempt` counts observed contentions, starting at 1.
   *
   * This is a pure notification -- it never changes acquire behaviour, and a
   * throw from it is not caught, so implementations must not throw. It exists
   * so a caller can prove contention actually happened rather than infer it
   * from elapsed wall-clock: a mutual-exclusion test that only sleeps and
   * hopes the contender got as far as an acquire attempt passes VACUOUSLY on a
   * loaded machine where it did not. Diagnostic logging is the other intended
   * consumer.
   */
  onContended?: (attempt: number) => void;
}

/**
 * Run `operation` while holding an exclusive cross-process lock for
 * (`namespace`, `lockFileName`). On filesystem backends the lock spans the whole
 * `operation` (typically a read-modify-write); on non-filesystem backends the
 * operation runs directly (single-process; no cross-process surface).
 *
 * THROWS {@link CrossProcessLockError} if the lock cannot be acquired within the
 * bounded timeout (another process is holding it, OR a crashed holder left a stale
 * lockfile). There is NO auto-stale-break (see the module header): a contended
 * acquire fails CLOSED with a manual-`rm` hint rather than risk the read-then-
 * unlink double-acquire race. The lockfile is ALWAYS removed in a `finally` once
 * held, even if `operation` throws, so a thrown operation never leaves a stale
 * lock for this process.
 */
export async function withCrossProcessLock<T>(
  storage: StorageBackend,
  namespace: string,
  lockFileName: string,
  operation: () => Promise<T>,
  options: CrossProcessLockOptions = {},
): Promise<T> {
  const capabilities = asFilesystemCapabilities(storage);
  if (!capabilities) return operation();
  const dir = capabilities.namespacePath(namespace);
  return withPathLock(dir, lockFileName, operation, options);
}

/**
 * HIGH-B (Codex gate, 2026-08-22): the SAME contention error a caller sees
 * from withCrossProcessLock/withPathLock, reworded to name the exit-import
 * writer guard's own remediation instead of a generic manual-`rm` hint -
 * for lock names where the holder set is exactly {import, rotate, resume,
 * recovery} and the fix is the same "run `sanctuary exit recover` (F1,
 * Exit V2 D1 operator finding, 2026-08-23), or inspect before removing"
 * text those callers already use elsewhere. Not a
 * different lock mechanism; a different message on the SAME
 * CrossProcessLockError shape, thrown from the SAME no-auto-break path.
 */
export class ExitAdmissionLockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExitAdmissionLockError";
  }
}

/**
 * Lower-level path-keyed variant of {@link withCrossProcessLock}: serialize
 * `operation` under an O_EXCL lockfile at `<lockDir>/<lockFileName>`, with the
 * SAME discipline as the storage-backed helper -- bounded wait, NO
 * auto-stale-break (fail CLOSED with a manual-`rm` hint on sustained
 * contention), and an always-`rm` `finally` release. Use this directly when
 * the critical section is keyed on a plain filesystem directory rather than a
 * StateStore namespace (for example the file-grant grant-tree root, whose
 * fortress-level ACE lifecycle must serialize a concurrent mint against a
 * concurrent revoke for the SAME agent uid). `lockDir` is created
 * `recursive`/`0700` before the acquire; a caller that needs to DEGRADE when
 * the directory cannot exist (unit rigs, unreal paths) should guard the call
 * and run `operation` directly on failure -- this helper itself always
 * attempts the lock.
 */
export async function withPathLock<T>(
  lockDir: string,
  lockFileName: string,
  operation: () => Promise<T>,
  options: CrossProcessLockOptions = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? CROSS_PROCESS_LOCK_TIMEOUT_MS;
  const retryMs = options.retryMs ?? CROSS_PROCESS_LOCK_RETRY_MS;
  await mkdir(lockDir, { recursive: true, mode: 0o700 });
  const lockPath = join(lockDir, lockFileName);
  const started = Date.now();
  let contentions = 0;

  for (;;) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      // MEDIUM (Codex gate, 2026-08-22 / 2026-08-23): the O_EXCL create
      // SUCCEEDED at this point, so this process (uniquely) owns the lock
      // file - a failure writing/syncing its metadata, OR a failure in
      // handle.close() itself (even after a clean write/sync), is NOT a
      // contention signal (that is the outer catch's EEXIST branch) and
      // must not leave an empty or orphaned lock file wedging every
      // future acquire. Both stages are tried independently (never a bare
      // try/finally around close, which would let a close() throw
      // silently discard an earlier write/sync error) so the unlink runs
      // whichever stage failed, and BOTH errors are preserved in the
      // thrown message when both occur.
      //
      // COOPERATIVE-OWNER ASSUMPTION: the unlink below trusts that nothing
      // else has replaced this exact path between this process's own
      // O_EXCL create and this cleanup - true here because O_EXCL makes
      // this process the unique owner of the path until it unlinks (this
      // module has no auto-stale-break, so no contender can have taken
      // over in between); a lock primitive that DID stale-break would need
      // a liveness re-check here before unlinking.
      let writeSyncErr: unknown;
      try {
        await handle.writeFile(
          JSON.stringify({
            pid: process.pid,
            acquired_at: new Date().toISOString(),
            ...options.metadata,
          }),
        );
        await handle.sync();
      } catch (err) {
        writeSyncErr = err;
      }
      let closeErr: unknown;
      try {
        await handle.close();
      } catch (err) {
        closeErr = err;
      }
      if (writeSyncErr !== undefined || closeErr !== undefined) {
        let unlinkErr: unknown;
        try {
          await rm(lockPath, { force: true });
        } catch (err) {
          unlinkErr = err;
        }
        const causes = [
          writeSyncErr !== undefined
            ? `metadata write/sync: ${errorMessage(writeSyncErr)}`
            : null,
          closeErr !== undefined ? `handle close: ${errorMessage(closeErr)}` : null,
        ].filter((cause): cause is string => cause !== null);
        throw new CrossProcessLockError(
          `cross-process lock (${lockPath}) was created but could not be ` +
            `finalized (${causes.join("; ")}), so the lock file was ` +
            (unlinkErr === undefined
              ? `removed rather than left stuck.`
              : `ALSO left behind - a follow-up removal attempt failed too ` +
                `(${errorMessage(unlinkErr)}); remove it manually: rm '${lockPath}'.`),
        );
      }
      break;
    } catch (err) {
      // The finalize branch above (write/sync/close) already unlinked its
      // own orphan and threw a fully-formed CrossProcessLockError - pass
      // it straight through instead of re-wrapping it a second time.
      if (err instanceof CrossProcessLockError) throw err;
      const code =
        err instanceof Error && "code" in err
          ? String((err as NodeJS.ErrnoException).code)
          : "";
      if (code !== "EEXIST") {
        throw new CrossProcessLockError(
          `cross-process lock could not be acquired (${lockPath}): ${errorMessage(err)}`,
        );
      }
      // Held (by a live process OR a crashed holder). We do NOT auto-break: a
      // read-then-unlink stale-break is a TOCTOU double-acquire (see module
      // header). Wait out the bounded budget, then fail CLOSED with a recovery
      // hint. A genuinely-dead holder is cleared by a one-time operator `rm`.
      contentions += 1;
      options.onContended?.(contentions);
      if (Date.now() - started >= timeoutMs) {
        throw new CrossProcessLockError(
          `cross-process lock ${lockPath} held >${timeoutMs}ms; refusing to proceed ` +
            `concurrently. If no other Sanctuary process is running, a prior holder ` +
            `crashed while holding it; clear it with: rm '${lockPath}'`,
        );
      }
      await sleep(retryMs);
    }
  }

  try {
    return await operation();
  } finally {
    await rm(lockPath, { force: true });
  }
}

function asFilesystemCapabilities(
  storage: StorageBackend,
): FilesystemStorageCapabilities | undefined {
  const candidate = storage as Partial<FilesystemStorageCapabilities>;
  if (
    typeof candidate.namespacePath === "function" &&
    typeof candidate.writeDurable === "function"
  ) {
    return candidate as FilesystemStorageCapabilities;
  }
  return undefined;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
