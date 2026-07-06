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

  const timeoutMs = options.timeoutMs ?? CROSS_PROCESS_LOCK_TIMEOUT_MS;
  const retryMs = options.retryMs ?? CROSS_PROCESS_LOCK_RETRY_MS;
  const dir = capabilities.namespacePath(namespace);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const lockPath = join(dir, lockFileName);
  const started = Date.now();

  for (;;) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      try {
        await handle.writeFile(
          JSON.stringify({
            pid: process.pid,
            acquired_at: new Date().toISOString(),
          }),
        );
        await handle.sync();
      } finally {
        await handle.close();
      }
      break;
    } catch (err) {
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
