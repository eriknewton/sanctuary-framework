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
 * processes on filesystem backends. It mirrors the proven transparency-emit lock
 * discipline: O_EXCL create of a lockfile in the namespace directory, a
 * provably-stale break (dead holder PID or a lock acquired before the current
 * boot), a bounded wait, and a fail-CLOSED throw on sustained contention. It is
 * deadlock-free by construction: every acquire either succeeds, breaks a provably
 * dead holder, or times out and throws. It is NOT reentrant within a single
 * process; callers must already serialize their own concurrent calls (the
 * federation store does so with its in-process write chain) so a process never
 * blocks on a lock it itself holds.
 *
 * Non-filesystem backends (single-process in-memory rigs and tests) have no
 * cross-process surface, so the lock degrades to running the operation directly.
 * Such rigs rely on the caller's monotonic merge for correctness, which is itself
 * sufficient when there is only one process.
 */

import { open, readFile, rm } from "node:fs/promises";
import { mkdir } from "node:fs/promises";
import { uptime as osUptime } from "node:os";
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
 * bounded timeout (a different live process is holding it). The lockfile is
 * ALWAYS removed in a `finally` once held, even if `operation` throws, so a
 * thrown operation never leaves a stale lock for this process.
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
      if (await breakProvablyStaleLock(lockPath)) continue;
      if (Date.now() - started >= timeoutMs) {
        throw new CrossProcessLockError(
          `cross-process lock ${lockPath} held by another live process >${timeoutMs}ms; refusing to proceed concurrently`,
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

/**
 * Break a lock ONLY when staleness is provable: the holder PID is dead, or the
 * lock was acquired before the current boot (so the holder cannot still exist).
 * An unreadable/corrupt lockfile is NEVER broken (cannot prove staleness). A
 * vanished lockfile (holder released it) is treated as breakable so the acquire
 * retries immediately. Returns true when the lock was broken (or already gone).
 */
async function breakProvablyStaleLock(lockPath: string): Promise<boolean> {
  let holderPid: number | undefined;
  let acquiredAtMs: number | undefined;
  try {
    const parsed = JSON.parse(await readFile(lockPath, "utf8")) as {
      pid?: unknown;
      acquired_at?: unknown;
    };
    if (typeof parsed.pid === "number" && Number.isInteger(parsed.pid)) {
      holderPid = parsed.pid;
    }
    if (typeof parsed.acquired_at === "string") {
      const t = Date.parse(parsed.acquired_at);
      if (!Number.isNaN(t)) acquiredAtMs = t;
    }
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? String((err as NodeJS.ErrnoException).code)
        : "";
    // Vanished: the holder released it; retry the acquire immediately.
    if (code === "ENOENT") return true;
    // Unreadable/corrupt: cannot PROVE staleness, so never break it.
    return false;
  }
  if (holderPid === process.pid) return false;
  const bootTimeMs = currentBootTimeMs();
  const predatesBoot =
    acquiredAtMs !== undefined &&
    bootTimeMs !== undefined &&
    acquiredAtMs < bootTimeMs;
  const holderDead = holderPid !== undefined && !isProcessAlive(holderPid);
  if (!predatesBoot && !holderDead) return false;
  await rm(lockPath, { force: true });
  return true;
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

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    // EPERM means the process exists but is owned by another user.
    return code === "EPERM";
  }
}

function currentBootTimeMs(): number | undefined {
  try {
    return Date.now() - osUptime() * 1000;
  } catch {
    return undefined;
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
