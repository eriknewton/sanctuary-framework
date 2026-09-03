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
 * processes on filesystem backends. Ordinary callers use a PLAIN O_EXCL lock.
 * Custody mutation callers use a process-owned Unix-domain listener keyed by the
 * locked directory inode, so the mutator itself owns the kernel capability and
 * cannot outlive a helper that silently released it. It is NOT
 * reentrant within a single process; callers must already serialize their own
 * concurrent calls (the federation store does so with its in-process write chain)
 * so a process never blocks on a lock it itself holds.
 *
 * ── PLAIN O_EXCL LOCKS NEVER AUTO-STALE-BREAK (#871) ────────────────────────
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
 * single-operator O_EXCL write path is to DELETE the auto-break and FAIL CLOSED: a
 * crashed holder wedging the path until a one-time manual `rm` is a fail-SAFE
 * tradeoff, strictly better than a fail-OPEN double-acquire on security-critical
 * state (revocation-list push, federation sync-state). Some callers deliberately
 * hold the lock for minutes; the thrown error therefore forbids removal while a
 * holder may be alive. Kernel-backed custody locks instead use a process-owned
 * Unix socket. A stale socket is revalidated and unlinked only by a short-lived
 * helper while it holds the inert scaffold's OS advisory reaper lock; the parent
 * never performs that unlink.
 *
 * Non-filesystem backends (single-process in-memory rigs and tests) have no
 * cross-process surface, so the lock degrades to running the operation directly.
 * Such rigs rely on the caller's monotonic merge for correctness, which is itself
 * sufficient when there is only one process.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { access, chmod, lstat, open, readdir, rm, statfs } from "node:fs/promises";
import { mkdir } from "node:fs/promises";
import { constants, lstatSync } from "node:fs";
import type { BigIntStats } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import {
  createConnection,
  createServer,
  type Server as NetServer,
} from "node:net";
import { platform } from "node:os";
import { dirname, join } from "node:path";

import type { StorageBackend } from "./interface.js";
import type {
  FilesystemStorageCapabilities,
  NamespaceLockStorageCapabilities,
} from "./interface.js";
import { classifyCustodyLockScaffold } from "./custody-lock-scaffold.js";

/** Default bounded wait before a contended acquire fails closed. */
export const CROSS_PROCESS_LOCK_TIMEOUT_MS = 5_000;
/** Poll interval while waiting on a held lock. */
export const CROSS_PROCESS_LOCK_RETRY_MS = 100;
/** Maximum wait for the process-owned Unix-domain listener to close. */
export const KERNEL_LOCK_RELEASE_TIMEOUT_MS = 2_000;
const KERNEL_SOCKET_PATH_MAX_BYTES = 100;
// Descriptive leaf for the per-uid custody lock ROOT directory. Cross-file
// contract: must match the leaf the resolver composes in
// {@link resolveCustodyLockRoot} and the test corpus in
// test/storage/custody-lock-root-resolver.test.ts.
const CUSTODY_LOCK_ROOT_LEAF = "sanctuary-custody-locks";
// Longest entry composed under the lock root is a reaper scaffold:
// `${digest.slice(0, 40)}.reaper`. The socket entry (`.sock`) is 2 bytes
// shorter, so bounding the reaper bounds every entry. 47 = 40-hex digest slice
// + ".reaper".length (7). Used only to reject a root whose composed entry paths
// would overflow KERNEL_SOCKET_PATH_MAX_BYTES; it is not a wire/at-rest value.
const CUSTODY_LOCK_MAX_ENTRY_BYTES = 40 + ".reaper".length;
const KERNEL_SOCKET_PROBE_TIMEOUT_MS = 500;
const STALE_REAPER_TIMEOUT_MS = 2_000;
// Round-2 (unbounded lock-dir growth): the shared runtime dir accumulates one
// reader socket per live unlock plus a few fixed scaffolds. A real host has a
// handful; anything past this ceiling means crashed-reader leakage or a same-uid
// abuse of the 0700 dir, and scanning it unboundedly amplifies work. Above the
// ceiling the barrier fails CLOSED with a remediation instead of scanning it.
const MAX_BARRIER_READER_SOCKETS = 4_096;
// Reaping a stale socket spawns a serialized helper process, so bound how many
// we launch per drain pass; the rest are handled on the next pass within the
// same overall timeout. This caps the N-reaps-per-pass amplification.
const MAX_STALE_REAPS_PER_PASS = 64;
const SHARED_FILESYSTEM_MAGIC = new Set<bigint>([
  0x00006969n, // NFS
  0xff534d42n, // CIFS/SMB2
  0x0000517bn, // SMB (Darwin/Linux variants)
  0x65735546n, // FUSE: may be remote; locality cannot be proven
]);
// M3: Linux custody-lock locality is an ALLOWLIST (fail closed on an
// unrecognized filesystem), matching the Darwin allowlist above, so an unknown
// network/overlay filesystem can never silently fail OPEN. Values are the
// `statfs(2)` f_type magics from linux/magic.h for on-disk / same-host
// filesystems that support Unix-domain sockets and O_EXCL (both required by the
// kernel lock). An fs missing here is refused with its magic named, not
// silently trusted; add a magic (with a source cite) rather than widening to a
// denylist. Removable FAT/exFAT/NTFS are deliberately NOT here: they lack Unix
// ownership/perms the barrier's 0700 gate needs and cannot hold a socket file,
// so they take the read-only degrade path instead of a false "local" pass.
const LINUX_LOCAL_FILESYSTEM_MAGIC = new Set<bigint>([
  0x0000ef53n, // EXT2/EXT3/EXT4
  0x9123683en, // BTRFS
  0x58465342n, // XFS
  0xf2f52010n, // F2FS
  0x01021994n, // TMPFS
  0x858458f6n, // RAMFS
  0x2fc12fc1n, // ZFS
  0x3153464an, // JFS
  0x52654973n, // REISERFS
  0x00003434n, // NILFS
  0xca451a4en, // BCACHEFS
  0x794c7630n, // OVERLAYFS (container root; same-host union mount)
  0xe0f5e1e2n, // EROFS (read-only on-disk)
  0x73717368n, // SQUASHFS (read-only on-disk)
  0x28cd3d45n, // CRAMFS
]);
const DARWIN_LOCAL_FILESYSTEM_TYPES = new Set([
  "apfs",
  "hfs",
  "devfs",
  "tmpfs",
]);

/**
 * Whether the host platform has the crash-recoverable kernel lock primitive
 * required by custody mutation ceremonies. Keep readiness probes and the
 * actual acquire path on this single platform truth.
 */
export function kernelBackedCrossProcessLockPlatformSupported(
  host: NodeJS.Platform,
): boolean {
  return host === "darwin" || host === "linux";
}

export type CrossProcessLockErrorKind =
  | "capability"
  | "contention"
  | "holder-lost"
  | "poisoned"
  | "io";

export class CrossProcessLockError extends Error {
  readonly kind: CrossProcessLockErrorKind;
  constructor(message: string, kind: CrossProcessLockErrorKind = "io") {
    super(message);
    this.name = "CrossProcessLockError";
    this.kind = kind;
  }
}

export type KernelLockCapability =
  | { readonly available: true; readonly command: string }
  | { readonly available: false; readonly reason: string };

/** Probe the process-owned kernel capability used by the acquire path. */
export async function probeKernelBackedCrossProcessLockCapability(
  host: NodeJS.Platform = platform(),
  _legacyCanExecute?: (command: string) => Promise<void>,
  targetLockDirectory?: string,
): Promise<KernelLockCapability> {
  if (!kernelBackedCrossProcessLockPlatformSupported(host)) {
    return { available: false, reason: `unsupported host platform ${host}` };
  }
  if (typeof process.getuid !== "function") {
    return {
      available: false,
      reason: "the Node runtime does not expose a Unix process owner identity",
    };
  }
  try {
    await access(kernelReaperCommand(host));
    const runtimeDir = await ensureKernelSocketRuntimeDirectory();
    await assertLocalLockFilesystem(runtimeDir, host);
    if (targetLockDirectory !== undefined) {
      await assertLocalLockFilesystemAtExistingAncestor(targetLockDirectory, host);
      await assertExistingTargetLockShape(targetLockDirectory);
    }
    const probePath = join(
      runtimeDir,
      `.probe-${process.pid}-${randomBytes(6).toString("hex")}.sock`,
    );
    if (Buffer.byteLength(probePath) > KERNEL_SOCKET_PATH_MAX_BYTES) {
      throw new Error("custody lock capability probe path is too long");
    }
    const server = createServer((socket) => socket.destroy());
    try {
      await listenOnSocket(server, probePath);
      await chmod(probePath, 0o600);
      const stats = await lstat(probePath, { bigint: true });
      assertOwnedSocket(probePath, stats);
      if (!server.listening) throw new Error("custody lock probe listener stopped");
    } finally {
      await closeServer(server);
    }
    return { available: true, command: "process-owned-unix-domain-socket" };
  } catch (error) {
    return { available: false, reason: errorMessage(error) };
  }
}

/** Legacy test-isolation seam; process-owned locks require no poison map. */
export function resetKernelLockPoisonForTests(): void {
  // Intentionally empty.
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
  /**
   * Use a process-owned Unix-domain listener instead of O_EXCL existence.
   * The mutating process itself owns the listener; process death closes it and
   * leaves only a same-inode-validated stale socket that a later contender may
   * safely remove only after repeated refusal probes serialized by the inert
   * scaffold's OS advisory reaper lock.
   * This is used only by bounded custody mutation ceremonies, where a stale
   * existence lock would prevent the next invocation from reaching its durable
   * recovery journal. Do not hold this across steady-state server lifetime; each
   * caller must release it when its bounded mutation returns.
   */
  kernelBacked?: boolean;
  /**
   * TEST ONLY: observe a deliberately non-owning helper after the mutating
   * process has acquired the lock. Killing this helper proves that helper loss
   * cannot release the process-owned lock. Production callers leave it undefined.
   */
  __testAfterKernelHolderAcquired?: (pid: number) => void;
  /** TEST ONLY: observe Darwin cwd-capability worker PIDs. */
  __testAfterDirectoryCapabilityAcquired?: (
    storageRootPid: number,
    fortressRootPid: number,
    lockedNamespacePid?: number,
  ) => void;
  /** TEST ONLY: shorten the per-operation Darwin capability bound. */
  __testDirectoryCapabilityTimeoutMs?: number;
  /**
   * TEST ONLY: wrap one namespace-capability close so cleanup-failure
   * aggregation can be proven without monkey-patching Node FileHandles.
   */
  __testCloseNamespaceCapability?: (
    kind: "root-worker" | "parent-worker" | "namespace-worker" |
      "root-fd" | "parent-fd" | "namespace-fd",
    close: () => Promise<unknown>,
  ) => Promise<unknown>;
  /**
   * Legacy test seam retained for source compatibility. Process-owned locks do
   * not have a separate holder whose death can be observed.
   */
  __testOnKernelHolderLoss?: (error: CrossProcessLockError) => void;
  /** TEST ONLY: shorten the production release bound. */
  __testReleaseTimeoutMs?: number;
  /** TEST ONLY: observe the serialized stale-socket reaper process. */
  __testAfterStaleReaperStarted?: (pid: number) => void;
  /** TEST ONLY: observe the process-owned socket path after identity capture. */
  __testAfterKernelSocketAcquired?: (path: string) => void;
  /** TEST ONLY: exercise the unsupported-platform pre-mutation fence. */
  __testPlatform?: NodeJS.Platform;
}

/** A live critical-section lease. Kernel-backed callers may observe abort. */
export interface CrossProcessLockLease {
  readonly signal: AbortSignal;
  /**
   * Locked FilesystemStorage root. On Linux this is a directory-descriptor path;
   * on Darwin storage calls route through the sibling cwd-bound capability
   * worker, while this remains the operator-facing path. Direct mutations must
   * use the backend/capability, never trust this pathname on Darwin.
   */
  readonly stableStorageRoot?: string;
  /** Fortress path; descriptor-bound on Linux, paired with the cwd worker on Darwin. */
  readonly stableStorageParent?: string;
  /**
   * Operation-scoped, inode-bound fortress-root mutations for Darwin, where
   * `/dev/fd/<dirfd>/child` is not traversable. The implementation is a
   * bounded child whose cwd pins the acquired directory inode.
   */
  readonly stableFortressCapability?: {
    tightenPermissions(): Promise<void>;
    mkdir(relativePath: string, mode: number): Promise<void>;
    isFreshExceptLockScaffold(lockFileName: string): Promise<boolean>;
    writeRecoveryKey(
      recoveryKey: string,
      fortressId?: string,
    ): Promise<{ written: boolean }>;
    provisionPin(input: {
      masterKey: Uint8Array;
      globalPinnedPublicKeyPath?: string;
    }): Promise<{
      code: number;
      stdout: string;
      stderr: string;
      warnings: string[];
    }>;
  };
  /** Cross-platform, inode-bound files at the fortress root. */
  readonly stableFortressFiles?: {
    read(name: string): Promise<Uint8Array | null>;
    write(name: string, data: Uint8Array, mode?: number): Promise<void>;
    delete(name: string): Promise<boolean>;
    restoreFreshLockScaffold(lockFileName: string): Promise<void>;
    cleanupFreshInitRecoveryResidue(lockFileName: string): Promise<boolean>;
  };
  /** Fail closed if kernel ownership was lost before the next protected step. */
  assertHeld(): void;
}

function stableLease(): CrossProcessLockLease {
  const controller = new AbortController();
  return { signal: controller.signal, assertHeld: () => undefined };
}

/**
 * Long-lived shared side of the master-rotation barrier. A process that has
 * unlocked a filesystem fortress keeps this lease until its final write. The
 * process-owned socket makes crash release automatic; {@link assertHeld}
 * fences every subsequent raw storage mutation on the same backend instance.
 */
export interface MasterWriteBarrierLease {
  readonly signal: AbortSignal;
  readonly filesystemBacked: boolean;
  /** Prove the admission/root identity still protects this unlock snapshot. */
  assertSessionHeld(): void;
  /** Prove the session is also authorized for a master-derived write. */
  assertHeld(): void;
  release(): Promise<void>;
}

export interface MasterWriteBarrierOptions {
  timeoutMs?: number;
  retryMs?: number;
  /** TEST ONLY: observe the shared reader socket after it is fully admitted. */
  __testAfterSharedSocketAcquired?: (path: string) => void;
  /** TEST ONLY: observe the exclusive gate after it is live. */
  __testAfterExclusiveSocketAcquired?: (path: string) => void;
  /** TEST ONLY: pause after the exclusive gate drained every prior reader. */
  __testAfterExclusiveDrain?: () => void | Promise<void>;
  /** TEST ONLY: shorten the release bound. */
  __testReleaseTimeoutMs?: number;
  /** TEST ONLY: exercise platform refusal without mutating the real host. */
  __testPlatform?: NodeJS.Platform;
  /**
   * When the barrier's per-invoker coordinates cannot be resolved for an
   * ENVIRONMENTAL capability reason (a non-owner invoking uid — a root daemon
   * or `sudo` verb on an operator fortress; a non-local/unsupported filesystem;
   * looser-than-0700 perms), degrade instead of throwing so a path that opened
   * before this barrier existed is not bricked:
   *   - "read-only": return a lease whose reads proceed and whose first
   *     master-derived WRITE fails closed with the cause's remediation. Use for
   *     read/export verbs and ordinary boot.
   *   - "inert": return the pre-barrier lease (reads AND writes proceed
   *     unbarriered). Use ONLY for an already-proven unattended write path that
   *     failing closed would regress (the launchd Castle Wall root daemon boot,
   *     which writes its own root-owned audit chain — reboot-survival is N=5
   *     proven and must not regress).
   * Unset (default): rethrow the capability error (fail closed).
   */
  degradeOnEnvironmentalLoss?: "read-only" | "inert";
  /** TEST ONLY: force the owner-identity check without a real uid change. */
  __testGetuid?: () => number | undefined;
}

interface MasterBarrierRegistry {
  readonly leases: Set<MasterWriteBarrierLease>;
}

const masterBarrierRegistry = new WeakMap<StorageBackend, MasterBarrierRegistry>();
const exclusiveMasterBarrierScope = new AsyncLocalStorage<{
  storage: StorageBackend;
  assertHeld(): void;
}>();

/**
 * Raw filesystem writes made after a master session was opened must retain
 * either that session's live shared lease or the rotation engine's exclusive
 * lease. Backends never used for a master session keep their historical raw
 * storage behavior.
 */
export function assertStorageMasterWriteBarrierHeld(storage: StorageBackend): void {
  const exclusive = exclusiveMasterBarrierScope.getStore();
  if (exclusive?.storage === storage) {
    exclusive.assertHeld();
    return;
  }
  const registry = masterBarrierRegistry.get(storage);
  if (registry === undefined) return;
  if (registry.leases.size === 0) {
    throw new CrossProcessLockError(
      "master write session was released; refusing a later raw fortress mutation",
      "holder-lost",
    );
  }
  for (const lease of registry.leases) lease.assertHeld();
}

function registerMasterWriteBarrier(
  storage: StorageBackend,
  lease: MasterWriteBarrierLease,
): void {
  const registry = masterBarrierRegistry.get(storage) ?? { leases: new Set() };
  registry.leases.add(lease);
  masterBarrierRegistry.set(storage, registry);
}

function unregisterMasterWriteBarrier(
  storage: StorageBackend,
  lease: MasterWriteBarrierLease,
): void {
  masterBarrierRegistry.get(storage)?.leases.delete(lease);
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
  operation: (lease: CrossProcessLockLease) => Promise<T>,
  options: CrossProcessLockOptions = {},
): Promise<T> {
  const explicit = asNamespaceLockCapabilities(storage);
  if (explicit) {
    return explicit.withNamespaceLock(namespace, lockFileName, operation, options);
  }
  const capabilities = asFilesystemCapabilities(storage);
  if (!capabilities) return operation(stableLease());
  const dir = capabilities.namespacePath(namespace);
  return withPathLock(dir, lockFileName, operation, options);
}

/** Custody-grade variant: an omitted lock capability is always a hard failure. */
export async function withRequiredCrossProcessLock<T>(
  storage: StorageBackend,
  namespace: string,
  lockFileName: string,
  operation: (lease: CrossProcessLockLease) => Promise<T>,
  options: CrossProcessLockOptions = {},
): Promise<T> {
  const explicit = asNamespaceLockCapabilities(storage);
  if (!explicit) {
    throw new CrossProcessLockError(
      "storage backend does not expose the required namespace-lock capability; " +
        "use a backend or decorator that explicitly implements withNamespaceLock",
      "capability",
    );
  }
  return explicit.withNamespaceLock(namespace, lockFileName, operation, options);
}

/**
 * HIGH-B (Codex gate, 2026-08-22): the SAME contention error a caller sees
 * from withCrossProcessLock/withPathLock, reworded to name the exit-import
 * writer guard's own remediation instead of a generic manual-`rm` hint -
 * for lock names where the holder set is exactly {import, rotate, resume,
 * recovery, memory_migration} and the fix is the same "run `sanctuary exit recover` (F1,
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
  operation: (lease: CrossProcessLockLease) => Promise<T>,
  options: CrossProcessLockOptions = {},
): Promise<T> {
  if (options.kernelBacked === true) {
    return withKernelPathLock(lockDir, lockFileName, operation, options);
  }
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
            `concurrently. Never remove this lock while a holder may still be alive; ` +
            `some ceremonies hold it for minutes. If no other Sanctuary process is ` +
            `running, a prior holder ` +
            `crashed while holding it; clear it with: rm '${lockPath}'`,
        );
      }
      await sleep(retryMs);
    }
  }

  try {
    return await operation(stableLease());
  } finally {
    await rm(lockPath, { force: true });
  }
}

interface KernelDirectoryIdentity {
  dev: string;
  ino: string;
}

interface AcquiredKernelLock {
  server: NetServer;
  socketPath: string;
  socketIdentity: KernelDirectoryIdentity;
  reaperScaffoldPath: string;
  host: NodeJS.Platform;
  testHelper?: ChildProcessWithoutNullStreams;
}

interface MasterBarrierCoordinates {
  readonly host: NodeJS.Platform;
  readonly lockIdentity: string;
  readonly lockDir: string;
  readonly lockDirectoryIdentity: KernelDirectoryIdentity;
  readonly runtimeDir: string;
  readonly runtimeIdentity: KernelDirectoryIdentity;
  readonly exclusiveSocketPath: string;
  readonly exclusiveReaperScaffoldPath: string;
  readonly readerSocketPrefix: string;
  readonly readerReaperScaffoldPath: string;
}

function assertAcquiredKernelLockHeld(acquired: AcquiredKernelLock): void {
  let current;
  try {
    current = lstatSync(acquired.socketPath, { bigint: true });
  } catch {
    current = null;
  }
  if (
    !acquired.server.listening ||
    current === null ||
    String(current.dev) !== acquired.socketIdentity.dev ||
    String(current.ino) !== acquired.socketIdentity.ino
  ) {
    throw new CrossProcessLockError(
      `process-owned custody lock socket identity was lost (${acquired.socketPath})`,
      "holder-lost",
    );
  }
  assertOwnedSocket(acquired.socketPath, current);
}

async function resolveMasterBarrierCoordinates(
  storage: StorageBackend,
  namespace: string,
  barrierName: string,
  host: NodeJS.Platform,
  getuid: () => number | undefined = process.getuid?.bind(process) ??
    (() => undefined),
): Promise<MasterBarrierCoordinates | null> {
  const capabilities = asFilesystemCapabilities(storage);
  if (!capabilities) return null;
  if (!kernelBackedCrossProcessLockPlatformSupported(host)) {
    throw new CrossProcessLockError(
      `master-rotation barrier is unavailable: unsupported host platform ${host}`,
      "capability",
    );
  }
  const lockDir = capabilities.namespacePath(namespace);
  await mkdir(lockDir, { recursive: true, mode: 0o700 });
  await assertLocalLockFilesystem(lockDir, host);
  const handle = await open(lockDir, "r");
  let directoryIdentity: KernelDirectoryIdentity;
  try {
    const stats = await handle.stat({ bigint: true });
    const uid = getuid();
    // The rotation barrier is a per-invoker uid-owned lock directory. A uid
    // mismatch (a root daemon or `sudo` verb against an operator-owned
    // fortress) or looser-than-0700 perms means we cannot provide the
    // write-coordination guarantee here. Each throws a remediation-bearing
    // `capability` error so `acquireMasterWriteBarrier` can degrade a READ
    // path (and only a read path) instead of surfacing an opaque failure.
    if (uid === undefined) {
      throw new CrossProcessLockError(
        `master-rotation barrier is unavailable: this runtime does not expose a ` +
          `Unix process owner identity (${lockDir})`,
        "capability",
      );
    }
    if (Number(stats.uid) !== uid) {
      throw new CrossProcessLockError(
        `master-rotation barrier directory ${lockDir} is owned by uid ${Number(stats.uid)}, ` +
          `not the invoking uid ${uid}. This happens when a root daemon or a ` +
          `\`sudo\` verb opens an operator-owned fortress. Run the fortress verb as ` +
          `its owner, or (for the launchd Castle Wall daemon) let it degrade to a ` +
          `read-only lease; a master-derived WRITE stays refused.`,
        "capability",
      );
    }
    if ((Number(stats.mode) & 0o077) !== 0) {
      throw new CrossProcessLockError(
        `master-rotation barrier directory ${lockDir} must be mode 0700 (group/other ` +
          `bits set). Tighten it with \`chmod 700\` on the fortress \`state/_meta\` path, ` +
          `then retry.`,
        "capability",
      );
    }
    directoryIdentity = { dev: String(stats.dev), ino: String(stats.ino) };
  } finally {
    await handle.close();
  }
  const runtimeDir = await ensureKernelSocketRuntimeDirectory();
  await assertLocalLockFilesystem(runtimeDir, host);
  const runtimeStats = await lstat(runtimeDir, { bigint: true });
  const runtimeIdentity = {
    dev: String(runtimeStats.dev),
    ino: String(runtimeStats.ino),
  };
  const lockIdentity = `${directoryIdentity.dev}:${directoryIdentity.ino}:${barrierName}`;
  const digest = createHash("sha256").update(lockIdentity).digest("hex");
  const exclusiveSocketPath = join(runtimeDir, `${digest.slice(0, 40)}.sock`);
  const exclusiveReaperScaffoldName = `${digest.slice(0, 40)}.reaper`;
  const readerReaperScaffoldName = `${digest.slice(0, 40)}.reader-reaper`;
  await ensureInertLockScaffold(runtimeDir, exclusiveReaperScaffoldName);
  await ensureInertLockScaffold(runtimeDir, readerReaperScaffoldName);
  return {
    host,
    lockIdentity,
    lockDir,
    lockDirectoryIdentity: directoryIdentity,
    runtimeDir,
    runtimeIdentity,
    exclusiveSocketPath,
    exclusiveReaperScaffoldPath: join(runtimeDir, exclusiveReaperScaffoldName),
    readerSocketPrefix: `${digest.slice(0, 24)}.reader-`,
    readerReaperScaffoldPath: join(runtimeDir, readerReaperScaffoldName),
  };
}

function assertMasterBarrierCoordinatesHeld(
  coordinates: MasterBarrierCoordinates,
): void {
  let lockDirectory: BigIntStats;
  let runtimeDirectory: BigIntStats;
  try {
    lockDirectory = lstatSync(coordinates.lockDir, { bigint: true });
    runtimeDirectory = lstatSync(coordinates.runtimeDir, { bigint: true });
  } catch {
    throw new CrossProcessLockError(
      "master-rotation barrier directory identity was lost",
      "holder-lost",
    );
  }
  if (
    String(lockDirectory.dev) !== coordinates.lockDirectoryIdentity.dev
    || String(lockDirectory.ino) !== coordinates.lockDirectoryIdentity.ino
    || String(runtimeDirectory.dev) !== coordinates.runtimeIdentity.dev
    || String(runtimeDirectory.ino) !== coordinates.runtimeIdentity.ino
  ) {
    throw new CrossProcessLockError(
      "master-rotation barrier directory identity changed while held",
      "holder-lost",
    );
  }
}

async function exclusiveMasterBarrierIsAbsent(
  coordinates: MasterBarrierCoordinates,
): Promise<boolean> {
  let observed = await lstat(coordinates.exclusiveSocketPath, { bigint: true })
    .catch((error) => {
      if (errorCode(error) === "ENOENT") return null;
      throw error;
    });
  if (observed === null) return true;
  observed = await settleOwnedSocketPermissions(
    coordinates.exclusiveSocketPath,
    observed,
  );
  if (observed === null) return true;
  const probe = await probeSocketOwner(coordinates.exclusiveSocketPath);
  if (probe === "live") return false;
  if (probe === "unknown") {
    throw new CrossProcessLockError(
      `master-rotation barrier liveness is indeterminate (${coordinates.exclusiveSocketPath})`,
      "io",
    );
  }
  const outcome = await reapStaleSocketWithSerializedAuthority(
    coordinates.exclusiveSocketPath,
    { dev: String(observed.dev), ino: String(observed.ino) },
    coordinates.exclusiveReaperScaffoldPath,
    coordinates.host,
  );
  return outcome === "reaped";
}

function inertMasterWriteBarrierLease(): MasterWriteBarrierLease {
  const controller = new AbortController();
  let released = false;
  return {
    signal: controller.signal,
    filesystemBacked: false,
    assertSessionHeld: () => {
      if (released) {
        throw new CrossProcessLockError(
          "master write session was already released",
          "holder-lost",
        );
      }
    },
    assertHeld: () => {
      if (released) {
        throw new CrossProcessLockError(
          "master write session was already released",
          "holder-lost",
        );
      }
    },
    release: async () => {
      if (released) return;
      released = true;
      controller.abort();
    },
  };
}

function readOnlyUnsupportedMasterBarrierLease(
  storage: StorageBackend,
  host: NodeJS.Platform,
  writeRefusalMessage?: string,
): MasterWriteBarrierLease {
  const controller = new AbortController();
  let released = false;
  // Default message covers the platform-unsupported (Windows) case; the
  // environmental-degrade path (S5/S5b: non-owner uid, non-local fs, looser
  // perms) supplies a cause-specific remediation so the write refusal names
  // exactly why the barrier could not be taken.
  const refusal =
    writeRefusalMessage ??
    `master-derived filesystem mutation is unavailable on ${host}: ` +
      "no reviewed crash-recoverable rotation barrier exists on this platform";
  const lease: MasterWriteBarrierLease = {
    signal: controller.signal,
    filesystemBacked: true,
    assertSessionHeld: () => {
      if (released) {
        throw new CrossProcessLockError(
          "master read session was already released",
          "holder-lost",
        );
      }
    },
    // A read/export unlock only ever calls assertSessionHeld, so it proceeds;
    // the FIRST master-derived raw write reaches assertHeld and fails closed.
    // This is the invariant that keeps the degraded lease read-only: reads
    // open, writes refuse (AGENTS MUST-NEVER 5, never silently degrade).
    assertHeld: () => {
      lease.assertSessionHeld();
      throw new CrossProcessLockError(refusal, "capability");
    },
    release: async () => {
      if (released) return;
      released = true;
      controller.abort();
      unregisterMasterWriteBarrier(storage, lease);
    },
  };
  return lease;
}

/**
 * Acquire a process-owned shared reader before a filesystem master is
 * unlocked. The absent-gate -> bind-reader -> absent-gate handshake closes the
 * admission race with an exclusive rotator: once the exclusive gate binds,
 * every later reader backs out before receiving key material, while the
 * rotator drains every reader that was admitted earlier.
 */
export async function acquireMasterWriteBarrier(
  storage: StorageBackend,
  namespace: string,
  barrierName: string,
  options: MasterWriteBarrierOptions = {},
): Promise<MasterWriteBarrierLease> {
  const host = options.__testPlatform ?? platform();
  const filesystem = asFilesystemCapabilities(storage);
  if (filesystem && !kernelBackedCrossProcessLockPlatformSupported(host)) {
    // Preserve authenticated read/export on platforms without custody
    // mutation support (notably Windows), while making every subsequent raw
    // write on this backend fail closed. Rotation itself remains unavailable.
    const readOnly = readOnlyUnsupportedMasterBarrierLease(storage, host);
    registerMasterWriteBarrier(storage, readOnly);
    return readOnly;
  }
  let coordinates: MasterBarrierCoordinates | null;
  try {
    coordinates = await resolveMasterBarrierCoordinates(
      storage,
      namespace,
      barrierName,
      host,
      options.__testGetuid,
    );
  } catch (error) {
    // Environmental capability loss (non-owner uid / non-local fs / looser
    // perms): degrade per the caller's declared intent rather than bricking a
    // path that opened before the barrier existed (S5/S5b). Any other error
    // (contention, holder-lost, io, a non-capability capability) still throws.
    if (
      error instanceof CrossProcessLockError &&
      error.kind === "capability" &&
      options.degradeOnEnvironmentalLoss !== undefined
    ) {
      if (options.degradeOnEnvironmentalLoss === "inert") {
        // Pre-barrier behavior: unregistered, so assertStorageMasterWriteBarrierHeld
        // finds no registry entry and permits raw writes exactly as before.
        return inertMasterWriteBarrierLease();
      }
      const readOnly = readOnlyUnsupportedMasterBarrierLease(
        storage,
        host,
        error.message,
      );
      registerMasterWriteBarrier(storage, readOnly);
      return readOnly;
    }
    throw error;
  }
  if (coordinates === null) return inertMasterWriteBarrierLease();
  const timeoutMs = options.timeoutMs ?? CROSS_PROCESS_LOCK_TIMEOUT_MS;
  const retryMs = options.retryMs ?? CROSS_PROCESS_LOCK_RETRY_MS;
  const started = Date.now();
  for (;;) {
    if (!(await exclusiveMasterBarrierIsAbsent(coordinates))) {
      if (Date.now() - started >= timeoutMs) {
        throw new CrossProcessLockError(
          `master rotation barrier remained exclusive for ${timeoutMs}ms`,
          "contention",
        );
      }
      await sleep(retryMs);
      continue;
    }
    const readerSocketPath = join(
      coordinates.runtimeDir,
      `${coordinates.readerSocketPrefix}${randomBytes(12).toString("hex")}.sock`,
    );
    if (Buffer.byteLength(readerSocketPath) > KERNEL_SOCKET_PATH_MAX_BYTES) {
      throw new CrossProcessLockError(
        `master write barrier socket path exceeds ${KERNEL_SOCKET_PATH_MAX_BYTES} bytes`,
        "capability",
      );
    }
    const server = createServer((socket) => socket.destroy());
    let acquired: AcquiredKernelLock | undefined;
    try {
      await listenOnSocket(server, readerSocketPath);
      await chmod(readerSocketPath, 0o600);
      const currentRuntime = await lstat(coordinates.runtimeDir, { bigint: true });
      if (
        String(currentRuntime.dev) !== coordinates.runtimeIdentity.dev ||
        String(currentRuntime.ino) !== coordinates.runtimeIdentity.ino
      ) {
        throw new CrossProcessLockError(
          "master write barrier runtime directory changed during admission",
          "holder-lost",
        );
      }
      const stats = await lstat(readerSocketPath, { bigint: true });
      assertOwnedSocket(readerSocketPath, stats);
      acquired = {
        server,
        socketPath: readerSocketPath,
        socketIdentity: { dev: String(stats.dev), ino: String(stats.ino) },
        reaperScaffoldPath: coordinates.readerReaperScaffoldPath,
        host,
      };
      if (!(await exclusiveMasterBarrierIsAbsent(coordinates))) {
        await releaseKernelLock(acquired, options.__testReleaseTimeoutMs);
        acquired = undefined;
        if (Date.now() - started >= timeoutMs) {
          throw new CrossProcessLockError(
            `master rotation barrier remained exclusive for ${timeoutMs}ms`,
            "contention",
          );
        }
        await sleep(retryMs);
        continue;
      }
      server.unref();
      const controller = new AbortController();
      let released = false;
      const held = acquired;
      const lease: MasterWriteBarrierLease = {
        signal: controller.signal,
        filesystemBacked: true,
        assertSessionHeld: () => {
          if (released) {
            throw new CrossProcessLockError(
              "master write barrier was released before the final write",
              "holder-lost",
            );
          }
          assertAcquiredKernelLockHeld(held);
          assertMasterBarrierCoordinatesHeld(coordinates);
        },
        assertHeld: () => {
          lease.assertSessionHeld();
        },
        release: async () => {
          if (released) return;
          released = true;
          controller.abort();
          unregisterMasterWriteBarrier(storage, lease);
          await releaseKernelLock(held, options.__testReleaseTimeoutMs);
        },
      };
      options.__testAfterSharedSocketAcquired?.(readerSocketPath);
      registerMasterWriteBarrier(storage, lease);
      // Round-2 (unbounded lock-dir growth): rotations are rare, so crashed
      // readers would otherwise leave sockets in the shared runtime dir forever.
      // Amortize cleanup on the acquire path: a bounded, best-effort reap of dead
      // reader sockets, triggered only once accumulation is visible. Never fails
      // the acquisition and never touches our own just-admitted socket.
      await evictStaleBarrierReaders(coordinates, readerSocketPath).catch(
        () => undefined,
      );
      return lease;
    } catch (error) {
      if (acquired !== undefined) {
        await releaseKernelLock(acquired, options.__testReleaseTimeoutMs)
          .catch(() => undefined);
      } else {
        await closeServer(server).catch(() => undefined);
      }
      throw error;
    }
  }
}

async function waitForMasterBarrierReaders(
  coordinates: MasterBarrierCoordinates,
  timeoutMs: number,
  retryMs: number,
): Promise<void> {
  const started = Date.now();
  for (;;) {
    let liveReaders = 0;
    let reapsThisPass = 0;
    let deferredStale = false;
    const names = await readdir(coordinates.runtimeDir);
    const readerNames = names.filter(
      (name) =>
        name.startsWith(coordinates.readerSocketPrefix) && name.endsWith(".sock"),
    );
    if (readerNames.length > MAX_BARRIER_READER_SOCKETS) {
      // Pathological runtime dir (crashed-reader leakage or same-uid abuse):
      // refuse rather than scan/reap it unboundedly (round-2 per-pass bound).
      throw new CrossProcessLockError(
        `master write barrier runtime dir holds ${readerNames.length} reader sockets ` +
          `(> ${MAX_BARRIER_READER_SOCKETS}); refusing to scan an unbounded set. No ` +
          `Sanctuary process should leave this many; if none is running, clear stale ` +
          `sockets under ${coordinates.runtimeDir}.`,
        "capability",
      );
    }
    for (const name of readerNames) {
      const path = join(coordinates.runtimeDir, name);
      let stats = await lstat(path, { bigint: true }).catch((error) => {
        if (errorCode(error) === "ENOENT") return null;
        throw error;
      });
      if (stats === null) continue;
      stats = await settleOwnedSocketPermissions(path, stats);
      if (stats === null) continue;
      const probe = await probeSocketOwner(path);
      if (probe === "live") {
        liveReaders += 1;
        continue;
      }
      if (probe === "unknown") {
        throw new CrossProcessLockError(
          `master write barrier reader liveness is indeterminate (${path})`,
          "io",
        );
      }
      // Stale: reap it, but bound the number of serialized reaper spawns per
      // pass. Any remainder is left for the next pass (same overall timeout),
      // so a large stale backlog cannot amplify into an unbounded spawn burst.
      if (reapsThisPass >= MAX_STALE_REAPS_PER_PASS) {
        deferredStale = true;
        continue;
      }
      reapsThisPass += 1;
      await reapStaleSocketWithSerializedAuthority(
        path,
        { dev: String(stats.dev), ino: String(stats.ino) },
        coordinates.readerReaperScaffoldPath,
        coordinates.host,
      );
    }
    // Only conclude "drained" when no live readers remain AND no stale sockets
    // were deferred past the per-pass cap (those must still be reaped).
    if (liveReaders === 0 && !deferredStale) return;
    if (Date.now() - started >= timeoutMs) {
      throw new CrossProcessLockError(
        `master rotation waited ${timeoutMs}ms for ${liveReaders} active writer session(s) to close` +
          (deferredStale ? " (plus a stale-reader backlog still draining under the per-pass cap)" : ""),
        "contention",
      );
    }
    await sleep(retryMs);
  }
}

// Trigger the amortized eviction sweep only once more than this many reader
// sockets are present, so an idle single-reader host pays nothing.
const BARRIER_READER_EVICTION_THRESHOLD = 16;
// Bound the serialized reaper spawns per eviction sweep (defense-in-depth with
// the rotator's MAX_STALE_REAPS_PER_PASS); the rest wait for a later sweep.
const MAX_EVICTIONS_PER_SWEEP = 8;

/**
 * Best-effort, bounded reap of DEAD reader sockets left in the shared runtime
 * directory by crashed unlocks, run OUTSIDE a rotation (round-2). It reaps only
 * sockets that probe as not-live and are stale, using the same serialized
 * reaper authority as the rotator, so it is safe to run concurrently with one.
 * It never touches `selfSocketPath` (the caller's just-admitted live socket) and
 * every failure is swallowed by the caller — cleanup must never fail an unlock.
 */
async function evictStaleBarrierReaders(
  coordinates: MasterBarrierCoordinates,
  selfSocketPath: string,
): Promise<void> {
  const names = await readdir(coordinates.runtimeDir);
  const readerNames = names.filter(
    (name) =>
      name.startsWith(coordinates.readerSocketPrefix) && name.endsWith(".sock"),
  );
  if (readerNames.length <= BARRIER_READER_EVICTION_THRESHOLD) return;
  let evictions = 0;
  for (const name of readerNames) {
    if (evictions >= MAX_EVICTIONS_PER_SWEEP) return;
    const path = join(coordinates.runtimeDir, name);
    if (path === selfSocketPath) continue;
    let stats = await lstat(path, { bigint: true }).catch(() => null);
    if (stats === null) continue;
    stats = await settleOwnedSocketPermissions(path, stats);
    if (stats === null) continue;
    // Only a positively-stale (dead-owner) socket is reaped; a "live" or
    // "unknown" probe is left untouched so an active reader is never disturbed.
    const probe = await probeSocketOwner(path);
    if (probe !== "stale") continue;
    evictions += 1;
    await reapStaleSocketWithSerializedAuthority(
      path,
      { dev: String(stats.dev), ino: String(stats.ino) },
      coordinates.readerReaperScaffoldPath,
      coordinates.host,
    ).catch(() => undefined);
  }
}

/** Exclusive side of the master-session barrier, held through finalization. */
export async function withExclusiveMasterRotationBarrier<T>(
  storage: StorageBackend,
  namespace: string,
  barrierName: string,
  operation: () => Promise<T>,
  options: MasterWriteBarrierOptions = {},
): Promise<T> {
  const host = options.__testPlatform ?? platform();
  const coordinates = await resolveMasterBarrierCoordinates(
    storage,
    namespace,
    barrierName,
    host,
  );
  if (coordinates === null) {
    return exclusiveMasterBarrierScope.run(
      { storage, assertHeld: () => undefined },
      operation,
    );
  }
  const timeoutMs = options.timeoutMs ?? CROSS_PROCESS_LOCK_TIMEOUT_MS;
  const retryMs = options.retryMs ?? CROSS_PROCESS_LOCK_RETRY_MS;
  const acquired = await acquireKernelLock(coordinates.lockIdentity, timeoutMs, {
    kernelBacked: true,
    ...(options.__testPlatform !== undefined
      ? { __testPlatform: options.__testPlatform }
      : {}),
    ...(options.__testAfterExclusiveSocketAcquired !== undefined
      ? { __testAfterKernelSocketAcquired: options.__testAfterExclusiveSocketAcquired }
      : {}),
  });
  const controller = new AbortController();
  let result!: T;
  let operationError: unknown;
  let releaseError: unknown;
  try {
    await waitForMasterBarrierReaders(coordinates, timeoutMs, retryMs);
    assertAcquiredKernelLockHeld(acquired);
    assertMasterBarrierCoordinatesHeld(coordinates);
    await options.__testAfterExclusiveDrain?.();
    assertAcquiredKernelLockHeld(acquired);
    assertMasterBarrierCoordinatesHeld(coordinates);
    result = await exclusiveMasterBarrierScope.run(
      {
        storage,
        assertHeld: () => {
          assertAcquiredKernelLockHeld(acquired);
          assertMasterBarrierCoordinatesHeld(coordinates);
        },
      },
      operation,
    );
    assertAcquiredKernelLockHeld(acquired);
    assertMasterBarrierCoordinatesHeld(coordinates);
  } catch (error) {
    operationError = error;
  } finally {
    controller.abort();
    try {
      await releaseKernelLock(acquired, options.__testReleaseTimeoutMs);
    } catch (error) {
      releaseError = error;
    }
  }
  if (operationError !== undefined && releaseError !== undefined) {
    throw new AggregateError(
      [operationError, releaseError],
      "master rotation failed and its exclusive barrier did not release cleanly",
      { cause: operationError },
    );
  }
  if (operationError !== undefined) throw operationError;
  if (releaseError !== undefined) throw releaseError;
  return result;
}

/**
 * Kernel-backed custody lock owned by the mutator process itself. A Unix-domain
 * listener is the exclusive kernel capability: a live owner accepts and closes
 * probes, while process death makes a stale socket return ECONNREFUSED. Because
 * the writer and lock owner are one process, no writer can continue after lock
 * release. The persistent zero-byte lock file remains only an inert filesystem
 * scaffold used by freshness and destructive-reset checks.
 */
async function withKernelPathLock<T>(
  lockDir: string,
  lockFileName: string,
  operation: (lease: CrossProcessLockLease) => Promise<T>,
  options: CrossProcessLockOptions,
): Promise<T> {
  const host = options.__testPlatform ?? platform();
  // In particular, a direct call on Windows must fail before mkdir can create
  // a misleading partial custody layout.
  if (!kernelBackedCrossProcessLockPlatformSupported(host)) {
    throw new CrossProcessLockError(
      `kernel-backed cross-process locking is unavailable: unsupported host platform ${host}`,
      "capability",
    );
  }
  const timeoutMs = options.timeoutMs ?? CROSS_PROCESS_LOCK_TIMEOUT_MS;
  await mkdir(lockDir, { recursive: true, mode: 0o700 });
  await assertLocalLockFilesystem(lockDir, host);
  const lockDirHandle = await open(lockDir, "r");
  let expectedIdentity: KernelDirectoryIdentity;
  try {
    const stats = await lockDirHandle.stat({ bigint: true });
    const uid = process.getuid?.();
    if (
      uid === undefined ||
      Number(stats.uid) !== uid ||
      (Number(stats.mode) & 0o077) !== 0
    ) {
      throw new CrossProcessLockError(
        `custody lock directory must be owned by the invoking uid with mode 0700 (${lockDir})`,
        "capability",
      );
    }
    expectedIdentity = { dev: String(stats.dev), ino: String(stats.ino) };
  } finally {
    await lockDirHandle.close();
  }
  await ensureInertLockScaffold(lockDir, lockFileName);
  const lockIdentity = `${expectedIdentity.dev}:${expectedIdentity.ino}:${lockFileName}`;
  const acquired = await acquireKernelLock(
    lockIdentity,
    timeoutMs,
    options,
  );
  const controller = new AbortController();
  const lease: CrossProcessLockLease = {
    signal: controller.signal,
    assertHeld: () => {
      let current;
      try {
        current = lstatSync(acquired.socketPath, { bigint: true });
      } catch {
        current = null;
      }
      if (
        !acquired.server.listening ||
        current === null ||
        String(current.dev) !== acquired.socketIdentity.dev ||
        String(current.ino) !== acquired.socketIdentity.ino
      ) {
        throw new CrossProcessLockError(
          `process-owned custody lock socket identity was lost (${acquired.socketPath})`,
          "holder-lost",
        );
      }
      assertOwnedSocket(acquired.socketPath, current);
    },
  };
  let result!: T;
  let operationError: unknown;
  let releaseError: unknown;
  try {
    result = await operation(lease);
    lease.assertHeld();
  } catch (error) {
    operationError = error;
  } finally {
    controller.abort();
    try {
      await releaseKernelLock(acquired, options.__testReleaseTimeoutMs);
    } catch (error) {
      releaseError = error;
    }
  }
  if (operationError !== undefined && releaseError !== undefined) {
    throw new AggregateError(
      [operationError, releaseError],
      "custody operation failed and the process-owned lock did not release cleanly",
      { cause: operationError },
    );
  }
  if (operationError !== undefined) throw operationError;
  if (releaseError !== undefined) throw releaseError;
  return result;
}

/**
 * Keep the historical zero-byte lock path as an inert, durable scaffold. It is
 * never the ownership primitive, is never truncated, and is rejected if another
 * object has been substituted at the expected path.
 */
async function ensureInertLockScaffold(
  lockDir: string,
  lockFileName: string,
): Promise<void> {
  const lockPath = join(lockDir, lockFileName);
  const uid = process.getuid?.();
  if (uid === undefined) {
    throw new CrossProcessLockError(
      `custody lock scaffold owner cannot be established (${lockPath})`,
      "capability",
    );
  }
  let created = false;
  try {
    const handle = await open(lockPath, "wx", 0o600);
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    created = true;
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error;
  }

  const handle = await open(
    lockPath,
    constants.O_RDWR | (constants.O_NOFOLLOW ?? 0),
  );
  let repaired = false;
  try {
    const held = await handle.stat();
    const shape = classifyCustodyLockScaffold(held, uid);
    if (shape === "unsafe") {
      throw new CrossProcessLockError(
        `custody lock scaffold must be a uid-owned, single-link, zero-byte regular file with mode 0600; ` +
          `only an exact legacy 0644 scaffold can be repaired automatically (${lockPath})`,
        "capability",
      );
    }
    if (shape === "legacy-0644") {
      await handle.chmod(0o600);
      await handle.sync();
      repaired = true;
    }
    const secured = await handle.stat();
    if (classifyCustodyLockScaffold(secured, uid) !== "secure") {
      throw new CrossProcessLockError(
        `custody lock scaffold mode repair did not produce a secure inode (${lockPath})`,
        "capability",
      );
    }
    const named = await lstat(lockPath);
    if (named.dev !== secured.dev || named.ino !== secured.ino) {
      throw new CrossProcessLockError(
        `custody lock scaffold changed during validation (${lockPath})`,
        "capability",
      );
    }
  } finally {
    await handle.close();
  }
  if (created || repaired) {
    const directory = await open(lockDir, "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
}

async function acquireKernelLock(
  lockIdentity: string,
  timeoutMs: number,
  options: CrossProcessLockOptions,
): Promise<AcquiredKernelLock> {
  const host = options.__testPlatform ?? platform();
  const capability = await probeKernelBackedCrossProcessLockCapability(host);
  if (!capability.available) {
    throw new CrossProcessLockError(
      `kernel-backed cross-process locking is unavailable: ${capability.reason}`,
      "capability",
    );
  }
  const runtimeDir = await ensureKernelSocketRuntimeDirectory();
  await assertLocalLockFilesystem(runtimeDir);
  const runtimeIdentity = await lstat(runtimeDir, { bigint: true });
  const digest = createHash("sha256").update(lockIdentity).digest("hex");
  const socketPath = join(runtimeDir, `${digest.slice(0, 40)}.sock`);
  // The custody namespace may be reached through /proc/self/fd in the mutator,
  // but that descriptor is close-on-exec and has no meaning in the reaper child.
  // Keep reaper serialization in the stable uid-owned runtime directory instead,
  // keyed by the canonical lock-directory dev+ino digest used by the socket.
  const reaperScaffoldName = `${digest.slice(0, 40)}.reaper`;
  await ensureInertLockScaffold(runtimeDir, reaperScaffoldName);
  const reaperScaffoldPath = join(runtimeDir, reaperScaffoldName);
  if (Buffer.byteLength(socketPath) > KERNEL_SOCKET_PATH_MAX_BYTES) {
    throw new CrossProcessLockError(
      `kernel custody lock socket path exceeds ${KERNEL_SOCKET_PATH_MAX_BYTES} bytes`,
      "capability",
    );
  }
  const started = Date.now();
  let contentions = 0;
  for (;;) {
    const server = createServer((socket) => socket.destroy());
    try {
      await listenOnSocket(server, socketPath);
      await chmod(socketPath, 0o600);
      const currentRuntime = await lstat(runtimeDir, { bigint: true });
      if (
        currentRuntime.dev !== runtimeIdentity.dev ||
        currentRuntime.ino !== runtimeIdentity.ino
      ) {
        throw new Error("custody lock runtime directory changed during bind");
      }
      const stats = await lstat(socketPath, { bigint: true });
      assertOwnedSocket(socketPath, stats);
      if (!server.listening) {
        throw new Error("listener stopped before custody callback admission");
      }
      options.__testAfterKernelSocketAcquired?.(socketPath);
      let testHelper: ChildProcessWithoutNullStreams | undefined;
      if (options.__testAfterKernelHolderAcquired) {
        testHelper = spawn(process.execPath, ["-e", "process.stdin.resume()"], {
          stdio: ["pipe", "pipe", "pipe"],
        });
        if (testHelper.pid === undefined) {
          await closeServer(server);
          throw new Error("test observer helper has no pid");
        }
        options.__testAfterKernelHolderAcquired(testHelper.pid);
      }
      return {
        server,
        socketPath,
        socketIdentity: { dev: String(stats.dev), ino: String(stats.ino) },
        reaperScaffoldPath,
        host,
        ...(testHelper ? { testHelper } : {}),
      };
    } catch (error) {
      await closeServer(server).catch(() => undefined);
      const code = errorCode(error);
      if (code !== "EADDRINUSE") {
        throw new CrossProcessLockError(
          `kernel custody lock could not bind ${socketPath}: ${errorMessage(error)}`,
          "io",
        );
      }
      let observed = await lstat(socketPath, { bigint: true }).catch((cause) => {
        if (errorCode(cause) === "ENOENT") return null;
        throw cause;
      });
      if (observed === null) continue;
      observed = await settleOwnedSocketPermissions(socketPath, observed);
      if (observed === null) continue;
      const probe = await probeSocketOwner(socketPath);
      if (probe === "stale") {
        const reaperOutcome = await reapStaleSocketWithSerializedAuthority(
          socketPath,
          { dev: String(observed.dev), ino: String(observed.ino) },
          reaperScaffoldPath,
          host,
          options.__testAfterStaleReaperStarted,
        );
        if (reaperOutcome === "reaped") continue;
        // Another contender may own the reaper lock or may already have replaced
        // the stale inode with its live socket. Retry the main acquire within the
        // caller's bound; never turn normal serialized progress into an I/O fault.
        contentions += 1;
        options.onContended?.(contentions);
        if (Date.now() - started >= timeoutMs) {
          throw new CrossProcessLockError(
            `kernel custody lock ${socketPath} remained held for ${timeoutMs}ms`,
            "contention",
          );
        }
        await sleep(options.retryMs ?? CROSS_PROCESS_LOCK_RETRY_MS);
        continue;
      }
      if (probe === "unknown") {
        throw new CrossProcessLockError(
          `kernel custody lock owner liveness is indeterminate (${socketPath}); refusing to unlink`,
          "io",
        );
      }
      contentions += 1;
      options.onContended?.(contentions);
      if (Date.now() - started >= timeoutMs) {
        throw new CrossProcessLockError(
          `kernel custody lock ${socketPath} remained held for ${timeoutMs}ms`,
          "contention",
        );
      }
      await sleep(options.retryMs ?? CROSS_PROCESS_LOCK_RETRY_MS);
    }
  }
}

function kernelReaperCommand(host: NodeJS.Platform): string {
  if (host === "darwin") return "/usr/bin/lockf";
  if (host === "linux") return "/usr/bin/flock";
  throw new CrossProcessLockError(
    `no reviewed stale-socket reaper lock command for ${host}`,
    "capability",
  );
}

function boundedCommandOutput(
  command: string,
  args: string[],
  maxBytes: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      reject(new Error(`filesystem inspection command timed out (${command})`));
    }, 2_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      if (stdout.length > maxBytes) child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
      if (stderr.length > 512) child.kill("SIGKILL");
    });
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0 || stdout.length === 0 || stdout.length > maxBytes) {
        reject(new Error(
          `filesystem inspection command failed (${command})` +
            `${stderr.trim() ? `: ${stderr.trim()}` : ""}`,
        ));
        return;
      }
      resolve(stdout);
    });
  });
}

async function darwinFilesystemType(
  path: string,
): Promise<{ type: string; local: boolean }> {
  // Node's Darwin statfs binding exposes only the numeric `f_type`, whose
  // values are not the Linux magic numbers above and are not stable enough for
  // a cross-platform denylist. Resolve the actual mount, then consume Darwin's
  // f_fstypename-equivalent mount report and MNT_LOCAL flag instead.
  const df = await boundedCommandOutput("/bin/df", ["-P", path], 4_096);
  const line = df.trim().split(/\r?\n/).at(-1);
  const match = line?.match(/^\S+\s+\d+\s+\d+\s+\d+\s+\d+%\s+(.+)$/);
  if (!match) throw new Error(`could not resolve Darwin mount point for ${path}`);
  const mountPoint = match[1]!;
  const mounts = await boundedCommandOutput("/sbin/mount", [], 1_048_576);
  const marker = ` on ${mountPoint} (`;
  const mountLine = mounts.split(/\r?\n/).find((entry) => entry.includes(marker));
  if (!mountLine) throw new Error(`could not inspect Darwin mount for ${path}`);
  const options = mountLine.slice(mountLine.indexOf(marker) + marker.length)
    .replace(/\)$/, "")
    .split(",")
    .map((value) => value.trim().toLowerCase());
  return { type: options[0] ?? "unknown", local: options.includes("local") };
}

async function assertLocalLockFilesystem(
  path: string,
  host: NodeJS.Platform = platform(),
): Promise<void> {
  if (host === "darwin") {
    const filesystem = await darwinFilesystemType(path);
    if (!filesystem.local || !DARWIN_LOCAL_FILESYSTEM_TYPES.has(filesystem.type)) {
      throw new CrossProcessLockError(
        `custody lock requires a reviewed local Darwin filesystem; ` +
          `f_fstypename '${filesystem.type}' (local=${filesystem.local}) is refused (${path})`,
        "capability",
      );
    }
    return;
  }
  const stats = await statfs(path, { bigint: true });
  if (LINUX_LOCAL_FILESYSTEM_MAGIC.has(stats.type)) return;
  // Fail closed on anything not positively identified as a same-host local fs.
  // A known shared magic gets the precise message; an unrecognized one is
  // refused too (M3: no silent fail-open on an unknown network/overlay fs).
  if (SHARED_FILESYSTEM_MAGIC.has(stats.type)) {
    throw new CrossProcessLockError(
      `custody lock requires a local same-host filesystem; shared/network filesystem type 0x${stats.type.toString(16)} is refused (${path})`,
      "capability",
    );
  }
  throw new CrossProcessLockError(
    `custody lock requires a reviewed same-host local filesystem; filesystem magic ` +
      `0x${stats.type.toString(16)} at ${path} is not on the recognized-local allowlist, so its ` +
      `locality cannot be proven and it is refused. If this is a legitimate local disk ` +
      `filesystem, report its magic so it can be added; custody reads still degrade to a ` +
      `read-only lease.`,
    "capability",
  );
}

async function assertLocalLockFilesystemAtExistingAncestor(
  path: string,
  host: NodeJS.Platform = platform(),
): Promise<void> {
  let cursor = path;
  for (;;) {
    try {
      await assertLocalLockFilesystem(cursor, host);
      return;
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw error;
      const parent = dirname(cursor);
      if (parent === cursor) throw error;
      cursor = parent;
    }
  }
}

async function assertExistingTargetLockShape(path: string): Promise<void> {
  let target;
  try {
    target = await lstat(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }
  const uid = process.getuid?.();
  if (
    target.isSymbolicLink() ||
    !target.isDirectory() ||
    uid === undefined ||
    target.uid !== uid
  ) {
    throw new CrossProcessLockError(
      `target custody lock directory is not a uid-owned, non-symlink directory (${path})`,
      "capability",
    );
  }
}

/**
 * Serialize the complete stale-socket proof and unlink under an OS advisory
 * lock on the inert scaffold. The parent never unlinks: helper death releases
 * only reaper authority, while the process-owned listening socket remains the
 * critical-section lock. Reviewed contenders use this same gate, so two stale
 * observers cannot unlink a winner's later socket.
 */
async function reapStaleSocketWithSerializedAuthority(
  socketPath: string,
  expected: KernelDirectoryIdentity,
  scaffoldPath: string,
  host: NodeJS.Platform,
  afterStarted?: (pid: number) => void,
): Promise<"reaped" | "retry"> {
  const script = String.raw`
const fs=require('node:fs'); const net=require('node:net');
const [path,dev,ino]=process.argv.slice(1); let refusals=0;
function same(){try{const s=fs.lstatSync(path,{bigint:true});return s.isSocket()&&String(s.dev)===dev&&String(s.ino)===ino;}catch{return false;}}
function finish(code){process.exitCode=code;}
function probe(){if(!same())return finish(73);const s=net.createConnection(path);let done=false;
 const end=(kind)=>{if(done)return;done=true;clearTimeout(timer);s.destroy();if(kind==='refused'){refusals++;if(refusals<3)return setTimeout(probe,50);if(!same())return finish(73);try{fs.unlinkSync(path);finish(0);}catch{finish(74);}}else finish(75);};
 const timer=setTimeout(()=>end('unknown'),500);s.once('connect',()=>end('live'));s.once('error',e=>end(e&&e.code==='ECONNREFUSED'?'refused':'unknown'));}
probe();`;
  const command = kernelReaperCommand(host);
  const commandArgs = host === "darwin"
    ? ["-t", "0", scaffoldPath, process.execPath, "-e", script, socketPath, expected.dev, expected.ino]
    : ["-n", scaffoldPath, process.execPath, "-e", script, socketPath, expected.dev, expected.ino];
  return await new Promise<"reaped" | "retry">((resolve, reject) => {
    // `detached: true` makes the reaper command its own process-group leader, so
    // the grandchild node reaper script (spawned by lockf/flock) shares that
    // group. On the bounded deadline we kill the whole GROUP, never just the
    // direct child: killing only lockf would ORPHAN the node script, which could
    // then `unlinkSync` the target socket AFTER we gave up and retried — a TOCTOU
    // double/wrong-reap against a possibly-recycled inode (round-2 reaper-orphan).
    const child = spawn(command, commandArgs, {
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    if (child.pid !== undefined) afterStarted?.(child.pid);
    const killReaperGroup = (): void => {
      const pid = child.pid;
      if (pid === undefined) return;
      // Negative pid targets the process group. Fall back to the single child if
      // the group send fails (e.g. the leader already reaped).
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {
          // Already exited; nothing to kill.
        }
      }
    };
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 4096) stderr += String(chunk).slice(0, 4096 - stderr.length);
    });
    const timer = setTimeout(() => {
      killReaperGroup();
      reject(new CrossProcessLockError("stale-socket reaper exceeded its bounded deadline", "io"));
    }, STALE_REAPER_TIMEOUT_MS);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(new CrossProcessLockError(`stale-socket reaper failed to start: ${errorMessage(error)}`, "capability"));
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) resolve("reaped");
      else if (signal !== null) {
        // A dead reaper holds no advisory authority. It may have exited before
        // or after unlinking the exact stale inode, so re-enter the bounded
        // acquire loop and re-observe current state instead of converting an
        // inert helper death into a permanent I/O failure.
        resolve("retry");
      }
      else if (code === 73 || code === 75 || code === 1) resolve("retry");
      else reject(new CrossProcessLockError(
        `stale-socket reaper failed (code=${String(code)} signal=${String(signal)} stderr=${stderr.trim()})`,
        "io",
      ));
    });
  });
}

/** Injected inputs for {@link resolveCustodyLockRoot}; production passes the real environment. */
export interface CustodyLockRootContext {
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
}

/**
 * Mirror of `node:os` `tmpdir()`'s POSIX branch (`TMPDIR||TMP||TEMP||'/tmp'`,
 * one trailing separator stripped unless it is the filesystem root), computed
 * from the INJECTED environment so the resolver stays pure and unit-testable.
 * On macOS `$TMPDIR` is `DARWIN_USER_TEMP_DIR` (`/var/folders/.../T`), a
 * per-user mode-0700 directory that is NOT world-writable.
 */
function darwinUserTempDir(env: NodeJS.ProcessEnv): string {
  const raw = env.TMPDIR || env.TMP || env.TEMP || "/tmp";
  if (raw.length > 1 && raw.endsWith("/")) return raw.slice(0, -1);
  return raw;
}

/**
 * A root is usable only if every entry we compose beneath it
 * (`${root}/${40-hex}${suffix}`, longest suffix `.reaper`) stays within the
 * kernel `sun_path` budget. This is a PURE length computation: `/run/user/<uid>`
 * and `DARWIN_USER_TEMP_DIR` are longer than `/tmp`, so a runtime-dir root can
 * overflow where `/tmp` would not. Must match the socket-path cap enforced at
 * bind time (search KERNEL_SOCKET_PATH_MAX_BYTES).
 */
function custodyLockRootFits(root: string): boolean {
  return (
    Buffer.byteLength(root) + 1 + CUSTODY_LOCK_MAX_ENTRY_BYTES <=
    KERNEL_SOCKET_PATH_MAX_BYTES
  );
}

/**
 * Resolve the custody kernel-lock ROOT directory deterministically from
 * `(uid, env, platform)`.
 *
 * INVARIANT (load-bearing rendezvous): the kernel lock is a cross-process
 * rendezvous keyed on uid; every cooperating same-uid process MUST resolve the
 * SAME root, or two processes hold "exclusive" locks in different directories
 * (a silent custody-safety break). This function therefore reads ONLY `env` and
 * `platform` — never time, randomness, or any filesystem probe (existence,
 * writability, ownership), any of which could differ between two same-uid
 * processes. Selection is by presence + platform + a pure length computation.
 * A non-override candidate that would overflow the socket-path cap falls through
 * to the hardened fallback by that pure length rule (NOT by probing); an
 * explicit operator override that overflows is a HARD ERROR (fail closed),
 * never silently downgraded to a different root — downgrading it would break
 * rendezvous with any peer that honored the override. A chosen root is never
 * silently swapped for another once selected.
 *
 * Precedence (first usable wins):
 *  1. `SANCTUARY_CUSTODY_LOCK_ROOT` override — the installer/systemd unit points
 *     the root daemon at its own runtime path (e.g. `/run/sanctuary/locks`).
 *  2. Linux `$XDG_RUNTIME_DIR` (`/run/user/<uid>`, per-user 0700 tmpfs).
 *  3. macOS `os.tmpdir()` = `DARWIN_USER_TEMP_DIR` (per-user 0700) when it fits;
 *     the `/var/folders/.../T` base is ~48 bytes, so the descriptive leaf can
 *     overflow the cap, and then step 4 is used (a pure, per-uid-identical
 *     length decision, never a probe).
 *  4. Hardened `/tmp/sanctuary-custody-locks-<uid>` fallback (universal), which
 *     keeps every existing hardening applied by the ensure path below.
 *
 * Hardening (mkdir 0700, owner/mode verification, local-filesystem assertion,
 * O_NOFOLLOW, device/inode identity) is applied by callers to WHATEVER root this
 * returns; this function only selects the path.
 */
export function resolveCustodyLockRoot(
  uid: number,
  context: CustodyLockRootContext,
): string {
  const { env, platform: host } = context;
  const fallback = join("/tmp", `${CUSTODY_LOCK_ROOT_LEAF}-${uid}`);

  // 1. Explicit override. Length is fixed by operator/installer intent, so an
  //    overflow is a configuration error we refuse loudly rather than silently
  //    swapping in a different root (which would break rendezvous with peers).
  const override = env.SANCTUARY_CUSTODY_LOCK_ROOT?.trim();
  if (override !== undefined && override.length > 0) {
    if (!custodyLockRootFits(override)) {
      throw new CrossProcessLockError(
        `SANCTUARY_CUSTODY_LOCK_ROOT '${override}' composes a custody lock socket path ` +
          `over the ${KERNEL_SOCKET_PATH_MAX_BYTES}-byte limit`,
        "capability",
      );
    }
    return override;
  }

  // 2. Linux user-session runtime dir. "Usable" is a PURE predicate (set,
  //    non-empty, absolute) — never a stat, so two same-session processes agree.
  if (host === "linux") {
    const xdg = env.XDG_RUNTIME_DIR?.trim();
    if (xdg !== undefined && xdg.length > 0 && xdg.startsWith("/")) {
      const candidate = join(xdg, CUSTODY_LOCK_ROOT_LEAF);
      if (custodyLockRootFits(candidate)) return candidate;
      // Deterministic (length-only) fall-through to the hardened fallback.
    }
  }

  // 3. macOS per-user temp dir. Deterministic length decision only; see note above.
  if (host === "darwin") {
    const candidate = join(
      darwinUserTempDir(env),
      `${CUSTODY_LOCK_ROOT_LEAF}-${uid}`,
    );
    if (custodyLockRootFits(candidate)) return candidate;
  }

  // 4. Hardened universal fallback. Fail closed if even this overflows.
  if (!custodyLockRootFits(fallback)) {
    throw new CrossProcessLockError(
      `custody lock fallback path '${fallback}' exceeds the ` +
        `${KERNEL_SOCKET_PATH_MAX_BYTES}-byte socket-path limit`,
      "capability",
    );
  }
  return fallback;
}

// Exported as a test seam: an injected `context` lets a unit test drive the
// owner/mode hardening below onto a controllable (non-/tmp) branch and prove it
// is carried regardless of which precedence branch selected the root. Production
// callers pass no argument and use the real environment.
export async function ensureKernelSocketRuntimeDirectory(
  context?: CustodyLockRootContext,
): Promise<string> {
  if (typeof process.getuid !== "function") {
    throw new Error("Unix process owner identity is unavailable");
  }
  const uid = process.getuid();
  // Deterministic root selection (env + platform only). Production reads the
  // real environment; tests inject a context to exercise the precedence table.
  const path = resolveCustodyLockRoot(
    uid,
    context ?? { env: process.env, platform: platform() },
  );
  // Hardening carried onto WHATEVER root the resolver chose (not only /tmp):
  // create it 0700, then refuse a pre-existing dir that is a symlink, a
  // non-directory, foreign-owned, or group/other-accessible. An attacker who
  // pre-creates the resolved root with the wrong owner or mode must be detected
  // and refused here, on every precedence branch.
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stats = await lstat(path);
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new Error(`custody lock runtime path is not a non-symlink directory (${path})`);
  }
  if (stats.uid !== uid || (stats.mode & 0o077) !== 0) {
    throw new Error(`custody lock runtime directory must be owned by uid ${uid} with mode 0700 (${path})`);
  }
  return path;
}

function assertOwnedSocket(
  path: string,
  stats: {
    uid: number | bigint;
    mode: number | bigint;
    isSocket(): boolean;
    isSymbolicLink(): boolean;
  },
): void {
  const uid = process.getuid?.();
  if (!stats.isSocket() || stats.isSymbolicLink()) {
    throw new CrossProcessLockError(
      `custody lock runtime entry is not a socket (${path})`,
      "io",
    );
  }
  if (uid === undefined || Number(stats.uid) !== uid) {
    throw new CrossProcessLockError(
      `custody lock socket has a foreign owner (${path})`,
      "io",
    );
  }
  if ((Number(stats.mode) & 0o077) !== 0) {
    throw new CrossProcessLockError(
      `custody lock socket permissions are too broad (${path})`,
      "io",
    );
  }
}

async function settleOwnedSocketPermissions(
  path: string,
  initial: BigIntStats,
): Promise<BigIntStats | null> {
  let current = initial;
  for (let attempt = 0; attempt < 4; attempt++) {
    if ((Number(current.mode) & 0o077) === 0) {
      assertOwnedSocket(path, current);
      return current;
    }
    // The listening process creates the socket inside a pre-verified 0700
    // uid-owned runtime directory and immediately chmods it to 0600. A
    // contender can observe the inode between bind and chmod; treat that mode
    // alone as transient, while still refusing a wrong type/owner immediately.
    if (!current.isSocket() || current.isSymbolicLink() ||
        Number(current.uid) !== process.getuid?.()) {
      assertOwnedSocket(path, current);
    }
    await sleep(10);
    const next = await lstat(path, { bigint: true }).catch((error) => {
      if (errorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (next === null) return null;
    current = next;
  }
  assertOwnedSocket(path, current);
  return current;
}

async function listenOnSocket(server: NetServer, path: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen({ path, exclusive: true }, () => {
      server.off("error", onError);
      resolve();
    });
  });
}

async function probeSocketOwner(
  path: string,
): Promise<"live" | "stale" | "unknown"> {
  return await new Promise((resolve) => {
    let settled = false;
    const socket = createConnection(path);
    const finish = (value: "live" | "stale" | "unknown"): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };
    const timer = setTimeout(() => finish("unknown"), KERNEL_SOCKET_PROBE_TIMEOUT_MS);
    socket.once("connect", () => finish("live"));
    socket.once("error", (error) => {
      const code = errorCode(error);
      finish(code === "ECONNREFUSED" || code === "ENOENT" ? "stale" : "unknown");
    });
  });
}

async function closeServer(
  server: NetServer,
  timeoutMs = KERNEL_LOCK_RELEASE_TIMEOUT_MS,
): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new CrossProcessLockError(
        `process-owned custody lock listener did not close within ${timeoutMs}ms`,
        "holder-lost",
      ));
    }, timeoutMs);
    timeout.unref?.();
    server.close((error) => {
      clearTimeout(timeout);
      if (error) reject(error);
      else resolve();
    });
  });
}

async function releaseKernelLock(
  acquired: AcquiredKernelLock,
  timeoutMs = KERNEL_LOCK_RELEASE_TIMEOUT_MS,
): Promise<void> {
  if (acquired.testHelper) {
    acquired.testHelper.stdin.end();
    acquired.testHelper.kill("SIGTERM");
  }
  const current = await lstat(acquired.socketPath, { bigint: true }).catch((error) => {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (
    current === null ||
    String(current.dev) !== acquired.socketIdentity.dev ||
    String(current.ino) !== acquired.socketIdentity.ino
  ) {
    // Node's public net.Server API always unlinks its pathname on close and has
    // no supported unlinkOnClose=false option on the Node >=22 floor. Closing a
    // displaced listener could therefore delete a successor at the same path.
    // Fail-stop instead: unref the now-unreachable old listener so process exit
    // releases the kernel fd without a normal pathname cleanup, and leave the
    // successor byte-for-byte untouched.
    acquired.server.unref();
    throw new CrossProcessLockError(
      `custody lock socket changed before release (${acquired.socketPath})`,
      "holder-lost",
    );
  }
  assertOwnedSocket(acquired.socketPath, current);
  await closeServer(acquired.server, timeoutMs);

  // Node normally removed the path as part of close. If this runtime leaves the
  // socket inode behind, use the same serialized, repeated-probe, same-inode
  // reaper as crash recovery. A successor has a different inode or answers live
  // and is therefore never unlinked.
  const after = await lstat(acquired.socketPath, { bigint: true }).catch((error) => {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (
    after !== null &&
    String(after.dev) === acquired.socketIdentity.dev &&
    String(after.ino) === acquired.socketIdentity.ino
  ) {
    assertOwnedSocket(acquired.socketPath, after);
    await reapStaleSocketWithSerializedAuthority(
      acquired.socketPath,
      acquired.socketIdentity,
      acquired.reaperScaffoldPath,
      acquired.host,
    );
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

function asNamespaceLockCapabilities(
  storage: StorageBackend,
): NamespaceLockStorageCapabilities | undefined {
  const candidate = storage as Partial<NamespaceLockStorageCapabilities>;
  return typeof candidate.withNamespaceLock === "function"
    ? candidate as NamespaceLockStorageCapabilities
    : undefined;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function errorCode(err: unknown): string | undefined {
  return err instanceof Error && "code" in err
    ? String((err as NodeJS.ErrnoException).code)
    : undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
