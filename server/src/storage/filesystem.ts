/**
 * Sanctuary MCP Server — Filesystem Storage Backend
 *
 * Default storage backend using the local filesystem.
 * Files are stored as: {basePath}/{namespace}/{key}.enc
 *
 * Security invariants:
 * - Data at rest is CIPHERTEXT: state entries are encrypted before they reach
 *   this backend. Secure deletion makes a best-effort attempt to overwrite the
 *   file's bytes with random data (3 passes, each fsync'd) before unlinking, so
 *   any residual on the medium is overwritten random bytes or the prior
 *   ciphertext — never plaintext. In-place overwrite is NOT guaranteed on
 *   copy-on-write (APFS), journaled (ext4), or flash-FTL/SSD storage, where the
 *   filesystem or controller may write the new bytes to fresh blocks and leave
 *   the original blocks intact until reclaimed. This routine therefore does not
 *   promise unrecoverable erasure of the original on-disk bytes; the at-rest
 *   confidentiality guarantee rests on encryption, not on this overwrite.
 * - Directory creation uses restrictive permissions (0o700)
 * - File creation uses restrictive permissions (0o600)
 *
 * Path encoding (byte-addressable domain, full-sweep #41):
 *   Distinct byte-addressable (namespace, key) inputs produce distinct on-disk paths;
 *   otherwise an agent that can choose namespace/key strings within a tenant
 *   could overwrite or read another namespace by colliding on the sanitized
 *   form (multi-tenant isolation invariant). The encoder retains the safe
 *   set [A-Za-z0-9_.-] (so internal namespaces such as `_audit`, `_bridge`,
 *   etc. preserve their on-disk paths verbatim) and `!`-escapes every other
 *   character as the legacy byte escape `!XX`. The escape character
 *   `!` itself is NOT in the safe set, so a literal `!` in input encodes as
 *   `!21`. Names stored by older builds outside the supported range are
 *   refused on write and may not round-trip when enumerated.
 *
 * Legacy fallback (forward compatibility):
 *   Pre-fix code used `replace(/[^a-zA-Z0-9_-]/g, "_")` for namespaces and
 *   `replace(/[^a-zA-Z0-9_.-]/g, "_")` for keys; non-bijective. read(),
 *   exists(), and delete() try the new path first; on ENOENT they fall back
 *   to the legacy path so existing fortresses with operator-supplied
 *   namespaces containing non-safe characters keep working. write() always
 *   uses the new bijective path. list() and totalSize() walk on-disk
 *   directory names directly and cannot disambiguate legacy collision-class
 *   pairs; they are forward-only by design.
 */

import { constants as fsConstants, existsSync, lstatSync } from "node:fs";
import { link, mkdir, open, opendir, unlink, readdir, stat, lstat } from "node:fs/promises";
import { NAMESPACE_DISCOVERY_LIMIT_REMEDIATION, MAX_DISCOVERED_NAMESPACES, MAX_NAMESPACE_DISCOVERY_ENTRIES } from "./interface.js";
import type { Stats } from "node:fs";
import { AsyncLocalStorage } from "node:async_hooks";
import { fork, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { platform } from "node:os";
import { basename, dirname, isAbsolute, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "../core/random.js";
import { constantTimeEqual } from "../core/encoding.js";
import {
  assertSdwRawWriteAuthorized,
  isSdwNamespace,
} from "../sdw/write-gate.js";
import type {
  FilesystemStorageCapabilities,
  NamespaceLockStorageCapabilities,
  StrictDurabilityStorageCapabilities,
  NamespaceLockOptions,
  StorageBackend,
  StorageEntryMeta,
} from "./interface.js";
import { readFileCustody, writeFileCustodyWithDurability, ensureDirectoryStrict, syncDirectoryStrict, syncExistingDirectoryChainStrict } from "./custody-fs.js";
import {
  assertStorageMasterWriteBarrierHeld,
  CrossProcessLockError,
  type CrossProcessLockLease,
  withPathLock,
} from "./cross-process-lock.js";
import { isBenignDirectoryFsyncError } from "./directory-fsync.js";
import {
  assertFilesystemStorageNameAddressable,
  decodeRawFilesystemStorageName,
  encodeFilesystemStorageName,
  FilesystemStorageNameError,
  isFilesystemStorageNameError,
} from "./filesystem-name-codec.js";
import {
  cleanupFreshInitRecoveryResidue,
  restoreFreshFortressLockScaffold,
} from "./fresh-fortress.js";
import {
  InvalidStorageNamespaceError,
  resolveStorageNamespacePath,
  storageNamespacePathComponent,
} from "./namespace-component.js";

// Starting the source worker requires loading tsx; on a saturated host that
// handshake can legitimately exceed two seconds even though the child is
// healthy. Custody mutation still waits fail-closed for a positive ready
// message, but gives process startup a bounded window distinct from the much
// shorter per-operation deadline used after admission.
export const DIRECTORY_CAPABILITY_READY_TIMEOUT_MS = 15_000;

// Legacy whitelist sanitizers, used ONLY for read-fallback against fortresses
// written before full-sweep #41. write() never produces these paths.
function legacyNamespaceSanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}
function legacyKeySanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_.-]/g, "_");
}

function encodedNamespacePath(basePath: string, namespace: string): string {
  return resolveStorageNamespacePath(basePath, namespace);
}

function stableFortressFilePath(root: string, value: string): string {
  if (
    value.length === 0 ||
    isAbsolute(value) ||
    normalize(value) !== value ||
    value.includes(sep) ||
    value === "." ||
    value === ".."
  ) {
    throw new Error("stable fortress file name must be one relative component");
  }
  return join(root, value);
}

async function readStableFortressFile(
  root: string,
  name: string,
): Promise<Buffer | null> {
  try {
    return await readFileCustody(stableFortressFilePath(root, name), {
      mode: { rejectGroupOrOther: true },
      verifyPathIdentity: true,
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

// Must match writeFileStrict in directory-capability-worker.ts so both held-parent paths preserve strict mode.
async function writeStableFortressFile(
  root: string,
  name: string,
  data: Uint8Array,
  mode: number,
  strictDurability: boolean,
): Promise<void> {
  await writeFileCustodyWithDurability(stableFortressFilePath(root, name), data, {
    mode,
    strictDurability,
    createParent: false,
  });
}

async function deleteStableFortressFile(root: string, name: string): Promise<boolean> {
  const path = stableFortressFilePath(root, name);
  try {
    const current = await lstat(path);
    if (current.isSymbolicLink() || !current.isFile()) {
      throw new Error("stable fortress delete refused non-regular file");
    }
    await unlink(path);
    const handle = await open(root, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

export interface CapabilityError {
  message: string;
  code?: string;
  kind?: string;
  rawName?: string;
  rawNamespace?: string;
  errors?: CapabilityError[];
  cause?: CapabilityError;
}

/** Preserve every strict failure across the private worker IPC boundary. */
export function serializeCapabilityError(error: unknown): CapabilityError {
  const value: CapabilityError = { message: error instanceof Error ? error.message : String(error) };
  if (error instanceof Error) {
    for (const key of ["code", "kind", "rawName", "rawNamespace"] as const) {
      const field = (error as unknown as Record<string, unknown>)[key];
      if (typeof field === "string") value[key] = field;
    }
    // Inner errors carry independent barrier failures that must survive worker serialization.
    if (error instanceof AggregateError) value.errors = error.errors.map(serializeCapabilityError);
    if (error.cause !== undefined) value.cause = serializeCapabilityError(error.cause);
  }
  return value;
}

/** Reconstitute worker failures without discarding nested errno evidence. */
export function deserializeCapabilityError(value: CapabilityError): Error {
  const options = value.cause ? { cause: deserializeCapabilityError(value.cause) } : undefined;
  const error = value.errors
    ? new AggregateError(value.errors.map(deserializeCapabilityError), value.message, options)
    : new Error(value.message, options);
  for (const key of ["code", "kind", "rawName", "rawNamespace"] as const) {
    if (value[key] !== undefined) Object.assign(error, { [key]: value[key] });
  }
  return error;
}

interface CapabilityResponse {
  id?: number;
  ready?: boolean;
  ok?: boolean;
  value?: unknown;
  error?: CapabilityError;
}

class DarwinDirectoryCapabilityClient {
  private nextId = 1;
  private chain: Promise<unknown> = Promise.resolve();
  private readonly pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (error: Error) => void }
  >();
  private dead: Error | undefined;

  private constructor(
    private readonly child: ChildProcess,
    private readonly operationTimeoutMs: number,
  ) {
    child.on("message", (raw: CapabilityResponse) => {
      if (raw.ready) return;
      if (raw.id === undefined) return;
      const waiter = this.pending.get(raw.id);
      if (!waiter) return;
      this.pending.delete(raw.id);
      if (raw.ok) {
        waiter.resolve(raw.value);
      } else {
        const error = deserializeCapabilityError(raw.error ?? { message: "directory-capability worker operation failed" });
        waiter.reject(error);
      }
    });
    const fail = (reason: unknown): void => {
      if (this.dead) return;
      this.dead = new CrossProcessLockError(
        `Darwin directory-capability worker was lost: ${reason instanceof Error ? reason.message : String(reason)}`,
        "holder-lost",
      );
      for (const waiter of this.pending.values()) waiter.reject(this.dead);
      this.pending.clear();
    };
    child.once("error", fail);
    child.once("exit", (code, signal) => {
      fail(`exit code=${String(code)} signal=${String(signal)}`);
    });
  }

  static async start(
    cwd: string,
    identity: { dev: string; ino: string },
    owner?: { uid: number; gid: number },
    operationTimeoutMs = 5_000,
    testPreload?: string,
  ): Promise<DarwinDirectoryCapabilityClient> {
    const sourceWorker = fileURLToPath(
      new URL("./directory-capability-worker.ts", import.meta.url),
    );
    const builtWorker = fileURLToPath(
      new URL("./directory-capability-worker.js", import.meta.url),
    );
    const fromSource = existsSync(sourceWorker);
    // The worker's cwd is the directory capability itself, so a bare `tsx`
    // import would resolve from operator-controlled storage instead of this
    // package. Resolve the development loader against this module before the
    // cwd transition; packaged builds execute the compiled worker directly.
    const sourceLoader = fromSource
      ? createRequire(import.meta.url).resolve("tsx")
      : undefined;
    const child = fork(fromSource ? sourceWorker : builtWorker, [
      identity.dev,
      identity.ino,
      owner === undefined ? "" : String(owner.uid),
      owner === undefined ? "" : String(owner.gid),
    ], {
      cwd,
      execArgv: [
        ...(sourceLoader ? ["--import", sourceLoader] : []),
        // A fault preload can rewrite worker barriers, so it arrives only from withFilesystemLockTestHooks, and then only inside the test environment.
        ...(testPreload !== undefined && process.env.VITEST ? ["--import", testPreload] : []),
      ],
      // Never inherit Sanctuary credential variables into the helper. It gets
      // only the one bounded operation payload over the private IPC channel.
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        TMPDIR: process.env.TMPDIR,
        USER: process.env.USER,
        LOGNAME: process.env.LOGNAME,
        SUDO_UID: process.env.SUDO_UID,
        SUDO_GID: process.env.SUDO_GID,
        SUDO_USER: process.env.SUDO_USER,
        LANG: process.env.LANG,
        LC_ALL: process.env.LC_ALL,
      },
      stdio: ["ignore", "ignore", "ignore", "ipc"],
      // Advanced serialization carries custody bytes as bytes. JSON IPC would
      // require a base64 JS string that cannot be explicitly zeroed.
      serialization: "advanced",
    });
    const client = new DarwinDirectoryCapabilityClient(child, operationTimeoutMs);
    try {
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error("directory-capability worker readiness timed out")),
          DIRECTORY_CAPABILITY_READY_TIMEOUT_MS,
        );
        const onMessage = (raw: CapabilityResponse): void => {
          if (!raw.ready) return;
          clearTimeout(timeout);
          child.off("error", onError);
          child.off("message", onMessage);
          resolve();
        };
        const onError = (error: Error): void => {
          clearTimeout(timeout);
          child.off("message", onMessage);
          reject(error);
        };
        child.on("message", onMessage);
        child.once("error", onError);
      });
    } catch (error) {
      child.kill("SIGKILL");
      throw error;
    }
    return client;
  }

  assertAlive(): void {
    if (this.dead) throw this.dead;
    if (this.child.exitCode !== null || this.child.signalCode !== null) {
      throw new CrossProcessLockError(
        "Darwin directory-capability worker exited during custody mutation",
        "holder-lost",
      );
    }
  }

  get pid(): number {
    if (this.child.pid === undefined) {
      throw new CrossProcessLockError(
        "Darwin directory-capability worker has no process id",
        "holder-lost",
      );
    }
    return this.child.pid;
  }

  call<T>(
    op: string,
    args: unknown[] = [],
    options: { boundNamespace?: true } = {},
  ): Promise<T> {
    const run = async (): Promise<T> => {
      this.assertAlive();
      const id = this.nextId++;
      return new Promise<T>((resolve, reject) => {
        const timeout = setTimeout(() => {
          this.pending.delete(id);
          const error = new CrossProcessLockError(
            `Darwin directory-capability operation '${op}' exceeded its ${this.operationTimeoutMs}ms bound`,
            "holder-lost",
          );
          this.child.kill("SIGKILL");
          reject(error);
        }, this.operationTimeoutMs);
        this.pending.set(id, {
          resolve: (value) => {
            clearTimeout(timeout);
            resolve(value as T);
          },
          reject: (error) => {
            clearTimeout(timeout);
            reject(error);
          },
        });
        this.child.send(
          {
            id,
            op,
            args,
            ...(options.boundNamespace ? { boundNamespace: true } : {}),
          },
          (error) => {
            if (!error) return;
            this.pending.delete(id);
            clearTimeout(timeout);
            reject(error);
          },
        );
      });
    };
    const result = this.chain.then(run, run);
    this.chain = result.then(() => undefined, () => undefined);
    return result;
  }

  async close(): Promise<void> {
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        this.child.kill("SIGKILL");
      }, 2_000);
      this.child.once("exit", () => {
        clearTimeout(timeout);
        resolve();
      });
      try {
        this.child.disconnect();
      } catch {
        clearTimeout(timeout);
        resolve();
      }
    });
  }
}

interface BoundStorageContext {
  basePath: string;
  darwinClient?: DarwinDirectoryCapabilityClient;
  lockedNamespace: string;
  namespaceBasePath?: string;
  darwinNamespaceClient?: DarwinDirectoryCapabilityClient;
  strictDurability: boolean;
}

// Must match DARWIN_BOUND_NAMESPACE_TOKEN in directory-capability-worker.ts:
// this is an internal capability token, not a caller-supplied namespace.
const DARWIN_BOUND_NAMESPACE_TOKEN = "\0sanctuary-bound-namespace\0";

/**
 * Instances built by `createDirectoryCapabilityWorkerStorage` alone. Membership
 * replaces a public constructor flag because the exemption skips the strict
 * lock requirement, which only the worker's held cwd may stand in for.
 */
const directoryCapabilityWorkerExecutors = new WeakSet<object>();

/**
 * Marks the one lock entry that `withStrictNamespaceLock` makes. A module-private
 * symbol cannot be supplied by a public caller, so a nested public
 * `withNamespaceLock` never inherits strict mode from an enclosing callback.
 */
const STRICT_NAMESPACE_LOCK: unique symbol = Symbol("sanctuary.strict-namespace-lock");

/**
 * Filesystem lock test hooks. They never travel in public lock options; only
 * `withFilesystemLockTestHooks` sets them, and only test files may import it.
 */
export interface FilesystemLockTestHooks {
  /** Module URL imported into each Darwin directory-capability worker; must match workerFaultPreload in filesystem-strict-durability.test.ts. */
  directoryCapabilityPreload?: string;
  /** Shorter per-operation Darwin capability bound. */
  directoryCapabilityTimeoutMs?: number;
  /** Observe Darwin cwd-capability worker PIDs. */
  afterDirectoryCapabilityAcquired?: (storageRootPid: number, fortressRootPid: number, lockedNamespacePid?: number) => void;
  /** Wrap one namespace-capability close so cleanup-failure aggregation can be proven. */
  closeNamespaceCapability?: (
    kind: "root-worker" | "parent-worker" | "namespace-worker" | "root-fd" | "parent-fd" | "namespace-fd",
    close: () => Promise<unknown>,
  ) => Promise<unknown>;
}

const filesystemLockTestHooks = new AsyncLocalStorage<FilesystemLockTestHooks>();

/**
 * Run `operation` with filesystem lock test hooks in scope. Must match the
 * import-graph pin in filesystem-internal-importers.test.ts: no file under
 * server/src or server/scripts imports this, so production never reaches it.
 */
export function withFilesystemLockTestHooks<T>(hooks: FilesystemLockTestHooks, operation: () => Promise<T>): Promise<T> {
  return filesystemLockTestHooks.run(hooks, operation);
}

/** Every `__test*` key is removed because public lock options never carry test authority. */
function withoutTestKeys<O extends object>(options: O): O {
  const copy = { ...options };
  for (const key of Object.keys(copy)) {
    if (key.startsWith("__test")) delete (copy as Record<string, unknown>)[key];
  }
  return copy;
}

/** Hooks this module reads; stripped on every public entry so only the injection supplies them. */
const FILESYSTEM_LOCK_HOOK_KEYS = [
  "__testDirectoryCapabilityPreload",
  "__testDirectoryCapabilityTimeoutMs",
  "__testAfterDirectoryCapabilityAcquired",
  "__testCloseNamespaceCapability",
] as const;

export class FilesystemStorage implements StorageBackend, FilesystemStorageCapabilities, NamespaceLockStorageCapabilities, StrictDurabilityStorageCapabilities {
  private basePath: string;
  /**
   * Custody mutations run through an inode-bound directory capability captured
   * before the kernel lock is acquired: `/proc/self/fd` on Linux and a bounded
   * child cwd on Darwin (where `/dev/fd/<dirfd>/child` is not traversable).
   * Async-local binding keeps concurrent read-only users of this instance on
   * the ordinary path while the protected callback uses the held inode.
   */
  private readonly strictLockLease = new AsyncLocalStorage<{ active: boolean; strict: boolean; assertHeld(): void }>();
  private readonly boundBasePath = new AsyncLocalStorage<BoundStorageContext>();
  /**
   * Create-with-fchown owner (fortress-ownership spec 2026-07-30): when set,
   * every file this backend creates is chowned to this owner before it
   * becomes visible. The namespace directory must already exist inside the
   * storage root; root recursive mkdir through a mutable path is refused
   * because Node exposes no mkdirat/openat primitive. Fail-closed: a missing
   * parent or chown failure fails the write.
   */
  private owner: { uid: number; gid: number } | undefined;

  constructor(
    basePath: string,
    options: {
      owner?: { uid: number; gid: number };
    } = {}
  ) {
    this.basePath = basePath;
    this.owner = options.owner;
  }

  /** True only for the worker executor; no constructor option can set it. */
  private get allowDirectoryCapabilityRootNamespace(): boolean {
    return directoryCapabilityWorkerExecutors.has(this);
  }

  private activeBasePath(): string {
    return this.boundBasePath.getStore()?.basePath ?? this.basePath;
  }

  private hasStableDirectoryCapability(): boolean {
    return this.boundBasePath.getStore() !== undefined;
  }

  private darwinCapability(namespace?: string): {
    client: DarwinDirectoryCapabilityClient;
    namespace?: string;
    boundNamespace?: true;
  } | undefined {
    const bound = this.boundBasePath.getStore();
    if (!bound) return undefined;
    if (
      namespace !== undefined &&
      namespace === bound.lockedNamespace &&
      bound.darwinNamespaceClient
    ) {
      return {
        client: bound.darwinNamespaceClient,
        boundNamespace: true,
      };
    }
    if (namespace !== undefined) storageNamespacePathComponent(namespace);
    return bound.darwinClient ? { client: bound.darwinClient, namespace } : undefined;
  }

  private callDarwinNamespace<T>(
    capability: {
      client: DarwinDirectoryCapabilityClient;
      namespace?: string;
      boundNamespace?: true;
    },
    op: string,
    args: unknown[] = [],
  ): Promise<T> {
    if (capability.boundNamespace) {
      return capability.client.call<T>(op, args, { boundNamespace: true });
    }
    return capability.client.call<T>(op, [capability.namespace, ...args]);
  }

  private assertCallerNamespace(namespace: string): void {
    // The Darwin worker's bound-namespace token is an internal capability
    // marker; only this worker-mode storage instance may resolve it to cwd.
    if (
      this.allowDirectoryCapabilityRootNamespace &&
      namespace === DARWIN_BOUND_NAMESPACE_TOKEN
    ) {
      return;
    }
    storageNamespacePathComponent(namespace);
  }

  private activeNamespacePath(namespace: string): string {
    // The Darwin worker maps only parent-flagged bound requests to cwd; caller
    // namespaces still pass through the shared component predicate first.
    if (
      this.allowDirectoryCapabilityRootNamespace &&
      namespace === DARWIN_BOUND_NAMESPACE_TOKEN
    ) {
      return this.activeBasePath();
    }
    const bound = this.boundBasePath.getStore();
    if (bound?.lockedNamespace === namespace && bound.namespaceBasePath) {
      this.assertCallerNamespace(namespace);
      return bound.namespaceBasePath;
    }
    return encodedNamespacePath(this.activeBasePath(), namespace);
  }

  private entryPath(namespace: string, key: string): string {
    assertFilesystemStorageNameAddressable(key, "key");
    const safeKey = encodeFilesystemStorageName(key);
    return join(this.activeNamespacePath(namespace), `${safeKey}.enc`);
  }

  namespacePath(namespace: string): string {
    if (isSdwNamespace(namespace)) {
      throw new Error("Filesystem paths for SDW namespaces are not exposed");
    }
    return this.activeNamespacePath(namespace);
  }

  /** Must match the strict namespace contract in interface.ts and worker dispatch. */
  async withStrictNamespaceLock<T>(
    namespace: string,
    lockFileName: string,
    operation: Parameters<typeof withPathLock<T>>[2],
    options: NamespaceLockOptions = {},
  ): Promise<T> {
    // Strict directory authority requires the kernel-backed path and cannot inherit an environmental degradation policy.
    // Test hooks can bypass lock custody, so a strict entry drops every one in every environment.
    const strictOptions = { ...withoutTestKeys(options), kernelBacked: true, degradeOnEnvironmentalLoss: undefined };
    // Must match the STRICT_NAMESPACE_LOCK read in withNamespaceLock; the marker is the only way into strict mode.
    // The marker goes on a fresh copy so the caller's options object is never mutated.
    const marked = { ...strictOptions, [STRICT_NAMESPACE_LOCK]: true as const };
    return this.withNamespaceLock(namespace, lockFileName, operation, marked);
  }

  async withNamespaceLock<T>(
    namespace: string,
    lockFileName: string,
    operation: Parameters<typeof withPathLock<T>>[2],
    requestedOptions: NamespaceLockOptions = {},
  ): Promise<T> {
    const strict = (requestedOptions as { [STRICT_NAMESPACE_LOCK]?: true })[STRICT_NAMESPACE_LOCK] === true;
    const nestedInStrictAuthority = this.strictLockLease.getStore()?.strict === true && this.strictLockLease.getStore()?.active === true;
    let options: Parameters<typeof withPathLock<T>>[3] = { ...requestedOptions };
    if (strict || nestedInStrictAuthority) {
      // Test hooks can bypass lock custody, so neither a strict lock nor a lock nested in strict authority forwards one, in any environment.
      options = withoutTestKeys(options);
    } else {
      // The filesystem hooks come only from withFilesystemLockTestHooks, so a public caller can never set them.
      // Generic withPathLock hooks forwarded by withCrossProcessLock still pass through on this legacy path.
      for (const key of FILESYSTEM_LOCK_HOOK_KEYS) delete (options as Record<string, unknown>)[key];
    }
    const testHooks = filesystemLockTestHooks.getStore();
    if (options.kernelBacked !== true) {
      return withPathLock(this.namespacePath(namespace), lockFileName, operation, options);
    }

    const host = platform();
    if (host !== "linux" && host !== "darwin") {
      // Refuse before mkdir: an unsupported host must not leave a partial
      // state/_meta custody layout that can be mistaken for initialized state.
      return withPathLock(
        this.namespacePath(namespace),
        lockFileName,
        operation,
        options,
      );
    }

    // Establish the directories before taking the capability. From the open(2)
    // below onward, Linux paths are descriptor-relative and Darwin storage I/O
    // is delegated to a child whose cwd is that exact inode. A rename or
    // replacement of the lexical fortress root cannot redirect a mutation.
    const namespaceComponent = storageNamespacePathComponent(namespace);
    let expectedParent: Stats | undefined;
    // A strict lock cannot establish durability for ancestors above its held parent.
    if (strict) {
      expectedParent = await lstat(dirname(this.basePath));
      if (!expectedParent.isDirectory() || expectedParent.isSymbolicLink()) throw new Error("strict root parent must already be a directory");
      try { await mkdir(this.basePath, { mode: 0o700 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    } else await mkdir(this.basePath, { recursive: true, mode: 0o700 });
    const strictDirectoryFlags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_DIRECTORY;
    // Strict capture refuses symlinks before granting held directory authority.
    const rootHandle = await open(this.basePath, strict ? strictDirectoryFlags : "r");
    let parentHandle: Awaited<ReturnType<typeof open>> | undefined;
    let namespaceHandle: Awaited<ReturnType<typeof open>> | undefined;
    let rootClient: DarwinDirectoryCapabilityClient | undefined;
    let parentClient: DarwinDirectoryCapabilityClient | undefined;
    let namespaceClient: DarwinDirectoryCapabilityClient | undefined;
    let operationResult!: T;
    let operationFailure: unknown;
    const cleanupFailures: unknown[] = [];
    try {
      // Root identity is captured before creating children so child setup cannot replace its authority.
      const capturedRoot = await rootHandle.stat();
      parentHandle = await open(dirname(this.basePath), strict ? strictDirectoryFlags : "r");
      const noFollow = typeof fsConstants.O_NOFOLLOW === "number"
        ? fsConstants.O_NOFOLLOW
        : 0;
      const directoryOnly = typeof fsConstants.O_DIRECTORY === "number"
        ? fsConstants.O_DIRECTORY
        : 0;
      await mkdir(encodedNamespacePath(this.basePath, namespace), { recursive: false, mode: 0o700 }).catch(error => {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      });
      namespaceHandle = await open(
        encodedNamespacePath(this.basePath, namespace),
        fsConstants.O_RDONLY | noFollow | directoryOnly,
      );
      // The /proc/self/fd/<digits> pattern must match assertAuditWriterAuthority in operational/audit-log.ts, including descriptorNamespace below.
      const descriptorRoot = host === "linux"
        ? `/proc/self/fd/${rootHandle.fd}`
        : `/dev/fd/${rootHandle.fd}`;
      const descriptorParent = host === "linux"
        ? `/proc/self/fd/${parentHandle.fd}`
        : `/dev/fd/${parentHandle.fd}`;
      const descriptorNamespace = host === "linux"
        ? `/proc/self/fd/${namespaceHandle.fd}`
        : `/dev/fd/${namespaceHandle.fd}`;
      const [heldRoot, heldNamespace, childFromParent, namespaceFromRoot] = await Promise.all([
        Promise.resolve(capturedRoot),
        namespaceHandle.stat(),
        host === "linux"
          ? stat(join(descriptorParent, basename(this.basePath)))
          : lstat(this.basePath),
        host === "linux"
          ? lstat(join(descriptorRoot, namespaceComponent))
          : lstat(encodedNamespacePath(this.basePath, namespace)),
      ]);
      if (
        childFromParent.isSymbolicLink() ||
        heldRoot.dev !== childFromParent.dev ||
        heldRoot.ino !== childFromParent.ino
      ) {
        throw new Error(
          `FilesystemStorage root changed while its stable directory capability was being established (${this.basePath})`,
        );
      }
      if (
        namespaceFromRoot.isSymbolicLink() ||
        !namespaceFromRoot.isDirectory() ||
        !heldNamespace.isDirectory() ||
        heldNamespace.dev !== namespaceFromRoot.dev ||
        heldNamespace.ino !== namespaceFromRoot.ino
      ) {
        throw new Error(
          `FilesystemStorage namespace changed while its stable directory capability was being established (${namespace})`,
        );
      }
      const heldParent = await parentHandle.stat();
      // The parent barrier must retain the identity first verified before root creation.
      if (expectedParent && (expectedParent.dev !== heldParent.dev || expectedParent.ino !== heldParent.ino)) throw new Error("strict root parent identity changed");
      if (host === "darwin") {
        rootClient = await DarwinDirectoryCapabilityClient.start(this.basePath, {
          dev: String(heldRoot.dev),
          ino: String(heldRoot.ino),
        }, this.owner, testHooks?.directoryCapabilityTimeoutMs, testHooks?.directoryCapabilityPreload);
        parentClient = await DarwinDirectoryCapabilityClient.start(
          dirname(this.basePath),
          { dev: String(heldParent.dev), ino: String(heldParent.ino) },
          this.owner,
          testHooks?.directoryCapabilityTimeoutMs,
          testHooks?.directoryCapabilityPreload,
        );
        namespaceClient = await DarwinDirectoryCapabilityClient.start(
          encodedNamespacePath(this.basePath, namespace),
          { dev: String(heldNamespace.dev), ino: String(heldNamespace.ino) },
          this.owner,
          testHooks?.directoryCapabilityTimeoutMs,
          testHooks?.directoryCapabilityPreload,
        );
        testHooks?.afterDirectoryCapabilityAcquired?.(
          rootClient.pid,
          parentClient.pid,
          namespaceClient.pid,
        );
      }
      const assertLexicalIdentity = (): void => {
        let currentRoot: Stats;
        let currentParent: Stats;
        let currentNamespace: Stats;
        try {
          currentRoot = lstatSync(this.basePath);
          currentParent = lstatSync(dirname(this.basePath));
          currentNamespace = lstatSync(encodedNamespacePath(this.basePath, namespace));
        } catch {
          throw new CrossProcessLockError(
            `FilesystemStorage root changed while the custody lock was held (${this.basePath})`,
            "holder-lost",
          );
        }
        if (
          currentRoot.isSymbolicLink() ||
          !currentRoot.isDirectory() ||
          currentRoot.dev !== heldRoot.dev ||
          currentRoot.ino !== heldRoot.ino ||
          currentParent.isSymbolicLink() ||
          !currentParent.isDirectory() ||
          currentParent.dev !== heldParent.dev ||
          currentParent.ino !== heldParent.ino ||
          currentNamespace.isSymbolicLink() ||
          !currentNamespace.isDirectory() ||
          currentNamespace.dev !== heldNamespace.dev ||
          currentNamespace.ino !== heldNamespace.ino
        ) {
          throw new CrossProcessLockError(
            `FilesystemStorage root identity changed while the custody lock was held (${this.basePath})`,
            "holder-lost",
          );
        }
      };
      if (strict) {
        // Parent authority belongs to the verified held handles, never to paths synced before capture.
        assertLexicalIdentity();
        // Namespace contents remain uncertain until this held namespace descriptor completes its barrier.
        await namespaceHandle.sync();
        // The namespace entry is durable only after this held root descriptor completes its barrier.
        await rootHandle.sync();
        // The fortress entry is durable only after this held parent descriptor completes its barrier.
        await parentHandle.sync();
        assertLexicalIdentity();
      }
      // The descriptor-root binding must match assertAuditWriterAuthority in operational/audit-log.ts.
      const boundBasePath = host === "linux" ? descriptorRoot : this.basePath;
      operationResult = await this.boundBasePath.run({
        basePath: boundBasePath,
        strictDurability: strict,
        lockedNamespace: namespace,
        ...(host === "linux" ? { namespaceBasePath: descriptorNamespace } : {}),
        ...(rootClient ? { darwinClient: rootClient } : {}),
        ...(namespaceClient ? { darwinNamespaceClient: namespaceClient } : {}),
      }, () =>
        withPathLock(
          this.namespacePath(namespace),
          lockFileName,
          async (lease) => {
            const authority = { active: true, strict, assertHeld: () => lease.assertHeld() };
            // Internal fences around the callback; the public assertHeld adds the inactive-lease refusal on top.
            const assertBound = (): void => {
              lease.assertHeld();
              rootClient?.assertAlive();
              parentClient?.assertAlive();
              namespaceClient?.assertAlive();
              assertLexicalIdentity();
            };
            // A kept strict lease must not reach a closed and possibly reused descriptor or a stopped worker after its callback settles.
            const leased = <A extends unknown[], R>(method: (...args: A) => Promise<R>): ((...args: A) => Promise<R>) =>
              strict
                ? async (...args: A) => {
                    if (!authority.active) throw new Error("strict lock lease is no longer active");
                    authority.assertHeld();
                    return method(...args);
                  }
                : method;
            const boundLease = {
              ...lease,
            stableStorageRoot: boundBasePath,
            stableStorageParent:
              host === "linux" ? descriptorParent : dirname(this.basePath),
            ...(parentClient
              ? { stableFortressCapability: {
                  tightenPermissions: leased(() => parentClient!.call("tighten")),
                  mkdir: leased((relativePath: string, mode: number) =>
                    parentClient!.call(strict ? "mkdirStrict" : "mkdir", [relativePath, mode])),
                  isFreshExceptLockScaffold: leased((name: string) =>
                    parentClient!.call("isFreshExceptLockScaffold", [name])),
                  writeRecoveryKey: leased((recoveryKey: string, fortressId?: string) =>
                    parentClient!.call(
                      "writeRecoveryKey",
                      fortressId === undefined
                        ? [recoveryKey]
                        : [recoveryKey, fortressId],
                    )),
                  provisionPin: leased(async (input: {
                    masterKey: Uint8Array;
                    globalPinnedPublicKeyPath?: string;
                  }): Promise<{
                    code: number;
                    stdout: string;
                    stderr: string;
                    warnings: string[];
                  }> => {
                    const transfer = Buffer.from(input.masterKey);
                    try {
                      return await parentClient!.call("provisionPin", [{
                        ...input,
                        masterKey: transfer,
                      }]);
                    } finally {
                      transfer.fill(0);
                    }
                  }),
                } }
              : {}),
            stableFortressFiles: parentClient
              ? {
                  read: leased(async (name: string) => {
                    const encoded = await parentClient!.call<string | null>("readFile", [name]);
                    return encoded === null
                      ? null
                      : new Uint8Array(Buffer.from(encoded, "base64"));
                  }),
                  write: leased((name: string, data: Uint8Array, mode = 0o600) =>
                    parentClient!.call(strict ? "writeFileStrict" : "writeFile", [
                      name,
                      Buffer.from(data).toString("base64"),
                      mode,
                    ])),
                  delete: leased((name: string) => parentClient!.call<boolean>("deleteFile", [name])),
                  restoreFreshLockScaffold: leased((name: string) =>
                    parentClient!.call("restoreFreshLockScaffold", [name])),
                  cleanupFreshInitRecoveryResidue: leased((name: string) =>
                    parentClient!.call("cleanupFreshInitRecoveryResidue", [name])),
                }
              : {
                  read: leased(async (name: string) => {
                    const raw = await readStableFortressFile(descriptorParent, name);
                    return raw === null ? null : new Uint8Array(raw);
                  }),
                  write: leased((name: string, data: Uint8Array, mode = 0o600) =>
                    writeStableFortressFile(descriptorParent, name, data, mode, strict)),
                  delete: leased((name: string) =>
                    deleteStableFortressFile(descriptorParent, name)),
                  restoreFreshLockScaffold: leased((name: string) =>
                    restoreFreshFortressLockScaffold(descriptorParent, name)),
                  cleanupFreshInitRecoveryResidue: leased((name: string) =>
                    cleanupFreshInitRecoveryResidue(
                      descriptorParent,
                      name,
                      this.owner?.uid ?? process.getuid!(),
                    )),
                },
              assertHeld: () => {
                // A kept strict lease must not report a held lock after its callback settles.
                if (strict && !authority.active) throw new Error("strict lock lease is no longer active");
                assertBound();
              },
            } satisfies CrossProcessLockLease;
            assertBound();
            let value: T;
            try {
              // Strict mutation authority begins only inside the acquired lock callback and ends when it settles.
              value = await this.strictLockLease.run(authority, () => operation(boundLease));
            } finally { authority.active = false; }
            assertBound();
            return value;
          },
          options,
        ),
      );
    } catch (error) {
      operationFailure = error;
    } finally {
      // Attempt every close in deterministic authority order, retaining every
      // failure. A cleanup exception must never mask the protected operation's
      // error, and one failed close must not skip the remaining capabilities.
      const cleanup = async (
        kind: "root-worker" | "parent-worker" | "namespace-worker" |
          "root-fd" | "parent-fd" | "namespace-fd",
        close: () => Promise<unknown>,
      ): Promise<void> => {
        try {
          if (testHooks?.closeNamespaceCapability) {
            await testHooks.closeNamespaceCapability(kind, close);
          } else {
            await close();
          }
        } catch (error) {
          cleanupFailures.push(error);
        }
      };
      if (rootClient) await cleanup("root-worker", () => rootClient!.close());
      if (parentClient) await cleanup("parent-worker", () => parentClient!.close());
      if (namespaceClient) {
        await cleanup("namespace-worker", () => namespaceClient!.close());
      }
      await cleanup("root-fd", () => rootHandle.close());
      if (parentHandle) await cleanup("parent-fd", () => parentHandle!.close());
      if (namespaceHandle) {
        await cleanup("namespace-fd", () => namespaceHandle!.close());
      }
    }
    const failures = [
      ...(operationFailure === undefined ? [] : [operationFailure]),
      ...cleanupFailures,
    ];
    if (failures.length > 1) {
      throw new AggregateError(
        failures,
        "FilesystemStorage namespace operation and capability cleanup failed",
        { cause: operationFailure ?? cleanupFailures[0] },
      );
    }
    if (failures.length === 1) throw failures[0];
    return operationResult;
  }

  // Legacy on-disk paths produced by the pre-#41 sanitizer. Returned for
  // ENOENT-fallback in read/exists/delete; never written to.
  private legacyEntryPath(namespace: string, key: string): string {
    return join(
      this.activeBasePath(),
      legacyNamespaceSanitize(namespace),
      `${legacyKeySanitize(key)}.enc`
    );
  }

  async write(
    namespace: string,
    key: string,
    data: Uint8Array
  ): Promise<void> {
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const capability = this.darwinCapability(namespace);
    if (capability) {
      await this.callDarwinNamespace(capability, "write", [
        key,
        Buffer.from(checkedData).toString("base64"),
      ]);
      return;
    }
    const filePath = this.entryPath(namespace, key);

    await this.atomicWriteFile(filePath, checkedData, false, false);
  }

  async writeIfAbsent(namespace: string, key: string, data: Uint8Array): Promise<boolean> {
    // Legacy validation order remains stable before the original-buffer authorization.
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    return this.writeIfAbsentMode(namespace, key, checkedData, false);
  }

  private async writeIfAbsentMode(
    namespace: string,
    key: string,
    checkedData: Uint8Array,
    strictDurability: boolean,
  ): Promise<boolean> {
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    // Only the public wrappers supply this already-authorized snapshot, so checking its new identity would reject valid SDW writes.
    const capability = this.darwinCapability(namespace);
    if (capability) {
      return this.callDarwinNamespace(capability, strictDurability ? "writeIfAbsentStrict" : "writeIfAbsent", [
        key,
        Buffer.from(checkedData).toString("base64"),
      ]);
    }
    const filePath = this.entryPath(namespace, key);
    const dirPath = dirname(filePath);
    const stagedPath = join(
      dirPath,
      `.${basename(filePath)}.${process.pid}.${Buffer.from(randomBytes(8)).toString("hex")}.claim`,
    );

    // Stage bytes with the backend's normal custody discipline, then publish
    // them with link(2). Creating the destination hard link is atomic and
    // fails with EEXIST when another process won; unlike rename it never
    // overwrites the winner. The random staging name does not end in `.enc`,
    // so an interrupted claim is never enumerated as a storage record.
    const failures: unknown[] = [];
    let created = false;
    let publishedDirectory: Stats | undefined;
    try {
      publishedDirectory = await writeFileCustodyWithDurability(stagedPath, checkedData, {
        strictDirectoryBase: this.strictDirectoryBase(namespace),
        // Must match the required strictDurability option of writeFileCustodyWithDurability in custody-fs.ts so this write preserves every barrier.
        strictDurability,
        mode: 0o600,
        parentMode: 0o700,
        ...(this.owner !== undefined
          ? {
              owner: this.owner,
              ownerBase: this.activeBasePath(),
              stableDirectoryCapability: this.hasStableDirectoryCapability(),
            }
          : {}),
      });
      // The custody descriptor supplies identity so exclusive publication cannot adopt a replacement directory.
      try {
        await link(stagedPath, filePath);
        created = true;
      } catch (err: unknown) {
        if (
          err instanceof Error &&
          "code" in err &&
          (err as NodeJS.ErrnoException).code === "EEXIST"
        ) {
          created = false;
        } else throw err;
      }
      if (created || strictDurability) await (strictDurability ? syncDirectoryStrict(dirPath, publishedDirectory) : this.fsyncDirectoryLegacy(dirPath));
    } catch (error) { failures.push(error); }
    finally {
      if (strictDurability) {
        // An absent staging name is harmless, while cleanup failures must retain publication evidence.
        let cleanupNeedsBarrier = publishedDirectory !== undefined;
        try { await unlink(stagedPath); cleanupNeedsBarrier = true; }
        catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            cleanupNeedsBarrier = true;
            failures.push(error);
          }
        }
        if (cleanupNeedsBarrier) {
          try { await syncDirectoryStrict(dirPath, publishedDirectory); } catch (error) { failures.push(error); }
        }
      } else await unlink(stagedPath).catch(() => undefined);
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) throw new AggregateError(failures, "strict publication and cleanup failed");
    return created;
  }

  async replaceIfEquals(namespace: string, key: string, expected: Uint8Array, data: Uint8Array): Promise<boolean> {
    // Legacy validation order remains stable before the original-buffer authorization.
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    return this.replaceIfEqualsMode(namespace, key, expected, checkedData, false);
  }

  private async replaceIfEqualsMode(
    namespace: string,
    key: string,
    expected: Uint8Array,
    checkedData: Uint8Array,
    strictDurability: boolean,
  ): Promise<boolean> {
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    // Only the public wrappers supply this already-authorized snapshot, so checking its new identity would reject valid SDW writes.
    const capability = this.darwinCapability(namespace);
    if (capability) {
      return this.callDarwinNamespace(capability, strictDurability ? "replaceIfEqualsStrict" : "replaceIfEquals", [
        key,
        Buffer.from(expected).toString("base64"),
        Buffer.from(checkedData).toString("base64"),
      ]);
    }
    const filePath = this.entryPath(namespace, key);
    const dirPath = dirname(filePath);
    const lockName = `.${basename(filePath)}.compare-replace.lock`;
    // Even an absent comparison creates lock parents, so strict setup cannot wait for a matching row.
    // Owner mode may not create parents, so its strict comparison syncs an existing chain and refuses a missing one with a typed code.
    const directoryIdentity = !strictDurability ? undefined
      : this.owner !== undefined ? await syncExistingDirectoryChainStrict(dirPath, this.strictDirectoryBase(namespace))
        : await ensureDirectoryStrict(dirPath, 0o700, this.strictDirectoryBase(namespace));

    // The lock covers the complete read -> compare -> atomic replacement
    // window. A plain read followed by rename is not CAS: two processes can
    // both observe `expected` and both overwrite. The O_EXCL lock makes the
    // second process re-read only after the winner has committed. A crashed
    // holder leaves a visible stale lock and future calls fail closed rather
    // than auto-breaking it with a racy unlink.
    let primaryFailure: unknown;
    let replaced: boolean;
    try { replaced = await withPathLock(
      dirPath,
      lockName,
      async () => {
        try {
          // The comparison lock must cover the same parent that strict setup captured before its lockfile existed.
          if (strictDurability) await syncDirectoryStrict(dirPath, directoryIdentity);
          const current = await this.readAtPath(filePath);
          if (current === null || !constantTimeEqual(current, expected)) return false;
          await this.atomicWriteFile(filePath, checkedData, true, strictDurability);
          return true;
        } catch (error) {
          if (strictDurability) primaryFailure = error;
          throw error;
        }
      },
      { metadata: { operation: "storage_compare_and_replace" } },
    );
    } catch (error) {
      // Legacy lock cleanup must retain the strict operation failure because both describe uncertain completion.
      if (primaryFailure !== undefined && error !== primaryFailure) throw new AggregateError([primaryFailure, error], "strict comparison and cleanup failed", { cause: error });
      throw error;
    }
    // Strict completion barriers the captured directory containing the removed comparison lock.
    if (strictDurability) await syncDirectoryStrict(dirPath, directoryIdentity);
    return replaced;
  }

  async writeDurable(
    namespace: string,
    key: string,
    data: Uint8Array
  ): Promise<void> {
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const capability = this.darwinCapability(namespace);
    if (capability) {
      await this.callDarwinNamespace(capability, "writeDurable", [
        key,
        Buffer.from(checkedData).toString("base64"),
      ]);
      return;
    }
    const filePath = this.entryPath(namespace, key);

    await this.atomicWriteFile(filePath, checkedData, true, false);
  }

  private strictDirectoryBase(namespace: string): string {
    if (this.allowDirectoryCapabilityRootNamespace) return ".";
    const bound = this.boundBasePath.getStore();
    return bound?.lockedNamespace === namespace ? this.activeNamespacePath(namespace) : this.activeBasePath();
  }

  private assertStrictDirectoryBinding(): void {
    const bound = this.boundBasePath.getStore();
    const authority = this.strictLockLease.getStore();
    // Only a live strict lock or its private worker executor supplies the held root and parent barriers.
    if (!this.allowDirectoryCapabilityRootNamespace && (!bound?.strictDurability || !authority?.active)) throw new Error("strict writes require a strict namespace binding");
    authority?.assertHeld();
  }

  /** Must match StrictDurabilityStorageCapabilities in interface.ts and worker strict dispatch. */
  async writeStrict(namespace: string, key: string, data: Uint8Array): Promise<void> {
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    this.assertStrictDirectoryBinding();
    const capability = this.darwinCapability(namespace);
    // Original-buffer authorization before dispatch must match strictWriteTarget in directory-capability-worker.ts.
    if (capability) {
      await this.callDarwinNamespace(capability, "writeStrict", [key, Buffer.from(checkedData).toString("base64")]);
      return;
    }
    await this.atomicWriteFile(this.entryPath(namespace, key), checkedData, true, true);
  }

  /** Exclusive strict publication; must match interface.ts and worker dispatch. */
  async writeIfAbsentStrict(namespace: string, key: string, data: Uint8Array): Promise<boolean> {
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    // Authorization belongs to the original prepared buffer, before its snapshot reaches the mode helper.
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    this.assertStrictDirectoryBinding();
    return this.writeIfAbsentMode(namespace, key, checkedData, true);
  }

  /** Strict serialized replacement; must match interface.ts and worker dispatch. */
  async replaceIfEqualsStrict(namespace: string, key: string, expected: Uint8Array, data: Uint8Array): Promise<boolean> {
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    // Authorization belongs to the original prepared buffer, before its snapshot reaches the mode helper.
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    this.assertStrictDirectoryBinding();
    return this.replaceIfEqualsMode(namespace, key, expected, checkedData, true);
  }

  private async atomicWriteFile(
    filePath: string,
    data: Uint8Array,
    syncFile: boolean,
    strictDurability: boolean,
  ): Promise<void> {
    // For owner writes, writeFileCustody verifies the namespace dir exists
    // inside basePath before opening the temp file. It will not recursively
    // create parent dirs as root.
    const directoryIdentity = await writeFileCustodyWithDurability(filePath, data, {
      strictDirectoryBase: this.allowDirectoryCapabilityRootNamespace ? "." : (this.boundBasePath.getStore()?.namespaceBasePath === dirname(filePath) ? dirname(filePath) : this.activeBasePath()),
      // Must match the required strictDurability option of writeFileCustodyWithDurability in custody-fs.ts so this write preserves every barrier.
      strictDurability,
      mode: 0o600,
      parentMode: 0o700,
      // The storage root is the containment base: an owner-write must never
      // land outside this backend's own basePath, even if a path component
      // inside it was replaced with a symlink.
      ...(this.owner !== undefined
        ? {
            owner: this.owner,
            ownerBase: this.activeBasePath(),
            stableDirectoryCapability: this.hasStableDirectoryCapability(),
          }
        : {}),
    });
    if (syncFile) await (strictDurability ? syncDirectoryStrict(dirname(filePath), directoryIdentity) : this.fsyncDirectoryLegacy(dirname(filePath)));
  }

  private async fsyncDirectoryLegacy(dirPath: string): Promise<void> {
    let handle;
    try {
      handle = await open(dirPath, "r");
      await handle.sync();
    } catch (error) {
      // Some supported platform/filesystem combinations do not permit syncing
      // a directory descriptor. Only those explicit capability failures are
      // best-effort; real I/O failures must propagate to the caller so a
      // journal unlink is never reported durably cleared when it was not.
      if (!isBenignDirectoryFsyncError(error)) throw error;
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    const capability = this.darwinCapability(namespace);
    if (capability) {
      const encoded = await this.callDarwinNamespace<string | null>(
        capability,
        "read",
        [key],
      );
      return encoded === null ? null : new Uint8Array(Buffer.from(encoded, "base64"));
    }
    const buf = await this.readAtPath(this.entryPath(namespace, key));
    if (buf !== null) return buf;
    // Legacy fallback: fortresses written before #41 used the pre-supported-
    // range sanitizer; if the new-form path is missing, try the legacy form.
    const legacy = this.legacyEntryPath(namespace, key);
    if (legacy === this.entryPath(namespace, key)) return null;
    return this.readAtPath(legacy);
  }

  private async readAtPath(filePath: string): Promise<Uint8Array | null> {
    try {
      const buf = await readFileCustody(filePath);
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        return null;
      }
      throw err;
    }
  }

  async delete(
    namespace: string,
    key: string,
    secureOverwrite = true
  ): Promise<boolean> {
    assertStorageMasterWriteBarrierHeld(this);
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    const capability = this.darwinCapability(namespace);
    if (capability) {
      return this.callDarwinNamespace(capability, "delete", [
        key,
        secureOverwrite,
      ]);
    }
    const newPath = this.entryPath(namespace, key);
    if (await this.deleteAtPath(newPath, secureOverwrite)) {
      await this.fsyncDirectoryLegacy(dirname(newPath));
      return true;
    }
    // Legacy fallback: existing fortresses may have data at the old path.
    const legacy = this.legacyEntryPath(namespace, key);
    if (legacy === newPath) return false;
    if (!(await this.deleteAtPath(legacy, secureOverwrite))) return false;
    await this.fsyncDirectoryLegacy(dirname(legacy));
    return true;
  }

  private async deleteAtPath(
    filePath: string,
    secureOverwrite: boolean
  ): Promise<boolean> {
    try {
      let openedStats: Stats | null = null;
      if (secureOverwrite) {
        const noFollow =
          typeof fsConstants.O_NOFOLLOW === "number"
            ? fsConstants.O_NOFOLLOW
            : 0;
        const fileHandle = await open(filePath, fsConstants.O_RDWR | noFollow);
        try {
          const fileStat = await fileHandle.stat();
          if (!fileStat.isFile()) {
            throw new Error("Secure delete target is not a regular file.");
          }
          openedStats = fileStat;
          const size = fileStat.size;

          // A zero-byte file has no content to overwrite (and randomBytes(0)
          // rejects a non-positive length); skip straight to unlink.
          // Overwrite with random bytes (3 passes for defense in depth). Each
          // pass is fsync'd so the bytes are flushed to the medium rather than
          // left in the page cache; this is best-effort durability, not a
          // guarantee of in-place overwrite on CoW / journaled / flash-FTL
          // filesystems (see the header comment).
          for (let pass = 0; size > 0 && pass < 3; pass++) {
            const randomData = randomBytes(size);
            // write() may short-write, so loop until every byte is on the fd
            // before fsync; otherwise a pass could flush only a prefix and
            // leave the suffix as prior ciphertext.
            let offset = 0;
            while (offset < randomData.length) {
              const { bytesWritten } = await fileHandle.write(
                randomData,
                offset,
                randomData.length - offset,
                offset
              );
              if (bytesWritten === 0) {
                throw new Error("Secure delete overwrite made no progress.");
              }
              offset += bytesWritten;
            }
            await fileHandle.sync();
          }
        } finally {
          await fileHandle.close();
        }
        let pathStats: Stats;
        try {
          pathStats = await lstat(filePath);
        } catch (err) {
          if (
            err instanceof Error &&
            "code" in err &&
            (err as NodeJS.ErrnoException).code === "ENOENT"
          ) {
            throw new Error("Secure delete target changed before unlink.", {
              cause: err,
            });
          }
          throw err;
        }
        if (
          pathStats.isSymbolicLink() ||
          pathStats.dev !== openedStats.dev ||
          pathStats.ino !== openedStats.ino
        ) {
          throw new Error("Secure delete target changed before unlink.");
        }
      }

      // Remove the file
      await unlink(filePath);
      return true;
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        return false;
      }
      throw err;
    }
  }

  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    this.assertCallerNamespace(namespace);
    const capability = this.darwinCapability(namespace);
    if (capability) {
      // Node's IPC serializer turns an `undefined` array element into `null`.
      // Sending `[namespace, undefined]` therefore made the cwd-bound worker
      // interpret an omitted prefix as the literal string `"null"`, hiding
      // every entry from callers such as the master-rotation namespace walk.
      // Omit the optional argument entirely so the worker preserves the local
      // FilesystemStorage `list(namespace)` contract.
      return this.callDarwinNamespace(
        capability,
        "list",
        prefix === undefined
          ? []
          : [prefix],
      );
    }
    const dirPath = this.activeNamespacePath(namespace);

    let files: string[];
    try {
      files = await readdir(dirPath);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const entries: StorageEntryMeta[] = [];
    for (const file of files) {
      if (!file.endsWith(".enc")) continue;
      const encodedKey = file.slice(0, -4); // Four characters in the .enc suffix.
      const key = decodeRawFilesystemStorageName(encodedKey, "key");
      if (prefix && !key.startsWith(prefix)) continue;
      let fileStat;
      try {
        fileStat = await stat(join(dirPath, file));
      } catch (err: unknown) {
        // A vanished candidate cannot discard surviving entries; the Darwin directory-capability worker delegates list here too.
        if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw err;
      }
      entries.push({ key, namespace, size_bytes: fileStat.size, modified_at: fileStat.mtime.toISOString() });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }

  /** Names only, with the complete-or-throw contract in storage/interface.ts. */
  async listKeys(namespace: string, prefix?: string): Promise<string[]> {
    this.assertCallerNamespace(namespace);
    const capability = this.darwinCapability(namespace);
    if (capability) {
      // Must match listKeys in directory-capability-worker.ts: omit undefined
      // so IPC cannot turn an absent prefix into a literal null prefix.
      return this.callDarwinNamespace(capability, "listKeys", prefix === undefined ? [] : [prefix]);
    }
    let files: string[];
    try {
      files = await readdir(this.activeNamespacePath(namespace));
    } catch (err: unknown) {
      // Only absence of the namespace is empty; incomplete enumeration throws.
      if (err instanceof Error && "code" in err && err.code === "ENOENT") return [];
      throw err;
    }
    const keys: string[] = [];
    for (const file of files) {
      if (!file.endsWith(".enc")) continue;
      const key = decodeRawFilesystemStorageName(file.slice(0, -".enc".length), "key");
      if (prefix && !key.startsWith(prefix)) continue;
      keys.push(key);
    }
    return keys.sort();
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    this.assertCallerNamespace(namespace);
    assertFilesystemStorageNameAddressable(key, "key");
    const capability = this.darwinCapability(namespace);
    if (capability) {
      return this.callDarwinNamespace(capability, "exists", [key]);
    }
    const newPath = this.entryPath(namespace, key);
    try {
      await stat(newPath);
      return true;
    } catch {
      // Legacy fallback for pre-#41 fortresses.
      const legacy = this.legacyEntryPath(namespace, key);
      if (legacy === newPath) return false;
      try {
        await stat(legacy);
        return true;
      } catch {
        return false;
      }
    }
  }

  async listNamespaces(): Promise<string[]> {
    const capability = this.darwinCapability();
    if (capability) return capability.client.call("listNamespaces");
    let root;
    try {
      root = await opendir(this.activeBasePath());
    } catch (error) {
      // Only an absent root proves an empty fortress; permission/I/O errors
      // cannot authorize an apparently complete export of a partial set.
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    const namespaces: string[] = [];
    let scanned = 0;
    const chargeEntry = () => {
      // Must match listNamespaces in interface.ts: one shared budget bounds
      // work even for empty/internal directories; opendir bounds allocation.
      if (++scanned > MAX_NAMESPACE_DISCOVERY_ENTRIES) {
        throw new Error(NAMESPACE_DISCOVERY_LIMIT_REMEDIATION);
      }
    };
    for await (const dir of root) {
      chargeEntry();
      const rootEntryPath = join(this.activeBasePath(), dir.name);
      const rootEntryStat = await stat(rootEntryPath);
      if (!rootEntryStat.isDirectory()) continue;
      let hasEntries = false;
      // Propagate subdirectory failures too: skipping an unreadable namespace
      // would turn a storage error into silent data loss in a full export.
      for await (const entry of await opendir(rootEntryPath)) {
        chargeEntry();
        if (entry.name.endsWith(".enc")) {
          // Discovery proves the namespace directory and first stored entry;
          // every consumer lists the namespace itself before acting on entries.
          try {
            decodeRawFilesystemStorageName(entry.name.slice(0, -4), "key");
          } catch (error) {
            if (isFilesystemStorageNameError(error)) {
              throw new FilesystemStorageNameError("key", {
                rawName: error.rawName,
                rawNamespace: dir.name,
              });
            }
            throw error;
          }
          hasEntries = true;
          break;
        }
      }
      if (!hasEntries) continue;
      if (namespaces.length >= MAX_DISCOVERED_NAMESPACES) {
        throw new Error(NAMESPACE_DISCOVERY_LIMIT_REMEDIATION);
      }
      // Empty non-canonical directories are root noise, but a directory with
      // entries is state-bearing; fail closed before a full export can omit it.
      // Raw stored directory names are classified before P13 canonicality so
      // operators see the on-disk segment they can actually recover or move.
      const namespace = decodeRawFilesystemStorageName(dir.name, "namespace");
      // The directory must be the canonical encoding of the name it decodes to;
      // otherwise the listed name addresses a different (absent) directory and a
      // full export would silently omit this one's data.
      if (storageNamespacePathComponent(namespace) !== dir.name) {
        throw new InvalidStorageNamespaceError(namespace);
      }
      namespaces.push(namespace);
    }
    return namespaces.sort();
  }

  async totalSize(): Promise<number> {
    const capability = this.darwinCapability();
    if (capability) return capability.client.call("totalSize");
    let total = 0;

    try {
      const namespaces = await readdir(this.activeBasePath());
      for (const ns of namespaces) {
        const rootEntryPath = join(this.activeBasePath(), ns);
        const rootEntryStat = await stat(rootEntryPath);
        if (!rootEntryStat.isDirectory()) continue;
        // totalSize measures bytes already under the state root for emptiness
        // gates; resolving root entries as namespaces would turn stray
        // directories into false-empty or partial-size answers.
        const nsPath = rootEntryPath;

        const files = await readdir(nsPath);
        for (const file of files) {
          const filePath = join(nsPath, file);
          const fileStat = await stat(filePath);
          total += fileStat.size;
        }
      }
    } catch {
      // If base path doesn't exist yet, total is 0
    }

    return total;
  }
}

/**
 * Build the Darwin worker executor, whose held cwd stands in for the strict lock.
 * Must match the only callers, in directory-capability-worker.ts. It is not
 * re-exported from the storage or package index, so no public construction path
 * can opt out of the strict lock requirement.
 */
export function createDirectoryCapabilityWorkerStorage(
  basePath: string,
  owner?: { uid: number; gid: number },
): FilesystemStorage {
  const storage = new FilesystemStorage(basePath, owner ? { owner } : {});
  directoryCapabilityWorkerExecutors.add(storage);
  return storage;
}
