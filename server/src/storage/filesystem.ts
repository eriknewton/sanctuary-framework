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
 * Path encoding (bijective, full-sweep #41):
 *   Distinct (namespace, key) inputs MUST produce distinct on-disk paths;
 *   otherwise an agent that can choose namespace/key strings within a tenant
 *   could overwrite or read another namespace by colliding on the sanitized
 *   form (multi-tenant isolation invariant). The encoder retains the safe
 *   set [A-Za-z0-9_.-] (so internal namespaces such as `_audit`, `_bridge`,
 *   etc. preserve their on-disk paths verbatim) and `!`-escapes every other
 *   character as `!XX` where XX is the upper-hex byte. The escape character
 *   `!` itself is NOT in the safe set, so a literal `!` in input encodes as
 *   `!21` and decoding remains unambiguous.
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
import { link, mkdir, open, unlink, readdir, stat, lstat } from "node:fs/promises";
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
  StorageBackend,
  StorageEntryMeta,
} from "./interface.js";
import { readFileCustody, writeFileCustody } from "./custody-fs.js";
import {
  assertStorageMasterWriteBarrierHeld,
  CrossProcessLockError,
  type CrossProcessLockLease,
  withPathLock,
} from "./cross-process-lock.js";
import { isBenignDirectoryFsyncError } from "./directory-fsync.js";
import {
  cleanupFreshInitRecoveryResidue,
  restoreFreshFortressLockScaffold,
} from "./fresh-fortress.js";

const SAFE_CHARS = /[^A-Za-z0-9_.-]/g;

function bijectiveEncode(name: string): string {
  return name.replace(SAFE_CHARS, (ch) =>
    "!" + ch.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()
  );
}

function bijectiveDecode(encoded: string): string {
  return encoded.replace(/!([0-9A-Fa-f]{2})/g, (_match, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
}

// Legacy whitelist sanitizers, used ONLY for read-fallback against fortresses
// written before full-sweep #41. write() never produces these paths.
function legacyNamespaceSanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}
function legacyKeySanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_.-]/g, "_");
}

function encodedNamespacePath(basePath: string, namespace: string): string {
  return join(basePath, bijectiveEncode(namespace));
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

async function writeStableFortressFile(
  root: string,
  name: string,
  data: Uint8Array,
  mode: number,
): Promise<void> {
  await writeFileCustody(stableFortressFilePath(root, name), data, {
    mode,
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

interface CapabilityResponse {
  id?: number;
  ready?: boolean;
  ok?: boolean;
  value?: unknown;
  error?: { message?: string; code?: string };
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
        const error = new Error(
          raw.error?.message ?? "directory-capability worker operation failed",
        ) as NodeJS.ErrnoException;
        if (raw.error?.code) error.code = raw.error.code;
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
      execArgv: sourceLoader ? ["--import", sourceLoader] : [],
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
          2_000,
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

  call<T>(op: string, args: unknown[] = []): Promise<T> {
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
        this.child.send({ id, op, args }, (error) => {
          if (!error) return;
          this.pending.delete(id);
          clearTimeout(timeout);
          reject(error);
        });
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
}

const DARWIN_BOUND_NAMESPACE_TOKEN = "\0sanctuary-bound-namespace\0";

export class FilesystemStorage implements StorageBackend, FilesystemStorageCapabilities, NamespaceLockStorageCapabilities {
  private basePath: string;
  /**
   * Custody mutations run through an inode-bound directory capability captured
   * before the kernel lock is acquired: `/proc/self/fd` on Linux and a bounded
   * child cwd on Darwin (where `/dev/fd/<dirfd>/child` is not traversable).
   * Async-local binding keeps concurrent read-only users of this instance on
   * the ordinary path while the protected callback uses the held inode.
   */
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

  constructor(basePath: string, options: { owner?: { uid: number; gid: number } } = {}) {
    this.basePath = basePath;
    this.owner = options.owner;
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
        namespace: DARWIN_BOUND_NAMESPACE_TOKEN,
      };
    }
    return bound.darwinClient ? { client: bound.darwinClient, namespace } : undefined;
  }

  private activeNamespacePath(namespace: string): string {
    const bound = this.boundBasePath.getStore();
    if (bound?.lockedNamespace === namespace && bound.namespaceBasePath) {
      return bound.namespaceBasePath;
    }
    return encodedNamespacePath(this.activeBasePath(), namespace);
  }

  private entryPath(namespace: string, key: string): string {
    const safeKey = bijectiveEncode(key);
    return join(this.activeNamespacePath(namespace), `${safeKey}.enc`);
  }

  namespacePath(namespace: string): string {
    if (isSdwNamespace(namespace)) {
      throw new Error("Filesystem paths for SDW namespaces are not exposed");
    }
    return this.activeNamespacePath(namespace);
  }

  async withNamespaceLock<T>(
    namespace: string,
    lockFileName: string,
    operation: Parameters<typeof withPathLock<T>>[2],
    options: Parameters<typeof withPathLock<T>>[3] = {},
  ): Promise<T> {
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
    await mkdir(this.basePath, { recursive: true, mode: 0o700 });
    await mkdir(encodedNamespacePath(this.basePath, namespace), {
      recursive: true,
      mode: 0o700,
    });
    const rootHandle = await open(this.basePath, "r");
    let parentHandle: Awaited<ReturnType<typeof open>> | undefined;
    let namespaceHandle: Awaited<ReturnType<typeof open>> | undefined;
    let rootClient: DarwinDirectoryCapabilityClient | undefined;
    let parentClient: DarwinDirectoryCapabilityClient | undefined;
    let namespaceClient: DarwinDirectoryCapabilityClient | undefined;
    let operationResult!: T;
    let operationFailure: unknown;
    const cleanupFailures: unknown[] = [];
    try {
      parentHandle = await open(dirname(this.basePath), "r");
      const noFollow = typeof fsConstants.O_NOFOLLOW === "number"
        ? fsConstants.O_NOFOLLOW
        : 0;
      const directoryOnly = typeof fsConstants.O_DIRECTORY === "number"
        ? fsConstants.O_DIRECTORY
        : 0;
      namespaceHandle = await open(
        encodedNamespacePath(this.basePath, namespace),
        fsConstants.O_RDONLY | noFollow | directoryOnly,
      );
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
        rootHandle.stat(),
        namespaceHandle.stat(),
        host === "linux"
          ? stat(join(descriptorParent, basename(this.basePath)))
          : lstat(this.basePath),
        host === "linux"
          ? lstat(join(descriptorRoot, bijectiveEncode(namespace)))
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
      if (host === "darwin") {
        rootClient = await DarwinDirectoryCapabilityClient.start(this.basePath, {
          dev: String(heldRoot.dev),
          ino: String(heldRoot.ino),
        }, this.owner, options.__testDirectoryCapabilityTimeoutMs);
        parentClient = await DarwinDirectoryCapabilityClient.start(
          dirname(this.basePath),
          { dev: String(heldParent.dev), ino: String(heldParent.ino) },
          this.owner,
          options.__testDirectoryCapabilityTimeoutMs,
        );
        namespaceClient = await DarwinDirectoryCapabilityClient.start(
          encodedNamespacePath(this.basePath, namespace),
          { dev: String(heldNamespace.dev), ino: String(heldNamespace.ino) },
          this.owner,
          options.__testDirectoryCapabilityTimeoutMs,
        );
        options.__testAfterDirectoryCapabilityAcquired?.(
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
      const boundBasePath = host === "linux" ? descriptorRoot : this.basePath;
      operationResult = await this.boundBasePath.run({
        basePath: boundBasePath,
        lockedNamespace: namespace,
        ...(host === "linux" ? { namespaceBasePath: descriptorNamespace } : {}),
        ...(rootClient ? { darwinClient: rootClient } : {}),
        ...(namespaceClient ? { darwinNamespaceClient: namespaceClient } : {}),
      }, () =>
        withPathLock(
          this.namespacePath(namespace),
          lockFileName,
          async (lease) => {
            const boundLease = {
              ...lease,
            stableStorageRoot: boundBasePath,
            stableStorageParent:
              host === "linux" ? descriptorParent : dirname(this.basePath),
            ...(parentClient
              ? { stableFortressCapability: {
                  tightenPermissions: () => parentClient!.call("tighten"),
                  mkdir: (relativePath: string, mode: number) =>
                    parentClient!.call("mkdir", [relativePath, mode]),
                  isFreshExceptLockScaffold: (name: string) =>
                    parentClient!.call("isFreshExceptLockScaffold", [name]),
                  writeRecoveryKey: (recoveryKey: string, fortressId?: string) =>
                    parentClient!.call(
                      "writeRecoveryKey",
                      fortressId === undefined
                        ? [recoveryKey]
                        : [recoveryKey, fortressId],
                    ),
                  provisionPin: async (input: {
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
                  },
                } }
              : {}),
            stableFortressFiles: parentClient
              ? {
                  read: async (name: string) => {
                    const encoded = await parentClient!.call<string | null>("readFile", [name]);
                    return encoded === null
                      ? null
                      : new Uint8Array(Buffer.from(encoded, "base64"));
                  },
                  write: (name: string, data: Uint8Array, mode = 0o600) =>
                    parentClient!.call("writeFile", [
                      name,
                      Buffer.from(data).toString("base64"),
                      mode,
                    ]),
                  delete: (name: string) => parentClient!.call("deleteFile", [name]),
                  restoreFreshLockScaffold: (name: string) =>
                    parentClient!.call("restoreFreshLockScaffold", [name]),
                  cleanupFreshInitRecoveryResidue: (name: string) =>
                    parentClient!.call("cleanupFreshInitRecoveryResidue", [name]),
                }
              : {
                  read: async (name: string) => {
                    const raw = await readStableFortressFile(descriptorParent, name);
                    return raw === null ? null : new Uint8Array(raw);
                  },
                  write: (name: string, data: Uint8Array, mode = 0o600) =>
                    writeStableFortressFile(descriptorParent, name, data, mode),
                  delete: (name: string) =>
                    deleteStableFortressFile(descriptorParent, name),
                  restoreFreshLockScaffold: (name: string) =>
                    restoreFreshFortressLockScaffold(descriptorParent, name),
                  cleanupFreshInitRecoveryResidue: (name: string) =>
                    cleanupFreshInitRecoveryResidue(
                      descriptorParent,
                      name,
                      this.owner?.uid ?? process.getuid!(),
                    ),
                },
              assertHeld: () => {
                lease.assertHeld();
                rootClient?.assertAlive();
                parentClient?.assertAlive();
                namespaceClient?.assertAlive();
                assertLexicalIdentity();
              },
            } satisfies CrossProcessLockLease;
            boundLease.assertHeld();
            const value = await operation(boundLease);
            boundLease.assertHeld();
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
          if (options.__testCloseNamespaceCapability) {
            await options.__testCloseNamespaceCapability(kind, close);
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
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const capability = this.darwinCapability(namespace);
    if (capability) {
      await capability.client.call("write", [
        capability.namespace,
        key,
        Buffer.from(checkedData).toString("base64"),
      ]);
      return;
    }
    const filePath = this.entryPath(namespace, key);

    await this.atomicWriteFile(filePath, checkedData, false);
  }

  async writeIfAbsent(
    namespace: string,
    key: string,
    data: Uint8Array,
  ): Promise<boolean> {
    assertStorageMasterWriteBarrierHeld(this);
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const capability = this.darwinCapability(namespace);
    if (capability) {
      return capability.client.call("writeIfAbsent", [
        capability.namespace,
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
    await writeFileCustody(stagedPath, checkedData, {
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
    try {
      try {
        await link(stagedPath, filePath);
      } catch (err: unknown) {
        if (
          err instanceof Error &&
          "code" in err &&
          (err as NodeJS.ErrnoException).code === "EEXIST"
        ) {
          return false;
        }
        throw err;
      }
      await this.fsyncDirectory(dirPath);
      return true;
    } finally {
      await unlink(stagedPath).catch(() => undefined);
    }
  }

  async replaceIfEquals(
    namespace: string,
    key: string,
    expected: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean> {
    assertStorageMasterWriteBarrierHeld(this);
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const capability = this.darwinCapability(namespace);
    if (capability) {
      return capability.client.call("replaceIfEquals", [
        capability.namespace,
        key,
        Buffer.from(expected).toString("base64"),
        Buffer.from(checkedData).toString("base64"),
      ]);
    }
    const filePath = this.entryPath(namespace, key);
    const dirPath = dirname(filePath);
    const lockName = `.${basename(filePath)}.compare-replace.lock`;

    // The lock covers the complete read -> compare -> atomic replacement
    // window. A plain read followed by rename is not CAS: two processes can
    // both observe `expected` and both overwrite. The O_EXCL lock makes the
    // second process re-read only after the winner has committed. A crashed
    // holder leaves a visible stale lock and future calls fail closed rather
    // than auto-breaking it with a racy unlink.
    return withPathLock(
      dirPath,
      lockName,
      async () => {
        const current = await this.readAtPath(filePath);
        if (current === null || !constantTimeEqual(current, expected)) return false;
        await this.atomicWriteFile(filePath, checkedData, true);
        return true;
      },
      { metadata: { operation: "storage_compare_and_replace" } },
    );
  }

  async writeDurable(
    namespace: string,
    key: string,
    data: Uint8Array
  ): Promise<void> {
    assertStorageMasterWriteBarrierHeld(this);
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const capability = this.darwinCapability(namespace);
    if (capability) {
      await capability.client.call("writeDurable", [
        capability.namespace,
        key,
        Buffer.from(checkedData).toString("base64"),
      ]);
      return;
    }
    const filePath = this.entryPath(namespace, key);

    await this.atomicWriteFile(filePath, checkedData, true);
  }

  private async atomicWriteFile(
    filePath: string,
    data: Uint8Array,
    syncFile: boolean
  ): Promise<void> {
    // For owner writes, writeFileCustody verifies the namespace dir exists
    // inside basePath before opening the temp file. It will not recursively
    // create parent dirs as root.
    await writeFileCustody(filePath, data, {
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
    if (syncFile) await this.fsyncDirectory(dirname(filePath));
  }

  private async fsyncDirectory(dirPath: string): Promise<void> {
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
    const capability = this.darwinCapability(namespace);
    if (capability) {
      const encoded = await capability.client.call<string | null>("read", [
        capability.namespace,
        key,
      ]);
      return encoded === null ? null : new Uint8Array(Buffer.from(encoded, "base64"));
    }
    const buf = await this.readAtPath(this.entryPath(namespace, key));
    if (buf !== null) return buf;
    // Legacy fallback: fortresses written before #41 used a non-bijective
    // sanitizer; if the new-form path is missing, try the legacy form.
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
    const capability = this.darwinCapability(namespace);
    if (capability) {
      return capability.client.call("delete", [
        capability.namespace,
        key,
        secureOverwrite,
      ]);
    }
    const newPath = this.entryPath(namespace, key);
    if (await this.deleteAtPath(newPath, secureOverwrite)) {
      await this.fsyncDirectory(dirname(newPath));
      return true;
    }
    // Legacy fallback: existing fortresses may have data at the old path.
    const legacy = this.legacyEntryPath(namespace, key);
    if (legacy === newPath) return false;
    if (!(await this.deleteAtPath(legacy, secureOverwrite))) return false;
    await this.fsyncDirectory(dirname(legacy));
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
    const capability = this.darwinCapability(namespace);
    if (capability) {
      // Node's IPC serializer turns an `undefined` array element into `null`.
      // Sending `[namespace, undefined]` therefore made the cwd-bound worker
      // interpret an omitted prefix as the literal string `"null"`, hiding
      // every entry from callers such as the master-rotation namespace walk.
      // Omit the optional argument entirely so the worker preserves the local
      // FilesystemStorage `list(namespace)` contract.
      return capability.client.call(
        "list",
        prefix === undefined
          ? [capability.namespace]
          : [capability.namespace, prefix],
      );
    }
    const dirPath = this.activeNamespacePath(namespace);

    try {
      const files = await readdir(dirPath);
      const entries: StorageEntryMeta[] = [];

      for (const file of files) {
        if (!file.endsWith(".enc")) continue;

        const encodedKey = file.slice(0, -4); // Remove .enc extension
        const key = bijectiveDecode(encodedKey);
        if (prefix && !key.startsWith(prefix)) continue;

        const filePath = join(dirPath, file);
        const fileStat = await stat(filePath);

        entries.push({
          key,
          namespace,
          size_bytes: fileStat.size,
          modified_at: fileStat.mtime.toISOString(),
        });
      }

      return entries.sort((a, b) => a.key.localeCompare(b.key));
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        return [];
      }
      throw err;
    }
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    const capability = this.darwinCapability(namespace);
    if (capability) {
      return capability.client.call("exists", [capability.namespace, key]);
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
    let dirNames: string[];
    try {
      dirNames = await readdir(this.activeBasePath());
    } catch {
      return []; // Base path does not exist yet — empty fortress.
    }
    const namespaces: string[] = [];
    for (const dirName of dirNames) {
      try {
        const s = await stat(join(this.activeBasePath(), dirName));
        if (!s.isDirectory()) continue;
      } catch {
        continue;
      }
      // Skip empty namespace directories: a namespace with no entries holds
      // nothing to rotate, and surfacing it would only trip the rotation
      // walker's unknown-namespace abort for leftover empty dirs.
      try {
        const files = await readdir(join(this.activeBasePath(), dirName));
        if (!files.some((f) => f.endsWith(".enc"))) continue;
      } catch {
        continue;
      }
      // bijectiveDecode is total (unmatched bytes pass through), so legacy
      // pre-#41 sanitized directory names still surface — as their raw names
      // — and the rotation walker's unknown-namespace abort catches them
      // (fail closed) instead of silently skipping a namespace.
      namespaces.push(bijectiveDecode(dirName));
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
        const nsPath = join(this.activeBasePath(), ns);
        const nsStat = await stat(nsPath);
        if (!nsStat.isDirectory()) continue;

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
