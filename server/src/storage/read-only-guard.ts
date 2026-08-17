/**
 * Sanctuary MCP Server — Read-only storage guard
 *
 * A `StorageBackend` decorator that delegates every READ and refuses every
 * WRITE, by throwing. It exists so a diagnostic verb can prove it does not
 * mutate the fortress STRUCTURALLY rather than by convention.
 *
 * Why a decorator and not "just don't call write": a read-only verb reaches
 * deep, shared machinery (`AuditLog.ensureLoaded`, the sealed-region walk, the
 * raw chain exporter, custody unwrap). Each of those can write on some path —
 * anchor stamping, marker establishment, custody migration — and none of them
 * announces it at the call site. Reviewing "does this transitively write?" by
 * hand is exactly the audit that goes stale on the next edit of a 7,900-line
 * module. Passing the guard instead converts that open-ended review into a
 * closed one: if any reachable code writes, the process fails loudly at the
 * attempt instead of silently mutating the operator's fortress.
 *
 * The guard is deliberately NOT a security boundary. It bounds THIS process's
 * own storage calls; it does nothing about a caller that holds the underlying
 * backend, opens the files directly, or shells out. Its job is to keep an
 * accidental or newly-introduced write from reaching disk, and to make that
 * failure loud.
 *
 * MUST-NEVER #5 (never silently degrade): a refused write THROWS. It is never
 * swallowed, never turned into a no-op that lets the caller believe the write
 * landed, and never downgraded to a warning.
 */

import { isSdwNamespace } from "../sdw/write-gate.js";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
  StorageEntryMeta,
} from "./interface.js";

/**
 * Thrown when code running behind a {@link ReadOnlyStorageGuard} attempts a
 * mutation. Reaching this is a DEFECT in the calling verb (a read-only path
 * that turned out to write), not an operator error, and the message says so
 * because that is who has to act on it.
 */
export class ReadOnlyStorageViolationError extends Error {
  readonly method: string;
  readonly namespace: string;
  readonly key: string;

  constructor(method: string, namespace: string, key: string) {
    super(
      `read-only storage guard refused ${method}(${namespace}/${key}): this ` +
        `code path is declared read-only and must not mutate fortress state`
    );
    this.name = "ReadOnlyStorageViolationError";
    this.method = method;
    this.namespace = namespace;
    this.key = key;
  }
}

/**
 * The methods the guard REFUSES. Must together with
 * {@link READ_ONLY_STORAGE_DELEGATED_METHODS} cover every method declared on
 * `StorageBackend` and `FilesystemStorageCapabilities` in
 * `storage/interface.ts` — a method in neither list is a method the guard
 * silently inherits or omits, which is the rule-5 hand-mirrored-registry drift
 * shape. Full-set parity (not "the first entry matches") is asserted by
 * `test/structure/read-only-storage-guard-parity.test.ts`.
 */
export const READ_ONLY_STORAGE_MUTATING_METHODS = [
  "write",
  "delete",
  "writeDurable",
] as const;

/**
 * The methods the guard DELEGATES unchanged. Must match the read surface of
 * `storage/interface.ts`; see {@link READ_ONLY_STORAGE_MUTATING_METHODS} for
 * why both lists exist and what enforces them.
 */
export const READ_ONLY_STORAGE_DELEGATED_METHODS = [
  "read",
  "list",
  "exists",
  "totalSize",
  "listNamespaces",
  "namespacePath",
] as const;

/**
 * Wrap a backend so reads pass through and writes throw.
 *
 * `FilesystemStorageCapabilities` is implemented as well as `StorageBackend`
 * because consumers feature-detect it by probing for `namespacePath` AND
 * `writeDurable` together (see `asFilesystemCapabilities` in
 * `operational/audit-log.ts`, `transparency/emitter.ts`, and
 * `storage/cross-process-lock.ts`). A guard that exposed only `namespacePath`
 * would fail that probe, and `AuditLog` would then skip the split-boundary
 * consultation entirely and report `sealed_region: not_present` on a fortress
 * that HAS a sealed region — a silently wrong verdict, which is worse than a
 * refused write. So `writeDurable` is present and throws.
 */
export class ReadOnlyStorageGuard
  implements StorageBackend, FilesystemStorageCapabilities
{
  private readonly inner: StorageBackend;
  private readonly innerCapabilities: Partial<FilesystemStorageCapabilities>;

  /**
   * Present only when the wrapped backend has it. Master-key rotation treats an
   * ABSENT `listNamespaces` as "this backend cannot enumerate, fail closed", so
   * the guard must mirror presence and absence exactly rather than always
   * defining a method that throws — always-present would turn a fail-closed
   * refusal into a runtime error, changing the meaning of the probe.
   */
  listNamespaces?: () => Promise<string[]>;

  constructor(inner: StorageBackend) {
    this.inner = inner;
    this.innerCapabilities = inner as Partial<FilesystemStorageCapabilities>;
    if (typeof inner.listNamespaces === "function") {
      this.listNamespaces = () => inner.listNamespaces!();
    }
  }

  // ---- refused ----

  // Each refusal declares the FULL parameter list of the method it stands in
  // for, unused arguments included. A shortened signature is still assignable
  // to the interface, so nothing would have caught the divergence at the class
  // level; it only surfaces at a call site, as a confusing arity error. Keeping
  // the shapes identical also means a reader comparing the guard against
  // `storage/interface.ts` sees one contract, not two.

  async write(namespace: string, key: string, _data: Uint8Array): Promise<void> {
    throw new ReadOnlyStorageViolationError("write", namespace, key);
  }

  async writeDurable(
    namespace: string,
    key: string,
    _data: Uint8Array
  ): Promise<void> {
    throw new ReadOnlyStorageViolationError("writeDurable", namespace, key);
  }

  async delete(
    namespace: string,
    key: string,
    _secureOverwrite?: boolean
  ): Promise<boolean> {
    throw new ReadOnlyStorageViolationError("delete", namespace, key);
  }

  // ---- delegated ----

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.inner.read(namespace, key);
  }

  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    return this.inner.list(namespace, prefix);
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.inner.exists(namespace, key);
  }

  async totalSize(): Promise<number> {
    return this.inner.totalSize();
  }

  /**
   * Pure path computation on every shipped backend (`FilesystemStorage`
   * resolves and encodes; it does not mkdir), so delegating it creates nothing
   * on disk. If a future backend makes this method create its namespace
   * directory, that write escapes this guard and the guard's contract breaks —
   * which is why the no-mutation tests hash the fortress DIRECTORY TREE, not
   * only file contents.
   */
  namespacePath(namespace: string): string {
    // Refused here as well as by the wrapped backend, not instead of it. A
    // decorator that only forwarded would inherit whatever it happens to wrap,
    // and holding a property regardless of what it wraps is this class's whole
    // purpose. Must match the same refusal in `FilesystemStorage.namespacePath`.
    if (isSdwNamespace(namespace)) {
      throw new Error("Filesystem paths for SDW namespaces are not exposed");
    }
    const fn = this.innerCapabilities.namespacePath;
    if (typeof fn !== "function") {
      throw new Error(
        "read-only storage guard: wrapped backend exposes no namespacePath"
      );
    }
    return fn.call(this.inner, namespace);
  }
}
