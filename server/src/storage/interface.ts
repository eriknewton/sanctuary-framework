/**
 * Sanctuary MCP Server — Storage Backend Interface
 *
 * Abstract interface for persistent storage. All state flows through this
 * interface, making the storage backend pluggable (filesystem, IPFS, S3, etc.).
 *
 * The storage backend deals in raw bytes — encryption/decryption happens
 * in the StateStore layer above.
 *
 * Every method declared on `StorageBackend` and `FilesystemStorageCapabilities`
 * must be classified as mutating-or-delegated in `read-only-guard.ts` (must
 * match `READ_ONLY_STORAGE_MUTATING_METHODS` /
 * `READ_ONLY_STORAGE_DELEGATED_METHODS` there); full-set parity is enforced by
 * `test/structure/read-only-storage-guard-parity.test.ts`. A method added here
 * without a classification there is exactly the drift that lets a "read-only"
 * caller mutate through a method nobody refused.
 */

/** Metadata about a stored entry */
export interface StorageEntryMeta {
  key: string;
  namespace: string;
  size_bytes: number;
  modified_at: string;
}

/** Abstract storage backend interface */
export interface StorageBackend {
  /**
   * Write raw bytes to storage.
   * @param namespace - Logical grouping
   * @param key - Entry key within namespace
   * @param data - Raw bytes to store
   */
  write(namespace: string, key: string, data: Uint8Array): Promise<void>;

  /**
   * Read raw bytes from storage.
   * @returns The stored bytes, or null if not found
   */
  read(namespace: string, key: string): Promise<Uint8Array | null>;

  /**
   * Delete an entry from storage.
   * @param secureOverwrite - If true, overwrite with random bytes before deletion
   */
  delete(
    namespace: string,
    key: string,
    secureOverwrite?: boolean
  ): Promise<boolean>;

  /**
   * List all entries in a namespace.
   */
  list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]>;

  /**
   * Check if an entry exists.
   */
  exists(namespace: string, key: string): Promise<boolean>;

  /**
   * Get the total size of all stored data.
   */
  totalSize(): Promise<number>;

  /**
   * OPTIONAL atomic create. Returns true only when this call created the
   * entry; false means an entry already existed and nothing changed.
   * Security-sensitive callers must fail closed when the capability is
   * absent instead of degrading to read-then-write.
   */
  writeIfAbsent?(
    namespace: string,
    key: string,
    data: Uint8Array,
  ): Promise<boolean>;

  /**
   * OPTIONAL compare-and-replace. Replaces the entry only when its current
   * bytes exactly equal `expected`; false means absent or changed and nothing
   * was written. Implementations must serialize the compare and replacement
   * across processes -- a read followed by an atomic rename is not enough.
   */
  replaceIfEquals?(
    namespace: string,
    key: string,
    expected: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean>;

  /**
   * Enumerate every namespace that currently holds at least one entry.
   * OPTIONAL capability: master-key rotation requires it (the rotation
   * walker must be able to prove it visited the WHOLE fortress and fails
   * closed on backends that cannot enumerate). Implemented by the
   * filesystem and in-memory backends.
   */
  listNamespaces?(): Promise<string[]>;
}

/** Optional filesystem capabilities used by code that must coordinate across processes. */
export interface FilesystemStorageCapabilities {
  /**
   * Return the absolute on-disk directory for a storage namespace, creating
   * callers' own files there only when they are intentionally outside the
   * normal encrypted key/value contract. SDW namespaces are not exposed through
   * this capability.
   */
  namespacePath(namespace: string): string;

  /** Write bytes and fsync the file before resolving. */
  writeDurable(namespace: string, key: string, data: Uint8Array): Promise<void>;
}
