/**
 * Sanctuary MCP Server — Storage Backend Interface
 *
 * Abstract interface for persistent storage. All state flows through this
 * interface, making the storage backend pluggable (filesystem, IPFS, S3, etc.).
 *
 * The storage backend deals in raw bytes — encryption/decryption happens
 * in the StateStore layer above.
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
