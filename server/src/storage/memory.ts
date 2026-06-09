/**
 * Sanctuary MCP Server — In-Memory Storage Backend
 *
 * Used for testing. Implements the same interface as filesystem storage
 * but stores everything in memory. Data does not persist across restarts.
 */

import type { StorageBackend, StorageEntryMeta } from "./interface.js";
import { assertSdwRawWriteAuthorized } from "../sdw/write-gate.js";

export class MemoryStorage implements StorageBackend {
  private store = new Map<string, { data: Uint8Array; modified_at: string }>();

  private storageKey(namespace: string, key: string): string {
    return `${namespace}/${key}`;
  }

  async write(
    namespace: string,
    key: string,
    data: Uint8Array
  ): Promise<void> {
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    this.store.set(this.storageKey(namespace, key), {
      data: checkedData,
      modified_at: new Date().toISOString(),
    });
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    const entry = this.store.get(this.storageKey(namespace, key));
    if (!entry) return null;
    return new Uint8Array(entry.data); // Copy to prevent external mutation
  }

  async delete(
    namespace: string,
    key: string,
    _secureOverwrite?: boolean
  ): Promise<boolean> {
    return this.store.delete(this.storageKey(namespace, key));
  }

  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    const entries: StorageEntryMeta[] = [];
    const nsPrefix = `${namespace}/`;

    for (const [storeKey, entry] of this.store) {
      if (!storeKey.startsWith(nsPrefix)) continue;
      const key = storeKey.slice(nsPrefix.length);
      if (prefix && !key.startsWith(prefix)) continue;

      entries.push({
        key,
        namespace,
        size_bytes: entry.data.length,
        modified_at: entry.modified_at,
      });
    }

    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.store.has(this.storageKey(namespace, key));
  }

  async totalSize(): Promise<number> {
    let total = 0;
    for (const entry of this.store.values()) {
      total += entry.data.length;
    }
    return total;
  }

  /** Clear all stored data (useful in tests) */
  clear(): void {
    this.store.clear();
  }
}
