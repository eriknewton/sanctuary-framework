import { mkdir } from "node:fs/promises";
import type * as Lmdb from "lmdb";
import type { StorageBackend, StorageEntryMeta } from "../storage/interface.js";

export interface SdwTxn {
  write(namespace: string, key: string, data: Uint8Array): Promise<void>;
  read(namespace: string, key: string): Promise<Uint8Array | null>;
  delete(namespace: string, key: string): Promise<boolean>;
}

export interface SdwTransactional {
  sdwTransaction<T>(fn: (txn: SdwTxn) => Promise<T>): Promise<T>;
}

export interface LmdbStorageBackendOptions {
  readonly path: string;
  readonly mapSizeBytes?: number;
}

export class LmdbStorageBackend implements StorageBackend, SdwTransactional {
  private readonly db: Lmdb.RootDatabase<Lmdb.Binary, string>;
  private readonly lmdb: typeof Lmdb;

  private constructor(
    db: Lmdb.RootDatabase<Lmdb.Binary, string>,
    lmdbModule: typeof Lmdb,
  ) {
    this.db = db;
    this.lmdb = lmdbModule;
  }

  static async open(
    options: LmdbStorageBackendOptions,
  ): Promise<LmdbStorageBackend> {
    await mkdir(options.path, { recursive: true, mode: 0o700 });
    const lmdb = await import("lmdb");
    const db = lmdb.open<Lmdb.Binary, string>({
      path: options.path,
      encoding: "binary",
      compression: false,
      mapSize: options.mapSizeBytes ?? 256 * 1024 * 1024,
    });
    return new LmdbStorageBackend(db, lmdb);
  }

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    await this.db.put(compositeKey(namespace, key), this.lmdb.asBinary(data));
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    const value = this.db.getBinary(compositeKey(namespace, key));
    if (value === undefined) return null;
    return new Uint8Array(value);
  }

  async delete(namespace: string, key: string): Promise<boolean> {
    return this.db.remove(compositeKey(namespace, key));
  }

  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    const start = compositeKey(namespace, prefix);
    const end = `${compositeKey(namespace, prefix)}\uffff`;
    const entries: StorageEntryMeta[] = [];
    for (const entry of this.db.getRange({ start, end })) {
      const parsed = splitCompositeKey(entry.key);
      if (parsed === null || parsed.namespace !== namespace) continue;
      const sizeBytes = entry.value instanceof Uint8Array ? entry.value.byteLength : 0;
      entries.push({
        namespace,
        key: parsed.key,
        size_bytes: sizeBytes,
        modified_at: new Date().toISOString(),
      });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.db.getBinary(compositeKey(namespace, key)) !== undefined;
  }

  async totalSize(): Promise<number> {
    let total = 0;
    for (const entry of this.db.getRange()) {
      if (entry.value instanceof Uint8Array) total += entry.value.byteLength;
    }
    return total;
  }

  async sdwTransaction<T>(fn: (txn: SdwTxn) => Promise<T>): Promise<T> {
    let result: T | undefined;
    await this.db.transaction(async () => {
      const txn: SdwTxn = {
        write: async (namespace, key, data) => {
          this.db.putSync(compositeKey(namespace, key), this.lmdb.asBinary(data));
        },
        read: async (namespace, key) => this.read(namespace, key),
        delete: async (namespace, key) => this.db.removeSync(compositeKey(namespace, key)),
      };
      result = await fn(txn);
    });
    return result as T;
  }

  async close(): Promise<void> {
    await this.db.close();
  }
}

function compositeKey(namespace: string, key: string): string {
  return `${namespace}\x00${key}`;
}

function splitCompositeKey(value: string): { namespace: string; key: string } | null {
  const index = value.indexOf("\x00");
  if (index < 0) return null;
  return {
    namespace: value.slice(0, index),
    key: value.slice(index + 1),
  };
}
