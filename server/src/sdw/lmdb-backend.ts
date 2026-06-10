import { mkdir } from "node:fs/promises";
import type * as Lmdb from "lmdb";
import type { StorageBackend, StorageEntryMeta } from "../storage/interface.js";
import type { SdwRecord } from "./records.js";
import {
  assertSdwRawWriteAuthorized,
  prepareSdwBackendWrite,
  type Persistable,
} from "./write-gate.js";

export interface SdwTxn {
  write(namespace: string, key: string, data: Uint8Array): Promise<void>;
  writePersistable<T extends SdwRecord>(
    persistable: Persistable<T>,
    encryptionKey: Uint8Array,
    fortressId: string,
  ): Promise<void>;
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
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    await this.db.put(compositeKey(namespace, key), this.lmdb.asBinary(checkedData));
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

  /**
   * All-or-nothing SDW transaction (staged-then-atomic-commit).
   *
   * lmdb-js's async `db.transaction()` does NOT roll back `putSync` writes
   * when an async callback rejects after writing (verified empirically
   * 2026-06-09: writes issued before the throw survive the "abort"); only
   * `transactionSync` truly aborts. Because `SdwTxn` consumers are async,
   * the honest atomicity construction is:
   *
   * 1. Stage every write/delete in an in-memory overlay while `fn` runs;
   *    nothing touches LMDB. Reads are read-your-writes against the overlay,
   *    falling back to the committed store.
   * 2. If `fn` throws, the overlay is discarded — zero writes.
   * 3. If `fn` resolves, apply the entire overlay inside ONE synchronous
   *    LMDB write transaction (`transactionSync`). A failure mid-apply
   *    aborts that transaction, rolling back every staged operation.
   *
   * Write-gate checks (`assertSdwRawWriteAuthorized` / `prepareSdwBackendWrite`)
   * run at staging time, exactly as they did when writes were direct.
   */
  async sdwTransaction<T>(fn: (txn: SdwTxn) => Promise<T>): Promise<T> {
    // Composite key → staged bytes; null marks a staged delete. The overlay
    // is the ONLY source the commit loop writes to LMDB, and every overlay
    // write below passes the SDW raw-write guard at staging time.
    const overlay = new Map<string, Uint8Array | null>();
    const txn: SdwTxn = {
      write: async (namespace, key, data) => {
        const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
        overlay.set(compositeKey(namespace, key), new Uint8Array(checkedData));
      },
      writePersistable: async (persistable, encryptionKey, fortressId) => {
        const prepared = prepareSdwBackendWrite(persistable, encryptionKey, fortressId);
        const checkedData = assertSdwRawWriteAuthorized(
          prepared.namespace,
          prepared.storageKey,
          prepared.data,
        );
        overlay.set(
          compositeKey(prepared.namespace, prepared.storageKey),
          new Uint8Array(checkedData),
        );
      },
      read: async (namespace, key) => {
        const staged = overlay.get(compositeKey(namespace, key));
        if (staged !== undefined) {
          return staged === null ? null : new Uint8Array(staged);
        }
        return this.read(namespace, key);
      },
      delete: async (namespace, key) => {
        const composite = compositeKey(namespace, key);
        const staged = overlay.get(composite);
        const existed =
          staged !== undefined
            ? staged !== null
            : this.db.getBinary(composite) !== undefined;
        overlay.set(composite, null);
        return existed;
      },
    };
    const result = await fn(txn);
    if (overlay.size > 0) {
      this.db.transactionSync(() => {
        for (const [composite, value] of overlay) {
          if (value === null) {
            this.db.removeSync(composite);
          } else {
            this.db.putSync(composite, this.lmdb.asBinary(value));
          }
        }
      });
    }
    return result;
  }

  /**
   * Synchronous, read-only ciphertext view for the D2 export path. The
   * approval gate's `approvalTargetArgs` callback is synchronous, and the
   * export-scope fingerprint must be computable at gate time without
   * decrypting anything — LMDB range reads are synchronous under the hood,
   * so this exposes them directly. Reads only; all writes stay behind the
   * SDW write gate.
   */
  listNamespaceEntriesSync(
    namespace: string,
  ): ReadonlyArray<{ key: string; data: Uint8Array }> {
    const start = compositeKey(namespace, "");
    const end = `${compositeKey(namespace, "")}\uffff`;
    const entries: Array<{ key: string; data: Uint8Array }> = [];
    for (const entry of this.db.getRange({ start, end })) {
      const parsed = splitCompositeKey(entry.key);
      if (parsed === null || parsed.namespace !== namespace) continue;
      if (!(entry.value instanceof Uint8Array)) continue;
      entries.push({ key: parsed.key, data: new Uint8Array(entry.value) });
    }
    return entries;
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
