import type { StorageBackend } from "../storage/interface.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { documentChunkKey, documentKey } from "./grammar.js";
import {
  SDW_DOCUMENT_CORPUS_HKDF_INFO,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  type SdwDocumentChunkRecord,
  type SdwDocumentRecord,
} from "./records.js";
import { mintPersistable, sdwBackendWrite, type Persistable, type Taint } from "./write-gate.js";
import { decodeSdwRecord } from "./store-codec.js";

export interface SdwDocumentCorpusStoreOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
}

export interface SdwCorpusTxn {
  writePersistable<T extends SdwDocumentRecord | SdwDocumentChunkRecord>(
    persistable: Persistable<T>,
    encryptionKey: Uint8Array,
    fortressId: string,
  ): Promise<void>;
  read(namespace: string, key: string): Promise<Uint8Array | null>;
}

export class SdwDocumentCorpusStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;

  constructor(options: SdwDocumentCorpusStoreOptions) {
    this.storage = options.storage;
    this.encryptionKey = derivePurposeKey(options.masterKey, SDW_DOCUMENT_CORPUS_HKDF_INFO);
    this.fortressId = options.fortressId;
  }

  async putDocument(record: SdwDocumentRecord, taint: Taint, txn?: SdwCorpusTxn): Promise<void> {
    const storageKey = documentKey(record.document_id);
    const persistable = mintPersistable(
      { value: record, taint },
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      storageKey,
      this.fortressId,
    );
    if (txn !== undefined) {
      await txn.writePersistable(persistable, this.encryptionKey, this.fortressId);
      return;
    }
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId);
  }

  async putChunk(record: SdwDocumentChunkRecord, taint: Taint, txn?: SdwCorpusTxn): Promise<void> {
    const storageKey = documentChunkStorageKey(record);
    const persistable = mintPersistable(
      { value: record, taint },
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      storageKey,
      this.fortressId,
    );
    if (txn !== undefined) {
      await txn.writePersistable(persistable, this.encryptionKey, this.fortressId);
      return;
    }
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId);
  }

  async getDocument(documentId: string, txn?: SdwCorpusTxn): Promise<SdwDocumentRecord | null> {
    const storageKey = documentKey(documentId);
    const raw = await (txn ?? this.storage).read(SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey);
    if (raw === null) return null;
    return decodeSdwRecord<SdwDocumentRecord>(raw, {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE,
      storageKey,
      fortressId: this.fortressId,
      encryptionKey: this.encryptionKey,
      expectedKind: "document",
      verifyIdentity: (record) => record.document_id === documentId,
    });
  }

  async getChunk(documentId: string, chunkOrdinal: number, chunkId: string): Promise<SdwDocumentChunkRecord | null> {
    const storageKey = documentChunkKey(documentId, padChunkOrdinal(chunkOrdinal), chunkId);
    const raw = await this.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey);
    if (raw === null) return null;
    return decodeSdwRecord<SdwDocumentChunkRecord>(raw, {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE,
      storageKey,
      fortressId: this.fortressId,
      encryptionKey: this.encryptionKey,
      expectedKind: "document_chunk",
      verifyIdentity: (record) =>
        record.document_id === documentId &&
        record.chunk_id === chunkId &&
        record.chunk_ordinal === chunkOrdinal,
    });
  }
}

export function documentChunkStorageKey(record: SdwDocumentChunkRecord): string {
  return documentChunkKey(record.document_id, padChunkOrdinal(record.chunk_ordinal), record.chunk_id);
}

export function padChunkOrdinal(ordinal: number): string {
  if (!Number.isSafeInteger(ordinal) || ordinal < 0) {
    throw new Error("Invalid SDW document chunk ordinal");
  }
  return String(ordinal).padStart(6, "0");
}
