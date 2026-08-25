import type { StorageBackend } from "../storage/interface.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  SDW_MEMORY_PROVENANCE_COMPLETION_KEY,
  SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY,
  SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY,
  documentChunkKey,
  documentKey,
  documentProvenanceKey,
  documentProvenanceStatusKey,
} from "./grammar.js";
import {
  SDW_DOCUMENT_CORPUS_HKDF_INFO,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_REPLAY_ANCHOR_KEY,
  type SdwDocumentChunkRecord,
  type SdwDocumentRecord,
  type SdwMemoryProvenanceCompletionRecord,
  type SdwMemoryProvenanceMigrationActiveRecord,
  type SdwMemoryProvenanceMigrationJournalRecord,
  type SdwMemoryProvenanceRecord,
  type SdwMemoryProvenanceStatusRecord,
  type SdwRecord,
} from "./records.js";
import {
  mintPersistable,
  restoreRawSdwBackendWrite,
  sdwBackendWrite,
  type MintPersistableOptions,
  type Persistable,
  type Taint,
} from "./write-gate.js";
import { decodeSdwRecord } from "./store-codec.js";
import { readReplayAnchor } from "./replay-anchor.js";

export interface SdwDocumentCorpusStoreOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
}

export interface SdwCorpusTxn {
  write(namespace: string, key: string, data: Uint8Array): Promise<void>;
  writePersistable<T extends SdwRecord>(
    persistable: Persistable<T>,
    encryptionKey: Uint8Array,
    fortressId: string,
    options?: MintPersistableOptions,
  ): Promise<void>;
  read(namespace: string, key: string): Promise<Uint8Array | null>;
  delete(namespace: string, key: string): Promise<boolean>;
}

export class SdwDocumentCorpusStore {
  private readonly storage: StorageBackend;
  private readonly masterKey: Uint8Array;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;

  constructor(options: SdwDocumentCorpusStoreOptions) {
    this.storage = options.storage;
    this.masterKey = options.masterKey;
    this.encryptionKey = derivePurposeKey(options.masterKey, SDW_DOCUMENT_CORPUS_HKDF_INFO);
    this.fortressId = options.fortressId;
  }

  /**
   * Mint a document persistable WITHOUT writing it. Minting runs the grammar
   * checks and the fail-closed secret classifier and has no side effects, so a
   * caller that wants to know whether a record WOULD be accepted must call this
   * rather than reimplement the checks; a reimplementation is free to drift
   * from the enforced gate, this cannot.
   */
  mintDocument(
    record: SdwDocumentRecord,
    taint: Taint,
    options?: MintPersistableOptions,
  ): Persistable<SdwDocumentRecord> {
    return mintPersistable(
      { value: record, taint },
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentKey(record.document_id),
      this.fortressId,
      options,
    );
  }

  /** Chunk counterpart of {@link mintDocument}: same gate, no side effects. */
  mintChunk(
    record: SdwDocumentChunkRecord,
    taint: Taint,
    options?: MintPersistableOptions,
  ): Persistable<SdwDocumentChunkRecord> {
    return mintPersistable(
      { value: record, taint },
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentChunkStorageKey(record),
      this.fortressId,
      options,
    );
  }

  mintProvenance(record: SdwMemoryProvenanceRecord, taint: Taint): Persistable<SdwMemoryProvenanceRecord> {
    return mintPersistable({ value: record, taint }, SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(record.document_id), this.fortressId);
  }

  mintProvenanceStatus(record: SdwMemoryProvenanceStatusRecord, taint: Taint): Persistable<SdwMemoryProvenanceStatusRecord> {
    return mintPersistable({ value: record, taint }, SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceStatusKey(record.document_id), this.fortressId);
  }

  async putDocument(
    record: SdwDocumentRecord,
    taint: Taint,
    txn?: SdwCorpusTxn,
    options?: MintPersistableOptions,
  ): Promise<void> {
    const persistable = this.mintDocument(record, taint, options);
    if (txn !== undefined) {
      await txn.writePersistable(persistable, this.encryptionKey, this.fortressId, options);
      return;
    }
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId, options);
  }

  async putChunk(
    record: SdwDocumentChunkRecord,
    taint: Taint,
    txn?: SdwCorpusTxn,
    options?: MintPersistableOptions,
  ): Promise<void> {
    const persistable = this.mintChunk(record, taint, options);
    if (txn !== undefined) {
      await txn.writePersistable(persistable, this.encryptionKey, this.fortressId, options);
      return;
    }
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId, options);
  }

  async putProvenance(record: SdwMemoryProvenanceRecord, taint: Taint, txn?: SdwCorpusTxn): Promise<void> {
    const persistable = this.mintProvenance(record, taint);
    if (txn !== undefined) {
      await txn.writePersistable(persistable, this.encryptionKey, this.fortressId);
      return;
    }
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId);
  }

  async putProvenanceStatus(record: SdwMemoryProvenanceStatusRecord, taint: Taint, txn?: SdwCorpusTxn): Promise<void> {
    const persistable = this.mintProvenanceStatus(record, taint);
    if (txn !== undefined) {
      await txn.writePersistable(persistable, this.encryptionKey, this.fortressId);
      return;
    }
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId);
  }

  /**
   * Restore-only counterpart of putDocument, used ONLY by
   * SdwMemoryBackendAdapter.restoreAndVerifyPriorPassages to replay the
   * EXACT ciphertext bytes already read out of the SAME encrypted store
   * before the failed batch began (getDocumentRaw, called by
   * capturePriorPassages) -- never a fresh re-encryption. `raw` is decoded
   * once here (decrypt + parse, the same identity checks getDocument runs)
   * to prove it is genuinely valid ciphertext for THIS fortress/key, and
   * `expectedContentHash` must equal the decoded record's own content_hash:
   * `raw` and `expectedContentHash` are two independent things the caller
   * supplies, so a mismatched pairing (a mixup bug, or a caller passing
   * bytes from a different document with an unrelated hash) is refused
   * before the write, not trusted on the caller's say-so. Only after both
   * checks pass are the ORIGINAL bytes written back unchanged
   * (restoreRawSdwBackendWrite never re-encrypts). No transactional (`txn`)
   * form exists because this path is only ever reached from the
   * NON-transactional rollback branch (a transactional batch's failure
   * discards the whole staged overlay atomically, so there is nothing to
   * roll back to).
   */
  async restorePriorDocument(
    documentId: string,
    raw: Uint8Array,
    expectedContentHash: string,
  ): Promise<void> {
    const storageKey = documentKey(documentId);
    const decoded = decodeSdwRecord<SdwDocumentRecord>(raw, {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE,
      storageKey,
      fortressId: this.fortressId,
      encryptionKey: this.encryptionKey,
      expectedKind: "document",
      verifyIdentity: (record) => record.document_id === documentId,
    });
    if (decoded.content_hash !== expectedContentHash) {
      throw new Error(
        "Refusing to restore a document whose decoded content_hash does not match the captured prior hash",
      );
    }
    await restoreRawSdwBackendWrite(this.storage, SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey, raw);
  }

  /** Chunk counterpart of {@link restorePriorDocument}, same verify-then-write-verbatim discipline. */
  async restorePriorChunk(
    documentId: string,
    chunkOrdinal: number,
    chunkId: string,
    raw: Uint8Array,
    expectedContentHash: string,
  ): Promise<void> {
    const storageKey = documentChunkKey(documentId, padChunkOrdinal(chunkOrdinal), chunkId);
    const decoded = decodeSdwRecord<SdwDocumentChunkRecord>(raw, {
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
    if (decoded.content_hash !== expectedContentHash) {
      throw new Error(
        "Refusing to restore a chunk whose decoded content_hash does not match the captured prior hash",
      );
    }
    await restoreRawSdwBackendWrite(this.storage, SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey, raw);
  }

  async restorePriorProvenance(documentId: string, raw: Uint8Array): Promise<void> {
    const storageKey = documentProvenanceKey(documentId);
    decodeSdwRecord<SdwMemoryProvenanceRecord>(raw, {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey, fortressId: this.fortressId,
      encryptionKey: this.encryptionKey, expectedKind: "memory_provenance",
      verifyIdentity: (record) => record.document_id === documentId,
    });
    await restoreRawSdwBackendWrite(this.storage, SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey, raw);
  }

  async restorePriorProvenanceStatus(documentId: string, raw: Uint8Array): Promise<void> {
    const storageKey = documentProvenanceStatusKey(documentId);
    decodeSdwRecord<SdwMemoryProvenanceStatusRecord>(raw, {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey, fortressId: this.fortressId,
      encryptionKey: this.encryptionKey, expectedKind: "memory_provenance_status",
      verifyIdentity: (record) => record.document_id === documentId,
    });
    await restoreRawSdwBackendWrite(this.storage, SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey, raw);
  }

  /**
   * C3 rollback restores the exact captured companion pre-image even when the
   * whole reason for quarantine was that those ciphertext bytes do not decode.
   * Scope stays fixed to one reconstructed `prov.<document_id>` key; callers
   * cannot select a namespace or arbitrary storage key.
   */
  async restoreMemoryMigrationProvenancePreimage(
    documentId: string,
    raw: Uint8Array,
  ): Promise<void> {
    await restoreRawSdwBackendWrite(
      this.storage,
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(documentId),
      raw,
    );
  }

  /** Status counterpart of {@link restoreMemoryMigrationProvenancePreimage}. */
  async restoreMemoryMigrationProvenanceStatusPreimage(
    documentId: string,
    raw: Uint8Array,
  ): Promise<void> {
    await restoreRawSdwBackendWrite(
      this.storage,
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceStatusKey(documentId),
      raw,
    );
  }

  /**
   * C3 rollback boundary for the three exact encrypted migration metadata
   * records. The caller cannot use this to replay arbitrary `_sdw_meta` bytes:
   * the key selects a fixed kind and the ciphertext is authenticated for that
   * exact namespace/key/fortress before the original bytes are restored.
   */
  async restorePriorMemoryMigrationMetadata(
    storageKey: string,
    raw: Uint8Array,
  ): Promise<void> {
    if (storageKey === SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY) {
      decodeSdwRecord<SdwMemoryProvenanceMigrationActiveRecord>(raw, {
        namespace: SDW_META_NAMESPACE, storageKey, fortressId: this.fortressId,
        encryptionKey: this.encryptionKey, expectedKind: "memory_provenance_migration_active",
        verifyIdentity: (record) => record.migration_id === "MI_C_SDW_MEMORY_PROVENANCE_V1",
      });
    } else if (storageKey === SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY) {
      decodeSdwRecord<SdwMemoryProvenanceMigrationJournalRecord>(raw, {
        namespace: SDW_META_NAMESPACE, storageKey, fortressId: this.fortressId,
        encryptionKey: this.encryptionKey, expectedKind: "memory_provenance_migration_journal",
        verifyIdentity: (record) => record.migration_id === "MI_C_SDW_MEMORY_PROVENANCE_V1",
      });
    } else if (storageKey === SDW_MEMORY_PROVENANCE_COMPLETION_KEY) {
      decodeSdwRecord<SdwMemoryProvenanceCompletionRecord>(raw, {
        namespace: SDW_META_NAMESPACE, storageKey, fortressId: this.fortressId,
        encryptionKey: this.encryptionKey, expectedKind: "memory_provenance_completion",
        verifyIdentity: (record) => record.migration_id === "MI_C_SDW_MEMORY_PROVENANCE_V1",
      });
    } else {
      throw new Error("Refusing to restore an unrecognized SDW memory migration metadata key");
    }
    await restoreRawSdwBackendWrite(this.storage, SDW_META_NAMESPACE, storageKey, raw);
  }

  /** C3 exact replay-anchor pre-image restore, after authenticating its MAC. */
  async restorePriorReplayAnchor(raw: Uint8Array): Promise<void> {
    const anchor = await readReplayAnchor({
      read: async (namespace: string, key: string) =>
        namespace === SDW_META_NAMESPACE && key === SDW_REPLAY_ANCHOR_KEY ? raw : null,
    }, this.masterKey);
    if (anchor.status !== "valid") {
      throw new Error("Refusing to restore an unauthenticated SDW replay anchor");
    }
    await restoreRawSdwBackendWrite(this.storage, SDW_META_NAMESPACE, SDW_REPLAY_ANCHOR_KEY, raw);
  }

  async getDocument(documentId: string, txn?: SdwCorpusTxn): Promise<SdwDocumentRecord | null> {
    return (await this.getDocumentRaw(documentId, txn))?.record ?? null;
  }

  /**
   * Raw-plus-decoded counterpart of {@link getDocument}: returns the exact
   * still-encrypted bytes alongside the decoded record. Used by
   * SdwMemoryBackendAdapter.capturePriorPassages to capture prior state for
   * a byte-verbatim restore; getDocument's plain
   * `| null` shape stays the normal read path everyone else uses.
   */
  async getDocumentRaw(
    documentId: string,
    txn?: SdwCorpusTxn,
  ): Promise<{ readonly raw: Uint8Array; readonly record: SdwDocumentRecord } | null> {
    const storageKey = documentKey(documentId);
    const raw = await (txn ?? this.storage).read(SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey);
    if (raw === null) return null;
    const record = decodeSdwRecord<SdwDocumentRecord>(raw, {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE,
      storageKey,
      fortressId: this.fortressId,
      encryptionKey: this.encryptionKey,
      expectedKind: "document",
      verifyIdentity: (record) => record.document_id === documentId,
    });
    return { raw, record };
  }

  async getChunk(documentId: string, chunkOrdinal: number, chunkId: string, txn?: SdwCorpusTxn): Promise<SdwDocumentChunkRecord | null> {
    return (await this.getChunkRaw(documentId, chunkOrdinal, chunkId, txn))?.record ?? null;
  }

  /** Raw-plus-decoded counterpart of {@link getChunk}; see {@link getDocumentRaw}. */
  async getChunkRaw(
    documentId: string,
    chunkOrdinal: number,
    chunkId: string,
    txn?: SdwCorpusTxn,
  ): Promise<{ readonly raw: Uint8Array; readonly record: SdwDocumentChunkRecord } | null> {
    const storageKey = documentChunkKey(documentId, padChunkOrdinal(chunkOrdinal), chunkId);
    const raw = await (txn ?? this.storage).read(SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey);
    if (raw === null) return null;
    const record = decodeSdwRecord<SdwDocumentChunkRecord>(raw, {
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
    return { raw, record };
  }

  async getProvenanceRaw(documentId: string, txn?: SdwCorpusTxn): Promise<{ readonly raw: Uint8Array; readonly record: SdwMemoryProvenanceRecord } | null> {
    const storageKey = documentProvenanceKey(documentId);
    const raw = await (txn ?? this.storage).read(SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey);
    if (raw === null) return null;
    const record = decodeSdwRecord<SdwMemoryProvenanceRecord>(raw, {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey, fortressId: this.fortressId,
      encryptionKey: this.encryptionKey, expectedKind: "memory_provenance",
      verifyIdentity: (candidate) => candidate.document_id === documentId,
    });
    return { raw, record };
  }

  async getProvenanceStatusRaw(documentId: string, txn?: SdwCorpusTxn): Promise<{ readonly raw: Uint8Array; readonly record: SdwMemoryProvenanceStatusRecord } | null> {
    const storageKey = documentProvenanceStatusKey(documentId);
    const raw = await (txn ?? this.storage).read(SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey);
    if (raw === null) return null;
    const record = decodeSdwRecord<SdwMemoryProvenanceStatusRecord>(raw, {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey, fortressId: this.fortressId,
      encryptionKey: this.encryptionKey, expectedKind: "memory_provenance_status",
      verifyIdentity: (candidate) => candidate.document_id === documentId,
    });
    return { raw, record };
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
