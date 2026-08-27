import { randomBytes } from "node:crypto";
import type { StorageBackend } from "../storage/interface.js";
import { withCrossProcessLock } from "../storage/cross-process-lock.js";
import { ROTATION_JOURNAL_KEY } from "../core/master-custody.js";
import {
  hasInterruptedExitImport,
  withExitAdmissionLock,
} from "../storage/exit-import-journal.js";
import { constantTimeEqual, toBase64url } from "../core/encoding.js";
import { hash } from "../core/hashing.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { SdwValidationError } from "./errors.js";
import {
  SDW_MEMORY_PROVENANCE_COMPLETION_KEY,
  SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY,
  SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY,
  documentProvenanceKey,
  documentProvenanceStatusKey,
} from "./grammar.js";
import {
  SDW_DOCUMENT_CORPUS_HKDF_INFO,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_REPLAY_ANCHOR_KEY,
  type SdwMemoryIntegrityState,
  type SdwMemoryProvenanceCompletionRecord,
  type SdwMemoryProvenanceMigrationActiveRecord,
  type SdwMemoryProvenanceMigrationJournalRecord,
  type SdwRecord,
} from "./records.js";
import { SdwDocumentCorpusStore, padChunkOrdinal, type SdwCorpusTxn } from "./document-corpus-store.js";
import { decodeSdwRecord } from "./store-codec.js";
import {
  mintPersistable,
  prepareReplayAnchorWrite,
  sdwBackendWrite,
  passageContentHash,
} from "./write-gate.js";
import {
  MEMORY_BATCH_LOCK_NAMESPACE,
  MEMORY_BATCH_LOCK_TIMEOUT_MS,
  MEMORY_PROVENANCE_QUARANTINE_CANDIDATE_CAP,
  sdwMemoryCorpusBatchLockFile,
  withSdwMemoryCorpusMutationLock,
} from "./adapters/sdw-memory-backend.js";
import {
  createMemoryProvenanceCompanion,
  signMemoryOrigin,
  verifyMemoryProvenanceCompanion,
  type MemoryProvenanceCompanion,
  type MemoryProvenanceSigningHandle,
} from "./memory-provenance-contract.js";
import { readReplayAnchor, replayAnchorCounterSeq, upsertReplayAnchorCounter } from "./replay-anchor.js";

export const SDW_MEMORY_PROVENANCE_MIGRATION_ID = "MI_C_SDW_MEMORY_PROVENANCE_V1" as const;
export const SDW_MEMORY_PROVENANCE_COMPLETION_COUNTER_ID = "memory-provenance-v1" as const;
export const SDW_MEMORY_PROVENANCE_MIGRATION_PAGE_SIZE = 100;

export const SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS = Object.freeze({
  migrate: "sdw_memory_provenance_migrate",
  abort: "sdw_memory_provenance_abort_migration",
  repair: "sdw_memory_provenance_repair_completion_marker",
  status: "sdw_memory_provenance_migration_status",
} as const);

type FaultBoundary =
  | "after_active_write"
  | "after_provenance_write"
  | "after_status_write"
  | "after_journal_write"
  | "after_completion_marker_write"
  | "after_completion_anchor_write"
  | "after_repair_marker_write"
  | "before_rollback_restore"
  | "after_rollback_restore";

export interface SdwMemoryProvenanceMigrationOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly ownerRef: string;
  readonly resolvePrimarySigningHandle: () => MemoryProvenanceSigningHandle;
  readonly resolveSignerPublicKey: (identityId: string, did: string) => Uint8Array | undefined;
  readonly now?: () => string;
  /** Tightening-only test seam. */
  readonly pageSize?: number;
  /** Tightening-only test seam for the frozen corpus-wide candidate cap. */
  readonly candidateCap?: number;
  /** Test-only fault injection; production composition never supplies it. */
  readonly __fault?: (boundary: FaultBoundary, key?: string) => void | Promise<void>;
}

export interface SdwMemoryMigrationProgress {
  readonly state: SdwMemoryIntegrityState;
  readonly run_id?: string;
  readonly scanned: number;
  readonly migrated: number;
  readonly verified: number;
  readonly quarantined: number;
  readonly unsigned: number;
  readonly cursor: string | null;
  readonly completed: boolean;
}

interface CandidateAction {
  readonly documentId: string;
  readonly outcome: "verified" | "migrated" | "quarantined" | "unsigned";
  readonly provenance?: MemoryProvenanceCompanion;
  readonly clearStatus: boolean;
  readonly quarantine?: {
    readonly reason: string;
    readonly contentHash: string;
    readonly provenanceSha256: string;
  };
}

interface RawSnapshot {
  readonly namespace: typeof SDW_META_NAMESPACE | typeof SDW_DOCUMENT_CORPUS_NAMESPACE;
  readonly key: string;
  readonly raw: Uint8Array | null;
}

class MigrationMetaStore {
  private readonly encryptionKey: Uint8Array;

  constructor(
    private readonly storage: StorageBackend,
    masterKey: Uint8Array,
    private readonly fortressId: string,
  ) {
    // C3 deliberately reuses the existing encrypted SDW document-corpus
    // purpose key; custody rotation must not acquire a parallel memory key.
    this.encryptionKey = derivePurposeKey(masterKey, SDW_DOCUMENT_CORPUS_HKDF_INFO);
  }

  async read<T extends SdwRecord>(
    key: string,
    kind: T["kind"],
    txn?: SdwCorpusTxn,
  ): Promise<{ readonly raw: Uint8Array; readonly record: T } | null> {
    const raw = await (txn ?? this.storage).read(SDW_META_NAMESPACE, key);
    if (raw === null) return null;
    const record = decodeSdwRecord<T>(raw, {
      namespace: SDW_META_NAMESPACE,
      storageKey: key,
      fortressId: this.fortressId,
      encryptionKey: this.encryptionKey,
      expectedKind: kind,
      verifyIdentity: (candidate) =>
        (candidate as { readonly migration_id?: unknown }).migration_id ===
        SDW_MEMORY_PROVENANCE_MIGRATION_ID,
    });
    return { raw, record };
  }

  async put<T extends SdwRecord>(record: T, key: string, txn?: SdwCorpusTxn): Promise<void> {
    const persistable = mintPersistable(
      { value: record, taint: "system_generated" },
      SDW_META_NAMESPACE,
      key,
      this.fortressId,
    );
    if (txn !== undefined) {
      await txn.writePersistable(persistable, this.encryptionKey, this.fortressId);
      return;
    }
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId);
  }
}

export class SdwMemoryProvenanceMigration {
  private readonly storage: StorageBackend;
  private readonly masterKey: Uint8Array;
  private readonly fortressId: string;
  private readonly ownerRef: string;
  private readonly documentPrefix: string;
  private readonly corpus: SdwDocumentCorpusStore;
  private readonly meta: MigrationMetaStore;
  private readonly resolvePrimarySigningHandle: () => MemoryProvenanceSigningHandle;
  private readonly resolveSignerPublicKey: (identityId: string, did: string) => Uint8Array | undefined;
  private readonly now: () => string;
  private readonly pageSize: number;
  private readonly candidateCap: number;
  private readonly fault?: SdwMemoryProvenanceMigrationOptions["__fault"];

  constructor(options: SdwMemoryProvenanceMigrationOptions) {
    this.storage = options.storage;
    this.masterKey = options.masterKey;
    this.fortressId = options.fortressId;
    this.ownerRef = options.ownerRef;
    // Completion is fortress-wide over the frozen doc.mem.* candidate set.
    // The configured owner is still the only owner this migration can bind;
    // an unexpected owner is quarantined and blocks completion, never ignored.
    this.documentPrefix = "doc.mem.";
    this.corpus = new SdwDocumentCorpusStore(options);
    this.meta = new MigrationMetaStore(options.storage, options.masterKey, options.fortressId);
    this.resolvePrimarySigningHandle = options.resolvePrimarySigningHandle;
    this.resolveSignerPublicKey = options.resolveSignerPublicKey;
    this.now = options.now ?? (() => new Date().toISOString());
    const pageSize = options.pageSize ?? SDW_MEMORY_PROVENANCE_MIGRATION_PAGE_SIZE;
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > SDW_MEMORY_PROVENANCE_MIGRATION_PAGE_SIZE) {
      throw new SdwValidationError("invalid_count", "Invalid SDW memory migration page size");
    }
    this.pageSize = pageSize;
    const candidateCap = options.candidateCap ?? MEMORY_PROVENANCE_QUARANTINE_CANDIDATE_CAP;
    if (!Number.isSafeInteger(candidateCap) || candidateCap < 1 ||
        candidateCap > MEMORY_PROVENANCE_QUARANTINE_CANDIDATE_CAP) {
      throw new SdwValidationError("invalid_count", "Invalid SDW memory migration candidate cap");
    }
    this.candidateCap = candidateCap;
    this.fault = options.__fault;
  }

  async getState(): Promise<SdwMemoryIntegrityState> {
    const anchor = await readReplayAnchor(this.storage, this.masterKey);
    const anchorEpoch = anchor.status === "valid"
      ? replayAnchorCounterSeq(
          anchor.data.memory_provenance_completion ?? [],
          SDW_MEMORY_PROVENANCE_COMPLETION_COUNTER_ID,
        )
      : 0;
    const marker = await this.meta.read<SdwMemoryProvenanceCompletionRecord>(
      SDW_MEMORY_PROVENANCE_COMPLETION_KEY,
      "memory_provenance_completion",
    );
    if (anchorEpoch > 0 && marker === null) return "state_MARKER_ABSENT_POST_COMPLETE";
    if (marker !== null) {
      if (anchorEpoch !== marker.record.completion_epoch || anchorEpoch < 1) {
        throw new SdwValidationError("auth_failed", "SDW memory provenance completion epoch mismatch");
      }
      return "state_COMPLETE";
    }
    const active = await this.meta.read<SdwMemoryProvenanceMigrationActiveRecord>(
      SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY,
      "memory_provenance_migration_active",
    );
    const journal = await this.readJournal();
    if (active === null) {
      if (journal === null || journal.record.status === "abandoned") return "state_PRE_MIGRATION";
      if (journal.record.status === "completed") return "state_MARKER_ABSENT_POST_COMPLETE";
      throw new SdwValidationError("auth_failed", "SDW memory provenance active pointer is absent");
    }
    if (journal === null || journal.record.status !== "active" || journal.record.run_id !== active.record.run_id) {
      throw new SdwValidationError("auth_failed", "SDW memory provenance migration journal mismatch");
    }
    return "state_MIGRATING";
  }

  async status(): Promise<SdwMemoryMigrationProgress> {
    const state = await this.getState();
    const journal = await this.readJournal();
    return {
      state,
      ...(journal === null ? {} : { run_id: journal.record.run_id }),
      scanned: journal?.record.scanned ?? 0,
      migrated: journal?.record.migrated ?? 0,
      verified: journal?.record.verified ?? 0,
      quarantined: journal?.record.quarantined ?? 0,
      unsigned: journal?.record.unsigned ?? 0,
      cursor: journal?.record.cursor ?? null,
      completed: state === "state_COMPLETE",
    };
  }

  async migratePage(): Promise<SdwMemoryMigrationProgress> {
    return this.withMigrationLock(async (txn) => {
      const initialState = await this.getStateInLock(txn);
      if (initialState === "state_COMPLETE") return this.statusInLock(txn, initialState);
      if (initialState === "state_MARKER_ABSENT_POST_COMPLETE") {
        throw new SdwValidationError("auth_failed", "Repair the completion marker before migration can continue");
      }
      const entries = await this.candidateEntries();
      if (entries.length > this.candidateCap) {
        throw new SdwValidationError("candidate_cap", "SDW memory migration candidate cap exceeded");
      }
      let journal = await this.readJournal(txn);
      if (initialState === "state_PRE_MIGRATION") {
        journal = await this.startRun(entries.length, txn);
      }
      if (journal === null || journal.record.status !== "active") {
        throw new SdwValidationError("auth_failed", "Active SDW memory migration journal is unavailable");
      }
      if (journal.record.failure_code === "partial_scope") {
        throw new SdwValidationError(
          "partial_scope",
          "SDW memory migration requires operator repair after an unverifiable rollback",
        );
      }

      const signer = this.resolvePrimarySigningHandle();
      this.assertJournalSigner(journal.record, signer);
      // An interrupted run never trusts its cursor blindly: all skipped rows
      // are fully reverified before the next page can advance.
      const skipped = journal.record.cursor === null
        ? []
        : entries.filter((entry) => entry.key.localeCompare(`doc.${journal!.record.cursor!}`) <= 0);
      for (const entry of skipped) {
        const check = await this.inspectCandidate(entry.key.slice("doc.".length), journal.record, signer, false, txn);
        if (check.outcome !== "verified") {
          const current = await this.verifyAllCandidates(entries, txn);
          const blocked: SdwMemoryProvenanceMigrationJournalRecord = {
            ...journal.record,
            verified: current.verified,
            quarantined: current.quarantined,
            unsigned: current.unsigned,
            updated_at: this.now(),
          };
          await this.commitPage([check], blocked, signer, txn);
          return this.statusInLock(txn, "state_MIGRATING", blocked);
        }
      }

      const remaining = journal.record.cursor === null
        ? entries
        : entries.filter((entry) => entry.key.localeCompare(`doc.${journal!.record.cursor!}`) > 0);
      const page = remaining.slice(0, this.pageSize);
      const actions: CandidateAction[] = [];
      for (const entry of page) {
        actions.push(await this.inspectCandidate(entry.key.slice("doc.".length), journal.record, signer, true, txn));
      }

      const nextJournal: SdwMemoryProvenanceMigrationJournalRecord = {
        ...journal.record,
        cursor: page.length === 0 ? journal.record.cursor : page[page.length - 1]!.key.slice("doc.".length),
        scanned: journal.record.scanned + page.length,
        migrated: journal.record.migrated + actions.filter((action) => action.outcome === "migrated").length,
        verified: journal.record.verified + actions.filter((action) => action.outcome === "verified").length,
        quarantined: journal.record.quarantined + actions.filter((action) => action.outcome === "quarantined").length,
        unsigned: Math.max(0, entries.length - journal.record.scanned - page.length),
        updated_at: this.now(),
      };
      await this.commitPage(actions, nextJournal, signer, txn);
      journal = { raw: new Uint8Array(), record: nextJournal };

      if (remaining.length > page.length) return this.statusInLock(txn, "state_MIGRATING", nextJournal);
      const final = await this.verifyAllCandidates(entries, txn);
      if (!final.complete) {
        const blocked = { ...nextJournal, quarantined: final.quarantined, unsigned: final.unsigned, updated_at: this.now() };
        await this.meta.put(blocked, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY, txn);
        return this.statusInLock(txn, "state_MIGRATING", blocked);
      }
      await this.completeRun(nextJournal, entries.length, txn);
      return this.statusInLock(txn, "state_COMPLETE", {
        ...nextJournal,
        status: "completed",
        verified: entries.length,
        quarantined: 0,
        unsigned: 0,
      });
    });
  }

  async abortMigration(): Promise<SdwMemoryMigrationProgress> {
    return this.withMigrationLock(async (txn) => {
      if (await this.getStateInLock(txn) !== "state_MIGRATING") {
        throw new SdwValidationError("schema_mismatch", "No recoverable SDW memory migration is active");
      }
      if (await this.meta.read<SdwMemoryProvenanceCompletionRecord>(
        SDW_MEMORY_PROVENANCE_COMPLETION_KEY,
        "memory_provenance_completion",
        txn,
      ) !== null) {
        throw new SdwValidationError("auth_failed", "A completed migration cannot be aborted");
      }
      const journal = await this.requireActiveJournal(txn);
      if (journal.failure_code === "partial_scope") {
        throw new SdwValidationError("partial_scope", "An unverifiable migration rollback cannot be abandoned");
      }
      const abandoned: SdwMemoryProvenanceMigrationJournalRecord = {
        ...journal,
        status: "abandoned",
        updated_at: this.now(),
      };
      const snapshots = txn === undefined
        ? await this.captureSnapshots([
            { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY },
            { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY },
          ])
        : [];
      try {
        await this.meta.put(abandoned, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY, txn);
        await (txn ?? this.storage).delete(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY);
      } catch (error) {
        if (txn !== undefined) throw error;
        await this.restoreSnapshotsOrThrow(snapshots, error);
      }
      return this.statusInLock(txn, "state_PRE_MIGRATION", abandoned);
    });
  }

  async repairCompletionMarker(): Promise<SdwMemoryMigrationProgress> {
    return this.withMigrationLock(async (txn) => {
      if (await this.getStateInLock(txn) !== "state_MARKER_ABSENT_POST_COMPLETE") {
        throw new SdwValidationError("schema_mismatch", "Completion-marker repair is not required");
      }
      const entries = await this.candidateEntries();
      if (entries.length > this.candidateCap) {
        throw new SdwValidationError("candidate_cap", "SDW memory migration candidate cap exceeded");
      }
      const final = await this.verifyAllCandidates(entries, txn);
      if (!final.complete) {
        throw new SdwValidationError("auth_failed", "Completion marker repair refused: full verification did not pass");
      }
      const anchor = await readReplayAnchor(txn ?? this.storage, this.masterKey);
      if (anchor.status !== "valid") {
        throw new SdwValidationError("auth_failed", "Completion marker repair refused: replay anchor unavailable");
      }
      const epoch = replayAnchorCounterSeq(
        anchor.data.memory_provenance_completion ?? [],
        SDW_MEMORY_PROVENANCE_COMPLETION_COUNTER_ID,
      );
      if (epoch < 1) throw new SdwValidationError("auth_failed", "Completion marker repair epoch is invalid");
      const snapshots = txn === undefined
        ? await this.captureSnapshots([
            { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_COMPLETION_KEY },
          ])
        : [];
      try {
        await this.meta.put({
          kind: "memory_provenance_completion",
          version: 1,
          migration_id: SDW_MEMORY_PROVENANCE_MIGRATION_ID,
          completion_epoch: epoch,
          candidate_count: entries.length,
          completed_at: this.now(),
        }, SDW_MEMORY_PROVENANCE_COMPLETION_KEY, txn);
        await this.fault?.("after_repair_marker_write");
      } catch (error) {
        if (txn !== undefined) throw error;
        await this.restoreSnapshotsOrThrow(snapshots, error);
      }
      return this.statusInLock(txn, "state_COMPLETE");
    });
  }

  private async startRun(candidateCount: number, txn?: SdwCorpusTxn) {
    const signer = this.resolvePrimarySigningHandle();
    const timestamp = this.now();
    const runId = toBase64url(new Uint8Array(randomBytes(18)));
    const journal: SdwMemoryProvenanceMigrationJournalRecord = {
      kind: "memory_provenance_migration_journal",
      version: 1,
      migration_id: SDW_MEMORY_PROVENANCE_MIGRATION_ID,
      run_id: runId,
      status: "active",
      started_at: timestamp,
      observation_time: timestamp,
      source_signer_identity_id: signer.identity_id,
      source_signer_did: signer.did,
      cursor: null,
      scanned: 0,
      migrated: 0,
      verified: 0,
      quarantined: 0,
      unsigned: candidateCount,
      updated_at: timestamp,
    };
    const snapshots = txn === undefined
      ? await this.captureSnapshots([
          { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY },
          { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY },
        ])
      : [];
    try {
      await this.meta.put(journal, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY, txn);
      await this.meta.put({
        kind: "memory_provenance_migration_active",
        version: 1,
        migration_id: SDW_MEMORY_PROVENANCE_MIGRATION_ID,
        run_id: runId,
        updated_at: timestamp,
      }, SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY, txn);
    } catch (error) {
      if (txn !== undefined) throw error;
      await this.restoreSnapshotsOrThrow(snapshots, error);
    }
    // A process interruption after BOTH durable records is resumable. Keep
    // this fault outside the write-failure rollback catch to preserve that
    // crash schedule rather than erasing a successfully published run.
    await this.fault?.("after_active_write");
    return { raw: new Uint8Array(), record: journal };
  }

  private async inspectCandidate(
    documentId: string,
    journal: SdwMemoryProvenanceMigrationJournalRecord,
    signer: MemoryProvenanceSigningHandle,
    createMissing: boolean,
    txn?: SdwCorpusTxn,
  ): Promise<CandidateAction> {
    let document;
    try {
      document = await this.corpus.getDocument(documentId, txn);
    } catch {
      return this.quarantineAction(documentId, "document_auth_failed", "invalid", null);
    }
    if (document === null) {
      return this.quarantineAction(documentId, "document_owner_mismatch", "invalid", null);
    }
    if (!documentId.startsWith(`mem.${this.ownerRef}.`)) {
      const rawProvenance = await (txn ?? this.storage).read(
        SDW_DOCUMENT_CORPUS_NAMESPACE,
        documentProvenanceKey(documentId),
      );
      return this.quarantineAction(
        documentId,
        "document_owner_mismatch",
        document.content_hash,
        rawProvenance,
      );
    }
    try {
      const chunks: string[] = [];
      for (let ordinal = 0; ordinal < document.chunk_count; ordinal++) {
        const chunk = await this.corpus.getChunk(documentId, ordinal, `c${padChunkOrdinal(ordinal)}`, txn);
        if (chunk === null) throw new Error("missing chunk");
        chunks.push(chunk.text);
      }
      const text = chunks.join("");
      if (passageContentHash(text) !== document.content_hash) throw new Error("content hash mismatch");
    } catch {
      return this.quarantineAction(documentId, "content_hash_mismatch", document.content_hash, null);
    }
    const rawProvenance = await (txn ?? this.storage).read(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(documentId));
    const provenanceSha256 = digestRaw(rawProvenance);
    const status = await this.corpus.getProvenanceStatusRaw(documentId, txn);
    if (
      status !== null &&
      status.record.observed_content_hash === document.content_hash &&
      status.record.observed_provenance_sha256 === provenanceSha256
    ) {
      return { documentId, outcome: "quarantined", clearStatus: false };
    }
    if (rawProvenance !== null) {
      try {
        const provenance = await this.corpus.getProvenanceRaw(documentId, txn);
        if (provenance === null) throw new Error("missing provenance");
        const result = verifyMemoryProvenanceCompanion(provenance.record.companion, {
          size: 1,
          resolve: (identityId, did) => this.resolveSignerPublicKey(identityId, did),
        }, expectedBinding(this.fortressId, this.ownerRef, documentId, document));
        if (!result.ok) {
          return this.quarantineAction(documentId, result.error.code, document.content_hash, rawProvenance);
        }
        return { documentId, outcome: "verified", clearStatus: status !== null };
      } catch {
        return this.quarantineAction(documentId, "provenance_auth_failed", document.content_hash, rawProvenance);
      }
    }
    if (!createMissing) {
      return { documentId, outcome: "unsigned", clearStatus: false };
    }
    const passageId = documentId.slice(`mem.${this.ownerRef}.`.length);
    const origin = signMemoryOrigin({
      origin_fortress_id: this.fortressId,
      owner_ref: this.ownerRef,
      passage_id: passageId,
      content_hash: document.content_hash,
      chunk_count: document.chunk_count,
      author_agent_id: "unknown_legacy",
      ingress_channel: "legacy_migration",
      source_class: "legacy_unattested",
      recorded_at: journal.observation_time,
    }, signer);
    if (!origin.ok) throw new SdwValidationError("auth_failed", "Legacy memory provenance signing failed");
    const companion = createMemoryProvenanceCompanion(origin.value, {
      destination_fortress_id: this.fortressId,
      destination_owner_ref: this.ownerRef,
      passage_id: passageId,
      admission_channel: "legacy_migration",
      origin_trust_tier: "legacy_unattested",
      verification_basis: "legacy_local_observation",
      admitted_at: journal.observation_time,
    }, signer);
    if (!companion.ok) throw new SdwValidationError("auth_failed", "Legacy memory admission signing failed");
    return { documentId, outcome: "migrated", provenance: companion.value, clearStatus: status !== null };
  }

  private quarantineAction(
    documentId: string,
    reason: string,
    contentHash: string,
    rawProvenance: Uint8Array | null,
  ): CandidateAction {
    return {
      documentId,
      outcome: "quarantined",
      clearStatus: false,
      ...(contentHash === "invalid" ? {} : {
        quarantine: {
          reason,
          contentHash,
          provenanceSha256: digestRaw(rawProvenance),
        },
      }),
    };
  }

  private async commitPage(
    actions: readonly CandidateAction[],
    journal: SdwMemoryProvenanceMigrationJournalRecord,
    signer: MemoryProvenanceSigningHandle,
    txn?: SdwCorpusTxn,
  ): Promise<void> {
    this.assertJournalSigner(journal, this.resolvePrimarySigningHandle());
    this.assertSameSigner(signer, this.resolvePrimarySigningHandle());
    const touched: readonly { readonly namespace: RawSnapshot["namespace"]; readonly key: string }[] = [
      ...actions.flatMap((action) => [
        { namespace: SDW_DOCUMENT_CORPUS_NAMESPACE, key: documentProvenanceKey(action.documentId) } as const,
        { namespace: SDW_DOCUMENT_CORPUS_NAMESPACE, key: documentProvenanceStatusKey(action.documentId) } as const,
      ]),
      { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY } as const,
    ] as const;
    const snapshots = txn === undefined ? await this.captureSnapshots(touched) : [];
    try {
      for (const action of actions) {
        if (action.provenance !== undefined) {
          await this.corpus.putProvenance({
            kind: "memory_provenance",
            version: 1,
            document_id: action.documentId,
            companion: action.provenance,
          }, "system_generated", txn);
          await this.fault?.("after_provenance_write", action.documentId);
        }
        if (action.quarantine !== undefined) {
          await this.corpus.putProvenanceStatus({
            kind: "memory_provenance_status",
            version: 1,
            document_id: action.documentId,
            status: "quarantined",
            reason: action.quarantine.reason,
            observed_content_hash: action.quarantine.contentHash,
            observed_provenance_sha256: action.quarantine.provenanceSha256,
            updated_at: this.now(),
          }, "system_generated", txn);
          await this.fault?.("after_status_write", action.documentId);
        } else if (action.clearStatus) {
          await (txn ?? this.storage).delete(
            SDW_DOCUMENT_CORPUS_NAMESPACE,
            documentProvenanceStatusKey(action.documentId),
          );
        }
      }
      await this.meta.put(journal, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY, txn);
      await this.fault?.("after_journal_write");
    } catch (error) {
      if (txn !== undefined) throw error;
      try {
        await this.restoreSnapshotsOrThrow(snapshots, error);
      } catch (rollbackError) {
        await this.markPartialScopeIfNeeded(journal, rollbackError);
        throw rollbackError;
      }
    }
  }

  private async completeRun(
    journal: SdwMemoryProvenanceMigrationJournalRecord,
    candidateCount: number,
    txn?: SdwCorpusTxn,
  ): Promise<void> {
    const completionSnapshots = txn === undefined
      ? await this.captureSnapshots([
          { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY },
          { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_COMPLETION_KEY },
          { namespace: SDW_META_NAMESPACE, key: SDW_REPLAY_ANCHOR_KEY },
          { namespace: SDW_META_NAMESPACE, key: SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY },
        ])
      : [];
    try {
      const anchor = await readReplayAnchor(txn ?? this.storage, this.masterKey);
      const base = anchor.status === "valid"
        ? anchor.data
        : { catalog: 0, chain_head: [], manifests: [], tombstones: [], export_state: 0 };
      const priorEpoch = replayAnchorCounterSeq(
        base.memory_provenance_completion ?? [],
        SDW_MEMORY_PROVENANCE_COMPLETION_COUNTER_ID,
      );
      const epoch = priorEpoch + 1;
      const completedAt = this.now();
      const completedJournal: SdwMemoryProvenanceMigrationJournalRecord = {
        ...journal,
        status: "completed",
        verified: candidateCount,
        quarantined: 0,
        unsigned: 0,
        updated_at: completedAt,
      };
      // Anchor first is the only crash-safe ordering: an interruption before
      // the marker yields the explicit repair-only state. Marker-first would
      // leave an epoch mismatch with no authorized recovery transition.
      const preparedAnchor = prepareReplayAnchorWrite(this.masterKey, {
        ...base,
        memory_provenance_completion: upsertReplayAnchorCounter(
          base.memory_provenance_completion ?? [],
          SDW_MEMORY_PROVENANCE_COMPLETION_COUNTER_ID,
          epoch,
        ),
      });
      await (txn ?? this.storage).write(preparedAnchor.namespace, preparedAnchor.storageKey, preparedAnchor.data);
      await this.fault?.("after_completion_anchor_write");
      await this.meta.put({
        kind: "memory_provenance_completion",
        version: 1,
        migration_id: SDW_MEMORY_PROVENANCE_MIGRATION_ID,
        completion_epoch: epoch,
        candidate_count: candidateCount,
        completed_at: completedAt,
      }, SDW_MEMORY_PROVENANCE_COMPLETION_KEY, txn);
      await this.fault?.("after_completion_marker_write");
      await this.meta.put(completedJournal, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY, txn);
      await (txn ?? this.storage).delete(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY);
    } catch (error) {
      if (txn !== undefined) throw error;
      try {
        await this.restoreSnapshotsOrThrow(completionSnapshots, error);
      } catch (rollbackError) {
        await this.markPartialScopeIfNeeded(journal, rollbackError);
        throw rollbackError;
      }
    }
  }

  private async verifyAllCandidates(
    entriesInput?: Awaited<ReturnType<SdwMemoryProvenanceMigration["candidateEntries"]>>,
    txn?: SdwCorpusTxn,
  ): Promise<{ readonly complete: boolean; readonly verified: number; readonly quarantined: number; readonly unsigned: number }> {
    const entries = entriesInput ?? await this.candidateEntries();
    let verified = 0;
    let quarantined = 0;
    let unsigned = 0;
    const journal = (await this.readJournal(txn))?.record;
    if (journal === undefined) return { complete: false, verified, quarantined, unsigned: entries.length };
    const signer = this.resolvePrimarySigningHandle();
    for (const entry of entries) {
      const action = await this.inspectCandidate(entry.key.slice("doc.".length), journal, signer, false, txn);
      if (action.outcome === "verified") verified += 1;
      else if (action.outcome === "migrated" || action.outcome === "unsigned") unsigned += 1;
      else quarantined += 1;
    }
    return { complete: verified === entries.length, verified, quarantined, unsigned };
  }

  private async candidateEntries() {
    return this.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, this.documentPrefix);
  }

  private readJournal(txn?: SdwCorpusTxn) {
    return this.meta.read<SdwMemoryProvenanceMigrationJournalRecord>(
      SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY,
      "memory_provenance_migration_journal",
      txn,
    );
  }

  private async requireActiveJournal(txn?: SdwCorpusTxn) {
    const journal = await this.readJournal(txn);
    if (journal === null || journal.record.status !== "active") {
      throw new SdwValidationError("auth_failed", "Active SDW memory provenance journal is unavailable");
    }
    return journal.record;
  }

  private async getStateInLock(txn?: SdwCorpusTxn): Promise<SdwMemoryIntegrityState> {
    const anchor = await readReplayAnchor(txn ?? this.storage, this.masterKey);
    const epoch = anchor.status === "valid"
      ? replayAnchorCounterSeq(anchor.data.memory_provenance_completion ?? [], SDW_MEMORY_PROVENANCE_COMPLETION_COUNTER_ID)
      : 0;
    const marker = await this.meta.read<SdwMemoryProvenanceCompletionRecord>(
      SDW_MEMORY_PROVENANCE_COMPLETION_KEY,
      "memory_provenance_completion",
      txn,
    );
    if (epoch > 0 && marker === null) return "state_MARKER_ABSENT_POST_COMPLETE";
    if (marker !== null) {
      if (marker.record.completion_epoch !== epoch || epoch < 1) {
        throw new SdwValidationError("auth_failed", "SDW memory provenance completion epoch mismatch");
      }
      return "state_COMPLETE";
    }
    const active = await this.meta.read<SdwMemoryProvenanceMigrationActiveRecord>(
      SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY,
      "memory_provenance_migration_active",
      txn,
    );
    const journal = await this.readJournal(txn);
    if (active === null) {
      if (journal === null || journal.record.status === "abandoned") return "state_PRE_MIGRATION";
      if (journal.record.status === "completed") return "state_MARKER_ABSENT_POST_COMPLETE";
      throw new SdwValidationError("auth_failed", "SDW memory provenance active pointer is absent");
    }
    if (journal === null || journal.record.status !== "active" || journal.record.run_id !== active.record.run_id) {
      throw new SdwValidationError("auth_failed", "SDW memory provenance migration journal mismatch");
    }
    return "state_MIGRATING";
  }

  private statusInLock(
    _txn: SdwCorpusTxn | undefined,
    state: SdwMemoryIntegrityState,
    journal?: SdwMemoryProvenanceMigrationJournalRecord,
  ): SdwMemoryMigrationProgress {
    return {
      state,
      ...(journal === undefined ? {} : { run_id: journal.run_id }),
      scanned: journal?.scanned ?? 0,
      migrated: journal?.migrated ?? 0,
      verified: journal?.verified ?? 0,
      quarantined: journal?.quarantined ?? 0,
      unsigned: journal?.unsigned ?? 0,
      cursor: journal?.cursor ?? null,
      completed: state === "state_COMPLETE",
    };
  }

  private async withMigrationLock<T>(fn: (txn?: SdwCorpusTxn) => Promise<T>): Promise<T> {
    return withExitAdmissionLock(this.storage, "memory_migration", async () => {
      if (await hasInterruptedExitImport(this.storage)) {
        throw new SdwValidationError(
          "auth_failed",
          "SDW memory migration refused while an Exit import journal exists",
        );
      }
      if (await this.storage.read("_meta", ROTATION_JOURNAL_KEY) !== null) {
        throw new SdwValidationError(
          "auth_failed",
          "SDW memory migration refused while a master-rotation journal exists",
        );
      }
      return withSdwMemoryCorpusMutationLock(this.storage, async () => {
        const transactional = asTransactional(this.storage);
        if (transactional !== null) return transactional.sdwTransaction(fn);
        return withCrossProcessLock(
          this.storage,
          MEMORY_BATCH_LOCK_NAMESPACE,
          sdwMemoryCorpusBatchLockFile(),
          () => fn(),
          { timeoutMs: MEMORY_BATCH_LOCK_TIMEOUT_MS },
        );
      });
    });
  }

  private assertJournalSigner(
    journal: SdwMemoryProvenanceMigrationJournalRecord,
    signer: MemoryProvenanceSigningHandle,
  ): void {
    if (journal.source_signer_identity_id !== signer.identity_id || journal.source_signer_did !== signer.did) {
      throw new SdwValidationError("auth_failed", "Primary identity changed during SDW memory migration");
    }
  }

  private assertSameSigner(a: MemoryProvenanceSigningHandle, b: MemoryProvenanceSigningHandle): void {
    if (a.identity_id !== b.identity_id || a.did !== b.did || !constantTimeEqual(a.public_key, b.public_key)) {
      throw new SdwValidationError("auth_failed", "Primary identity changed before SDW memory migration commit");
    }
  }

  private async captureSnapshots(
    keys: readonly { readonly namespace: RawSnapshot["namespace"]; readonly key: string }[],
  ): Promise<readonly RawSnapshot[]> {
    const unique = new Map<string, { readonly namespace: RawSnapshot["namespace"]; readonly key: string }>();
    for (const item of keys) unique.set(`${item.namespace}\0${item.key}`, item);
    const snapshots: RawSnapshot[] = [];
    for (const item of unique.values()) {
      snapshots.push({ ...item, raw: await this.storage.read(item.namespace, item.key) });
    }
    return snapshots;
  }

  private async restoreSnapshotsOrThrow(snapshots: readonly RawSnapshot[], cause: unknown): Promise<never> {
    try {
      await this.fault?.("before_rollback_restore");
      for (const snapshot of [...snapshots].reverse()) {
        if (snapshot.raw === null) {
          await this.storage.delete(snapshot.namespace, snapshot.key);
        } else if (snapshot.namespace === SDW_DOCUMENT_CORPUS_NAMESPACE) {
          if (snapshot.key.startsWith("prov-status.")) {
            const documentId = snapshot.key.slice("prov-status.".length);
            if (documentProvenanceStatusKey(documentId) !== snapshot.key) {
              throw new Error("Invalid migration provenance-status snapshot key");
            }
            await this.corpus.restoreMemoryMigrationProvenanceStatusPreimage(documentId, snapshot.raw);
          } else if (snapshot.key.startsWith("prov.")) {
            const documentId = snapshot.key.slice("prov.".length);
            if (documentProvenanceKey(documentId) !== snapshot.key) {
              throw new Error("Invalid migration provenance snapshot key");
            }
            await this.corpus.restoreMemoryMigrationProvenancePreimage(documentId, snapshot.raw);
          } else {
            throw new Error("Invalid migration document-corpus snapshot key");
          }
        } else if (snapshot.key === SDW_REPLAY_ANCHOR_KEY) {
          await this.corpus.restorePriorReplayAnchor(snapshot.raw);
        } else {
          await this.corpus.restorePriorMemoryMigrationMetadata(snapshot.key, snapshot.raw);
        }
      }
      for (const snapshot of snapshots) {
        const restored = await this.storage.read(snapshot.namespace, snapshot.key);
        if (
          (snapshot.raw === null && restored !== null) ||
          (snapshot.raw !== null && (restored === null || !constantTimeEqual(snapshot.raw, restored)))
        ) throw new Error("migration rollback verification failed");
      }
      await this.fault?.("after_rollback_restore");
    } catch (rollbackError) {
      throw new SdwValidationError(
        "partial_scope",
        "SDW memory migration failed and exact rollback could not be verified",
        { cause: new AggregateError([cause, rollbackError]) },
      );
    }
    throw cause;
  }

  private async markPartialScopeIfNeeded(
    journal: SdwMemoryProvenanceMigrationJournalRecord,
    error: unknown,
  ): Promise<void> {
    if (!(error instanceof SdwValidationError) || error.category !== "partial_scope") return;
    try {
      await this.meta.put({
        ...journal,
        status: "active",
        failure_code: "partial_scope",
        updated_at: this.now(),
      }, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY);
    } catch {
      // The caller still receives partial_scope. At this point storage is by
      // definition unverifiable, so a second write cannot be claimed durable;
      // failure to persist the poison marker must not replace the root error.
    }
  }
}

function expectedBinding(
  fortressId: string,
  ownerRef: string,
  documentId: string,
  document: { readonly content_hash: string; readonly chunk_count: number },
) {
  const passageId = documentId.slice(`mem.${ownerRef}.`.length);
  return {
    origin: {
      origin_fortress_id: fortressId,
      owner_ref: ownerRef,
      passage_id: passageId,
      content_hash: document.content_hash,
      chunk_count: document.chunk_count,
    },
    destination: {
      destination_fortress_id: fortressId,
      destination_owner_ref: ownerRef,
      passage_id: passageId,
    },
  };
}

function digestRaw(raw: Uint8Array | null): string {
  return toBase64url(hash(raw ?? new Uint8Array()));
}

interface TransactionalStorage {
  sdwTransaction<T>(fn: (txn: SdwCorpusTxn) => Promise<T>): Promise<T>;
}

function asTransactional(storage: StorageBackend): TransactionalStorage | null {
  return typeof (storage as { readonly sdwTransaction?: unknown }).sdwTransaction === "function"
    ? storage as StorageBackend & TransactionalStorage
    : null;
}
