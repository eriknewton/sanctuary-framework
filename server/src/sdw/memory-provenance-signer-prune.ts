import { createHash } from "node:crypto";

import { runJournaledMemoryProvenanceSignerPrune } from "../exit/bundle.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import type { AuditLog } from "../operational/audit-log.js";
import {
  KNOWN_SIGNERS_NAMESPACE,
  KnownSignersStore,
  knownSignerStorageKey,
} from "../reputation/known-signers-store.js";
import { withCrossProcessLock } from "../storage/cross-process-lock.js";
import { withExitAdmissionLock } from "../storage/exit-import-journal.js";
import type { StorageBackend } from "../storage/interface.js";
import {
  MEMORY_BATCH_LOCK_NAMESPACE,
  MEMORY_BATCH_LOCK_TIMEOUT_MS,
  sdwMemoryCorpusBatchLockFile,
  withSdwMemoryCorpusMutationLock,
} from "./adapters/sdw-memory-backend.js";
import { SdwDocumentCorpusStore } from "./document-corpus-store.js";
import {
  documentKey,
  documentProvenanceKey,
  documentProvenanceStatusKey,
} from "./grammar.js";
import { memoryProvenancePublicKeyFingerprint } from "./memory-provenance-bad-signers.js";
import { verifyMemoryProvenanceCompanion } from "./memory-provenance-contract.js";
import { MAX_MEMORY_PROVENANCE_CANDIDATES } from "./memory-provenance-limits.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE, type SdwDocumentRecord } from "./records.js";

export const MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION =
  "memory_provenance_prune_signers";
export const MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN_AUDIT =
  "MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN";
export const MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE_AUDIT =
  "MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE";

const DOCUMENT_PREFIX = "doc.mem.";
const PROVENANCE_PREFIX = "prov.mem.";
const STATUS_PREFIX = "prov-status.mem.";

export interface MemoryProvenanceSignerPruneDeletion {
  readonly signer_did: string;
  readonly storage_key: string;
  readonly public_key_sha256: string;
}

export interface MemoryProvenanceSignerPruneResult {
  readonly deleted: readonly MemoryProvenanceSignerPruneDeletion[];
  readonly exact_set_digest: string;
  readonly scanned: {
    readonly union: number;
    readonly documents: number;
    readonly provenance: number;
    readonly statuses: number;
    readonly signers: number;
  };
}

export interface MemoryProvenanceSignerPrunerOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly knownSignersStore: KnownSignersStore;
  readonly resolveSignerPublicKey: (
    identityId: string,
    did: string,
  ) => Uint8Array | undefined;
  /** Remove a durably pruned DID from the process-local resolver cache. */
  readonly forgetSigner: (did: string) => void;
  readonly auditLog: AuditLog;
}

interface CorpusListing {
  readonly documents: readonly string[];
  readonly provenance: readonly string[];
  readonly statuses: readonly string[];
  readonly union: readonly string[];
}

/**
 * Forced Tier-1 mark-and-sweep for the separately capped `memprov.` signer
 * partition. It deletes only mappings absent from every authenticated
 * provenance companion after a complete, bounded, lock-protected scan.
 */
export class MemoryProvenanceSignerPruner {
  private readonly corpus: SdwDocumentCorpusStore;

  constructor(private readonly options: MemoryProvenanceSignerPrunerOptions) {
    this.corpus = new SdwDocumentCorpusStore({
      storage: options.storage,
      masterKey: options.masterKey,
      fortressId: options.fortressId,
    });
  }

  async prune(input: {
    readonly approvalAuditId: string;
    readonly identityId?: string;
  }): Promise<MemoryProvenanceSignerPruneResult> {
    if (!/^[A-Za-z0-9:._-]{1,256}$/.test(input.approvalAuditId)) {
      throw new Error("invalid signer-prune approval audit id");
    }
    return withExitAdmissionLock(this.options.storage, "memory_signer_prune", () =>
      withSdwMemoryCorpusMutationLock(this.options.storage, () =>
        withCrossProcessLock(
          this.options.storage,
          MEMORY_BATCH_LOCK_NAMESPACE,
          sdwMemoryCorpusBatchLockFile(),
          () => this.pruneUnderLocks(input),
          { timeoutMs: MEMORY_BATCH_LOCK_TIMEOUT_MS },
        ),
      ),
    );
  }

  private async pruneUnderLocks(input: {
    readonly approvalAuditId: string;
    readonly identityId?: string;
  }): Promise<MemoryProvenanceSignerPruneResult> {
    const listing = await this.listCorpus();
    const documents = new Map<string, SdwDocumentRecord>();
    for (const key of listing.documents) {
      const documentId = exactDocumentId(key, DOCUMENT_PREFIX, "doc.", documentKey);
      const decoded = await this.corpus.getDocumentRaw(documentId);
      if (decoded === null) throw new Error("listed SDW memory document disappeared");
      documents.set(documentId, decoded.record);
    }

    // Authentication, DID/key binding, partition cap, key derivation, and
    // duplicate-conflict checks are prerequisites, never reimplemented here.
    const signers = await this.options.knownSignersStore.loadAll();
    const persistedByDid = new Map(signers.map((entry) => [entry.did, entry.publicKey]));
    const resolver = {
      // The bounded table being scanned is exactly this authenticated
      // partition; an optional local-primary resolver entry is not persisted
      // signer-table population and must not make an at-cap partition appear
      // over cap.
      size: signers.length,
      resolve: (identityId: string, did: string): Uint8Array | undefined =>
        this.options.resolveSignerPublicKey(identityId, did) ?? persistedByDid.get(did)?.slice(),
    };
    const referencedDids = new Set<string>();

    for (const key of listing.provenance) {
      const documentId = exactDocumentId(key, PROVENANCE_PREFIX, "prov.", documentProvenanceKey);
      const decoded = await this.corpus.getProvenanceRaw(documentId);
      if (decoded === null) throw new Error("listed SDW memory provenance disappeared");
      const companion = decoded.record.companion;
      const admission = companion.admission.body;
      if (documentId !== `mem.${admission.destination_owner_ref}.${admission.passage_id}`) {
        throw new Error("memory provenance storage key does not match its signed destination");
      }
      const document = documents.get(documentId);
      const expectedContentHash = document?.content_hash ?? companion.origin.body.content_hash;
      const expectedChunkCount = document?.chunk_count ?? companion.origin.body.chunk_count;
      const verified = verifyMemoryProvenanceCompanion(companion, resolver, {
        origin: {
          origin_fortress_id: companion.origin.body.origin_fortress_id,
          owner_ref: companion.origin.body.owner_ref,
          passage_id: companion.origin.body.passage_id,
          content_hash: expectedContentHash,
          chunk_count: expectedChunkCount,
        },
        destination: {
          destination_fortress_id: this.options.fortressId,
          destination_owner_ref: admission.destination_owner_ref,
          passage_id: admission.passage_id,
        },
      });
      if (!verified.ok) {
        throw new Error(`memory provenance reachability is unprovable: ${verified.error.code}`);
      }
      // Orphan-but-authenticated and quarantined companions remain references.
      referencedDids.add(verified.value.origin.body.signer_did);
    }

    for (const key of listing.statuses) {
      const documentId = exactDocumentId(
        key,
        STATUS_PREFIX,
        "prov-status.",
        documentProvenanceStatusKey,
      );
      if (await this.corpus.getProvenanceStatusRaw(documentId) === null) {
        throw new Error("listed SDW memory provenance status disappeared");
      }
    }

    const deleted = signers
      .filter((entry) => !referencedDids.has(entry.did))
      .map((entry): MemoryProvenanceSignerPruneDeletion => ({
        signer_did: entry.did,
        storage_key: knownSignerStorageKey(entry.did, "memory_provenance"),
        public_key_sha256: memoryProvenancePublicKeyFingerprint(entry.publicKey),
      }))
      .sort((left, right) =>
        compareExactString(left.signer_did, right.signer_did) ||
        compareExactString(left.storage_key, right.storage_key),
      );
    const exactSetDigest = createHash("sha256")
      .update(canonicalizeToBytes(deleted))
      .digest("hex");
    const scanned = {
      union: listing.union.length,
      documents: listing.documents.length,
      provenance: listing.provenance.length,
      statuses: listing.statuses.length,
      signers: signers.length,
    } as const;

    // Re-list at the last boundary before journal publication. Exact equality
    // is required even though cooperative writers are excluded by the locks.
    const relisted = await this.listCorpus();
    if (!sameKeys(listing.documents, relisted.documents) ||
        !sameKeys(listing.provenance, relisted.provenance) ||
        !sameKeys(listing.statuses, relisted.statuses)) {
      throw new Error("memory provenance corpus changed before signer deletion");
    }

    await this.options.auditLog.appendCritical({
      layer: "l1",
      operation: MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN_AUDIT,
      identity_id: input.identityId ?? "principal",
      result: "success",
      details: {
        approval_audit_id: input.approvalAuditId,
        exact_set_digest: exactSetDigest,
        deletion_set: deleted,
        scan_counts: scanned,
      },
    });

    if (deleted.length > 0) {
      await runJournaledMemoryProvenanceSignerPrune({
        storage: this.options.storage,
        identityId: input.identityId ?? "principal",
        locations: deleted.map((entry) => ({
          namespace: KNOWN_SIGNERS_NAMESPACE,
          key: entry.storage_key,
        })),
        operation: async ({ recordPostImage }) => {
          for (const entry of deleted) {
            // The intended null post-image is durable before the destructive
            // mutation, so a kill at either boundary has an exact disposition.
            await recordPostImage(KNOWN_SIGNERS_NAMESPACE, entry.storage_key, null);
            if (!await this.options.storage.delete(
              KNOWN_SIGNERS_NAMESPACE,
              entry.storage_key,
              true,
            )) throw new Error("planned memory-provenance signer disappeared before delete");
            if (await this.options.storage.read(KNOWN_SIGNERS_NAMESPACE, entry.storage_key) !== null) {
              throw new Error("memory-provenance signer deletion was not durable");
            }
          }
        },
      });
      for (const entry of deleted) this.options.forgetSigner(entry.signer_did);
    }

    await this.options.auditLog.appendCritical({
      layer: "l1",
      operation: MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE_AUDIT,
      identity_id: input.identityId ?? "principal",
      result: "success",
      details: {
        approval_audit_id: input.approvalAuditId,
        exact_set_digest: exactSetDigest,
        deleted: deleted.length,
        scan_counts: scanned,
      },
    });
    return { deleted, exact_set_digest: exactSetDigest, scanned };
  }

  private async listCorpus(): Promise<CorpusListing> {
    const documents = keys(await this.options.storage.list(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      DOCUMENT_PREFIX,
    ));
    const provenance = keys(await this.options.storage.list(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      PROVENANCE_PREFIX,
    ));
    const statuses = keys(await this.options.storage.list(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      STATUS_PREFIX,
    ));
    const union = [...new Set([...documents, ...provenance, ...statuses])].sort();
    // The union is bounded before any attacker-influenced record is decoded.
    if (union.length > MAX_MEMORY_PROVENANCE_CANDIDATES) {
      throw new Error("memory provenance signer prune scan exceeds the corpus cap");
    }
    return { documents, provenance, statuses, union };
  }
}

function keys(entries: readonly { key: string }[]): readonly string[] {
  return [...new Set(entries.map((entry) => entry.key))].sort();
}

function sameKeys(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((key, index) => key === right[index]);
}

function compareExactString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactDocumentId(
  key: string,
  requiredPrefix: string,
  kindPrefix: string,
  reconstruct: (documentId: string) => string,
): string {
  const documentId = key.slice(kindPrefix.length);
  if (!key.startsWith(requiredPrefix) || reconstruct(documentId) !== key) {
    throw new Error("invalid SDW memory corpus storage key");
  }
  return documentId;
}
