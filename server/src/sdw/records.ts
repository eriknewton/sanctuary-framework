export const SDW_CATALOG_NAMESPACE = "_sdw_catalog";
export const SDW_META_NAMESPACE = "_sdw_meta";
export const SDW_WORKING_STATE_NAMESPACE = "_sdw_working_state";
export const SDW_QUERY_HISTORY_NAMESPACE = "_sdw_query_history";
export const SDW_DOCUMENT_CORPUS_NAMESPACE = "_sdw_document_corpus";
export const SDW_VECTOR_MEMORY_NAMESPACE = "_sdw_vector_memory";

export const SDW_CATALOG_HKDF_INFO = "sdw-catalog-v1";
export const SDW_WORKING_STATE_HKDF_INFO = "sdw-working-state-v1";
export const SDW_QUERY_HISTORY_HKDF_INFO = "sdw-query-history-v1";
export const SDW_DOCUMENT_CORPUS_HKDF_INFO = "sdw-document-corpus-v1";
export const SDW_VECTOR_MEMORY_HKDF_INFO = "sdw-vector-memory-v1";
export const SDW_REPLAY_ANCHOR_KEY = "sdw-replay-anchors-v1";

export const SDW_MEMORY_INTEGRITY_STATES = [
  "state_PRE_MIGRATION",
  "state_MIGRATING",
  "state_COMPLETE",
  "state_MARKER_ABSENT_POST_COMPLETE",
] as const;
export type SdwMemoryIntegrityState = typeof SDW_MEMORY_INTEGRITY_STATES[number];
/** C2 compatibility default; C3 production wiring resolves durable state. */
export const SDW_MEMORY_INTEGRITY_STATE = "state_PRE_MIGRATION" as const;

export type SdwNamespace =
  | typeof SDW_CATALOG_NAMESPACE
  | typeof SDW_META_NAMESPACE
  | typeof SDW_WORKING_STATE_NAMESPACE
  | typeof SDW_QUERY_HISTORY_NAMESPACE
  | typeof SDW_DOCUMENT_CORPUS_NAMESPACE
  | typeof SDW_VECTOR_MEMORY_NAMESPACE;

export interface SdwStoreDescriptor {
  readonly namespace: Exclude<SdwNamespace, typeof SDW_META_NAMESPACE>;
  readonly hkdf_info: string;
  readonly current_record_version: 1;
}

export interface SdwCatalogRecord {
  readonly kind: "catalog";
  readonly version: 1;
  readonly fortress_id: string;
  readonly environment_id: string;
  readonly created_at: string;
  readonly replay_anchor_seq: number;
  readonly stores: readonly SdwStoreDescriptor[];
}

export interface SdwReplayAnchorData {
  readonly catalog: number;
  readonly chain_head: readonly ReplayAnchorCounter[];
  readonly manifests: readonly ReplayAnchorCounter[];
  readonly tombstones: readonly ReplayAnchorCounter[];
  readonly export_state: number;
  /** C3 completion epoch; absent on pre-C3 anchors and read as an empty set. */
  readonly memory_provenance_completion?: readonly ReplayAnchorCounter[];
}

export interface ReplayAnchorCounter {
  readonly id: string;
  readonly seq: number;
}

export interface SdwReplayAnchorRecord {
  readonly kind: "replay_anchor";
  readonly version: 1;
  readonly fortress_id: string;
  readonly data: SdwReplayAnchorData;
  readonly updated_at: string;
}

export interface SdwWorkingStateRecord {
  readonly kind: "working_state";
  readonly version: 1;
  readonly state_id: string;
  readonly scope: "task" | "thread" | "tool" | "session" | "other";
  readonly owner_ref: string;
  readonly status: "active" | "superseded" | "completed" | "failed";
  readonly created_at: string;
  readonly updated_at: string;
  readonly expires_at?: string;
  readonly content_type: "application/json";
  readonly state:
    | {
        readonly kind: "retrieval_context";
        readonly query_ref: string;
        readonly selected_refs: readonly string[];
        readonly notes?: string;
      }
    | {
        readonly kind: "tool_result_summary";
        readonly tool_name: string;
        readonly invocation_ref: string;
        readonly summary: string;
        readonly artifact_refs?: readonly string[];
      }
    | {
        readonly kind: "task_checkpoint";
        readonly task_ref: string;
        readonly summary: string;
        readonly next_steps?: readonly string[];
      };
  readonly source_refs?: readonly SdwTypedRef[];
}

export interface SdwTypedRef {
  readonly kind: "query" | "document_chunk" | "vector" | "tool_call" | "external";
  readonly ref: string;
}

export interface SdwQueryHistoryRecord {
  readonly kind: "query_history";
  readonly version: 1;
  readonly query_id: string;
  readonly sequence: number;
  readonly previous_record_hash: string | null;
  readonly previous_query_key: string | null;
  readonly record_hash: string;
  readonly audit_event_id: string;
  readonly occurred_at: string;
  readonly actor: {
    readonly kind: "operator" | "agent" | "system";
    readonly principal_ref?: string;
    readonly agent_ref?: string;
  };
  readonly channel: "mcp" | "cli" | "dashboard" | "internal";
  readonly operation: string;
  readonly prompt_or_query: string;
  readonly normalized_query?: string;
  readonly result_summary?: string;
  readonly result_refs?: readonly SdwQueryResultRef[];
  readonly policy_visibility: "not_included";
  readonly created_at: string;
}

export interface SdwQueryResultRef {
  readonly kind: "working_state" | "document" | "document_chunk" | "vector" | "audit_event";
  readonly ref: string;
}

export interface SdwQueryHistoryChainHeadRecord {
  readonly kind: "query_history_chain_head";
  readonly version: 1;
  readonly fortress_id: string;
  readonly latest_sequence: number;
  readonly latest_record_hash: string | null;
  readonly latest_query_key: string | null;
  readonly replay_anchor_seq: number;
  readonly updated_at: string;
}

export interface SdwDocumentRecord {
  readonly kind: "document";
  readonly version: 1;
  readonly document_id: string;
  readonly source: {
    readonly kind: "file" | "url" | "paste" | "tool_output" | "internal";
    readonly uri?: string;
    readonly title?: string;
    readonly media_type?: string;
  };
  readonly content_hash: string;
  readonly chunk_count: number;
  readonly byte_length?: number;
  readonly created_at: string;
  readonly updated_at: string;
  readonly indexed_at?: string;
  readonly tags?: readonly string[];
  readonly metadata?: readonly SdwDocumentMetadata[];
}

export interface SdwDocumentChunkRecord {
  readonly kind: "document_chunk";
  readonly version: 1;
  readonly chunk_id: string;
  readonly document_id: string;
  readonly chunk_ordinal: number;
  readonly text: string;
  readonly content_hash: string;
  readonly char_start?: number;
  readonly char_end?: number;
  readonly token_count?: number;
  readonly vector_refs?: readonly string[];
  readonly created_at: string;
}

export interface SdwMemoryProvenanceRecord {
  readonly kind: "memory_provenance";
  readonly version: 1;
  readonly document_id: string;
  readonly companion: import("./memory-provenance-contract.js").MemoryProvenanceCompanion;
}

export interface SdwMemoryProvenanceStatusRecord {
  readonly kind: "memory_provenance_status";
  readonly version: 1;
  readonly document_id: string;
  readonly status: "quarantined";
  readonly reason: string;
  readonly observed_content_hash: string;
  readonly observed_provenance_sha256: string;
  readonly updated_at: string;
}

export interface SdwMemoryProvenanceMigrationActiveRecord {
  readonly kind: "memory_provenance_migration_active";
  readonly version: 1;
  readonly migration_id: "MI_C_SDW_MEMORY_PROVENANCE_V1";
  readonly run_id: string;
  readonly updated_at: string;
}

export interface SdwMemoryProvenanceMigrationJournalRecord {
  readonly kind: "memory_provenance_migration_journal";
  readonly version: 1;
  readonly migration_id: "MI_C_SDW_MEMORY_PROVENANCE_V1";
  readonly run_id: string;
  readonly status: "active" | "abandoned" | "completed" | "partial_scope";
  readonly started_at: string;
  readonly observation_time: string;
  readonly source_signer_identity_id: string;
  readonly source_signer_did: string;
  readonly cursor: string | null;
  readonly scanned: number;
  readonly migrated: number;
  readonly verified: number;
  readonly quarantined: number;
  readonly unsigned: number;
  readonly updated_at: string;
  readonly failure_code?: string;
}

export interface SdwMemoryProvenanceCompletionRecord {
  readonly kind: "memory_provenance_completion";
  readonly version: 1;
  readonly migration_id: "MI_C_SDW_MEMORY_PROVENANCE_V1";
  readonly completion_epoch: number;
  readonly candidate_count: number;
  readonly completed_at: string;
}

export interface SdwDocumentMetadata {
  readonly key: string;
  readonly value: string;
}

export interface SdwVectorRecord {
  readonly kind: "vector_record";
  readonly version: 1;
  readonly vector_id: string;
  readonly source: { readonly kind: "document_chunk" | "query" | "working_state" | "manual"; readonly ref: string };
  readonly segment_id: string;
  readonly hnsw_label: number;
  readonly vector: readonly number[];
  readonly created_at: string;
  readonly deleted_at?: string;
}

export interface SdwVectorLabelMapRecord {
  readonly kind: "vector_label_map";
  readonly version: 1;
  readonly segment_id: string;
  readonly hnsw_label: number;
  readonly vector_id: string;
  readonly vector_key: string;
  readonly vector_record_hash: string;
  readonly manifest_generation: number;
  readonly created_at: string;
}

export interface SdwHnswIndexManifestRecord {
  readonly kind: "hnsw_index_manifest";
  readonly version: 1;
  readonly segment_id: string;
  readonly active_generation: number;
  readonly status: "building" | "active" | "compacting" | "retired";
  readonly replay_anchor_seq: number;
  readonly created_at: string;
  readonly updated_at: string;
  readonly segment_key: string;
}

export interface SdwVectorTombstoneRecord {
  readonly kind: "vector_tombstone";
  readonly version: 1;
  readonly vector_id: string;
  readonly epoch: number;
  readonly deleted_at: string;
}

export type SdwRecord =
  | SdwCatalogRecord
  | SdwReplayAnchorRecord
  | SdwWorkingStateRecord
  | SdwQueryHistoryRecord
  | SdwQueryHistoryChainHeadRecord
  | SdwDocumentRecord
  | SdwDocumentChunkRecord
  | SdwMemoryProvenanceRecord
  | SdwMemoryProvenanceStatusRecord
  | SdwMemoryProvenanceMigrationActiveRecord
  | SdwMemoryProvenanceMigrationJournalRecord
  | SdwMemoryProvenanceCompletionRecord
  | SdwVectorRecord
  | SdwVectorLabelMapRecord
  | SdwHnswIndexManifestRecord
  | SdwVectorTombstoneRecord;

export function defaultSdwStoreDescriptors(): readonly SdwStoreDescriptor[] {
  return [
    {
      namespace: SDW_CATALOG_NAMESPACE,
      hkdf_info: SDW_CATALOG_HKDF_INFO,
      current_record_version: 1,
    },
    {
      namespace: SDW_WORKING_STATE_NAMESPACE,
      hkdf_info: SDW_WORKING_STATE_HKDF_INFO,
      current_record_version: 1,
    },
    {
      namespace: SDW_QUERY_HISTORY_NAMESPACE,
      hkdf_info: SDW_QUERY_HISTORY_HKDF_INFO,
      current_record_version: 1,
    },
    {
      namespace: SDW_DOCUMENT_CORPUS_NAMESPACE,
      hkdf_info: SDW_DOCUMENT_CORPUS_HKDF_INFO,
      current_record_version: 1,
    },
    {
      namespace: SDW_VECTOR_MEMORY_NAMESPACE,
      hkdf_info: SDW_VECTOR_MEMORY_HKDF_INFO,
      current_record_version: 1,
    },
  ];
}
