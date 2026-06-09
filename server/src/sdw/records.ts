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
  readonly operation: string;
  readonly prompt_or_query: string;
  readonly policy_visibility: "not_included";
  readonly created_at: string;
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
  readonly created_at: string;
  readonly updated_at: string;
}

export interface SdwDocumentChunkRecord {
  readonly kind: "document_chunk";
  readonly version: 1;
  readonly chunk_id: string;
  readonly document_id: string;
  readonly chunk_ordinal: number;
  readonly text: string;
  readonly content_hash: string;
  readonly created_at: string;
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
