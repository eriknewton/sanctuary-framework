/**
 * SDW Memory-Backend Adapter Contract
 *
 * Engine-neutral contract for using the Sovereign Data Warehouse as the
 * passage storage backend of an agent-memory engine (Letta, formerly MemGPT,
 * is the primary target; the contract is deliberately engine-agnostic).
 *
 * Posture (docs/sdw/letta-adapter-design.md): SDW is the sovereign substrate
 * UNDER agent memory. The engine keeps all retrieval IQ (embeddings, semantic
 * ranking, recency weighting); this contract covers only sovereign custody of
 * the passages themselves plus a deterministic lexical search so the operator
 * can always query their own vault without any engine running.
 *
 * v1 deliberately has NO embedding field: vector custody is a separate lane
 * (see the design doc non-goals). There is also no passage mutation; insert
 * and delete only.
 */

import type { SdwDocumentMetadata } from "../records.js";
import type { PersistableTaint } from "../provenance.js";

/** A passage as stored in, and returned from, the sovereign backend. */
export interface MemoryPassage {
  /** Engine-visible passage id, unique within the owner scope. */
  readonly passage_id: string;
  /** The engine instance / archive this passage belongs to. */
  readonly owner_ref: string;
  /** Full passage text, reassembled from encrypted chunks. */
  readonly text: string;
  /** Engine-supplied tags (SDW identifier grammar). */
  readonly tags: readonly string[];
  /** Engine-supplied metadata entries (keys follow SDW identifier grammar). */
  readonly metadata: readonly SdwDocumentMetadata[];
  readonly created_at: string;
  /** Number of encrypted chunks the text is stored as. */
  readonly chunk_count: number;
  /** Hash over the full passage text; verified on read (fail closed). */
  readonly content_hash: string;
}

/** Input for inserting a passage. */
export interface MemoryPassageInput {
  /** Optional caller-supplied id (SDW identifier grammar); generated if absent. */
  readonly passage_id?: string;
  readonly text: string;
  readonly tags?: readonly string[];
  readonly metadata?: readonly SdwDocumentMetadata[];
  /** Optional caller-supplied creation timestamp (ISO 8601). */
  readonly created_at?: string;
}

/**
 * Deterministic sovereign-side query. Semantic / embedding search is
 * explicitly NOT part of this contract; that stays engine-side.
 */
export interface MemorySearchQuery {
  /** Case-insensitive substring to match against passage text. */
  readonly text: string;
  /** Restrict matches to passages carrying this tag. */
  readonly tag?: string;
  /** Maximum number of results (default implementation-defined). */
  readonly limit?: number;
}

export interface MemorySearchResult {
  readonly passage: MemoryPassage;
  /** Number of substring occurrences; primary sort key (descending). */
  readonly match_count: number;
}

export interface MemoryListOptions {
  readonly limit?: number;
  /** Return passages with passage_id strictly after this one (key order). */
  readonly after?: string;
}

/**
 * The storage operations a memory engine needs from a sovereign backend.
 *
 * Every implementation MUST preserve the SDW custody invariants: encrypted
 * at rest through the SDW write gate, operator inspectable / exportable /
 * deletable, zero network calls, fail closed on any integrity failure.
 */
export interface MemoryBackendAdapter {
  /**
   * Persist a passage. The caller asserts the persistable taint of the text
   * (typically "user_content" for conversation-derived passages or
   * "agent_derived_clean" for engine summaries); forbidden taints and
   * classifier hits are rejected by the SDW write gate before encryption.
   */
  insertPassage(input: MemoryPassageInput, taint: PersistableTaint): Promise<MemoryPassage>;

  /** Fetch one passage by id, or null if absent. Fails closed on integrity errors. */
  getPassage(passageId: string): Promise<MemoryPassage | null>;

  /** Deterministic lexical search over decrypted passage text. */
  searchPassages(query: MemorySearchQuery): Promise<readonly MemorySearchResult[]>;

  /** List passages in stable key order, with optional cursor pagination. */
  listPassages(options?: MemoryListOptions): Promise<readonly MemoryPassage[]>;

  /**
   * Delete a passage and all of its chunks (secure overwrite).
   * Returns false if the passage does not exist.
   */
  deletePassage(passageId: string): Promise<boolean>;

  /** Number of passages in this adapter's owner scope. */
  countPassages(): Promise<number>;
}
