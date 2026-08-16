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

/** Outcome of a non-throwing write-gate dry run for one passage. */
export type MemoryPassageScreen =
  | { readonly ok: true }
  | {
      readonly ok: false;
      /** SdwValidationError category, e.g. "classifier_reject". */
      readonly category: string;
      readonly message: string;
    };

/**
 * The storage operations a memory engine needs from a sovereign backend.
 *
 * Every implementation MUST preserve the SDW custody invariants: encrypted
 * at rest through the SDW write gate, operator inspectable / exportable /
 * deletable, zero network calls, fail closed on any integrity failure.
 */
export interface MemoryBackendAdapter {
  /** The engine instance / archive scope every passage here belongs to. */
  readonly ownerRef: string;

  /**
   * Persist a passage. The caller asserts the persistable taint of the text
   * (typically "user_content" for conversation-derived passages or
   * "agent_derived_clean" for engine summaries); forbidden taints and
   * classifier hits are rejected by the SDW write gate before encryption.
   */
  insertPassage(input: MemoryPassageInput, taint: PersistableTaint): Promise<MemoryPassage>;

  /**
   * Insert-or-replace a whole SET of passages as one verified unit.
   *
   * Every input MUST carry an explicit passage_id: replace semantics need a
   * caller-stable id, and a generated one would make every run a fresh insert.
   *
   * A mirror that commits a prefix of its passages and then throws leaves a
   * vault the operator cannot re-import (each committed id now collides) and
   * cannot distinguish from a complete one. On success every input is durable.
   * On non-transactional filesystem storage, replacement is owner-scope locked
   * across processes because rollback verifies the raw owner-scope key listing.
   * On a recoverable write failure, rollback is verified against that listing
   * before the original error is surfaced. If rollback cannot be verified, the
   * implementation MUST fail with a partial_scope category so the caller and
   * audit trail do not report the run as a clean all-or-nothing failure.
   */
  putPassages(
    inputs: readonly MemoryPassageInput[],
    taint: PersistableTaint,
  ): Promise<readonly MemoryPassage[]>;

  /**
   * Atomically create a whole SET only when every explicit passage id is
   * absent. Returns null without writing when any target already exists.
   *
   * Security-sensitive callers use this instead of a separate absence check
   * followed by putPassages: that check/write split permits two concurrent
   * writers to both observe absence and then replace one another's signed
   * records. Implementations MUST linearize the absence decision with the
   * batch commit under the same transaction or owner-scope lock.
   */
  putPassagesIfAbsent(
    inputs: readonly MemoryPassageInput[],
    taint: PersistableTaint,
  ): Promise<readonly MemoryPassage[] | null>;

  /**
   * Dry-run the write gate for one passage: the SAME validation, grammar, and
   * secret classification the real write performs, with nothing persisted.
   *
   * A batch caller uses this to decide per input whether to include it, so one
   * rejected input does not abort a whole mirror. It NEVER relaxes the gate:
   * putPassages re-runs the real gate on everything it writes.
   */
  screenPassage(input: MemoryPassageInput, taint: PersistableTaint): MemoryPassageScreen;

  /**
   * Derive a stable passage id from a caller label, keyed to this fortress and
   * owner scope.
   *
   * Passage ids appear in storage keys, and a filesystem backend turns a
   * storage key into a directory entry name. A caller whose natural label is
   * private (a memory-file topic name, a document title) must therefore NOT
   * use it as the id: the encrypted body would be safe while the topic index
   * was published in cleartext. This returns an opaque keyed digest instead,
   * so the label survives only inside the encrypted record metadata, while
   * re-deriving from the same label still lands on the same passage.
   */
  derivePassageId(domain: string, label: string): string;

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
