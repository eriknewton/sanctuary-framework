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
import type { ClassifierOverrideAuthorization } from "../write-gate.js";

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
  /**
   * Rung-1 point 3 (2026-08-22):
   * bypasses ONLY the secret-classifier detector step for this one passage;
   * grammar, size, and taint checks still run. Every other check in the
   * write gate still applies, so this can never turn an otherwise-invalid
   * write into a valid one, only a classifier_reject into an accepted one.
   *
   * Deliberately an OPAQUE, unforgeable token (`ClassifierOverrideAuthorization`
   * from write-gate.ts), not a plain boolean: a boolean here was a
   * true/false switch any caller constructing a MemoryPassageInput could
   * flip with zero verification. A token can only be produced by the ROOT
   * minting function write-gate.ts declares for this purpose, which ONLY
   * sdw/adapters/memory-file-allow-list.ts may call (structurally pinned by
   * a test), after the classifier genuinely refused this exact text (via
   * screenPassage, which never mints or honors this field) and the operator
   * named this exact source file on an explicit, per-file `--allow-file` /
   * `allow_files` list. preparePassage (sdw-memory-backend.ts) re-verifies
   * this token against the passage's own content hash before deriving any
   * per-record authorization from it, so a token bound to different text
   * cannot be reused here. There is deliberately no batch-wide or global
   * equivalent: `putPassages`/`screenPassage` re-run the classifier on every
   * OTHER passage in the same call exactly as before, and `screenPassage`
   * never reads this field on ANY passage (see its doc below).
   */
  readonly classifierOverrideAuthorization?: ClassifierOverrideAuthorization;
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
      /** SdwValidationError.detector; populated only for category "classifier_reject". */
      readonly detector?: string;
      /** SdwValidationError.line; the 1-based line the detector matched, when known. */
      readonly line?: number;
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
   *
   * `applyBareCredentialFallback` (default false) opts
   * every input in this batch into the extra bare-high-entropy-credential
   * classifier check (see write-gate.ts's `assertSdwClassifierCleanText`).
   * Only a caller mirroring RAW HARNESS MEMORY FILES (where the classifier
   * is the only backstop) should pass true; a caller writing
   * system-generated content shaped like a credential (archive manifests,
   * signed lineage receipts, content hashes) must leave it false or every
   * such write becomes a false refusal.
   */
  putPassages(
    inputs: readonly MemoryPassageInput[],
    taint: PersistableTaint,
    applyBareCredentialFallback?: boolean,
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
   * putPassages re-runs the real gate on everything it writes, with the one
   * narrow, explicit exception a caller opts a SPECIFIC input into via
   * `MemoryPassageInput.classifierOverrideAuthorization` (see that field's
   * doc); screenPassage itself never sets or reads that field, so the dry run
   * always reports what the classifier would say absent an override.
   *
   * `applyBareCredentialFallback`: see putPassages above; a screen and the
   * real write it is deciding for must pass the SAME value or the dry run
   * can disagree with what actually gets persisted.
   */
  screenPassage(
    input: MemoryPassageInput,
    taint: PersistableTaint,
    applyBareCredentialFallback?: boolean,
  ): MemoryPassageScreen;

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
