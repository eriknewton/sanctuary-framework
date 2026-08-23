/**
 * SDW implementation of the memory-backend adapter contract.
 *
 * Maps engine passages onto the existing SDW document-corpus store: one
 * passage becomes one SdwDocumentRecord plus one or more
 * SdwDocumentChunkRecords in the _sdw_document_corpus namespace. Every write
 * goes through the SDW write gate (mintPersistable + sdwBackendWrite), never
 * around it, so passages inherit the full custody model: AES-256-GCM at rest
 * under the document-corpus HKDF key with fortress-bound AAD, persistable
 * taint enforcement, the secret classifier as fail-closed defense in depth,
 * and coverage by the existing export / query / secure-delete paths.
 *
 * Zero new dependencies, zero network calls. See
 * docs/sdw/letta-adapter-design.md for the boundary and non-goals.
 */

import { randomBytes } from "node:crypto";
import type { StorageBackend } from "../../storage/interface.js";
import { withCrossProcessLock } from "../../storage/cross-process-lock.js";
import { constantTimeEqual, stringToBytes, toBase64url } from "../../core/encoding.js";
import { hmacSha256 } from "../../core/hashing.js";
import { derivePurposeKey } from "../../core/key-derivation.js";
import {
  SdwDocumentCorpusStore,
  type SdwCorpusTxn,
  documentChunkStorageKey,
  padChunkOrdinal,
} from "../document-corpus-store.js";
import { SdwValidationError } from "../errors.js";
import {
  assertSdwIdentifier,
  documentChunkKey,
  documentKey,
  isSdwIdentifier,
  lengthPrefixedUtf8,
} from "../grammar.js";
import {
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  type SdwDocumentChunkRecord,
  type SdwDocumentRecord,
} from "../records.js";
import type { PersistableTaint } from "../provenance.js";
import {
  assertSdwClassifierCleanText,
  deriveClassifierOverrideAuthorization,
  passageContentHash,
  type ClassifierOverrideAuthorization,
  type MintPersistableOptions,
} from "../write-gate.js";
import type {
  MemoryBackendAdapter,
  MemoryListOptions,
  MemoryPassage,
  MemoryPassageInput,
  MemoryPassageScreen,
  MemorySearchQuery,
  MemorySearchResult,
} from "./memory-backend.js";

/** Document ids minted by this adapter are namespaced under this prefix. */
export const MEMORY_PASSAGE_DOCUMENT_PREFIX = "mem";

/**
 * HKDF label for the passage-id derivation key. FROZEN: changing this string
 * re-derives every id from derivePassageId, so a re-ingest would land on new
 * passages instead of replacing the existing ones and the old records would be
 * orphaned. Treat it like the at-rest labels in reorg-surface-manifest.md.
 */
const MEMORY_PASSAGE_ID_HKDF_INFO = "sdw-memory-passage-id-v1";
/** Domain separator inside the id MAC; distinct from the HKDF label above. */
const MEMORY_PASSAGE_ID_MAC_DOMAIN = "sanctuary.sdw-memory-passage-id.v1";
// 32 hex chars = 128 bits of the SHA-256 MAC. Hex (not base64url) because the
// SDW identifier grammar excludes "_", which base64url emits.
const MEMORY_PASSAGE_ID_HEX_CHARS = 32;
const MEMORY_BATCH_LOCK_NAMESPACE = "sdw_memory_locks";
const MEMORY_BATCH_LOCK_FILE = "batch-replace.lock";
const MEMORY_BATCH_LOCK_TIMEOUT_MS = 30_000;

const DEFAULT_MAX_CHUNK_CHARS = 8192;
const MAX_CONFIGURABLE_CHUNK_CHARS = 100_000;
const DEFAULT_SEARCH_LIMIT = 10;

/**
 * LD4 SDW-SEARCH-DOS-01 rule-8 bound: hard ceiling on the number of document
 * records (metadata for listPassages, metadata + full chunk-body for
 * searchPassages) a single searchPassages/listPassages call will decrypt.
 * Without this, memory_search / memory_list (Tier-3 auto-allowed MCP tools)
 * let an agent force a full-owner-corpus decrypt on every call by looping,
 * and cost grows unbounded with vault size. Derivation: the only real-corpus
 * timing on record for this adapter is the 413-file / 7184 ms first-ingest
 * measurement above MEMORY_BATCH_LOCK_TIMEOUT_MS (encrypt is at least as
 * expensive as decrypt); 2000 keeps one call's decrypt work within roughly
 * that same low-seconds order of magnitude regardless of how large the vault
 * grows, instead of scaling with it.
 */
const MEMORY_CORPUS_SCAN_CAP = 2000;

/**
 * Hard ceiling on the caller-supplied `limit` for search/list, and the
 * default when the caller supplies none (searchPassages keeps its own
 * smaller DEFAULT_SEARCH_LIMIT default; this is the max either can reach). A
 * limit above this is clamped, never rejected: paging with `after`
 * (listPassages) or a narrower query (searchPassages tag/text) is how a
 * caller gets the rest. Deliberately well below MEMORY_CORPUS_SCAN_CAP (see
 * assertion below) so a scan never stops before filling a full page.
 */
const MEMORY_LIST_MAX_LIMIT = 500;

if (MEMORY_CORPUS_SCAN_CAP < MEMORY_LIST_MAX_LIMIT) {
  // Invariant listPassages relies on to tell "short page" from "capped scan"
  // apart without a separate truncation flag (see listPassages below). A
  // constant edit that violates it must fail loudly at import time, not
  // silently reintroduce a truncated-looking-complete page.
  throw new Error("MEMORY_CORPUS_SCAN_CAP must be >= MEMORY_LIST_MAX_LIMIT");
}

/** Everything an insert-or-replace needs, computed before any write happens. */
interface PreparedPassage {
  readonly documentId: string;
  readonly text: string;
  readonly documentRecord: SdwDocumentRecord;
  readonly chunkRecords: readonly SdwDocumentChunkRecord[];
  /**
   * Per-record authorizations derived from the source
   * MemoryPassageInput.classifierOverrideAuthorization (Rung-1 point 3), one
   * per record because a passage's document content_hash covers the whole
   * text while each chunk's content_hash covers only its own substring --
   * the write gate verifies a token against the ONE record it is about to
   * classify, so a whole-passage token cannot itself authorize a chunk.
   * `undefined` per slot when there was no valid parent authorization (the
   * ordinary, non-waiving case). Every write site below (insertPassage,
   * putPassages, putPassagesIfAbsent) must thread the matching slot into
   * mintDocument/mintChunk/putDocument/putChunk via documentMintOptions /
   * chunkMintOptions, because the classify pass those call lives one level
   * deeper than preparePassage's own assertSdwClassifierCleanText check.
   */
  readonly documentClassifierOverride: ClassifierOverrideAuthorization | undefined;
  readonly chunkClassifierOverrides: readonly (ClassifierOverrideAuthorization | undefined)[];
}

/**
 * `undefined` (not `{ classifierOverride: <token> }` unconditionally) for the
 * common case, so every OTHER call site's mintDocument/putDocument options
 * argument is exactly what it was before Rung-1 point 3 existed.
 */
function documentMintOptions(item: PreparedPassage): MintPersistableOptions | undefined {
  return item.documentClassifierOverride === undefined
    ? undefined
    : { classifierOverride: item.documentClassifierOverride };
}

/** Chunk counterpart of {@link documentMintOptions}, indexed to match `item.chunkRecords`. */
function chunkMintOptions(
  item: PreparedPassage,
  chunkIndex: number,
): MintPersistableOptions | undefined {
  const token = item.chunkClassifierOverrides[chunkIndex];
  return token === undefined ? undefined : { classifierOverride: token };
}

/** The prior state of one passage, captured so a failed batch can restore it. */
/** One still-encrypted record captured verbatim for a byte-for-byte restore. */
interface PriorRawRecord {
  readonly raw: Uint8Array;
  readonly contentHash: string;
}

/**
 * The prior state of one passage, captured so a failed batch can restore it.
 * `rawDocument`/`rawChunks` carry the EXACT ciphertext bytes read out of
 * storage before the batch began, for a verbatim restore -- `record` is kept
 * ONLY for bookkeeping (chunk_count, orphan-chunk deletion range), never
 * re-encrypted or written back itself.
 */
interface PriorPassage {
  readonly documentId: string;
  readonly record: SdwDocumentRecord | null;
  readonly rawDocument: PriorRawRecord | null;
  readonly rawChunks: readonly PriorRawRecord[];
}

interface OwnerScopeSnapshot {
  readonly keys: readonly string[];
}

export interface SdwMemoryBackendAdapterOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  /**
   * Scopes one engine instance (for Letta: one archive) to its own document
   * id prefix, isolating it from operator documents and from other engines
   * under the same fortress. SDW identifier grammar.
   */
  readonly ownerRef: string;
  /** Maximum characters per encrypted chunk (default 8192). */
  readonly maxChunkChars?: number;
  /**
   * Override for MEMORY_CORPUS_SCAN_CAP (default; see that constant's
   * derivation). Only a TIGHTER cap is accepted (1..default): this can
   * never be raised past the module default, so a caller cannot use this
   * option to defeat the rule-8 per-call decrypt bound. Test-only in
   * practice, to exercise the bound without a multi-thousand-passage corpus.
   */
  readonly corpusScanCap?: number;
  /** Same tightening-only contract as corpusScanCap, for MEMORY_LIST_MAX_LIMIT. */
  readonly listMaxLimit?: number;
  /** Injectable clock for tests; defaults to the system clock. */
  readonly now?: () => string;
}

export class SdwMemoryBackendAdapter implements MemoryBackendAdapter {
  private readonly storage: StorageBackend;
  private readonly corpus: SdwDocumentCorpusStore;
  readonly ownerRef: string;
  private readonly passageIdKey: Uint8Array;
  private readonly maxChunkChars: number;
  private readonly corpusScanCap: number;
  private readonly listMaxLimit: number;
  private readonly now: () => string;
  /**
   * Process-local duplicate-insert guard for non-transactional backends. This
   * does not coordinate with another Sanctuary process pointed at the same
   * filesystem storage path; cross-process duplicate prevention must come from
   * a backend-level atomic conditional write or transaction.
   */
  private readonly insertLocks = new Map<string, Promise<void>>();

  constructor(options: SdwMemoryBackendAdapterOptions) {
    assertSdwIdentifier(options.ownerRef, "owner_ref");
    if (options.ownerRef.includes(".")) {
      throw new SdwValidationError(
        "invalid_identifier",
        "Invalid SDW identifier: owner_ref must not contain '.'",
      );
    }
    const maxChunkChars = options.maxChunkChars ?? DEFAULT_MAX_CHUNK_CHARS;
    if (
      !Number.isSafeInteger(maxChunkChars) ||
      maxChunkChars < 1 ||
      maxChunkChars > MAX_CONFIGURABLE_CHUNK_CHARS
    ) {
      throw new SdwValidationError(
        "invalid_identifier",
        "Invalid SDW memory adapter maxChunkChars",
      );
    }
    const corpusScanCap = options.corpusScanCap ?? MEMORY_CORPUS_SCAN_CAP;
    if (
      !Number.isSafeInteger(corpusScanCap) ||
      corpusScanCap < 1 ||
      corpusScanCap > MEMORY_CORPUS_SCAN_CAP
    ) {
      throw new SdwValidationError(
        "invalid_identifier",
        `Invalid SDW memory adapter corpusScanCap (must be 1-${MEMORY_CORPUS_SCAN_CAP})`,
      );
    }
    const listMaxLimit = options.listMaxLimit ?? MEMORY_LIST_MAX_LIMIT;
    if (
      !Number.isSafeInteger(listMaxLimit) ||
      listMaxLimit < 1 ||
      listMaxLimit > MEMORY_LIST_MAX_LIMIT
    ) {
      throw new SdwValidationError(
        "invalid_identifier",
        `Invalid SDW memory adapter listMaxLimit (must be 1-${MEMORY_LIST_MAX_LIMIT})`,
      );
    }
    if (corpusScanCap < listMaxLimit) {
      // Same invariant as the module-level default assertion, re-checked per
      // instance: listPassages relies on scanning at least `limit` candidates
      // whenever they exist, so a short page always means "no more" and
      // never "we stopped scanning too early to tell".
      throw new SdwValidationError(
        "invalid_identifier",
        "Invalid SDW memory adapter options: corpusScanCap must be >= listMaxLimit",
      );
    }
    this.storage = options.storage;
    this.corpus = new SdwDocumentCorpusStore({
      storage: options.storage,
      masterKey: options.masterKey,
      fortressId: options.fortressId,
    });
    this.ownerRef = options.ownerRef;
    this.passageIdKey = derivePurposeKey(options.masterKey, MEMORY_PASSAGE_ID_HKDF_INFO);
    this.maxChunkChars = maxChunkChars;
    this.corpusScanCap = corpusScanCap;
    this.listMaxLimit = listMaxLimit;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async insertPassage(
    input: MemoryPassageInput,
    taint: PersistableTaint,
  ): Promise<MemoryPassage> {
    const prepared = this.preparePassage(input);
    const { documentId, documentRecord, chunkRecords } = prepared;

    const transactional = asSdwTransactional(this.storage);
    if (transactional !== null) {
      await transactional.sdwTransaction(async (txn) => {
        await this.assertDocumentAbsent(documentId, txn);
        for (const [index, chunkRecord] of chunkRecords.entries()) {
          await this.corpus.putChunk(chunkRecord, taint, txn, chunkMintOptions(prepared, index));
        }
        await this.corpus.putDocument(documentRecord, taint, txn, documentMintOptions(prepared));
      });
    } else {
      await this.withDocumentLock(documentId, async () => {
        await this.assertDocumentAbsent(documentId);
        const writtenChunkKeys: string[] = [];
        try {
          for (const [index, chunkRecord] of chunkRecords.entries()) {
            writtenChunkKeys.push(documentChunkStorageKey(chunkRecord));
            await this.corpus.putChunk(
              chunkRecord,
              taint,
              undefined,
              chunkMintOptions(prepared, index),
            );
          }
          await this.corpus.putDocument(
            documentRecord,
            taint,
            undefined,
            documentMintOptions(prepared),
          );
        } catch (error) {
          await this.rollbackInsert(documentId, writtenChunkKeys);
          throw error;
        }
      });
    }
    return this.toPassage(documentRecord, prepared.text);
  }

  screenPassage(
    input: MemoryPassageInput,
    taint: PersistableTaint,
    applyBareCredentialFallback = false,
  ): MemoryPassageScreen {
    try {
      // screenPassage NEVER sets or reads classifierOverrideAuthorization (see
      // the interface doc in memory-backend.ts): the dry run always reports
      // the UN-WAIVED verdict, even when the caller's input already carries a
      // genuine authorization token. A caller cannot get a false "ok" out of a
      // screen by pre-setting the field on the input it screens with; only
      // putPassages/insertPassage/putPassagesIfAbsent honor it, and only for
      // the exact input object it was set on.
      const unwaived: MemoryPassageInput = {
        ...input,
        classifierOverrideAuthorization: undefined,
      };
      const prepared = this.preparePassage(unwaived, applyBareCredentialFallback);
      // Mint (and discard) every record the real write would persist. Minting
      // is the enforcement point for the grammar checks and the fail-closed
      // secret classifier and has no side effects, so this screen cannot drift
      // from the gate putPassages re-runs on the same records (absent an
      // override, which this screen never applies).
      this.corpus.mintDocument(prepared.documentRecord, taint);
      for (const chunkRecord of prepared.chunkRecords) {
        this.corpus.mintChunk(chunkRecord, taint);
      }
      return { ok: true };
    } catch (error) {
      if (error instanceof SdwValidationError) {
        return {
          ok: false,
          category: error.category,
          message: error.message,
          detector: error.detector,
          line: error.line,
        };
      }
      throw error;
    }
  }

  async putPassages(
    inputs: readonly MemoryPassageInput[],
    taint: PersistableTaint,
    applyBareCredentialFallback = false,
  ): Promise<readonly MemoryPassage[]> {
    if (inputs.length === 0) return [];
    for (const input of inputs) {
      if (input.passage_id === undefined) {
        throw new SdwValidationError(
          "invalid_identifier",
          "SDW memory batch write requires an explicit passage_id per passage",
        );
      }
    }
    // Prepare (and therefore validate and classify) EVERYTHING before the first
    // byte is written. A rejection found halfway through would otherwise be the
    // partial-commit this method exists to prevent.
    const prepared = inputs.map((input) => this.preparePassage(input, applyBareCredentialFallback));
    const seen = new Set<string>();
    for (const item of prepared) {
      if (seen.has(item.documentId)) {
        throw new SdwValidationError(
          "duplicate_passage",
          "SDW memory batch write contains the same passage_id twice",
        );
      }
      seen.add(item.documentId);
    }

    const documentIds = prepared.map((item) => item.documentId);
    return this.withDocumentLocks(documentIds, async () => {
      const transactional = asSdwTransactional(this.storage);
      if (transactional !== null) {
        const prior = await this.capturePriorPassages(prepared);
        await transactional.sdwTransaction(async (txn) => {
          for (const item of prepared) {
            for (const [index, chunkRecord] of item.chunkRecords.entries()) {
              await this.corpus.putChunk(chunkRecord, taint, txn, chunkMintOptions(item, index));
            }
            await this.corpus.putDocument(item.documentRecord, taint, txn, documentMintOptions(item));
          }
        });
        await this.pruneOrphanChunks(prepared, prior);
        return prepared.map((item) => this.toPassage(item.documentRecord, item.text));
      } else {
        return withCrossProcessLock(
          this.storage,
          MEMORY_BATCH_LOCK_NAMESPACE,
          this.ownerScopeBatchLockFile(),
          async () => {
            const prior = await this.capturePriorPassages(prepared);
            const beforeOwnerScope = await this.captureOwnerScopeSnapshot();
            try {
              for (const item of prepared) {
                for (const [index, chunkRecord] of item.chunkRecords.entries()) {
                  await this.corpus.putChunk(
                    chunkRecord,
                    taint,
                    undefined,
                    chunkMintOptions(item, index),
                  );
                }
                await this.corpus.putDocument(
                  item.documentRecord,
                  taint,
                  undefined,
                  documentMintOptions(item),
                );
              }
            } catch (error) {
              await this.restoreAndVerifyPriorPassages(prepared, prior, beforeOwnerScope);
              throw error;
            }
            // Post-commit only. A replaced passage that shrank leaves chunks
            // past the new chunk_count; reads are bounded by chunk_count so
            // they are already unreachable, and this removes the stale
            // ciphertext. A failure here leaves garbage, never a wrong read,
            // so it must not fail the write.
            await this.pruneOrphanChunks(prepared, prior);
            return prepared.map((item) => this.toPassage(item.documentRecord, item.text));
          },
          {
            // Measured 2026-08-07 against a real 413-file Claude Code memory
            // directory: first ingest 7184 ms, re-ingest 8052 ms. The 30 s
            // budget gives this batch write room beyond the lock helper's
            // default for millisecond-duration state writes.
            timeoutMs: MEMORY_BATCH_LOCK_TIMEOUT_MS,
          },
        );
      }
    });
  }

  async putPassagesIfAbsent(
    inputs: readonly MemoryPassageInput[],
    taint: PersistableTaint,
  ): Promise<readonly MemoryPassage[] | null> {
    if (inputs.length === 0) return [];
    for (const input of inputs) {
      if (input.passage_id === undefined) {
        throw new SdwValidationError(
          "invalid_identifier",
          "SDW memory conditional batch write requires an explicit passage_id per passage",
        );
      }
    }
    // As with putPassages, validate and classify the complete set before
    // entering the decision/write critical section.
    const prepared = inputs.map((input) => this.preparePassage(input));
    const seen = new Set<string>();
    for (const item of prepared) {
      if (seen.has(item.documentId)) {
        throw new SdwValidationError(
          "duplicate_passage",
          "SDW memory conditional batch write contains the same passage_id twice",
        );
      }
      seen.add(item.documentId);
    }

    const documentIds = prepared.map((item) => item.documentId);
    return this.withDocumentLocks(documentIds, async () => {
      const transactional = asSdwTransactional(this.storage);
      if (transactional !== null) {
        return transactional.sdwTransaction(async (txn) => {
          for (const item of prepared) {
            if (await this.corpus.getDocument(item.documentId, txn) !== null) {
              return null;
            }
          }
          for (const item of prepared) {
            for (const [index, chunkRecord] of item.chunkRecords.entries()) {
              await this.corpus.putChunk(chunkRecord, taint, txn, chunkMintOptions(item, index));
            }
            await this.corpus.putDocument(item.documentRecord, taint, txn, documentMintOptions(item));
          }
          return prepared.map((item) => this.toPassage(item.documentRecord, item.text));
        });
      }

      return withCrossProcessLock(
        this.storage,
        MEMORY_BATCH_LOCK_NAMESPACE,
        this.ownerScopeBatchLockFile(),
        async () => {
          for (const item of prepared) {
            if (await this.corpus.getDocument(item.documentId) !== null) {
              return null;
            }
          }
          const prior = await this.capturePriorPassages(prepared);
          const beforeOwnerScope = await this.captureOwnerScopeSnapshot();
          try {
            for (const item of prepared) {
              for (const [index, chunkRecord] of item.chunkRecords.entries()) {
                await this.corpus.putChunk(
                  chunkRecord,
                  taint,
                  undefined,
                  chunkMintOptions(item, index),
                );
              }
              await this.corpus.putDocument(
                item.documentRecord,
                taint,
                undefined,
                documentMintOptions(item),
              );
            }
          } catch (error) {
            await this.restoreAndVerifyPriorPassages(
              prepared,
              prior,
              beforeOwnerScope,
            );
            throw error;
          }
          return prepared.map((item) => this.toPassage(item.documentRecord, item.text));
        },
        { timeoutMs: MEMORY_BATCH_LOCK_TIMEOUT_MS },
      );
    });
  }

  derivePassageId(domain: string, label: string): string {
    assertSdwIdentifier(domain, "passage_id_domain");
    const mac = hmacSha256(
      this.passageIdKey,
      lengthPrefixedUtf8([MEMORY_PASSAGE_ID_MAC_DOMAIN, domain, this.ownerRef, label]),
    );
    const id = Buffer.from(mac).toString("hex").slice(0, MEMORY_PASSAGE_ID_HEX_CHARS);
    // Hex is a strict subset of the SDW identifier grammar; assert anyway so a
    // future encoding change cannot silently mint an invalid storage key.
    return assertSdwIdentifier(id, "passage_id");
  }

  async getPassage(passageId: string): Promise<MemoryPassage | null> {
    assertSdwIdentifier(passageId, "passage_id");
    const document = await this.corpus.getDocument(this.documentId(passageId));
    if (document === null) return null;
    const text = await this.readPassageText(document);
    return this.toPassage(document, text);
  }

  async searchPassages(query: MemorySearchQuery): Promise<readonly MemorySearchResult[]> {
    const rawLimit = query.limit ?? DEFAULT_SEARCH_LIMIT;
    if (!Number.isSafeInteger(rawLimit) || rawLimit < 1) {
      throw new SdwValidationError("invalid_identifier", "Invalid SDW memory search limit");
    }
    const limit = Math.min(rawLimit, this.listMaxLimit);
    const needle = query.text.toLowerCase();
    // Ranking needs every passage's match_count, so unlike listPassages
    // (which can cap-and-page via the `after` cursor) there is no partial
    // scan that stays honest: a corpus over the cap fails closed with a
    // typed bound instead of silently ranking only an arbitrary slice of it
    // and returning that as if it were the best matches in the vault.
    const { documents, truncated } = await this.listDocuments(this.corpusScanCap);
    if (truncated) {
      throw new SdwValidationError(
        "search_scan_bound",
        `SDW memory search corpus exceeds the ${this.corpusScanCap}-passage per-call scan bound; narrow with a tag filter or use memory_list to page instead`,
      );
    }
    const results: MemorySearchResult[] = [];
    for (const document of documents) {
      if (query.tag !== undefined && !(document.tags ?? []).includes(query.tag)) {
        continue;
      }
      const text = await this.readPassageText(document);
      const matchCount = needle.length === 0 ? 0 : countOccurrences(text.toLowerCase(), needle);
      if (matchCount === 0) continue;
      results.push({ passage: this.toPassage(document, text), match_count: matchCount });
    }
    results.sort(
      (a, b) =>
        b.match_count - a.match_count ||
        b.passage.created_at.localeCompare(a.passage.created_at) ||
        a.passage.passage_id.localeCompare(b.passage.passage_id),
    );
    return results.slice(0, limit);
  }

  async listPassages(options: MemoryListOptions = {}): Promise<readonly MemoryPassage[]> {
    const rawLimit = options.limit ?? this.listMaxLimit;
    if (!Number.isSafeInteger(rawLimit) || rawLimit < 1) {
      throw new SdwValidationError("invalid_identifier", "Invalid SDW memory list limit");
    }
    const limit = Math.min(rawLimit, this.listMaxLimit);
    // rule-8 bound: this.corpusScanCap >= this.listMaxLimit is asserted in
    // the constructor (mirroring the module-default assertion above), so a
    // scan capped at this.corpusScanCap always covers at least `limit`
    // after-filtered candidates when that many exist. A short page (fewer
    // than `limit` results) therefore always means "no more past the
    // cursor", never "we stopped scanning too early to tell"; it is never
    // presented as complete when it might not be. A FULL page (length ===
    // limit) means there may be more: the caller pages again with
    // after=<last returned passage_id>, the standard cursor idiom this
    // contract already documents, rather than this method claiming
    // completeness it cannot verify without a second scan.
    const { documents } = await this.listDocuments(this.corpusScanCap, options.after);
    const passages: MemoryPassage[] = [];
    for (const document of documents) {
      passages.push(this.toPassage(document, await this.readPassageText(document)));
      if (passages.length >= limit) break;
    }
    return passages;
  }

  async deletePassage(passageId: string): Promise<boolean> {
    assertSdwIdentifier(passageId, "passage_id");
    const documentId = this.documentId(passageId);
    const document = await this.corpus.getDocument(documentId);
    if (document === null) return false;
    for (let ordinal = 0; ordinal < document.chunk_count; ordinal++) {
      await this.storage.delete(
        SDW_DOCUMENT_CORPUS_NAMESPACE,
        documentChunkKey(documentId, padChunkOrdinal(ordinal), chunkId(ordinal)),
        true,
      );
    }
    return this.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentKey(documentId), true);
  }

  async countPassages(): Promise<number> {
    const entries = await this.storage.list(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      this.documentKeyPrefix(),
    );
    return entries.length;
  }

  /**
   * Build every record a passage write persists. Pure: it validates, classifies,
   * and returns records, and touches no storage. insertPassage, putPassages, and
   * screenPassage all go through here so the three cannot disagree about what
   * "acceptable" means.
   */
  private preparePassage(
    input: MemoryPassageInput,
    applyBareCredentialFallback = false,
  ): PreparedPassage {
    const passageId = input.passage_id ?? generatePassageId();
    const documentId = this.documentId(passageId);
    const createdAt = input.created_at ?? this.now();
    const tags = input.tags ?? [];
    const metadata = input.metadata ?? [];
    validatePassageText(input.text);
    validatePassageDecorators(tags, metadata);
    // Rung-1 point 3: the document record's own authorization, verified
    // against input.text itself BEFORE anything downstream trusts it.
    // deriveClassifierOverrideAuthorization independently recomputes the
    // parent's content hash from parentText and requires recordText to be a
    // literal substring of it, so a token bound to different text (or a
    // caller-supplied hash with no matching text) never verifies here even
    // if it is genuinely a real, registered token -- a verified parent is
    // never a mint oracle for an arbitrary, unrelated hash.
    const passageHash = passageContentHash(input.text);
    const documentClassifierOverride = deriveClassifierOverrideAuthorization(
      input.classifierOverrideAuthorization,
      input.text,
      input.text,
    );
    // classifierOverrideAuthorization skips ONLY this one check, for this one
    // passage, and only once it has verified above. It is set exclusively by
    // the memory-file ingest path, and only for a source file the operator
    // named on an explicit --allow-file / allow_files list AFTER a prior
    // classifier run already reported what it would have refused (see
    // MemoryPassageInput.classifierOverrideAuthorization). Every other input
    // in the same batch, and every other check for THIS input (grammar, size,
    // taint), is unaffected.
    if (documentClassifierOverride === undefined) {
      assertSdwClassifierCleanText(input.text, applyBareCredentialFallback);
    }
    const chunks = chunkText(input.text, this.maxChunkChars);
    const chunkRecords = chunks.map(
      (text, ordinal): SdwDocumentChunkRecord => ({
        kind: "document_chunk",
        version: 1,
        chunk_id: chunkId(ordinal),
        document_id: documentId,
        chunk_ordinal: ordinal,
        text,
        content_hash: passageContentHash(text),
        created_at: createdAt,
      }),
    );
    const documentRecord: SdwDocumentRecord = {
      kind: "document",
      version: 1,
      document_id: documentId,
      source: { kind: "internal" },
      content_hash: passageHash,
      chunk_count: chunks.length,
      byte_length: stringToBytes(input.text).length,
      created_at: createdAt,
      updated_at: createdAt,
      tags,
      metadata,
    };
    // Re-scope the SAME verified passage-level authorization to each CHUNK's
    // own text (a chunk's content_hash is over its substring, not the whole
    // passage, so the document-level token above cannot itself authorize a
    // chunk write; deriveClassifierOverrideAuthorization verifies chunkRecord.text
    // is literally contained in input.text, which chunkText's contiguous
    // slicing guarantees for every real chunk). Undefined for every chunk
    // when there was no valid parent authorization, exactly mirroring
    // documentClassifierOverride.
    const chunkClassifierOverrides = chunkRecords.map((chunkRecord) =>
      deriveClassifierOverrideAuthorization(
        input.classifierOverrideAuthorization,
        input.text,
        chunkRecord.text,
      ),
    );
    return {
      documentId,
      text: input.text,
      documentRecord,
      chunkRecords,
      documentClassifierOverride,
      chunkClassifierOverrides,
    };
  }

  /**
   * Hold the per-document locks for a whole batch. Ids are acquired in sorted
   * order, so two overlapping batches acquire shared documents in the same
   * order and cannot deadlock against each other.
   */
  private async withDocumentLocks<T>(
    documentIds: readonly string[],
    fn: () => Promise<T>,
  ): Promise<T> {
    const ordered = [...new Set(documentIds)].sort();
    const acquire = async (index: number): Promise<T> =>
      index >= ordered.length
        ? fn()
        : this.withDocumentLock(ordered[index]!, () => acquire(index + 1));
    return acquire(0);
  }

  /**
   * Read the pre-write state of every batch target so a failed non-transactional
   * batch can be undone. Captures the EXACT still-encrypted bytes
   * (getDocumentRaw/getChunkRaw), not decrypted plaintext -- restore writes
   * these SAME bytes back unchanged rather than re-encrypting a decrypted
   * copy (see restorePriorChunk/restorePriorDocument below).
   */
  private async capturePriorPassages(
    prepared: readonly PreparedPassage[],
  ): Promise<readonly PriorPassage[]> {
    const prior: PriorPassage[] = [];
    for (const item of prepared) {
      const documentRaw = await this.corpus.getDocumentRaw(item.documentId);
      if (documentRaw === null) {
        prior.push({ documentId: item.documentId, record: null, rawDocument: null, rawChunks: [] });
        continue;
      }
      const rawChunks: PriorRawRecord[] = [];
      for (let ordinal = 0; ordinal < documentRaw.record.chunk_count; ordinal++) {
        const chunkRaw = await this.corpus.getChunkRaw(item.documentId, ordinal, chunkId(ordinal));
        if (chunkRaw === null) {
          throw new SdwValidationError(
            "passage_incomplete",
            "SDW memory passage chunk missing during rollback capture",
          );
        }
        rawChunks.push({ raw: chunkRaw.raw, contentHash: chunkRaw.record.content_hash });
      }
      prior.push({
        documentId: item.documentId,
        record: documentRaw.record,
        rawDocument: { raw: documentRaw.raw, contentHash: documentRaw.record.content_hash },
        rawChunks,
      });
    }
    return prior;
  }

  /**
   * Compensating undo for a partially applied non-transactional batch: restore
   * what existed, delete what did not, then verify the raw owner-scope key
   * listing and restored contents. If verification cannot prove the pre-state,
   * the caller gets an explicit partial_scope failure instead of an
   * all-or-nothing-looking write error.
   */
  private async restoreAndVerifyPriorPassages(
    prepared: readonly PreparedPassage[],
    prior: readonly PriorPassage[],
    beforeOwnerScope: OwnerScopeSnapshot,
  ): Promise<void> {
    const failures: unknown[] = [];
    const attempt = async (fn: () => Promise<void>): Promise<void> => {
      try {
        await fn();
      } catch (error) {
        failures.push(error);
      }
    };
    const preparedByDocumentId = new Map(
      prepared.map((item) => [item.documentId, item]),
    );

    for (const item of [...prior].reverse()) {
      const preparedItem = preparedByDocumentId.get(item.documentId);
      if (preparedItem === undefined) {
        failures.push(new Error("SDW memory rollback target missing"));
        continue;
      }

      if (item.record === null || item.rawDocument === null) {
        for (const chunkRecord of [...preparedItem.chunkRecords].reverse()) {
          const key = documentChunkStorageKey(chunkRecord);
          await attempt(async () => {
            await this.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, key, true);
          });
        }
        await attempt(async () => {
          await this.storage.delete(
            SDW_DOCUMENT_CORPUS_NAMESPACE,
            documentKey(item.documentId),
            true,
          );
        });
        continue;
      }

      // Restore through restorePriorChunk / restorePriorDocument,
      // NEVER through putChunk/putDocument, and with the EXACT captured raw
      // ciphertext bytes, never a re-encrypted copy of decrypted plaintext.
      // These prior bytes were already durably persisted before this batch
      // began (read back by capturePriorPassages out of the SAME encrypted
      // store), so re-running them through the classifying write path would
      // re-trip the classifier for a PREVIOUSLY-waived passage and turn a
      // rollback into a second, unrecoverable failure; and re-encrypting a
      // byte-identical plaintext would still not be the SAME bytes that were
      // at rest, which is the property being restored.
      for (const [ordinal, rawChunk] of item.rawChunks.entries()) {
        await attempt(async () => {
          await this.corpus.restorePriorChunk(
            item.documentId,
            ordinal,
            chunkId(ordinal),
            rawChunk.raw,
            rawChunk.contentHash,
          );
        });
      }
      await attempt(async () => {
        await this.corpus.restorePriorDocument(
          item.documentId,
          item.rawDocument!.raw,
          item.rawDocument!.contentHash,
        );
      });

      for (
        let ordinal = item.record.chunk_count;
        ordinal < preparedItem.chunkRecords.length;
        ordinal++
      ) {
        const chunkRecord = preparedItem.chunkRecords[ordinal]!;
        const key = documentChunkStorageKey(chunkRecord);
        await attempt(async () => {
          await this.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, key, true);
        });
      }
    }

    if (failures.length > 0) {
      throw partialScopeError(rollbackFailureCause(failures));
    }
    try {
      await this.verifyPriorPassagesRestored(beforeOwnerScope, prior);
    } catch (error) {
      throw partialScopeError(error);
    }
  }

  private async pruneOrphanChunks(
    prepared: readonly PreparedPassage[],
    prior: readonly PriorPassage[],
  ): Promise<void> {
    const priorCounts = new Map(
      prior.map((item) => [item.documentId, item.record?.chunk_count ?? 0]),
    );
    for (const item of prepared) {
      const before = priorCounts.get(item.documentId) ?? 0;
      for (let ordinal = item.chunkRecords.length; ordinal < before; ordinal++) {
        try {
          await this.storage.delete(
            SDW_DOCUMENT_CORPUS_NAMESPACE,
            documentChunkKey(item.documentId, padChunkOrdinal(ordinal), chunkId(ordinal)),
            true,
          );
        } catch {
          // Unreachable ciphertext left behind is not a correctness failure.
        }
      }
    }
  }

  private async captureOwnerScopeSnapshot(): Promise<OwnerScopeSnapshot> {
    return { keys: await this.ownerScopeCorpusKeys() };
  }

  /**
   * Verifies BYTE-FOR-BYTE that the restored ciphertext matches what
   * capturePriorPassages actually captured -- not merely that the DECRYPTED
   * content is equivalent (a re-encryption could satisfy that while
   * producing genuinely different at-rest bytes, which is exactly what this
   * restore path is designed to avoid).
   */
  private async verifyPriorPassagesRestored(
    beforeOwnerScope: OwnerScopeSnapshot,
    prior: readonly PriorPassage[],
  ): Promise<void> {
    const afterKeys = await this.ownerScopeCorpusKeys();
    if (!sameStrings(afterKeys, beforeOwnerScope.keys)) {
      throw new Error("SDW memory rollback owner-scope key listing mismatch");
    }
    for (const item of prior) {
      const documentRaw = await this.corpus.getDocumentRaw(item.documentId);
      if (item.record === null || item.rawDocument === null) {
        if (documentRaw !== null) {
          throw new Error(`SDW memory rollback left unexpected document ${item.documentId}`);
        }
        continue;
      }
      if (documentRaw === null) {
        throw new Error(`SDW memory rollback did not restore document ${item.documentId}`);
      }
      if (!constantTimeEqual(documentRaw.raw, item.rawDocument.raw)) {
        throw new Error(
          `SDW memory rollback restored the wrong document bytes for ${item.documentId}`,
        );
      }
      for (const [ordinal, rawChunk] of item.rawChunks.entries()) {
        const chunkRaw = await this.corpus.getChunkRaw(item.documentId, ordinal, chunkId(ordinal));
        if (chunkRaw === null) {
          throw new Error(
            `SDW memory rollback did not restore chunk ${String(ordinal)} of ${item.documentId}`,
          );
        }
        if (!constantTimeEqual(chunkRaw.raw, rawChunk.raw)) {
          throw new Error(
            `SDW memory rollback restored the wrong chunk ${String(ordinal)} bytes for ${item.documentId}`,
          );
        }
      }
    }
  }

  private async ownerScopeCorpusKeys(): Promise<readonly string[]> {
    const entries = [
      ...(await this.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, this.documentKeyPrefix())),
      ...(await this.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, this.documentChunkKeyPrefix())),
    ];
    return [...new Set(entries.map((entry) => entry.key))].sort();
  }

  private documentId(passageId: string): string {
    assertSdwIdentifier(passageId, "passage_id");
    const documentId = `${MEMORY_PASSAGE_DOCUMENT_PREFIX}.${this.ownerRef}.${passageId}`;
    // Re-assert the combined id so a near-limit passage id cannot silently
    // produce an over-length or malformed document id.
    return assertSdwIdentifier(documentId, "document_id");
  }

  private passageIdOf(documentId: string): string {
    return documentId.slice(`${MEMORY_PASSAGE_DOCUMENT_PREFIX}.${this.ownerRef}.`.length);
  }

  private documentKeyPrefix(): string {
    return `doc.${MEMORY_PASSAGE_DOCUMENT_PREFIX}.${this.ownerRef}.`;
  }

  private documentChunkKeyPrefix(): string {
    return `chunk.${MEMORY_PASSAGE_DOCUMENT_PREFIX}.${this.ownerRef}.`;
  }

  private ownerScopeBatchLockFile(): string {
    // The lock spans every passage in this owner scope because rollback verifies
    // the whole raw owner-scope key listing. A narrower lock could treat another
    // process's committed passage as rollback damage.
    return `${MEMORY_PASSAGE_DOCUMENT_PREFIX}.${this.ownerRef}.${MEMORY_BATCH_LOCK_FILE}`;
  }

  private async assertDocumentAbsent(documentId: string, txn?: SdwCorpusTxn): Promise<void> {
    const raw = await (txn ?? this.storage).read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentKey(documentId),
    );
    if (raw !== null) {
      throw new SdwValidationError(
        "duplicate_passage",
        "SDW memory passage already exists",
      );
    }
  }

  private async withDocumentLock<T>(documentId: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.insertLocks.get(documentId) ?? Promise.resolve();
    const run = previous.catch(() => {}).then(fn);
    const tail = run.then(
      () => undefined,
      () => undefined,
    );
    this.insertLocks.set(documentId, tail);
    try {
      return await run;
    } finally {
      if (this.insertLocks.get(documentId) === tail) {
        this.insertLocks.delete(documentId);
      }
    }
  }

  private async rollbackInsert(documentId: string, writtenChunkKeys: readonly string[]): Promise<void> {
    const failures: unknown[] = [];
    for (const key of [...writtenChunkKeys].reverse()) {
      try {
        await this.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, key, true);
      } catch (error) {
        failures.push(error);
      }
    }
    try {
      await this.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentKey(documentId), true);
    } catch (error) {
      failures.push(error);
    }
    if (failures.length > 0) {
      throw partialScopeError(rollbackFailureCause(failures));
    }
  }

  /**
   * Decrypt document metadata for up to `maxScan` documents in this owner
   * scope, in stable key order, optionally starting strictly after
   * `afterPassageId`. LD4 SDW-SEARCH-DOS-01 rule-8 bound: storage.list()
   * returns keys already sorted by key with no decryption (both
   * StorageBackend implementations this adapter ships against, filesystem.ts
   * and memory.ts, sort their list() output by key; this method's cursor
   * math depends on that and would silently misorder pages against a future
   * backend that does not), so the `after` cursor is applied to the
   * plaintext key BEFORE any document is decrypted, and metadata decrypt
   * here never exceeds `maxScan` documents regardless of corpus size.
   * `truncated: true` means more matching entries exist past what was
   * scanned; a caller must not treat the returned set as "everything".
   *
   * LD4 fix-round-2: the cursor comparison MUST use the same ordering as
   * storage.list()'s sort, or the filter disagrees with the iteration order
   * and silently drops or repeats entries across pages. Both shipping
   * backends sort with `String.prototype.localeCompare` (filesystem.ts,
   * memory.ts), which is a locale-collation order, NOT the code-unit order
   * of `>`; they diverge across the passage_id charset
   * (`[A-Za-z0-9._:@+-]`, and base64url `[A-Za-z0-9_-]`), e.g. `"_" > "Z"`
   * in code-unit order but `"_".localeCompare("Z") < 0` under default
   * collation. Comparing with `localeCompare` here matches the iteration
   * order exactly, so the cursor never skips or repeats a record.
   */
  private async listDocuments(
    maxScan: number,
    afterPassageId?: string,
  ): Promise<{ readonly documents: readonly SdwDocumentRecord[]; readonly truncated: boolean }> {
    // DEBT: storage.list() itself still enumerates the full owner-scope
    // corpus (O(corpus) key listing, no decryption) before the maxScan cap
    // below limits the decrypt work. Accepted as a residual, not fixed
    // here; see the LD4 SDW-SEARCH-DOS-01 rule-8 bound above for what IS
    // bounded.
    const entries = await this.storage.list(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      this.documentKeyPrefix(),
    );
    const afterKey =
      afterPassageId === undefined ? undefined : this.documentKeyPrefix() + afterPassageId;
    const candidates =
      afterKey === undefined
        ? entries
        : entries.filter((entry) => entry.key.localeCompare(afterKey) > 0);
    const truncated = candidates.length > maxScan;
    const scanSet = truncated ? candidates.slice(0, maxScan) : candidates;
    const documents: SdwDocumentRecord[] = [];
    for (const entry of scanSet) {
      const documentId = entry.key.slice("doc.".length);
      const document = await this.corpus.getDocument(documentId);
      // A vanished entry between list and read is a benign race; anything
      // decode-level (auth, identity) throws inside getDocument and
      // propagates: fail closed, never skip silently.
      if (document !== null) documents.push(document);
    }
    return { documents, truncated };
  }

  private async readPassageText(document: SdwDocumentRecord): Promise<string> {
    const parts: string[] = [];
    for (let ordinal = 0; ordinal < document.chunk_count; ordinal++) {
      const chunk = await this.corpus.getChunk(document.document_id, ordinal, chunkId(ordinal));
      if (chunk === null) {
        throw new SdwValidationError(
          "passage_incomplete",
          "SDW memory passage chunk missing",
        );
      }
      parts.push(chunk.text);
    }
    const text = parts.join("");
    if (passageContentHash(text) !== document.content_hash) {
      throw new SdwValidationError(
        "identity_mismatch",
        "SDW memory passage content hash mismatch",
      );
    }
    return text;
  }

  private toPassage(document: SdwDocumentRecord, text: string): MemoryPassage {
    return {
      passage_id: this.passageIdOf(document.document_id),
      owner_ref: this.ownerRef,
      text,
      tags: document.tags ?? [],
      metadata: document.metadata ?? [],
      created_at: document.created_at,
      chunk_count: document.chunk_count,
      content_hash: document.content_hash,
    };
  }
}

export function chunkText(text: string, maxChunkChars: number): readonly string[] {
  if (text.length === 0) return [""];
  const chunks: string[] = [];
  for (let start = 0; start < text.length; start += maxChunkChars) {
    chunks.push(text.slice(start, start + maxChunkChars));
  }
  return chunks;
}

// Moved to write-gate.ts (2026-08-22), imported above and
// re-exported here (the local binding, not a second module fetch) so every
// existing importer of passageContentHash from THIS module keeps working
// without an import-path change.
export { passageContentHash };

function chunkId(ordinal: number): string {
  return `c${padChunkOrdinal(ordinal)}`;
}

function countOccurrences(haystack: string, needle: string): number {
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

function generatePassageId(): string {
  const id = toBase64url(new Uint8Array(randomBytes(15)));
  // Defensive: base64url output always satisfies the SDW identifier grammar.
  if (!isSdwIdentifier(id)) {
    throw new SdwValidationError("invalid_identifier", "Invalid SDW identifier: passage_id");
  }
  return id;
}

interface SdwTransactionalStorage {
  sdwTransaction<T>(fn: (txn: SdwCorpusTxn) => Promise<T>): Promise<T>;
}

function asSdwTransactional(storage: StorageBackend): SdwTransactionalStorage | null {
  const candidate = storage as { readonly sdwTransaction?: unknown };
  return typeof candidate.sdwTransaction === "function"
    ? (candidate as SdwTransactionalStorage)
    : null;
}

function partialScopeError(cause?: unknown): SdwValidationError {
  return new SdwValidationError(
    "partial_scope",
    "SDW memory write failed and rollback could not verify the owner scope; inspect the audit record before retrying",
    cause === undefined ? undefined : { cause },
  );
}

function rollbackFailureCause(failures: readonly unknown[]): unknown {
  return failures.length === 1
    ? failures[0]
    : new AggregateError(failures, "SDW memory rollback had multiple restore failures");
}

function sameStrings(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((value, index) => value === b[index]);
}

function validatePassageDecorators(
  tags: readonly string[],
  metadata: readonly { readonly key: string }[],
): void {
  for (const tag of tags) assertSdwIdentifier(tag, "tag");
  for (const entry of metadata) assertSdwIdentifier(entry.key, "metadata.key");
}

function validatePassageText(text: string): void {
  if (hasUnpairedSurrogate(text)) {
    throw new SdwValidationError("invalid_text", "SDW memory passage text contains unpaired surrogate code units");
  }
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) return true;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}
