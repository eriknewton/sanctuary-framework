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
import { stringToBytes, toBase64url } from "../../core/encoding.js";
import { hash } from "../../core/hashing.js";
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
} from "../grammar.js";
import {
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  type SdwDocumentChunkRecord,
  type SdwDocumentRecord,
} from "../records.js";
import type { PersistableTaint } from "../provenance.js";
import { assertSdwClassifierCleanText } from "../write-gate.js";
import type {
  MemoryBackendAdapter,
  MemoryListOptions,
  MemoryPassage,
  MemoryPassageInput,
  MemorySearchQuery,
  MemorySearchResult,
} from "./memory-backend.js";

/** Document ids minted by this adapter are namespaced under this prefix. */
export const MEMORY_PASSAGE_DOCUMENT_PREFIX = "mem";

const DEFAULT_MAX_CHUNK_CHARS = 8192;
const MAX_CONFIGURABLE_CHUNK_CHARS = 100_000;
const DEFAULT_SEARCH_LIMIT = 10;

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
  /** Injectable clock for tests; defaults to the system clock. */
  readonly now?: () => string;
}

export class SdwMemoryBackendAdapter implements MemoryBackendAdapter {
  private readonly storage: StorageBackend;
  private readonly corpus: SdwDocumentCorpusStore;
  private readonly ownerRef: string;
  private readonly maxChunkChars: number;
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
    this.storage = options.storage;
    this.corpus = new SdwDocumentCorpusStore({
      storage: options.storage,
      masterKey: options.masterKey,
      fortressId: options.fortressId,
    });
    this.ownerRef = options.ownerRef;
    this.maxChunkChars = maxChunkChars;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async insertPassage(
    input: MemoryPassageInput,
    taint: PersistableTaint,
  ): Promise<MemoryPassage> {
    const passageId = input.passage_id ?? generatePassageId();
    const documentId = this.documentId(passageId);
    const createdAt = input.created_at ?? this.now();
    const tags = input.tags ?? [];
    const metadata = input.metadata ?? [];
    validatePassageText(input.text);
    validatePassageDecorators(tags, metadata);
    assertSdwClassifierCleanText(input.text);
    const contentHash = passageContentHash(input.text);
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
      content_hash: contentHash,
      chunk_count: chunks.length,
      byte_length: stringToBytes(input.text).length,
      created_at: createdAt,
      updated_at: createdAt,
      tags,
      metadata,
    };

    const transactional = asSdwTransactional(this.storage);
    if (transactional !== null) {
      await transactional.sdwTransaction(async (txn) => {
        await this.assertDocumentAbsent(documentId, txn);
        for (const chunkRecord of chunkRecords) {
          await this.corpus.putChunk(chunkRecord, taint, txn);
        }
        await this.corpus.putDocument(documentRecord, taint, txn);
      });
    } else {
      await this.withDocumentLock(documentId, async () => {
        await this.assertDocumentAbsent(documentId);
        const writtenChunkKeys: string[] = [];
        try {
          for (const chunkRecord of chunkRecords) {
            writtenChunkKeys.push(documentChunkStorageKey(chunkRecord));
            await this.corpus.putChunk(chunkRecord, taint);
          }
          await this.corpus.putDocument(documentRecord, taint);
        } catch (error) {
          await this.rollbackInsert(documentId, writtenChunkKeys);
          throw error;
        }
      });
    }
    return this.toPassage(documentRecord, input.text);
  }

  async getPassage(passageId: string): Promise<MemoryPassage | null> {
    assertSdwIdentifier(passageId, "passage_id");
    const document = await this.corpus.getDocument(this.documentId(passageId));
    if (document === null) return null;
    const text = await this.readPassageText(document);
    return this.toPassage(document, text);
  }

  async searchPassages(query: MemorySearchQuery): Promise<readonly MemorySearchResult[]> {
    const limit = query.limit ?? DEFAULT_SEARCH_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new SdwValidationError("invalid_identifier", "Invalid SDW memory search limit");
    }
    const needle = query.text.toLowerCase();
    const results: MemorySearchResult[] = [];
    for (const document of await this.listDocuments()) {
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
    const limit = options.limit ?? Number.MAX_SAFE_INTEGER;
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new SdwValidationError("invalid_identifier", "Invalid SDW memory list limit");
    }
    const passages: MemoryPassage[] = [];
    for (const document of await this.listDocuments()) {
      const passageId = this.passageIdOf(document.document_id);
      if (options.after !== undefined && passageId.localeCompare(options.after) <= 0) {
        continue;
      }
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
    for (const key of [...writtenChunkKeys].reverse()) {
      try {
        await this.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, key, true);
      } catch {
        // Best effort: keep deleting other rollback targets and preserve the
        // original insert error.
      }
    }
    try {
      await this.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentKey(documentId), true);
    } catch {
      // Best effort: rollback failures must not replace the insert failure.
    }
  }

  private async listDocuments(): Promise<readonly SdwDocumentRecord[]> {
    const entries = await this.storage.list(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      this.documentKeyPrefix(),
    );
    const documents: SdwDocumentRecord[] = [];
    for (const entry of entries) {
      const documentId = entry.key.slice("doc.".length);
      const document = await this.corpus.getDocument(documentId);
      // A vanished entry between list and read is a benign race; anything
      // decode-level (auth, identity) throws inside getDocument and
      // propagates: fail closed, never skip silently.
      if (document !== null) documents.push(document);
    }
    return documents;
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

export function passageContentHash(text: string): string {
  const domain = stringToBytes("sdw-memory-passage-content-v1\n");
  const body = stringToBytes(text);
  const bytes = new Uint8Array(domain.length + body.length);
  bytes.set(domain, 0);
  bytes.set(body, domain.length);
  return toBase64url(hash(bytes));
}

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
