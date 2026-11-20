// Shared fixture for the score-first recall tests: an instrumented in-memory store, every seed kind the
// equivalence test needs, the verify-everything reference loop recall used before it scored first, and an
// independent oracle computed from the seeds alone.
import { ed25519 } from "@noble/curves/ed25519";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { publicKeyToDid } from "../../src/core/identity.js";
import {
  HermesRecallBudget,
  RECALL_READ_AHEAD_PASSAGES,
  compareRecallCandidates,
  recallTimestamp,
  type HermesRecallCandidate,
  type HermesRecallResult,
} from "../../src/hermes-memory-bridge/recall.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SdwDocumentCorpusStore, padChunkOrdinal } from "../../src/sdw/document-corpus-store.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import { documentChunkKey, documentKey, documentProvenanceKey, documentProvenanceStatusKey } from "../../src/sdw/grammar.js";
import { signMemoryOrigin } from "../../src/sdw/memory-provenance-contract.js";
import { exitV2ForeignImportIngress, memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE, type SdwDocumentRecord, type SdwMemoryIntegrityState } from "../../src/sdw/records.js";
import { passageContentHash } from "../../src/sdw/write-gate.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { testMemoryProvenanceDependencies } from "./test-memory-backend.js";

export const MASTER = new Uint8Array(32).fill(23);
export const FORTRESS = "recall-score-first";
export const OWNER = "agent";
export const NOW = "2026-11-01T00:00:00.000Z";
export const QUERY = "alpha bravo charlie";
export const QUERY_WORDS = ["alpha", "bravo", "charlie"] as const;
// None of these contains a query term as a substring, so a passage built only from them never matches.
export const FILLER_WORDS = ["garden", "budget", "review", "dentist", "flight", "library", "printer", "kitchen"] as const;
const GARBAGE = stringToBytes("{}"); // Parses as JSON but carries no ciphertext, so the record codec refuses it.

/** Counts every storage mutation; recall must leave the count at zero. */
export class RecallStorage extends MemoryStorage {
  writes = 0;
  chunkReads = 0;
  now = 0;
  step = 0;
  beforeRead?: (key: string) => void | Promise<void>;
  /** Keys whose stored bytes read back undecodable, as a damaged file would; the write gate refuses planting them. */
  readonly corrupt = new Set<string>();
  override async write(...args: Parameters<MemoryStorage["write"]>) { this.writes++; return super.write(...args); }
  override async writeIfAbsent(...args: Parameters<MemoryStorage["writeIfAbsent"]>) { this.writes++; return super.writeIfAbsent(...args); }
  override async replaceIfEquals(...args: Parameters<MemoryStorage["replaceIfEquals"]>) { this.writes++; return super.replaceIfEquals(...args); }
  override async delete(...args: Parameters<MemoryStorage["delete"]>) { this.writes++; return super.delete(...args); }
  override async read(namespace: string, key: string) {
    await this.beforeRead?.(key);
    this.now += this.step;
    if (key.startsWith("chunk.")) this.chunkReads++;
    const stored = await super.read(namespace, key);
    return stored !== null && this.corrupt.has(key) ? GARBAGE.slice() : stored;
  }
}

/** Every seed kind, grouped by how the verify-everything loop treats it: answered, skipped, or aborting the recall. */
export const SEED_KINDS = [
  "valid", "foreign-valid", "stale-status", "unsigned",
  "quarantined", "invalid-signature", "bad-signer", "unresolved-signer", "quarantined-missing-chunk",
  "bad-signer-max-body", "invalid-with-broken-chunk", "undecodable-provenance", "is-marked-throws-invalid",
  "missing-chunk", "undecodable-chunk", "undecodable-document",
  "undecodable-status", "is-marked-throws",
] as const;
export type SeedKind = typeof SEED_KINDS[number];
/** Kinds whose base outcome is an abort of the whole recall at the document or chunk layer. */
export const CLASS_A_KINDS: readonly SeedKind[] = ["missing-chunk", "undecodable-chunk", "undecodable-document"];
/** Kinds whose base outcome is a per-passage provenance abort; unsigned joins them in state_COMPLETE. */
export const CLASS_C_KINDS: readonly SeedKind[] = ["undecodable-status", "is-marked-throws"];
/** Kinds whose passage verification fails after its text was scored; only these can empty the heap short. */
export const SCORED_THEN_REJECTED_KINDS: readonly SeedKind[] = ["invalid-signature"];

export function outputEligible(kind: SeedKind, state: SdwMemoryIntegrityState): boolean {
  if (kind === "unsigned") return state !== "state_COMPLETE";
  return kind === "valid" || kind === "foreign-valid" || kind === "stale-status";
}
export function classC(kind: SeedKind, state: SdwMemoryIntegrityState): boolean {
  return CLASS_C_KINDS.includes(kind) || (kind === "unsigned" && state === "state_COMPLETE");
}

export interface Seed {
  readonly kind: SeedKind;
  readonly passageId: string;
  readonly text: string;
  readonly createdAt: string;
}

let foreignSeedByte = 0;

/** The read-ahead windows every recall case table runs at: one passage at a time, and the production default. */
export const RECALL_TEST_WINDOWS = [1, RECALL_READ_AHEAD_PASSAGES] as const;

export async function recallFixture(options: { readonly maxChunkChars?: number; readonly readAhead?: number } = {}) {
  const storage = new RecallStorage();
  const local = testMemoryProvenanceDependencies(MASTER);
  const foreignKeys = new Map<string, Uint8Array>();
  const marked = new Set<string>();
  const throwing = new Set<string>();
  const maxChunkChars = options.maxChunkChars ?? 8192; // The adapter default chunk size.
  let createdAt = NOW;
  let state: SdwMemoryIntegrityState | (() => Promise<SdwMemoryIntegrityState>) = "state_PRE_MIGRATION";
  const adapter = new SdwMemoryBackendAdapter({
    storage, masterKey: MASTER, fortressId: FORTRESS, ownerRef: OWNER, maxChunkChars, now: () => createdAt,
    resolvePrimarySigningHandle: local.resolvePrimarySigningHandle,
    resolveSignerPublicKey: (identityId, did) => foreignKeys.get(did)?.slice() ?? local.resolveSignerPublicKey(identityId, did),
    resolveMemoryIntegrityState: async () => typeof state === "function" ? state() : state,
    badSignerAuthority: { async isMarked(did) {
      if (throwing.has(did)) throw new Error("bad-signer authority unavailable");
      return marked.has(did);
    } },
    testOnlyDefaultProvenanceContext: memoryInsertIngress(() => "system:test", "system_generated"),
  });
  const corpus = new SdwDocumentCorpusStore({ storage, masterKey: MASTER, fortressId: FORTRESS });
  const documentIdOf = (passageId: string) => `mem.${OWNER}.${passageId}`;
  const firstChunkKey = (documentId: string) => documentChunkKey(documentId, padChunkOrdinal(0), `c${padChunkOrdinal(0)}`);

  async function insertForeign(passageId: string, text: string): Promise<string> {
    const seed = new Uint8Array(32).fill(++foreignSeedByte % 250 + 1); // Byte values 1..250 give distinct test keys.
    const publicKey = ed25519.getPublicKey(seed);
    const did = publicKeyToDid(publicKey);
    const signed = signMemoryOrigin({
      origin_fortress_id: `foreign-${passageId}`, owner_ref: "source-owner", passage_id: `source-${passageId}`,
      content_hash: passageContentHash(text), chunk_count: Math.max(1, Math.ceil(text.length / maxChunkChars)),
      author_agent_id: `agent-${passageId}`, ingress_channel: "memory_insert", source_class: "user_content", recorded_at: NOW,
    }, { identity_id: `foreign-${passageId}`, did, public_key: publicKey, sign: bytes => ed25519.sign(bytes, seed) });
    if (!signed.ok) throw new Error(signed.error.message);
    foreignKeys.set(did, publicKey);
    await adapter.insertPassage({ passage_id: passageId, text, provenanceContext: exitV2ForeignImportIngress({
      origin: signed.value, originPublicKey: publicKey, trustTier: "foreign_direct",
      transferLineageRef: "f".repeat(64), // Sixty-four hex characters is the lineage reference grammar.
    }) }, "user_content");
    return did;
  }
  async function tamperSignature(documentId: string): Promise<void> {
    const record = (await corpus.getProvenanceRaw(documentId))!.record;
    const signature = record.companion.origin.signature;
    const flipped = (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    await corpus.putProvenance({ ...record, companion: { ...record.companion,
      origin: { ...record.companion.origin, signature: flipped } } }, "system_generated");
  }
  async function writeStatus(documentId: string, stale: boolean): Promise<void> {
    const document = (await corpus.getDocument(documentId))!;
    const raw = await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(documentId));
    await corpus.putProvenanceStatus({ kind: "memory_provenance_status", version: 1, document_id: documentId,
      status: "quarantined", reason: "origin_signature_invalid", observed_content_hash: document.content_hash,
      observed_provenance_sha256: toBase64url(hash(stale ? GARBAGE : raw ?? new Uint8Array())), updated_at: NOW },
    "agent_derived_clean");
  }

  /** Seed one passage of the given kind; integrity state is pre-migration while seeding. */
  async function seed(input: Seed): Promise<void> {
    const { kind, passageId, text } = input;
    createdAt = input.createdAt;
    const documentId = documentIdOf(passageId);
    const foreignKind = kind === "foreign-valid" || kind === "bad-signer" || kind === "unresolved-signer" ||
      kind === "bad-signer-max-body" || kind === "is-marked-throws" || kind === "is-marked-throws-invalid";
    const did = foreignKind ? await insertForeign(passageId, text)
      : (await adapter.insertPassage({ passage_id: passageId, text }, "user_content"), undefined);
    switch (kind) {
      case "valid": case "foreign-valid": break;
      case "stale-status": await writeStatus(documentId, true); break;
      case "unsigned": await storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(documentId)); break;
      case "quarantined": await tamperSignature(documentId); await writeStatus(documentId, false); break;
      case "invalid-signature": await tamperSignature(documentId); break;
      case "bad-signer": case "bad-signer-max-body": marked.add(did!); break;
      case "unresolved-signer": foreignKeys.delete(did!); break;
      case "quarantined-missing-chunk":
        await tamperSignature(documentId); await writeStatus(documentId, false);
        await storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, firstChunkKey(documentId)); break;
      case "invalid-with-broken-chunk":
        await tamperSignature(documentId); await storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, firstChunkKey(documentId)); break;
      case "undecodable-provenance": storage.corrupt.add(documentProvenanceKey(documentId)); break;
      case "is-marked-throws": throwing.add(did!); break;
      case "is-marked-throws-invalid": throwing.add(did!); await tamperSignature(documentId); break;
      case "missing-chunk": await storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, firstChunkKey(documentId)); break;
      case "undecodable-chunk": storage.corrupt.add(firstChunkKey(documentId)); break;
      case "undecodable-document": storage.corrupt.add(documentKey(documentId)); break;
      case "undecodable-status": await writeStatus(documentId, true); storage.corrupt.add(documentProvenanceStatusKey(documentId)); break;
    }
  }

  /** Count companion verifications, the expensive step score-first recall bounds. */
  function countVerifications(onVerify?: (count: number) => void): { readonly count: () => number; reset(): void } {
    const target = adapter as unknown as { verifyCompanion: (...args: unknown[]) => unknown };
    const original = target.verifyCompanion.bind(adapter);
    let count = 0;
    target.verifyCompanion = (...args: unknown[]) => { count++; onVerify?.(count); return original(...args); };
    return { count: () => count, reset() { count = 0; } };
  }

  return {
    storage, adapter, corpus, seed, countVerifications, documentIdOf, firstChunkKey,
    setState(next: SdwMemoryIntegrityState | (() => Promise<SdwMemoryIntegrityState>)) { state = next; },
    budget(query = QUERY, nowMs: () => number = () => 0, signal = new AbortController().signal) {
      return new HermesRecallBudget(query, nowMs, signal, options.readAhead === undefined ? {} : { readAhead: options.readAhead });
    },
  };
}

interface ReferenceInternals {
  readonly storage: MemoryStorage;
  readonly corpus: SdwDocumentCorpusStore;
  documentKeyPrefix(): string;
  verifyOrQuarantineProvenance(document: SdwDocumentRecord): Promise<"verified" | "unsigned" | "quarantined">;
  assertUnsignedCompatibilityAllowed(status: "verified" | "unsigned" | "quarantined"): Promise<void>;
  toPassage(document: SdwDocumentRecord, text: string, status: "verified" | "unsigned"): { passage_id: string; created_at: string; text: string };
}

/**
 * The verify-everything loop recall ran before it scored first, kept as the equivalence reference.
 * It reaches the adapter's unchanged private provenance methods; like the original it quarantines (writes),
 * so a test runs it after the write-free loop it is compared with.
 */
export async function referenceRecall(adapter: SdwMemoryBackendAdapter, budget: HermesRecallBudget): Promise<HermesRecallResult> {
  const self = adapter as unknown as ReferenceInternals;
  if (budget.terms.length === 0 || !budget.active()) return budget.result();
  const entries = await self.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, self.documentKeyPrefix.call(adapter));
  for (const entry of entries) {
    // The original candidate check: the full wall, then the candidate cap.
    if (!budget.active()) break;
    if (budget.candidatesScanned === budget.limits.candidates) { budget.truncated = true; break; }
    budget.candidatesScanned++;
    const document = await self.corpus.getDocument(entry.key.slice("doc.".length));
    if (!budget.active()) break;
    if (document === null || recallTimestamp(document.created_at) === null) continue;
    if (document.chunk_count > budget.limits.passageUnits) { budget.truncated = true; continue; }
    const provenance = await self.verifyOrQuarantineProvenance.call(adapter, document);
    if (!budget.active()) break;
    if (provenance === "quarantined") continue;
    await self.assertUnsignedCompatibilityAllowed.call(adapter, provenance);
    const parts: string[] = [];
    let units = 0;
    let complete = true;
    for (let ordinal = 0; ordinal < document.chunk_count; ordinal++) {
      if (!budget.active()) { complete = false; break; }
      const chunk = await self.corpus.getChunk(document.document_id, ordinal, `c${padChunkOrdinal(ordinal)}`);
      if (chunk === null) throw new SdwValidationError("passage_incomplete", "SDW memory passage chunk missing");
      if (!budget.active() || !budget.scan(chunk.text.length)) { complete = false; break; }
      units += chunk.text.length;
      if (units > budget.limits.passageUnits) { budget.truncated = true; complete = false; break; }
      parts.push(chunk.text);
    }
    if (!complete) continue;
    const text = parts.join("");
    if (passageContentHash(text) !== document.content_hash) {
      throw new SdwValidationError("identity_mismatch", "SDW memory passage content hash mismatch");
    }
    budget.retain(self.toPassage.call(adapter, document, text, provenance));
  }
  return budget.result();
}

/** The answer from the seeds alone: the best three output-eligible passages, in today's ranking order. */
export function oracleRecall(seeds: readonly Seed[], state: SdwMemoryIntegrityState, query = QUERY): HermesRecallResult {
  const budget = new HermesRecallBudget(query, () => 0, new AbortController().signal);
  const candidates = seeds.filter(seed => outputEligible(seed.kind, state))
    .map(seed => budget.score({ passage_id: seed.passageId, created_at: seed.createdAt, text: seed.text }))
    .filter((candidate): candidate is HermesRecallCandidate => candidate !== null)
    .sort(compareRecallCandidates);
  for (const candidate of candidates) budget.admit(candidate);
  return budget.result();
}

export async function settle<T>(run: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: unknown }> {
  try { return { ok: true, value: await run() }; } catch (error) { return { ok: false, error }; }
}

/** Mulberry32 (its published constants), a small deterministic PRNG so a failing seed reproduces exactly. */
export function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
  };
}
