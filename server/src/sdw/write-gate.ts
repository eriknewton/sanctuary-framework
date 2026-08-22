import type { StorageBackend } from "../storage/interface.js";
import { encrypt } from "../core/encryption.js";
import { bytesToString, stringToBytes, toBase64url } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hashToString, hmacSha256 } from "../core/hashing.js";
import { sdwAad, assertSdwIdentifier } from "./grammar.js";
import { assertTainted, type Tainted } from "./provenance.js";
import {
  SDW_CATALOG_NAMESPACE,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_REPLAY_ANCHOR_KEY,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_VECTOR_MEMORY_NAMESPACE,
  SDW_WORKING_STATE_NAMESPACE,
  type SdwNamespace,
  type SdwReplayAnchorData,
  type SdwRecord,
} from "./records.js";
import { SdwValidationError, type SdwClassifierDetector } from "./errors.js";

const PERSISTABLE_BRAND: unique symbol = Symbol("sanctuary.sdw.persistable");
const MAX_RECORD_BYTES = 1024 * 1024;
const SDW_REPLAY_MAC_DOMAIN = "sanctuary.sdw-replay-anchor-mac.v1\n";
const SDW_REPLAY_MAC_MARKER = "__sanctuary_sdw_replay_anchor_mac_v1";
const SDW_REPLAY_MAC_INFO = "sdw-replay-anchor-mac";
// ceil(32 bytes * 8 bits / 6 base64 bits) without the trailing `=` padding.
const BASE64URL_32_BYTE_KEY_CHARS = 43;
// Two hex characters encode each of 32 bytes.
const HEX_32_BYTE_KEY_CHARS = 64;
const BASE64URL_32_BYTE_KEY_SHAPE = new RegExp(
  `^[A-Za-z0-9_-]{${BASE64URL_32_BYTE_KEY_CHARS}}$`,
);
const HEX_32_BYTE_KEY_SHAPE = new RegExp(`^[A-Fa-f0-9]{${HEX_32_BYTE_KEY_CHARS}}$`);
const RECOVERY_KEY_LABEL_PATTERN = String.raw`SANCTUARY_RECOVERY_KEY|recovery[_ -]?key`;
const ED25519_PRIVATE_KEY_LABEL_PATTERN = String.raw`ed25519[_ -]?(?:private|secret)(?:[_ -]?key)?|(?:private|secret)(?:[_ -]?key)?[_ -]?ed25519`;
const PRIVATE_KEY_MARKER_PROBES: readonly RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i,
  /\bBEGIN [A-Z0-9 ]*PRIVATE KEY\b/i,
];

export type Taint =
  | "user_content"
  | "agent_derived_clean"
  | "system_generated"
  | "policy"
  | "secret"
  | "identity_key"
  | "unknown";

export interface Untrusted<T extends SdwRecord> {
  readonly value: T;
  /**
   * Legacy caller-asserted entry for records whose origin is already statically
   * clean. Crown-jewel material must enter through mintPersistableFromProvenance
   * so the source-carried taint cannot be relabeled by the caller.
   */
  readonly taint?: Taint;
}

export interface Persistable<T extends SdwRecord> {
  readonly [PERSISTABLE_BRAND]: true;
  readonly record: T;
  readonly namespace: SdwNamespace;
  readonly storageKey: string;
  readonly aad: Uint8Array;
  readonly taint: "user_content" | "agent_derived_clean" | "system_generated";
}

export interface PreparedSdwWrite {
  readonly namespace: SdwNamespace;
  readonly storageKey: string;
  readonly data: Uint8Array;
}

interface AuthorizedSdwPayload {
  readonly namespace: SdwNamespace;
  readonly storageKey: string;
  readonly digest: string;
}

const authorizedSdwPayloads = new WeakMap<Uint8Array, AuthorizedSdwPayload>();

export function mintPersistable<T extends SdwRecord>(
  input: Untrusted<T>,
  namespace: SdwNamespace,
  storageKey: string,
  fortressId: string,
): Persistable<T> {
  assertAllowedTaint(input.taint);
  validateRecord(input.value);
  assertNamespaceForRecord(namespace, input.value);
  assertSdwIdentifier(namespace, "namespace");
  assertSdwIdentifier(storageKey, "storage_key");
  const aad = sdwAad(fortressId, namespace, storageKey);
  classifyRecord(input.value);
  return {
    [PERSISTABLE_BRAND]: true,
    record: input.value,
    namespace,
    storageKey,
    aad,
    taint: input.taint,
  };
}

export function mintPersistableFromProvenance<T extends SdwRecord>(
  carrier: Tainted<T>,
  namespace: SdwNamespace,
  storageKey: string,
  fortressId: string,
): Persistable<T> {
  assertTainted(carrier);
  return mintPersistable(
    { value: carrier.value, taint: carrier.taint },
    namespace,
    storageKey,
    fortressId,
  );
}

export async function sdwBackendWrite<T extends SdwRecord>(
  backend: StorageBackend,
  persistable: Persistable<T>,
  encryptionKey: Uint8Array,
  fortressId: string,
): Promise<void> {
  const prepared = prepareSdwBackendWrite(persistable, encryptionKey, fortressId);
  await backend.write(prepared.namespace, prepared.storageKey, prepared.data);
}

export function prepareSdwBackendWrite<T extends SdwRecord>(
  persistable: Persistable<T>,
  encryptionKey: Uint8Array,
  fortressId: string,
): PreparedSdwWrite {
  assertRuntimePersistable(persistable);
  const namespace = persistable.namespace;
  const storageKey = persistable.storageKey;
  assertSdwNamespace(namespace);
  assertSdwIdentifier(namespace, "namespace");
  assertSdwIdentifier(storageKey, "storage_key");
  assertSdwIdentifier(fortressId, "fortress_id");
  assertAllowedTaint(persistable.taint);
  assertSdwRecord(persistable.record);
  validateRecord(persistable.record);
  assertNamespaceForRecord(namespace, persistable.record);
  classifyRecord(persistable.record);
  const aad = sdwAad(fortressId, namespace, storageKey);
  const envelope = encrypt(
    stringToBytes(JSON.stringify(persistable.record)),
    encryptionKey,
    aad,
  );
  const data = stringToBytes(JSON.stringify(envelope));
  return authorizePreparedSdwPayload({
    namespace,
    storageKey,
    data: new Uint8Array(data),
  });
}

export function assertSdwClassifierCleanText(text: string): void {
  if (text.length === 0) return;
  classifyText(text, text.replace(/[^A-Za-z0-9]+/g, ""), undefined, [text]);
}

export async function writeReplayAnchor(
  backend: StorageBackend,
  masterKey: Uint8Array,
  data: SdwReplayAnchorData,
): Promise<void> {
  const prepared = prepareReplayAnchorWrite(masterKey, data);
  await backend.write(prepared.namespace, prepared.storageKey, prepared.data);
}

export function prepareReplayAnchorWrite(
  masterKey: Uint8Array,
  data: SdwReplayAnchorData,
): PreparedSdwWrite {
  assertReplayAnchorData(data);
  const envelope = {
    marker: SDW_REPLAY_MAC_MARKER,
    data,
    mac: sdwReplayAnchorMac(masterKey, data),
  };
  return authorizePreparedSdwPayload({
    namespace: SDW_META_NAMESPACE,
    storageKey: SDW_REPLAY_ANCHOR_KEY,
    data: new Uint8Array(stringToBytes(JSON.stringify(envelope))),
  });
}

export function assertSdwRawWriteAuthorized(
  namespace: string,
  storageKey: string,
  data: Uint8Array,
): Uint8Array {
  const snapshot = new Uint8Array(data);
  if (!isSdwNamespace(namespace)) return snapshot;
  const authorized = authorizedSdwPayloads.get(data);
  if (
    authorized === undefined ||
    authorized.namespace !== namespace ||
    authorized.storageKey !== storageKey ||
    authorized.digest !== hashToString(snapshot)
  ) {
    throw new SdwValidationError(
      "raw_sdw_write_forbidden",
      "SDW namespace writes must pass through the SDW write gate with unmodified prepared bytes",
    );
  }
  return snapshot;
}

export function isSdwNamespace(namespace: string): namespace is SdwNamespace {
  return (
    namespace === SDW_CATALOG_NAMESPACE ||
    namespace === SDW_META_NAMESPACE ||
    namespace === SDW_WORKING_STATE_NAMESPACE ||
    namespace === SDW_QUERY_HISTORY_NAMESPACE ||
    namespace === SDW_DOCUMENT_CORPUS_NAMESPACE ||
    namespace === SDW_VECTOR_MEMORY_NAMESPACE
  );
}

export function assertAllowedTaint(taint: Taint | undefined): asserts taint is
  | "user_content"
  | "agent_derived_clean"
  | "system_generated" {
  if (
    taint !== "user_content" &&
    taint !== "agent_derived_clean" &&
    taint !== "system_generated"
  ) {
    throw new SdwValidationError("forbidden_taint", "SDW record is not persistable");
  }
}

export function combineTaint(a: Taint, b: Taint): Taint {
  const rank: readonly Taint[] = [
    "user_content",
    "agent_derived_clean",
    "system_generated",
    "unknown",
    "policy",
    "secret",
    "identity_key",
  ];
  const aRank = rank.indexOf(a);
  const bRank = rank.indexOf(b);
  return aRank >= bRank ? a : b;
}

function assertReplayAnchorData(data: SdwReplayAnchorData): void {
  const record: SdwRecord = {
    kind: "replay_anchor",
    version: 1,
    fortress_id: "sdw:replay-anchor",
    data,
    updated_at: "1970-01-01T00:00:00.000Z",
  };
  validateRecord(record);
  classifyRecord(record);
}

function validateRecord(record: SdwRecord): void {
  const encoded = stringToBytes(JSON.stringify(record));
  if (encoded.length > MAX_RECORD_BYTES) {
    throw new SdwValidationError("record_too_large", "SDW record exceeds size limit");
  }
  switch (record.kind) {
    case "catalog":
      assertVersion(record.version);
      assertSdwIdentifier(record.fortress_id, "fortress_id");
      assertSdwIdentifier(record.environment_id, "environment_id");
      assertNonNegativeInteger(record.replay_anchor_seq, "replay_anchor_seq");
      for (const store of record.stores) {
        assertSdwIdentifier(store.namespace, "store.namespace");
        assertSdwIdentifier(store.hkdf_info, "store.hkdf_info");
        assertVersion(store.current_record_version);
      }
      return;
    case "replay_anchor":
      assertVersion(record.version);
      assertSdwIdentifier(record.fortress_id, "fortress_id");
      assertReplayAnchorDataShape(record.data);
      assertNonNegativeInteger(record.data.catalog, "catalog");
      assertNonNegativeInteger(record.data.export_state, "export_state");
      for (const counter of [
        ...record.data.chain_head,
        ...record.data.manifests,
        ...record.data.tombstones,
      ]) {
        assertSdwIdentifier(counter.id, "replay_counter.id");
        assertNonNegativeInteger(counter.seq, "replay_counter.seq");
      }
      return;
    case "working_state":
      assertVersion(record.version);
      assertSdwIdentifier(record.state_id, "state_id");
      assertSdwIdentifier(record.owner_ref, "owner_ref");
      assertOneOf(record.scope, ["task", "thread", "tool", "session", "other"], "scope");
      assertOneOf(record.status, ["active", "superseded", "completed", "failed"], "status");
      if (record.content_type !== "application/json") {
        throw new SdwValidationError("schema_mismatch", "Invalid SDW content_type");
      }
      switch (record.state.kind) {
        case "retrieval_context":
          assertSdwIdentifier(record.state.query_ref, "query_ref");
          for (const ref of record.state.selected_refs) assertSdwIdentifier(ref, "selected_ref");
          break;
        case "tool_result_summary":
          assertSdwIdentifier(record.state.tool_name, "tool_name");
          assertSdwIdentifier(record.state.invocation_ref, "invocation_ref");
          for (const ref of record.state.artifact_refs ?? []) assertSdwIdentifier(ref, "artifact_ref");
          break;
        case "task_checkpoint":
          assertSdwIdentifier(record.state.task_ref, "task_ref");
          break;
        default:
          throw new SdwValidationError("schema_mismatch", "Unknown SDW working-state payload");
      }
      for (const sourceRef of record.source_refs ?? []) {
        assertOneOf(sourceRef.kind, ["query", "document_chunk", "vector", "tool_call", "external"], "source_ref.kind");
        assertSdwIdentifier(sourceRef.ref, "source_ref.ref");
      }
      return;
    case "query_history":
      assertVersion(record.version);
      assertSdwIdentifier(record.query_id, "query_id");
      assertSdwIdentifier(record.audit_event_id, "audit_event_id");
      assertSdwIdentifier(record.operation, "operation");
      assertOneOf(record.actor.kind, ["operator", "agent", "system"], "actor.kind");
      if (record.actor.principal_ref !== undefined) assertSdwIdentifier(record.actor.principal_ref, "principal_ref");
      if (record.actor.agent_ref !== undefined) assertSdwIdentifier(record.actor.agent_ref, "agent_ref");
      assertOneOf(record.channel, ["mcp", "cli", "dashboard", "internal"], "channel");
      assertNonNegativeInteger(record.sequence, "sequence");
      if (record.previous_record_hash !== null) assertHashString(record.previous_record_hash, "previous_record_hash");
      if (record.previous_query_key !== null) assertSdwIdentifier(record.previous_query_key, "previous_query_key");
      assertHashString(record.record_hash, "record_hash");
      if (record.policy_visibility !== "not_included") {
        throw new SdwValidationError("schema_mismatch", "Invalid SDW policy_visibility");
      }
      for (const resultRef of record.result_refs ?? []) {
        assertOneOf(resultRef.kind, ["working_state", "document", "document_chunk", "vector", "audit_event"], "result_ref.kind");
        assertSdwIdentifier(resultRef.ref, "result_ref.ref");
      }
      return;
    case "query_history_chain_head":
      assertVersion(record.version);
      assertSdwIdentifier(record.fortress_id, "fortress_id");
      assertNonNegativeInteger(record.latest_sequence, "latest_sequence");
      assertNonNegativeInteger(record.replay_anchor_seq, "replay_anchor_seq");
      return;
    case "document":
      assertVersion(record.version);
      assertSdwIdentifier(record.document_id, "document_id");
      assertOneOf(record.source.kind, ["file", "url", "paste", "tool_output", "internal"], "source.kind");
      assertNonNegativeInteger(record.chunk_count, "chunk_count");
      if (record.byte_length !== undefined) assertNonNegativeInteger(record.byte_length, "byte_length");
      for (const tag of record.tags ?? []) assertSdwIdentifier(tag, "tag");
      for (const item of record.metadata ?? []) assertSdwIdentifier(item.key, "metadata.key");
      return;
    case "document_chunk":
      assertVersion(record.version);
      assertSdwIdentifier(record.document_id, "document_id");
      assertSdwIdentifier(record.chunk_id, "chunk_id");
      assertNonNegativeInteger(record.chunk_ordinal, "chunk_ordinal");
      if (record.char_start !== undefined) assertNonNegativeInteger(record.char_start, "char_start");
      if (record.char_end !== undefined) assertNonNegativeInteger(record.char_end, "char_end");
      if (record.token_count !== undefined) assertNonNegativeInteger(record.token_count, "token_count");
      for (const ref of record.vector_refs ?? []) assertSdwIdentifier(ref, "vector_ref");
      return;
    case "vector_record":
      assertVersion(record.version);
      assertSdwIdentifier(record.vector_id, "vector_id");
      assertSdwIdentifier(record.segment_id, "segment_id");
      assertNonNegativeInteger(record.hnsw_label, "hnsw_label");
      return;
    case "vector_label_map":
      assertVersion(record.version);
      assertSdwIdentifier(record.segment_id, "segment_id");
      assertSdwIdentifier(record.vector_id, "vector_id");
      assertSdwIdentifier(record.vector_key, "vector_key");
      assertNonNegativeInteger(record.hnsw_label, "hnsw_label");
      assertNonNegativeInteger(record.manifest_generation, "manifest_generation");
      return;
    case "hnsw_index_manifest":
      assertVersion(record.version);
      assertSdwIdentifier(record.segment_id, "segment_id");
      assertSdwIdentifier(record.segment_key, "segment_key");
      assertNonNegativeInteger(record.active_generation, "active_generation");
      assertNonNegativeInteger(record.replay_anchor_seq, "replay_anchor_seq");
      return;
    case "vector_tombstone":
      assertVersion(record.version);
      assertSdwIdentifier(record.vector_id, "vector_id");
      assertNonNegativeInteger(record.epoch, "epoch");
      return;
    default:
      throw new SdwValidationError("schema_mismatch", "Unknown SDW record kind");
  }
}

function assertRuntimePersistable<T extends SdwRecord>(
  persistable: Persistable<T>,
): void {
  if (
    persistable === null ||
    typeof persistable !== "object" ||
    persistable[PERSISTABLE_BRAND] !== true
  ) {
    throw new SdwValidationError("untrusted_persistable", "Untrusted SDW persistable");
  }
}

function assertSdwRecord(record: unknown): asserts record is SdwRecord {
  if (record === null || typeof record !== "object" || typeof (record as { kind?: unknown }).kind !== "string") {
    throw new SdwValidationError("schema_mismatch", "Invalid SDW record");
  }
}

function assertSdwNamespace(namespace: string): asserts namespace is SdwNamespace {
  if (!isSdwNamespace(namespace)) {
    throw new SdwValidationError("namespace_mismatch", "Unknown SDW namespace");
  }
}

function assertNamespaceForRecord(namespace: SdwNamespace, record: SdwRecord): void {
  const valid =
    (record.kind === "catalog" && namespace === SDW_CATALOG_NAMESPACE) ||
    (record.kind === "replay_anchor" && namespace === SDW_META_NAMESPACE) ||
    (record.kind === "working_state" && namespace === SDW_WORKING_STATE_NAMESPACE) ||
    ((record.kind === "query_history" || record.kind === "query_history_chain_head") &&
      namespace === SDW_QUERY_HISTORY_NAMESPACE) ||
    ((record.kind === "document" || record.kind === "document_chunk") &&
      namespace === SDW_DOCUMENT_CORPUS_NAMESPACE) ||
    ((record.kind === "vector_record" ||
      record.kind === "vector_label_map" ||
      record.kind === "hnsw_index_manifest" ||
      record.kind === "vector_tombstone") &&
      namespace === SDW_VECTOR_MEMORY_NAMESPACE);
  if (!valid) {
    throw new SdwValidationError("namespace_mismatch", "SDW record namespace mismatch");
  }
}

function assertVersion(version: number): void {
  if (version !== 1) {
    throw new SdwValidationError("unsupported_record_version", "Unsupported SDW record version");
  }
}

function assertNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new SdwValidationError("schema_mismatch", `Invalid SDW integer: ${label}`);
  }
}

function assertReplayAnchorDataShape(value: unknown): asserts value is SdwReplayAnchorData {
  if (value === null || typeof value !== "object") {
    throw new SdwValidationError("schema_mismatch", "Invalid SDW replay-anchor data");
  }
  const data = value as { readonly [key: string]: unknown };
  for (const label of ["chain_head", "manifests", "tombstones"] as const) {
    const counters = data[label];
    if (!Array.isArray(counters)) {
      throw new SdwValidationError("schema_mismatch", `Invalid SDW replay-anchor data: ${label}`);
    }
    for (const counter of counters) {
      if (
        counter === null ||
        typeof counter !== "object" ||
        typeof (counter as { readonly id?: unknown }).id !== "string" ||
        typeof (counter as { readonly seq?: unknown }).seq !== "number"
      ) {
        throw new SdwValidationError("schema_mismatch", `Invalid SDW replay-anchor data: ${label}`);
      }
    }
  }
}

function assertHashString(value: string, label: string): void {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(value)) {
    throw new SdwValidationError("schema_mismatch", `Invalid SDW hash: ${label}`);
  }
}

function assertOneOf<T extends string>(
  value: string,
  allowed: readonly T[],
  label: string,
): asserts value is T {
  if (!(allowed as readonly string[]).includes(value)) {
    throw new SdwValidationError("schema_mismatch", `Invalid SDW enum: ${label}`);
  }
}

function classifyRecord(record: SdwRecord): void {
  const text = canonicalClassifierText(record);
  if (text.length === 0) return;
  // This text scan is defense in depth only. The enforced persistence control for
  // source-known crown jewels is provenance taint plus persistable/raw-write
  // authorization; classifier hits still fail closed, but classifier passes are
  // never a guarantee that arbitrary free text contains no secret.
  const normalized = normalizeClassifierText(text);
  // Split-marker reassembly must run over field VALUES ONLY. canonicalClassifierText
  // interleaves key-path tokens between values, which would wedge between a "PRIVATE"
  // in one field and a "KEY" in another and defeat the compact PRIVATEKEY match. The
  // values-only compact reassembles a marker fragmented across non-adjacent fields.
  const views = collectClassifierTextViews(record);
  classifyText(text, views.compactValues, normalized, views.entropyContexts);
}

/**
 * Outcome of one detector check: `undefined` means no match; a defined hit
 * with `index` set means a match was found at that character offset in the
 * text the detector was given; a defined hit with `index` absent means a
 * match was found only in a normalized or field-reassembled view whose
 * offsets do not map back onto the original text, so no location can be
 * reported for it (SdwValidationError.line stays absent in that case).
 */
interface ClassifierHit {
  readonly index?: number;
}

interface AttributedClassifierHit extends ClassifierHit {
  readonly detector: SdwClassifierDetector;
}

function classifyText(
  text: string,
  compact: string,
  normalized = normalizeClassifierText(text),
  entropyContexts: readonly string[] = [text],
): void {
  const hit = findClassifierHit(text, compact, normalized, entropyContexts);
  if (hit === undefined) return;
  const location = hit.index === undefined ? undefined : lineColumnAt(text, hit.index);
  throw new SdwValidationError("classifier_reject", "SDW classifier rejected sensitive material", {
    detector: hit.detector,
    line: location?.line,
    column: location?.column,
  });
}

/**
 * Run the nine classifier checks in order and return the first hit, named by
 * detector so a refusal can tell an operator which one fired (Rung-1 F2).
 * The order matches the boolean chain this replaced, so which detector wins
 * when more than one would match is unchanged.
 */
function findClassifierHit(
  text: string,
  compact: string,
  normalized: string,
  entropyContexts: readonly string[],
): AttributedClassifierHit | undefined {
  const privateKeyMarker = findPrivateKeyMarker(text, normalized);
  if (privateKeyMarker !== undefined) {
    return { detector: "private_key_marker", ...privateKeyMarker };
  }

  const splitPrivateKeyMarker = findSplitPrivateKeyMarker(compact);
  if (splitPrivateKeyMarker !== undefined) {
    return { detector: "private_key_marker_split", ...splitPrivateKeyMarker };
  }

  const encodedPrivateKey = findEncodedEd25519Pkcs8PrivateKey(text);
  if (encodedPrivateKey !== undefined) {
    return { detector: "encoded_private_key", ...encodedPrivateKey };
  }

  const labeledPrivateKey = findLabeledEd25519PrivateKeyMaterial(text);
  if (labeledPrivateKey !== undefined) {
    return { detector: "labeled_private_key", ...labeledPrivateKey };
  }

  const labeledRecoveryKey = findLabeledRecoveryKeyMaterial(text);
  if (labeledRecoveryKey !== undefined) {
    return { detector: "labeled_recovery_key", ...labeledRecoveryKey };
  }

  const knownSecretToken = findKnownSecretToken(text);
  if (knownSecretToken !== undefined) {
    return { detector: "known_secret_token", ...knownSecretToken };
  }

  const jwt = findJwt(text);
  if (jwt !== undefined) return { detector: "jwt", ...jwt };

  const urlCredential = findUrlCredential(text);
  if (urlCredential !== undefined) return { detector: "url_credential", ...urlCredential };

  for (const context of entropyContexts) {
    const hit = findKeywordGatedHighEntropySecret(context);
    if (hit === undefined) continue;
    // entropyContexts may be per-field slices (collectClassifierTextViews),
    // so a hit's index is relative to its own context, not `text`; map it
    // back only when that mapping is reliable (see locateInSourceText).
    const index = hit.index === undefined ? undefined : locateInSourceText(text, context, hit.index);
    return { detector: "keyword_gated_high_entropy", index };
  }

  return undefined;
}

function buildLineIndex(text: string): readonly number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === "\n") starts.push(i + 1);
  }
  return starts;
}

function lineNumberForIndex(lineStarts: readonly number[], index: number): number {
  // Binary search for the last line start <= index; lineStarts is sorted
  // ascending by construction (buildLineIndex appends in text order).
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (lineStarts[mid]! <= index) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

function lineColumnAt(text: string, index: number): { readonly line: number; readonly column: number } {
  const lineStarts = buildLineIndex(text);
  const line = lineNumberForIndex(lineStarts, index);
  const column = index - lineStarts[line - 1]! + 1;
  return { line, column };
}

/**
 * Maps an index found inside `context` back to its offset in `text`, for the
 * common case where `context` is `text` itself or a literal substring of it
 * (every entropyContexts entry collectClassifierTextViews pushes for a plain
 * string field is one). Returns undefined for a synthetic reassembly (the
 * "key\nvalue" metadata pairing at collectClassifierTextViews below) that
 * does not appear verbatim in `text`, since no reliable offset exists to map
 * back to; the caller reports no location for that hit rather than a wrong one.
 */
function locateInSourceText(text: string, context: string, indexInContext: number): number | undefined {
  if (context === text) return indexInContext;
  const contextOffset = text.indexOf(context);
  return contextOffset === -1 ? undefined : contextOffset + indexInContext;
}

function findPrivateKeyMarker(text: string, normalized: string): ClassifierHit | undefined {
  for (const probe of PRIVATE_KEY_MARKER_PROBES) {
    const match = probe.exec(text);
    if (match) return { index: match.index };
  }
  for (const probe of PRIVATE_KEY_MARKER_PROBES) {
    if (probe.test(normalized)) {
      // Matched only after normalization (punctuation/whitespace collapsed
      // to spaces); normalized offsets do not correspond to positions in
      // the original text, so this hit carries no location.
      return {};
    }
  }
  return undefined;
}

function findLabeledRecoveryKeyMaterial(text: string): ClassifierHit | undefined {
  return findLabeled32ByteKeyMaterial(text, RECOVERY_KEY_LABEL_PATTERN);
}

function findLabeledEd25519PrivateKeyMaterial(text: string): ClassifierHit | undefined {
  return findLabeled32ByteKeyMaterial(text, ED25519_PRIVATE_KEY_LABEL_PATTERN);
}

function findLabeled32ByteKeyMaterial(text: string, labelPattern: string): ClassifierHit | undefined {
  const pattern = new RegExp(
    String.raw`\b(?:${labelPattern})(?:\s*(?:=|:)\s*|\s+is\s+|\s+)["']?([A-Za-z0-9_-]+)(?![A-Za-z0-9_-])`,
    "gi",
  );
  for (const match of text.matchAll(pattern)) {
    const candidate = match[1] ?? "";
    if (isPlausible32ByteBase64urlKey(candidate) || HEX_32_BYTE_KEY_SHAPE.test(candidate)) {
      return { index: match.index };
    }
  }
  return undefined;
}

function isPlausible32ByteBase64urlKey(value: string): boolean {
  // A Sanctuary recovery key (and a raw 32-byte Ed25519 key) is 32 random
  // bytes rendered as unpadded base64url.
  return BASE64URL_32_BYTE_KEY_SHAPE.test(value) && !isAllowedPlaceholder(value);
}

function findSplitPrivateKeyMarker(compactText: string): ClassifierHit | undefined {
  const beginIndex = compactText.search(/BEGIN/i);
  const privateKeyIndex = compactText.search(/PRIVATEKEY/i);
  if (beginIndex !== -1 && privateKeyIndex !== -1 && Math.abs(beginIndex - privateKeyIndex) <= 4096) {
    // Matched only in the values-only compacted reassembly (collectClassifierTextViews);
    // its offsets do not correspond to positions in the original text.
    return {};
  }
  return undefined;
}

function findEncodedEd25519Pkcs8PrivateKey(text: string): ClassifierHit | undefined {
  const compact = text.replace(/[\s"'`,;:]+/g, "");
  const hexPrefix = "302e020100300506032b657004220420";
  const base64Prefix = "MC4CAQAwBQYDK2VwBCIEI";
  if (compact.toLowerCase().includes(hexPrefix) || compact.includes(base64Prefix)) {
    // Matched in the whitespace/punctuation-stripped view; its offsets do
    // not correspond to positions in the original text.
    return {};
  }
  return undefined;
}

function canonicalClassifierText(value: SdwRecord): string {
  const out: string[] = [];
  const visit = (item: unknown, keyPath = ""): void => {
    if (keyPath !== "") out.push(keyPath);
    if (typeof item === "string") {
      out.push(item);
      return;
    }
    if (Array.isArray(item)) {
      item.forEach((child, index) => visit(child, `${keyPath}[${index}]`));
      return;
    }
    if (item !== null && typeof item === "object") {
      const object = item as { readonly [key: string]: unknown };
      for (const key of Object.keys(object).sort()) {
        visit(object[key], keyPath === "" ? key : `${keyPath}.${key}`);
      }
    }
  };
  visit(value);
  return out.join("\n");
}

function normalizeClassifierText(text: string): string {
  return text.replace(/[^A-Za-z0-9_-]+/g, " ");
}

interface ClassifierTextViews {
  readonly compactValues: string;
  readonly entropyContexts: readonly string[];
}

function collectClassifierTextViews(value: SdwRecord): ClassifierTextViews {
  const stringValues: string[] = [];
  const entropyContexts: string[] = [];
  const visit = (item: unknown): void => {
    if (typeof item === "string") {
      stringValues.push(item);
      entropyContexts.push(item);
      return;
    }
    if (Array.isArray(item)) {
      for (const child of item) visit(child);
      return;
    }
    if (item !== null && typeof item === "object") {
      const object = item as { readonly [key: string]: unknown };
      // Metadata key/value pairs are one semantic field. The whitespace
      // boundary intentionally lets a label such as `credential` gate the
      // candidate stored in its paired value. Individual strings are also
      // retained below so their self-contained signals remain detectable.
      if (typeof object.key === "string" && typeof object.value === "string") {
        entropyContexts.push(`${object.key}\n${object.value}`);
      }
      for (const key of Object.keys(object).sort()) visit(object[key]);
    }
  };
  visit(value);
  return {
    // Field values only (no key paths), in canonical sorted order. Joining
    // reassembles private-key markers fragmented across record fields.
    compactValues: stringValues.join("").replace(/[^A-Za-z0-9]+/g, ""),
    entropyContexts,
  };
}

// Whole-record by design (unchanged by Rung-1 F1, which scopes only the
// keyword-gated entropy check below): every branch here is a specific,
// high-confidence shape (a vendor token prefix, a checksum-validated GitHub
// token) except the last, which pairs a vendor-name keyword with any 32+
// char token-shaped run anywhere in the same text. That last branch is
// deliberately as broad today as the pre-fix entropy check was; it stays
// that way because narrowing it is a separate, not-yet-measured change
// (see the F1 finding in Review/Sanctuary/drill-rung1-roundtrip-2026-08-22/RESULTS.md).
function findKnownSecretToken(text: string): ClassifierHit | undefined {
  const githubToken = findGitHubToken(text);
  if (githubToken !== undefined) return githubToken;

  const shapePatterns: readonly RegExp[] = [
    /\b(?:sk|sk-ant|rk)_(?:live|test|proj)?_[A-Za-z0-9_-]{20,}\b/,
    /\bsk-[A-Za-z0-9_-]{20,}\b/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bASIA[0-9A-Z]{16}\b/,
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    /\bAIza[0-9A-Za-z_-]{35}\b/,
    /\bglpat-[0-9A-Za-z_-]{20,}\b/,
    /\bnpm_[0-9A-Za-z]{36,}\b/,
  ];
  for (const pattern of shapePatterns) {
    const match = pattern.exec(text);
    if (match) return { index: match.index };
  }

  const vendorLabel = /\b(?:stripe|slack|google|github|aws|npm)[_-]?(?:token|key|secret)\b/i.exec(text);
  const tokenShaped = /\b[A-Za-z0-9_-]{32,}\b/.exec(text);
  if (vendorLabel && tokenShaped) return { index: vendorLabel.index };
  return undefined;
}

// Deliberate FP-control trade-off (documented in README "known false negatives"):
// a gh*_/github_pat_ token is flagged only when its trailing CRC32-base62 checksum
// validates. Malformed/legacy-format tokens may pass — this is defense-in-depth, not
// the enforced boundary (provenance is). Tightening it belongs in consumer-integration.
function findGitHubToken(text: string): ClassifierHit | undefined {
  const tokenPattern = /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/g;
  for (const match of text.matchAll(tokenPattern)) {
    if (hasValidGitHubChecksum(match[0])) return { index: match.index };
  }
  return undefined;
}

function hasValidGitHubChecksum(token: string): boolean {
  const body = token.slice(0, -6);
  const checksum = token.slice(-6);
  if (!/^[0-9A-Za-z]{6}$/.test(checksum) || body.length === 0) return false;
  return base62Crc32(body).padStart(6, "0").slice(-6) === checksum;
}

function base62Crc32(value: string): string {
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let n = crc32(value);
  if (n === 0) return "0";
  let out = "";
  while (n > 0) {
    out = alphabet[n % 62] + out;
    n = Math.floor(n / 62);
  }
  return out;
}

function crc32(value: string): number {
  let crc = 0xffffffff;
  for (let index = 0; index < value.length; index += 1) {
    crc ^= value.charCodeAt(index);
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function findJwt(text: string): ClassifierHit | undefined {
  const jwtPattern = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
  for (const match of text.matchAll(jwtPattern)) {
    try {
      const header = JSON.parse(Buffer.from(match[0].split(".")[0] ?? "", "base64url").toString("utf8")) as {
        readonly alg?: unknown;
        readonly typ?: unknown;
      };
      if (typeof header.alg === "string" && (header.typ === undefined || header.typ === "JWT")) {
        return { index: match.index };
      }
    } catch {
      // Malformed JWT-shaped text is ignored by this heuristic.
    }
  }
  return undefined;
}

function findUrlCredential(text: string): ClassifierHit | undefined {
  const match = /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]{1,128}:[^/\s:@]{8,128}@/i.exec(text);
  return match ? { index: match.index } : undefined;
}

// Longest string a candidate pattern below matches (the `{32,128}` quantifier
// on each). The proximity window is sized to comfortably hold one candidate
// plus the keyword that gates it, whichever side of the pair is longer.
const KEYWORD_ENTROPY_CANDIDATE_MAX_CHARS = 128;
/**
 * Rung-1 F1: a keyword and a high-entropy candidate must be near each other
 * to read as one secret-shaped pair. Pre-fix, this check scanned an entire
 * context (often a whole file) for "a keyword appears somewhere" AND "a
 * high-entropy run appears somewhere", so an index file that says "token" in
 * one heading and holds one unrelated high-entropy identifier hundreds of
 * lines away was refused as a secret (Rung-1 round-trip drill, 2026-08-22:
 * 5 of 6 whole-context keyword_gated_high_entropy refusals on the real
 * corpus fired only at file scope, no single line tripped on its own). The
 * window below is two candidate-lengths of characters, OR the same physical
 * line, so a keyword immediately before/after a maximal-length candidate on
 * one line, or split across a "label:\n  value" line break, still gates,
 * while unrelated mentions elsewhere in the same file do not. Every other
 * detector in this file stays whole-record: the shapes they match (a PEM
 * block, a vendor token prefix, a JWT, a URL credential, a labeled 32-byte
 * key) are self-contained and specific enough that scanning the whole
 * context does not create the same false-positive class this narrows.
 */
const KEYWORD_ENTROPY_PROXIMITY_CHARS = KEYWORD_ENTROPY_CANDIDATE_MAX_CHARS * 2;

function findKeywordGatedHighEntropySecret(text: string): ClassifierHit | undefined {
  const keywordPattern = /\b(?:api[_-]?key|access[_-]?key|auth|authorization|bearer|credential|password|private[_-]?key|secret|token)\b/gi;
  const keywordMatches = [...text.matchAll(keywordPattern)];
  if (keywordMatches.length === 0) return undefined;

  const candidates = [
    ...text.matchAll(/\b[A-Fa-f0-9]{32,128}\b/g),
    ...text.matchAll(/\b[A-Za-z0-9+/=]{32,128}\b/g),
    ...text.matchAll(/\b[A-Za-z0-9_-]{32,128}\b/g),
  ];
  const lineStarts = buildLineIndex(text);
  for (const match of candidates) {
    const candidate = match[0];
    if (isAllowedPlaceholder(candidate) || isKnownHashLength(candidate)) continue;
    const threshold = /^[A-Fa-f0-9]+$/.test(candidate) ? 3.2 : 4.5;
    if (shannonEntropy(candidate) < threshold) continue;
    const candidateIndex = match.index ?? 0;
    const nearAKeyword = keywordMatches.some((keyword) => {
      const keywordIndex = keyword.index ?? 0;
      if (Math.abs(candidateIndex - keywordIndex) <= KEYWORD_ENTROPY_PROXIMITY_CHARS) return true;
      return (
        lineNumberForIndex(lineStarts, keywordIndex) === lineNumberForIndex(lineStarts, candidateIndex)
      );
    });
    if (nearAKeyword) return { index: candidateIndex };
  }
  return undefined;
}

function isAllowedPlaceholder(value: string): boolean {
  return (
    /^(?:x+|0+|1+|a+|A+|example|placeholder|redacted|dummy)$/i.test(value) ||
    value === "AKIAIOSFODNN7EXAMPLE" ||
    value.toLowerCase().includes("example") ||
    value.toLowerCase().includes("redacted")
  );
}

// Deliberate FP-control trade-off (documented in README "known false negatives"):
// canonical hash lengths (md5/sha1/sha256 hex) are skipped by the entropy heuristic to
// avoid flagging content hashes/ids that legitimately appear in records. A secret that
// is exactly a hash length may pass even with a nearby keyword. Defense-in-depth only.
function isKnownHashLength(value: string): boolean {
  // 32 / 40 / 64 are HEX CHARACTER counts, not byte counts: md5 (16 bytes),
  // sha1 (20 bytes), and sha256 (32 bytes) each rendered as two hex chars per
  // byte. These are not key lengths.
  return /^[A-Fa-f0-9]+$/.test(value) && (value.length === 32 || value.length === 40 || value.length === 64);
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export function encryptedEnvelopeContains(raw: Uint8Array, forbidden: string): boolean {
  return bytesToString(raw).includes(forbidden);
}

function authorizePreparedSdwPayload(prepared: PreparedSdwWrite): PreparedSdwWrite {
  const data = new Uint8Array(prepared.data);
  authorizedSdwPayloads.set(data, {
    namespace: prepared.namespace,
    storageKey: prepared.storageKey,
    digest: hashToString(data),
  });
  return {
    namespace: prepared.namespace,
    storageKey: prepared.storageKey,
    data,
  };
}

function sdwReplayAnchorMac(masterKey: Uint8Array, data: SdwReplayAnchorData): string {
  const macKey = derivePurposeKey(masterKey, SDW_REPLAY_MAC_INFO);
  const payload = SDW_REPLAY_MAC_DOMAIN +
    SDW_REPLAY_ANCHOR_KEY +
    "\n" +
    canonicalJson(data);
  return toBase64url(hmacSha256(macKey, stringToBytes(payload)));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => canonicalize(item));
  const object = value as { readonly [key: string]: unknown };
  const out: { [key: string]: unknown } = {};
  for (const key of Object.keys(object).sort()) {
    const item = object[key];
    if (item !== undefined) out[key] = canonicalize(item);
  }
  return out;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}
