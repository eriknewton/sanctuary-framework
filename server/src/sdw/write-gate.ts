import { AsyncLocalStorage } from "node:async_hooks";
import type { StorageBackend } from "../storage/interface.js";
import { encrypt } from "../core/encryption.js";
import { bytesToString, stringToBytes } from "../core/encoding.js";
import { sdwAad, assertSdwIdentifier } from "./grammar.js";
import {
  SDW_CATALOG_NAMESPACE,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_VECTOR_MEMORY_NAMESPACE,
  SDW_WORKING_STATE_NAMESPACE,
  type SdwNamespace,
  type SdwRecord,
} from "./records.js";
import { SdwValidationError } from "./errors.js";

const PERSISTABLE_BRAND: unique symbol = Symbol("sanctuary.sdw.persistable");
const MAX_RECORD_BYTES = 1024 * 1024;

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

interface PreparedSdwWrite {
  readonly namespace: SdwNamespace;
  readonly storageKey: string;
  readonly data: Uint8Array;
}

const sdwWriteAuthority = new AsyncLocalStorage<boolean>();

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

export async function sdwBackendWrite<T extends SdwRecord>(
  backend: StorageBackend,
  persistable: Persistable<T>,
  encryptionKey: Uint8Array,
  fortressId: string,
): Promise<void> {
  const prepared = prepareSdwBackendWrite(persistable, encryptionKey, fortressId);
  await runWithSdwWriteAuthority(() =>
    backend.write(prepared.namespace, prepared.storageKey, prepared.data),
  );
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
  return {
    namespace,
    storageKey,
    data: stringToBytes(JSON.stringify(envelope)),
  };
}

export async function sdwBackendWriteAuthenticatedMeta(
  backend: StorageBackend,
  namespace: typeof SDW_META_NAMESPACE,
  storageKey: string,
  data: Uint8Array,
): Promise<void> {
  assertSdwIdentifier(namespace, "namespace");
  assertSdwIdentifier(storageKey, "storage_key");
  await runWithSdwWriteAuthority(() => backend.write(namespace, storageKey, data));
}

export function assertSdwRawWriteAuthorized(namespace: string): void {
  if (isSdwNamespace(namespace) && sdwWriteAuthority.getStore() !== true) {
    throw new SdwValidationError(
      "raw_sdw_write_forbidden",
      "SDW namespace writes must pass through the SDW write gate",
    );
  }
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

export async function runWithSdwWriteAuthority<T>(fn: () => Promise<T>): Promise<T> {
  return sdwWriteAuthority.run(true, fn);
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
  return rank.indexOf(a) >= rank.indexOf(b) ? a : b;
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
      return;
    case "query_history":
      assertVersion(record.version);
      assertSdwIdentifier(record.query_id, "query_id");
      assertNonNegativeInteger(record.sequence, "sequence");
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
      assertNonNegativeInteger(record.chunk_count, "chunk_count");
      return;
    case "document_chunk":
      assertVersion(record.version);
      assertSdwIdentifier(record.document_id, "document_id");
      assertSdwIdentifier(record.chunk_id, "chunk_id");
      assertNonNegativeInteger(record.chunk_ordinal, "chunk_ordinal");
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

function classifyRecord(record: SdwRecord): void {
  const text = collectText(record).join("\n");
  if (text.length === 0) return;
  const probes: readonly RegExp[] = [
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i,
    /principal[_ -]?policy/i,
    /\brecovery[_ -]?key\b/i,
    /\bed25519\b.{0,80}\b(private|secret)\b/i,
    /\bSANCTUARY_RECOVERY_KEY\b/i,
  ];
  if (probes.some((probe) => probe.test(text))) {
    throw new SdwValidationError("classifier_reject", "SDW classifier rejected sensitive material");
  }
}

function collectText(value: SdwRecord): string[] {
  const out: string[] = [];
  const visit = (item: unknown): void => {
    if (typeof item === "string") {
      out.push(item);
      return;
    }
    if (Array.isArray(item)) {
      for (const child of item) visit(child);
      return;
    }
    if (item !== null && typeof item === "object") {
      const object = item as { readonly [key: string]: unknown };
      for (const key of Object.keys(object)) visit(object[key]);
    }
  };
  visit(value);
  return out;
}

export function encryptedEnvelopeContains(raw: Uint8Array, forbidden: string): boolean {
  return bytesToString(raw).includes(forbidden);
}
