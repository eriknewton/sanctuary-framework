/**
 * SDW D2 — Export: approval-bound ciphertext-inventory digest + signed manifest.
 *
 * Option A+ (Erik-ratified 2026-06-09):
 * - Before any approval prompt, the export scope is enumerated from plaintext
 *   LMDB storage keys and each record's CIPHERTEXT envelope is hashed. Nothing
 *   is decrypted; no plaintext enters memory; nothing leaves the machine.
 * - The resulting scope digest is metadata (counts + names + digest) and is
 *   bound into the Tier-1 approval (gate context + ApprovalProofStore args
 *   hash) via the tool's `approvalTargetArgs`.
 * - At assembly time the live store is re-enumerated; ANY drift between the
 *   approved inventory and the live store fails closed (`SdwExportScopeDriftError`)
 *   before anything is signed or written.
 * - The export manifest is canonicalized and Ed25519-signed EXCLUSIVELY through
 *   `core/identity.ts:sign()` — the existing key-isolation boundary that
 *   decrypts the private key transiently, signs, zeroes the key in `finally`,
 *   and never returns key material. This module never imports curve/decrypt
 *   primitives and never sees raw private-key bytes.
 * - Bundles carry ciphertext envelopes only (portability strategy v1: decrypt
 *   happens exclusively inside an approved import). Export never decrypts.
 */

import { rename, unlink, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import type { EncryptedPayload } from "../core/encryption.js";
import { bytesToString, stringToBytes, toBase64url } from "../core/encoding.js";
import { hashToString } from "../core/hashing.js";
import { sign } from "../core/identity.js";
import { assertSdwIdentifier } from "./grammar.js";
import {
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_VECTOR_MEMORY_NAMESPACE,
  SDW_WORKING_STATE_NAMESPACE,
  defaultSdwStoreDescriptors,
  type SdwNamespace,
} from "./records.js";
import { SdwValidationError } from "./errors.js";

// ── Domain separation ────────────────────────────────────────────────────────
// The identity key also signs arbitrary operator commitments (identity_sign),
// rotation events, and checkpoints. Every D2 artifact hash/signature input is
// domain-prefixed so an export manifest can never be confused with (or replayed
// as) any other signed payload, and vice versa.
const SDW_EXPORT_RECORD_HASH_DOMAIN = "sanctuary.sdw-export-record-hash.v1\n";
const SDW_EXPORT_SCOPE_DIGEST_DOMAIN = "sanctuary.sdw-export-scope-digest.v1\n";
const SDW_EXPORT_MANIFEST_SIGNING_DOMAIN = "sanctuary.sdw-export-manifest.v1\n";

/**
 * Namespaces eligible for export. `_sdw_catalog` and `_sdw_meta` are
 * environment-bound (catalog pins the LMDB environment to one fortress id;
 * the replay anchor is MAC'd under the source master key) and are NEVER
 * exported — they are recreated by the target environment.
 */
export const SDW_EXPORTABLE_NAMESPACES = [
  SDW_WORKING_STATE_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_VECTOR_MEMORY_NAMESPACE,
] as const;

export type SdwExportableNamespace = (typeof SDW_EXPORTABLE_NAMESPACES)[number];

/**
 * Storage keys excluded from export scope: the query-history chain head is a
 * fortress-bound derived cache pointer (rebuilt from the audit log on boot,
 * per ratified D1) and carries the SOURCE fortress id inside its body.
 * Exporting it cross-fortress would import a chain head claiming the wrong
 * fortress. The query records themselves (prefix `query.`) ARE exported.
 */
const EXCLUDED_KEY_PREFIXES: ReadonlyMap<SdwNamespace, readonly string[]> = new Map([
  [SDW_QUERY_HISTORY_NAMESPACE, ["chain-head."]],
]);

/** Synchronous, decryption-free view of stored SDW ciphertext envelopes. */
export interface SdwExportInventorySource {
  /** Return every stored entry (raw ciphertext bytes) in a namespace. */
  listNamespaceSync(
    namespace: SdwExportableNamespace,
  ): readonly SdwInventoryEntry[];
}

export interface SdwInventoryEntry {
  readonly key: string;
  readonly data: Uint8Array;
}

export interface SdwExportScopeRecord {
  readonly namespace: SdwExportableNamespace;
  readonly key: string;
  /** Hash of the ciphertext envelope (canonical form). Computed WITHOUT decryption. */
  readonly record_hash: string;
  readonly byte_length: number;
  readonly envelope: EncryptedPayload;
}

/** The frozen ciphertext inventory the human's approval is bound to. */
export interface SdwExportInventory {
  readonly namespaces: readonly SdwExportableNamespace[];
  /** Canonically ordered by (namespace, key). */
  readonly records: readonly SdwExportScopeRecord[];
  readonly record_count: number;
  readonly total_bytes: number;
  readonly scope_digest: string;
}

// ── Ratified D2 manifest / bundle shapes ─────────────────────────────────────

export interface SdwExportManifestBody {
  readonly version: 1;
  readonly bundle_version: 1;
  readonly source_fortress_id: string;
  readonly export_audit_event_id: string;
  readonly created_at: string;
  readonly records: ReadonlyArray<{
    readonly namespace: string;
    readonly key: string;
    readonly record_hash: string;
    readonly plaintext_record_version?: number;
  }>;
  readonly hnsw_segments: ReadonlyArray<{
    readonly namespace: "_sdw_vector_memory";
    readonly key: string;
    readonly segment_id: string;
    readonly generation: number;
    readonly record_hash: string;
  }>;
}

export interface SdwSignedExportManifest {
  readonly body: SdwExportManifestBody;
  readonly signature: {
    readonly alg: "ed25519";
    readonly key_ref: string;
    readonly value: string; // base64url
  };
}

export interface SdwStateExportBundle {
  readonly version: 1;
  readonly exported_at: string;
  readonly source_fortress_id: string;
  readonly export_audit_event_id: string;
  readonly manifest: SdwSignedExportManifest;
  readonly stores: ReadonlyArray<{
    readonly namespace: string;
    readonly hkdf_info: string;
    readonly records: ReadonlyArray<{
      readonly key: string;
      readonly aad_identity: {
        readonly fortress_id: string;
        readonly namespace: string;
        readonly key: string;
      };
      readonly plaintext_record_version?: number;
      readonly encrypted_payload: EncryptedPayload;
    }>;
  }>;
  readonly hnsw_segments: ReadonlyArray<{
    readonly namespace: "_sdw_vector_memory";
    readonly segment_id: string;
    readonly generation: number;
    readonly key: string;
    readonly aad_identity: {
      readonly fortress_id: string;
      readonly namespace: "_sdw_vector_memory";
      readonly key: string;
    };
    readonly encrypted_payload: EncryptedPayload;
  }>;
}

/** Approved-vs-live drift between gate time and assembly time. Fail closed. */
export class SdwExportScopeDriftError extends Error {
  readonly approvedDigest: string;
  readonly currentDigest: string;

  constructor(approvedDigest: string, currentDigest: string) {
    // Message is for the AUDIT LOG only — handlers must surface the generic
    // deny string to the agent (invariant #7), never this detail.
    super("SDW export scope drifted between approval and assembly");
    this.name = "SdwExportScopeDriftError";
    this.approvedDigest = approvedDigest;
    this.currentDigest = currentDigest;
  }
}

export function isSdwExportableNamespace(
  value: string,
): value is SdwExportableNamespace {
  return (SDW_EXPORTABLE_NAMESPACES as readonly string[]).includes(value);
}

export function sdwHkdfInfoForNamespace(namespace: string): string {
  const descriptor = defaultSdwStoreDescriptors().find(
    (store) => store.namespace === namespace,
  );
  if (descriptor === undefined) {
    throw new SdwValidationError("namespace_mismatch", "Unknown SDW namespace");
  }
  return descriptor.hkdf_info;
}

/**
 * Hash one ciphertext envelope. Operates on the canonical JSON of the parsed
 * envelope (not raw stored bytes) so the hash is reproducible from a bundle's
 * `encrypted_payload` object on the import side. Domain-separated.
 */
export function computeSdwExportRecordHash(envelope: EncryptedPayload): string {
  assertEncryptedEnvelopeShape(envelope);
  return hashToString(
    stringToBytes(SDW_EXPORT_RECORD_HASH_DOMAIN + canonicalJson(envelope)),
  );
}

/**
 * Enumerate the exact set of ciphertext records an export would ship, and
 * compute the scope digest the human's approval is bound to.
 *
 * Nothing is decrypted. Records are sorted canonically by (namespace, key)
 * and each digest entry binds namespace + key + ciphertext hash + length, so
 * reordering, swapping payloads between keys, or moving a record across
 * namespaces all change the digest (second-preimage hardening).
 */
export function enumerateSdwExportInventory(
  source: SdwExportInventorySource,
  namespaces?: readonly string[],
): SdwExportInventory {
  const requested =
    namespaces === undefined || namespaces.length === 0
      ? [...SDW_EXPORTABLE_NAMESPACES]
      : [...new Set(namespaces)];
  for (const namespace of requested) {
    if (!isSdwExportableNamespace(namespace)) {
      throw new SdwValidationError(
        "namespace_mismatch",
        "SDW namespace is not exportable",
      );
    }
  }
  const sortedNamespaces = [...requested].sort() as SdwExportableNamespace[];

  const records: SdwExportScopeRecord[] = [];
  const seen = new Set<string>();
  for (const namespace of sortedNamespaces) {
    const excludedPrefixes = EXCLUDED_KEY_PREFIXES.get(namespace) ?? [];
    const entries = [...source.listNamespaceSync(namespace)].sort((a, b) =>
      a.key < b.key ? -1 : a.key > b.key ? 1 : 0,
    );
    for (const entry of entries) {
      if (excludedPrefixes.some((prefix) => entry.key.startsWith(prefix))) {
        continue;
      }
      assertSdwIdentifier(entry.key, "storage_key");
      const composite = `${namespace}\u0000${entry.key}`;
      if (seen.has(composite)) {
        throw new SdwValidationError(
          "schema_mismatch",
          "Duplicate SDW export inventory entry",
        );
      }
      seen.add(composite);
      const envelope = parseEnvelope(entry.data);
      records.push({
        namespace,
        key: entry.key,
        record_hash: computeSdwExportRecordHash(envelope),
        byte_length: entry.data.length,
        envelope,
      });
    }
  }

  const digestEntries = records.map((record) => ({
    namespace: record.namespace,
    key: record.key,
    record_hash: record.record_hash,
    byte_length: record.byte_length,
  }));
  const scopeDigest = hashToString(
    stringToBytes(
      SDW_EXPORT_SCOPE_DIGEST_DOMAIN + canonicalJson(digestEntries),
    ),
  );

  return {
    namespaces: sortedNamespaces,
    records,
    record_count: records.length,
    total_bytes: records.reduce((sum, record) => sum + record.byte_length, 0),
    scope_digest: scopeDigest,
  };
}

/**
 * The metadata-only approval context (constraint #1: webhook/dashboard safe —
 * counts, names, digest; never record bodies, never ciphertext).
 */
export function sdwExportApprovalContext(inventory: SdwExportInventory): {
  namespaces: string[];
  record_count: number;
  total_bytes: number;
  scope_digest: string;
} {
  return {
    namespaces: [...inventory.namespaces],
    record_count: inventory.record_count,
    total_bytes: inventory.total_bytes,
    scope_digest: inventory.scope_digest,
  };
}

/** Exact bytes signed/verified for a manifest body (domain-prefixed canonical JSON). */
export function sdwManifestCanonicalBytes(
  body: SdwExportManifestBody,
): Uint8Array {
  return stringToBytes(
    SDW_EXPORT_MANIFEST_SIGNING_DOMAIN + canonicalJson(body),
  );
}

/** Digest of the canonical manifest body — the only manifest detail that may be logged. */
export function sdwManifestBodyDigest(body: SdwExportManifestBody): string {
  return hashToString(sdwManifestCanonicalBytes(body));
}

export interface SdwExportSigningKey {
  /** Public key reference recorded in the manifest (kid). NEVER key material. */
  readonly keyRef: string;
  /** Encrypted private key blob from identity storage (opaque to this module). */
  readonly encryptedPrivateKey: EncryptedPayload;
  /** Key-encryption key passed through to core/identity.sign(). */
  readonly encryptionKey: Uint8Array;
}

/**
 * Assemble and sign the export bundle from the APPROVED inventory snapshot.
 *
 * Fail-closed ordering (ratified invariants):
 * 1. Re-enumerate the live store and recompute the scope digest. Any drift
 *    from the approved inventory throws `SdwExportScopeDriftError` — nothing
 *    is signed, nothing is written.
 * 2. Only on an exact match: canonicalize the manifest body and sign it via
 *    `core/identity.ts:sign()` (key isolation boundary — key material never
 *    enters this module).
 *
 * The bundle's record payloads come from the approved snapshot itself, so the
 * shipped ciphertext is byte-for-byte what the human approved.
 */
export function buildSignedSdwExportBundle(params: {
  readonly inventory: SdwExportInventory;
  readonly source: SdwExportInventorySource;
  readonly fortressId: string;
  readonly exportAuditEventId: string;
  readonly signingKey: SdwExportSigningKey;
  readonly now?: string;
}): { bundle: SdwStateExportBundle; manifestBodyDigest: string } {
  assertSdwIdentifier(params.fortressId, "fortress_id");
  assertSdwIdentifier(params.exportAuditEventId, "export_audit_event_id");

  // ── 1. Drift recheck (fail closed BEFORE signing) ─────────────────────────
  const live = enumerateSdwExportInventory(
    params.source,
    params.inventory.namespaces,
  );
  if (live.scope_digest !== params.inventory.scope_digest) {
    throw new SdwExportScopeDriftError(
      params.inventory.scope_digest,
      live.scope_digest,
    );
  }

  // ── 2. Manifest body from the approved snapshot ───────────────────────────
  const createdAt = params.now ?? new Date().toISOString();
  const body: SdwExportManifestBody = {
    version: 1,
    bundle_version: 1,
    source_fortress_id: params.fortressId,
    export_audit_event_id: params.exportAuditEventId,
    created_at: createdAt,
    records: params.inventory.records.map((record) => ({
      namespace: record.namespace,
      key: record.key,
      record_hash: record.record_hash,
    })),
    // HNSW segment snapshots are not implemented yet (pre-ratification gate #1
    // is open); vector RECORDS in _sdw_vector_memory export as ordinary
    // records above and indexes rebuild from them on import.
    hnsw_segments: [],
  };

  // ── 3. Sign through the key-isolation boundary ────────────────────────────
  const canonicalBytes = sdwManifestCanonicalBytes(body);
  const signatureBytes = sign(
    canonicalBytes,
    params.signingKey.encryptedPrivateKey,
    params.signingKey.encryptionKey,
  );
  const manifest: SdwSignedExportManifest = {
    body,
    signature: {
      alg: "ed25519",
      key_ref: params.signingKey.keyRef,
      value: toBase64url(signatureBytes),
    },
  };

  // ── 4. Bundle stores grouped by namespace ─────────────────────────────────
  const stores = params.inventory.namespaces.map((namespace) => ({
    namespace,
    hkdf_info: sdwHkdfInfoForNamespace(namespace),
    records: params.inventory.records
      .filter((record) => record.namespace === namespace)
      .map((record) => ({
        key: record.key,
        aad_identity: {
          fortress_id: params.fortressId,
          namespace,
          key: record.key,
        },
        encrypted_payload: record.envelope,
      })),
  }));

  const bundle: SdwStateExportBundle = {
    version: 1,
    exported_at: createdAt,
    source_fortress_id: params.fortressId,
    export_audit_event_id: params.exportAuditEventId,
    manifest,
    stores,
    hnsw_segments: [],
  };

  return { bundle, manifestBodyDigest: sdwManifestBodyDigest(body) };
}

/** Injectable fs surface for crash-safety testing. */
export interface SdwExportFs {
  writeFile(path: string, data: string, options: { mode: number }): Promise<void>;
  rename(oldPath: string, newPath: string): Promise<void>;
  unlink(path: string): Promise<void>;
}

const defaultFs: SdwExportFs = {
  writeFile: (path, data, options) => writeFile(path, data, options),
  rename: (oldPath, newPath) => rename(oldPath, newPath),
  unlink: (path) => unlink(path),
};

/**
 * Atomic bundle write: temp file in the destination directory, then rename.
 * A crash or failure at any point leaves NO partial bundle at the destination
 * path; the temp file is best-effort cleaned on failure.
 */
export async function writeSdwExportBundleAtomic(
  bundle: SdwStateExportBundle,
  destinationPath: string,
  fsImpl: SdwExportFs = defaultFs,
): Promise<void> {
  const tempPath = `${destinationPath}.tmp-${randomBytes(8).toString("hex")}`;
  try {
    await fsImpl.writeFile(tempPath, JSON.stringify(bundle), { mode: 0o600 });
    await fsImpl.rename(tempPath, destinationPath);
  } catch (error) {
    try {
      await fsImpl.unlink(tempPath);
    } catch {
      // Best-effort temp cleanup; the destination path is untouched either way.
    }
    throw error;
  }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

function parseEnvelope(raw: Uint8Array): EncryptedPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    throw new SdwValidationError(
      "malformed",
      "SDW stored record is not a ciphertext envelope",
    );
  }
  assertEncryptedEnvelopeShape(parsed);
  return parsed;
}

function assertEncryptedEnvelopeShape(
  value: unknown,
): asserts value is EncryptedPayload {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (value as { v?: unknown }).v !== 1 ||
    (value as { alg?: unknown }).alg !== "aes-256-gcm" ||
    typeof (value as { iv?: unknown }).iv !== "string" ||
    typeof (value as { ct?: unknown }).ct !== "string" ||
    typeof (value as { ts?: unknown }).ts !== "string"
  ) {
    throw new SdwValidationError(
      "malformed",
      "SDW ciphertext envelope has an unexpected shape",
    );
  }
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
