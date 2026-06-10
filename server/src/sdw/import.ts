/**
 * SDW D2 — Import: verify-before-prompt, decrypt-only-inside-approval,
 * digest-only rejection logging.
 *
 * Ratified invariants implemented here:
 * - The manifest signature is verified (Ed25519, via `core/identity.ts:verify`)
 *   BEFORE any approval prompt fires and before any record is touched.
 *   Verification needs only the public key — no decryption, no Tier-1 resource.
 * - Rejected/invalid bundles are NEVER logged verbatim: failures carry only a
 *   category and (when computable) the manifest-body digest.
 * - Record decryption happens exclusively inside the approved import flow:
 *   verify again on the exact bytes → decrypt with source material → validate
 *   (version, kind, manifest membership, canonical hash) → rebind AAD to the
 *   target fortress → re-encrypt through `mintPersistable` → `sdwBackendWrite`.
 * - Two-phase commit: every record is decrypted and validated in memory FIRST;
 *   nothing is written unless the entire bundle validates (fail closed, no
 *   partial imports).
 */

import type { StorageBackend } from "../storage/interface.js";
import { decrypt, type EncryptedPayload } from "../core/encryption.js";
import { bytesToString, fromBase64url, stringToBytes } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { verify } from "../core/identity.js";
import { sdwAad, isSdwIdentifier } from "./grammar.js";
import {
  isSdwNamespace,
  mintPersistable,
  sdwBackendWrite,
  type Persistable,
} from "./write-gate.js";
import type { SdwNamespace, SdwRecord } from "./records.js";
import {
  computeSdwExportRecordHash,
  isSdwExportableNamespace,
  sdwHkdfInfoForNamespace,
  sdwManifestBodyDigest,
  sdwManifestCanonicalBytes,
  type SdwExportManifestBody,
  type SdwStateExportBundle,
} from "./export.js";

/** Hard caps — a hostile bundle must not exhaust memory before verification. */
const MAX_BUNDLE_BYTES = 64 * 1024 * 1024;
const MAX_BUNDLE_RECORDS = 100_000;

export type SdwImportRejectCategory =
  | "malformed_bundle"
  | "oversize"
  | "unsupported_version"
  | "key_unknown"
  | "signature_invalid"
  | "manifest_mismatch"
  | "record_hash_mismatch"
  | "identity_mismatch"
  | "decrypt_failed"
  | "schema_invalid"
  | "source_key_unavailable";

/**
 * Typed verification/import failure. `message` and `category` are safe to
 * audit-log; the bundle body never appears in either. `manifestBodyDigest` is
 * null when the failure occurred before a manifest body could be decoded.
 */
export class SdwImportVerificationError extends Error {
  readonly category: SdwImportRejectCategory;
  readonly manifestBodyDigest: string | null;

  constructor(
    category: SdwImportRejectCategory,
    manifestBodyDigest: string | null = null,
  ) {
    super(`SDW import rejected: ${category}`);
    this.name = "SdwImportVerificationError";
    this.category = category;
    this.manifestBodyDigest = manifestBodyDigest;
  }
}

export interface SdwVerifiedImportSummary {
  readonly manifest_body_digest: string;
  readonly source_fortress_id: string;
  readonly export_audit_event_id: string;
  readonly namespaces: readonly string[];
  readonly record_count: number;
  readonly total_ciphertext_bytes: number;
}

/**
 * Decode a base64url-encoded bundle with size caps and full structural
 * validation. Throws `SdwImportVerificationError` — never echoes content.
 */
export function decodeSdwExportBundle(bundleBase64url: string): SdwStateExportBundle {
  if (typeof bundleBase64url !== "string" || bundleBase64url.length === 0) {
    throw new SdwImportVerificationError("malformed_bundle");
  }
  // base64url expands ~4/3; cheap pre-cap before decode.
  if (bundleBase64url.length > (MAX_BUNDLE_BYTES * 4) / 3 + 4) {
    throw new SdwImportVerificationError("oversize");
  }
  let json: string;
  try {
    json = bytesToString(fromBase64url(bundleBase64url));
  } catch {
    throw new SdwImportVerificationError("malformed_bundle");
  }
  if (json.length > MAX_BUNDLE_BYTES) {
    throw new SdwImportVerificationError("oversize");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new SdwImportVerificationError("malformed_bundle");
  }
  return assertBundleShape(parsed);
}

/**
 * Verify a decoded bundle's signed manifest and full internal consistency.
 * Pure + synchronous so a tool's `approvalTargetArgs` can run it BEFORE the
 * human is prompted. No decryption, no writes, no key material.
 *
 * Rejects when (ratified D2 list): the signature fails; the body
 * `source_fortress_id` or `export_audit_event_id` differs from the bundle; a
 * listed record is absent; an unlisted record is present; a namespace/key
 * identity differs; or a computed per-record hash differs from the manifest.
 */
export function verifySdwExportManifest(
  bundle: SdwStateExportBundle,
  resolvePublicKey: (keyRef: string) => Uint8Array | null,
): SdwVerifiedImportSummary {
  const body = bundle.manifest.body;
  const digest = sdwManifestBodyDigest(body);

  if (body.version !== 1 || body.bundle_version !== 1 || bundle.version !== 1) {
    throw new SdwImportVerificationError("unsupported_version", digest);
  }

  // ── Signature FIRST: nothing else about the bundle is trusted until the
  //    manifest authenticates. ─────────────────────────────────────────────
  if (bundle.manifest.signature.alg !== "ed25519") {
    throw new SdwImportVerificationError("signature_invalid", digest);
  }
  const publicKey = resolvePublicKey(bundle.manifest.signature.key_ref);
  if (publicKey === null) {
    throw new SdwImportVerificationError("key_unknown", digest);
  }
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64url(bundle.manifest.signature.value);
  } catch {
    throw new SdwImportVerificationError("signature_invalid", digest);
  }
  if (!verify(sdwManifestCanonicalBytes(body), signatureBytes, publicKey)) {
    throw new SdwImportVerificationError("signature_invalid", digest);
  }

  // ── Bundle/body cross-checks ──────────────────────────────────────────────
  if (
    bundle.source_fortress_id !== body.source_fortress_id ||
    bundle.export_audit_event_id !== body.export_audit_event_id
  ) {
    throw new SdwImportVerificationError("manifest_mismatch", digest);
  }

  // ── Record-set equality (both directions) + per-record hashes ────────────
  const manifestRecords = new Map<string, string>();
  for (const record of body.records) {
    const composite = compositeRecordId(record.namespace, record.key);
    if (manifestRecords.has(composite)) {
      throw new SdwImportVerificationError("manifest_mismatch", digest);
    }
    manifestRecords.set(composite, record.record_hash);
  }

  let totalCiphertextBytes = 0;
  const seenBundleRecords = new Set<string>();
  for (const store of bundle.stores) {
    if (sdwHkdfInfoSafe(store.namespace) !== store.hkdf_info) {
      throw new SdwImportVerificationError("schema_invalid", digest);
    }
    for (const record of store.records) {
      const composite = compositeRecordId(store.namespace, record.key);
      if (seenBundleRecords.has(composite)) {
        throw new SdwImportVerificationError("manifest_mismatch", digest);
      }
      seenBundleRecords.add(composite);

      const expectedHash = manifestRecords.get(composite);
      if (expectedHash === undefined) {
        // Unlisted record present in the bundle.
        throw new SdwImportVerificationError("manifest_mismatch", digest);
      }
      if (
        record.aad_identity.fortress_id !== body.source_fortress_id ||
        record.aad_identity.namespace !== store.namespace ||
        record.aad_identity.key !== record.key
      ) {
        throw new SdwImportVerificationError("identity_mismatch", digest);
      }
      if (computeSdwExportRecordHash(record.encrypted_payload) !== expectedHash) {
        throw new SdwImportVerificationError("record_hash_mismatch", digest);
      }
      totalCiphertextBytes += record.encrypted_payload.ct.length;
    }
  }
  if (seenBundleRecords.size !== manifestRecords.size) {
    // Listed record absent from the bundle.
    throw new SdwImportVerificationError("manifest_mismatch", digest);
  }
  if (bundle.hnsw_segments.length !== body.hnsw_segments.length) {
    throw new SdwImportVerificationError("manifest_mismatch", digest);
  }

  return {
    manifest_body_digest: digest,
    source_fortress_id: body.source_fortress_id,
    export_audit_event_id: body.export_audit_event_id,
    namespaces: [...new Set(bundle.stores.map((store) => store.namespace))].sort(),
    record_count: seenBundleRecords.size,
    total_ciphertext_bytes: totalCiphertextBytes,
  };
}

export interface SdwImportResult {
  readonly manifest_body_digest: string;
  readonly source_fortress_id: string;
  readonly imported: number;
  readonly skipped_existing: number;
  readonly overwritten: number;
  readonly namespaces: readonly string[];
}

/**
 * Execute the ratified import flow (steps 2–8) AFTER Tier-1 approval.
 *
 * Phase 1 (no writes): re-verify the signed manifest on the exact bytes, then
 * decrypt and validate EVERY record in memory. Any failure aborts the whole
 * import before a single write (fail closed; constraint #5 — no partial,
 * degraded import).
 *
 * Phase 2: rebind AAD to `target_fortress_id || namespace || key` and persist
 * each record through `mintPersistable` → `sdwBackendWrite` (the single
 * gated write path, with taint/schema/classifier checks as defense-in-depth).
 */
export async function importSdwExportBundle(params: {
  readonly bundle: SdwStateExportBundle;
  readonly storage: StorageBackend;
  readonly resolvePublicKey: (keyRef: string) => Uint8Array | null;
  readonly sourceMasterKey: Uint8Array;
  readonly targetMasterKey: Uint8Array;
  readonly targetFortressId: string;
  readonly conflictResolution?: "skip" | "overwrite";
}): Promise<SdwImportResult> {
  const summary = verifySdwExportManifest(params.bundle, params.resolvePublicKey);
  const digest = summary.manifest_body_digest;
  const conflictResolution = params.conflictResolution ?? "skip";
  if (!isSdwIdentifier(params.targetFortressId)) {
    throw new SdwImportVerificationError("schema_invalid", digest);
  }

  // ── Phase 1: decrypt + validate + mint everything, write nothing ─────────
  // Minting happens in phase 1 (not interleaved with writes) so a record that
  // fails schema/namespace/classifier validation aborts the import BEFORE any
  // write — no partial imports (constraint #5).
  const minted: Array<{
    namespace: SdwNamespace;
    key: string;
    persistable: Persistable<SdwRecord>;
    targetStoreKey: Uint8Array;
  }> = [];
  for (const store of params.bundle.stores) {
    if (!isSdwNamespace(store.namespace) || !isSdwExportableNamespace(store.namespace)) {
      throw new SdwImportVerificationError("schema_invalid", digest);
    }
    const namespace = store.namespace;
    const sourceStoreKey = derivePurposeKey(
      params.sourceMasterKey,
      store.hkdf_info,
    );
    const targetStoreKey = derivePurposeKey(
      params.targetMasterKey,
      sdwHkdfInfoForNamespace(namespace),
    );
    for (const bundleRecord of store.records) {
      const plaintextRecord = decryptBundleRecord(
        bundleRecord.encrypted_payload,
        sourceStoreKey,
        params.bundle.source_fortress_id,
        namespace,
        bundleRecord.key,
        digest,
      );
      // mintPersistable revalidates schema + namespace binding + classifier
      // and computes the TARGET AAD (target fortress id || namespace || key).
      let persistable: Persistable<SdwRecord>;
      try {
        persistable = mintPersistable(
          { value: plaintextRecord, taint: "user_content" },
          namespace,
          bundleRecord.key,
          params.targetFortressId,
        );
      } catch {
        throw new SdwImportVerificationError("schema_invalid", digest);
      }
      minted.push({
        namespace,
        key: bundleRecord.key,
        persistable,
        targetStoreKey,
      });
    }
  }

  // ── Phase 2: rebind + re-encrypt under the target fortress ───────────────
  let imported = 0;
  let skippedExisting = 0;
  let overwritten = 0;
  for (const item of minted) {
    const existing = await params.storage.read(item.namespace, item.key);
    if (existing !== null) {
      if (conflictResolution === "skip") {
        skippedExisting += 1;
        continue;
      }
      overwritten += 1;
    }
    await sdwBackendWrite(
      params.storage,
      item.persistable,
      item.targetStoreKey,
      params.targetFortressId,
    );
    imported += 1;
  }

  return {
    manifest_body_digest: digest,
    source_fortress_id: summary.source_fortress_id,
    imported,
    skipped_existing: skippedExisting,
    overwritten,
    namespaces: summary.namespaces,
  };
}

// ── Internal helpers ─────────────────────────────────────────────────────────

function decryptBundleRecord(
  envelope: EncryptedPayload,
  sourceStoreKey: Uint8Array,
  sourceFortressId: string,
  namespace: SdwNamespace,
  key: string,
  digest: string,
): SdwRecord {
  let plaintext: Uint8Array;
  try {
    const aad = sdwAad(sourceFortressId, namespace, key);
    plaintext = decrypt(envelope, sourceStoreKey, aad);
  } catch {
    throw new SdwImportVerificationError("decrypt_failed", digest);
  }
  let record: SdwRecord & { readonly version?: unknown };
  try {
    record = JSON.parse(bytesToString(plaintext)) as SdwRecord;
  } catch {
    throw new SdwImportVerificationError("schema_invalid", digest);
  } finally {
    plaintext.fill(0);
  }
  if (record === null || typeof record !== "object") {
    throw new SdwImportVerificationError("schema_invalid", digest);
  }
  if (record.version !== 1) {
    // Direct-read semantics: unknown-newer record versions fail closed.
    throw new SdwImportVerificationError("unsupported_version", digest);
  }
  return record;
}

function compositeRecordId(namespace: string, key: string): string {
  return `${stringToBytes(namespace).length}:${namespace}|${stringToBytes(key).length}:${key}`;
}

function sdwHkdfInfoSafe(namespace: string): string | null {
  try {
    return sdwHkdfInfoForNamespace(namespace);
  } catch {
    return null;
  }
}

function assertBundleShape(value: unknown): SdwStateExportBundle {
  const fail = (): never => {
    throw new SdwImportVerificationError("malformed_bundle");
  };
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const bundle = value as SdwStateExportBundle;
  if (
    typeof bundle.exported_at !== "string" ||
    typeof bundle.source_fortress_id !== "string" ||
    typeof bundle.export_audit_event_id !== "string" ||
    !isSdwIdentifier(bundle.source_fortress_id) ||
    !isSdwIdentifier(bundle.export_audit_event_id) ||
    bundle.manifest === null ||
    typeof bundle.manifest !== "object" ||
    bundle.manifest.body === null ||
    typeof bundle.manifest.body !== "object" ||
    bundle.manifest.signature === null ||
    typeof bundle.manifest.signature !== "object" ||
    typeof bundle.manifest.signature.key_ref !== "string" ||
    typeof bundle.manifest.signature.value !== "string" ||
    !Array.isArray(bundle.stores) ||
    !Array.isArray(bundle.hnsw_segments)
  ) {
    fail();
  }
  assertManifestBodyShape(bundle.manifest.body);
  let recordCount = 0;
  for (const store of bundle.stores) {
    if (
      store === null ||
      typeof store !== "object" ||
      typeof store.namespace !== "string" ||
      typeof store.hkdf_info !== "string" ||
      !Array.isArray(store.records)
    ) {
      fail();
    }
    for (const record of store.records) {
      recordCount += 1;
      if (recordCount > MAX_BUNDLE_RECORDS) {
        throw new SdwImportVerificationError("oversize");
      }
      if (
        record === null ||
        typeof record !== "object" ||
        typeof record.key !== "string" ||
        !isSdwIdentifier(record.key) ||
        record.aad_identity === null ||
        typeof record.aad_identity !== "object" ||
        typeof record.aad_identity.fortress_id !== "string" ||
        typeof record.aad_identity.namespace !== "string" ||
        typeof record.aad_identity.key !== "string" ||
        !isEncryptedPayloadShape(record.encrypted_payload)
      ) {
        fail();
      }
    }
  }
  return bundle;
}

function assertManifestBodyShape(value: unknown): asserts value is SdwExportManifestBody {
  const fail = (): never => {
    throw new SdwImportVerificationError("malformed_bundle");
  };
  const body = value as SdwExportManifestBody;
  if (
    typeof body.source_fortress_id !== "string" ||
    typeof body.export_audit_event_id !== "string" ||
    typeof body.created_at !== "string" ||
    !Array.isArray(body.records) ||
    !Array.isArray(body.hnsw_segments)
  ) {
    fail();
  }
  if (body.records.length > MAX_BUNDLE_RECORDS) {
    throw new SdwImportVerificationError("oversize");
  }
  for (const record of body.records) {
    if (
      record === null ||
      typeof record !== "object" ||
      typeof record.namespace !== "string" ||
      typeof record.key !== "string" ||
      typeof record.record_hash !== "string"
    ) {
      fail();
    }
  }
}

function isEncryptedPayloadShape(value: unknown): value is EncryptedPayload {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (value as { v?: unknown }).v === 1 &&
    (value as { alg?: unknown }).alg === "aes-256-gcm" &&
    typeof (value as { iv?: unknown }).iv === "string" &&
    typeof (value as { ct?: unknown }).ct === "string" &&
    typeof (value as { ts?: unknown }).ts === "string"
  );
}
