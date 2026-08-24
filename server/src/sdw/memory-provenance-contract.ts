/**
 * Memory Integrity Slice C1: dormant signed-memory provenance contract.
 *
 * This module defines bytes and verification semantics only. It does not
 * write SDW records, change read eligibility, migrate legacy passages, or
 * enable Exit/fleet/capsule carriage. Later slices must import these parsers
 * and verifiers rather than mirror their decisions.
 */

import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../core/crypto-suite-registry.js";
import {
  concatBytes,
  fromBase64urlStrict,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import { hash } from "../core/hashing.js";
import {
  legacyPublicKeyToDid,
  publicKeyBytesEqual,
  publicKeyToDid,
  verify as verifyIdentitySignature,
} from "../core/identity.js";
import { parseIsoInstantWithOffset } from "../core/time.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { MAX_KNOWN_SIGNERS } from "../reputation/known-signers-store.js";
import { SubstrateError } from "../substrate/errors.js";
import { parseStrictJson } from "../substrate/strict-json.js";
import { isSdwIdentifier } from "./grammar.js";

export const MEMORY_PROVENANCE_COMPANION_FORMAT =
  "SANCTUARY_SDW_MEMORY_PROVENANCE_V1" as const;
export const MEMORY_ORIGIN_FORMAT =
  "SANCTUARY_SDW_MEMORY_ORIGIN_V1" as const;
export const MEMORY_ADMISSION_FORMAT =
  "SANCTUARY_SDW_MEMORY_ADMISSION_V1" as const;
export const MEMORY_SIGNATURE_SCHEME = "ed25519-v1" as const;

/** Must match the two entries in core/signing-domains.ts exactly. */
export const MEMORY_ORIGIN_SIGNING_DOMAIN =
  "sanctuary.sdw.memory-origin.v1\n" as const;
/** Must match the two entries in core/signing-domains.ts exactly. */
export const MEMORY_ADMISSION_SIGNING_DOMAIN =
  "sanctuary.sdw.memory-admission.v1\n" as const;

/** 16 KiB, fixed by the Slice C design and checked before JSON parsing. */
export const MAX_MEMORY_PROVENANCE_COMPANION_BYTES = 16 * 1024;
/** Existing bounded Exit known-signers ceiling; checked before iteration. */
export const MAX_MEMORY_PROVENANCE_SIGNER_ENTRIES = MAX_KNOWN_SIGNERS;

export const MEMORY_ADMISSION_CHANNELS = [
  "local_write",
  "legacy_migration",
  "exit_v2_import",
  "fleet_sync",
  "operator_readmission",
] as const;
export type MemoryAdmissionChannel =
  (typeof MEMORY_ADMISSION_CHANNELS)[number];

export const MEMORY_ORIGIN_TRUST_TIERS = [
  "local_attested",
  "legacy_unattested",
  "foreign_direct",
  "foreign_relayed",
] as const;
export type MemoryOriginTrustTier =
  (typeof MEMORY_ORIGIN_TRUST_TIERS)[number];

export const MEMORY_VERIFICATION_BASES = [
  "local_primary_identity",
  "legacy_local_observation",
  "exit_v2_manifest_key",
  "exit_v2_known_signers",
  "exit_v2_legacy_v1",
  "fleet_sync_manifest_key",
  "fleet_sync_known_signers",
  "operator_readmission_after_compromise",
] as const;
export type MemoryVerificationBasis =
  (typeof MEMORY_VERIFICATION_BASES)[number];

export interface MemoryAdmissionTriple {
  readonly admission_channel: MemoryAdmissionChannel;
  readonly origin_trust_tier: MemoryOriginTrustTier;
  readonly verification_basis: MemoryVerificationBasis;
}

export const MEMORY_ADMISSION_TRIPLES: readonly MemoryAdmissionTriple[] = [
  {
    admission_channel: "local_write",
    origin_trust_tier: "local_attested",
    verification_basis: "local_primary_identity",
  },
  {
    admission_channel: "legacy_migration",
    origin_trust_tier: "legacy_unattested",
    verification_basis: "legacy_local_observation",
  },
  {
    admission_channel: "exit_v2_import",
    origin_trust_tier: "foreign_direct",
    verification_basis: "exit_v2_manifest_key",
  },
  {
    admission_channel: "exit_v2_import",
    origin_trust_tier: "foreign_relayed",
    verification_basis: "exit_v2_known_signers",
  },
  {
    admission_channel: "exit_v2_import",
    origin_trust_tier: "legacy_unattested",
    verification_basis: "exit_v2_legacy_v1",
  },
  {
    admission_channel: "fleet_sync",
    origin_trust_tier: "foreign_direct",
    verification_basis: "fleet_sync_manifest_key",
  },
  {
    admission_channel: "fleet_sync",
    origin_trust_tier: "foreign_relayed",
    verification_basis: "fleet_sync_known_signers",
  },
  {
    admission_channel: "operator_readmission",
    origin_trust_tier: "legacy_unattested",
    verification_basis: "operator_readmission_after_compromise",
  },
] as const;

export const MEMORY_INGRESS_CHANNELS = [
  "memory_insert",
  "anthropic_memory_tool",
  "file_import",
  "memory_transcode",
  "legacy_migration",
  "legacy_unknown",
  "fleet_sync",
] as const;
export type MemoryIngressChannel = (typeof MEMORY_INGRESS_CHANNELS)[number];

export const MEMORY_SOURCE_CLASSES = [
  "user_content",
  "agent_derived_clean",
  "system_generated",
  "claude_code_index",
  "claude_code_fact",
  "codex_index",
  "codex_summary",
  "codex_raw",
  "transcode_manifest",
  "transcode_source_file",
  "exit_lineage",
  "legacy_unattested",
  "fleet_sync_lineage",
] as const;
export type MemorySourceClass = (typeof MEMORY_SOURCE_CLASSES)[number];

export const MEMORY_INGRESS_SOURCE_PAIRS = {
  memory_insert: ["user_content", "agent_derived_clean", "system_generated"],
  anthropic_memory_tool: [
    "user_content",
    "agent_derived_clean",
    "system_generated",
  ],
  file_import: [
    "claude_code_index",
    "claude_code_fact",
    "codex_index",
    "codex_summary",
    "codex_raw",
  ],
  memory_transcode: [
    "transcode_manifest",
    "transcode_source_file",
    "exit_lineage",
  ],
  legacy_migration: ["legacy_unattested"],
  legacy_unknown: ["legacy_unattested"],
  fleet_sync: ["fleet_sync_lineage"],
} as const satisfies Record<
  MemoryIngressChannel,
  readonly MemorySourceClass[]
>;

/**
 * Rule-7 credibility contract. Consumers may make these conclusions and no
 * stronger ones from a verified C1 record.
 */
export const MEMORY_PROVENANCE_CREDIBILITY = Object.freeze({
  author_agent_id:
    "The origin fortress says it observed the named harness-configured agent id at ingress; this is not an agent self-signature or proof of authorship.",
  ingress_channel:
    "The origin fortress says the record crossed the named code-owned ingress; this does not authenticate upstream data.",
  source_class:
    "The origin fortress says its adapter or classifier selected the named closed class; this does not prove the class is true or the content is safe.",
  recorded_at:
    "The origin fortress key holder asserted this time; freshness and clock accuracy remain relying-party policy.",
  origin_subject:
    "The origin signature binds fortress, owner, passage, content hash, and chunk count; it does not prove content truth or uniqueness.",
  destination_admission:
    "The destination fortress states what it verified and how it classified the origin; admission never upgrades or replaces the origin signature.",
  signature:
    "A valid Ed25519 signature proves only that the holder of the resolved key signed these exact bytes.",
} as const);

export interface MemoryOriginBody {
  readonly format: typeof MEMORY_ORIGIN_FORMAT;
  readonly origin_fortress_id: string;
  readonly owner_ref: string;
  readonly passage_id: string;
  readonly content_hash: string;
  readonly chunk_count: number;
  readonly author_agent_id: string;
  readonly ingress_channel: MemoryIngressChannel;
  readonly source_class: MemorySourceClass;
  readonly recorded_at: string;
  readonly signer_identity_id: string;
  readonly signer_did: string;
  readonly signature_scheme: typeof MEMORY_SIGNATURE_SCHEME;
}

export interface SignedMemoryOrigin {
  readonly body: MemoryOriginBody;
  /** Canonical no-padding base64url Ed25519 signature. */
  readonly signature: string;
}

export interface MemoryAdmissionBody {
  readonly format: typeof MEMORY_ADMISSION_FORMAT;
  readonly origin_provenance_digest: string;
  readonly destination_fortress_id: string;
  readonly destination_owner_ref: string;
  readonly passage_id: string;
  readonly admission_channel: MemoryAdmissionChannel;
  readonly origin_trust_tier: MemoryOriginTrustTier;
  readonly verification_basis: MemoryVerificationBasis;
  readonly admitted_at: string;
  readonly transfer_lineage_ref?: string;
  readonly signer_identity_id: string;
  readonly signer_did: string;
  readonly signature_scheme: typeof MEMORY_SIGNATURE_SCHEME;
}

export interface SignedMemoryAdmission {
  readonly body: MemoryAdmissionBody;
  /** Canonical no-padding base64url Ed25519 signature. */
  readonly signature: string;
}

export interface MemoryProvenanceCompanion {
  readonly format: typeof MEMORY_PROVENANCE_COMPANION_FORMAT;
  readonly origin: SignedMemoryOrigin;
  readonly origin_provenance_digest: string;
  readonly admission: SignedMemoryAdmission;
}

export type MemoryProvenanceFailureCode =
  | "companion_too_large"
  | "json_invalid"
  | "object_expected"
  | "unknown_key"
  | "duplicate_key"
  | "prototype_key"
  | "json_too_deep"
  | "json_trailing_bytes"
  | "missing_key"
  | "invalid_literal"
  | "invalid_identifier"
  | "invalid_hash"
  | "invalid_count"
  | "invalid_timestamp"
  | "invalid_base64url"
  | "invalid_public_key_length"
  | "invalid_signature_length"
  | "ingress_source_pair_invalid"
  | "admission_triple_invalid"
  | "transfer_lineage_invalid"
  | "signer_did_key_mismatch"
  | "signer_duplicate_conflict"
  | "signer_self_entry"
  | "signer_table_too_large"
  | "signer_unknown"
  | "signature_invalid"
  | "sign_failed"
  | "origin_provenance_digest_mismatch"
  | "origin_subject_mismatch"
  | "destination_mismatch";

export interface MemoryProvenanceFailure {
  readonly code: MemoryProvenanceFailureCode;
  readonly path: string;
  readonly message: string;
}

export type MemoryProvenanceResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: MemoryProvenanceFailure };

export interface MemoryProvenanceSigningHandle {
  readonly identity_id: string;
  readonly did: string;
  readonly public_key: Uint8Array;
  /** Narrow signing handle: no private key is exposed through this contract. */
  sign(bytes: Uint8Array): Uint8Array;
}

export interface MemoryOriginInput {
  readonly origin_fortress_id: string;
  readonly owner_ref: string;
  readonly passage_id: string;
  readonly content_hash: string;
  readonly chunk_count: number;
  readonly author_agent_id: string;
  readonly ingress_channel: MemoryIngressChannel;
  readonly source_class: MemorySourceClass;
  readonly recorded_at: string;
}

export interface MemoryAdmissionInput {
  readonly origin_provenance_digest: string;
  readonly destination_fortress_id: string;
  readonly destination_owner_ref: string;
  readonly passage_id: string;
  readonly admission_channel: MemoryAdmissionChannel;
  readonly origin_trust_tier: MemoryOriginTrustTier;
  readonly verification_basis: MemoryVerificationBasis;
  readonly admitted_at: string;
  readonly transfer_lineage_ref?: string;
}

export interface MemoryProvenanceSignerEntry {
  readonly signer_identity_id: string;
  readonly signer_did: string;
  readonly public_key: string;
}

export interface MemoryProvenanceSignerResolver {
  readonly size: number;
  resolve(signerIdentityId: string, signerDid: string): Uint8Array | undefined;
}

export interface MemoryProvenanceExpectedBinding {
  readonly origin: {
    readonly origin_fortress_id: string;
    readonly owner_ref: string;
    readonly passage_id: string;
    readonly content_hash: string;
    readonly chunk_count: number;
  };
  readonly destination: {
    readonly destination_fortress_id: string;
    readonly destination_owner_ref: string;
    readonly passage_id: string;
  };
}

const ORIGIN_BODY_KEYS = [
  "format",
  "origin_fortress_id",
  "owner_ref",
  "passage_id",
  "content_hash",
  "chunk_count",
  "author_agent_id",
  "ingress_channel",
  "source_class",
  "recorded_at",
  "signer_identity_id",
  "signer_did",
  "signature_scheme",
] as const;
const ADMISSION_BODY_KEYS = [
  "format",
  "origin_provenance_digest",
  "destination_fortress_id",
  "destination_owner_ref",
  "passage_id",
  "admission_channel",
  "origin_trust_tier",
  "verification_basis",
  "admitted_at",
  "transfer_lineage_ref",
  "signer_identity_id",
  "signer_did",
  "signature_scheme",
] as const;
const SIGNED_VALUE_KEYS = ["body", "signature"] as const;
const COMPANION_KEYS = [
  "format",
  "origin",
  "origin_provenance_digest",
  "admission",
] as const;
const SIGNER_ENTRY_KEYS = [
  "signer_identity_id",
  "signer_did",
  "public_key",
] as const;

function failure(
  code: MemoryProvenanceFailureCode,
  path: string,
  message: string,
): MemoryProvenanceResult<never> {
  return { ok: false, error: { code, path, message } };
}

function exactObject(
  value: unknown,
  requiredKeys: readonly string[],
  path: string,
  optionalKeys: readonly string[] = [],
): MemoryProvenanceResult<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return failure("object_expected", path, "Expected a JSON object");
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set(requiredKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      return failure("unknown_key", path, "Object contains an unknown key");
    }
  }
  const optional = new Set(optionalKeys);
  for (const key of requiredKeys) {
    if (!optional.has(key) && !Object.hasOwn(record, key)) {
      return failure("missing_key", `${path}.${key}`, "Required key is missing");
    }
  }
  return { ok: true, value: record };
}

function parseIdentifier(
  value: unknown,
  path: string,
): MemoryProvenanceResult<string> {
  if (typeof value !== "string" || !isSdwIdentifier(value)) {
    return failure("invalid_identifier", path, "Expected a bounded SDW identifier");
  }
  return { ok: true, value };
}

function parseDid(value: unknown, path: string): MemoryProvenanceResult<string> {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    !/^did:key:z[A-Za-z0-9_-]{1,240}$/.test(value)
  ) {
    return failure("invalid_identifier", path, "Expected a bounded did:key identifier");
  }
  return { ok: true, value };
}

function decodeFixedBase64url(
  value: unknown,
  byteLength: number,
  path: string,
  lengthCode: "invalid_hash" | "invalid_public_key_length" | "invalid_signature_length",
): MemoryProvenanceResult<Uint8Array> {
  if (typeof value !== "string") {
    return failure("invalid_base64url", path, "Expected canonical base64url text");
  }
  let decoded: Uint8Array;
  try {
    decoded = fromBase64urlStrict(value);
  } catch {
    return failure("invalid_base64url", path, "Expected canonical base64url text");
  }
  if (decoded.length !== byteLength) {
    return failure(lengthCode, path, "Decoded byte length is invalid");
  }
  return { ok: true, value: decoded };
}

function parseContentHash(value: unknown, path: string): MemoryProvenanceResult<string> {
  const decoded = decodeFixedBase64url(value, 32, path, "invalid_hash");
  return decoded.ok ? { ok: true, value: value as string } : decoded;
}

function parseProvenanceDigest(
  value: unknown,
  path: string,
): MemoryProvenanceResult<string> {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    return failure(
      "invalid_hash",
      path,
      "Expected a lowercase 64-character SHA-256 hex digest",
    );
  }
  return { ok: true, value };
}

function parseTimestamp(
  value: unknown,
  path: string,
): MemoryProvenanceResult<string> {
  if (
    typeof value !== "string" ||
    value.length > 64 ||
    parseIsoInstantWithOffset(value) === undefined
  ) {
    return failure(
      "invalid_timestamp",
      path,
      "Expected a strict ISO-8601 instant with an explicit offset",
    );
  }
  return { ok: true, value };
}

function includesLiteral<T extends string>(
  values: readonly T[],
  value: unknown,
): value is T {
  return typeof value === "string" && (values as readonly string[]).includes(value);
}

export function isAllowedMemoryIngressSourcePair(
  ingressChannel: MemoryIngressChannel,
  sourceClass: MemorySourceClass,
): boolean {
  return (MEMORY_INGRESS_SOURCE_PAIRS[ingressChannel] as readonly string[]).includes(
    sourceClass,
  );
}

export function isAllowedMemoryAdmissionTriple(
  triple: MemoryAdmissionTriple,
): boolean {
  return MEMORY_ADMISSION_TRIPLES.some(
    (allowed) =>
      allowed.admission_channel === triple.admission_channel &&
      allowed.origin_trust_tier === triple.origin_trust_tier &&
      allowed.verification_basis === triple.verification_basis,
  );
}

function parseOriginBody(value: unknown): MemoryProvenanceResult<MemoryOriginBody> {
  const object = exactObject(value, ORIGIN_BODY_KEYS, "origin.body");
  if (!object.ok) return object;
  const record = object.value;
  if (record.format !== MEMORY_ORIGIN_FORMAT) {
    return failure("invalid_literal", "origin.body.format", "Unsupported origin format");
  }
  if (record.signature_scheme !== MEMORY_SIGNATURE_SCHEME) {
    return failure(
      "invalid_literal",
      "origin.body.signature_scheme",
      "Unsupported signature scheme",
    );
  }
  const originFortress = parseIdentifier(record.origin_fortress_id, "origin.body.origin_fortress_id");
  if (!originFortress.ok) return originFortress;
  const owner = parseIdentifier(record.owner_ref, "origin.body.owner_ref");
  if (!owner.ok) return owner;
  const passage = parseIdentifier(record.passage_id, "origin.body.passage_id");
  if (!passage.ok) return passage;
  // Design tension resolved in favor of the shipped MemoryPassage contract:
  // passage content hashes remain canonical unpadded base64url SHA-256.
  const contentHash = parseContentHash(record.content_hash, "origin.body.content_hash");
  if (!contentHash.ok) return contentHash;
  if (!Number.isSafeInteger(record.chunk_count) || (record.chunk_count as number) < 1) {
    return failure("invalid_count", "origin.body.chunk_count", "Chunk count must be a positive safe integer");
  }
  const author = parseIdentifier(record.author_agent_id, "origin.body.author_agent_id");
  if (!author.ok) return author;
  if (!includesLiteral(MEMORY_INGRESS_CHANNELS, record.ingress_channel)) {
    return failure("invalid_literal", "origin.body.ingress_channel", "Unknown ingress channel");
  }
  if (!includesLiteral(MEMORY_SOURCE_CLASSES, record.source_class)) {
    return failure("invalid_literal", "origin.body.source_class", "Unknown source class");
  }
  if (!isAllowedMemoryIngressSourcePair(record.ingress_channel, record.source_class)) {
    return failure(
      "ingress_source_pair_invalid",
      "origin.body",
      "Ingress channel and source class are not an allowed pair",
    );
  }
  const recordedAt = parseTimestamp(record.recorded_at, "origin.body.recorded_at");
  if (!recordedAt.ok) return recordedAt;
  const signerIdentity = parseIdentifier(record.signer_identity_id, "origin.body.signer_identity_id");
  if (!signerIdentity.ok) return signerIdentity;
  const signerDid = parseDid(record.signer_did, "origin.body.signer_did");
  if (!signerDid.ok) return signerDid;
  return {
    ok: true,
    value: record as unknown as MemoryOriginBody,
  };
}

function parseAdmissionBody(
  value: unknown,
): MemoryProvenanceResult<MemoryAdmissionBody> {
  const object = exactObject(
    value,
    ADMISSION_BODY_KEYS,
    "admission.body",
    ["transfer_lineage_ref"],
  );
  if (!object.ok) return object;
  const record = object.value;
  if (record.format !== MEMORY_ADMISSION_FORMAT) {
    return failure("invalid_literal", "admission.body.format", "Unsupported admission format");
  }
  if (record.signature_scheme !== MEMORY_SIGNATURE_SCHEME) {
    return failure(
      "invalid_literal",
      "admission.body.signature_scheme",
      "Unsupported signature scheme",
    );
  }
  const digest = parseProvenanceDigest(
    record.origin_provenance_digest,
    "admission.body.origin_provenance_digest",
  );
  if (!digest.ok) return digest;
  for (const [key, path] of [
    ["destination_fortress_id", "admission.body.destination_fortress_id"],
    ["destination_owner_ref", "admission.body.destination_owner_ref"],
    ["passage_id", "admission.body.passage_id"],
    ["signer_identity_id", "admission.body.signer_identity_id"],
  ] as const) {
    const parsed = parseIdentifier(record[key], path);
    if (!parsed.ok) return parsed;
  }
  if (!includesLiteral(MEMORY_ADMISSION_CHANNELS, record.admission_channel)) {
    return failure("invalid_literal", "admission.body.admission_channel", "Unknown admission channel");
  }
  if (!includesLiteral(MEMORY_ORIGIN_TRUST_TIERS, record.origin_trust_tier)) {
    return failure("invalid_literal", "admission.body.origin_trust_tier", "Unknown origin trust tier");
  }
  if (!includesLiteral(MEMORY_VERIFICATION_BASES, record.verification_basis)) {
    return failure("invalid_literal", "admission.body.verification_basis", "Unknown verification basis");
  }
  if (
    !isAllowedMemoryAdmissionTriple({
      admission_channel: record.admission_channel,
      origin_trust_tier: record.origin_trust_tier,
      verification_basis: record.verification_basis,
    })
  ) {
    return failure(
      "admission_triple_invalid",
      "admission.body",
      "Admission channel, trust tier, and verification basis are not an allowed triple",
    );
  }
  const admittedAt = parseTimestamp(record.admitted_at, "admission.body.admitted_at");
  if (!admittedAt.ok) return admittedAt;
  const signerDid = parseDid(record.signer_did, "admission.body.signer_did");
  if (!signerDid.ok) return signerDid;
  const needsLineage =
    record.admission_channel === "exit_v2_import" || record.admission_channel === "fleet_sync";
  if (needsLineage) {
    const lineage = parseIdentifier(
      record.transfer_lineage_ref,
      "admission.body.transfer_lineage_ref",
    );
    if (!lineage.ok) {
      return failure(
        "transfer_lineage_invalid",
        "admission.body.transfer_lineage_ref",
        "Transport admission requires a bounded transfer lineage reference",
      );
    }
  } else if (record.transfer_lineage_ref !== undefined) {
    return failure(
      "transfer_lineage_invalid",
      "admission.body.transfer_lineage_ref",
      "This admission channel must not carry a transfer lineage reference",
    );
  }
  return { ok: true, value: record as unknown as MemoryAdmissionBody };
}

function parseSignedOrigin(value: unknown): MemoryProvenanceResult<SignedMemoryOrigin> {
  const object = exactObject(value, SIGNED_VALUE_KEYS, "origin");
  if (!object.ok) return object;
  const body = parseOriginBody(object.value.body);
  if (!body.ok) return body;
  const signature = decodeFixedBase64url(
    object.value.signature,
    ED25519_SIGNATURE_BYTES,
    "origin.signature",
    "invalid_signature_length",
  );
  if (!signature.ok) return signature;
  return {
    ok: true,
    value: { body: body.value, signature: object.value.signature as string },
  };
}

function parseSignedAdmission(
  value: unknown,
): MemoryProvenanceResult<SignedMemoryAdmission> {
  const object = exactObject(value, SIGNED_VALUE_KEYS, "admission");
  if (!object.ok) return object;
  const body = parseAdmissionBody(object.value.body);
  if (!body.ok) return body;
  const signature = decodeFixedBase64url(
    object.value.signature,
    ED25519_SIGNATURE_BYTES,
    "admission.signature",
    "invalid_signature_length",
  );
  if (!signature.ok) return signature;
  return {
    ok: true,
    value: { body: body.value, signature: object.value.signature as string },
  };
}

/**
 * Parses an already-materialized value. This API cannot recover duplicate-key
 * evidence that a caller has already lost. Wire and persisted JSON callers
 * must enter through parseMemoryProvenanceCompanionJson instead.
 */
export function parseMemoryProvenanceCompanionValue(
  value: unknown,
): MemoryProvenanceResult<MemoryProvenanceCompanion> {
  const object = exactObject(value, COMPANION_KEYS, "companion");
  if (!object.ok) return object;
  if (object.value.format !== MEMORY_PROVENANCE_COMPANION_FORMAT) {
    return failure("invalid_literal", "companion.format", "Unsupported companion format");
  }
  const origin = parseSignedOrigin(object.value.origin);
  if (!origin.ok) return origin;
  const digest = parseProvenanceDigest(
    object.value.origin_provenance_digest,
    "companion.origin_provenance_digest",
  );
  if (!digest.ok) return digest;
  const admission = parseSignedAdmission(object.value.admission);
  if (!admission.ok) return admission;
  return {
    ok: true,
    value: {
      format: MEMORY_PROVENANCE_COMPANION_FORMAT,
      origin: origin.value,
      origin_provenance_digest: digest.value,
      admission: admission.value,
    },
  };
}

export function parseMemoryProvenanceCompanionJson(
  input: string | Uint8Array,
): MemoryProvenanceResult<MemoryProvenanceCompanion> {
  // UTF-16 code units are never more numerous than their UTF-8 bytes. This
  // cheap check refuses obviously oversized strings before allocating an
  // attacker-sized encoded copy; the byte check below remains authoritative.
  if (
    typeof input === "string" &&
    input.length > MAX_MEMORY_PROVENANCE_COMPANION_BYTES
  ) {
    return failure(
      "companion_too_large",
      "companion",
      "Companion exceeds the pre-parse byte ceiling",
    );
  }
  const bytes = typeof input === "string" ? stringToBytes(input) : input;
  if (bytes.length > MAX_MEMORY_PROVENANCE_COMPANION_BYTES) {
    return failure(
      "companion_too_large",
      "companion",
      "Companion exceeds the pre-parse byte ceiling",
    );
  }
  let text: string;
  try {
    text =
      typeof input === "string"
        ? input
        : new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    return failure("json_invalid", "companion", "Companion is not valid UTF-8 JSON");
  }
  let parsed: unknown;
  try {
    parsed = parseStrictJson(text);
  } catch (error) {
    if (error instanceof SubstrateError) {
      if (error.reason === "json_duplicate_key") {
        return failure("duplicate_key", "companion", "Companion contains a duplicate object key");
      }
      if (error.reason === "json_prototype_key") {
        return failure("prototype_key", "companion", "Companion contains a prototype key");
      }
      if (error.reason === "json_too_deep") {
        return failure("json_too_deep", "companion", "Companion nesting is too deep");
      }
      if (error.reason === "frame_trailing_bytes") {
        return failure("json_trailing_bytes", "companion", "Companion JSON has invalid or trailing bytes");
      }
    }
    return failure("json_invalid", "companion", "Companion is not valid JSON");
  }
  return parseMemoryProvenanceCompanionValue(parsed);
}

export function memoryOriginSigningBytes(body: MemoryOriginBody): Uint8Array {
  return concatBytes(
    stringToBytes(MEMORY_ORIGIN_SIGNING_DOMAIN),
    canonicalizeToBytes(body),
  );
}

export function memoryAdmissionSigningBytes(
  body: MemoryAdmissionBody,
): Uint8Array {
  return concatBytes(
    stringToBytes(MEMORY_ADMISSION_SIGNING_DOMAIN),
    canonicalizeToBytes(body),
  );
}

export function computeMemoryOriginProvenanceDigest(
  origin: SignedMemoryOrigin,
): string {
  const digest = hash(
    canonicalizeToBytes({ body: origin.body, signature: origin.signature }),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function signerMatchesKey(
  signerDid: string,
  publicKey: Uint8Array,
): boolean {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  return (
    signerDid === publicKeyToDid(publicKey) ||
    signerDid === legacyPublicKeyToDid(publicKey)
  );
}

function validateSigningHandle(
  signer: MemoryProvenanceSigningHandle,
): MemoryProvenanceResult<MemoryProvenanceSigningHandle> {
  const identity = parseIdentifier(signer.identity_id, "signer.identity_id");
  if (!identity.ok) return identity;
  const did = parseDid(signer.did, "signer.did");
  if (!did.ok) return did;
  if (signer.public_key.length !== ED25519_PUBLIC_KEY_BYTES) {
    return failure(
      "invalid_public_key_length",
      "signer.public_key",
      "Signer public key length is invalid",
    );
  }
  if (!signerMatchesKey(signer.did, signer.public_key)) {
    return failure(
      "signer_did_key_mismatch",
      "signer.did",
      "Signer DID does not derive from signer public key",
    );
  }
  return { ok: true, value: signer };
}

export function signMemoryOrigin(
  input: MemoryOriginInput,
  signer: MemoryProvenanceSigningHandle,
): MemoryProvenanceResult<SignedMemoryOrigin> {
  const handle = validateSigningHandle(signer);
  if (!handle.ok) return handle;
  const bodyCandidate: MemoryOriginBody = {
    format: MEMORY_ORIGIN_FORMAT,
    ...input,
    signer_identity_id: signer.identity_id,
    signer_did: signer.did,
    signature_scheme: MEMORY_SIGNATURE_SCHEME,
  };
  const body = parseOriginBody(bodyCandidate);
  if (!body.ok) return body;
  let signature: Uint8Array;
  try {
    signature = signer.sign(memoryOriginSigningBytes(body.value));
  } catch {
    return failure("sign_failed", "origin.signature", "Origin signing failed");
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    return failure(
      "invalid_signature_length",
      "origin.signature",
      "Signer returned an invalid signature length",
    );
  }
  if (
    !verifyIdentitySignature(
      memoryOriginSigningBytes(body.value),
      signature,
      signer.public_key,
    )
  ) {
    return failure(
      "signature_invalid",
      "origin.signature",
      "Signer output did not self-verify",
    );
  }
  return {
    ok: true,
    value: { body: body.value, signature: toBase64url(signature) },
  };
}

export function signMemoryAdmission(
  input: MemoryAdmissionInput,
  signer: MemoryProvenanceSigningHandle,
): MemoryProvenanceResult<SignedMemoryAdmission> {
  const handle = validateSigningHandle(signer);
  if (!handle.ok) return handle;
  const bodyCandidate: MemoryAdmissionBody = {
    format: MEMORY_ADMISSION_FORMAT,
    ...input,
    signer_identity_id: signer.identity_id,
    signer_did: signer.did,
    signature_scheme: MEMORY_SIGNATURE_SCHEME,
  };
  const body = parseAdmissionBody(bodyCandidate);
  if (!body.ok) return body;
  let signature: Uint8Array;
  try {
    signature = signer.sign(memoryAdmissionSigningBytes(body.value));
  } catch {
    return failure("sign_failed", "admission.signature", "Admission signing failed");
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    return failure(
      "invalid_signature_length",
      "admission.signature",
      "Signer returned an invalid signature length",
    );
  }
  if (
    !verifyIdentitySignature(
      memoryAdmissionSigningBytes(body.value),
      signature,
      signer.public_key,
    )
  ) {
    return failure(
      "signature_invalid",
      "admission.signature",
      "Signer output did not self-verify",
    );
  }
  return {
    ok: true,
    value: { body: body.value, signature: toBase64url(signature) },
  };
}

export function createMemoryProvenanceCompanion(
  origin: SignedMemoryOrigin,
  admissionInput: Omit<MemoryAdmissionInput, "origin_provenance_digest">,
  admissionSigner: MemoryProvenanceSigningHandle,
): MemoryProvenanceResult<MemoryProvenanceCompanion> {
  const parsedOrigin = parseSignedOrigin(origin);
  if (!parsedOrigin.ok) return parsedOrigin;
  const originProvenanceDigest = computeMemoryOriginProvenanceDigest(parsedOrigin.value);
  const admission = signMemoryAdmission(
    {
      ...admissionInput,
      origin_provenance_digest: originProvenanceDigest,
    },
    admissionSigner,
  );
  if (!admission.ok) return admission;
  return {
    ok: true,
    value: {
      format: MEMORY_PROVENANCE_COMPANION_FORMAT,
      origin: parsedOrigin.value,
      origin_provenance_digest: originProvenanceDigest,
      admission: admission.value,
    },
  };
}

export function createBoundedMemoryProvenanceSignerResolver(
  entries: readonly unknown[],
  options: {
    readonly maxEntries?: number;
    readonly forbiddenSigner?: {
      readonly did: string;
      readonly public_key: Uint8Array;
    };
  } = {},
): MemoryProvenanceResult<MemoryProvenanceSignerResolver> {
  if (!Array.isArray(entries)) {
    return failure("object_expected", "signers", "Signer table must be an array");
  }
  const maxEntries = options.maxEntries ?? MAX_MEMORY_PROVENANCE_SIGNER_ENTRIES;
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 0) {
    return failure("invalid_count", "signers", "Signer-table bound is invalid");
  }
  // Count is checked before any attacker-controlled element is inspected.
  if (entries.length > maxEntries) {
    return failure(
      "signer_table_too_large",
      "signers",
      "Signer table exceeds its pre-iteration entry ceiling",
    );
  }
  const byDid = new Map<
    string,
    { readonly identityId: string; readonly publicKey: Uint8Array }
  >();
  const byIdentity = new Map<string, { readonly did: string; readonly publicKey: Uint8Array }>();
  for (let index = 0; index < entries.length; index += 1) {
    const path = `signers[${String(index)}]`;
    const object = exactObject(entries[index], SIGNER_ENTRY_KEYS, path);
    if (!object.ok) return object;
    const identity = parseIdentifier(object.value.signer_identity_id, `${path}.signer_identity_id`);
    if (!identity.ok) return identity;
    const did = parseDid(object.value.signer_did, `${path}.signer_did`);
    if (!did.ok) return did;
    const key = decodeFixedBase64url(
      object.value.public_key,
      ED25519_PUBLIC_KEY_BYTES,
      `${path}.public_key`,
      "invalid_public_key_length",
    );
    if (!key.ok) return key;
    if (!signerMatchesKey(did.value, key.value)) {
      return failure(
        "signer_did_key_mismatch",
        `${path}.signer_did`,
        "Signer DID does not derive from signer public key",
      );
    }
    if (
      options.forbiddenSigner !== undefined &&
      (did.value === options.forbiddenSigner.did ||
        publicKeyBytesEqual(key.value, options.forbiddenSigner.public_key))
    ) {
      return failure(
        "signer_self_entry",
        path,
        "Signer table contains the forbidden exporting signer",
      );
    }
    const didExisting = byDid.get(did.value);
    if (
      didExisting !== undefined &&
      (didExisting.identityId !== identity.value ||
        !publicKeyBytesEqual(didExisting.publicKey, key.value))
    ) {
      return failure(
        "signer_duplicate_conflict",
        path,
        "Signer DID appears with conflicting identity or key material",
      );
    }
    const identityExisting = byIdentity.get(identity.value);
    if (
      identityExisting !== undefined &&
      (identityExisting.did !== did.value ||
        !publicKeyBytesEqual(identityExisting.publicKey, key.value))
    ) {
      return failure(
        "signer_duplicate_conflict",
        path,
        "Signer identity appears with conflicting DID or key material",
      );
    }
    byDid.set(did.value, { identityId: identity.value, publicKey: key.value });
    byIdentity.set(identity.value, { did: did.value, publicKey: key.value });
  }
  return {
    ok: true,
    value: Object.freeze({
      size: byDid.size,
      resolve(signerIdentityId: string, signerDid: string): Uint8Array | undefined {
        const entry = byDid.get(signerDid);
        if (entry === undefined || entry.identityId !== signerIdentityId) return undefined;
        return entry.publicKey.slice();
      },
    }),
  };
}

export function verifyMemoryProvenanceCompanion(
  companionValue: unknown,
  resolver: MemoryProvenanceSignerResolver,
  expected: MemoryProvenanceExpectedBinding,
): MemoryProvenanceResult<MemoryProvenanceCompanion> {
  const parsed = parseMemoryProvenanceCompanionValue(companionValue);
  if (!parsed.ok) return parsed;
  const companion = parsed.value;
  const originKey = resolver.resolve(
    companion.origin.body.signer_identity_id,
    companion.origin.body.signer_did,
  );
  if (originKey === undefined) {
    return failure("signer_unknown", "origin.body.signer_did", "Origin signer is unknown");
  }
  if (!signerMatchesKey(companion.origin.body.signer_did, originKey)) {
    return failure(
      "signer_did_key_mismatch",
      "origin.body.signer_did",
      "Origin signer DID does not derive from resolved key",
    );
  }
  const originSignature = fromBase64urlStrict(companion.origin.signature);
  if (
    !verifyIdentitySignature(
      memoryOriginSigningBytes(companion.origin.body),
      originSignature,
      originKey,
    )
  ) {
    return failure("signature_invalid", "origin.signature", "Origin signature is invalid");
  }
  const computedDigest = computeMemoryOriginProvenanceDigest(companion.origin);
  if (
    computedDigest !== companion.origin_provenance_digest ||
    computedDigest !== companion.admission.body.origin_provenance_digest
  ) {
    return failure(
      "origin_provenance_digest_mismatch",
      "companion.origin_provenance_digest",
      "Origin provenance digest does not bind origin and admission",
    );
  }
  const origin = companion.origin.body;
  if (
    origin.origin_fortress_id !== expected.origin.origin_fortress_id ||
    origin.owner_ref !== expected.origin.owner_ref ||
    origin.passage_id !== expected.origin.passage_id ||
    origin.content_hash !== expected.origin.content_hash ||
    origin.chunk_count !== expected.origin.chunk_count
  ) {
    return failure(
      "origin_subject_mismatch",
      "origin.body",
      "Origin subject does not match the logical passage",
    );
  }
  const admissionKey = resolver.resolve(
    companion.admission.body.signer_identity_id,
    companion.admission.body.signer_did,
  );
  if (admissionKey === undefined) {
    return failure("signer_unknown", "admission.body.signer_did", "Admission signer is unknown");
  }
  if (!signerMatchesKey(companion.admission.body.signer_did, admissionKey)) {
    return failure(
      "signer_did_key_mismatch",
      "admission.body.signer_did",
      "Admission signer DID does not derive from resolved key",
    );
  }
  const admissionSignature = fromBase64urlStrict(companion.admission.signature);
  if (
    !verifyIdentitySignature(
      memoryAdmissionSigningBytes(companion.admission.body),
      admissionSignature,
      admissionKey,
    )
  ) {
    return failure(
      "signature_invalid",
      "admission.signature",
      "Admission signature is invalid",
    );
  }
  const admission = companion.admission.body;
  if (
    admission.destination_fortress_id !== expected.destination.destination_fortress_id ||
    admission.destination_owner_ref !== expected.destination.destination_owner_ref ||
    admission.passage_id !== expected.destination.passage_id
  ) {
    return failure(
      "destination_mismatch",
      "admission.body",
      "Admission destination does not match the local passage",
    );
  }
  return { ok: true, value: companion };
}
