/**
 * Sanctuary Verifiable Transparency — Enforcement Checkpoint format.
 *
 * An enforcement checkpoint is a compact SIGNED record that lets a third
 * party verify, offline, that a Sanctuary fortress's enforcement surface
 * (Castle Wall policy + tamper-evident audit log) was in a specific,
 * non-rolled-back state at a specific moment:
 *
 *   { audit-log Merkle root, policy hashes, daemon binary hash/version,
 *     per-rule enforcement counters (opaque labels), timestamp,
 *     strictly monotonic counter, previous-checkpoint hash }
 *
 * PRIVACY INVARIANTS (hard constraints #6 and #7 in CLAUDE.md):
 *   - NO state content. The checkpoint carries hashes and counts only.
 *   - NO rule details. Per-rule counters are keyed by an opaque label
 *     (domain-separated SHA-256 of the rule id), never the rule id or rule
 *     contents, so a published checkpoint does not disclose the policy.
 *   - NO key material. The record embeds only the PUBLIC verification key.
 *
 * SIGNING: a checkpoint is ALWAYS signed. There is no "unsigned" variant —
 * if no signer is reachable, emission refuses (hard constraint #5,
 * never-degrade). The production signer is the Castle Wall key custody
 * path (#387 helper-as-signer on macOS: the root helper holds the private
 * key and signs opaque domain-separated bytes; the emitting process never
 * sees the key).
 *
 * This module is PURE: types + canonical serialization + hashing +
 * signature verification. No I/O, no storage, no process state.
 */

import { canonicalJson, sha256Hex } from "../audit/chain.js";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { verify as verifyEd25519 } from "../core/identity.js";

/**
 * CROSS-FILE CONTRACT. `TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION`,
 * `TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX`, `TRANSPARENCY_CHECKPOINT_GENESIS`,
 * and `TRANSPARENCY_BUNDLE_FORMAT` are duplicated verbatim in
 * `transparency/verify.ts`, which imports no Sanctuary module at all. It could
 * not import them from here without acquiring this file's own imports
 * (`audit/chain.ts`, `core/encoding.ts`, `core/identity.ts`, and through
 * identity the crypto runtime), which is precisely the dependency graph an
 * offline verifier must not have. `TRANSPARENCY_CHECKPOINT_DOMAIN` and
 * `TRANSPARENCY_RULE_LABEL_DOMAIN` are not duplicated: verify.ts only ever
 * needs the newline-suffixed prefix form.
 *
 * Failure mode of a drifted copy: nothing fails to compile. The offline
 * verifier reports a signature or schema FAILURE on a bundle the fortress
 * signed correctly, and an auditor reads that as evidence of tampering rather
 * than as a stale mirror. Change a value here and in `transparency/verify.ts`
 * in the SAME PR. Enforced by
 * `test/structure/cross-file-contract-pins.test.ts`.
 */
export const TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION = 1;
export const TRANSPARENCY_CHECKPOINT_DOMAIN =
  "sanctuary.enforcement-checkpoint.v1";
export const TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX = `${TRANSPARENCY_CHECKPOINT_DOMAIN}\n`;
export const TRANSPARENCY_CHECKPOINT_GENESIS = "GENESIS";
export const TRANSPARENCY_RULE_LABEL_DOMAIN =
  "sanctuary.transparency.rule-label.v1";
export const TRANSPARENCY_BUNDLE_FORMAT = "SANCTUARY_TRANSPARENCY_BUNDLE_V1";

/** Audit-log window covered by a checkpoint (the surviving hash chain). */
export interface CheckpointAuditWindow {
  /** Root over ALL surviving chained entry hashes at emission time. */
  merkle_root: string;
  /** Lowest surviving chained sequence (0 when the chain is empty). */
  lowest_sequence: number;
  /** Highest surviving chained sequence (0 when the chain is empty). */
  highest_sequence: number;
  /** entry_hash of the chain head ("GENESIS" when the chain is empty). */
  head_hash: string;
  /** Number of surviving chained entries the root covers. */
  entry_count: number;
}

/** Policy posture covered by a checkpoint. Hashes and counts only. */
export interface CheckpointPolicy {
  /**
   * Domain-separated hash over the sorted per-rule-file hashes in
   * `policy/egress/rules/` — the exact inputs the Castle Wall daemon loads.
   */
  rules_sha256: string;
  rules_count: number;
  /** SHA-256 of `policy/egress/manifest.json` bytes when present, else null. */
  manifest_sha256: string | null;
}

/** Emitting-binary identity. SELF-REPORTED by the emitting process. */
export interface CheckpointDaemon {
  version: string;
  binary_sha256: string;
}

/** Per-rule enforcement counts keyed by OPAQUE labels (no rule details). */
export interface CheckpointRuleCounter {
  rule_label: string;
  allowed: number;
  blocked: number;
}

export interface CheckpointEnforcement {
  /** egress_allowed events in the covered audit window. */
  total_allowed: number;
  /** egress_blocked events in the covered audit window. */
  total_blocked: number;
  /** Sorted by rule_label ascending; only rules with at least one event. */
  rules: CheckpointRuleCounter[];
}

/** The signed payload. Every field below is covered by the signature. */
export interface EnforcementCheckpointPayload {
  checkpoint_kind: "enforcement-checkpoint";
  schema_version: typeof TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION;
  /** Strictly monotonic, starts at 1, increments by exactly 1. */
  counter: number;
  /**
   * SHA-256 (hex) of the canonical JSON of the PREVIOUS checkpoint payload,
   * or "GENESIS" for the first checkpoint. Hash-chains checkpoints so a
   * replaced or reordered checkpoint breaks linkage.
   */
  previous_checkpoint_hash: string;
  issued_at: string;
  fortress_id: string;
  audit: CheckpointAuditWindow;
  policy: CheckpointPolicy;
  daemon: CheckpointDaemon;
  enforcement: CheckpointEnforcement;
}

/** The persisted/published record: payload + mandatory signature envelope. */
export interface EnforcementCheckpointRecord extends EnforcementCheckpointPayload {
  signer_kid: string;
  signature: string;
  signature_algorithm: "Ed25519";
  payload_encoding: "domain-separated-canonical-json-v1";
  /** Base64url raw 32-byte Ed25519 public key of the signer. */
  public_key: string;
}

/** Self-contained publishable bundle (offline-verifiable with the key alone). */
export interface TransparencyBundle {
  format: typeof TRANSPARENCY_BUNDLE_FORMAT;
  exported_at: string;
  /** Base64url raw 32-byte Ed25519 public key all checkpoints verify under. */
  public_key: string;
  checkpoints: EnforcementCheckpointRecord[];
}

/** Extract the signed payload (drops the signature envelope fields). */
export function checkpointPayloadOf(
  record: EnforcementCheckpointRecord
): EnforcementCheckpointPayload {
  return {
    checkpoint_kind: record.checkpoint_kind,
    schema_version: record.schema_version,
    counter: record.counter,
    previous_checkpoint_hash: record.previous_checkpoint_hash,
    issued_at: record.issued_at,
    fortress_id: record.fortress_id,
    audit: record.audit,
    policy: record.policy,
    daemon: record.daemon,
    enforcement: record.enforcement,
  };
}

/** Domain-separated bytes that are actually signed. */
export function checkpointSigningBytes(
  payload: EnforcementCheckpointPayload
): Uint8Array {
  return stringToBytes(
    `${TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX}${canonicalJson(payload)}`
  );
}

/** Hash used for previous_checkpoint_hash linkage. */
export function computeCheckpointHash(
  payload: EnforcementCheckpointPayload
): string {
  return sha256Hex(
    `${TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX}${canonicalJson(payload)}`
  );
}

/**
 * Opaque per-rule label: discloses event counts per rule WITHOUT disclosing
 * the rule id or contents (constraint #7 — policy stays agent-opaque and a
 * published checkpoint stays policy-opaque). Recomputable on the host (which
 * knows the rule ids) for counter cross-checks; not reversible offline
 * beyond dictionary guessing of rule-id strings.
 */
export function transparencyRuleLabel(
  fortressId: string,
  ruleId: string
): string {
  return sha256Hex(
    `${TRANSPARENCY_RULE_LABEL_DOMAIN}\n${fortressId}\n${ruleId}`
  );
}

/** Verify the record's Ed25519 signature against an explicit public key. */
export function verifyEnforcementCheckpointSignature(
  record: EnforcementCheckpointRecord,
  publicKey: string | Uint8Array
): boolean {
  try {
    const keyBytes =
      typeof publicKey === "string" ? fromBase64url(publicKey) : publicKey;
    // 32 = RFC 8032 Ed25519 public key, the compressed Edwards point encoding.
    // Kept as a literal on purpose: this module is a LEGACY FROZEN SERIALIZER,
    // and `test/structure/pqc-slice1-additive.test.ts` forbids it from even
    // naming the signature-suite registry, so that frozen v1 signatures stay
    // byte-stable. The value must equal `ED25519_PUBLIC_KEY_BYTES`;
    // `test/structure/key-length-constants.test.ts` asserts that it does.
    if (keyBytes.length !== 32) return false;
    return verifyEd25519(
      checkpointSigningBytes(checkpointPayloadOf(record)),
      fromBase64url(record.signature),
      keyBytes
    );
  } catch {
    return false;
  }
}

// Lowercase 64-char SHA-256 hex. NOT a cross-file contract: every module that
// validates a hash digest declares its own copy of this shape (10 files, 14
// occurrences in server/src as of 2026-08-05), and they are independent local
// validators rather than mirrors of one canonical declaration. Deliberately
// not hoisted; the same note is on the counterpart in `verify.ts`.
const HEX64 = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isAuditWindow(value: unknown): value is CheckpointAuditWindow {
  return (
    isRecord(value) &&
    typeof value.merkle_root === "string" &&
    HEX64.test(value.merkle_root) &&
    isNonNegativeSafeInteger(value.lowest_sequence) &&
    isNonNegativeSafeInteger(value.highest_sequence) &&
    typeof value.head_hash === "string" &&
    isNonNegativeSafeInteger(value.entry_count)
  );
}

function isPolicy(value: unknown): value is CheckpointPolicy {
  return (
    isRecord(value) &&
    typeof value.rules_sha256 === "string" &&
    HEX64.test(value.rules_sha256) &&
    isNonNegativeSafeInteger(value.rules_count) &&
    (value.manifest_sha256 === null ||
      (typeof value.manifest_sha256 === "string" &&
        HEX64.test(value.manifest_sha256)))
  );
}

function isDaemon(value: unknown): value is CheckpointDaemon {
  return (
    isRecord(value) &&
    typeof value.version === "string" &&
    typeof value.binary_sha256 === "string" &&
    HEX64.test(value.binary_sha256)
  );
}

function isEnforcement(value: unknown): value is CheckpointEnforcement {
  if (
    !isRecord(value) ||
    !isNonNegativeSafeInteger(value.total_allowed) ||
    !isNonNegativeSafeInteger(value.total_blocked) ||
    !Array.isArray(value.rules)
  ) {
    return false;
  }
  return value.rules.every(
    (rule) =>
      isRecord(rule) &&
      typeof rule.rule_label === "string" &&
      HEX64.test(rule.rule_label) &&
      isNonNegativeSafeInteger(rule.allowed) &&
      isNonNegativeSafeInteger(rule.blocked)
  );
}

export function isEnforcementCheckpointRecord(
  value: unknown
): value is EnforcementCheckpointRecord {
  return (
    isRecord(value) &&
    value.checkpoint_kind === "enforcement-checkpoint" &&
    value.schema_version === TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION &&
    typeof value.counter === "number" &&
    Number.isSafeInteger(value.counter) &&
    value.counter > 0 &&
    typeof value.previous_checkpoint_hash === "string" &&
    (value.previous_checkpoint_hash === TRANSPARENCY_CHECKPOINT_GENESIS ||
      HEX64.test(value.previous_checkpoint_hash)) &&
    typeof value.issued_at === "string" &&
    typeof value.fortress_id === "string" &&
    isAuditWindow(value.audit) &&
    isPolicy(value.policy) &&
    isDaemon(value.daemon) &&
    isEnforcement(value.enforcement) &&
    typeof value.signer_kid === "string" &&
    value.signer_kid.length > 0 &&
    typeof value.signature === "string" &&
    value.signature.length > 0 &&
    value.signature_algorithm === "Ed25519" &&
    value.payload_encoding === "domain-separated-canonical-json-v1" &&
    typeof value.public_key === "string" &&
    value.public_key.length > 0
  );
}

export function isTransparencyBundle(
  value: unknown
): value is TransparencyBundle {
  return (
    isRecord(value) &&
    value.format === TRANSPARENCY_BUNDLE_FORMAT &&
    typeof value.exported_at === "string" &&
    typeof value.public_key === "string" &&
    value.public_key.length > 0 &&
    Array.isArray(value.checkpoints) &&
    value.checkpoints.every((checkpoint) =>
      isEnforcementCheckpointRecord(checkpoint)
    )
  );
}
