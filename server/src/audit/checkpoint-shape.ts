/**
 * Sanctuary Audit - Checkpoint record SHAPE (pure, dependency-free).
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * G1 (post-#969 sweep re-gate, 2026-07-27): the raw CLI exporter
 * (`cli/audit-chain-export.ts`) deliberately avoids importing the server
 * runtime, so it carried a hand-DUPLICATED copy of the audit-log's checkpoint
 * validator. The copies drifted: a record missing `schema_version`,
 * `signature_algorithm`, and `payload_encoding` passed the exporter's weaker
 * duplicate (and was exported uncounted, so the evidence pack could sign a
 * populated export) while the runtime validator in `operational/audit-log.ts`
 * rejected it. This module makes that drift structurally impossible: the ONE
 * checkpoint shape predicate lives here, with ZERO imports (no server runtime,
 * no node builtins), and BOTH the runtime audit log and the raw exporter
 * import it. The exporter's no-runtime-imports posture survives because this
 * module has no runtime to drag in.
 *
 * The `_audit_checkpoints` control-key constants live here for the same
 * reason (G5): the exporter's key-aware skip allowlist and the audit log's
 * writers must agree on which fixed keys are legitimate non-checkpoint
 * control records, and a shared definition is the only mechanism that cannot
 * drift. The literals are LIVE at-rest storage keys; never edit the values.
 *
 * `audit/chain.ts` re-exports this surface, so existing importers of the
 * checkpoint record type and schema version are unchanged.
 */

/** Schema version stamped on every persisted checkpoint record. */
export const AUDIT_CHECKPOINT_SCHEMA_VERSION = 1;

/**
 * Audit-chain wire constants, moved here 2026-08-05 for the SAME reason the
 * checkpoint shape predicate was (G1): the standalone external verifier
 * `cli/audit-chain-verify.ts` re-typed THREE of them as local constants
 * (`AUDIT_CHAIN_GENESIS`, `AUDIT_CHAIN_SCHEMA_VERSION`, and
 * `AUDIT_CHECKPOINT_DOMAIN_PREFIX`) because importing them from
 * `audit/chain.ts` would have dragged in `core/identity.ts` ->
 * `core/encryption.ts` and the rest of the crypto runtime. The fourth,
 * `AUDIT_CHECKPOINT_DOMAIN`, was never a separate declaration there: it
 * existed only spelled out inside that prefix string, which is the more
 * dangerous shape, since a domain change had no named constant to grep for.
 *
 * This module has ZERO imports, so the verifier can import from here at no
 * dependency cost, exactly as `cli/audit-chain-export.ts` already does for the
 * checkpoint shape. `audit/chain.ts` re-exports all four, so every existing
 * importer is unchanged.
 *
 * The literals are LIVE at-rest and signing-domain values; never edit them.
 * `AUDIT_CHECKPOINT_DOMAIN_PREFIX`'s trailing newline is part of the signed
 * bytes.
 */
export const AUDIT_CHAIN_GENESIS = "GENESIS";
export const AUDIT_CHAIN_SCHEMA_VERSION = 2;
export const AUDIT_CHECKPOINT_DOMAIN = "sanctuary.audit-checkpoint.v1";
export const AUDIT_CHECKPOINT_DOMAIN_PREFIX = `${AUDIT_CHECKPOINT_DOMAIN}\n`;

/**
 * Fixed `_audit_checkpoints` storage key of the MAC-authenticated audit head
 * anchor (anti-rollback). A control record, never exported as a checkpoint.
 */
export const AUDIT_HEAD_ANCHOR_KEY = "__head_anchor";

/**
 * Fixed `_audit_checkpoints` storage key of the authenticated custody-epoch
 * record (prior-master audit keys across rotations). A control record, never
 * exported as a checkpoint.
 */
export const AUDIT_EPOCH_KEYS_KEY = "__custody_epoch_keys";

/**
 * Fixed `_audit_checkpoints` storage key of the MAC-authenticated
 * checkpoint-signing latch: one-way fortress memory that a SIGNED checkpoint
 * was once written, so a later `unsigned` checkpoint reads as a downgrade
 * finding instead of an honest pre-bootstrap store. A control record, never
 * exported as a checkpoint.
 */
export const AUDIT_SIGNING_LATCH_KEY = "__signing_latch";

/**
 * The CLOSED allowlist of legitimate NON-EXPORT control records that live in
 * the `_audit_checkpoints` namespace under fixed keys. A record under one of
 * these keys may be skipped by the chain exporter WITHOUT counting toward
 * `checkpointsSkipped`; a record under any OTHER key that parses but fails
 * {@link isAuditCheckpointRecord} is malformed and MUST be counted (F-2). A
 * new control record added to the namespace MUST be added here in the same
 * PR, exactly like the master-rotation classifier's closed set
 * (`core/master-rotation.ts` `convertAuditAnchors`); forgetting it discloses
 * a loud false INCOMPLETE on healthy fortresses, never a silent flattering
 * claim. (`__rotation_anchor` is NOT here: it is positively classified and
 * exported by its own marker-based guard.)
 */
export const AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS: readonly string[] = [
  AUDIT_HEAD_ANCHOR_KEY,
  AUDIT_EPOCH_KEYS_KEY,
  AUDIT_SIGNING_LATCH_KEY,
];

/** The fields a checkpoint signature ranges over. */
export interface AuditCheckpointSigningPayload {
  checkpoint_kind: "audit-checkpoint" | "legacy-anchor";
  checkpoint_sequence: number;
  from_sequence: number;
  root_hash: string;
  previous_checkpoint_sequence: number;
  signed_at: string;
}

/** The persisted checkpoint / legacy-anchor record. */
export interface AuditCheckpointRecord extends AuditCheckpointSigningPayload {
  schema_version: typeof AUDIT_CHECKPOINT_SCHEMA_VERSION;
  signer_kid: string | null;
  signature: string | null;
  signature_algorithm: "Ed25519" | null;
  /**
   * SHARED VOCABULARY, not a two-sided contract. The string
   * `domain-separated-canonical-json-v1` names ONE encoding (a domain prefix
   * followed by the sorted-key, undefined-filtered canonical JSON that
   * `audit/chain.ts:canonicalJson` produces) and is declared independently by
   * every signed surface that uses it, because those surfaces version
   * separately:
   *
   *   - this checkpoint record (emitted at `operational/audit-log.ts`, where
   *     the literal is re-typed for the SAME zero-import reason as the rest of
   *     this module)
   *   - the transparency checkpoint: its shape in `transparency/checkpoint.ts`,
   *     the producer that stamps it in `transparency/emitter.ts`, and the
   *     standalone mirror `transparency/verify.ts`
   *   - `InternalSigningResult` (`cognitive/tools.ts`)
   *   - `WORKLOAD_HOST_ATTESTATION_PAYLOAD_ENCODING`
   *     (`workload-lifecycle/host-attestation.ts`)
   *   - `WORKLOAD_UNDECLARED_FINDING_PAYLOAD_ENCODING`
   *     (`workload-lifecycle/undeclared-finding.ts`)
   *
   * There is deliberately no central constant: these are not mirrors of one
   * declaration and MAY legitimately diverge if one surface ever adopts a
   * different encoding. What must never happen is two surfaces claiming this
   * SAME name for two different byte-level encodings, because an external
   * verifier reads the name and reconstructs the signing bytes from it.
   * `test/structure/cross-file-contract-pins.test.ts` asserts that the set of
   * `server/src` files spelling this name as a QUOTED string is EXACTLY the
   * list above, so a surface added later without being listed here fails. Two
   * things it cannot do: detect a surface that invents a DIFFERENT name for
   * the same encoding (nothing mechanical can, which is why this is documented
   * as vocabulary), and detect a mention that is not quote-delimited.
   */
  payload_encoding: "domain-separated-canonical-json-v1";
  unsigned: boolean;
  unsigned_reason?: string;
  public_key?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

// ── Rotation anchor (F3) shape ───────────────────────────────────────

/**
 * Distinctive envelope marker of the MAC-authenticated rotation anchor
 * (`__rotation_anchor`). Byte-matches the writer in
 * `operational/audit-log.ts` `writeRotationAnchor`; a LIVE at-rest token,
 * never edit the value.
 */
export const AUDIT_ROTATION_ANCHOR_MARKER =
  "__sanctuary_audit_rotation_anchor_v1";

/**
 * The persisted rotation-anchor envelope. `mac` is UNCONDITIONALLY required:
 * the marker and the master-key MAC shipped together in the same F3 envelope
 * format, so no legitimate writer has ever produced a marker-bearing record
 * without one (there is NO legacy mac-less arm; the runtime treats a
 * marker-STRIPPED record as an untrusted no-anchor and a marker-bearing
 * record with a missing or malformed mac as INVALID).
 */
export interface AuditRotationAnchorEnvelope {
  data: { base_sequence: number; base_prev_hash: string };
  mac: string;
}

/**
 * The EXACT set of strings the legitimate anchor writer can emit as `mac`
 * (re-gate round 4): `toBase64url` of the 32-byte HMAC-SHA256. 32 bytes are
 * 256 bits; unpadded base64url carries 6 bits per character, so the canonical
 * encoding is EXACTLY ceil(256/6) = 43 characters, and the final character
 * carries the last 4 payload bits plus 2 zero pad bits. Canonical
 * (round-tripping, per the repo's base64url definition in
 * `core/encoding.ts`) therefore means: length exactly 43, base64url alphabet
 * with no padding, and a final character whose symbol index is divisible by 4
 * (its unused low 2 bits are zero), i.e. one of "AEIMQUYcgkosw048". An
 * alphabet-only check was not enough: `mac: "A"` (impossible length) or a
 * 43-char non-round-tripping string passed the shape while the runtime
 * rejected it at MAC compare, re-opening the export-unskipped hole.
 */
const ROTATION_ANCHOR_MAC_RE = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/**
 * THE rotation-anchor SHAPE predicate, shared by the runtime audit log and
 * the raw CLI exporter (re-gate round 3): the exporter's local duplicate had
 * drifted to marker + data only, with NO mac requirement, while the runtime
 * requires and MAC-verifies `mac`. That drift was NOT inclusion-safe: the
 * standalone verifier checks anchor linkage only, so a forged mac-less anchor
 * consistent with a truncated suffix was rejected by the runtime yet exported
 * unskipped and could PASS external verification. This predicate checks the
 * full persisted SHAPE, requiring `mac` to be exactly a canonical 43-char
 * base64url encoding of a 32-byte MAC (see {@link ROTATION_ANCHOR_MAC_RE}),
 * the only strings the legitimate writer can emit. It deliberately does NOT
 * verify the MAC itself: the MAC is keyed from the fortress custody (master)
 * key, which neither the exporter nor the standalone verifier holds;
 * cryptographic anchor authenticity is checkable only by the fortress
 * runtime.
 */
export function isAuditRotationAnchorEnvelope(
  value: unknown
): value is AuditRotationAnchorEnvelope & Record<string, unknown> {
  if (!isRecord(value) || value[AUDIT_ROTATION_ANCHOR_MARKER] !== true) {
    return false;
  }
  const data = value.data;
  const mac = value.mac;
  return (
    isRecord(data) &&
    typeof data.base_sequence === "number" &&
    Number.isSafeInteger(data.base_sequence) &&
    data.base_sequence > 0 &&
    typeof data.base_prev_hash === "string" &&
    typeof mac === "string" &&
    ROTATION_ANCHOR_MAC_RE.test(mac)
  );
}

/**
 * THE checkpoint shape predicate: strict, and identical for every consumer by
 * construction (this is the only definition). Requires the full persisted
 * shape including `schema_version`, the 64-hex `root_hash`,
 * `signature_algorithm`, and `payload_encoding`; a record that fails any of
 * these is not a checkpoint, whatever key it sits under.
 */
export function isAuditCheckpointRecord(
  value: unknown
): value is AuditCheckpointRecord {
  return (
    isRecord(value) &&
    value.schema_version === AUDIT_CHECKPOINT_SCHEMA_VERSION &&
    (value.checkpoint_kind === "audit-checkpoint" ||
      value.checkpoint_kind === "legacy-anchor") &&
    typeof value.checkpoint_sequence === "number" &&
    Number.isSafeInteger(value.checkpoint_sequence) &&
    typeof value.from_sequence === "number" &&
    Number.isSafeInteger(value.from_sequence) &&
    typeof value.root_hash === "string" &&
    /^[0-9a-f]{64}$/.test(value.root_hash) &&
    typeof value.previous_checkpoint_sequence === "number" &&
    Number.isSafeInteger(value.previous_checkpoint_sequence) &&
    typeof value.signed_at === "string" &&
    (typeof value.signer_kid === "string" || value.signer_kid === null) &&
    (typeof value.signature === "string" || value.signature === null) &&
    (value.signature_algorithm === "Ed25519" ||
      value.signature_algorithm === null) &&
    value.payload_encoding === "domain-separated-canonical-json-v1" &&
    typeof value.unsigned === "boolean"
  );
}
