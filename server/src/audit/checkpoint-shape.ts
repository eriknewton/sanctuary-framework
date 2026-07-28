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
  payload_encoding: "domain-separated-canonical-json-v1";
  unsigned: boolean;
  unsigned_reason?: string;
  public_key?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
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
