/**
 * Sanctuary v1.1 — Privacy Audit Payload Contracts
 *
 * Shared payload shapes emitted by the privacy core (Prompt 3) and consumed by
 * the remote-bound enforcement workstream (Prompt 4), the operator hub API
 * (Prompt 5), and the dashboard privacy panel (Prompt 8).
 *
 * Local-only invariant:
 * Payloads describe outbound traffic from a single fortress on a single
 * operator's machine. v1.1 ships local-only, single-operator scope.
 *
 * Enclosure-and-signing model:
 * Privacy events are NOT signed objects on their own. They are payloads
 * carried inside an enclosing audit-chain entry (`l2-operational/audit-log`
 * AuditEntry encrypted-at-rest under L1, plus `mesh/audit-batch`
 * SignedAuditBatch where federation propagation applies). The enclosing
 * audit entry carries the signature scheme; this file deliberately does not
 * declare a signature field on any payload type.
 *
 * When an enforcement path emits a privacy event:
 *   1. Build a `PrivacyAuditPayload` from this file.
 *   2. Append it as the `details` (or equivalent payload field) of an
 *      `AuditEntry` in the L2 audit log.
 *   3. The mesh-layer batch envelope (`SIGNATURE_SCHEME_V1`) signs the
 *      batch that carries this entry.
 *
 * Safe-metadata invariant:
 * Raw sensitive content MUST NEVER appear in any field of any payload defined
 * in this file. Only safe metadata is permitted: detector class, field path,
 * action, content hash, policy id, destination category, identity id,
 * placeholder labels.
 *
 * If a future workstream needs to surface a sensitive value to the operator,
 * it MUST go through the encrypted placeholder vault — not through these
 * payload shapes.
 */

import type {
  PrivacyAction,
  PrivacyDestinationCategory,
  PrivacyDetectorClass,
  PrivacyHashAlg,
} from "./constants.js";

/**
 * Common metadata header on every v1.1 privacy audit payload.
 *
 * `event_id` is the audit-chain id assigned by the enclosing AuditEntry.
 * `policy_id` is the bound privacy policy that produced the decision.
 * `identity_id` is the operator identity the policy is bound to.
 */
export interface PrivacyAuditPayloadHeader {
  /** v1.1 payload-shape version. */
  version: "1.1";
  /** Unique event id; SHOULD match the enclosing audit-chain id. */
  event_id: string;
  /** ISO8601 timestamp of the decision. */
  emitted_at: string;
  /** Policy id that produced this decision. */
  policy_id: string;
  /** Identity the policy is bound to. */
  identity_id: string;
  /** Wrapped agent the outbound traffic originates from. */
  agent_id: string;
  /** Destination category for the outbound payload. */
  destination_category: PrivacyDestinationCategory;
}

/**
 * Per-field decision recorded inside a privacy audit payload. Field-level
 * decisions bubble up into the rolled-up payload kinds below.
 *
 * Path-and-hash safety:
 * `field_path` MUST be sanitized — see `PRIVACY_FIELD_PATH_PATTERN` in
 * constants.ts. Raw object keys (which can themselves leak sensitive
 * information) MUST NOT appear on the wire. `content_hash` MUST use a keyed
 * hash algorithm (`hmac-sha256-fortress-keyed-v1` at v1.1) to defeat
 * dictionary attacks against low-entropy field values.
 */
export interface PrivacyFieldDecision {
  /**
   * Sanitized field path. Conforms to `PRIVACY_FIELD_PATH_PATTERN`:
   * positional references like "$0" / "$1.$2" or typed positional like
   * "obj:0" / "key:1.val:0". The fortress-local mapping back to the real
   * path is held in the placeholder vault. Real object keys MUST NOT
   * appear here.
   */
  field_path: string;
  /** Detector class that fired on this field. */
  detector_class: PrivacyDetectorClass;
  /** Action taken on this field. */
  action: PrivacyAction;
  /**
   * Keyed hash of the original field value. Hex-encoded.
   * Algorithm pinned via `hash_alg`; v1.1 only accepts
   * `hmac-sha256-fortress-keyed-v1`. The HMAC key is fortress-local
   * (HKDF-derived from the master key); equality of two `content_hash`
   * values within the same fortress means equal field values, but the
   * hash is opaque to any verifier outside the fortress and resists
   * dictionary attacks against low-entropy values. Plain SHA-256 is NOT
   * permitted. The original value MUST NOT appear anywhere in the payload.
   */
  content_hash: string;
  /** Hash algorithm identifier. v1.1 only accepts the keyed HMAC variant. */
  hash_alg: PrivacyHashAlg;
  /**
   * Stable placeholder label this field was substituted with on the outbound
   * payload, if applicable. Examples: "PERSON_1", "CLIENT_3", "SECRET_2".
   */
  placeholder_label?: string;
}

/**
 * Outbound payload was filtered. At least one field was redacted, hashed, or
 * substituted with a placeholder, and the call proceeded.
 */
export interface PrivacyFilteredPayload extends PrivacyAuditPayloadHeader {
  kind: "filtered";
  field_decisions: PrivacyFieldDecision[];
  /**
   * Keyed hash of the canonicalized outbound payload after filtering.
   * Same `hash_alg` constraint as `PrivacyFieldDecision.content_hash`.
   */
  outbound_payload_hash: string;
  /** Hash algorithm. v1.1 only accepts `hmac-sha256-fortress-keyed-v1`. */
  payload_hash_alg: PrivacyHashAlg;
}

/**
 * Outbound payload was allowed unchanged. No detector fired, or every fired
 * detector resolved to "allow" under the bound policy.
 */
export interface PrivacyAllowedPayload extends PrivacyAuditPayloadHeader {
  kind: "allowed";
  /**
   * Keyed hash of the canonicalized outbound payload.
   * Same `hash_alg` constraint as `PrivacyFieldDecision.content_hash`.
   */
  outbound_payload_hash: string;
  /** Hash algorithm. v1.1 only accepts `hmac-sha256-fortress-keyed-v1`. */
  payload_hash_alg: PrivacyHashAlg;
}

/**
 * Outbound payload was denied. Either a "deny" rule fired on a field, or the
 * fail-closed default applied because the policy or vault was unavailable.
 *
 * The `denial_reason_class` is a machine-friendly label, NOT a free-text
 * explanation. Operator-facing UIs may render a generic message keyed by this
 * label; raw policy-rule details MUST NOT be revealed.
 */
export interface PrivacyDeniedPayload extends PrivacyAuditPayloadHeader {
  kind: "denied";
  /**
   * Coarse denial reason class. Permitted values:
   * - "policy_deny_rule" — at least one field had a deny rule
   * - "fail_closed_no_policy" — fail-closed because policy missing
   * - "fail_closed_filter_error" — fail-closed because filter raised
   * - "fail_closed_vault_error" — fail-closed because vault unavailable
   * - "operator_override_denied" — explicit operator override path failed
   */
  denial_reason_class:
    | "policy_deny_rule"
    | "fail_closed_no_policy"
    | "fail_closed_filter_error"
    | "fail_closed_vault_error"
    | "operator_override_denied";
}

/**
 * Privacy filter raised an unrecoverable error and outbound traffic failed
 * closed. Distinct from PrivacyDeniedPayload because the operator may want to
 * surface error events as alerts rather than as policy decisions.
 */
export interface PrivacyErrorPayload extends PrivacyAuditPayloadHeader {
  kind: "error";
  /** Stable error code. Implementation-specific catalog. No raw stack traces. */
  error_code: string;
}

/**
 * Inbound provider response was rehydrated using the placeholder vault. Only
 * fires when the bound policy permits rehydration for the destination category.
 */
export interface PrivacyRehydratedPayload extends PrivacyAuditPayloadHeader {
  kind: "rehydrated";
  /**
   * Number of placeholders successfully rehydrated. The placeholders themselves
   * are NOT logged.
   */
  rehydrated_count: number;
  /** Number of placeholders that could not be rehydrated (e.g., vault entry expired). */
  unresolvable_count: number;
  /**
   * Keyed hash of the canonicalized rehydrated response.
   * Same `hash_alg` constraint as `PrivacyFieldDecision.content_hash`.
   */
  response_hash: string;
  /** Hash algorithm. v1.1 only accepts `hmac-sha256-fortress-keyed-v1`. */
  response_hash_alg: PrivacyHashAlg;
}

/**
 * Discriminated union of every v1.1 privacy audit payload. The hub API and
 * dashboard privacy panel switch on `kind`. Integrity of these payloads
 * derives from the enclosing audit entry (encrypted-at-rest, plus signed at
 * the mesh-batch layer where applicable). No payload in this file carries a
 * self-signature.
 */
export type PrivacyAuditPayload =
  | PrivacyFilteredPayload
  | PrivacyAllowedPayload
  | PrivacyDeniedPayload
  | PrivacyErrorPayload
  | PrivacyRehydratedPayload;

/**
 * Type guard for a privacy audit payload of a specific kind.
 */
export function isPrivacyPayloadOfKind<K extends PrivacyAuditPayload["kind"]>(
  payload: PrivacyAuditPayload,
  kind: K,
): payload is Extract<PrivacyAuditPayload, { kind: K }> {
  return payload.kind === kind;
}
