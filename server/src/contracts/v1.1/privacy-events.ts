/**
 * Sanctuary v1.1 — Privacy Event Contracts
 *
 * Shared event shapes emitted by the privacy core (Prompt 3) and consumed by
 * the remote-bound enforcement workstream (Prompt 4), the operator hub API
 * (Prompt 5), and the dashboard privacy panel (Prompt 8).
 *
 * Local-only invariant:
 * Events describe outbound traffic from a single fortress on a single
 * operator's machine. v1.1 ships local-only, single-operator scope.
 *
 * Safe-metadata invariant:
 * Raw sensitive content MUST NEVER appear in any field of any event defined
 * in this file. Only safe metadata is permitted: detector class, field path,
 * action, content hash, policy id, destination category, identity id,
 * placeholder labels.
 *
 * If a future workstream needs to surface a sensitive value to the operator,
 * it MUST go through the encrypted placeholder vault — not through these
 * event shapes.
 */

import type {
  PrivacyAction,
  PrivacyDestinationCategory,
  PrivacyDetectorClass,
  SignatureScheme,
} from "./constants.js";

/**
 * Common metadata header on every v1.1 privacy event.
 *
 * `event_id` is the audit-chain id. `policy_id` is the bound privacy policy
 * that produced the decision. `identity_id` is the operator identity the
 * policy is bound to.
 */
export interface PrivacyEventHeader {
  /** v1.1 event-shape version. */
  version: "1.1";
  /** Unique event id; SHOULD match the audit-chain id. */
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
 * Per-field decision recorded inside a privacy event. Field-level events bubble
 * up into the rolled-up event types below.
 */
export interface PrivacyFieldDecision {
  /** Dot-path or JSON-pointer to the field within the outbound payload. */
  field_path: string;
  /** Detector class that fired on this field. */
  detector_class: PrivacyDetectorClass;
  /** Action taken on this field. */
  action: PrivacyAction;
  /**
   * SHA-256 hash of the original field value. Hex-encoded. The original value
   * itself MUST NOT appear anywhere in the event.
   */
  content_hash: string;
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
export interface PrivacyFilteredEvent extends PrivacyEventHeader {
  kind: "filtered";
  field_decisions: PrivacyFieldDecision[];
  /** SHA-256 hash of the canonicalized outbound payload after filtering. */
  outbound_payload_hash: string;
  /** Filter signature scheme. */
  signature_scheme: SignatureScheme;
}

/**
 * Outbound payload was allowed unchanged. No detector fired, or every fired
 * detector resolved to "allow" under the bound policy.
 */
export interface PrivacyAllowedEvent extends PrivacyEventHeader {
  kind: "allowed";
  /** SHA-256 hash of the canonicalized outbound payload. */
  outbound_payload_hash: string;
  signature_scheme: SignatureScheme;
}

/**
 * Outbound payload was denied. Either a "deny" rule fired on a field, or the
 * fail-closed default applied because the policy or vault was unavailable.
 *
 * The `denial_reason_class` is a machine-friendly label, NOT a free-text
 * explanation. Operator-facing UIs may render a generic message keyed by this
 * label; raw policy-rule details MUST NOT be revealed.
 */
export interface PrivacyDeniedEvent extends PrivacyEventHeader {
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
  signature_scheme: SignatureScheme;
}

/**
 * Privacy filter raised an unrecoverable error and outbound traffic failed
 * closed. Distinct from PrivacyDeniedEvent because the operator may want to
 * surface error events as alerts rather than as policy decisions.
 */
export interface PrivacyErrorEvent extends PrivacyEventHeader {
  kind: "error";
  /** Stable error code. Implementation-specific catalog. No raw stack traces. */
  error_code: string;
  signature_scheme: SignatureScheme;
}

/**
 * Inbound provider response was rehydrated using the placeholder vault. Only
 * fires when the bound policy permits rehydration for the destination category.
 */
export interface PrivacyRehydratedEvent extends PrivacyEventHeader {
  kind: "rehydrated";
  /**
   * Number of placeholders successfully rehydrated. The placeholders themselves
   * are NOT logged.
   */
  rehydrated_count: number;
  /** Number of placeholders that could not be rehydrated (e.g., vault entry expired). */
  unresolvable_count: number;
  /** SHA-256 hash of the canonicalized rehydrated response. */
  response_hash: string;
  signature_scheme: SignatureScheme;
}

/**
 * Discriminated union of every v1.1 privacy event. The hub API and dashboard
 * privacy panel switch on `kind`.
 */
export type PrivacyEvent =
  | PrivacyFilteredEvent
  | PrivacyAllowedEvent
  | PrivacyDeniedEvent
  | PrivacyErrorEvent
  | PrivacyRehydratedEvent;

/**
 * Type guard for a privacy event with a specific kind.
 */
export function isPrivacyEventOfKind<K extends PrivacyEvent["kind"]>(
  event: PrivacyEvent,
  kind: K,
): event is Extract<PrivacyEvent, { kind: K }> {
  return event.kind === kind;
}
