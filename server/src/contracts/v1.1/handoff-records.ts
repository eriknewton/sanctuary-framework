/**
 * Sanctuary v1.1 — Local Agent-to-Agent Handoff Records
 *
 * Shared shapes for the internal coordination workstream (Prompt 6) and any
 * downstream consumers that need to inspect or audit a local handoff.
 *
 * Local-only invariant:
 * v1.1 handoffs cross only between agents wrapped by the same fortress.
 * Cross-operator handoffs are deferred to v1.3 public federation. This
 * contract MUST NOT be used as a transport for cross-fortress traffic.
 *
 * Signed-record invariant:
 * Every handoff record carries an Ed25519 signature over canonicalized JSON.
 * Verifiers MUST reject records whose `signature_scheme` is anything other
 * than the v1.1 supported set.
 *
 * Policy-context invariant:
 * Handoffs MUST reference a policy context that was active at handoff-create
 * time. The reference is by policy id; the full policy is fetched from the
 * compiled policy artifact store at verification time.
 */

import type {
  HandoffStatus,
  SignatureScheme,
} from "./constants.js";

/**
 * Task scope handed from sender to recipient. The shape is intentionally
 * narrow: the recipient agent receives capability and context references,
 * NOT raw query content. Raw content is fetched separately, gated by the
 * policy-context reference.
 */
export interface LocalHandoffTaskScope {
  /**
   * Coarse task category. Stable enum so the audit chain and operator hub
   * can group handoffs without parsing free text.
   */
  category:
    | "delegate_subtask"
    | "request_review"
    | "request_signature"
    | "transfer_state"
    | "request_action"
    | "other";
  /**
   * Stable task identifier scoped to the originating agent. Optional; useful
   * when the same task gets re-handed across multiple agents.
   */
  task_id?: string;
  /**
   * Capabilities the recipient is asked to exercise. The recipient's policy
   * gate is the authoritative check; this list is the sender's request.
   */
  requested_capabilities: string[];
  /**
   * Coarse priority signal. Implementation-defined ordering across categories.
   */
  priority: "low" | "normal" | "high";
}

/**
 * Reference into the placeholder vault and audit chain that lets the recipient
 * agent fetch the actual context it needs, gated by policy.
 */
export interface LocalHandoffContextReference {
  /** Bound policy-context id active at handoff create time. */
  policy_context_id: string;
  /**
   * Audit-chain entry id that captured the handoff create event. This serves
   * as the canonical pointer for replay and dispute resolution.
   */
  audit_entry_id: string;
  /**
   * Optional placeholder-vault refs. Each entry is a vault-internal id that
   * the recipient may resolve through the privacy filter, subject to policy.
   * Raw content MUST NOT be inlined here.
   */
  placeholder_refs: string[];
}

/**
 * Signed local handoff record. Persisted in the audit chain on every state
 * transition.
 */
export interface LocalHandoffRecord {
  version: "1.1";
  /** Stable handoff identifier; unique within a fortress. */
  handoff_id: string;
  /** ISO8601 timestamp the handoff was created. */
  created_at: string;
  /** Sender agent id. */
  sender_agent_id: string;
  /** Recipient agent id. Same fortress; same operator identity. */
  recipient_agent_id: string;
  /** Operator identity owning both agents. */
  identity_id: string;
  /** Task scope the sender is requesting. */
  task_scope: LocalHandoffTaskScope;
  /** Context reference into the policy + audit chain. */
  context_reference: LocalHandoffContextReference;
  /** Current lifecycle status. */
  status: HandoffStatus;
  /** ISO8601 timestamp of the most recent state transition. */
  status_changed_at: string;
  /**
   * Coarse status reason class, when status is denied or failed. NOT a free-text
   * field; consumers render generic copy keyed by this label.
   */
  status_reason_class?:
    | "policy_deny"
    | "recipient_locked_down"
    | "recipient_unavailable"
    | "context_unavailable"
    | "operator_denied"
    | "other";
  /**
   * Base64url-encoded Ed25519 signature over canonicalize(everything above
   * except `signature` and `signature_scheme`) by the sender agent's identity
   * key.
   */
  signature: string;
  /** Signature scheme. v1.1 ships only "ed25519-v1". */
  signature_scheme: SignatureScheme;
}

/**
 * Audit-chain event emitted on every handoff status transition. Consumers may
 * derive the activity feed and inbox items from these events.
 */
export interface LocalHandoffAuditEvent {
  version: "1.1";
  /** Audit-chain entry id. */
  event_id: string;
  /** ISO8601 timestamp. */
  emitted_at: string;
  /** Foreign key to the handoff record. */
  handoff_id: string;
  /** New status after the transition. */
  new_status: HandoffStatus;
  /** Reason class, when applicable. */
  reason_class?: string;
  /** Signature scheme on this audit event. */
  signature_scheme: SignatureScheme;
}

/**
 * Type guard for a handoff record in a specific status.
 */
export function isHandoffInStatus<S extends HandoffStatus>(
  record: LocalHandoffRecord,
  status: S,
): record is LocalHandoffRecord & { status: S } {
  return record.status === status;
}
