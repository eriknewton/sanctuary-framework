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
 * Two-layer signing model (load-bearing — read carefully):
 *
 * Layer 1 — Handoff request itself (`LocalHandoffRecord`):
 * The sender agent signs the canonical-JSON of the handoff record at create
 * time. This signature is for non-repudiation of the request: who asked,
 * who they asked, what they asked for, what policy context they invoked.
 * The signature lives on the record itself (`signature` + `signature_scheme`
 * fields). The scheme is positioned INSIDE the signed bytes so it cannot be
 * substituted independently of the signature. Verifiers MUST reject records
 * whose `signature_scheme` is anything other than the v1.1 supported set.
 *
 * Layer 2 — Lifecycle transitions (`LocalHandoffAuditPayload`):
 * Each lifecycle transition (created / accepted / denied / completed /
 * failed) is a payload signed by the ACTOR (sender, recipient, or policy
 * gate) with their identity key, then carried inside an enclosing audit-
 * chain entry. The actor signature attests authorship; the audit-chain
 * entry provides ordering, tamper-evident chaining, and encrypted-at-rest
 * integrity. Both layers are required: the audit-chain signature alone
 * cannot distinguish "the fortress recorded that the recipient said yes"
 * from "the fortress recorded a synthesized acceptance."
 *
 * Per-transition actor rule (the signer for each transition):
 *   - created   → sender agent
 *   - accepted  → recipient agent
 *   - denied    → recipient agent OR policy_gate (operator-bound)
 *   - completed → recipient agent
 *   - failed    → whichever side surfaced the failure (sender if recipient
 *                 unreachable; recipient otherwise)
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
 * Signed local handoff record (Layer 1 of the two-layer signing model).
 *
 * The sender agent signs the canonical-JSON of every field in this record
 * EXCEPT `signature` and `signature_scheme`. Persistence happens through the
 * audit chain; the record's self-signature is for non-repudiation of the
 * request itself.
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
   * Coarse status reason class, when status is denied or failed. NOT a
   * free-text field; consumers render generic copy keyed by this label.
   */
  status_reason_class?:
    | "policy_deny"
    | "recipient_locked_down"
    | "recipient_unavailable"
    | "context_unavailable"
    | "operator_denied"
    | "other";
  /**
   * Layer 1 signature scheme. v1.1 ships only "ed25519-v1". Position above
   * `signature` so the scheme is itself covered by the signed bytes — that
   * is, the canonical-JSON input to the signature includes
   * `signature_scheme` but excludes `signature`. This makes the crypto-
   * agility hinge non-substitutable: a verifier cannot accept a record
   * whose scheme has been swapped without producing a fresh signature.
   */
  signature_scheme: SignatureScheme;
  /**
   * Base64url-encoded Ed25519 signature over canonicalize(every field
   * above, including `signature_scheme`, but excluding `signature` itself)
   * by the sender agent's identity key. Layer 1 non-repudiation on the
   * handoff request.
   */
  signature: string;
}

/**
 * Lifecycle-transition payload (Layer 2 of the two-layer signing model).
 *
 * Emitted on every handoff status transition. The actor (sender, recipient,
 * or policy gate) signs the payload with their identity key — this Layer 2
 * signature is the load-bearing attestation of "who caused this
 * transition." The fortress-master audit-chain entry that carries the
 * payload provides the integrity wrapper (timestamp ordering, sequence
 * binding, encrypted-at-rest), but the actor signature is what attests
 * authorship.
 *
 * Without the per-transition actor signature, recipient acceptance and
 * operator denial would only be attested by the fortress-master signature,
 * which cannot distinguish "the fortress recorded that the recipient said
 * yes" from "the fortress recorded a synthesized acceptance." The actor
 * signature closes that gap.
 *
 * The payload carries `previous_status` (anti-replay), the full identity
 * triple (sender / recipient / operator) so an isolated payload is self-
 * descriptive, the actor's signature, and the signature scheme inside the
 * signed bytes (so the scheme cannot be substituted independently).
 */
export interface LocalHandoffAuditPayload {
  version: "1.1";
  /** Audit-chain entry id (foreign key into the L2 audit log). */
  event_id: string;
  /** ISO8601 timestamp. */
  emitted_at: string;
  /** Foreign key to the handoff record. */
  handoff_id: string;
  /** Previous status — anti-replay guard; lets verifiers reconstruct the lifecycle. */
  previous_status: HandoffStatus;
  /** New status after the transition. */
  new_status: HandoffStatus;
  /** Sender agent id, copied from the handoff record so this payload is self-descriptive. */
  sender_agent_id: string;
  /** Recipient agent id, copied from the handoff record. */
  recipient_agent_id: string;
  /** Operator identity owning both agents. */
  identity_id: string;
  /**
   * Identifier of the actor who caused the transition. Interpretation
   * depends on `actor_role`:
   *  - "sender" / "recipient" → an agent_id (matches sender_agent_id or recipient_agent_id)
   *  - "policy_gate"          → an operator identity_id (matches identity_id)
   */
  actor_id: string;
  /**
   * Role of the actor who caused the transition. Per-transition signer rule:
   *   created   → sender
   *   accepted  → recipient
   *   denied    → recipient OR policy_gate (operator-bound denial)
   *   completed → recipient
   *   failed    → whichever side surfaced the failure
   */
  actor_role: "sender" | "recipient" | "policy_gate";
  /** Reason class, when applicable. Same shape as `LocalHandoffRecord.status_reason_class`. */
  reason_class?:
    | "policy_deny"
    | "recipient_locked_down"
    | "recipient_unavailable"
    | "context_unavailable"
    | "operator_denied"
    | "other";
  /**
   * Layer 2 signature scheme. v1.1 ships only "ed25519-v1". Embedded inside
   * the signed bytes (see `actor_signature` for the canonical-JSON input
   * specification) so the scheme cannot be substituted independently of the
   * signature.
   */
  signature_scheme: SignatureScheme;
  /**
   * Base64url-encoded Ed25519 signature over canonicalize(every field above,
   * including `signature_scheme`, but excluding `actor_signature` itself)
   * by the actor's identity key. The audit-chain entry that wraps this
   * payload provides ordering and tamper-evident chaining; this signature
   * provides authorship attestation.
   */
  actor_signature: string;
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
