/**
 * Sanctuary Attestation UX v1.0 -- Types
 *
 * BadgeState, AttestationEvent, LayerContext, FailureModeEntry,
 * CustodyProvenanceStub, and supporting shapes.
 *
 * Design brief: Review/Sanctuary/Attestation_UX_Design_Brief_2026-04-21.md
 */

import type {
  AttestationEventType,
  BadgeStateColor,
  CustodyProvenanceState,
  FailureModeCode,
  LayerType,
  SeverityRank,
  SignatureScheme,
} from "./constants.js";

// -----------------------------------------------------------------------
// Badge state (returned by all three layer APIs)
// -----------------------------------------------------------------------

/**
 * Badge state object. Returned by getGlobalBadge(), getAgentBadge(agent_id),
 * and getActionBadge(action_id).
 *
 * Design brief section 3: "color + shape + position together communicate
 * state before a label is read."
 */
export interface BadgeState {
  /** Current color/state. */
  state: BadgeStateColor;
  /** Operator-facing label (fortress vocabulary). */
  label: string;
  /** ISO8601 UTC timestamp of last state update. */
  last_updated_at: string;
  /** Event IDs that drove this badge to its current state. */
  source_event_ids: string[];
  /**
   * Operator-facing explanation key. Maps to a plain-English explanation
   * that appears on click-through per design brief section 2, rule 3.
   */
  explanation_key: string;
  /** Layer this badge belongs to. */
  layer: LayerType;
  /** Scoping identifier: fortress_id for global, agent_id for per-agent, action_id for per-action. */
  scope_id: string;
}

// -----------------------------------------------------------------------
// Attestation event (drives badge state changes)
// -----------------------------------------------------------------------

/**
 * Attestation event. Every badge state-change is derived from one of these.
 * Bound to the federation v0.1 signed-event envelope per acceptance criterion 6.
 */
export interface AttestationEvent {
  /** Unique event ID. */
  event_id: string;
  /** Attestation event type (attestation_* prefix). */
  event_type: AttestationEventType;
  /** Signature scheme (ed25519-v1 at v1.0). */
  signature_scheme: SignatureScheme;
  /** Layer this event targets. */
  target_layer: LayerType;
  /** Scoping ID: fortress_id, agent_id, or action_id. */
  scope_id: string;
  /** New badge state resulting from this event. */
  resulting_state: BadgeStateColor;
  /** Failure mode code, if any. null for recovery/green events. */
  failure_mode?: FailureModeCode;
  /** ISO8601 UTC timestamp. */
  emitted_at: string;
  /** Operator-facing explanation (plain English, no em-dashes). */
  explanation: string;
  /** Optional metadata for downstream consumers. */
  metadata?: Record<string, unknown>;
}

// -----------------------------------------------------------------------
// Layer context (input for badge derivation)
// -----------------------------------------------------------------------

/** Global (fortress-level) context for deriving Layer 1 badge. */
export interface GlobalLayerContext {
  fortress_id: string;
  /** Per-node states: node_id -> state. */
  node_states: Record<string, BadgeStateColor>;
  /** Audit chain verification state. */
  audit_chain_state: BadgeStateColor;
  /** Policy sync state across nodes. */
  policy_sync_state: BadgeStateColor;
  /** Guardian presence state. */
  guardian_state: BadgeStateColor;
  /** Per-agent badge states: agent_id -> state. */
  agent_badge_states: Record<string, BadgeStateColor>;
}

/** Per-agent context for deriving Layer 2 badge. */
export interface AgentLayerContext {
  agent_id: string;
  fortress_id: string;
  /** Node this agent is bound to. */
  bound_node_id: string;
  /** Bound node's attestation state. */
  node_attestation_state: BadgeStateColor;
  /** Whether identity HKDF chain is valid. */
  identity_valid: boolean;
  /** Whether policy is pinned and current. */
  policy_pinned: boolean;
  /** Policy version pinned at launch. */
  policy_version: number;
  /** Per-annex attestation states: annex_id -> state. */
  annex_states: Record<string, BadgeStateColor>;
  /** Whether egress posture is enforcing. */
  egress_enforcing: boolean;
}

/** Per-action context for deriving Layer 3 badge. */
export interface ActionLayerContext {
  action_id: string;
  agent_id: string;
  fortress_id: string;
  /** Badge state at time-of-action (immutable once recorded). */
  time_of_action_state: BadgeStateColor;
  /** Current verifier state (may differ from time-of-action). */
  current_verifier_state: BadgeStateColor;
  /** Policy version at time-of-action. */
  policy_version: number;
  /** Provider reached for this action, if any. */
  provider?: string;
  /** Token counts, if applicable. */
  tokens?: { input: number; output: number };
  /** ISO8601 UTC timestamp of the action. */
  action_at: string;
}

// -----------------------------------------------------------------------
// Failure-mode catalog entry (9-row catalog per design brief section 6)
// -----------------------------------------------------------------------

/**
 * A single row in the 9-row failure-mode catalog.
 *
 * Design brief section 6: "Every cell in this table is a non-modal experience."
 * Degrade-not-destroy: no row maps to "halt" or "throw".
 */
export interface FailureModeEntry {
  /** Unique failure-mode code. */
  code: FailureModeCode;
  /** Human-readable name (fortress vocabulary). */
  name: string;
  /** Severity: critical / warning / informational. */
  severity: SeverityRank;
  /** Detection rule (what triggers this failure mode). */
  detection_rule: string;
  /** Badge state result when this failure mode fires. */
  badge_result: BadgeStateColor;
  /**
   * Degrade-or-halt decision. Always "degrade" at v1.0.
   * If any row were "halt", it would be misclassified per spawn prompt hard rule.
   */
  degrade_decision: "degrade";
  /** Operator-visible explanation key. */
  explanation_key: string;
  /** Affected layers. */
  affected_layers: LayerType[];
  /** Suggested remediation actions (fortress vocabulary). */
  remediation_actions: string[];
}

// -----------------------------------------------------------------------
// Custody provenance stub (Layer 4, v1.x Key 17)
// -----------------------------------------------------------------------

/**
 * Custody provenance stub. v1.0 returns this shape with `v1_0_stub: true`.
 * The adapter hook is a no-op.
 *
 * v1.x migration path: when Key 17 sovereign-signer adapter ships, the
 * `v1_0_stub` field is removed, `state` is populated from real custody
 * chain analysis, and `adapter_result` carries the x402/ERC-8004/AP2
 * signing verification result.
 */
export interface CustodyProvenanceStub {
  /** Transaction identifier. */
  tx_id: string;
  /** v1.0 stub flag. */
  v1_0_stub: true;
  /** Stub state (always unknown_custody at v1.0). */
  state: CustodyProvenanceState;
  /** Signature scheme. */
  signature_scheme: SignatureScheme;
  /** ISO8601 UTC. */
  checked_at: string;
  /**
   * v1.x: will contain x402 request payload hash, ERC-8004 registry pointer,
   * AP2 mandate hash, signing key fingerprint, and custody chain.
   * v1.0: empty object.
   */
  adapter_result: Record<string, never>;
  /**
   * Reserved references[] slot for receipt embedding.
   * v1.x receipts are forward-compatible with no schema migration.
   */
  receipt_reference_slot: "custody_provenance";
}

// -----------------------------------------------------------------------
// Badge state store (internal, for the service layer)
// -----------------------------------------------------------------------

/** Stored badge state with event history. */
export interface StoredBadgeState {
  badge: BadgeState;
  /** Recent events that influenced this badge (bounded to last 50). */
  recent_events: AttestationEvent[];
  /** Cached-badge flag for offline/degrade mode. */
  is_cached: boolean;
  /** ISO8601 UTC of when cache was set (null if live). */
  cached_at: string | null;
}
