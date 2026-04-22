/**
 * Sanctuary Operator Console v1.0 — API types.
 *
 * These shapes are produced by `MeshConsoleClient` and consumed by the
 * HTTP surface + rendered HTML. They are NOT wire-format types; wire-
 * format is defined in `server/src/mesh/types.ts` and MUST flow through
 * that module unmodified.
 */

import type { NodeMode } from "../mesh/constants.js";
import type { MeshHealthSnapshot } from "../mesh/failure-modes/types.js";
import type { NodeIdentityCertificate } from "../mesh/types.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";

/**
 * Attestation-state classes surfaced on the three-layer badge (global / per-
 * agent / per-action). The fourth per-transaction custody-provenance class
 * is a v1.x stub (`custody-provenance-stub`) per spawn prompt scope item 4.
 */
export type AttestationState =
  | "verified"
  | "pending"
  | "degraded"
  | "failed"
  | "unknown";

export interface AttestationBadgeView {
  layer: "global" | "per-agent" | "per-action" | "custody-provenance-stub";
  state: AttestationState;
  /** Plain-English label used in the rendered badge. */
  label: string;
  /** Deterministic per-layer+state class name used for CSS + testability. */
  class_name: string;
  /** Short tooltip / detail text; never an agent-visible error. */
  tooltip: string;
}

/** Fortress overview surface. */
export interface FortressOverviewView {
  fortress_id: string;
  master_created_at: string;
  canonical_audit_node: string;
  canonical_audit_loss: boolean;
  guardian_roster: Array<{ guardian_id: string; role: "guardian" }>;
  last_rotation_at: string | null;
  nodes: Array<{
    node_id: string;
    mode: NodeMode;
    presence: string;
    last_heartbeat_at: number | null;
    badge: AttestationBadgeView;
  }>;
  global_badge: AttestationBadgeView;
}

/** A single wrapped agent as rendered on the Agents panel. */
export interface AgentPanelEntryView {
  agent_id: string;
  last_policy_version: number;
  last_usage_event_id: string | null;
  last_usage_event_at: string | null;
  per_agent_badge: AttestationBadgeView;
  last_action_badge: AttestationBadgeView;
}

export interface AgentsPanelView {
  agents: AgentPanelEntryView[];
  empty_state: string;
}

/** Policy editor: read-side view of the pinned policy for an agent. */
export interface PinnedPolicyView {
  agent_id: string;
  policy_version: number;
  channel_template_id: ChannelTemplateId;
  counterparty: string;
  source_english: string;
  pinned_at: string;
  signed_event_id: string;
}

/** Policy editor: what the operator composes before signing. */
export interface PolicyComposeInput {
  agent_id: string;
  counterparty: string;
  channel_template_id: ChannelTemplateId;
  scope?: Record<string, string>;
}

export interface PolicyComposeResult {
  signed_event_id: string;
  policy_version: number;
  source_english: string;
}

/** Join ceremony — a pending request awaiting operator approval. */
export interface PendingJoinView {
  request_id: string;
  bootstrap_token_nonce: string;
  candidate_node_pubkey: string;
  candidate_node_mode: NodeMode;
  candidate_node_id: string;
  requested_at: string;
  attestation_ok: boolean;
  issuer_principal: string;
}

/** Revoke ceremony — current candidate targets. */
export interface RevokeTargetView {
  node_id: string;
  mode: NodeMode;
  presence: string;
  reason_hint: string;
}

/** Alert inbox row — derived from a FailureModeAlert with decision options. */
export interface AlertInboxRow {
  alert_id: string;
  mode: string;
  target_node: string;
  detected_at: number;
  message: string;
  decision_options: Array<{ id: string; label: string }>;
  state: "open" | "resolved";
}

export interface AlertInboxView {
  rows: AlertInboxRow[];
  health_snapshot: MeshHealthSnapshot | null;
}

/** Recovery-entry stub — routing + auth gate lives here; ceremony is WP-MVP-8. */
export interface RecoveryEntryView {
  status: "stub_v1_0";
  message: string;
  eta: "WP-MVP-8";
}

/** SSE event envelopes pushed to the console UI. */
export type ConsoleSSEEvent =
  | { kind: "fortress"; payload: FortressOverviewView }
  | { kind: "agents"; payload: AgentsPanelView }
  | { kind: "alert"; payload: AlertInboxRow }
  | { kind: "health"; payload: MeshHealthSnapshot }
  | { kind: "join-pending"; payload: PendingJoinView }
  | { kind: "join-resolved"; payload: { request_id: string; approved: boolean } }
  | { kind: "policy-pinned"; payload: PinnedPolicyView };

/** Surfaced by `MeshConsoleClient` integration tests + the HTTP surface. */
export interface MeshConsoleClientState {
  fortress: FortressOverviewView;
  agents: AgentsPanelView;
  alerts: AlertInboxView;
  pending_joins: PendingJoinView[];
  pinned_policies: Record<string, PinnedPolicyView>;
}

/** Inbound approval decision from the operator UI. */
export interface AlertAckInput {
  alert_id: string;
  decision: string;
  note?: string;
}

/** Inbound join approval/denial from the operator UI. */
export interface JoinDecisionInput {
  request_id: string;
  approved: boolean;
  denial_reason?: string;
}

/** Inbound revoke from the operator UI. Requires guardian-quorum signatures. */
export interface RevokeInput {
  node_id: string;
  reason: string;
  effective_at: string;
  quorum_signatures: Array<{ guardian_pubkey: string; signature: string }>;
}

/** Re-export for downstream consumers. */
export type { NodeIdentityCertificate };
