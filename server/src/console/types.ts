/**
 * Sanctuary Operator Console v1.0 -- Types
 *
 * View context shapes for the six primary views + persistent header.
 * These types are produced by the view-aggregator and consumed by the
 * API router + the static HTML/JS surface.
 *
 * WP-MVP-2: Key 4 Console + Q5 Option A.
 */

import type { ModeTier } from "../fortress/constants.js";
import type { TierProfile, TransitionHistoryEntry } from "../fortress/types.js";
import type { BadgeState } from "../attestation/types.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";
import type { PresenceState } from "../chat/constants.js";
import type { CascadeState } from "../recovery/types.js";
import type { GuardianRoster } from "../mesh/guardian/types.js";
import type { ViewName } from "./constants.js";

// -----------------------------------------------------------------------
// Persistent header context
// -----------------------------------------------------------------------

/** Persistent attestation header, always visible at top of every view. */
export interface ConsoleHeaderContext {
  /** Global (fortress-level) attestation badge from WP-MVP-9. */
  global_badge: BadgeState;
  /** Current fortress mode tier. */
  fortress_tier: ModeTier;
  /** Operator-facing tier label. */
  fortress_tier_label: string;
  /** Federation mesh peer count (0 if Tier 1 Private). */
  federation_peer_count: number;
}

// -----------------------------------------------------------------------
// Fortress mode view (WP-MVP-1)
// -----------------------------------------------------------------------

export interface FortressViewContext {
  view: "fortress";
  current_tier: ModeTier;
  current_profile: TierProfile;
  capability_bits: number;
  transitions_history: TransitionHistoryEntry[];
  last_transition_at: string | null;
  /** Legal target tiers from current position. */
  legal_targets: ModeTier[];
}

export interface FortressTransitionRequest {
  target_tier: ModeTier;
  reason: string;
}

export interface FortressTransitionResponse {
  event_id: string;
  from_tier: ModeTier;
  to_tier: ModeTier;
  capability_bits: number;
  transitioned_at: string;
}

// -----------------------------------------------------------------------
// Agent roster view (WP-MVP-4 + WP-MVP-9)
// -----------------------------------------------------------------------

export interface AgentRosterEntry {
  agent_id: string;
  fortress_id: string;
  tier: "A" | "B" | "C";
  harness_id: string;
  model_provider: string;
  model_id: string;
  policy_version: number;
  issued_at: string;
  /** Per-agent attestation badge from WP-MVP-9. */
  badge: BadgeState;
}

export interface AgentRosterViewContext {
  view: "agent_roster";
  agents: AgentRosterEntry[];
  empty_state: string;
}

// -----------------------------------------------------------------------
// Policy editor view (WP-MVP-5)
// -----------------------------------------------------------------------

export interface ChannelTemplateInfo {
  id: ChannelTemplateId;
  label: string;
  description: string;
}

export interface PolicyCompileRequest {
  agent_id: string;
  counterparty: string;
  channel_template_id: ChannelTemplateId;
  scope?: Record<string, unknown>;
}

export interface PolicyCompileResponse {
  signed_event_id: string;
  policy_version: number;
  source_english: string;
  digest: string;
}

export interface PolicyEditorViewContext {
  view: "policy_editor";
  templates: ChannelTemplateInfo[];
  /** Currently pinned policies per agent. */
  pinned_policies: Record<string, {
    agent_id: string;
    policy_version: number;
    channel_template_id: ChannelTemplateId;
    pinned_at: string;
  }>;
}

// -----------------------------------------------------------------------
// Chat view (WP-MVP-7)
// -----------------------------------------------------------------------

export interface ChatGroupInfo {
  group_id: string;
  group_type: "intra_fortress" | "cross_fortress";
  member_count: number;
  created_at: string;
}

export interface ChatMessageView {
  sender_id: string;
  content: string;
  sent_at: string;
  group_id: string;
}

export interface ChatPresenceEntry {
  member_id: string;
  state: PresenceState;
  heartbeat_at: string;
}

export interface ChatViewContext {
  view: "chat";
  groups: ChatGroupInfo[];
  presence: ChatPresenceEntry[];
  /** Forward-secret group chat label (NOT "MLS" per Scope Lock). */
  encryption_label: "AES-256-GCM per-epoch forward-secret";
}

export interface ChatSendRequest {
  group_id: string;
  content: string;
}

// -----------------------------------------------------------------------
// Recovery view (WP-MVP-8)
// -----------------------------------------------------------------------

export interface GuardianEntry {
  guardian_id: string;
  guardian_pubkey: string;
  enrolled_at: string;
}

export interface RecoveryViewContext {
  view: "recovery";
  /** Guardian roster with M-of-N threshold display. */
  roster: GuardianRoster;
  threshold_m: number;
  threshold_n: number;
  /** DMswitch status. */
  dmswitch: {
    max_offline_window_ms: number;
    estate_planning_enabled: boolean;
    last_activity_at: string | null;
    /** Operator-facing window label. */
    window_label: string;
  };
  /** Active cascade events, if any. */
  active_cascades: CascadeState[];
}

// -----------------------------------------------------------------------
// Audit log view
// -----------------------------------------------------------------------

export interface AuditEventRow {
  event_id: string;
  event_type: string;
  emitted_at: string;
  emitter_node: string;
  /** Truncated payload preview. */
  payload_preview: string;
  /** Full signed envelope JSON for expanding rows. */
  envelope_json: string;
}

export interface AuditLogViewContext {
  view: "audit_log";
  events: AuditEventRow[];
  /** Filtered event-type prefixes currently shown. */
  active_filters: string[];
}

// -----------------------------------------------------------------------
// Union type for all view contexts
// -----------------------------------------------------------------------

export type ViewContext =
  | FortressViewContext
  | AgentRosterViewContext
  | PolicyEditorViewContext
  | ChatViewContext
  | RecoveryViewContext
  | AuditLogViewContext;

// -----------------------------------------------------------------------
// API request/response shapes
// -----------------------------------------------------------------------

export interface ApiResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
  detail?: string;
}

// -----------------------------------------------------------------------
// SSE event envelope
// -----------------------------------------------------------------------

export interface ConsoleSSEEnvelope {
  kind: ViewName | "header" | "audit_event";
  payload: unknown;
  emitted_at: string;
}
