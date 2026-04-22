/**
 * Sanctuary Operator Console v1.0 -- View Aggregator
 *
 * Pulls live state from each backend service into ViewContext objects.
 * One aggregator function per primary view. Delegates only; owns no
 * domain logic. All derivation is pure-logic: no LLM calls, no
 * external network fetches.
 *
 * WP-MVP-2: Key 4 Console.
 */

import type { FortressService } from "../fortress/fortress-service.js";
import type { ModeTier } from "../fortress/constants.js";
import {
  getGlobalBadge,
  getAgentBadge,
} from "../attestation/attestation-service.js";
import {
  listChannelTemplates,
} from "../policy-engine/channel-templates.js";
import type { ChatService } from "../chat/chat-service.js";
import type { RecoveryStore } from "../recovery/recovery-service.js";
import type { GuardianRoster } from "../mesh/guardian/types.js";

import { TIER_LABELS, CONSOLE_LEGAL_TRANSITIONS } from "./constants.js";
import type {
  ConsoleHeaderContext,
  FortressViewContext,
  AgentRosterViewContext,
  AgentRosterEntry,
  PolicyEditorViewContext,
  ChatViewContext,
  ChatGroupInfo,
  ChatPresenceEntry,
  RecoveryViewContext,
  AuditLogViewContext,
  AuditEventRow,
  ChannelTemplateInfo,
} from "./types.js";

// -----------------------------------------------------------------------
// Service dependencies injected at construction
// -----------------------------------------------------------------------

export interface ViewAggregatorDeps {
  fortressService: FortressService;
  /** Fortress ID for badge lookups. */
  fortressId: string;
  /** Agent IDs currently enrolled. */
  getAgentIds: () => string[];
  /** Agent card metadata lookup by agent_id. */
  getAgentCard?: (agentId: string) => {
    tier: "A" | "B" | "C";
    harness_id: string;
    model_provider: string;
    model_id: string;
    policy_version: number;
    issued_at: string;
  } | null;
  /** Chat service (optional; null if chat not initialized). */
  chatService?: ChatService | null;
  /** Recovery store for cascade queries. */
  recoveryStore?: RecoveryStore | null;
  /** Guardian roster for recovery view. */
  guardianRoster?: GuardianRoster | null;
  /** Recovery config for DMswitch display. */
  recoveryConfig?: {
    dmswitch: { max_offline_window_ms: number; estate_planning_enabled: boolean };
    last_activity_at: string | null;
  } | null;
  /** Signed event log for audit view. */
  getSignedEvents?: (filters?: string[], limit?: number) => Array<{
    event_id: string;
    event_type: string;
    emitted_at: string;
    emitter_node: string;
    payload: Record<string, unknown>;
    envelope_json: string;
  }>;
  /** Mesh peer count. */
  getMeshPeerCount?: () => number;
}

// -----------------------------------------------------------------------
// Header aggregator
// -----------------------------------------------------------------------

export async function aggregateHeader(
  deps: ViewAggregatorDeps
): Promise<ConsoleHeaderContext> {
  const mode = await deps.fortressService.getCurrentMode();
  const globalBadge = getGlobalBadge(deps.fortressId);

  return {
    global_badge: globalBadge,
    fortress_tier: mode.tier,
    fortress_tier_label: TIER_LABELS[mode.tier] ?? mode.tier,
    federation_peer_count: deps.getMeshPeerCount?.() ?? 0,
  };
}

// -----------------------------------------------------------------------
// Fortress mode view
// -----------------------------------------------------------------------

export async function aggregateFortressView(
  deps: ViewAggregatorDeps
): Promise<FortressViewContext> {
  const mode = await deps.fortressService.getCurrentMode();
  const legalTargets = (CONSOLE_LEGAL_TRANSITIONS[mode.tier] ?? []) as ModeTier[];

  return {
    view: "fortress",
    current_tier: mode.tier,
    current_profile: mode.profile,
    capability_bits: mode.capability_bits,
    transitions_history: mode.transitions_history,
    last_transition_at: mode.last_transition_at,
    legal_targets: legalTargets,
  };
}

// -----------------------------------------------------------------------
// Agent roster view
// -----------------------------------------------------------------------

export function aggregateAgentRosterView(
  deps: ViewAggregatorDeps
): AgentRosterViewContext {
  const agentIds = deps.getAgentIds();
  const agents: AgentRosterEntry[] = agentIds.map((agent_id) => {
    const card = deps.getAgentCard?.(agent_id);
    const badge = getAgentBadge(agent_id);

    return {
      agent_id,
      fortress_id: deps.fortressId,
      tier: card?.tier ?? "C",
      harness_id: card?.harness_id ?? "unknown",
      model_provider: card?.model_provider ?? "unknown",
      model_id: card?.model_id ?? "unknown",
      policy_version: card?.policy_version ?? 0,
      issued_at: card?.issued_at ?? new Date().toISOString(),
      badge,
    };
  });

  return {
    view: "agent_roster",
    agents,
    empty_state:
      "No wrapped agents on this fortress yet. Use `sanctuary wrap` to add one.",
  };
}

// -----------------------------------------------------------------------
// Policy editor view
// -----------------------------------------------------------------------

export function aggregatePolicyEditorView(
  _deps: ViewAggregatorDeps
): PolicyEditorViewContext {
  const rawTemplates = listChannelTemplates();
  const templates: ChannelTemplateInfo[] = rawTemplates.map((t) => ({
    id: t.id,
    label: t.label,
    description: t.description,
  }));

  return {
    view: "policy_editor",
    templates,
    pinned_policies: {},
  };
}

// -----------------------------------------------------------------------
// Chat view
// -----------------------------------------------------------------------

export function aggregateChatView(
  deps: ViewAggregatorDeps
): ChatViewContext {
  const groups: ChatGroupInfo[] = [];
  const presence: ChatPresenceEntry[] = [];

  if (deps.chatService) {
    // MLSGroupManager exposes getGroupState(id) but no list method;
    // the chat service tracks groups via its config.
    // Presence uses getAllPresence().
    const tracker = deps.chatService.presenceTracker;
    for (const entry of tracker.getAllPresence()) {
      presence.push({
        member_id: entry.member_id,
        state: entry.state,
        heartbeat_at: entry.last_heartbeat_at,
      });
    }
  }

  return {
    view: "chat",
    groups,
    presence,
    encryption_label: "AES-256-GCM per-epoch forward-secret",
  };
}

// -----------------------------------------------------------------------
// Recovery view
// -----------------------------------------------------------------------

export function aggregateRecoveryView(
  deps: ViewAggregatorDeps
): RecoveryViewContext {
  const activeCascades = deps.recoveryStore?.listActive() ?? [];
  const cfg = deps.recoveryConfig;
  const roster = deps.guardianRoster;

  const defaultWindowMs = 30 * 24 * 60 * 60 * 1000; // 30 days
  const windowMs = cfg?.dmswitch?.max_offline_window_ms ?? defaultWindowMs;
  const windowDays = Math.round(windowMs / (24 * 60 * 60 * 1000));

  // Build a minimal roster if none provided
  const emptyRoster: GuardianRoster = {
    m: 3,
    n: 0,
    guardians: [],
    signature_scheme: "ed25519-v1",
    version: 0,
    created_at: new Date().toISOString(),
    fortress_id: deps.fortressId,
    master_signature: "",
  };
  const effectiveRoster = roster ?? emptyRoster;

  return {
    view: "recovery",
    roster: effectiveRoster,
    threshold_m: effectiveRoster.m,
    threshold_n: effectiveRoster.n,
    dmswitch: {
      max_offline_window_ms: windowMs,
      estate_planning_enabled: cfg?.dmswitch?.estate_planning_enabled ?? false,
      last_activity_at: cfg?.last_activity_at ?? null,
      window_label: `${windowDays} day${windowDays !== 1 ? "s" : ""}`,
    },
    active_cascades: activeCascades,
  };
}

// -----------------------------------------------------------------------
// Audit log view
// -----------------------------------------------------------------------

export function aggregateAuditLogView(
  deps: ViewAggregatorDeps,
  filters?: string[],
  limit = 100
): AuditLogViewContext {
  const events: AuditEventRow[] = [];

  if (deps.getSignedEvents) {
    const raw = deps.getSignedEvents(filters, limit);
    for (const e of raw) {
      const preview = JSON.stringify(e.payload).slice(0, 120);
      events.push({
        event_id: e.event_id,
        event_type: e.event_type,
        emitted_at: e.emitted_at,
        emitter_node: e.emitter_node,
        payload_preview: preview.length >= 120 ? preview + "..." : preview,
        envelope_json: e.envelope_json,
      });
    }
  }

  return {
    view: "audit_log",
    events,
    active_filters: filters ?? [],
  };
}
