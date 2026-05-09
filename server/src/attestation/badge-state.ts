/**
 * Sanctuary Attestation UX v1.0 -- Badge State Derivation
 *
 * Global / per-agent / per-action state stores + derivation from signed events.
 * Pure logic only; no LLM calls, no network fetches.
 *
 * Design brief: Review/Sanctuary/Attestation_UX_Design_Brief_2026-04-21.md section 3
 */

import {
  BADGE_STATE_LABELS,
  type BadgeStateColor,
  type LayerType,
} from "./constants.js";
import { BadgeScopeNotFoundError } from "./errors.js";
import type {
  ActionLayerContext,
  AgentLayerContext,
  AttestationEvent,
  BadgeState,
  GlobalLayerContext,
  StoredBadgeState,
} from "./types.js";

// -----------------------------------------------------------------------
// Badge state stores (in-memory; production deployment swaps backend)
// -----------------------------------------------------------------------

const globalStore = new Map<string, StoredBadgeState>();
const agentStore = new Map<string, StoredBadgeState>();
const actionStore = new Map<string, StoredBadgeState>();

const MAX_RECENT_EVENTS = 50;

// -----------------------------------------------------------------------
// Store access
// -----------------------------------------------------------------------

function getStore(layer: LayerType): Map<string, StoredBadgeState> {
  switch (layer) {
    case "global":
      return globalStore;
    case "per_agent":
      return agentStore;
    case "per_action":
      return actionStore;
    case "custody_provenance":
      return new Map(); // Layer 4 stub; no store at v1.0
  }
}

// -----------------------------------------------------------------------
// Badge derivation: pure-logic functions
// -----------------------------------------------------------------------

/**
 * Derive global (fortress-level) badge from context.
 *
 * Aggregation rule (design brief section 3, Layer 1):
 * worst-of among reachable nodes, plus unreachable node count.
 */
export function deriveGlobalBadge(ctx: GlobalLayerContext): BadgeStateColor {
  const nodeStates = Object.values(ctx.node_states);
  const agentStates = Object.values(ctx.agent_badge_states);

  // If no nodes at all, offline
  if (nodeStates.length === 0) {
    return "offline";
  }

  // Check for red conditions (design brief section 3, Layer 1 red states)
  if (
    nodeStates.includes("red") ||
    ctx.audit_chain_state === "red" ||
    agentStates.includes("red")
  ) {
    return "red";
  }

  // Check for yellow conditions
  if (
    nodeStates.includes("yellow") ||
    nodeStates.includes("offline") ||
    ctx.audit_chain_state === "yellow" ||
    ctx.policy_sync_state === "yellow" ||
    ctx.guardian_state === "yellow" ||
    agentStates.includes("yellow")
  ) {
    return "yellow";
  }

  return "green";
}

/**
 * Derive per-agent badge from context.
 *
 * Aggregation rule (design brief section 3, Layer 2):
 * worst-of among identity, node attestation, policy, annex states, and egress.
 */
export function deriveAgentBadge(ctx: AgentLayerContext): BadgeStateColor {
  // local_only if node attestation is local_only and no annexes are degraded
  const annexStates = Object.values(ctx.annex_states);
  if (
    ctx.node_attestation_state === "local_only" &&
    !annexStates.some((s) => s === "yellow" || s === "red")
  ) {
    return "local_only";
  }

  // Red conditions
  if (
    ctx.node_attestation_state === "red" ||
    annexStates.includes("red") ||
    !ctx.identity_valid
  ) {
    return "red";
  }

  // Offline
  if (ctx.node_attestation_state === "offline") {
    return "offline";
  }

  // Yellow conditions
  if (
    ctx.node_attestation_state === "yellow" ||
    annexStates.includes("yellow") ||
    !ctx.policy_pinned ||
    !ctx.egress_enforcing
  ) {
    return "yellow";
  }

  return "green";
}

/**
 * Derive per-action badge from context.
 *
 * Design brief section 3, Layer 3: "Two surfaces of the same fact."
 * The embedded attestation reflects the moment-of-action (immutable).
 * The live glyph reflects the current verifier check.
 */
export function deriveActionBadge(ctx: ActionLayerContext): BadgeStateColor {
  // If time-of-action was local_only, that is the steady state
  if (ctx.time_of_action_state === "local_only") {
    return "local_only";
  }

  // If time-of-action was red, it stays red (attestation gap)
  if (ctx.time_of_action_state === "red") {
    return "red";
  }

  // If time-of-action was offline, return offline explicitly
  if (ctx.time_of_action_state === "offline") {
    return "offline";
  }

  // If time-of-action was green but current verifier disagrees
  if (
    ctx.time_of_action_state === "green" &&
    ctx.current_verifier_state !== "green"
  ) {
    return "yellow"; // "attested then; uncertain now"
  }

  // If time-of-action was yellow, stays yellow
  if (ctx.time_of_action_state === "yellow") {
    return "yellow";
  }

  return ctx.time_of_action_state;
}

// -----------------------------------------------------------------------
// Badge creation + update
// -----------------------------------------------------------------------

function makeBadge(
  state: BadgeStateColor,
  layer: LayerType,
  scope_id: string,
  event_ids: string[],
  explanation_key: string
): BadgeState {
  return {
    state,
    label: BADGE_STATE_LABELS[state],
    last_updated_at: new Date().toISOString(),
    source_event_ids: event_ids,
    explanation_key,
    layer,
    scope_id,
  };
}

function makeStoredBadge(
  badge: BadgeState,
  event?: AttestationEvent
): StoredBadgeState {
  return {
    badge,
    recent_events: event ? [event] : [],
    is_cached: false,
    cached_at: null,
  };
}

// -----------------------------------------------------------------------
// Public: apply an attestation event to update badge state
// -----------------------------------------------------------------------

/**
 * Apply an attestation event to the appropriate badge store.
 * Returns the updated badge state.
 *
 * Pure logic: no LLM, no network, no side effects beyond the in-memory store.
 */
export function applyAttestationEvent(event: AttestationEvent): BadgeState {
  const store = getStore(event.target_layer);
  const existing = store.get(event.scope_id);

  const badge = makeBadge(
    event.resulting_state,
    event.target_layer,
    event.scope_id,
    existing
      ? [...existing.badge.source_event_ids.slice(-9), event.event_id]
      : [event.event_id],
    event.failure_mode
      ? `failure.${event.failure_mode}`
      : `${event.target_layer}.${event.resulting_state}`
  );

  if (existing) {
    existing.badge = badge;
    existing.recent_events = [
      ...existing.recent_events.slice(-(MAX_RECENT_EVENTS - 1)),
      event,
    ];
    existing.is_cached = false;
    existing.cached_at = null;
    store.set(event.scope_id, existing);
  } else {
    store.set(event.scope_id, makeStoredBadge(badge, event));
  }

  return badge;
}

// -----------------------------------------------------------------------
// Public: read badge state
// -----------------------------------------------------------------------

export function getGlobalBadgeState(fortress_id: string): BadgeState {
  const stored = globalStore.get(fortress_id);
  if (!stored) {
    // Default: offline (no events received yet)
    return makeBadge("offline", "global", fortress_id, [], "global.no_data");
  }
  return stored.badge;
}

export function getAgentBadgeState(agent_id: string): BadgeState {
  const stored = agentStore.get(agent_id);
  if (!stored) {
    throw new BadgeScopeNotFoundError(agent_id, "per_agent");
  }
  return stored.badge;
}

export function getActionBadgeState(action_id: string): BadgeState {
  const stored = actionStore.get(action_id);
  if (!stored) {
    throw new BadgeScopeNotFoundError(action_id, "per_action");
  }
  return stored.badge;
}

export function getStoredBadge(
  layer: LayerType,
  scope_id: string
): StoredBadgeState | undefined {
  return getStore(layer).get(scope_id);
}

// -----------------------------------------------------------------------
// Public: update from layer context (full derivation)
// -----------------------------------------------------------------------

export function updateGlobalFromContext(
  ctx: GlobalLayerContext,
  source_event_ids: string[]
): BadgeState {
  const state = deriveGlobalBadge(ctx);
  const badge = makeBadge(
    state,
    "global",
    ctx.fortress_id,
    source_event_ids,
    `global.${state}`
  );
  const existing = globalStore.get(ctx.fortress_id);
  if (existing) {
    existing.badge = badge;
    existing.is_cached = false;
    existing.cached_at = null;
  } else {
    globalStore.set(ctx.fortress_id, makeStoredBadge(badge));
  }
  return badge;
}

export function updateAgentFromContext(
  ctx: AgentLayerContext,
  source_event_ids: string[]
): BadgeState {
  const state = deriveAgentBadge(ctx);
  const badge = makeBadge(
    state,
    "per_agent",
    ctx.agent_id,
    source_event_ids,
    `per_agent.${state}`
  );
  const existing = agentStore.get(ctx.agent_id);
  if (existing) {
    existing.badge = badge;
    existing.is_cached = false;
    existing.cached_at = null;
  } else {
    agentStore.set(ctx.agent_id, makeStoredBadge(badge));
  }
  return badge;
}

export function updateActionFromContext(
  ctx: ActionLayerContext,
  source_event_ids: string[]
): BadgeState {
  const state = deriveActionBadge(ctx);
  const badge = makeBadge(
    state,
    "per_action",
    ctx.action_id,
    source_event_ids,
    ctx.time_of_action_state === "green" && state === "yellow"
      ? "per_action.attested_then_uncertain_now"
      : `per_action.${state}`
  );
  const existing = actionStore.get(ctx.action_id);
  if (existing) {
    existing.badge = badge;
    existing.is_cached = false;
    existing.cached_at = null;
  } else {
    actionStore.set(ctx.action_id, makeStoredBadge(badge));
  }
  return badge;
}

// -----------------------------------------------------------------------
// Public: store management
// -----------------------------------------------------------------------

/** Clear all stores. Test-only. */
export function clearAllBadgeStores(): void {
  globalStore.clear();
  agentStore.clear();
  actionStore.clear();
}

/** Get counts for diagnostic purposes. */
export function getBadgeStoreCounts(): Record<LayerType, number> {
  return {
    global: globalStore.size,
    per_agent: agentStore.size,
    per_action: actionStore.size,
    custody_provenance: 0,
  };
}
