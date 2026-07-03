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
  BADGE_STATES,
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
// Fail-closed input normalization (anti-false-green)
// -----------------------------------------------------------------------

/**
 * True only for values that are members of the closed BADGE_STATES enum.
 *
 * Badge derivation inputs (node states, agent states, annex states, audit /
 * policy / guardian states) are typed BadgeStateColor, but the context
 * objects are assembled by callers from live signals and may carry a value
 * outside the enum if a producer is buggy, a payload is truncated, or an
 * input is tampered with. Such a value must never be treated as nominal.
 */
function isKnownBadgeState(value: unknown): value is BadgeStateColor {
  return (
    typeof value === "string" &&
    (BADGE_STATES as readonly string[]).includes(value)
  );
}

/**
 * Fail-closed classification of a single derivation input.
 *
 * Returns "nominal" ONLY for a positively-recognized healthy state: an
 * explicit "green" or the valid "local_only" steady state. Every other
 * value, including "yellow", "red", "offline", and any UNRECOGNIZED value,
 * is not nominal, so an aggregate badge can only reach green when every
 * input independently earns it.
 *
 * This is the anti-false-green invariant: green is positively earned by
 * every input, not merely the absence of a listed bad value. An unknown or
 * corrupt input degrades to a truthful state ("yellow", walls watch) rather
 * than silently rendering green.
 */
function classifyInput(value: unknown): {
  nominal: boolean;
  degradedTo: BadgeStateColor;
} {
  if (value === "green" || value === "local_only") {
    return { nominal: true, degradedTo: value };
  }
  if (isKnownBadgeState(value)) {
    // A recognized non-nominal state (yellow / red / offline): degrade to it.
    return { nominal: false, degradedTo: value };
  }
  // Unrecognized / corrupt / absent: truthful "look at this" degrade, never green.
  return { nominal: false, degradedTo: "yellow" };
}

/**
 * Worst-of reducer over a set of derivation inputs. Any value that is not a
 * positively-recognized nominal state pulls the aggregate away from green.
 *
 * Aggregate severity order (worst first): red, then yellow. A single input
 * that is "offline" is a degraded ("look at this") condition at the
 * aggregate level, not a whole-fortress offline: it maps into the yellow
 * tier so a missing sub-signal surfaces as "walls watch" rather than being
 * masked as green (design brief section 3, Layer 1: an unreachable node
 * surfaces yellow while the fortress stays watchful). A whole-scope offline
 * (no nodes / scope absent) is decided by the callers before this reducer.
 * "local_only" is a valid nominal steady state and does not degrade.
 */
function worstOf(values: readonly unknown[]): BadgeStateColor {
  let sawRed = false;
  let sawDegraded = false;
  for (const value of values) {
    const { nominal, degradedTo } = classifyInput(value);
    if (nominal) continue;
    if (degradedTo === "red") {
      sawRed = true;
    } else {
      // yellow, offline, and any unknown-degraded input all surface as
      // "walls watch" at the aggregate: truthfully degraded, never green.
      sawDegraded = true;
    }
  }
  if (sawRed) return "red";
  if (sawDegraded) return "yellow";
  return "green";
}

// -----------------------------------------------------------------------
// Badge derivation: pure-logic functions
// -----------------------------------------------------------------------

/**
 * Derive global (fortress-level) badge from context.
 *
 * Aggregation rule (design brief section 3, Layer 1): worst-of among
 * reachable nodes, the audit chain, policy sync, guardian presence, and
 * per-agent states.
 *
 * Fail-closed: green requires every input to positively present a nominal
 * state. A "red" or "offline" on audit / policy / guardian (previously only
 * "yellow" was inspected on the latter two) now propagates, and any
 * unrecognized input degrades rather than falling through to green.
 */
export function deriveGlobalBadge(ctx: GlobalLayerContext): BadgeStateColor {
  const nodeStates = Object.values(ctx.node_states);

  // If no nodes at all, offline (no signal).
  if (nodeStates.length === 0) {
    return "offline";
  }

  // Worst-of across every input. Each aggregate input is classified
  // fail-closed: unknown values degrade to yellow, and red/offline on any
  // subsystem propagates rather than being ignored.
  return worstOf([
    ...nodeStates,
    ...Object.values(ctx.agent_badge_states),
    ctx.audit_chain_state,
    ctx.policy_sync_state,
    ctx.guardian_state,
  ]);
}

/**
 * Derive per-agent badge from context.
 *
 * Aggregation rule (design brief section 3, Layer 2): worst-of among
 * identity, node attestation, policy, annex states, and egress.
 *
 * Fail-closed: green requires node attestation and every annex to positively
 * present a nominal state, identity to be valid, policy pinned, and egress
 * enforcing. An unrecognized node or annex state degrades to yellow rather
 * than rendering green.
 */
export function deriveAgentBadge(ctx: AgentLayerContext): BadgeStateColor {
  const annexStates = Object.values(ctx.annex_states);

  // local_only is a valid steady state only when node attestation is a clean
  // local_only AND no annex is in any non-nominal state (including unknown).
  if (
    ctx.node_attestation_state === "local_only" &&
    annexStates.every((s) => classifyInput(s).nominal)
  ) {
    return "local_only";
  }

  // Hard-red inputs that are not captured by the worst-of over enum states:
  // an invalid identity is always red regardless of the other signals.
  if (!ctx.identity_valid) {
    return "red";
  }

  // The agent's bound node is a singular binding (unlike the global layer's
  // node set): if its attestation state is offline, and nothing else is red,
  // the agent surfaces offline (no signal) explicitly. A red annex still wins.
  if (
    ctx.node_attestation_state === "offline" &&
    !annexStates.some((s) => classifyInput(s).degradedTo === "red")
  ) {
    return "offline";
  }

  // Boolean posture inputs degrade to yellow when not satisfied.
  const posture: BadgeStateColor[] = [];
  if (!ctx.policy_pinned) posture.push("yellow");
  if (!ctx.egress_enforcing) posture.push("yellow");

  return worstOf([
    ctx.node_attestation_state,
    ...annexStates,
    ...posture,
  ]);
}

/**
 * Derive per-action badge from context.
 *
 * Design brief section 3, Layer 3: "Two surfaces of the same fact."
 * The embedded attestation reflects the moment-of-action (immutable).
 * The live glyph reflects the current verifier check.
 *
 * Fail-closed: an unrecognized time-of-action state must never pass through
 * verbatim (it would render as an unknown/absent badge). It degrades to
 * yellow. Green is returned only when the action was attested green AND the
 * current verifier still positively confirms green.
 */
export function deriveActionBadge(ctx: ActionLayerContext): BadgeStateColor {
  // Unrecognized time-of-action state: degrade truthfully, never emit raw.
  if (!isKnownBadgeState(ctx.time_of_action_state)) {
    return "yellow";
  }

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

  // If time-of-action was yellow, stays yellow
  if (ctx.time_of_action_state === "yellow") {
    return "yellow";
  }

  // time_of_action_state is "green" here. Green survives ONLY if the current
  // verifier positively confirms green; any other or unrecognized verifier
  // state degrades to yellow ("attested then; uncertain now").
  if (ctx.current_verifier_state === "green") {
    return "green";
  }
  return "yellow";
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
