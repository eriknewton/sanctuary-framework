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
import { getFailureMode } from "./failure-catalog.js";
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
 * explicit "green" or, WHERE it is a legitimate steady state for this input
 * class, the "local_only" state. Every other value, including "yellow",
 * "red", "offline", and any UNRECOGNIZED value, is not nominal, so an
 * aggregate badge can only reach green when every input independently earns it.
 *
 * Field-awareness (anti-false-green, B4 finding #3): "local_only" is a
 * legitimate nominal steady state ONLY for the fields that describe an
 * agent's / node's / action's own attestation posture (a node running in
 * pure local mode, an annex pending first approval, a local-mode action).
 * See the failure-mode catalog: the two rows whose badge_result is
 * "local_only" (local_only_mode, annex_approval_pending) affect only the
 * per_agent / per_action layers. It is NOT a valid nominal state for the
 * GLOBAL subsystem fields (audit chain, policy sync, guardian presence):
 * those are fortress-wide verification signals with no "local mode" steady
 * state, so a "local_only" there means "no source-verified signal" and MUST
 * degrade rather than earn a green fortress badge. Callers pass
 * allowLocalOnly=false for those global subsystem fields; it defaults to
 * true for the posture fields that legitimately steady-state to local_only.
 *
 * This is the anti-false-green invariant: green is positively earned by
 * every input, not merely the absence of a listed bad value. An unknown or
 * corrupt input, and a local_only where it is not a legitimate steady state,
 * degrade to a truthful state ("yellow", walls watch) rather than silently
 * rendering green.
 */
function classifyInput(
  value: unknown,
  allowLocalOnly = true
): {
  nominal: boolean;
  degradedTo: BadgeStateColor;
} {
  if (value === "green") {
    return { nominal: true, degradedTo: value };
  }
  if (value === "local_only") {
    // Legitimate nominal steady state only for posture fields; on a global
    // subsystem field it is "no source-verified signal" and must degrade.
    return allowLocalOnly
      ? { nominal: true, degradedTo: value }
      : { nominal: false, degradedTo: "yellow" };
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
 * "local_only" is a valid nominal steady state ONLY for posture fields
 * (allowLocalOnly, the default); on global subsystem fields it degrades.
 */
function worstOf(
  values: readonly unknown[],
  allowLocalOnly = true
): BadgeStateColor {
  let sawRed = false;
  let sawDegraded = false;
  for (const value of values) {
    const { nominal, degradedTo } = classifyInput(value, allowLocalOnly);
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

/**
 * Worst-of two already-reduced aggregate results. Used to combine input
 * groups that differ in local_only legitimacy (the posture group, where
 * local_only is nominal, versus the global-subsystem group, where it is
 * not). Severity order matches worstOf: red beats any degrade, and any
 * degrade beats green.
 */
function combineAggregates(
  a: BadgeStateColor,
  b: BadgeStateColor
): BadgeStateColor {
  if (a === "red" || b === "red") return "red";
  if (a === "green" && b === "green") return "green";
  // Any non-green, non-red aggregate (yellow / offline / local_only) surfaces
  // as "walls watch" at the fortress level: truthfully degraded, never green.
  return "yellow";
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
 *
 * Field-awareness (B4 finding #3): the inputs split into two classes with
 * different local_only legitimacy. Node and per-agent states describe
 * attestation posture, for which local_only is a legitimate nominal steady
 * state. The three global subsystem fields (audit chain, policy sync,
 * guardian presence) are fortress-wide verification signals with no local
 * steady state, so a local_only there is "no source-verified signal" and
 * must degrade, not earn a green fortress badge. The two groups are reduced
 * separately (allowLocalOnly true vs false) and then combined.
 */
export function deriveGlobalBadge(ctx: GlobalLayerContext): BadgeStateColor {
  const nodeStates = Object.values(ctx.node_states);

  // If no nodes at all, offline (no signal).
  if (nodeStates.length === 0) {
    return "offline";
  }

  // Posture group: nodes + per-agent states. local_only is a legitimate
  // nominal steady state here.
  const posture = worstOf([
    ...nodeStates,
    ...Object.values(ctx.agent_badge_states),
  ]);

  // Global-subsystem group: audit chain, policy sync, guardian presence.
  // local_only is NOT a legitimate nominal state for these fortress-wide
  // verification signals, so it degrades (allowLocalOnly = false).
  const subsystems = worstOf(
    [ctx.audit_chain_state, ctx.policy_sync_state, ctx.guardian_state],
    false
  );

  return combineAggregates(posture, subsystems);
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
 * than rendering green. The local_only steady state is likewise positively
 * earned: it requires the SAME posture as green (valid identity, pinned
 * policy, enforcing egress, all annexes nominal), differing only in that the
 * node makes no external attestation claim.
 */
export function deriveAgentBadge(ctx: AgentLayerContext): BadgeStateColor {
  const annexStates = Object.values(ctx.annex_states);

  // Hard-red inputs that are not captured by the worst-of over enum states:
  // an invalid identity is always red regardless of the other signals. This
  // is checked BEFORE the local_only return so a compromised identity can
  // never be masked by a clean local_only node (B4 finding #2).
  if (!ctx.identity_valid) {
    return "red";
  }

  // local_only is a positively-earned steady state, NOT a fall-through: the
  // node makes no external attestation claim, but every other posture signal
  // must still be nominal. It requires a clean local_only node, all annexes
  // nominal, AND policy pinned + egress enforcing (identity already verified
  // above). If any of those fail, the agent degrades below rather than
  // presenting a trusted local_only badge (B4 finding #2).
  if (
    ctx.node_attestation_state === "local_only" &&
    ctx.policy_pinned &&
    ctx.egress_enforcing &&
    annexStates.every((s) => classifyInput(s).nominal)
  ) {
    return "local_only";
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
 * Aggregate severity rank of a badge state (higher = worse). Used to take
 * the more-severe of two states when reconciling a signed event's claimed
 * resulting_state against its failure_mode's authoritative catalog result.
 *
 * Ordering mirrors the derivation reducers: red is worst, then the
 * "degraded / no clean signal" tier (yellow / offline), then the nominal
 * tier (local_only / green). An unrecognized value ranks as high as red so
 * a corrupt state can never be treated as the milder of the two.
 */
function severityRank(state: BadgeStateColor): number {
  switch (state) {
    case "red":
      return 3;
    case "offline":
    case "yellow":
      return 2;
    case "local_only":
      return 1;
    case "green":
      return 0;
    default:
      return 3;
  }
}

/**
 * Reconcile a signed event's claimed resulting_state against its failure_mode
 * (B4 finding #1, fail-CLOSED).
 *
 * fromSignedEvent only enum-validates resulting_state; it does NOT check that
 * the claimed state is consistent with the failure_mode. A signature-verified
 * event can therefore carry {failure_mode: 'sovereign_node_attestation_fail',
 * resulting_state: 'green'} from a buggy or compromised producer and, unfixed,
 * render a green badge with a failure explanation: a false-green.
 *
 * When a failure_mode is present, the failure-mode catalog's badge_result is
 * the authoritative expected state for that failure. We take the MORE SEVERE
 * of the claimed state and the catalog result, so:
 *   - a failure_mode with badge_result "red"/"yellow"/"local_only" can never
 *     be downgraded to green by a lying resulting_state (the false-green is
 *     closed), and
 *   - a producer that legitimately reports a worse state than the catalog
 *     baseline (e.g. red for a nominally-yellow failure) is honored.
 * A hard floor also guarantees that ANY present failure_mode, including an
 * unknown code not in the catalog, never yields green.
 */
function reconcileEventState(event: AttestationEvent): BadgeStateColor {
  if (!event.failure_mode) {
    return event.resulting_state;
  }
  const entry = getFailureMode(event.failure_mode);
  // Catalog result is authoritative for the failure; fall back to "yellow"
  // (truthful degrade) for a failure_mode with no catalog row.
  const catalogState: BadgeStateColor = entry ? entry.badge_result : "yellow";
  const reconciled =
    severityRank(event.resulting_state) >= severityRank(catalogState)
      ? event.resulting_state
      : catalogState;
  // Hard floor: a present failure_mode must never render green, even if both
  // the claimed and catalog states somehow read green.
  return reconciled === "green" ? "yellow" : reconciled;
}

/**
 * Apply an attestation event to the appropriate badge store.
 * Returns the updated badge state.
 *
 * Pure logic: no LLM, no network, no side effects beyond the in-memory store.
 */
export function applyAttestationEvent(event: AttestationEvent): BadgeState {
  const store = getStore(event.target_layer);
  const existing = store.get(event.scope_id);

  // Reconcile the claimed state against the failure-mode catalog so a signed
  // event cannot store a state inconsistent with its failure_mode (finding #1).
  const effectiveState = reconcileEventState(event);

  const badge = makeBadge(
    effectiveState,
    event.target_layer,
    event.scope_id,
    existing
      ? [...existing.badge.source_event_ids.slice(-9), event.event_id]
      : [event.event_id],
    event.failure_mode
      ? `failure.${event.failure_mode}`
      : `${event.target_layer}.${effectiveState}`
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
