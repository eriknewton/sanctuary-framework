/**
 * Fleet control plane PR-2: the NODE-COUNT enforcement gate (pure core).
 *
 * This is the single chokepoint that turns a resolved entitlement into the
 * concrete "how many nodes may this fortress manage centrally" cap and applies
 * it to a {@link FleetRoster}. It is PURE (no I/O, no crypto, deterministic
 * given its inputs) so every fail-closed branch is exhaustively unit-testable.
 *
 * ── WHAT THIS GATES, AND WHAT IT MUST NEVER GATE (RATIFIED 2026-07-05) ───────
 * The license gates fleet-MANAGEMENT SCALE only: how many nodes appear in the
 * CENTRAL roster / remote console. It NEVER gates security:
 *
 *   - Every node's Castle Wall enforcement runs FREE at any scale, always. This
 *     module touches NOTHING on any wall/enforcement/local-dashboard path; it
 *     only reshapes the central-management roster presentation.
 *   - Policy-push (signed operator-policy distribution) is a SECURITY function,
 *     ALWAYS FREE and uncapped. {@link applyFleetCap} preserves the roster's
 *     `policy_distribution` rail verbatim and NEVER counts it toward the cap.
 *   - Kill-safety (M-of-N guardian) is SAFETY, not gated here.
 *
 * The gate is therefore expressed entirely as: "when the fleet is over its
 * entitled node count, drop the nodes beyond the cap out of the CENTRAL roster;
 * every node keeps its free local wall + local dashboard." Enforcement is never
 * touched.
 *
 * ── FAIL-CLOSED DIRECTION ───────────────────────────────────────────────────
 * A verify/resolve failure (invalid / expired / unreadable / malformed) resolves
 * to the COMMUNITY cap (5 free nodes), NEVER to unlimited. A bug here can only
 * ever REMOVE paid management capacity, never grant it. It can NEVER remove a
 * node's wall.
 *
 * ── GRANDFATHERING (RATIFIED) ───────────────────────────────────────────────
 * An existing multi-node fleet at launch keeps its current node count free,
 * indefinitely. The persisted activation state carries a per-fleet
 * `grandfatheredBaseline`; the effective community cap is
 * `max(COMMUNITY_FREE_NODE_CAP, grandfatheredBaseline)`. The 5-node free cap
 * applies to NEW fleets only. A paid (Team+) grant with an unlimited or
 * higher-than-baseline entitlement supersedes the grandfather floor.
 */

import type { FleetRoster, FleetRosterNode } from "../principal-policy/fleet-roster.js";

/**
 * The community free node cap: a NEW, unlicensed fleet may centrally manage up
 * to this many nodes for free. Team lifts it (per-node pricing above this).
 * Every node's local wall + local dashboard is free regardless of this number.
 */
export const COMMUNITY_FREE_NODE_CAP = 5;

/**
 * The resolved node-count cap for a fleet: `null` means UNLIMITED (a valid Team+
 * grant with `entitledCount === null`), otherwise the maximum number of nodes
 * that may appear in the central roster.
 *
 * `reason` is operator-facing provenance (surfaced by PR-3's downgrade log /
 * banner). It never affects the cap arithmetic; it only explains WHY the fleet
 * is at this cap so "why did N nodes leave the console" is answerable.
 */
export interface FleetCap {
  /** Max nodes centrally manageable; null = unlimited. */
  maxNodes: number | null;
  /** True only on a valid, in-window (or in-grace) paid grant lifting the cap. */
  paid: boolean;
  /** Operator-facing tier label for the resolved cap ("community" | the granted tier). */
  tier: string;
  /** Why the fleet resolved to this cap (fail-closed provenance for PR-3). */
  reason: FleetCapReason;
  /**
   * True when a paid grant is being honored during its grace window. Advisory
   * for PR-3's "renew soon" banner; the cap is already the paid cap here.
   */
  graceActive: boolean;
}

/**
 * Why a fleet resolved to its cap. Every non-`granted` reason resolves to the
 * community floor (fail-closed). These are stable identifiers PR-3 surfaces.
 */
export type FleetCapReason =
  | "granted" // a valid paid grant lifted (or set) the cap
  | "no_license" // no license activated: community floor (never a free-ride)
  | "invalid" // license failed verification: community floor
  | "expired" // past notAfter (and grace): community floor
  | "not_yet_valid" // before notBefore: community floor
  | "unreadable" // activation state present but unreadable/tampered: community floor
  | "grandfathered"; // no paid grant but a grandfather baseline raised the free cap

/**
 * The minimal shape {@link resolveFleetCap} needs from a resolved entitlement.
 * This is exactly the subset of `EntitlementResolution` the node-count gate
 * reads; taking the subset (not the whole resolution) keeps this pure core
 * decoupled from the token module and trivially testable.
 */
export interface ResolvedEntitlementView {
  /** True only when the token verified and is in-window (or in-grace). */
  granted: boolean;
  /** The resolved tier (COMMUNITY on any failure). */
  tier: string;
  /**
   * Max entitled units from a granted v2 license (null = unlimited). Absent on a
   * denial and on a v1 grant. Only consulted when `granted` is true.
   */
  entitledCount?: number | null;
  /** The pricing axis; the node-count gate only enforces when this is "node". */
  pricingUnit?: string;
  /** True when the grant is being honored inside its grace window. */
  graceActive?: boolean;
  /** The deny reason when `granted` is false (maps to a FleetCapReason). */
  reason?: string;
}

/**
 * Map an entitlement deny-reason to the operator-facing {@link FleetCapReason}.
 * Anything not explicitly a window/validity denial collapses to `invalid` (the
 * safe, non-committal community-floor reason) so a new deny reason can never
 * accidentally read as "granted".
 */
function reasonForDenied(denyReason: string | undefined): FleetCapReason {
  switch (denyReason) {
    case "absent":
      return "no_license";
    case "expired":
      return "expired";
    case "not_yet_valid":
      return "not_yet_valid";
    // "malformed" | "unknown_tier" | "bad_signature" | anything unknown:
    default:
      return "invalid";
  }
}

/**
 * The safe community-floor cap. The free node count is
 * `max(COMMUNITY_FREE_NODE_CAP, grandfatheredBaseline)` so an existing >5-node
 * fleet is grandfathered at its current count. `reason` distinguishes a plain
 * community floor from a grandfather-raised one for PR-3's log.
 */
function communityCap(
  grandfatheredBaseline: number,
  reason: FleetCapReason,
): FleetCap {
  const baseline = normalizeBaseline(grandfatheredBaseline);
  const grandfathered = baseline > COMMUNITY_FREE_NODE_CAP;
  return {
    maxNodes: Math.max(COMMUNITY_FREE_NODE_CAP, baseline),
    paid: false,
    tier: "community",
    // A grandfather baseline that actually RAISES the floor is surfaced as
    // "grandfathered" so the operator understands why their >5-node fleet still
    // fully appears; otherwise the plain fail-closed reason is preserved.
    reason: grandfathered ? "grandfathered" : reason,
    graceActive: false,
  };
}

/**
 * Normalize a grandfather baseline to a safe non-negative integer. A malformed
 * baseline (NaN / negative / non-integer / absent) degrades to 0 (no
 * grandfather floor), NEVER to a large number: a corrupt baseline must not be
 * able to silently lift the cap. Fail-closed toward the plain community cap.
 */
function normalizeBaseline(baseline: number): number {
  if (
    typeof baseline === "number" &&
    Number.isSafeInteger(baseline) &&
    baseline >= 0
  ) {
    return baseline;
  }
  return 0;
}

/**
 * Resolve the node-count cap for a fleet from a verified entitlement view and
 * the fleet's grandfathered baseline. PURE and FAIL-CLOSED.
 *
 * Branch table (every branch resolves safely):
 *  - NOT granted (no license / invalid / expired / not-yet-valid / unreadable) →
 *    community floor (max(5, baseline)). Never a free-ride to unlimited.
 *  - granted but NOT a node-metered license (`pricingUnit !== "node"`) → we do
 *    not know how to meter this on the node axis, so we DO NOT lift the node cap;
 *    resolve to the community floor. (A seat/fleet pivot is a future slice; until
 *    then a non-node license must not silently grant unlimited nodes.)
 *  - granted, node-metered, `entitledCount === null` → UNLIMITED (Team+ lifts the
 *    cap entirely).
 *  - granted, node-metered, `entitledCount` a finite integer ≥ 0 →
 *    `max(entitledCount, communityFloor)`: a paid grant never LOWERS a fleet
 *    below its free/grandfathered floor.
 *  - granted but `entitledCount` malformed → fail-closed to the community floor
 *    (a broken count must not grant unlimited).
 */
export function resolveFleetCap(
  view: ResolvedEntitlementView,
  grandfatheredBaseline = 0,
): FleetCap {
  const baseline = normalizeBaseline(grandfatheredBaseline);
  const floor = Math.max(COMMUNITY_FREE_NODE_CAP, baseline);

  if (!view.granted) {
    return communityCap(baseline, reasonForDenied(view.reason));
  }

  // A granted-but-non-node-metered license does not lift the NODE cap. Until a
  // seat/fleet meter exists, treat it as community for node-count purposes
  // rather than silently granting unlimited nodes (fail-closed).
  if (view.pricingUnit !== "node") {
    return communityCap(baseline, "invalid");
  }

  const graceActive = view.graceActive === true;

  // Unlimited grant (Team+ with entitledCount null): lift the cap entirely.
  if (view.entitledCount === null) {
    return {
      maxNodes: null,
      paid: true,
      tier: view.tier,
      reason: "granted",
      graceActive,
    };
  }

  // Finite, valid count: a paid grant never lowers the fleet below its free /
  // grandfathered floor.
  if (
    typeof view.entitledCount === "number" &&
    Number.isSafeInteger(view.entitledCount) &&
    view.entitledCount >= 0
  ) {
    return {
      maxNodes: Math.max(view.entitledCount, floor),
      paid: true,
      tier: view.tier,
      reason: "granted",
      graceActive,
    };
  }

  // Granted but the count is malformed (should never happen post-verify, but a
  // bug or an unexpected shape must fail closed, never grant unlimited).
  return communityCap(baseline, "invalid");
}

/**
 * The result of applying a cap to a roster: the (possibly reshaped) roster plus
 * the enforcement metadata PR-3 will surface.
 */
export interface CappedFleetRoster {
  /** The roster as the CENTRAL console should present it (nodes beyond the cap dropped). */
  roster: FleetRoster;
  /** The cap that was applied. */
  cap: FleetCap;
  /**
   * How many nodes were DROPPED from the central roster by the cap (0 when
   * within cap or unlimited). These nodes keep their free local wall + local
   * dashboard; they simply left the console. PR-3's downgrade log surfaces this.
   */
  droppedNodeCount: number;
}

/**
 * Apply a node-count cap to a fleet roster. PURE.
 *
 * SEMANTICS (RATIFIED "keep wall, drop from console"): when the roster has more
 * `available` nodes than `cap.maxNodes`, the nodes BEYOND the cap are dropped
 * from the central roster's `nodes` list and the `summary` counts are recomputed
 * over the RETAINED nodes only. Every dropped node keeps its free local wall +
 * local dashboard (this function touches neither - it only reshapes the central
 * presentation). Enforcement is never touched.
 *
 * WHAT IS NEVER CAPPED (invariant, asserted by tests):
 *  - `policy_distribution` is preserved VERBATIM from the input roster. Policy
 *    push is a free security function and is never counted toward, or reduced by,
 *    the cap.
 *  - `available` / `enabled` / `fortress_id` / `node_id` / `eviction_serial` are
 *    passed through unchanged.
 *  - `sync_health` is recomputed over the retained nodes for an honest console
 *    liveness rollup (a dropped node is not "in the console"), but this is
 *    liveness only and never a trust or enforcement signal.
 *
 * An UNLIMITED cap (`maxNodes === null`), a not-`available` roster, or a roster
 * already within cap is returned UNCHANGED (a fresh object with the same node
 * identity), with `droppedNodeCount: 0`.
 *
 * Node retention is DETERMINISTIC and STABLE: the first `maxNodes` nodes in the
 * roster's existing order are retained. The roster order is the federation
 * presenter's order (stable across requests), so the same nodes stay in-console
 * across refreshes rather than flapping.
 */
export function applyFleetCap(roster: FleetRoster, cap: FleetCap): CappedFleetRoster {
  // Unlimited, or an absent/unavailable roster (no fleet to cap): pass through.
  // We never fabricate or add nodes; capping only ever REMOVES from the console.
  if (cap.maxNodes === null || !roster.available) {
    return { roster: { ...roster }, cap, droppedNodeCount: 0 };
  }

  const maxNodes = cap.maxNodes;
  const allNodes = roster.nodes;
  if (allNodes.length <= maxNodes) {
    // Within cap: nothing drops. Return a shallow copy for referential hygiene.
    return { roster: { ...roster }, cap, droppedNodeCount: 0 };
  }

  const retained: FleetRosterNode[] = allNodes.slice(0, maxNodes);
  const droppedNodeCount = allNodes.length - retained.length;

  const summary = {
    total: retained.length,
    admitted: retained.filter((n) => n.trust_state === "admitted").length,
    revoked: retained.filter((n) => n.trust_state === "revoked").length,
    untrusted: retained.filter((n) => n.trust_state === "untrusted").length,
  };

  return {
    roster: {
      ...roster,
      nodes: retained,
      summary,
      sync_health: recomputeSyncHealth(retained, roster.sync_health.freshness_window_ms),
      // Policy-push distribution is a FREE security function: preserve it verbatim,
      // NEVER reshaped by the cap. This is the "we never gate your security" line.
      policy_distribution: roster.policy_distribution,
    },
    cap,
    droppedNodeCount,
  };
}

/**
 * Recompute the liveness rollup over the retained nodes. Mirrors the presenter's
 * own `buildSyncHealth` so a dropped node is not counted as in-console reach.
 * Liveness only; never a trust or enforcement input.
 */
function recomputeSyncHealth(
  retained: FleetRosterNode[],
  freshnessWindowMs: number,
): FleetRoster["sync_health"] {
  let reachable = 0;
  let stale = 0;
  let never = 0;
  let oldestMs: number | null = null;
  let oldestIso: string | null = null;

  for (const node of retained) {
    if (node.reach === "recent") reachable += 1;
    else if (node.reach === "stale") stale += 1;
    else never += 1;

    const iso = node.last_sync_received_at;
    if (iso === null) continue;
    const ms = Date.parse(iso);
    if (Number.isNaN(ms)) continue;
    if (oldestMs === null || ms < oldestMs) {
      oldestMs = ms;
      oldestIso = iso;
    }
  }

  return {
    reachable,
    stale,
    never,
    oldest_last_sync: oldestIso,
    freshness_window_ms: freshnessWindowMs,
  };
}
