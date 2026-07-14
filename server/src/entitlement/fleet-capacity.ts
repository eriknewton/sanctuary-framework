/**
 * Fleet control plane, Add-Machine slice: the PURE "enrollment headroom" view.
 *
 * This is the single arithmetic chokepoint behind two operator-facing surfaces
 * (`GET /api/fleet/capacity` and the pre-check inside `POST
 * /api/fleet/enroll-token`, both wired in `principal-policy/dashboard.ts`). It
 * takes the ALREADY-RESOLVED {@link FleetCap} (from `resolveFleetCap`) and the
 * durable roster's active-node count (`buildFleetRoster(...).summary.admitted`)
 * and answers: how many of the paid node cap are in use, and is there room for
 * one more.
 *
 * PURE (no I/O, no crypto): deterministic given its inputs, so every boundary
 * (unlimited / within / exactly-at / over cap, and roster-unavailable) is
 * exhaustively unit-testable without a daemon.
 *
 * WHAT THIS IS NOT (ratified 2026-07-05):
 * `at_capacity` / `enrollment_allowed` are MANAGEMENT-CAPACITY UX, not a
 * security gate. They stop the operator wasting an enrollment invite; they are
 * NOT the node-count enforcement, which remains `applyFleetCap` on the central
 * roster (already shipped, unchanged by this module). A bug here can only ever
 * over-block enrollment (fail-closed), never over-admit a node, and it NEVER
 * touches a wall / enforcement / local-dashboard / policy-push / kill-safety
 * path (this module imports nothing from any of those and has no I/O at all).
 */

import type { FleetCap } from "./fleet-cap.js";

/**
 * The enrollment-headroom view for the operator-facing capacity surfaces.
 */
export interface FleetCapacityView {
  /** Operator-facing tier label for the resolved cap (`cap.tier`). */
  tier: string;
  /** Max nodes centrally manageable; null = unlimited (`cap.maxNodes`). */
  max_nodes: number | null;
  /** Current active (admitted, non-revoked) node count on the durable roster. */
  active_nodes: number;
  /**
   * Headroom remaining under the cap: `max(0, max_nodes - active_nodes)`.
   * `null` when the cap is unlimited. NEVER negative even when the roster
   * already exceeds a shrunk cap (e.g. after a downgrade/revocation): a
   * negative remaining count would be a confusing, meaningless UX signal.
   */
  remaining: number | null;
  /**
   * True only when the cap is finite AND the active count has reached or
   * passed it. An unlimited cap is never at capacity.
   */
  at_capacity: boolean;
  /** Advisory only, see the module doc. `!at_capacity`. */
  enrollment_allowed: boolean;
  /** Fail-closed provenance for the resolved cap (`cap.reason`). */
  reason: FleetCap["reason"];
}

/**
 * Normalize an active-node count to a safe non-negative integer. A malformed
 * count (NaN / negative / non-integer, e.g. a roster read that returned
 * something unexpected) degrades to 0 (honest absence, matching the
 * roster-unavailable branch every other capacity/status read already uses),
 * NEVER a large number that could fabricate an at-capacity block or, worse, a
 * false "there is room" signal from an underflowed negative.
 */
function normalizeActiveNodes(activeNodes: number): number {
  if (
    typeof activeNodes === "number" &&
    Number.isSafeInteger(activeNodes) &&
    activeNodes >= 0
  ) {
    return activeNodes;
  }
  return 0;
}

/**
 * Build the pure enrollment-headroom view from a resolved {@link FleetCap} and
 * the current active-node count. Never throws.
 *
 * Branch table:
 *  - `maxNodes === null` (unlimited/Team+ with no finite entitlement): always
 *    `remaining: null`, `at_capacity: false`.
 *  - `activeNodes < maxNodes`: `remaining = maxNodes - activeNodes`,
 *    `at_capacity: false`.
 *  - `activeNodes === maxNodes` (exactly at cap): `remaining: 0`,
 *    `at_capacity: true`.
 *  - `activeNodes > maxNodes` (roster already exceeds a shrunk cap, e.g. after
 *    a downgrade before `applyFleetCap` next runs): `remaining` clamps to `0`,
 *    never negative; `at_capacity: true`.
 */
export function computeFleetCapacityView(
  cap: FleetCap,
  activeNodes: number,
): FleetCapacityView {
  const active = normalizeActiveNodes(activeNodes);

  if (cap.maxNodes === null) {
    return {
      tier: cap.tier,
      max_nodes: null,
      active_nodes: active,
      remaining: null,
      at_capacity: false,
      enrollment_allowed: true,
      reason: cap.reason,
    };
  }

  const remaining = Math.max(0, cap.maxNodes - active);
  const atCapacity = active >= cap.maxNodes;

  return {
    tier: cap.tier,
    max_nodes: cap.maxNodes,
    active_nodes: active,
    remaining,
    at_capacity: atCapacity,
    enrollment_allowed: !atCapacity,
    reason: cap.reason,
  };
}
