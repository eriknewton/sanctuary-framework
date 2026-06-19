/**
 * Sovereignty Posture Dashboard - Phase 2 distress/habeas tile shaper.
 *
 * Pure shaper for the agent drill-down Standing section's "Distress channel"
 * line (Phase 2 design 2026-06-19, section 2.4). Per the CISO-first mandate the
 * distress/welfare surface does NOT lead on Home; its honest home is the
 * per-agent drill-down Standing section, where Slice 4 already renders the
 * agent's honest posture row. This shaper turns the already-mounted, durable
 * `/api/distress/inbox` response into a facts-only tile.
 *
 * HONESTY CONTRACT (#617 never-fake-green, design 2.4 C):
 *  - The tile reports FACTS only: the count of received distress signals and the
 *    most-recent received time. It never renders a green "channel healthy/active"
 *    state - there is no listener-bound evidence on this read (only stderr at
 *    boot), so claiming the channel is live would be exactly the kind of
 *    unearned green the discipline forbids.
 *  - Absence of signals is "no distress signals recorded", NEVER a fabricated
 *    green "all well". A quiet inbox is genuinely ambiguous (no agent distress vs
 *    a listener that never bound), so it is shown neutrally, never green.
 *  - The guaranteed-egress habeas rule is surfaced as a STRUCTURAL POLICY FACT
 *    ("the wall policy always permits a wrapped agent to reach the operator at
 *    the habeas port"), which is true and verifiable from the curated allowlist /
 *    composer (the reserved `reserved_habeas_distress_local` rule is always
 *    injected and non-shadowable), NOT as a welfare guarantee.
 *
 * The shaper is pure over its injected inbox view so it unit-tests without a
 * live HTTP server or a bound listener.
 */

import {
  HABEAS_DISTRESS_PORT,
  HABEAS_LOCAL_RULE_ID,
} from "../castle-wall/allowlist/habeas-port.js";

/**
 * The minimal shape of one received distress signal the tile needs. A subset of
 * the durable `DistressInboxEntry` (inbox.ts); kept narrow so the shaper does
 * not couple to the full envelope and stays trivially testable.
 */
export interface DistressTileSignalView {
  /** When the LISTENER accepted the signal (ISO8601). */
  received_at: string;
  /** Closed-vocabulary reason, surfaced for the most-recent line only. */
  reason: string;
  /** Closed-vocabulary severity, surfaced for the most-recent line only. */
  severity: string;
}

export interface BuildDistressTileInput {
  originMachine: string;
  /**
   * Newest-first received signals (as the inbox `list()` returns them). May be
   * empty: an empty inbox is the honest "no distress signals recorded" state,
   * never a green "all well".
   */
  signals: DistressTileSignalView[];
}

/**
 * The distress tile shape. Facts only; carries NO health/active claim and NO
 * green color. `/v1`-compatible via `origin_machine`.
 */
export interface DistressTile {
  origin_machine: string;
  /** Number of distress signals the operator has received (durable inbox). */
  signal_count: number;
  /** Most-recent received time (ISO8601), or null when the inbox is empty. */
  most_recent_at: string | null;
  /** Most-recent signal's reason, or null when the inbox is empty. */
  most_recent_reason: string | null;
  /** Most-recent signal's severity, or null when the inbox is empty. */
  most_recent_severity: string | null;
  /**
   * The static, structural guaranteed-egress policy fact. ALWAYS true: the
   * composer injects the reserved loopback habeas rule into every manifest and
   * the gate refuses any operator ruleset that would shadow it. This is a policy
   * fact, not a listener-liveness or welfare claim.
   */
  guaranteed_egress: {
    /** Reserved rule id that carries the lane (always present, non-shadowable). */
    rule_id: string;
    /** Loopback habeas port the lane admits. */
    port: number;
  };
}

/**
 * Build the distress tile from a (newest-first) inbox view. Pure.
 *
 * Note on color: this shaper deliberately emits NO status/color field. The tile
 * is informational (a count + a timestamp + a structural policy fact); the
 * renderer shows it neutrally and never green. Keeping the color out of the
 * shape makes the never-green contract structural rather than a stringly-typed
 * value a future edit could flip to "green".
 */
export function buildDistressTile(input: BuildDistressTileInput): DistressTile {
  const signals = input.signals;
  const mostRecent = signals.length > 0 ? signals[0] : null;
  return {
    origin_machine: input.originMachine,
    signal_count: signals.length,
    most_recent_at: mostRecent ? mostRecent.received_at : null,
    most_recent_reason: mostRecent ? mostRecent.reason : null,
    most_recent_severity: mostRecent ? mostRecent.severity : null,
    guaranteed_egress: {
      rule_id: HABEAS_LOCAL_RULE_ID,
      port: HABEAS_DISTRESS_PORT,
    },
  };
}
