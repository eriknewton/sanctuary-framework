/**
 * Failure-mode detection constants.
 *
 * Spec §8.5 (canonical-audit-loss 24h grace), Architecture Walk Key 8
 * (incident-response ladder).
 *
 * The failure modes share the alert-class taxonomy below; each detector
 * module emits a sentinel_alert usage event tagged with its `failure_mode`.
 */

/**
 * Default grace window after canonical-audit-node unreachable before operator
 * prompt. Spec §8.5 — 24 hours past the heartbeat-miss threshold.
 *
 * Distinct identifier from guardian/constants's DEFAULT_CANONICAL_AUDIT_LOSS_GRACE_MS
 * so the mesh barrel can re-export both without collision.
 */
export const FAILURE_MODE_CANONICAL_AUDIT_LOSS_GRACE_MS =
  24 * 60 * 60 * 1000;

/** Default detector tick interval — small to keep latency low without burning CPU. */
export const DEFAULT_DETECTOR_TICK_INTERVAL_MS = 1_000;

/**
 * Stable identifier strings for the failure modes. These appear on the SSE
 * event shape (`mesh-health` event) and on the `capability_target` field of
 * every emitted sentinel_alert usage event so downstream filters can route by
 * failure mode.
 */
export const FAILURE_MODE = {
  OFFLINE: "offline" as const,
  COMPROMISED: "compromised" as const,
  ROLLBACK: "rollback" as const,
  SPLIT_BRAIN: "split_brain" as const,
  CANONICAL_AUDIT_LOSS: "canonical_audit_loss" as const,
  /**
   * QI-02-F12. A verified peer's event was refused for a reason that says
   * nothing about the peer's integrity: a freshness window this node's clock
   * put out of range, or a local capacity/correlation bound. ADDITIVE sixth
   * mode; the five above keep their exact strings, so no existing SSE
   * consumer, capability_target filter, or dashboard rollup changes meaning.
   *
   * `computeRollup` maps this to `degraded` (it is a flag, and it is not
   * COMPROMISED), which is the intended operator reading: "something is off
   * between these two nodes — most often a clock — look at it," never "this
   * node may be compromised."
   *
   * INVARIANT: a refusal whose cause is this node's own clock or its own local
   * bounds is never rendered as a compromise accusation against the peer. That
   * separation is what this mode exists to carry.
   */
  PEER_REFUSED: "peer_refused" as const,
};

export type FailureMode = (typeof FAILURE_MODE)[keyof typeof FAILURE_MODE];

/**
 * Pseudo-agent_id for mesh-level usage-event emission. The Agent Contract
 * requires every usage event to carry an agent_id; mesh-level alerts use a
 * predictable system-pseudo-agent identifier that downstream consumers can
 * filter on.
 */
export function meshSystemAgentId(nodeId: string): string {
  return `mesh:${nodeId}`;
}

/**
 * Stable capability_target string for failure-mode-emitted usage events.
 * Format: `mesh.failure_mode.<mode>:<target>` so audit viewers can filter by
 * mode.
 */
export function failureModeCapabilityTarget(
  mode: FailureMode,
  target: string
): string {
  return `mesh.failure_mode.${mode}:${target}`;
}

/**
 * Stable capability_target string for guardian-recovery emissions
 * (master_rotation acceptance, dmswitch propagation, post-recovery prompt).
 */
export function recoveryCapabilityTarget(
  kind:
    | "master_rotation"
    | "dmswitch"
    | "post_recovery_prompt"
    | "guardian_quorum",
  target: string
): string {
  return `mesh.recovery.${kind}:${target}`;
}
