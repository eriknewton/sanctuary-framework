/**
 * The ONE mapping from a live Castle Wall daemon health reading onto the
 * runtime snapshot `buildHealthEvidenceReport` consumes.
 *
 * It exists so the honesty gate in `evidence.ts` has a real production
 * producer. Before this, `CastleWallRuntimeSnapshot.statusResponse` was
 * populated by nothing outside tests: every `buildHealthEvidenceReport` call
 * site omitted `castleWall` entirely, so the lifecycle/runtime branch of
 * `evaluateCastleWall` had ZERO production call paths and its unit tests proved
 * a capability that was not shipped (AGENTS rules 4 and 9).
 *
 * Keeping the mapping in one function, rather than inline at each call site, is
 * the rule-5 point: a second hand-written copy would drift from this one and the
 * drift would be invisible until a status field changed meaning.
 */

import type { CastleWallHealth } from "../castle-wall/runtime/lifecycle.js";
// From the DRAIN module, never from the activation gate: the gate imports
// `castleWallSnapshotFromHealth` from this file, so importing the type back from
// there is a cycle. Must match `CastleWallDrainState` in
// `castle-wall/runtime/linux-audit-drain.ts`.
import type { CastleWallDrainState } from "../castle-wall/runtime/linux-audit-drain.js";
import type { CastleWallEvidenceChannel, CastleWallRuntimeSnapshot } from "./evidence.js";

/** Everything the caller knows that the daemon's own status cannot tell it. */
export interface CastleWallSnapshotContext {
  /** The platform the daemon runs on. Defaults to this process's platform. */
  platform?: string;
  /** Name of the detector producing this snapshot, for the evidence string. */
  detectorName?: string;
  /** Last observed enforcement event time, if the caller tracks one. */
  lastEventAt?: string | null;
  /**
   * What the drain LOOP is currently doing, three-valued. A healthy daemon whose
   * drain link is wedged is armed-but-not-draining, which must not read as
   * active enforcement; a daemon that merely answered "busy" is stalled, which
   * must not read as broken. Combined with `health.auditAckConfirmed` to derive
   * the snapshot's `evidenceChannel`.
   *
   * OMISSION MEANS UNOBSERVED, not healthy. This used to default to healthy
   * "because a caller that does not track the loop cannot report a fault" - but
   * not being able to report a fault is not the same as there being none, and
   * that default is precisely how the MCP server process would have published
   * `confirmed` for a channel it never saw. A caller that knows passes the
   * value; a caller that does not gets a verdict capped at `unknown`.
   */
  drainState?: CastleWallDrainState;
  /**
   * Why the channel is stalled or faulted, in the operator's words. Surfaced in
   * the evidence string; omitted when the channel is healthy.
   */
  drainStateReason?: string;
}

/**
 * Classify the signed-evidence channel from the two facts that describe it.
 *
 * Kept as one function so the precedence is stated once, worst first:
 *   `faulted`         no evidence arriving and the link is PROVEN broken.
 *   `unconfirmed_ack` evidence arriving, reclamation structurally unprovable
 *                     against this peer. A standing property of the peer, so it
 *                     outranks a transient stall.
 *   `drain_retrying`  evidence flow stalled on a retryable daemon condition.
 *                     Recovers on its own; escalates to `faulted` if it does not.
 *   `confirmed`       only when both dimensions are good.
 * Inlining this at each call site is how the states would drift apart.
 */
function classifyEvidenceChannel(
  auditAckConfirmed: boolean,
  drainState: CastleWallDrainState | undefined
): CastleWallEvidenceChannel {
  if (drainState === "faulted") return "faulted";
  if (!auditAckConfirmed) return "unconfirmed_ack";
  if (drainState === "retrying") return "drain_retrying";
  // Checked LAST among the non-confirmed states and BEFORE `confirmed`: an
  // unobserved channel is the weakest thing we can say, so anything the caller
  // positively observed outranks it - but it must never fall through to
  // `confirmed`, which is a claim nobody made.
  if (drainState === undefined) return "unobserved";
  return "confirmed";
}

/**
 * Build the runtime snapshot from a live health reading plus the raw status the
 * reading came from.
 *
 * `nftablesApplied` / `cgroupAttached` are deliberately left UNSET rather than
 * guessed from readiness: nothing in this process observes the kernel objects
 * directly, and `evaluateCastleWall` treats an unset detail as incomplete
 * (`degraded`) rather than as proof. That is the honest direction, and it is why
 * `kernel_runtime_ready` does not by itself produce an `active` verdict: a live
 * kernel runtime with NO agent wrapped is not enforcement (ASSURANCE_MATRIX
 * row 17), and this mapping must not be the place that quietly upgrades it.
 */
export function castleWallSnapshotFromHealth(
  health: CastleWallHealth,
  context: CastleWallSnapshotContext = {}
): CastleWallRuntimeSnapshot {
  // The status is taken FROM the health reading, never accepted as a separate
  // argument. An independent `status` parameter let a caller pair a readiness
  // verdict with the raw fields of a different, later observation; removing the
  // parameter removes the class, not just the one call site that had it wrong.
  const status = health.status;
  // Absence never manufactures confirmation on EITHER dimension: an omitted
  // `drainState` reads `unobserved`, and an unconfirmed peer still degrades.
  const evidenceChannel = classifyEvidenceChannel(
    health.auditAckConfirmed,
    context.drainState
  );
  const snapshot: CastleWallRuntimeSnapshot = {
    platform: context.platform ?? process.platform,
    configured: true,
    evidenceChannel,
    // The status round-trip completed, so the daemon answered. `unknown` would
    // understate a fact we positively observed.
    daemonUp: true,
    detectorName: context.detectorName ?? "Castle Wall Linux daemon (IPC status)",
    lastEventAt: context.lastEventAt ?? null,
    statusResponse: {
      uptime_seconds: status.uptime_seconds,
      loaded_rule_count: status.loaded_rule_count,
      no_wall_engaged: status.no_wall_engaged,
      loaded_manifest_signature_b64url: status.loaded_manifest_signature_b64url,
      manifest_state: status.manifest_state,
      lifecycle_state: status.lifecycle_state,
      runtime_state: status.runtime_state,
      kernel_runtime_ready: status.kernel_runtime_ready,
      enforcing: status.enforcing,
      runtime_health: status.runtime_health,
    },
  };
  if (evidenceChannel === "faulted") {
    // A wedged evidence channel is a degradation of the WALL, not of the
    // daemon's own runtime, so the daemon's reported status is left intact and
    // the degradation is carried by `evidenceChannel` (which `evaluateCastleWall`
    // acts on) plus this operator-facing reason.
    snapshot.reason =
      "signed enforcement evidence is not reaching the consumer (drain link unhealthy)" +
      (context.drainStateReason ? `: ${context.drainStateReason}` : "");
  } else if (evidenceChannel === "unobserved") {
    snapshot.reason =
      context.drainStateReason ??
      "the consumer-side drain loop is not observable from this process";
  } else if (evidenceChannel === "drain_retrying") {
    snapshot.reason =
      "signed enforcement evidence flow is stalled on a retryable daemon " +
      "condition; the drain loop is backing off and the link is not proven broken" +
      (context.drainStateReason ? `: ${context.drainStateReason}` : "");
  } else if (evidenceChannel === "unconfirmed_ack") {
    snapshot.reason =
      "the daemon does not negotiate audit_drain_ack_response, so reclaimed WAL " +
      "evidence is truncated without a confirmed ACK (operation continues on the " +
      "weaker pre-v2 basis)";
  }
  if (health.indeterminate) {
    snapshot.reason =
      snapshot.reason ??
      "the daemon does not currently report a proven kernel-runtime state";
  }
  return snapshot;
}
