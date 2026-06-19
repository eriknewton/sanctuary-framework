/**
 * Sanctuary v1.1 — Agent liveness staleness
 *
 * A hub `LocalAgentRecord.status` of `active` is a LIVENESS claim ("this agent
 * is up and being protected right now"). The stored status is the last value
 * written and is never aged, so a crashed or silently-dead agent keeps reading
 * `active` indefinitely while the dashboard's ~5s poll re-renders the stale
 * state, manufacturing a false impression of fresh confirmation.
 *
 * This module is the single authority for aging a stale `active` down to
 * `unknown` based on `last_activity_at`. It lives in the contracts layer so both
 * the hub read-projection (which ages the status it serves) and the dashboard
 * status mapping (which renders it) share one definition. Pure, no I/O.
 */

import type { HubAgentStatus } from "./constants.js";

/**
 * Liveness staleness window for an `active` agent, in milliseconds.
 *
 * The dashboard polls roughly every 5 seconds and `last_activity_at` is stamped
 * on every status/policy/template mutation. We age an `active` agent whose last
 * activity is older than this window down to `unknown`: we have not heard from
 * it recently enough to assert it is live. The window is deliberately generous
 * relative to the 5s poll (a genuinely-busy or quietly-idle-but-live agent
 * stamps activity well inside it) so a healthy agent is never falsely aged out,
 * while a dead one stops claiming liveness within a couple of minutes.
 * Two minutes = 24 poll cycles of silence.
 *
 * JUDGMENT CALL (flag for review): 120s is a heuristic, not a contract. An agent
 * with legitimately long quiet periods between activity stamps could read
 * `unknown` here even while live; that is the conservative, honest direction
 * (under-claim liveness rather than over-claim it). A future heartbeat that
 * stamps `last_activity_at` on a fixed cadence would let this window track the
 * cadence directly. Only `active` is aged; explicit states (paused,
 * locked_down, error, unwrapping, restarting, unknown) are operator/system
 * facts that do not decay with silence.
 */
export const ACTIVE_LIVENESS_STALENESS_MS = 120_000;

/**
 * Compute the effective status given liveness evidence. An `active` status is
 * downgraded to `unknown` when `last_activity_at` is missing, unparseable, or
 * older than {@link ACTIVE_LIVENESS_STALENESS_MS}. All other statuses pass
 * through unchanged: they are explicit states, not liveness inferences, so
 * silence does not age them.
 *
 * Because the per-agent attestation badge renders "protected / verified" only
 * for an `active` status, aging a stale `active` to `unknown` also drops the
 * verified badge for a dead agent, which is the honest outcome: absence of
 * recent evidence must not render as a current attestation.
 */
export function effectiveLivenessStatus(
  status: HubAgentStatus,
  lastActivityAt: string | null | undefined,
  now: number = Date.now(),
  windowMs: number = ACTIVE_LIVENESS_STALENESS_MS,
): HubAgentStatus {
  if (status !== "active") return status;
  if (!lastActivityAt) return "unknown";
  const ts = new Date(lastActivityAt).getTime();
  if (Number.isNaN(ts)) return "unknown";
  if (now - ts > windowMs) return "unknown";
  return "active";
}
