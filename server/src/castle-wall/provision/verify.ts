/**
 * Auto-provision Step 2 (Build 1): connectivity verification, both
 * pre-arm and post-arm (fix B2).
 *
 * FIX B2 (folded from the adversarial review): the naive flow's
 * "verify-before-arm" was circular and overclaimed. The harness daemon
 * (which drops the agent to the new uid) must exist BEFORE the agent can
 * run "as the new uid" at all, and there is no wall to reach "through the
 * gate" before arming (arming is what creates the gate). So this module
 * splits verification into two distinct, honestly-scoped checks:
 *
 *   - `verifyReachabilityBeforeArm` (post-daemon, PRE-arm): the re-homed
 *     agent, now running as the new uid via the just-installed harness
 *     daemon, is confirmed to reach its endpoints UNFILTERED. This proves
 *     re-home correctness (secrets, DNS, network reachability as the new
 *     identity) -- it proves NOTHING about allow-list correctness, because
 *     the wall is not yet armed. Any "through the gate" framing here would
 *     overclaim; this function's return value and doc comments never use
 *     that language.
 *   - `verifyReachabilityAfterArm` (POST-arm): after `enable --agent-uid`
 *     succeeds, re-check the SAME endpoints now that the wall is enforcing.
 *     Allow-list correctness is only provable at this point. On failure,
 *     the orchestrator fast-disarms (`disable`) rather than leaving a
 *     bricked-but-armed agent.
 *
 * Both functions share the same shape (probe a list of named endpoints,
 * report per-endpoint pass/fail) so the orchestrator can reuse one
 * fail-closed reporting path for either phase.
 */

/** A single endpoint the agent is expected to reach (LLM, Telegram, Gmail, ...). */
export interface EndpointProbeTarget {
  /** Human-readable name for reporting, e.g. "LLM (Venice)". */
  name: string;
  /** Injected probe: resolves true if reachable, false otherwise. Never throws (fail-closed false on any internal error). */
  probe(): Promise<boolean>;
}

/** Per-endpoint result. */
export interface EndpointProbeResult {
  name: string;
  reachable: boolean;
}

/** Aggregate verification result. */
export interface ConnectivityVerifyResult {
  allReachable: boolean;
  results: EndpointProbeResult[];
}

async function probeAll(targets: EndpointProbeTarget[]): Promise<ConnectivityVerifyResult> {
  const results: EndpointProbeResult[] = [];
  for (const target of targets) {
    let reachable: boolean;
    try {
      reachable = await target.probe();
    } catch {
      // Fail-closed: a probe that throws counts as unreachable, never as
      // "unknown, assume fine".
      reachable = false;
    }
    results.push({ name: target.name, reachable });
  }
  return { allReachable: results.every((r) => r.reachable), results };
}

/**
 * Pre-arm reachability check (post-daemon-install). Proves the re-homed
 * agent reaches its endpoints as the new uid, UNFILTERED. Does not, and
 * cannot, prove allow-list correctness -- the wall is not armed yet. On
 * `allReachable: false` the orchestrator must STOP before arming and
 * surface the failure + the backup/restore path (fix B2 ordering).
 */
export async function verifyReachabilityBeforeArm(
  targets: EndpointProbeTarget[],
): Promise<ConnectivityVerifyResult> {
  return probeAll(targets);
}

/**
 * Post-arm reachability re-check. Proves the allow-list the wall just
 * started enforcing actually permits the agent's real traffic. On
 * `allReachable: false` the orchestrator must fast-disarm (`disable`) and
 * surface the failure, rather than leaving a bricked-but-armed agent (fix
 * B2's disarm-rollback).
 */
export async function verifyReachabilityAfterArm(
  targets: EndpointProbeTarget[],
): Promise<ConnectivityVerifyResult> {
  return probeAll(targets);
}
