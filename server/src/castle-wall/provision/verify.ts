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
 *   - `verifyReachabilityBeforeArm` (post-daemon, PRE-arm)
 *   - `verifyReachabilityAfterArm` (POST-arm): after `enable --agent-uid`
 *     succeeds, re-probe the SAME endpoint list now that the wall is
 *     enforcing. On failure, the orchestrator fast-disarms (`disable`)
 *     rather than leaving a bricked-but-armed agent.
 *
 * FIX G5 (MEDIUM, 2026-07-07 re-gate 3 / fix-round 3): the doc block above
 * previously claimed both phases prove the agent "running as the new uid"
 * reaches its endpoints, including "network reachability as the new
 * identity." That overclaimed what the REAL probe list (built in
 * `wrap/auto-provision.ts`'s `hermesEndpointProbes`) actually proves: this
 * whole module runs in-process inside the ROOT `sanctuary protect` process
 * -- no setuid/seteuid/launchctl-asuser boundary crosses before either probe
 * call runs, so nothing here executes AS the re-homed agent's uid. What the
 * real probe list honestly proves, per phase:
 *   - each configured Hermes endpoint hostname (LLM, Telegram, Google MCP)
 *     is DNS-resolvable from this host/network right now (name resolution
 *     is not uid-scoped, so this is a true statement regardless of caller);
 *   - EVERY moved Hermes credential path (not just one) is present on disk
 *     and its owner/mode bits mark it readable BY THE TARGET UID, checked
 *     via `stat`, never assumed via a root `access()` call that would
 *     bypass the very permission bits this probe exists to check.
 * This module's `EndpointProbeTarget.probe` is an injected black box --
 * `verify.ts` itself has no opinion on what a probe checks -- so this
 * comment describes what the SHIPPED probe list actually proves, not a
 * property `verify.ts` itself guarantees. Proving the re-homed agent,
 * running AS the new uid, actually reaches these hosts end-to-end through
 * the enforcing wall is the Erik-present drill's job, never this module's
 * or the probe list's.
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
  // FIX F1 (BLOCKER, 2026-07-07 fix-round): an empty target list must never
  // resolve `allReachable: true` by vacuous truth. `Array.prototype.every`
  // on `[]` is `true`, which let a caller that (accidentally or otherwise)
  // supplies no probes sail through both the pre-arm and post-arm gates
  // unconditionally -- verification became a decorative no-op that always
  // reported success. Fail-closed instead: no endpoints configured means
  // nothing was actually verified, so report a single synthetic unreachable
  // result and force the orchestrator's abort/fast-disarm branch.
  if (targets.length === 0) {
    return {
      allReachable: false,
      results: [{ name: "(no endpoints configured)", reachable: false }],
    };
  }

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
 * Pre-arm probe pass (post-daemon-install). Runs whatever `targets` the
 * caller supplies -- per the module doc's FIX G5 note, the SHIPPED Hermes
 * probe list proves DNS-resolvability of each endpoint hostname plus
 * each moved credential's presence-and-readable-by-target-uid (via `stat`),
 * NOT that the re-homed agent, running as the new uid, actually reaches
 * these hosts end-to-end -- this module has no way to elevate to that uid
 * and cannot prove it. Does not, and cannot, prove allow-list correctness
 * either -- the wall is not armed yet. On `allReachable: false` the
 * orchestrator must STOP before arming and surface the failure + the
 * backup/restore path (fix B2 ordering).
 */
export async function verifyReachabilityBeforeArm(
  targets: EndpointProbeTarget[],
): Promise<ConnectivityVerifyResult> {
  return probeAll(targets);
}

/**
 * Post-arm re-probe of the SAME target list, now that the wall is
 * enforcing. Re-running the same DNS-resolvability + moved-credential-
 * readable probes after arming does not newly prove allow-list correctness
 * either (see the module doc's FIX G5 note) -- it re-confirms the same
 * narrow preconditions still hold post-arm. On `allReachable: false` the
 * orchestrator must fast-disarm (`disable`) and surface the failure, rather
 * than leaving a bricked-but-armed agent (fix B2's disarm-rollback). Proving
 * the allow-list actually permits the re-homed agent's real traffic, as the
 * new uid, is the Erik-present drill's job.
 */
export async function verifyReachabilityAfterArm(
  targets: EndpointProbeTarget[],
): Promise<ConnectivityVerifyResult> {
  return probeAll(targets);
}
