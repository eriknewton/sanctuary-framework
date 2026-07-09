/**
 * Bug B (the one-flow gap): pure decision layer for "ensure a reachable Castle
 * Wall POLICY daemon before arming".
 *
 * `protect --hermes` (auto-provision "install and you're protected in one
 * flow") installs the AGENT's harness daemon and then tries to ARM Castle Wall.
 * The arm step probes `<fortress>/castle.sock` and CORRECTLY refuses if nothing
 * is listening -- arming with no policy daemon fail-closes the machine to
 * deny-all (filter on + daemon down = locked out, including SSH). On a stock box
 * the arm only succeeds because a boot daemon already serves the DEFAULT
 * fortress; on any OTHER fortress the arm refuses and the whole flow rolls back.
 *
 * The fix is to ENSURE a reachable policy daemon for the target fortress BEFORE
 * arming. This module is the PURE decision seam that maps the observed state
 * (socket reachability + the SINGLETON boot-service state) to the one action the
 * flow must take. The side-effecting composition (real socket probe, real
 * install-boot / uninstall-boot) lives in `wrap/auto-provision.ts`'s
 * `ensurePolicyDaemon` op; the orchestrator only ever sees the injected op's
 * result. Splitting the decision out here keeps the security-critical branch
 * table unit-testable without a real host or privileged binary.
 *
 * SINGLE WALL PER MACHINE (the security invariant this seam pins): the Castle
 * Wall boot service is a singleton -- one launchd label, one plist, per machine.
 * A boot service that targets a DIFFERENT fortress must NEVER be silently
 * swapped for this one; doing so would stand the machine's existing wall down.
 * We REFUSE instead and let the flow roll back (refuse, not swap).
 */

/** Observed state of the machine's Castle Wall policy daemon for a target fortress. */
export interface PolicyDaemonState {
  /** Whether `<fortressPath>/castle.sock` answered the arm's own daemon probe. */
  socketReachable: boolean;
  /**
   * Whether a well-formed singleton boot service is installed AND targets THIS
   * fortress (its `SANCTUARY_STORAGE_PATH` equals the target fortress path).
   */
  bootServiceForThisFortress: boolean;
  /**
   * Whether the matching singleton boot service is installed AND currently
   * certified live/stable under launchd. A socket can be reachable because a
   * transient/manual daemon is running; only this field can justify a no-op.
   */
  bootServiceReadyForThisFortress: boolean;
  /**
   * Whether ANY well-formed singleton boot service is installed (for this
   * fortress OR a different one). `bootServiceForThisFortress` implies this.
   */
  bootServiceForAnyFortress: boolean;
}

/**
 * The one action the flow must take to ensure a reachable policy daemon for the
 * target fortress before arming.
 *   - "noop": the socket already answers AND a matching persistent boot
 *     service is installed and certified live for this fortress; nothing to
 *     do, nothing to tear down.
 *   - "install-fresh": NO boot service exists for ANY fortress -> stand up the
 *     singleton boot service for THIS fortress. This also covers the Bug D
 *     transient-daemon state: a daemon answers NOW, but no persistent boot
 *     service exists, so arming would still fail the reboot-survival guard.
 *     THIS run created the machine's persistent wall from nothing, so a later
 *     abort MUST tear it back down (restoring the prior "no wall" state).
 *   - "restart-existing": a boot service for THIS fortress is installed but it
 *     is not ready/live enough to no-op (including the Bug D shape where a
 *     transient daemon answers the socket while launchd is stopped) ->
 *     (re)bootstrap + verify it. It PRE-EXISTED, so a later abort must NOT tear
 *     it down (booting out working infrastructure over a transient failure is
 *     destructive -- R6-3 rationale, one wall over).
 *   - "refuse-conflict": a boot service is installed for a DIFFERENT fortress ->
 *     REFUSE (one machine runs one wall; do not swap). The flow rolls back.
 */
export type PolicyDaemonAction =
  | "noop"
  | "install-fresh"
  | "restart-existing"
  | "refuse-conflict";

/**
 * Map the observed policy-daemon state to the single action the flow must take.
 * Pure: no I/O. Fail-closed ordering -- a matching persistent boot service is
 * mandatory even when the socket answers NOW. A transient/manual daemon without
 * a matching, ready boot service cannot satisfy the arm guard, so it must drive
 * install-boot before arming.
 */
export function resolvePolicyDaemonAction(state: PolicyDaemonState): PolicyDaemonAction {
  if (state.socketReachable && state.bootServiceReadyForThisFortress) {
    return "noop";
  }
  if (!state.bootServiceForAnyFortress) {
    return "install-fresh";
  }
  if (state.bootServiceForThisFortress) {
    return "restart-existing";
  }
  return "refuse-conflict";
}
