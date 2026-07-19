/**
 * THE CLAIM REGISTER for the exclusive-egress subsystem (`egress-gate/` and
 * `castle-wall/provision/`), fix-round 3, 2026-07-19.
 *
 * WHY THIS FILE EXISTS. Across three adversarial gate rounds this subsystem
 * produced the SAME defect four times at four different altitudes:
 *
 *   1. the flow promised a restart seven abort sites never delivered;
 *   2. the fix promised a restore the failing path never performed;
 *   3. `restoreRunningHarness` derived "restarted" from a pid existing rather
 *      than from the restored plist being the loaded unit;
 *   4. `runReleaseBarrierSequence` reasserted "parked" by INTENT -- because
 *      `bootoutJob` did not throw -- and only checked liveness after the
 *      release had already completed.
 *
 * Four instances is not bad luck. It is a systemic property: in this
 * subsystem, success is habitually derived from CONTROL FLOW (a call
 * returned, no error was thrown, a branch was reached, an exit code was zero)
 * instead of from an OBSERVATION of state. Fixing only the site a reviewer
 * happens to name guarantees a fifth instance in the next round.
 *
 * THE RULE THIS REGISTER ENFORCES. Every site that hands a caller or the
 * operator a positive assertion about host state -- running, stopped,
 * disabled, installed, removed, armed, restored, flushed, verified -- must be
 * exactly one of:
 *
 *   - `observed`         the claim is gated on a read-back of real state;
 *   - `weakened`         the claim was narrowed to state only what was seen;
 *   - `documented-bound` the claim is control-flow derived, and `unobserved`
 *                        names precisely what was NOT read back.
 *
 * Silence is not an option. A claim that is neither observed, weakened, nor
 * documented is a defect, and {@link CLAIM_SITES} being a total `Record` over
 * {@link ClaimSiteId} makes an undeclared id a COMPILE error rather than a
 * review miss (the same shape `ARTIFACT_SCOPES` uses in `evidence-pack`).
 *
 * WHAT THE GUARD CATCHES, HONESTLY. `claim-basis-structural.test.ts` scans
 * both directories for claim-shaped literals and fails when a file's count
 * changes without a corresponding registry update. That is a FAILING TEST, not
 * a compile error, and its reach is exactly the detector's literal set: a new
 * claim written in a shape the detector does not match (most importantly, a
 * `Promise<void>` whose contract is "this resolving means state X holds") is
 * NOT caught automatically. Those are declared here by hand and marked
 * `detectorBlind`. Read that as the guard's stated bound, not as a claim of
 * completeness.
 */

/** How a claim is justified. See the file header for the rule. */
export type ClaimBasis = "observed" | "weakened" | "documented-bound";

/** One claim-producing site. */
export interface ClaimSiteDeclaration {
  /** Repo-relative source file. */
  readonly file: string;
  /** The symbol the claim lives in; the guard asserts it still exists. */
  readonly symbol: string;
  /** The claim in plain words -- what a reader is entitled to conclude. */
  readonly claim: string;
  readonly basis: ClaimBasis;
  /**
   * REQUIRED for `documented-bound`: exactly what is not read back. Forbidden
   * for `observed` (if something is unobserved, the row is not observed).
   */
  readonly unobserved?: string;
  /**
   * True when the claim is a `Promise<void>` resolving, a string, or another
   * shape the literal detector cannot see. Declared by hand; the guard cannot
   * find a new one for you.
   */
  readonly detectorBlind?: true;
}

/**
 * The claim-site ids. Adding a site means adding an id here, which makes the
 * missing {@link CLAIM_SITES} row a compile error.
 */
export type ClaimSiteId =
  // --- egress-gate/harness-daemon.ts ---
  | "harness-daemon.status"
  | "harness-daemon.stable-running"
  | "harness-daemon.await-stopped"
  | "harness-daemon.read-disabled-override"
  | "harness-daemon.set-job-disabled"
  | "harness-daemon.install"
  | "harness-daemon.install-reload"
  | "harness-daemon.kickstart"
  | "harness-daemon.uninstall-stopped"
  | "harness-daemon.uninstall-remove"
  | "harness-daemon.bootout-not-loaded"
  | "harness-daemon.bootout-in-progress"
  // --- egress-gate/release-barrier.ts ---
  | "release-barrier.write-into-hold-dir"
  | "release-barrier.parked-install-standdown-notice"
  | "release-barrier.parked-install-hold-removal"
  | "release-barrier.parked-install-stopped"
  | "release-barrier.revert-plist-restored"
  | "release-barrier.revert-harness-restarted"
  | "release-barrier.revert-restored-verdict"
  | "release-barrier.revert-clean-host"
  | "release-barrier.park-cleanup-hold-removed"
  | "release-barrier.park-cleanup-job-disabled"
  | "release-barrier.park-cleanup-carried"
  | "release-barrier.reassert-parked-stopped"
  | "release-barrier.probe-running"
  | "release-barrier.released"
  | "release-barrier.released-repark-failed"
  | "release-barrier.parked-outcome-flags"
  // --- egress-gate/arming-wiring.ts ---
  | "arming-wiring.port-owner"
  | "arming-wiring.root-dir-ensure"
  | "arming-wiring.atomic-root-write"
  | "arming-wiring.bring-up"
  | "arming-wiring.wait-gate-runtime"
  | "arming-wiring.bootstrap-gate-daemon-for-boot"
  | "arming-wiring.barrier-disable-enable"
  | "arming-wiring.barrier-bootstrap"
  | "arming-wiring.barrier-bootout"
  | "arming-wiring.barrier-remove-hold"
  | "arming-wiring.barrier-write-hold"
  | "arming-wiring.rearm-install-noop"
  | "arming-wiring.rearm-probed"
  | "arming-wiring.verify-gate"
  | "arming-wiring.commit-generation"
  | "arming-wiring.write-released-plist"
  | "arming-wiring.restore-parked-plist"
  | "arming-wiring.harness-status"
  | "arming-wiring.start-harness-coarse"
  | "arming-wiring.restore-coarse-composition"
  | "arming-wiring.verify-job-disabled"
  | "arming-wiring.verify-parked-persistent"
  | "arming-wiring.park-persistently"
  | "arming-wiring.park-for-unprotect"
  | "arming-wiring.sole-user-invariant"
  | "arming-wiring.bootout-gate-daemon"
  | "arming-wiring.invalidate-oracle-token"
  | "arming-wiring.revoke-credential"
  | "arming-wiring.remove-gate-surfaces"
  | "arming-wiring.remove-registry-entry-flushed"
  | "arming-wiring.reassert-parked-without-context"
  | "arming-wiring.boot-supervisor-shared-label-skip"
  | "arming-wiring.posture-gate-process-up"
  | "arming-wiring.posture-port-owner-verified"
  // --- egress-gate, other modules ---
  | "anchor-registry.apply-union-flush"
  | "pf-anchor.arm"
  | "pf-anchor.arm-union"
  | "pf-anchor.disarm"
  | "liveness-oracle.mint"
  | "liveness-oracle.verify"
  | "runtime-fs-plan.apply"
  | "runtime-fs-plan.mkdir-lstat"
  | "gate-credential.verify"
  // --- castle-wall/provision ---
  | "provision-account.execute-plan-uid"
  | "provision-egress.publish-rules"
  | "provision-egress.scrub-early-return"
  | "provision-egress.scrub-survivors"
  | "provision-uid-gate.uid-exists"
  | "provision-verify.probe-all"
  | "provision-rehome.step-restored"
  | "provision-rehome.fully-restored"
  | "provision-exclusive-arm.exclusive-armed"
  | "provision-exclusive-arm.coarse-composition-restored"
  | "provision-exclusive-arm.harness-started-coarse"
  | "provision-exclusive-arm.degraded-coarse-active"
  | "provision-exclusive-arm.parked-state-verified"
  | "provision-exclusive-arm.boot-parked-flags"
  | "provision-exclusive-unprotect.flushed-print"
  | "provision-exclusive-unprotect.unprotected"
  | "provision-orchestrate.harness-restore-note-restarted"
  | "provision-orchestrate.harness-restore-note-put-back"
  | "provision-orchestrate.disarmed"
  | "provision-orchestrate.rules-scrubbed"
  | "provision-orchestrate.armed"
  | "provision-orchestrate.rehome-restored-note"
  | "provision-unprovision.disarm-ok"
  | "provision-unprovision.uninstall-daemon-ok"
  | "provision-unprovision.scrub-ok"
  | "provision-unprovision.restore-rehome-ok"
  | "provision-unprovision.fully-ok";

const EG = "server/src/egress-gate";
const CW = "server/src/castle-wall/provision";

/**
 * The register. Total over {@link ClaimSiteId} -- a missing row does not
 * compile.
 */
export const CLAIM_SITES: Record<ClaimSiteId, ClaimSiteDeclaration> = {
  // ---------------------------------------------------------------- daemon
  "harness-daemon.status": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "agentHarnessDaemonStatus",
    claim: "launchd knows / does not know this service, and it has this pid",
    basis: "observed",
  },
  "harness-daemon.stable-running": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "agentHarnessDaemonStableRunning",
    claim: "the job held the same pid across consecutive samples",
    basis: "observed",
  },
  "harness-daemon.await-stopped": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "awaitHarnessStoppedVia",
    claim: "this is the last status sampled while waiting for the job to stop",
    basis: "observed",
  },
  "harness-daemon.read-disabled-override": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "readAgentHarnessJobDisabledOverride",
    claim: "launchd's persistent override table does / does not carry this label",
    basis: "observed",
  },
  "harness-daemon.set-job-disabled": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "setAgentHarnessJobDisabled",
    claim: "the persistent override state is now what was asked for",
    basis: "observed",
    detectorBlind: true,
  },
  "harness-daemon.install": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "installAgentHarnessDaemon",
    claim: "the plist is installed and the job is running that plist",
    basis: "observed",
    detectorBlind: true,
  },
  "harness-daemon.install-reload": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "installAgentHarnessDaemon",
    claim: "when the bytes changed, the old unit stopped before the new one loaded",
    basis: "observed",
    detectorBlind: true,
  },
  "harness-daemon.kickstart": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "kickstartAgentHarnessDaemon",
    claim: "the job was started and holds a stable pid",
    basis: "observed",
    detectorBlind: true,
  },
  "harness-daemon.uninstall-stopped": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "uninstallAgentHarnessDaemon",
    claim: "the job settled to stopped before the unit file was touched",
    basis: "observed",
    detectorBlind: true,
  },
  "harness-daemon.uninstall-remove": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "uninstallAgentHarnessDaemon",
    claim: "the unit file is gone",
    basis: "documented-bound",
    unobserved:
      "the plist path is never stat'd after `removeFile`. Bounded: the job is proven stopped first, so a " +
      "surviving file cannot strand a LIVE harness -- the fail-open direction is closed; only the tidiness " +
      "claim rests on the remove resolving.",
    detectorBlind: true,
  },
  "harness-daemon.bootout-not-loaded": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "launchctlBootoutWasNotLoaded",
    claim: "this bootout result is consistent with the job not being loaded",
    basis: "weakened",
    unobserved:
      "nothing -- the predicate deliberately decides only whether to refuse EARLY or to proceed to an " +
      "authoritative `launchctl print` re-read. Every caller now performs that re-read (fix-round 3 made the " +
      "release sequence, the last exception, honour it).",
  },
  "harness-daemon.bootout-in-progress": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "launchctlBootoutWasInProgress",
    claim: "the stop was accepted and is still running down",
    basis: "weakened",
    unobserved:
      "nothing is claimed about the job being gone; the predicate exists precisely to send the caller into a " +
      "settle loop instead of letting it conclude either way.",
  },

  // -------------------------------------------------------- release barrier
  "release-barrier.write-into-hold-dir": {
    file: `${EG}/release-barrier.ts`,
    symbol: "writeIntoHoldDir",
    claim: "the file is placed inside the root-owned hold directory",
    basis: "documented-bound",
    unobserved:
      "the directory's ownership/mode after `chown`/`chmod`, and the written bytes. The PATH-safety half is " +
      "observed (composition from a directory plus a bare filename, plus the ensure's lstat kind check).",
    detectorBlind: true,
  },
  "release-barrier.parked-install-standdown-notice": {
    file: `${EG}/release-barrier.ts`,
    symbol: "executeParkedHarnessInstall",
    claim: "the operator is told the pre-existing job was unloaded and stays stopped unless the gate commits",
    basis: "weakened",
    unobserved:
      "printed on a zero bootout exit, BEFORE the settle. Reworded in fix-round 2 to state the mechanism plus " +
      "the caveat rather than promise an outcome; the authoritative stopped assertion follows and refuses.",
    detectorBlind: true,
  },
  "release-barrier.parked-install-hold-removal": {
    file: `${EG}/release-barrier.ts`,
    symbol: "executeParkedHarnessInstall",
    claim: "no stale hold file remains, so the wrapper refuses every start",
    basis: "documented-bound",
    unobserved:
      "the hold path is not stat'd after `removeFile`; the park assertion that follows checks run-state only. " +
      "Bounded: the plist written in the same call embeds the parked expected-generation, which the wrapper " +
      "refuses unconditionally, so a surviving hold file alone cannot release anything.",
    detectorBlind: true,
  },
  "release-barrier.parked-install-stopped": {
    file: `${EG}/release-barrier.ts`,
    symbol: "executeParkedHarnessInstall",
    claim: "the harness job is not running after the parked install",
    basis: "observed",
    detectorBlind: true,
  },
  "release-barrier.revert-plist-restored": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim: "the prior plist bytes are back on disk (or the file is gone)",
    basis: "observed",
  },
  "release-barrier.revert-harness-restarted": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim: "the job was running before, and the RESTORED plist is what is loaded and running now",
    basis: "observed",
  },
  "release-barrier.revert-restored-verdict": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim: "the operator's agent is back the way it was before this run",
    basis: "observed",
  },
  "release-barrier.revert-clean-host": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim: "the parked plist and the disable this run created on a clean host are gone",
    basis: "observed",
  },
  "release-barrier.park-cleanup-hold-removed": {
    file: `${EG}/release-barrier.ts`,
    symbol: "parkCleanup",
    claim: "the release hold file is confirmed absent",
    basis: "observed",
  },
  "release-barrier.park-cleanup-job-disabled": {
    file: `${EG}/release-barrier.ts`,
    symbol: "parkCleanup",
    claim: "the job is confirmed disabled in launchd's persistent override database",
    basis: "observed",
  },
  "release-barrier.park-cleanup-carried": {
    file: `${EG}/release-barrier.ts`,
    symbol: "parkCleanup",
    claim: "a state this call did not act on still holds",
    basis: "weakened",
    unobserved:
      "nothing is assumed by default any more: a skipped step reports FALSE unless the caller explicitly " +
      "carries an observation forward, and the one caller that does (post-re-park cleanup) carries a flag its " +
      "own preceding `disableJob` read back.",
  },
  "release-barrier.reassert-parked-stopped": {
    file: `${EG}/release-barrier.ts`,
    symbol: "probeHarnessStopped",
    claim: "the pre-existing harness was stopped before the release sequence proceeded",
    basis: "observed",
  },
  "release-barrier.probe-running": {
    file: `${EG}/release-barrier.ts`,
    symbol: "probeHarnessRunning",
    claim: "the job holds a stable running pid",
    basis: "observed",
  },
  "release-barrier.released": {
    file: `${EG}/release-barrier.ts`,
    symbol: "runReleaseBarrierSequence",
    claim: "the harness is released: stopped first, then confined and running under the committed generation",
    basis: "observed",
  },
  "release-barrier.released-repark-failed": {
    file: `${EG}/release-barrier.ts`,
    symbol: "runReleaseBarrierSequence",
    claim: "released and running, but the persistent boot state is NOT re-parked",
    basis: "observed",
  },
  "release-barrier.parked-outcome-flags": {
    file: `${EG}/release-barrier.ts`,
    symbol: "runReleaseBarrierSequence",
    claim: "on this abort the hold file is gone and the job is disabled",
    basis: "observed",
  },

  // --------------------------------------------------------- arming wiring
  "arming-wiring.port-owner": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "verifyLoopbackTcpPortOwner",
    claim: "the listener on this port is that pid, uid and start-time",
    basis: "observed",
  },
  "arming-wiring.root-dir-ensure": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "applyRootOwnedDirEnsure",
    claim: "this directory exists, is a real directory, root-owned at this mode",
    basis: "documented-bound",
    unobserved:
      "`chown(0,0)` and `chmod(mode)` are not re-stat'd. The KIND half is observed (lstat refuses a symlink or " +
      "non-directory before ownership is applied), which is the half an attacker controls.",
    detectorBlind: true,
  },
  "arming-wiring.atomic-root-write": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "atomicRootWrite",
    claim: "the bytes are on disk at this path with this mode",
    basis: "documented-bound",
    unobserved: "no read-back or stat after the write+rename.",
    detectorBlind: true,
  },
  "arming-wiring.bring-up": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "productionBringUp",
    claim: "the gate daemon is up, owns its port, and pf is live for this generation",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.wait-gate-runtime": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "waitForGateRuntime",
    claim: "the daemon published a runtime state naming this generation, port and uid",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.bootstrap-gate-daemon-for-boot": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "bootstrapGateDaemonForBoot",
    claim: "the per-uid gate daemon is bootstrapped and started",
    basis: "documented-bound",
    unobserved:
      "when `expected === null` (the tombstoned / no-generation boot path) the runtime-state wait is skipped " +
      "entirely and only the bootstrap+kickstart exit codes back the claim. With a generation expected, " +
      "`waitForGateRuntime` observes it.",
    detectorBlind: true,
  },
  "arming-wiring.barrier-disable-enable": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "disableJob",
    claim: "the harness job's persistent override state is now disabled / enabled",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.barrier-bootstrap": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "bootstrapJob",
    claim: "the job is bootstrapped and kickstarted",
    basis: "documented-bound",
    unobserved:
      "exit codes only; no stable-pid check inside the op. Bounded: `runReleaseBarrierSequence` treats the " +
      "running claim as a SEPARATE stage and gates `released` on `probeHarnessRunning`, so a bootstrap that " +
      "starts nothing parks rather than releases.",
    detectorBlind: true,
  },
  "arming-wiring.barrier-bootout": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "bootoutJob",
    claim: "the harness job is stopped",
    basis: "weakened",
    unobserved:
      "the op itself reads only the exit code through the shared not-loaded predicate. It no longer stands " +
      "alone: fix-round 3 made the sequence's reassert-parked stage perform the authoritative settled " +
      "`launchctl print` re-read the predicate's safety argument assumes of every caller.",
    detectorBlind: true,
  },
  "arming-wiring.barrier-remove-hold": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "removeHoldFile",
    claim: "the per-uid release hold file is gone",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.barrier-write-hold": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "writeHoldFile",
    claim: "the hold file for this generation is on disk",
    basis: "documented-bound",
    unobserved:
      "the written bytes are not re-read or re-parsed. Bounded: the record is RENDERED (fail-closed field " +
      "validation) before the write, and the wrapper independently parses and cross-checks the file at exec " +
      "time, so a malformed or absent hold file refuses the start rather than releasing it.",
    detectorBlind: true,
  },
  "arming-wiring.rearm-install-noop": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "rearmAnchor",
    claim: "the pf anchor is armed for this uid",
    basis: "documented-bound",
    unobserved:
      "on the install path this returns ok unconditionally; the basis is that G3 armed pf earlier in the same " +
      "process, not a fresh probe. Bounded: `verifyGate` runs a LIVE oracle refresh immediately afterwards " +
      "and parks if pf is not live.",
  },
  "arming-wiring.rearm-probed": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "rearmAnchor",
    claim: "the committed pf union is re-asserted and live",
    basis: "observed",
  },
  "arming-wiring.verify-gate": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "verifyGate",
    claim: "gate up, port owner verified, generation surfaces matching, pf live right now",
    basis: "observed",
  },
  "arming-wiring.commit-generation": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "commitGeneration",
    claim: "this is the committed generation for this uid",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.write-released-plist": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "writeReleasedPlist",
    claim: "the released plist embedding this generation is on disk",
    basis: "documented-bound",
    unobserved:
      "the plist is not read back. Bounded: the wrapper re-reads the plist's embedded generation at exec time " +
      "and refuses on a mismatch, and the sequence gates `released` on the harness actually running.",
    detectorBlind: true,
  },
  "arming-wiring.restore-parked-plist": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "restoreParkedPlist",
    claim: "the parked barrier plist is back on disk",
    basis: "documented-bound",
    unobserved:
      "not read back at this site. `verifyHarnessParkedPersistent` DOES byte-compare the on-disk plist against " +
      "a freshly rendered parked plan, and is the check the unprotect / park paths gate on.",
    detectorBlind: true,
  },
  "arming-wiring.harness-status": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "harnessStatus",
    claim: "the harness holds a stable running pid (and carries its pid either way)",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.start-harness-coarse": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "startHarnessCoarse",
    claim: "the harness is running under the coarse plist",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.restore-coarse-composition": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "restoreCoarseCompositionProduction",
    claim: "the gate daemon is down, gate surfaces are gone, the manifest is back in coarse scope",
    basis: "documented-bound",
    unobserved:
      "the bootout exit code stands alone, and six `removeFile` calls are never stat'd. Bounded: this runs on " +
      "the LOUD degrade path, whose outcome is reported to the operator as non-green regardless; it is a " +
      "best-effort restoration, not a posture the flow subsequently claims as green.",
    detectorBlind: true,
  },
  "arming-wiring.verify-job-disabled": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "verifyHarnessJobDisabled",
    claim: "launchd's persistent override database shows this label disabled",
    basis: "observed",
  },
  "arming-wiring.verify-parked-persistent": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "verifyHarnessParkedPersistent",
    claim: "not running, persistently disabled, no hold file, parked plist on disk",
    basis: "observed",
  },
  "arming-wiring.park-persistently": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "parkHarnessPersistently",
    claim: "the full persistent parked posture holds",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.park-for-unprotect": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "parkHarnessForUnprotect",
    claim: "the harness is parked, with the plist either restored or removed",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.sole-user-invariant": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "assertSoleUserInvariant",
    claim: "no other committed non-tombstone uid exists",
    basis: "observed",
  },
  "arming-wiring.bootout-gate-daemon": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "bootoutGateDaemon",
    claim: "the egress-gate daemon is stopped",
    basis: "documented-bound",
    unobserved:
      "no `launchctl print` re-read and no check that the gate port stopped listening. Bounded: this runs only " +
      "on the unprotect teardown path, after the harness is proven parked -- a lingering gate daemon with no " +
      "confined agent to serve is a resource leak, not an egress path.",
    detectorBlind: true,
  },
  "arming-wiring.invalidate-oracle-token": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "invalidateOracleToken",
    claim: "the pf liveness token is gone",
    basis: "documented-bound",
    unobserved: "`rm(force)` is never stat'd. Bounded: tokens carry an expiry the gate verifies per-CONNECT.",
    detectorBlind: true,
  },
  "arming-wiring.revoke-credential": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "revokeCredential",
    claim: "the bearer credential and accept-state are gone",
    basis: "documented-bound",
    unobserved: "two `rm(force)` calls, never stat'd.",
    detectorBlind: true,
  },
  "arming-wiring.remove-gate-surfaces": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "removeGateSurfaces",
    claim: "every gate policy / config / runtime surface is removed",
    basis: "documented-bound",
    unobserved: "six `rm(force)` calls; no path is read back.",
    detectorBlind: true,
  },
  "arming-wiring.remove-registry-entry-flushed": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "removeRegistryEntry",
    claim: "the pf anchor was flushed empty when the last uid left",
    basis: "documented-bound",
    unobserved:
      "derived from the registry's own bookkeeping (`committed.length === 0`) and from `disarmPfAnchor` " +
      "returning, not from re-listing the anchor. Tracked with `pf-anchor.disarm`, which is the root gap.",
  },
  "arming-wiring.reassert-parked-without-context": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "reassertParkedWithoutContext",
    claim: "this uid's hold file is absent and its job is disabled",
    basis: "documented-bound",
    unobserved:
      "`holdFileRemoved` comes from `rm(force)` resolving and `jobDisabled` from a zero `launchctl disable` " +
      "exit; neither is read back. Bounded: this is the BOOT path's last-resort park for a uid whose context " +
      "could not be reconstructed -- it reports a best-effort park to the operator and never releases anything.",
  },
  "arming-wiring.boot-supervisor-shared-label-skip": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "startExclusiveEgressBootSupervisor",
    claim: "the shared harness job is not running before this uid is reported parked",
    basis: "observed",
    detectorBlind: true,
  },
  "arming-wiring.posture-gate-process-up": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "createExclusiveEgressPostureProducer",
    claim: "the gate process is up",
    basis: "documented-bound",
    unobserved:
      "derived from the EXISTENCE of a parseable runtime-state file; a stale file from a dead daemon reads as " +
      "up. Bounded: the sibling `port_owner_verified` probes the live listener, and posture consumers are " +
      "required to read the pair together.",
  },
  "arming-wiring.posture-port-owner-verified": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "createExclusiveEgressPostureProducer",
    claim: "the listener on the gate port is the gate daemon",
    basis: "observed",
  },

  // ------------------------------------------------- other egress-gate mods
  "anchor-registry.apply-union-flush": {
    file: `${EG}/anchor-registry.ts`,
    symbol: "applyUnion",
    claim: "the pf anchor is flushed empty and the enable reference released",
    basis: "documented-bound",
    unobserved: "delegates to `disarmPfAnchor`; see `pf-anchor.disarm`.",
    detectorBlind: true,
  },
  "pf-anchor.arm": {
    file: `${EG}/pf-anchor.ts`,
    symbol: "armPfAnchor",
    claim: "the anchor is armed and live for this policy",
    basis: "observed",
    detectorBlind: true,
  },
  "pf-anchor.arm-union": {
    file: `${EG}/pf-anchor.ts`,
    symbol: "armPfAnchorUnion",
    claim: "the union is loaded, hooked, pf enabled and live",
    basis: "observed",
    detectorBlind: true,
  },
  "pf-anchor.disarm": {
    file: `${EG}/pf-anchor.ts`,
    symbol: "disarmPfAnchor",
    claim: "the anchor is flushed empty and the pf enable reference released",
    basis: "documented-bound",
    unobserved:
      "exit codes of `pfctl -F all` and `pfctl -X` only; the anchor is never re-listed as empty, asymmetric " +
      "with the arm paths' settle-probes. This is the weakest link in the unprotect outcome and is the " +
      "highest-value remaining observation gap in this subsystem.",
    detectorBlind: true,
  },
  "liveness-oracle.mint": {
    file: `${EG}/liveness-oracle.ts`,
    symbol: "refresh",
    claim: "the pf anchor is live for this uid, port and generation",
    basis: "observed",
  },
  "liveness-oracle.verify": {
    file: `${EG}/liveness-oracle.ts`,
    symbol: "verifyLivenessToken",
    claim: "this attestation is authentic, unexpired, and bound to my expectations",
    basis: "observed",
  },
  "runtime-fs-plan.apply": {
    file: `${EG}/runtime-fs-plan.ts`,
    symbol: "applyGateRuntimeFsPlan",
    claim: "the runtime filesystem layout exists, root-owned, at these modes",
    basis: "documented-bound",
    unobserved:
      "`chown`/`chmod` results are never re-stat'd; a step succeeds when its op does not throw. The mkdir " +
      "half IS observed (lstat, refusing non-directories) -- see `runtime-fs-plan.mkdir-lstat`.",
    detectorBlind: true,
  },
  "runtime-fs-plan.mkdir-lstat": {
    file: `${EG}/runtime-fs-plan.ts`,
    symbol: "createRealGateRuntimeFsOps",
    claim: "this path is a real directory, not a symlink",
    basis: "observed",
    detectorBlind: true,
  },
  "gate-credential.verify": {
    file: `${EG}/gate-credential.ts`,
    symbol: "verifyGateCredential",
    claim: "the presented credential matches the stored one",
    basis: "observed",
  },

  // ------------------------------------------------------ castle-wall flow
  "provision-account.execute-plan-uid": {
    file: `${CW}/account.ts`,
    symbol: "executeAccountProvisionPlan",
    claim: "an account now exists at this uid",
    basis: "documented-bound",
    unobserved:
      "the uid returned is the PLANNED one; `createUser` resolving is the whole basis and no re-lookup " +
      "happens here. Bounded: `checkUidExistenceBeforeArm` (`uid-gate.ts`) performs the authoritative lookup " +
      "before anything is armed, and the flow parks if it disagrees.",
  },
  "provision-egress.publish-rules": {
    file: `${CW}/egress.ts`,
    symbol: "publishProvisionedEgressRules",
    claim: "every declared rule file is written and the daemon reloaded",
    basis: "documented-bound",
    unobserved:
      "written rule files are not read back, and `reload.ok` is the injected trigger's own control-flow " +
      "verdict. `staleRuleIdsRemoved` IS observed (a real `readdir`).",
  },
  "provision-egress.scrub-early-return": {
    file: `${CW}/egress.ts`,
    symbol: "scrubProvisionedEgressRules",
    claim: "there was nothing to scrub and the reload is fine",
    basis: "weakened",
    unobserved:
      "ENOENT on the rules directory returns `reloadOk: true` without invoking a reload. The claim is scoped " +
      "to 'no rules dir, so nothing to reload', which is what was observed.",
  },
  "provision-egress.scrub-survivors": {
    file: `${CW}/egress.ts`,
    symbol: "scrubProvisionedEgressRules",
    claim: "no provisioned rule file for this harness survives",
    basis: "observed",
  },
  "provision-uid-gate.uid-exists": {
    file: `${CW}/uid-gate.ts`,
    symbol: "checkUidExistenceBeforeArm",
    claim: "an account with this name exists at exactly this uid",
    basis: "observed",
  },
  "provision-verify.probe-all": {
    file: `${CW}/verify.ts`,
    symbol: "probeAll",
    claim: "every declared endpoint probe passed",
    basis: "observed",
  },
  "provision-rehome.step-restored": {
    file: `${CW}/rehome.ts`,
    symbol: "restoreRehomeSteps",
    claim: "this path is back at its original location",
    basis: "documented-bound",
    unobserved: "`ops.restore` returning `restored: true`; `sourcePath` is never stat'd in this module.",
  },
  "provision-rehome.fully-restored": {
    file: `${CW}/rehome.ts`,
    symbol: "restoreRehomeSteps",
    claim: "every non-skipped path came back cleanly",
    basis: "documented-bound",
    unobserved: "an aggregate over `provision-rehome.step-restored`; it inherits that row's basis exactly.",
  },
  "provision-exclusive-arm.exclusive-armed": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "runExclusiveEgressArming",
    claim: "exclusive egress is live and the harness is confined and running",
    basis: "observed",
    detectorBlind: true,
  },
  "provision-exclusive-arm.coarse-composition-restored": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "degradeLoud",
    claim: "the manifest is back in coarse, agent-reachable scope",
    basis: "documented-bound",
    unobserved:
      "`restoreCoarseComposition` resolving; see `arming-wiring.restore-coarse-composition`. LOAD-BEARING: " +
      "this flag gates whether the agent is started, so a false positive starts an agent into a composition " +
      "nobody re-read. It is reported to the operator as part of a non-green degrade outcome.",
  },
  "provision-exclusive-arm.harness-started-coarse": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "degradeLoud",
    claim: "the agent is running in coarse mode",
    basis: "observed",
  },
  "provision-exclusive-arm.degraded-coarse-active": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "degradeLoud",
    claim: "coarse is active, with these two component flags",
    basis: "documented-bound",
    unobserved:
      "carries `provision-exclusive-arm.coarse-composition-restored` verbatim onto every downstream posture " +
      "surface; the running half is observed.",
    detectorBlind: true,
  },
  "provision-exclusive-arm.parked-state-verified": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "failParked",
    claim: "the agent is verifiably parked despite the failure",
    basis: "observed",
    detectorBlind: true,
  },
  "provision-exclusive-arm.boot-parked-flags": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "runBootExclusiveEgressRelease",
    claim: "the agent is parked, with the hold file gone and the job disabled",
    basis: "documented-bound",
    unobserved:
      "carries whatever the barrier reported. Through the release sequence those flags are now observed; " +
      "through `reassertParkedWithoutContext` (the no-context boot fallback) they are not. Bounded: both are " +
      "PARK outcomes -- nothing is released on this path.",
    detectorBlind: true,
  },
  "provision-exclusive-unprotect.flushed-print": {
    file: `${CW}/exclusive-unprotect.ts`,
    symbol: "runUnprotectSequenceLocked",
    claim: "the pf anchor was flushed when the last agent left",
    basis: "documented-bound",
    unobserved: "see `pf-anchor.disarm`. The 'remaining agents re-verified live' clause IS settle-probed.",
    detectorBlind: true,
  },
  "provision-exclusive-unprotect.unprotected": {
    file: `${CW}/exclusive-unprotect.ts`,
    symbol: "runUnprotectSequenceLocked",
    claim: "this agent is fully unprotected: parked, surfaces gone, registry updated",
    basis: "documented-bound",
    unobserved:
      "an aggregate whose park and manifest-scrub components are observed and whose daemon bootout, token / " +
      "credential / surface removals and anchor flush are not. It inherits its weakest component.",
    detectorBlind: true,
  },
  "provision-orchestrate.harness-restore-note-restarted": {
    file: `${CW}/orchestrate.ts`,
    symbol: "harnessRestoreNote",
    claim: "the agent this run stood down was restarted and is running again",
    basis: "observed",
    detectorBlind: true,
  },
  "provision-orchestrate.harness-restore-note-put-back": {
    file: `${CW}/orchestrate.ts`,
    symbol: "harnessRestoreNote",
    claim: "the prior plist is back on disk",
    basis: "observed",
    detectorBlind: true,
  },
  "provision-orchestrate.disarmed": {
    file: `${CW}/orchestrate.ts`,
    symbol: "runProvisionFlowSteps",
    claim: "the Castle Wall filter was disarmed rather than left over a bricked agent",
    basis: "documented-bound",
    unobserved:
      "`ops.disarm()` resolving; the filter is not re-probed. Bounded: this is a ROLLBACK claim on an already " +
      "failing run, reported as a non-green outcome.",
  },
  "provision-orchestrate.rules-scrubbed": {
    file: `${CW}/orchestrate.ts`,
    symbol: "runProvisionFlowSteps",
    claim: "the provisioned egress rules were scrubbed",
    basis: "observed",
  },
  "provision-orchestrate.armed": {
    file: `${CW}/orchestrate.ts`,
    symbol: "runProvisionFlowSteps",
    claim: "the wall is armed and the agent was verified reachable and confined",
    basis: "observed",
    detectorBlind: true,
  },
  "provision-orchestrate.rehome-restored-note": {
    file: `${CW}/orchestrate.ts`,
    symbol: "describeRestoreForReason",
    claim: "the re-homed paths were restored to the operator",
    basis: "documented-bound",
    unobserved: "chains to `provision-rehome.fully-restored`; no path is stat'd in this module either.",
    detectorBlind: true,
  },
  "provision-unprovision.disarm-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovision",
    claim: "the wall is disarmed",
    basis: "documented-bound",
    unobserved: "`unprovisionOps.disarm()` resolving; the filter is not re-probed.",
  },
  "provision-unprovision.uninstall-daemon-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovision",
    claim: "the harness daemon is uninstalled",
    basis: "observed",
  },
  "provision-unprovision.scrub-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovision",
    claim: "no provisioned allow rule survives",
    basis: "observed",
  },
  "provision-unprovision.restore-rehome-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovision",
    claim: "every re-homed path was restored",
    basis: "documented-bound",
    unobserved: "chains to `provision-rehome.fully-restored`.",
  },
  "provision-unprovision.fully-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovisionFullyOk",
    claim: "the whole rollback succeeded",
    basis: "documented-bound",
    unobserved:
      "a conjunction over the four rows above; it inherits the weakest (disarm and restore-rehome).",
  },
};

/**
 * Per-file counts of DETECTOR-VISIBLE claim literals, as of fix-round 3.
 *
 * This is the ratchet. `claim-basis-structural.test.ts` recomputes these and
 * fails when a file's count moves, which forces the author of a new claim to
 * come here and classify it. A count that legitimately changes is updated in
 * the same commit as the claim -- that is the whole mechanism.
 *
 * BOUND, STATED PLAINLY: this catches claims the detector's literal set
 * matches. It does not catch a new `Promise<void>`-shaped claim; those live in
 * {@link CLAIM_SITES} with `detectorBlind: true` and are maintained by review.
 */
export const CLAIM_LITERAL_COUNTS: Readonly<Record<string, number>> = {
  [`${EG}/arming-wiring.ts`]: 21,
  [`${EG}/gate-credential.ts`]: 2,
  [`${EG}/harness-daemon.ts`]: 12,
  [`${EG}/liveness-oracle.ts`]: 2,
  [`${EG}/posture.ts`]: 1,
  [`${EG}/release-barrier.ts`]: 16,
  [`${CW}/egress.ts`]: 4,
  [`${CW}/exclusive-arm.ts`]: 4,
  [`${CW}/exclusive-unprotect.ts`]: 4,
  [`${CW}/orchestrate.ts`]: 9,
  [`${CW}/uid-gate.ts`]: 2,
  [`${CW}/unprovision.ts`]: 4,
  [`${CW}/verify.ts`]: 1,
};

/**
 * The field names the detector treats as claim-shaped when assigned `true`.
 * Kept here (not in the test) so a reviewer reads the detector's REACH in the
 * same file as the bound it is stated against.
 */
export const CLAIM_LITERAL_FIELDS: readonly string[] = [
  "ok",
  "restored",
  "plistRestored",
  "harnessRestarted",
  "holdFileRemoved",
  "jobDisabled",
  "flushed",
  "scrubbed",
  "live",
  "allReachable",
  "installed",
  "running",
  "up",
  "disarmed",
  "rolledBack",
  "fullyRestored",
  "coarseCompositionRestored",
  "harnessStartedCoarse",
  "parkedStateVerified",
  "reloadOk",
  "unprovisionFullyOk",
  "port_owner_verified",
  "rules_scrubbed",
  "serve",
  "known",
  "verified",
  "removed",
  "armed",
  "committed",
];

/** The regex the detector runs, built from {@link CLAIM_LITERAL_FIELDS}. */
export function claimLiteralRegex(): RegExp {
  return new RegExp(`\\b(${CLAIM_LITERAL_FIELDS.join("|")})\\s*[:=]\\s*true\\b|\\breturn true\\b`, "g");
}
