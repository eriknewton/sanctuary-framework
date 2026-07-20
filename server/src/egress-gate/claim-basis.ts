/**
 * THE CLAIM REGISTER for the exclusive-egress subsystem (`egress-gate/`,
 * `castle-wall/provision/`, and the CLI render layer), fix-round 4,
 * 2026-07-19.
 *
 * WHY THIS FILE EXISTS. Across four adversarial gate rounds this subsystem
 * produced the SAME defect NINE times at nine different altitudes:
 *
 *   1. the flow promised a restart seven abort sites never delivered;
 *   2. the fix promised a restore the failing path never performed;
 *   3. `restoreRunningHarness` derived "restarted" from a pid existing rather
 *      than from the restored plist being the loaded unit;
 *   4. `runReleaseBarrierSequence` reasserted "parked" by INTENT -- because
 *      `bootoutJob` did not throw -- and only checked liveness after the
 *      release had already completed;
 *   5. the bootstrap / verify-running ABORT cleanups returned a clean
 *      `kind: "parked"` after the same `bootoutJob` resolved, with no settled
 *      read-back at all (round 3 fixed shape 4 by putting a probe beside ONE
 *      site; these two identical siblings survived);
 *   6. `degradeLoud`'s `harnessStartedCoarse: false` -- "we did not start it"
 *      -- was rendered at four altitudes, ending at `wrap/cli.ts`, as "The
 *      agent is PARKED (not running)", over the very process the round-3 gate
 *      had just refused to proceed past BECAUSE it was running;
 *   7. the boot path's contextless re-park returned a clean parked outcome
 *      whenever its ops resolved, and its one probe was a single unsettled
 *      sample that ignored `pid`;
 *   8. `harnessRestoreNote` told the operator "The agent is STOPPED" because
 *      the RESTORE had failed;
 *   9. and the same function's other branch said "is not running now" because
 *      this run had not started it.
 *
 * Nine instances is not bad luck, and it is not nine bugs. It is a systemic
 * property with a missing chokepoint: in this subsystem, success is habitually
 * derived from CONTROL FLOW (a call returned, no error was thrown, a branch
 * was reached, an exit code was zero) instead of from an OBSERVATION of state.
 * Rounds 1-3 each fixed the site a reviewer named, and each produced the next
 * round. Round 4 stopped doing that: {@link RUN_STATE_PROSE_SOLE_OWNER} is now
 * the ONLY constructor of a run-state claim, its output type is brand-locked
 * so no other module can forge one, and the outcome types that used to carry a
 * bare `kind: "parked"` now REQUIRE one. Instances 7, 8 and 9 above were found
 * BY THOSE MECHANISMS during the round that built them -- 7 by the compiler,
 * 8 and 9 by the prose guard -- not by a reviewer.
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
 *
 * WHAT ROUND 4 ADDED, AND WHAT IS STILL ONLY REVIEW:
 *
 *   - COMPILE ERROR (new): a run-state claim cannot be constructed outside
 *     `parked-claim.ts` -- the type is branded -- and `ReleaseBarrierOutcome`'s
 *     parked arm requires one, so returning "parked" without observing is no
 *     longer expressible. This is what caught instance 7.
 *   - COMPILE ERROR (new): a boolean-backed row cannot omit its negative
 *     branch (`branches: "boolean"` implies `negativeBranch`).
 *   - FAILING TEST (new): run-state PROSE outside the chokepoint, found by
 *     walking the TypeScript AST's string literals across both directories AND
 *     `wrap/cli.ts`. This is what caught instances 8 and 9.
 *   - STILL ONLY REVIEW: whether a given row is honestly marked `boolean`
 *     rather than `single`; whether a `detectorBlind` row's prose is accurate;
 *     and any run-state claim phrased in words not in
 *     {@link RUN_STATE_PROSE_PATTERNS}. The pattern list is a list, and a list
 *     is not a semantics.
 */

/** How a claim is justified. See the file header for the rule. */
export type ClaimBasis = "observed" | "weakened" | "documented-bound";

/** Where in the stack a claim is made. See {@link ClaimSiteBase.layer}. */
export type ClaimLayer = "compute" | "render";

/** The fields every row carries, whatever its branch shape. */
export interface ClaimSiteBase {
  /** Repo-relative source file. */
  readonly file: string;
  /** The symbol the claim lives in; the guard asserts it still exists. */
  readonly symbol: string;
  /** The claim in plain words -- what a reader is entitled to conclude. */
  readonly claim: string;
  readonly basis: ClaimBasis;
  /**
   * REQUIRED for `documented-bound` and `weakened`: exactly what is not read
   * back. Forbidden for `observed` (if something is unobserved, the row is not
   * observed).
   */
  readonly unobserved?: string;
  /**
   * True when the claim is a `Promise<void>` resolving, a string, or another
   * shape the literal detector cannot see. Declared by hand; the guard cannot
   * find a new one for you.
   */
  readonly detectorBlind?: true;
  /**
   * WHERE the claim is made (fix-round 4, Part B blind spot 2).
   *
   *   - `compute`: the claim is DERIVED here.
   *   - `render`: the claim is STATED to a human here.
   *
   * The round-4 HIGH was a `render` site. The register had 95 rows and ZERO on
   * the rendering layer: it audited where claims are computed, and so it was
   * certifying a subsystem whose output layer was unaudited, while the false
   * sentence the operator actually read lived in `wrap/cli.ts` (`grep -c
   * "wrap/cli" claim-basis.ts` returned 0). Rendering surfaces are now in
   * scope, and {@link RUN_STATE_PROSE_SOLE_OWNER} enforces the stronger rule
   * that keeps them nearly rowless.
   */
  readonly layer: ClaimLayer;
}

/**
 * What the FALSE branch of a boolean-backed claim is rendered to mean, and on
 * what basis. See {@link ClaimSiteDeclaration}.
 */
export interface ClaimNegativeBranch {
  /** What a reader is entitled to conclude from the FALSE value. */
  readonly claim: string;
  readonly basis: ClaimBasis;
  /** REQUIRED unless `basis` is `observed`; same rule as the positive branch. */
  readonly unobserved?: string;
}

/**
 * One claim-producing site.
 *
 * `branches` is REQUIRED, and it is fix-round 4's Part B shape fix. The
 * register was organised ONE ROW PER FLAG, and a boolean flag carries TWO
 * claims. The round-4 HIGH lived entirely in the negative space that shape
 * could not represent: `provision-exclusive-arm.harness-started-coarse` was
 * `basis: "observed"` and ACCURATE -- for its `true` branch, since
 * `startHarnessCoarse` resolving does observe a stable pid. There was no row
 * for what `false` was rendered to mean, and `false` -- which means "this run
 * did not start it" -- was rendered at four altitudes as "The agent is PARKED
 * (not running)", over a process that was demonstrably alive.
 *
 * So a boolean-backed row can no longer be declared without classifying BOTH
 * branches: `branches: "boolean"` makes `negativeBranch` structurally
 * required, and every row must say which shape it is, which forces the per-row
 * decision the old shape let an author skip in silence.
 *
 * HONEST BOUND: which rows are `boolean` is a REVIEW judgement, not a machine
 * check -- nothing stops a future author declaring a boolean-backed claim
 * `single`. What the type buys is that the question is now asked of every row
 * and answered in the file, instead of being unaskable.
 */
export type ClaimSiteDeclaration =
  | (ClaimSiteBase & {
      /** A single claim with no meaningful complement (a string, an outcome kind). */
      readonly branches: "single";
    })
  | (ClaimSiteBase & {
      /** A boolean / two-valued claim. BOTH branches must be classified. */
      readonly branches: "boolean";
      readonly negativeBranch: ClaimNegativeBranch;
    });

/**
 * The claim-site ids. Adding a site means adding an id here, which makes the
 * missing {@link CLAIM_SITES} row a compile error.
 */
export type ClaimSiteId =
  // --- egress-gate/parked-claim.ts (THE chokepoint, fix-round 4) ---
  | "parked-claim.assess"
  | "parked-claim.started-coarse-disposition"
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
  | "release-barrier.revert-run-state"
  | "release-barrier.park-cleanup-hold-removed"
  | "release-barrier.park-cleanup-job-disabled"
  | "release-barrier.park-cleanup-carried"
  | "release-barrier.reassert-parked-stopped"
  | "release-barrier.probe-running"
  | "release-barrier.released"
  | "release-barrier.released-repark-failed"
  | "release-barrier.parked-outcome-flags"
  | "release-barrier.parked-outcome-claim"
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
  | "arming-wiring.contextless-repark-claim"
  | "arming-wiring.assess-harness-parked"
  | "arming-wiring.boot-supervisor-shared-label-skip"
  | "arming-wiring.posture-gate-process-up"
  | "arming-wiring.posture-port-owner-verified"
  | "arming-wiring.gate-account-home-layout"
  // --- egress-gate, other modules ---
  | "anchor-registry.apply-union-flush"
  | "pf-anchor.arm"
  | "pf-anchor.arm-union"
  | "pf-anchor.disarm"
  | "liveness-oracle.mint"
  | "liveness-oracle.verify"
  | "runtime-fs-plan.apply"
  | "runtime-fs-plan.mkdir-lstat"
  | "gate-account.verify-record"
  | "gate-account.rollback-incomplete"
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
  | "provision-exclusive-arm.harness-disposition"
  | "provision-exclusive-arm.degraded-coarse-active"
  | "provision-exclusive-arm.parked-state-verified"
  | "provision-exclusive-arm.boot-parked-flags"
  | "provision-exclusive-arm.degrade-print"
  | "provision-exclusive-arm.boot-parked-print"
  | "provision-exclusive-unprotect.flushed-print"
  | "provision-exclusive-unprotect.unprotected"
  | "provision-orchestrate.harness-restore-note-restarted"
  | "provision-orchestrate.harness-restore-note-put-back"
  | "provision-orchestrate.harness-restore-note-not-restored"
  | "provision-orchestrate.disarmed"
  | "provision-orchestrate.rules-scrubbed"
  | "provision-orchestrate.armed"
  | "provision-orchestrate.rehome-restored-note"
  | "provision-unprovision.disarm-ok"
  | "provision-unprovision.uninstall-daemon-ok"
  | "provision-unprovision.scrub-ok"
  | "provision-unprovision.restore-rehome-ok"
  | "provision-unprovision.fully-ok"
  // --- wrap/cli.ts (THE RENDER LAYER -- had zero rows before fix-round 4) ---
  | "wrap-cli.degrade-agent-state";

const EG = "server/src/egress-gate";
const CW = "server/src/castle-wall/provision";

/**
 * The register. Total over {@link ClaimSiteId} -- a missing row does not
 * compile.
 */
export const CLAIM_SITES: Record<ClaimSiteId, ClaimSiteDeclaration> = {
  // ------------------------------------------------------- parked-claim.ts
  "parked-claim.assess": {
    file: `${EG}/parked-claim.ts`,
    symbol: "assessHarnessParked",
    claim:
      "the agent harness process is not running (`state: \"parked\"`), is running (`\"alive\"`), or " +
      "could not be established (`\"unknown\"`)",
    basis: "observed",
    layer: "compute",
    // NOT `branches: "boolean"` -- that is the entire point of the type. Three
    // named states, each carrying its own basis and its own operator sentence,
    // so there is no false branch left for a caller to reinterpret.
    branches: "single",
  },
  "parked-claim.started-coarse-disposition": {
    file: `${EG}/parked-claim.ts`,
    symbol: "startedCoarseDisposition",
    claim: "the agent is running in coarse-only mode",
    basis: "observed",
    layer: "compute",
    branches: "single",
    detectorBlind: true,
  },
  // ---------------------------------------------------------------- daemon
  "harness-daemon.status": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "agentHarnessDaemonStatus",
    claim: "launchd knows / does not know this service, and it has this pid",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "launchd does NOT know this service, or its state is unknowable",
      basis: "observed",
    },
  },
  "harness-daemon.stable-running": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "agentHarnessDaemonStableRunning",
    claim: "the job held the same pid across consecutive samples",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the pid was NOT stable across samples -- which is NOT 'the job is stopped'; a crash-looping process is unstable AND alive",
      basis: "weakened",
      unobserved:
        "nothing about liveness. The false branch deliberately says less than 'stopped'; a caller that needs 'stopped' must use `assessHarnessParked`, whose pid check is separate from `running` for exactly this reason.",
    },
  },
  "harness-daemon.await-stopped": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "awaitHarnessStoppedVia",
    claim: "this is the last status sampled while waiting for the job to stop",
    basis: "observed",
    layer: "compute",
    branches: "single",
  },
  "harness-daemon.read-disabled-override": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "readAgentHarnessJobDisabledOverride",
    claim: "launchd's persistent override table does / does not carry this label",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "launchd's override table does NOT carry this label",
      basis: "observed",
    },
  },
  "harness-daemon.set-job-disabled": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "setAgentHarnessJobDisabled",
    claim: "the persistent override state is now what was asked for",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "harness-daemon.install": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "installAgentHarnessDaemon",
    claim: "the plist is installed and the job is running that plist",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "harness-daemon.install-reload": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "installAgentHarnessDaemon",
    claim: "when the bytes changed, the old unit stopped before the new one loaded",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "harness-daemon.kickstart": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "kickstartAgentHarnessDaemon",
    claim: "the job was started and holds a stable pid",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "harness-daemon.uninstall-stopped": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "uninstallAgentHarnessDaemon",
    claim: "the job settled to stopped before the unit file was touched",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "harness-daemon.bootout-in-progress": {
    file: `${EG}/harness-daemon.ts`,
    symbol: "launchctlBootoutWasInProgress",
    claim: "the stop was accepted and is still running down",
    basis: "weakened",
    unobserved:
      "nothing is claimed about the job being gone; the predicate exists precisely to send the caller into a " +
      "settle loop instead of letting it conclude either way.",
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "release-barrier.parked-install-stopped": {
    file: `${EG}/release-barrier.ts`,
    symbol: "executeParkedHarnessInstall",
    claim: "the harness job is not running after the parked install",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "release-barrier.revert-plist-restored": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim: "the prior plist bytes are back on disk (or the file is gone)",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the prior bytes are NOT confirmed back on disk",
      basis: "observed",
    },
  },
  "release-barrier.revert-harness-restarted": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim: "the job was running before, and the RESTORED plist is what is loaded and running now",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "this run did NOT observe the restored plist loaded and running",
      basis: "weakened",
      unobserved:
        "whether any process is running. False means the restart was not proven; it is not a claim that the agent is down.",
    },
  },
  "release-barrier.revert-restored-verdict": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim: "the operator's agent is back the way it was before this run",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the pre-run state was NOT fully put back; the component rows say which part",
      basis: "weakened",
      unobserved:
        "a conjunction: false inherits from whichever component was not observed.",
    },
  },
  "release-barrier.revert-clean-host": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim: "the parked plist and the disable this run created on a clean host are gone",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "this was not a clean host, or the clean-host revert did not complete",
      basis: "observed",
    },
  },
  "release-barrier.revert-run-state": {
    file: `${EG}/release-barrier.ts`,
    symbol: "revertParkedHarnessInstall",
    claim:
      "what the agent harness's run state IS after a revert that did not put a running agent back",
    // The round-5 HIGH's remedy. The register had NO row for this claim
    // because the claim was not computed anywhere: `standDownStillStoppedAdvice`
    // asserted "the agent harness is STOPPED" straight from `wasRunning` plus
    // a failed restore. It is now a `ParkedClaim` from `assessHarnessParked`,
    // so it is observed, weakened, or explicitly unknown -- never inferred.
    basis: "observed",
    layer: "compute",
    branches: "single",
  },
  "release-barrier.park-cleanup-hold-removed": {
    file: `${EG}/release-barrier.ts`,
    symbol: "parkCleanup",
    claim: "the release hold file is confirmed absent",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "this call did NOT confirm the hold file gone",
      basis: "weakened",
      unobserved:
        "whether the file is present. False means the removal threw or was not attempted; it never means the file exists.",
    },
  },
  "release-barrier.park-cleanup-job-disabled": {
    file: `${EG}/release-barrier.ts`,
    symbol: "parkCleanup",
    claim: "the job is confirmed disabled in launchd's persistent override database",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "this call did NOT confirm the job disabled",
      basis: "weakened",
      unobserved:
        "whether the override is set. False means the disable threw or was not attempted; it never means the job is enabled.",
    },
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
    layer: "compute",
    branches: "single",
  },
  "release-barrier.reassert-parked-stopped": {
    file: `${EG}/release-barrier.ts`,
    symbol: "runReleaseBarrierSequence",
    claim: "the pre-existing harness was stopped before the release sequence proceeded",
    basis: "observed",
    layer: "compute",
    branches: "single",
    // The probe itself moved to `parked-claim.assess` in fix-round 4. It was
    // moved rather than copied: a stopped-probe any site could choose not to
    // call is exactly the shape that let two of its three sibling sites skip it
    // for four rounds.
    detectorBlind: true,
  },
  "release-barrier.probe-running": {
    file: `${EG}/release-barrier.ts`,
    symbol: "probeHarnessRunning",
    claim: "the job holds a stable running pid",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the job has no stable running pid",
      basis: "weakened",
      unobserved:
        "whether a process exists at all: an unstable pid reads false here. This probe answers 'did it come up?', NOT 'is it gone?'; the stopped direction is `assessHarnessParked`.",
    },
  },
  "release-barrier.released": {
    file: `${EG}/release-barrier.ts`,
    symbol: "runReleaseBarrierSequence",
    claim: "the harness is released: stopped first, then confined and running under the committed generation",
    basis: "observed",
    layer: "compute",
    branches: "single",
  },
  "release-barrier.released-repark-failed": {
    file: `${EG}/release-barrier.ts`,
    symbol: "runReleaseBarrierSequence",
    claim: "released and running, but the persistent boot state is NOT re-parked",
    basis: "observed",
    layer: "compute",
    branches: "single",
  },
  "release-barrier.parked-outcome-flags": {
    file: `${EG}/release-barrier.ts`,
    symbol: "runReleaseBarrierSequence",
    claim: "on this abort the hold file is gone and the job is disabled",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "on this abort one of the two could not be confirmed; `cleanupErrors` names which",
      basis: "weakened",
      unobserved:
        "the unconfirmed side is not re-read. False is 'not proven', never 'proven not'.",
    },
  },

  // --------------------------------------------------------- arming wiring
  "release-barrier.parked-outcome-claim": {
    file: `${EG}/release-barrier.ts`,
    symbol: "parkedOutcome",
    claim:
      "every abort of the release sequence reports the agent's run state from a settled observation " +
      "made by that abort, or explicitly declines to claim one",
    basis: "observed",
    layer: "compute",
    branches: "single",
    detectorBlind: true,
  },
  "arming-wiring.port-owner": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "verifyLoopbackTcpPortOwner",
    claim: "the listener on this port is that pid, uid and start-time",
    basis: "observed",
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.atomic-root-write": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "atomicRootWrite",
    claim: "the bytes are on disk at this path with this mode",
    basis: "documented-bound",
    unobserved: "no read-back or stat after the write+rename.",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.bring-up": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "productionBringUp",
    claim: "the gate daemon is up, owns its port, and pf is live for this generation",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.wait-gate-runtime": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "waitForGateRuntime",
    claim: "the daemon published a runtime state naming this generation, port and uid",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.barrier-disable-enable": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "disableJob",
    claim: "the harness job's persistent override state is now disabled / enabled",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.barrier-bootout": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "bootoutJob",
    claim: "the harness job is stopped",
    basis: "weakened",
    unobserved:
      "the op itself reads only the exit code through the shared not-loaded predicate. It does not stand " +
      "alone: EVERY parked outcome of the release sequence now performs the authoritative settled " +
      "`launchctl print` re-read that the predicate's safety argument assumes of every caller. " +
      "FIX-ROUND-4 CORRECTION: this row previously credited that re-read to the reassert-parked stage, " +
      "which was true of ONE caller. The bootstrap and verify-running abort cleanups also ran this op and " +
      "did NOT re-read, so the sentence was false for two reachable production callers -- Codex reproduced " +
      "a clean `parked` outcome over a modelled harness at `running: true, pid: 4242`. The claim is now " +
      "true of all of them because the re-read is the single `parkedOutcome` chokepoint rather than a " +
      "probe placed beside whichever site a review round named.",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.barrier-remove-hold": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "removeHoldFile",
    claim: "the per-uid release hold file is gone",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.rearm-probed": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "rearmAnchor",
    claim: "the committed pf union is re-asserted and live",
    basis: "observed",
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.verify-gate": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "verifyGate",
    claim: "gate up, port owner verified, generation surfaces matching, pf live right now",
    basis: "observed",
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.commit-generation": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "commitGeneration",
    claim: "this is the committed generation for this uid",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.harness-status": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "harnessStatus",
    claim: "the harness holds a stable running pid (and carries its pid either way)",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "no stable running pid -- and `pid` is STILL carried through, because an unstable pid is a live process",
      basis: "observed",
    },
  },
  "arming-wiring.start-harness-coarse": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "startHarnessCoarse",
    claim: "the harness is running under the coarse plist",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.verify-job-disabled": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "verifyHarnessJobDisabled",
    claim: "launchd's persistent override database shows this label disabled",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the override database does NOT show this label disabled, or could not be read",
      basis: "weakened",
      unobserved:
        "which of the two cases holds; that is distinguished in the caller's error text, not in the boolean.",
    },
  },
  "arming-wiring.verify-parked-persistent": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "verifyHarnessParkedPersistent",
    claim: "not running, persistently disabled, no hold file, parked plist on disk",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the full persistent parked posture does NOT hold; `problems` enumerates every failed check",
      basis: "observed",
    },
  },
  "arming-wiring.park-persistently": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "parkHarnessPersistently",
    claim: "the full persistent parked posture holds",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.park-for-unprotect": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "parkHarnessForUnprotect",
    claim: "the harness is parked, with the plist either restored or removed",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.sole-user-invariant": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "assertSoleUserInvariant",
    claim: "no other committed non-tombstone uid exists",
    basis: "observed",
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.invalidate-oracle-token": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "invalidateOracleToken",
    claim: "the pf liveness token is gone",
    basis: "documented-bound",
    unobserved: "`rm(force)` is never stat'd. Bounded: tokens carry an expiry the gate verifies per-CONNECT.",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.revoke-credential": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "revokeCredential",
    claim: "the bearer credential and accept-state are gone",
    basis: "documented-bound",
    unobserved: "two `rm(force)` calls, never stat'd.",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.remove-gate-surfaces": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "removeGateSurfaces",
    claim: "every gate policy / config / runtime surface is removed",
    basis: "documented-bound",
    unobserved: "six `rm(force)` calls; no path is read back.",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.remove-registry-entry-flushed": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "removeRegistryEntry",
    claim: "the pf anchor was flushed empty when the last uid left",
    basis: "documented-bound",
    unobserved:
      "derived from the registry's own bookkeeping (`committed.length === 0`) and from `disarmPfAnchor` " +
      "returning, not from re-listing the anchor. Tracked with `pf-anchor.disarm`, which is the root gap.",
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.reassert-parked-without-context": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "reassertParkedWithoutContext",
    claim: "this uid's hold file is absent and its job is disabled",
    basis: "documented-bound",
    unobserved:
      "`holdFileRemoved` comes from `rm(force)` resolving and `jobDisabled` from a zero `launchctl disable` " +
      "exit; neither is read back. Bounded, and the bound is now much tighter than it was: this is the BOOT " +
      "path's last-resort park for a uid whose context could not be reconstructed, it never releases " +
      "anything, and since fix-round 4 its RUN-STATE claim is separately gated on a settled " +
      "`assessHarnessParked` (`arming-wiring.contextless-repark-claim`) that throws to the distinct " +
      "`park-not-verified` outcome rather than reporting a park it did not observe. Only the hold-file and " +
      "disable flags remain control-flow derived.",
    layer: "compute",
    branches: "single",
  },
  "arming-wiring.boot-supervisor-shared-label-skip": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "startExclusiveEgressBootSupervisor",
    claim: "the shared harness job is not running before this uid is reported parked",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the shared harness job is running or unknowable; the caller throws to the DISTINCT `park-not-verified` outcome rather than reporting a park",
      basis: "observed",
    },
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
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "no runtime file is present",
      basis: "weakened",
      unobserved:
        "liveness on either branch. False is 'no runtime file', not 'the process is dead'; aggregate `exclusive` additionally requires `port_owner_verified`.",
    },
  },
  "arming-wiring.posture-port-owner-verified": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "createExclusiveEgressPostureProducer",
    claim: "the listener on the gate port is the gate daemon",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the listener on the gate port is NOT the gate daemon, or ownership could not be read",
      basis: "weakened",
      unobserved:
        "which of the two; the posture surface treats both as non-green.",
    },
  },

  "arming-wiring.gate-account-home-layout": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "ensureGateAccountHomeLayout",
    claim:
      "the gate account home/log directories and launchd stdout/stderr log files exist with the expected owner and mode",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },

  // ------------------------------------------------- other egress-gate mods
  "arming-wiring.contextless-repark-claim": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "assessHarnessParked",
    claim:
      "the boot path's contextless re-park settled the shared harness job stopped before reporting a park",
    basis: "observed",
    layer: "compute",
    branches: "single",
    detectorBlind: true,
  },
  "arming-wiring.assess-harness-parked": {
    file: `${EG}/arming-wiring.ts`,
    symbol: "assessHarnessParked",
    claim:
      "the install-time degrade path's run-state probe carries `pid` through a downgraded `running`, " +
      "so a crash-looping survivor reads as ALIVE rather than as parked",
    basis: "observed",
    layer: "compute",
    branches: "single",
    detectorBlind: true,
  },
  "anchor-registry.apply-union-flush": {
    file: `${EG}/anchor-registry.ts`,
    symbol: "applyUnion",
    claim: "the pf anchor is flushed empty and the enable reference released",
    basis: "documented-bound",
    unobserved: "delegates to `disarmPfAnchor`; see `pf-anchor.disarm`.",
    detectorBlind: true,
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the anchor was not flushed empty",
      basis: "documented-bound",
      unobserved:
        "pfctl exit codes only on both branches; the anchor is not re-listed either way.",
    },
  },
  "pf-anchor.arm": {
    file: `${EG}/pf-anchor.ts`,
    symbol: "armPfAnchor",
    claim: "the anchor is armed and live for this policy",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the anchor is not armed or not live; the caller fails closed",
      basis: "observed",
    },
  },
  "pf-anchor.arm-union": {
    file: `${EG}/pf-anchor.ts`,
    symbol: "armPfAnchorUnion",
    claim: "the union is loaded, hooked, pf enabled and live",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the union is not loaded, hooked, or live; the caller fails closed",
      basis: "observed",
    },
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
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the anchor was not flushed empty",
      basis: "documented-bound",
      unobserved:
        "pfctl exit codes only on both branches; the anchor is not re-listed either way. This remains the highest-value unprotect observation gap.",
    },
  },
  "liveness-oracle.mint": {
    file: `${EG}/liveness-oracle.ts`,
    symbol: "refresh",
    claim: "the pf anchor is live for this uid, port and generation",
    basis: "observed",
    layer: "compute",
    branches: "single",
  },
  "liveness-oracle.verify": {
    file: `${EG}/liveness-oracle.ts`,
    symbol: "verifyLivenessToken",
    claim: "this attestation is authentic, unexpired, and bound to my expectations",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the attestation is not authentic, is expired, or does not bind to my expectations",
      basis: "observed",
    },
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
    layer: "compute",
    branches: "single",
  },
  "runtime-fs-plan.mkdir-lstat": {
    file: `${EG}/runtime-fs-plan.ts`,
    symbol: "createRealGateRuntimeFsOps",
    claim: "this path is a real directory, not a symlink",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "this path is not a real directory, or is a symlink; the caller fails closed",
      basis: "observed",
    },
  },
  "gate-account.verify-record": {
    file: `${EG}/gate-account.ts`,
    symbol: "planAndCreateGateAccount",
    claim:
      "the gate account directory-service record carries the expected uid, canonically matching NFSHomeDirectory, hidden-account truth, and UserShell=/usr/bin/false",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "gate-account.rollback-incomplete": {
    file: `${CW}/account.ts`,
    symbol: "rollbackCreatedServiceAccount",
    claim:
      "a fresh-create gate account recovery inherits the shared observed account rollback: it reports whether absence was observed before any deletion was attempted, or whether a record was left in place for repair; it never claims deletion",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "gate-credential.verify": {
    file: `${EG}/gate-credential.ts`,
    symbol: "verifyGateCredential",
    claim: "the presented credential matches the stored one",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the presented credential does NOT match the stored one",
      basis: "observed",
    },
  },

  // ------------------------------------------------------ castle-wall flow
  "provision-account.execute-plan-uid": {
    file: `${CW}/account.ts`,
    symbol: "executeAccountProvisionPlan",
    claim:
      "the service account directory-service record carries the expected uid, canonically matching NFSHomeDirectory, hidden-account truth, and UserShell=/usr/bin/false",
    basis: "observed",
    layer: "compute",
    branches: "single",
  },
  "provision-egress.publish-rules": {
    file: `${CW}/egress.ts`,
    symbol: "publishProvisionedEgressRules",
    claim: "every declared rule file is written and the daemon reloaded",
    basis: "documented-bound",
    unobserved:
      "written rule files are not read back, and `reload.ok` is the injected trigger's own control-flow " +
      "verdict. `staleRuleIdsRemoved` IS observed (a real `readdir`).",
    layer: "compute",
    branches: "single",
  },
  "provision-egress.scrub-early-return": {
    file: `${CW}/egress.ts`,
    symbol: "scrubProvisionedEgressRules",
    claim: "there was nothing to scrub and the reload is fine",
    basis: "weakened",
    unobserved:
      "ENOENT on the rules directory returns `reloadOk: true` without invoking a reload. The claim is scoped " +
      "to 'no rules dir, so nothing to reload', which is what was observed.",
    layer: "compute",
    branches: "single",
  },
  "provision-egress.scrub-survivors": {
    file: `${CW}/egress.ts`,
    symbol: "scrubProvisionedEgressRules",
    claim: "no provisioned rule file for this harness survives",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "a provisioned rule file for this harness SURVIVES the scrub",
      basis: "observed",
    },
  },
  "provision-uid-gate.uid-exists": {
    file: `${CW}/uid-gate.ts`,
    symbol: "checkUidExistenceBeforeArm",
    claim: "an account with this name exists at exactly this uid",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "no account with this name exists at this uid",
      basis: "observed",
    },
  },
  "provision-verify.probe-all": {
    file: `${CW}/verify.ts`,
    symbol: "probeAll",
    claim: "every declared endpoint probe passed",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "at least one declared endpoint probe failed; the per-endpoint table names which",
      basis: "observed",
    },
  },
  "provision-rehome.step-restored": {
    file: `${CW}/rehome.ts`,
    symbol: "restoreRehomeSteps",
    claim: "this path is back at its original location",
    basis: "documented-bound",
    unobserved: "`ops.restore` returning `restored: true`; `sourcePath` is never stat'd in this module.",
    layer: "compute",
    branches: "single",
  },
  "provision-rehome.fully-restored": {
    file: `${CW}/rehome.ts`,
    symbol: "restoreRehomeSteps",
    claim: "every non-skipped path came back cleanly",
    basis: "documented-bound",
    unobserved: "an aggregate over `provision-rehome.step-restored`; it inherits that row's basis exactly.",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "at least one non-skipped path did not come back cleanly",
      basis: "documented-bound",
      unobserved:
        "chains to `provision-rehome.step-restored`; no path is stat'd on either branch.",
    },
  },
  "provision-exclusive-arm.exclusive-armed": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "runExclusiveEgressArming",
    claim: "exclusive egress is live and the harness is confined and running",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "THIS RUN's restore of the manifest to coarse scope failed. It is a fact about our own action and asserts NOTHING about the agent's run state. Rendering it as a run-state claim is precisely the round-4 HIGH, and the CLI no longer does: run state is `harness` and nothing else.",
      basis: "observed",
    },
  },
  "provision-exclusive-arm.harness-disposition": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "degradeLoud",
    claim:
      "what the degrade path did with the agent process: `started-coarse` (observed -- the coarse " +
      "install requires a stable running pid), or `not-started` carrying a settled ParkedClaim",
    basis: "observed",
    layer: "compute",
    // THE ROUND-4 ROW. This was `harness-started-coarse`, a boolean whose true
    // branch was correctly `observed` and whose FALSE branch -- "this run did
    // not start it" -- had no row at all and was rendered as "The agent is
    // PARKED (not running)" over a live pid. The field is no longer a boolean,
    // so `branches: "single"` here is a statement about the fixed SHAPE, not a
    // dodge: every arm of the union is separately named and separately based.
    branches: "single",
    detectorBlind: true,
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
    layer: "compute",
    branches: "single",
  },
  "provision-exclusive-arm.parked-state-verified": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "failParked",
    claim: "the agent is verifiably parked despite the failure",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the full persistent parked posture was NOT verified; `parkedStateProblems` enumerates which checks failed. False means 'the agent may be startable now or at the next boot', never 'the agent is running'.",
      basis: "observed",
    },
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
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the barrier could not confirm one of them; `cleanupErrors` says which",
      basis: "weakened",
      unobserved:
        "the unconfirmed side is not re-read. NEITHER branch is a run-state claim: that is `parkedClaim`, which fix-round 4 made a REQUIRED field of this outcome.",
    },
  },
  "provision-exclusive-arm.degrade-print": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "degradeLoud",
    claim: "the operator line states the agent's run state",
    basis: "observed",
    layer: "render",
    branches: "single",
    detectorBlind: true,
  },
  "provision-exclusive-arm.boot-parked-print": {
    file: `${CW}/exclusive-arm.ts`,
    symbol: "runBootExclusiveEgressRelease",
    claim: "the boot log line states the agent's run state",
    basis: "observed",
    layer: "render",
    branches: "single",
    detectorBlind: true,
  },
  "provision-exclusive-unprotect.flushed-print": {
    file: `${CW}/exclusive-unprotect.ts`,
    symbol: "runUnprotectSequenceLocked",
    claim: "the pf anchor was flushed when the last agent left",
    basis: "documented-bound",
    unobserved: "see `pf-anchor.disarm`. The 'remaining agents re-verified live' clause IS settle-probed.",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
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
    layer: "compute",
    branches: "single",
  },
  "provision-orchestrate.harness-restore-note-restarted": {
    file: `${CW}/orchestrate.ts`,
    symbol: "harnessRestoreNote",
    claim: "the agent this run stood down was restarted and is running again",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "provision-orchestrate.harness-restore-note-put-back": {
    file: `${CW}/orchestrate.ts`,
    symbol: "harnessRestoreNote",
    claim: "the prior plist is back on disk",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "provision-orchestrate.harness-restore-note-not-restored": {
    file: `${CW}/orchestrate.ts`,
    symbol: "harnessRestoreNote",
    // THE ROUND-6 ROW. Both rows above cover `restored === true`; the FALSE
    // branch -- the one that carried the false "did not verify its run state"
    // sentence AND the unguarded "re-run to bring it back up" imperative --
    // had no row at all, which is verbatim the boolean-carries-two-claims gap
    // round 4 was supposed to close. The claim is now the branded
    // `RunStateAdvice` the restore op observed, printed verbatim.
    claim:
      "the pre-run state is NOT back, plus (when one is owed) the agent's OBSERVED run state and the recovery " +
      "step that follows from it",
    basis: "observed",
    detectorBlind: true,
    layer: "render",
    branches: "single",
  },
  "provision-orchestrate.disarmed": {
    file: `${CW}/orchestrate.ts`,
    symbol: "runProvisionFlowSteps",
    claim: "the Castle Wall filter was disarmed rather than left over a bricked agent",
    basis: "documented-bound",
    unobserved:
      "`ops.disarm()` resolving; the filter is not re-probed. Bounded: this is a ROLLBACK claim on an already " +
      "failing run, reported as a non-green outcome.",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the disarm was not attempted, or did not resolve",
      basis: "documented-bound",
      unobserved:
        "the filter is not re-probed on either branch; see the positive bound.",
    },
  },
  "provision-orchestrate.rules-scrubbed": {
    file: `${CW}/orchestrate.ts`,
    symbol: "runProvisionFlowSteps",
    claim: "the provisioned egress rules were scrubbed",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the provisioned rules were NOT scrubbed; the outcome carries the manual-recovery note",
      basis: "observed",
    },
  },
  "provision-orchestrate.armed": {
    file: `${CW}/orchestrate.ts`,
    symbol: "runProvisionFlowSteps",
    claim: "the wall is armed and the agent was verified reachable and confined",
    basis: "observed",
    detectorBlind: true,
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the wall is not armed, or reachability / confinement was not verified; the flow returns a distinct non-green outcome",
      basis: "observed",
    },
  },
  "provision-orchestrate.rehome-restored-note": {
    file: `${CW}/orchestrate.ts`,
    symbol: "describeRestoreForReason",
    claim: "the re-homed paths were restored to the operator",
    basis: "documented-bound",
    unobserved: "chains to `provision-rehome.fully-restored`; no path is stat'd in this module either.",
    detectorBlind: true,
    layer: "compute",
    branches: "single",
  },
  "provision-unprovision.disarm-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovision",
    claim: "the wall is disarmed",
    basis: "documented-bound",
    unobserved: "`unprovisionOps.disarm()` resolving; the filter is not re-probed.",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "`disarm()` threw",
      basis: "documented-bound",
      unobserved:
        "the filter is not re-probed on either branch.",
    },
  },
  "provision-unprovision.uninstall-daemon-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovision",
    claim: "the harness daemon is uninstalled",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "the harness daemon is NOT confirmed uninstalled",
      basis: "observed",
    },
  },
  "provision-unprovision.scrub-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovision",
    claim: "no provisioned allow rule survives",
    basis: "observed",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "a provisioned allow rule survives",
      basis: "observed",
    },
  },
  "provision-unprovision.restore-rehome-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovision",
    claim: "every re-homed path was restored",
    basis: "documented-bound",
    unobserved: "chains to `provision-rehome.fully-restored`.",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "at least one re-homed path was not restored",
      basis: "documented-bound",
      unobserved:
        "chains to `provision-rehome.fully-restored` on both branches.",
    },
  },
  // ------------------------------------------------------- THE RENDER LAYER
  "wrap-cli.degrade-agent-state": {
    file: "server/src/wrap/cli.ts",
    symbol: "harnessDispositionSentence",
    claim: "the operator is told the agent's run state after a degrade",
    basis: "observed",
    layer: "render",
    branches: "single",
    detectorBlind: true,
  },
  "provision-unprovision.fully-ok": {
    file: `${CW}/unprovision.ts`,
    symbol: "unprovisionFullyOk",
    claim: "the whole rollback succeeded",
    basis: "documented-bound",
    unobserved:
      "a conjunction over the four rows above; it inherits the weakest (disarm and restore-rehome).",
    layer: "compute",
    branches: "boolean",
    negativeBranch: {
      claim:
        "at least one of the four components failed; each is reported separately",
      basis: "documented-bound",
      unobserved:
        "a conjunction: false inherits the weakest component, exactly as true does.",
    },
  },
};

/**
 * Per-file counts of DETECTOR-VISIBLE claim literals, as of fix-round 3.
 *
 * This is the ratchet. `claim-basis-structural.test.ts` derives the tracked
 * file set from the scoped source directories, recomputes these counts, and
 * fails when either a file is missing from this map or a count moves. A count
 * that legitimately changes is updated in the same commit as the claim -- that
 * is the whole mechanism. Zero-literal files are listed intentionally: absence
 * means "untracked", not "zero".
 *
 * BOUND, STATED PLAINLY: this catches claims the detector's literal set
 * matches. It does not catch a new `Promise<void>`-shaped claim; those live in
 * {@link CLAIM_SITES} with `detectorBlind: true` and are maintained by review.
 *
 * AND IT DOES NOT COVER THE RENDER LAYER, DELIBERATELY. `wrap/cli.ts` is NOT
 * on this list and should not be: it is 4,400 lines serving the whole CLI, so
 * a count ratchet over it would trip on every unrelated edit and be bumped
 * without thought, which is worse than no guard. The round-4 defect there was
 * a SENTENCE, which no count would have caught anyway. The render layer is
 * covered by {@link RUN_STATE_PROSE_PATTERNS} instead -- an ownership rule,
 * not a count.
 */
export const CLAIM_LITERAL_COUNTS: Readonly<Record<string, number>> = {
  [`${CW}/account.ts`]: 1,
  [`${CW}/detect.ts`]: 0,
  [`${CW}/egress.ts`]: 4,
  [`${CW}/exclusive-arm.ts`]: 3,
  [`${CW}/exclusive-unprotect.ts`]: 4,
  [`${CW}/harness-argv.ts`]: 0,
  [`${CW}/index.ts`]: 0,
  [`${CW}/lockfile.ts`]: 0,
  [`${CW}/orchestrate.ts`]: 9,
  [`${CW}/policy-daemon.ts`]: 0,
  [`${CW}/rehome.ts`]: 0,
  [`${CW}/uid-gate.ts`]: 2,
  [`${CW}/unprovision.ts`]: 4,
  [`${CW}/verify.ts`]: 1,
  [`${EG}/anchor-registry.ts`]: 0,
  [`${EG}/arming-wiring.ts`]: 21,
  [`${EG}/claim-basis.ts`]: 3,
  [`${EG}/drift-guard.ts`]: 0,
  [`${EG}/exec-runner.ts`]: 0,
  [`${EG}/gate-account.ts`]: 0,
  [`${EG}/gate-client-auth.ts`]: 0,
  [`${EG}/gate-credential.ts`]: 2,
  [`${EG}/gate-daemon.ts`]: 0,
  [`${EG}/gate-server.ts`]: 0,
  [`${EG}/generation.ts`]: 0,
  [`${EG}/harness-daemon.ts`]: 12,
  [`${EG}/index.ts`]: 0,
  [`${EG}/liveness-oracle.ts`]: 2,
  [`${EG}/parity.ts`]: 0,
  [`${EG}/parked-claim.ts`]: 1,
  [`${EG}/peer-identity.ts`]: 0,
  [`${EG}/pf-anchor.ts`]: 0,
  [`${EG}/posture.ts`]: 1,
  [`${EG}/protection-claim.ts`]: 0,
  [`${EG}/release-barrier.ts`]: 15,
  [`${EG}/runtime-fs-plan.ts`]: 0,
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

// ---------------------------------------------------------------------------
// THE RENDER-LAYER GUARD (fix-round 4, Part B blind spot 2)
// ---------------------------------------------------------------------------

/**
 * The ONE file allowed to contain run-state prose. Everything else must route
 * to it. See {@link RUN_STATE_PROSE_PATTERNS}.
 */
export const RUN_STATE_PROSE_SOLE_OWNER = `${EG}/parked-claim.ts`;

/**
 * Prose that ASSERTS something about whether the agent process is alive.
 *
 * Round 4's HIGH was a sentence, not a flag: `wrap/cli.ts:1289` printed "The
 * agent is PARKED (not running)" derived from a boolean meaning "we did not
 * start it", while the same output's reason string said the job still reported
 * pid 9001. No count ratchet would have caught it -- the register covered
 * where claims are COMPUTED, and `wrap/cli.ts` had zero rows.
 *
 * So the guard for the render layer is not a count, it is an OWNERSHIP rule:
 * these phrases may appear in string and template literals in exactly one
 * file, the chokepoint that can only produce them from a settled observation.
 * Every other surface prints `ParkedClaim.sentence`. A future author who
 * composes their own parked sentence anywhere in the subsystem or in the CLI
 * fails the build.
 *
 * The scan is PARSER-based (the TypeScript AST's string and template literals),
 * not a line scanner: doc comments must stay free to discuss parking in plain
 * English, and a line-oriented matcher cannot tell the two apart.
 *
 * MATCHING IS NORMALIZED, NOT LITERAL (fix-round 5, 2026-07-19). Round 4 wrote
 * this list from the sentences it had just fixed and compared with a raw
 * `includes`. Every surviving assertion in the subsystem was written `is
 * STOPPED`, so the guard matched none of them: the round-5 HIGH was one
 * `toLowerCase()` away from being caught by the round's own tool. Comparison
 * now goes through {@link normalizeRunStateProse} on BOTH sides -- case-folded
 * and whitespace-collapsed, so a sentence wrapped across lines in a template
 * literal cannot hide either -- and the scanner additionally flattens
 * `"a" + "b"` literal-concatenation chains before testing, closing the
 * `"The agent is " + "PARKED"` split the round-5 Codex lens demonstrated.
 *
 * WHAT REMAINS LEXICAL, stated plainly rather than implied away. This guard
 * catches a run-state sentence that is SPELLED like one of these phrases in
 * source text. It does not and cannot catch: a phrase assembled through a
 * template SUBSTITUTION or a variable (`` `The agent is ${state}` ``), a
 * sentence held in a lookup table and printed by key, a synonym or a reordered
 * equivalent ("no process is alive for the harness"), or prose built at
 * runtime from data. It is a tripwire on the shape the defect has actually
 * taken ten times, not a proof that no module can assert run state. The
 * structural half of the rule is the {@link ParkedClaim} brand; this is the
 * half that catches an author who never touched the type.
 *
 * IMPERATIVES ARE CLAIMS (fix-round 6, 2026-07-19). Round 5 closed this list's
 * case-folding gap and predicted the class was now "the build fails" rather
 * than "a reviewer must notice". The round-6 gate found the eleventh instance
 * anyway, and the reason is worth keeping: BOTH of the last two instances were
 * IMPERATIVES, and every pattern above governs a DESCRIPTION. "Re-run
 * 'sudo sanctuary protect --hermes' to bring it back up" asserts nothing about
 * a process by the letter of this list, while being the sentence that actually
 * causes an operator to stand a live agent down. An instruction premised on a
 * state is a claim about that state, so the recovery imperative now lives in
 * the sole-owner chokepoint alongside the sentence, and its phrasings are on
 * this list.
 *
 * The imperative entries are deliberately NARROW. "Re-run 'sanctuary protect
 * --hermes'" on its own is ordinary, honest advice at six sites in
 * `wrap/cli.ts` that make no run-state claim at all (a failed connectivity
 * re-check, an unreconciled file). What makes a phrase run-state prose is the
 * premise that something is DOWN and this will bring it UP.
 */
export const RUN_STATE_PROSE_PATTERNS: readonly string[] = [
  "is PARKED",
  "PARKED (not running)",
  "remains parked",
  "remains PARKED",
  "is not running",
  "is NOT running",
  "not running)",
  "agent is RUNNING",
  "is stopped",
  // Imperatives (fix-round 6). Each asserts, by its premise, that the agent is
  // not currently up.
  "bring it back up",
  "bring the agent up",
  "to restart the agent",
];

/**
 * Fold the case and collapse the whitespace of a candidate string, so the
 * ownership rule is not defeated by shouting or by a line wrap.
 *
 * Exported so the guard test and this register apply the SAME normalization --
 * a pattern list normalized one way and compared another is how round 4's
 * guard came to match nothing.
 */
export function normalizeRunStateProse(text: string): string {
  return text.replace(/\s+/g, " ").toLowerCase();
}

/**
 * Files the ownership rule is enforced over. `wrap/cli.ts` is on this list
 * because it is where the round-4 falsehood was actually READ by a human; the
 * register having no reach into it was the blind spot.
 *
 * WHAT IS NOT ON THIS LIST, named rather than left to be discovered
 * (fix-round 5): `wrap/auto-provision.ts`, which contains two "PARKED"
 * sentences on the repair and unprotect branches. They are deliberately out of
 * scope rather than overlooked: both are gated on `verifyParkedPersistent`,
 * which is a STRONGER observation than a {@link ParkedClaim} (not running AND
 * job disabled in the override db AND hold file absent AND parked plist), and
 * `parked-claim.ts` explicitly disclaims that persistent posture. Routing them
 * through the chokepoint would weaken them. Adding the file with an exemption
 * would buy nothing but a maintenance surface. The honest statement is that
 * this guard's reach ends here.
 */
export const RUN_STATE_PROSE_SCANNED_DIRS: readonly string[] = [
  "server/src/egress-gate",
  "server/src/castle-wall/provision",
];

/** Individual files scanned in addition to {@link RUN_STATE_PROSE_SCANNED_DIRS}. */
export const RUN_STATE_PROSE_SCANNED_FILES: readonly string[] = ["server/src/wrap/cli.ts"];

/**
 * Files exempt from the ownership rule, with the reason. Short by design: an
 * exemption is how this guard would rot.
 *
 * THIS FILE is exempt because it is the register itself. Its string literals
 * DESCRIBE claims rather than making them (`claim:` and `unobserved:` prose),
 * and it necessarily contains {@link RUN_STATE_PROSE_PATTERNS} verbatim. A
 * register that could not quote the prose it governs could not document it.
 */
export const RUN_STATE_PROSE_EXEMPT: Readonly<Record<string, string>> = {
  [`${EG}/claim-basis.ts`]: "the register describes claims rather than making them, and holds the pattern list",
};
