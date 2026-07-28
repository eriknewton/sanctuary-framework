/**
 * Auto-provision Step 2 (Build 1): one-flow orchestration + confirm
 * ceremony.
 *
 * This is the corrected, folded-fix flow from the ratified scope doc
 * (Step2_Auto_Provision_At_Install_Scope_2026-07-06.md, "Adversarial
 * review"), NOT the naive "verify before installing the daemon" flow:
 *
 *   detect -> plan-and-print -> ONE confirm (privileged sub-steps refuse on
 *   non-TTY; the cooperative wrap itself still completes -- fix H4) ->
 *   create account -> re-home -> install harness daemon (agent now runs at
 *   the new uid, wall NOT yet armed) -> verify reachability UNFILTERED as
 *   the new uid (fix B2; fail-closed, STOP before arming on failure) ->
 *   arm-time uid-existence gate (fix H1) -> arm via the shipped
 *   `enable --agent-uid=N --ceiling` -> post-arm connectivity re-check with
 *   fast disarm-rollback (fix B2) -> fail-closed between every step (a
 *   failure anywhere between create and arm NEVER leaves an armed wall over
 *   a half-provisioned agent).
 *
 * FIX F6 (HIGH, Codex second family, 2026-07-07 fix-round): when
 * `detectResult.alreadyDedicated` is true (now only set on a VERIFIED
 * account name/shape, see detect.ts), the flow skips ONLY create + re-home
 * -- it still runs install-daemon -> verify -> uid-gate -> arm ->
 * post-arm-verify. `alreadyDedicated` NEVER again means "skip straight to
 * done"; that was the exact defect (a stale/foreign uid could report
 * "already dedicated" while nothing was actually confined).
 *
 * This module is the PURE decision/sequencing layer: every side-effecting
 * step (account create, re-home, daemon install, arm, verify, disarm) is an
 * injected async function, so the whole sequence -- including every
 * fail-closed branch -- is unit-testable against mocks/spies without a real
 * host, TTY, or privileged binary. The CLI layer (wired into `sanctuary
 * protect`) supplies the real implementations and the real
 * `process.stdin.isTTY` check.
 */

import type { ProvisionNeedResult } from "./detect.js";
import type { HarnessDisposition, RunStateAdvice } from "../../egress-gate/parked-claim.js";
import { assessHarnessParked, runStateAdvice, startedCoarseDisposition } from "../../egress-gate/parked-claim.js";
import {
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND,
  EGRESS_GATE_STAND_DOWN_EFFECT,
  EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND,
} from "../../egress-gate/operator-advice.js";
import {
  runExclusiveEgressArming,
  type ExclusiveEgressArmOps,
  type ExclusiveRoutingResidue,
} from "./exclusive-arm.js";
import type { AccountProvisionPlan } from "./account.js";
import type { RehomePlan, RehomeStepResult } from "./rehome.js";
import { RehomeExecutionError } from "./rehome.js";
import type { ConnectivityVerifyResult, EndpointProbeTarget } from "./verify.js";
import { verifyReachabilityAfterArm, verifyReachabilityBeforeArm } from "./verify.js";
import type { UidExistenceCheckResult } from "./uid-gate.js";
import type {
  AgentEgressVerifyReport,
  EndpointStaticCheck,
  HarnessEndpointSet,
} from "./egress.js";
import {
  EGRESS_PROVISIONED_AUDIT_OP,
  EGRESS_PROVISION_REFUSED_AUDIT_OP,
  renderAgentEgressReportLines,
  renderEgressPlanLines,
  renderEndpointCheckLines,
} from "./egress.js";

/**
 * Operator-facing shutdown state for an in-flight provision attempt.
 * A signal cleanup uses the latest value when rollback does not settle before
 * its deadline, so it can name the residual state without inventing a clean
 * rollback claim.
 */
export interface ProvisionFlowShutdownStatus {
  /** The current provision stage, using the same vocabulary as outcome stages where possible. */
  stage: string;
  /** The host state that may remain if the process exits before rollback is observed. */
  residualState: string;
  /** Exact product command or verb the operator should run to recover this residual state. */
  recoveryCommand: string;
}

/** Everything the orchestrator needs to decide + print, resolved once up front. */
export interface ProvisionFlowContext {
  agentId: string;
  accountName: string;
  ceiling: number;
  detectResult: ProvisionNeedResult;
  /** Whether stdin is a TTY. Privileged sub-steps refuse when false (fix H4). */
  isTty: boolean;
  /** Pre-answers the CHOICE only (fix L2): still confirms on a TTY, still plan-and-prints. */
  preAnsweredProvision?: boolean;
  /**
   * Bug B (one-flow gap): absolute fortress path whose Castle Wall POLICY daemon
   * the flow must ensure is reachable BEFORE arming. Passed to
   * `ops.ensurePolicyDaemon`, and `ops.arm`/`ops.disarm` target the SAME fortress
   * (the CLI threads it through `--fortress`), so a non-default fortress is never
   * probed at the default socket.
   */
  fortressPath: string;
  /**
   * The harness's declared endpoint set (design doc
   * Confined_Agent_Egress_Design_2026-07-10.md section 3.1). Used here for
   * the Tier-1 confirm plan-print ONLY (every grant named before the one
   * confirm, messaging hosts marked exfil-risk, broad gateways marked broad);
   * the provisioning + probes consume the SAME set through the injected ops
   * so the granted set and the printed set can never drift.
   */
  harnessEndpoints: HarnessEndpointSet;
  /**
   * Unified Protect Slice 5 S5-6: this provision is FINE-GRAINED
   * (exclusive-egress) mode. When true the flow REQUIRES (fail-closed,
   * checked BEFORE any mutation): (a) `ops.exclusiveEgress` wired, and
   * (b) `ops.installHarnessDaemon` performing the S5-5 PARKED install
   * (`parked: true` on its result) -- the agent must not run until the
   * release barrier passes. After the coarse stages prove live, the flow
   * runs the exclusive arming stage (gate generation bring-up + release
   * barrier), with the degrade-loud coarse fallback on failure.
   */
  fineGrainedDeclared?: boolean;
  /**
   * Set by the CLI signal cleanup when SIGINT/SIGTERM arrives. The flow checks it
   * only at rollback-safe checkpoints, never by duplicating host cleanup in the
   * signal handler.
   */
  shutdownSignal?: AbortSignal;
  /**
   * Receives the current rollback-relevant state for bounded signal shutdown.
   * It must not contain secrets; it is rendered to the operator if rollback hangs.
   */
  onShutdownStatus?: (status: ProvisionFlowShutdownStatus) => void;
}

export type DisarmNePreferenceOutcome =
  | "corroborated_off"
  | "save_accepted_inconclusive"
  | "fail_open_deadman";

function disarmOutcomeObservedOff(outcome: DisarmNePreferenceOutcome): boolean {
  return outcome === "corroborated_off";
}

function disarmOutcomeAllowsFreshDaemonTeardown(
  outcome: DisarmNePreferenceOutcome,
): boolean {
  return outcome !== "fail_open_deadman";
}

/** The injected, side-effecting steps. Each corresponds to one stage of the target flow. */
export interface ProvisionFlowOps {
  /** Ask the single "proceed? [y/N]" question. Only called when `isTty` is true. */
  confirm(promptText: string, signal?: AbortSignal): Promise<boolean>;
  /** Print a line to the operator-facing channel (plan-and-print, progress, errors). */
  print(line: string): void;
  /** Build the account-provision plan (pure) then execute it. Returns the account's uid. */
  createAccount(): Promise<{ plan: AccountProvisionPlan; uid: number }>;
  /** Build + execute the re-home plan. Returns per-step results (for rollback). */
  rehome(uid: number, gid: number): Promise<{ plan: RehomePlan; results: RehomeStepResult[] }>;
  /**
   * Install the harness daemon for the given uid. Returns a discriminated
   * result (mirroring `arm`) rather than throwing on failure, so the
   * teardown-on-abort decision always has the honest daemon-presence signals:
   *   - ok: whether the install succeeded.
   *   - bootstrappedThisRun (success): did THIS run stand up a NEW daemon
   *     (vs find one already loaded)?
   *   - daemonPreexisted (failure): was a daemon already loaded BEFORE this
   *     run's install attempt? On failure the caller tears down iff
   *     `!daemonPreexisted` (a fresh daemon this attempt left live must be
   *     removed; a genuinely pre-existing one must be preserved -- R6-3).
   *
   * FIX (round 5 / R7-1, R8-1): the teardown decision (N3/R6-3) must key on
   * "did this run stand the daemon up", NOT on `alreadyDedicated` (which is set
   * from the ACCOUNT shape, not daemon presence). R7-1 fixed the
   * install-SUCCESS-then-later-abort branches; R8-1 makes install FAILURE carry
   * the same honest signal (a throwing op left the install-abort branch on the
   * stale `!alreadyDedicated` heuristic, stranding a fresh daemon on the
   * alreadyDedicated path). A result object closes the whole daemon-lifecycle
   * teardown decision on one honest signal instead of per-branch heuristics.
   */
  installHarnessDaemon(
    uid: number,
  ): Promise<
    | {
        ok: true;
        bootstrappedThisRun: boolean;
        /**
         * S5-6: true when the install was the S5-5 PARKED form (plist
         * Disabled + launchctl-disabled + hold file absent; the daemon was
         * NOT bootstrapped). REQUIRED true when `ctx.fineGrainedDeclared`;
         * the flow aborts fail-closed otherwise (a running agent before the
         * release barrier is the exact BLOCKER-2 escape).
         */
        parked?: boolean;
        /**
         * S5-6 drill-D2 fix-round (2026-07-18): TRUE when the (parked) install
         * MODIFIED a pre-existing harness job -- overwrote its plist, set a
         * persistent launchd disable, and/or booted a loaded job out.
         *
         * This exists because `bootstrappedThisRun: false` used to mean "a
         * genuinely pre-existing daemon was found and LEFT ALONE", which the
         * parked install made false: it now stands the operator's live agent
         * down before the flow is committed to anything. Keying an abort's
         * cleanup on `bootstrappedThisRun` alone therefore left the agent
         * stopped on every abort path. `uninstallHarnessDaemon` is still the
         * wrong remedy here (this run did not create the job, so destroying it
         * would be worse); the remedy is `restoreStoodDownHarness`.
         */
        harnessStoodDown?: boolean;
      }
    | { ok: false; error: string; daemonPreexisted: boolean }
  >;
  /**
   * Put a harness this run STOOD DOWN back the way it was (drill-D2
   * fix-round). Called from exactly one place -- the outcome chokepoint at the
   * bottom of `runProvisionFlow` -- for every outcome that is not one where
   * the exclusive-egress stage has taken ownership of the harness.
   *
   * The single call site is the point. There are seven-plus places this flow
   * can refuse between the parked install and the exclusive stage, and a
   * per-site restore call is how the eighth one gets forgotten. Deciding once,
   * from the OUTCOME, means an abort added later is covered without anyone
   * remembering to cover it.
   *
   * MUST NOT THROW: it runs on a path that is already failing for some other
   * reason, and that reason is the more important message. It reports what it
   * could not put back so the caller can surface both.
   *
   * FIX-ROUND 2 (2026-07-18): the result carries the two OBSERVED facts the
   * operator-facing sentence is built from, because the re-gate found the
   * sentence being built from neither. `restored` used to be derived by the
   * production op from an empty error list -- so a job that was running, could
   * not be restarted, and raised no error printed "was restarted and restored
   * to its previous state" while stopped. Every field here must be a statement
   * about state that was looked at, never about a call that was made.
   *
   * FIX-ROUND 6 (2026-07-19): `runState` was the field that did not exist, and
   * its absence was the eleventh instance of this subsystem's one defect. The
   * production op ALREADY paid for a full settle loop and received a
   * `ParkedClaim` reading `alive (pid 9001)` -- then dropped it at this
   * boundary, because this type had nowhere to put it. `harnessRestoreNote`
   * then told the operator "this run ... did not verify its run state" and sent
   * them to re-run over a live agent. Routing the restore DECISION through one
   * chokepoint did nothing for the SENTENCE printed about it; the claim now
   * travels too.
   */
  restoreStoodDownHarness(): Promise<{
    /** The pre-run state is genuinely back: plist restored AND the job's run-state matches. */
    restored: boolean;
    /** The job was running before this run stood it down. */
    wasRunning: boolean;
    /** OBSERVED running again. Only ever true when a restart was verified. */
    harnessRestarted: boolean;
    problems: string[];
    /**
     * The OBSERVED run state plus the recovery step that follows from it.
     * PRESENT EXACTLY WHEN `runStateOwed({ wasRunning, harnessRestarted })`.
     * Branded: only `runStateAdvice` in the parked-claim chokepoint can build
     * one, so no consumer here can compose a second copy of this advice.
     */
    runState?: RunStateAdvice;
  }>;
  /**
   * Uninstall the harness daemon (fix, round 5 item N3). `installHarnessDaemon`
   * bootstraps a LIVE root LaunchDaemon; every post-install abort branch
   * (verify-before-arm, uid-existence-gate, arm) MUST tear it back down, or a
   * fail-closed abort leaves the daemon running under the dedicated account
   * while the flow reports a clean rollback. Idempotent + fail-loud (matches
   * the shipped `uninstallAgentHarnessDaemon` teardown semantics).
   */
  uninstallHarnessDaemon(): Promise<void>;
  /**
   * Bug B (the one-flow gap): ensure a reachable Castle Wall POLICY daemon
   * exists for `fortressPath` BEFORE arming. Arming with no policy daemon
   * fail-closes the machine to deny-all (the exact lockout the arm's own probe
   * refuses), so on a box with no wall for this fortress the flow must stand one
   * up first. Returns a discriminated result (mirroring `installHarnessDaemon`)
   * rather than throwing, so the abort/teardown decision keys on ONE honest
   * signal:
   *   - ok:true, freshlyInstalled:false -> a daemon was ALREADY reachable, or a
   *     PRE-EXISTING boot service for this fortress was (re)started. There is
   *     nothing for THIS flow to tear down on a later abort.
   *   - ok:true, freshlyInstalled:true  -> THIS run stood up the singleton boot
   *     service from nothing (no wall existed for any fortress). A later abort
   *     MUST tear it back down (via `teardownPolicyDaemon`), restoring the prior
   *     "no wall" state.
   *   - ok:false                        -> could not ensure a reachable policy
   *     daemon (a DIFFERENT-fortress boot service refuses to swap -- one machine
   *     runs one wall; or an install/restart whose socket never became
   *     reachable). The flow aborts + rolls back prior steps. `freshlyInstalled`
   *     still reports whether this attempt left a fresh boot service live that
   *     the abort must tear down (fail toward removing anything this run stood
   *     up, never toward stranding it).
   *
   * This op ONLY ensures the policy daemon: it MUST NOT turn on the content
   * filter (arm stays a separate, still-fail-closed step) and MUST NEVER leave
   * the box in a filter-on / daemon-down (lockout) state.
   */
  ensurePolicyDaemon(
    fortressPath: string,
  ): Promise<
    | { ok: true; freshlyInstalled: boolean }
    | { ok: false; error: string; freshlyInstalled: boolean }
  >;
  /**
   * Tear the FRESHLY-INSTALLED singleton Castle Wall boot (policy) service back
   * down (bootout + remove the plist), used ONLY on an abort after
   * `ensurePolicyDaemon` reported `freshlyInstalled:true`. Restores the prior
   * "no wall for this machine" state. Idempotent + fail-loud (mirrors
   * `uninstallHarnessDaemon`). NEVER called for a pre-existing boot service --
   * we only fresh-install when no prior boot service existed, so tearing down to
   * "no wall" is correct, and there is deliberately no swap-restore because we
   * REFUSE to swap.
   */
  teardownPolicyDaemon(): Promise<void>;
  /**
   * Provision-egress step (design section 5 layer 1, runs AFTER
   * ensure-policy-daemon and BEFORE arm): publish the harness's
   * provenance-tagged allow rules into the signed manifest source (the
   * reachable policy daemon re-signs and broadcasts), then STATICALLY verify
   * every declared endpoint evaluates to an allow through the same TS
   * matcher the enforcement paths use, plus the #380 derived-DNS presence.
   * Returns a discriminated result (never throws) so the abort branch always
   * has the per-endpoint table to print. `ok: false` MUST abort before arm
   * (fail-closed: arming over an unprovisioned/unverified egress path is the
   * exact silent-brick this feature exists to prevent).
   */
  provisionEgress(): Promise<
    | { ok: true; ruleIds: string[]; checks: EndpointStaticCheck[]; dnsRulePresent: boolean }
    | { ok: false; error: string; checks?: EndpointStaticCheck[]; dnsRulePresent?: boolean }
  >;
  /**
   * Put this harness's provisioned egress rules back to the state
   * `provisionEgress` found them in, and VERIFY the result by reading the
   * signing source back. Used on abort/rollback after `provisionEgress` ran.
   *
   * Design section 6 says a failed run must leave no orphan grants, and on a
   * FIRST run the pre-run state is "no provisioned rules", so this still
   * removes everything the run added. FIX F-REVOKE (Mini1 drill 2026-07-26):
   * the pre-fix op was an unconditional scrub of every
   * `provisioned-<harness>-*` rule, which on a SECOND run also revoked the
   * grants a previous successful provision had published and this run never
   * touched -- taking a live, correctly-confined agent from "reaches its own
   * manifest" to "reaches nothing" underneath an operator-facing message that
   * read like a clean rollback.
   *
   * Never throws (it runs on abort paths, where a throw would mask the
   * original failure). `restored: false` or `reloadOk: false` MUST reach the
   * operator as loud, actionable guidance -- see {@link restoreEgressBestEffort}.
   */
  restoreProvisionedEgressToPreRunState(): Promise<{
    /** Observed: the rules directory matches the pre-run capture byte-for-byte. */
    restored: boolean;
    /** Observed: the running policy daemon reloaded, so the restored set is actually being served. */
    reloadOk: boolean;
    problems: string[];
  }>;
  /**
   * Post-arm as-uid egress verification (design section 5, the check the
   * 2026-07-09 drill proved DNS-only probes cannot make): a probe process
   * running AS THE AGENT UID (real uid; the wall keys on ruid) completes a
   * TCP+TLS connect to each declared endpoint through the ARMED wall, and
   * the non-listed negative control stays BLOCKED. Failure triggers the
   * existing fix-B2 fast-disarm rollback.
   */
  verifyAgentEgressAfterArm(uid: number): Promise<AgentEgressVerifyReport>;
  /**
   * Append one egress audit record through the existing audit-event path
   * with a DISTINCT operation string (local values, never a widened shared
   * enum): `egress_provisioned` on success, `egress_provision_refused` on
   * refusal. MUST be best-effort and never throw (an audit-write failure
   * must not mask the outcome it records).
   */
  auditEgress(
    operation: typeof EGRESS_PROVISIONED_AUDIT_OP | typeof EGRESS_PROVISION_REFUSED_AUDIT_OP,
    details: Record<string, unknown>,
  ): Promise<void>;
  /** Endpoints to probe before arming (LLM / Telegram / Gmail, etc). */
  preArmEndpoints(): EndpointProbeTarget[];
  /** Hard existence + uid-match check immediately before arming (fix H1). */
  checkUidExistence(uid: number): Promise<UidExistenceCheckResult>;
  /** Arm via the shipped `enable --agent-uid=N --ceiling` (step 1). */
  arm(uid: number, ceiling: number): Promise<{ ok: true } | { ok: false; error: string }>;
  /** Endpoints to re-probe after arming (same list, post-arm). */
  postArmEndpoints(): EndpointProbeTarget[];
  /**
   * Disarm the content filter (the unconditional dead-man `castle-wall
   * disable`). Used by the post-arm re-check rollback (fix B2) AND, Bug B P1, by
   * the arm-abort branch's disarm-first ordering before tearing a
   * freshly-installed policy daemon down.
   *
   * THROWS when the disarm hard-fails (the dead-man lever itself failed).
   * On success (no throw) it returns a three-way NE preference outcome:
   *   - `corroborated_off` -> a status re-read observed disabled. This is the
   *     ONLY outcome that may become a user-facing observed-off claim.
   *   - `save_accepted_inconclusive` -> the save-disabled mutation returned ok,
   *     but the status re-read did not observe disabled. This is usable as a
   *     rollback control-flow result, never as an observation.
   *   - `fail_open_deadman` -> the disable save did NOT complete, but the
   *     authenticated dead-man lease revoke made the provider fail open now.
   *     The NE preference may still be enabled and a reboot could come up
   *     enabled with no daemon = deny-all; leave the daemon UP.
   */
  disarm(): Promise<{ nePreferenceOutcome: DisarmNePreferenceOutcome }>;
  /**
   * Restore re-home from backup, used on a fail-closed abort between create
   * and arm. FIX F2/F5 (2026-07-07 fix-round): returns whether the restore
   * ACTUALLY reproduced every path (never a hardcoded success) so the
   * outcome's `rolledBack` field reflects reality, not an assumption.
   * `restoredCount`/`attemptedCount` let the caller distinguish a totally
   * failed restore from a partial one (some paths came back, some did not).
   */
  restoreRehome(results: RehomeStepResult[]): Promise<{
    fullyRestored: boolean;
    restoredCount: number;
    attemptedCount: number;
    backupPaths: string[];
    /**
     * FIX (round 5 / R5-2): the sibling paths where a RECREATED-source R6
     * conflict left the recovered re-homed data. A conflict is NOT a failed
     * restore -- the operator's recreated file is intact and the re-homed copy
     * is safe here -- so the orchestrator must surface these instead of
     * collapsing them into a false "restore FAILED" that misdirects the
     * operator to overwrite their newer file from the stale backup.
     */
    conflictPaths: string[];
    /**
     * FIX (round 5 / R6-2): source paths whose restore GENUINELY failed
     * (status "failed", not "conflict"). Threaded separately so the CLI can
     * distinguish a pure-conflict abort (all data safe) from a conflict that
     * co-occurs with a real failure -- the latter must stay LOUD and surface
     * the backup path, never be softened by the conflict frame.
     */
    failedPaths: string[];
  }>;
  /**
   * S5-6: the exclusive-egress arming stage ops (gate generation bring-up +
   * S5-5 release barrier + degrade-loud coarse fallback). REQUIRED when
   * `ctx.fineGrainedDeclared`; the flow aborts BEFORE any mutation when it is
   * missing (a fine-grained provision without the arming stage would end with
   * a parked agent and no path to release it).
   */
  exclusiveEgress?: ExclusiveEgressArmOps;
  /**
   * OBSERVE the host's CURRENT per-agent egress confinement, for the abort
   * paths that must say something about enforcement state.
   *
   * FIX F-COARSE-AFTER-EXCLUSIVE, honesty half (HIGH, Mini1 re-drill
   * 2026-07-26). The provision-egress abort printed the flat sentence "The
   * wall was NOT armed". On the drill host, at the instant that sentence was
   * printed, pf was `Status: Enabled`, the gate registry showed
   * `committed: [{agent_uid: 503, generation_id: 23}]`, and the confined agent
   * was 0/9 reachable INCLUDING its own manifest. The product told the
   * operator nothing was armed while the machine was enforcing. The sentence
   * was true about the CODE PATH ("this run did not reach the arm step") and
   * false about the HOST -- which is the exact class this codebase forbids.
   *
   * So enforcement-state prose is now derived from an OBSERVATION. MUST never
   * throw: an unobservable host is reported as unobserved, never as "nothing
   * is armed".
   */
  observeAgentConfinement(): Promise<ObservedAgentConfinement>;
  /**
   * THE exclusive-routing residue gate (FIX F-COARSE-AFTER-EXCLUSIVE, class
   * half, 2026-07-26). Reconcile a leftover `exclusive-routing.json` marker
   * (plus its `exclusive-egress-gate.json`) that an interrupted or failed
   * prior arm left in the fortress, and report what was decided.
   *
   * WHY THIS IS MODE-INDEPENDENT, and why it hangs here rather than off
   * `exclusiveEgress`: the signing daemon
   * (`castle-wall/runtime/macos-daemon.ts`) picks the manifest composition
   * from MARKER PRESENCE ALONE. It has never consulted, and cannot consult,
   * which mode the operator asked this CLI run for. So a leftover marker
   * makes the daemon compose EXCLUSIVE against a plain coarse run's
   * agent-scoped rules, find agent-reachable direct allows, and correctly
   * refuse to produce a manifest. The self-heal used to be reachable ONLY
   * when `fineGrainedDeclared` was true AND the exclusive ops were wired --
   * i.e. it was gated on the one signal the wedging component does not read.
   * That asymmetry IS the defect: on the Mini1 re-drill the plain
   * `protect --hermes --provision-agent-account` run never ran the reconcile
   * at all, was judged by exclusive composition rules, and was refused.
   *
   * CONTRACT:
   *  - Called with `intent: "observe"` AFTER every step that can still say no
   *    (the non-TTY refusal, the pre-declined return) and BEFORE the operator
   *    confirm, so a doomed run is refused before anyone is asked to confirm
   *    it and a run that was never going to arm never reaches this op at all.
   *  - Called a SECOND time with `intent: "clear"` ONLY when the observation
   *    was `orphaned` AND the confirm said yes. That call is the first
   *    mutation of the run. It RE-PROBES; it does not trust the observation.
   *  - `armTargetUid` is the uid this run resolved as the agent's run-as
   *    identity, or `undefined` when none is resolved. A marker declaring a
   *    different uid, or any marker when the subject is `undefined`, is KEPT
   *    fail-closed rather than reconciled against the wrong subject.
   *  - MUST NOT write anything on `intent: "observe"`.
   *  - MAY THROW: a present-but-unreadable marker is the fail-closed contract
   *    of `loadExclusiveRoutingMarker`. The flow turns the throw into the
   *    explicit `unreadable` verdict (see {@link ExclusiveRoutingResidue});
   *    "could not look" must never collapse into "nothing is there".
   */
  reconcileExclusiveRoutingResidue(
    armTargetUid: number | undefined,
    intent: "observe" | "clear",
  ): Promise<ExclusiveRoutingResidue>;

  /**
   * The uid of the dedicated agent account IF one already exists, or
   * `undefined` when it does not. Read ONLY as the residue gate's fallback
   * subject (see {@link resolveResidueSubjectUid} and FIX G3): the detect
   * probe resolves a uid only from a RUNNING agent process in v1, so without
   * this every host whose agent is merely stopped hit the unknown-subject
   * refusal, whose remedy is a destructive teardown.
   *
   * MUST NOT invent a uid: a lookup that finds nothing returns `undefined`,
   * and the gate then refuses fail-closed rather than judging against a guess.
   */
  lookupDedicatedAccountUid(): Promise<number | undefined>;
}

export type { ExclusiveRoutingResidue };

const EGRESS_GATE_REPAIR_QUOTED_ADVICE =
  `'${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND}' (${EGRESS_GATE_STAND_DOWN_EFFECT})`;
const EGRESS_GATE_UNPROTECT_QUOTED_ADVICE =
  `'${EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND}' (${EGRESS_GATE_STAND_DOWN_EFFECT})`;

/**
 * THE refusal sentence for a run blocked by exclusive-routing residue -- the
 * single place this claim is put into words, exported so the mapping
 * verdict -> sentence is asserted directly rather than through the flow.
 *
 * It states what was OBSERVED on disk, what that means for this run, what this
 * run did NOT change, and a way forward that actually works for THAT verdict.
 * It makes no claim about whether the wall is armed: that is a different
 * observation, and inventing it from control flow is the defect this whole fix
 * exists to close.
 *
 * FIX F2 (adversarial review, 2026-07-26): this used to be ONE sentence for
 * every keep, and it asserted "this run would be refused at the arming step
 * after changing the host". That is a counterfactual about a step the refusing
 * run never reaches -- structurally the same defect as the "The wall was NOT
 * armed" claim this PR exists downstream of, in the safe direction. It is
 * gone. The keep space is also split, because a HEALTHY live gate and an
 * uncertain surface are different facts with different remedies: telling the
 * operator of a correctly-confined agent to run `--unprotect-egress-gate`
 * tells them to de-confine a working agent and park it down.
 *
 * FIX F5: "Nothing has been changed." was false at the command level -- by the
 * time this is reached the cooperative wrap has already rewritten config and
 * bootstrapped identity. The claim is now scoped to what this flow actually
 * did not do.
 */
export type ExclusiveRoutingResidueRefusal = Extract<
  ExclusiveRoutingResidue,
  { kind: "kept-live" | "kept-uncertain" | "kept-unknown-subject" | "unreadable" | "removal-failed" }
>;

/**
 * Narrow a residue verdict to the ones that must STOP the run, or `undefined`
 * for the ones the run may continue past (`clear`, `orphaned`, `reconciled`).
 * A `switch` rather than a `!==` chain so a new verdict is a type error at this
 * seam instead of silently defaulting to "keep going".
 */
export function exclusiveRoutingResidueRefusal(
  residue: ExclusiveRoutingResidue,
): ExclusiveRoutingResidueRefusal | undefined {
  switch (residue.kind) {
    case "kept-live":
    case "kept-uncertain":
    case "kept-unknown-subject":
    case "unreadable":
    case "removal-failed":
      return residue;
    case "clear":
    case "orphaned":
    case "reconciled":
      return undefined;
  }
}

export function describeExclusiveRoutingResidueRefusal(residue: ExclusiveRoutingResidueRefusal): string {
  // F5: true at the command level. Provisioning is what did not happen; the
  // cooperative wrap around this flow has already done its own work.
  //
  // FIX G5 (re-gate, 2026-07-26): "no Castle Wall change was made by this run"
  // is DERIVED, not asserted. The one verdict that can reach this renderer
  // after a mutation is `removal-failed`, which carries what it removed; every
  // other refusal is produced before any removal is attempted, so the flat
  // sentence is true for them and provably false for that one.
  const untouched =
    residue.kind === "removal-failed" && residue.removed.length > 0
      ? ` No account was created and nothing was re-homed, but this run DID change Castle Wall state: it removed ${residue.removed.join(" and ")}.`
      : " No account was created, nothing was re-homed, and no Castle Wall change was made by this run.";
  switch (residue.kind) {
    case "kept-live":
      // A positive observation of live confinement. NOT a "could not tell", and
      // NOT necessarily a problem: the common instance is a healthy, correctly
      // armed host. So the first thing offered is "nothing needs doing".
      return (
        `Refusing to provision: this fortress already has exclusive-egress confinement in place ` +
        `(${residue.reason}). While it stands, the signing daemon composes EVERY manifest under the ` +
        "exclusive-routing rules regardless of the mode this run asked for, so a re-run cannot " +
        "compose over it. If the confinement already in place is the one you want, nothing needs " +
        `doing. If you meant to re-provision from scratch, tear the gate down first with ${EGRESS_GATE_UNPROTECT_QUOTED_ADVICE}; ` +
        `this leaves the harness parked and down. Then re-run this command.${untouched}`
      );
    case "kept-uncertain":
      return (
        `Refusing to provision: an exclusive-routing marker is present in this fortress and could ` +
        `NOT be shown to be stale (${residue.reason}). While that marker stands, the signing daemon ` +
        "composes EVERY manifest under the exclusive-routing rules regardless of the mode this run " +
        `asked for. Recover an interrupted arm with ${EGRESS_GATE_REPAIR_QUOTED_ADVICE}, ` +
        `or clear the exclusive-egress state outright with ${EGRESS_GATE_UNPROTECT_QUOTED_ADVICE}, ` +
        `then re-run this command.${untouched}`
      );
    case "kept-unknown-subject":
      // FIX F3: the one keep whose subject account may be gone entirely. The
      // verb named here works in exactly that state -- see
      // `clearExclusiveRoutingResidueWithoutAccount` in arming-wiring.ts, which
      // is the no-account fallback `--unprotect-egress-gate` now runs.
      //
      // FIX G2 (re-gate, 2026-07-26): that promise used to be UNCONDITIONAL
      // ("which removes this residue even when the dedicated agent account is
      // gone"), and the teardown it names REFUSES whenever the marker's uid
      // still has a registry entry or a gate that could serve. A sentence that
      // promises unconditionally what a branch refuses is the exact class this
      // change exists to eliminate, so it now says what each branch does.
      //
      // FIX G6 (re-gate, 2026-07-26): "no running agent" was a positive claim
      // built on a probe (`readRunningHermesGatewayUid`) that returns
      // `undefined` on a `ps` failure, a PATH problem, or a sandbox
      // restriction just as it does on a genuinely absent process. What was
      // observed is that the identity could not be DETERMINED.
      return (
        `Refusing to provision: an exclusive-routing marker for agent uid ${residue.markerAgentUid} ` +
        "is present in this fortress, but this run could not determine the agent's run-as identity " +
        "(no harness-configured uid, no dedicated agent account, and no agent process was found), " +
        "so the marker cannot be judged stale without reconciling it against an unknown subject. " +
        `Clear the leftover exclusive-egress state with ${EGRESS_GATE_UNPROTECT_QUOTED_ADVICE}: ` +
        `when nothing is still armed for uid ${residue.markerAgentUid} it ` +
        "removes the residue even with the dedicated agent account gone, and when something IS still " +
        "armed for that uid it changes nothing and names the state it found. Then re-run this " +
        `command.${untouched}`
      );
    case "unreadable":
      // FIX G8 (re-gate, 2026-07-26): this verdict is produced by ANY throw out
      // of the residue op, so asserting the MARKER was at fault was wrong
      // whenever the throw came from another surface the check reads (a
      // malformed anchor registry, say) -- and the remedy offered there removes
      // a marker that is fine and fixes nothing. The claim now tracks `source`,
      // which is classified from the error itself.
      return residue.source === "marker"
        ? `Refusing to provision: this fortress's exclusive-routing marker could NOT be read ` +
            `(${residue.detail}), so the routing mode is unknown. The signing daemon composes on that ` +
            "marker, so proceeding would mean arming over a mode nothing established. Clear the " +
            `exclusive-egress state with ${EGRESS_GATE_UNPROTECT_QUOTED_ADVICE} (which ` +
            "removes the marker once it can prove nothing is still armed), then re-run this command." +
            untouched
        : `Refusing to provision: the exclusive-routing residue check could NOT complete ` +
            `(${residue.detail}), so this fortress's routing mode is unknown. The signing daemon ` +
            "composes on the exclusive-routing marker, so proceeding would mean arming over a mode " +
            "nothing established. Fix the surface named above (the marker itself may be perfectly " +
            "readable, so removing it is not the remedy), then re-run this command." + untouched;
    case "removal-failed":
      // FIX G5: the one refusal reachable AFTER a mutation. It must state what
      // it removed, not inherit the "nothing changed" frame.
      return (
        `Refusing to provision: clearing the stale exclusive-routing residue FAILED part way ` +
        `(${residue.detail}). The fortress is now in a mixed state, so this run will not arm over ` +
        `it. Complete the teardown with ${EGRESS_GATE_UNPROTECT_QUOTED_ADVICE}, then ` +
        `re-run this command.${untouched}`
      );
  }
}

/**
 * What {@link ProvisionFlowOps.observeAgentConfinement} saw. Deliberately a
 * discriminated union: "we could not look" must be representable, because
 * collapsing it into `false` is how "nothing is armed" gets said about a host
 * that is enforcing.
 */
export type ObservedAgentConfinement =
  | {
      known: true;
      /** Uids with a committed per-uid egress-gate confinement right now. */
      confinedUids: number[];
      /** True when the fortress carries an exclusive-routing marker. */
      exclusiveRoutingMarkerPresent: boolean;
    }
  | { known: false; reason: string };

/**
 * THE enforcement-state sentence for a refused (never-armed-by-this-run)
 * provisioning attempt -- the single place this claim is put into words, and
 * it is a function of the OBSERVATION, not of the caller's position in the
 * control flow. Exported so the mapping observation -> sentence is asserted
 * directly.
 *
 * The first clause is always the same, because it is the one thing the code
 * path genuinely knows: THIS RUN did not arm anything. Everything after it
 * comes from what was measured.
 */
export function describeObservedAgentConfinement(observed: ObservedAgentConfinement): string {
  if (!observed.known) {
    return (
      "This run did not arm the wall. The host's CURRENT enforcement state could NOT be observed " +
      `(${observed.reason}), so this run makes no claim about it -- check it with: ` +
      "'sanctuary castle-wall status'."
    );
  }
  if (observed.confinedUids.length === 0 && !observed.exclusiveRoutingMarkerPresent) {
    return "This run did not arm the wall, and no per-agent egress confinement was observed on this host.";
  }
  const parts: string[] = [];
  if (observed.confinedUids.length > 0) {
    parts.push(`uid(s) ${observed.confinedUids.join(", ")} are confined by a committed egress gate`);
  }
  if (observed.exclusiveRoutingMarkerPresent) {
    parts.push("the fortress carries an exclusive-routing marker");
  }
  return (
    "This run did not arm the wall, BUT per-agent egress confinement from an EARLIER run is live on " +
    `this host (${parts.join("; ")}). A confined agent may be reaching nothing right now, and while ` +
    "the exclusive routing composition stands this coarse path will keep being refused. Clear it with: " +
    `${EGRESS_GATE_UNPROTECT_QUOTED_ADVICE}.`
  );
}

/**
 * Terminal outcome of the whole flow, for the CLI layer to render + exit-code
 * on. FIX F2/F5 (2026-07-07 fix-round): `rolledBack` on `aborted` is now
 * `boolean | "partial"` -- `"partial"` means SOME but not all re-homed paths
 * came back, which must render loud manual-recovery guidance at the CLI
 * layer, never be collapsed into a clean `true`. `backupPath` threads the
 * custody-copy location through so the CLI can print it for manual recovery.
 *
 * FIX R5 (HIGH, 2026-07-07 fix-round 2): `armed-rollback-failed` is a
 * distinct terminal outcome for the case where the post-arm connectivity
 * re-check fails AND the fast-disarm rollback ITSELF fails. Before this fix,
 * `ops.disarm()` in that branch was uncaught: a throw there propagated out of
 * `runProvisionFlow` entirely, the CLI's generic catch swallowed it into no
 * outcome at all, and the wrap's own success banner still printed -- an
 * operator could be left with an ARMED wall over a half-provisioned agent
 * and a stray disarm failure with no loud "manual recovery required"
 * message. This outcome carries `uid` (which account is affected) and
 * `disarmError` (why disarm failed) so `renderAutoProvisionOutcome` can print
 * unambiguous manual-recovery guidance.
 */
export type ProvisionFlowOutcome =
  | { kind: "skipped-already-dedicated"; reason: string }
  | { kind: "skipped-non-tty-cooperative-only"; reason: string }
  | { kind: "declined-by-operator" }
  | { kind: "armed"; uid: number }
  | {
      kind: "aborted";
      stage: string;
      reason: string;
      rolledBack: boolean | "partial";
      backupPaths?: string[];
      /**
       * FIX (round 5 / R2-2): true when a post-install abort could NOT tear
       * the harness daemon down (a root LaunchDaemon may still be live). The
       * CLI renderer keys the LOUD warning frame on this independently of
       * `rolledBack`, so a clean re-home restore (`rolledBack: true`) with a
       * failed daemon teardown is never softened into a "Note: ... re-run to
       * retry" line that contradicts its own embedded manual-recovery note.
       */
      daemonTeardownFailed?: boolean;
      /**
       * FIX (round 5 / R3-2): false when this abort fired BEFORE any re-home
       * path was moved (root-check, operator-identity, detect, create-account,
       * or a rehome that threw before moving anything), so there is genuinely
       * NOTHING to restore. The CLI renderer emits a neutral "nothing was
       * changed; safe to re-run" line for these, instead of the false
       * "restore of your re-homed files FAILED; do not re-run" alarm the
       * `rolledBack === false` branch would otherwise print (the N7 false-alarm
       * class, which the round-5 N7 fix only closed for the one rehome stage).
       * Undefined is treated as "re-home may have run" (use the rolledBack
       * framing) for backward compatibility.
       */
      rehomeAttempted?: boolean;
      /**
       * FIX (round 5 / R4-2): true when THIS run created the dedicated account
       * before aborting (create-account succeeded, then a later stage failed --
       * e.g. re-home threw before moving anything). The neutral "nothing was
       * changed" render frame keys on this so it never falsely claims "No
       * dedicated account was created" while an orphaned hidden account exists.
       * `rehomeAttempted` only tracks whether a MOVE happened, which is the
       * wrong signal for the account's existence.
       */
      accountCreated?: boolean;
      /**
       * FIX (round 5 / R5-2): sibling paths holding recovered re-homed data
       * after a RECREATED-source R6 conflict during restore. Non-empty means
       * the operator's recreated file(s) are intact and the re-homed copy is
       * safe at these paths -- the CLI renders reconcile-manually guidance and
       * must NEVER tell the operator to overwrite from the stale backup.
       */
      conflictPaths?: string[];
      /**
       * FIX (round 5 / R6-2): source paths whose restore GENUINELY failed
       * (distinct from a safe conflict). Non-empty means the CLI keeps the
       * LOUD manual-recovery frame + backup path even when conflicts also
       * occurred -- a conflict never masks a real failure.
       */
      failedPaths?: string[];
      /**
       * Bug B P0 (disarm-first): true ONLY on an ARM-stage abort where a policy
       * daemon was freshly installed this run AND `ops.disarm()` could NOT
       * confirm the content filter is off. `arm` returning ok:false does NOT
       * imply the filter is off -- on macOS Tahoe the host app can SAVE the NE
       * config ENABLED then report non-zero because its post-change status
       * corroboration timed out. Booting a FRESHLY-INSTALLED policy daemon out
       * in that state would be filter-on + daemon-down = the exact deny-all
       * lockout this feature prevents, so the freshly-installed policy daemon is
       * deliberately LEFT RUNNING (filter-on + daemon-up is enforcing and
       * RECOVERABLE). The CLI renderer keys a LOUD "the wall may still be armed;
       * run 'sanctuary castle-wall disable'" frame on this and NEVER softens it
       * into a clean "rolled back; re-run" line (the honesty gap the P0 flagged).
       */
      wallMayBeArmed?: boolean;
      /**
       * Positive observed-off evidence from `ops.disarm()`. Absence means "not
       * observed", never "off".
       */
      disarmObservedOff?: true;
    }
  | {
      kind: "armed-then-rolled-back";
      uid: number;
      reason: string;
      disarmObservedOff?: true;
    }
  | { kind: "armed-rollback-failed"; uid: number; reason: string; disarmError: string }
  /**
   * SIGINT/SIGTERM arrived after the Castle Wall arm mutation completed but
   * before the flow reached a final safe success outcome. The shutdown path
   * fast-disarmed through the same rollback operation used by the post-arm
   * verification failures, and restored provisioned egress rules to their
   * pre-run state when that could be observed.
   */
  | {
      kind: "shutdown-after-arm-rolled-back";
      uid: number;
      reason: string;
      egressRestoredToPreRunState: boolean;
      wallMayBeArmed?: true;
      disarmObservedOff?: true;
    }
  /**
   * Egress-provision outcome vocabulary (design section 5): a DISTINCT local
   * variant, never a widened shared enum (the file-grant round-4 lesson).
   * The wall ARMED, but the post-arm AS-UID egress verification failed (an
   * endpoint unreachable as the agent uid, or the negative control
   * reachable), so the flow fast-disarmed (fix B2) and put the provisioned
   * rules back to their pre-run state rather than leave a confined-into-silence
   * agent or an unverified grant. The agent stays re-homed under its dedicated
   * account.
   */
  | {
      kind: "egress-unprovisioned-rolled-back";
      uid: number;
      reason: string;
      /**
       * FIX F-REVOKE: OBSERVED -- the harness's provisioned rules match the
       * pre-run capture and the daemon confirmed the reload. On a first run the
       * pre-run state is "none", so this is the old scrub claim; on a re-run it
       * additionally asserts a previous run's grants SURVIVED. False when
       * either could not be confirmed (the outcome carries the loud note).
       */
      egressRestoredToPreRunState: boolean;
      disarmObservedOff?: true;
    }
  /**
   * S5-6 (Unified Protect Slice 5): the FULL fine-grained outcome -- coarse
   * stages proved live AND the exclusive-egress generation committed AND the
   * S5-5 release barrier released the (previously parked) harness. The only
   * fine-grained outcome that may contribute to aggregate green.
   */
  | { kind: "armed-exclusive"; uid: number; generationId: number }
  /**
   * S5-6: exclusive stack LIVE and the harness running confined, but the
   * persistent boot state could not be re-parked (the next boot could
   * auto-start the harness before G5). DISTINCT AMBER, never green; fixed by
   * `sudo sanctuary protect --repair-egress-gate --stand-down-agent`.
   */
  | { kind: "armed-exclusive-repark-failed"; uid: number; generationId: number; reparkError: string }
  /**
   * S5-6 DEGRADE-LOUD (design answer 2 choice (b), requires S5-P on every
   * surface): fine-grained was declared but the exclusive stack could not
   * come live; the PROVEN coarse wall stays armed. The manifest was
   * explicitly recomposed to coarse scope through the audited S5-4 fallback
   * (`coarseCompositionRestored`). What happened to the AGENT PROCESS is
   * `harness` and nothing else: a failed restore or a failed start is a fact
   * about this run, never evidence that a process is gone. ALWAYS a distinct
   * non-green posture (`coarse-only` / amber on every surface); NEVER silent,
   * NEVER fake-green.
   */
  | {
      kind: "exclusive-egress-unarmed-coarse-active";
      uid: number;
      stage: "bring-up" | "release";
      reason: string;
      coarseCompositionRestored: boolean;
      /**
       * What happened to the agent process. Fix-round 4 replaced the former
       * `harnessStartedCoarse: boolean`, whose FALSE branch ("this run did not
       * start it") was rendered here and at the CLI as "the agent is PARKED
       * (not running)" over processes that were demonstrably alive.
       */
      harness: HarnessDisposition;
      cleanupErrors: string[];
    };

/**
 * Mutable box threaded into the step sequence so the outcome chokepoint below
 * knows whether the (destructive) fine-grained harness install stood a
 * pre-existing agent down.
 */
interface HarnessStandDownState {
  owed: boolean;
}

const PROTECT_RETRY_COMMAND = "sudo sanctuary protect --hermes";
const CASTLE_WALL_DISABLE_COMMAND = "sudo sanctuary castle-wall disable";

function reportShutdownStatus(ctx: ProvisionFlowContext, status: ProvisionFlowShutdownStatus): void {
  ctx.onShutdownStatus?.(status);
}

function shutdownRequested(ctx: ProvisionFlowContext): boolean {
  return ctx.shutdownSignal?.aborted === true;
}

function shutdownReason(ctx: ProvisionFlowContext): string {
  const reason = ctx.shutdownSignal?.reason;
  if (reason instanceof Error) return reason.message;
  if (typeof reason === "string" && reason.length > 0) return reason;
  return "process shutdown requested";
}

function shutdownRollbackReason(ctx: ProvisionFlowContext, checkpoint: string): string {
  return (
    `shutdown requested (${shutdownReason(ctx)}) at ${checkpoint}; ` +
    "stopping automatic account provisioning before the next mutation and running the normal rollback path."
  );
}

function shutdownBeforeRehomeOutcome(
  ctx: ProvisionFlowContext,
  stage: string,
  accountCreated: boolean,
  reason?: string,
): Extract<ProvisionFlowOutcome, { kind: "aborted" }> {
  return {
    kind: "aborted",
    stage,
    reason:
      reason ??
      (accountCreated
        ? `shutdown requested (${shutdownReason(ctx)}) after the dedicated account was created and before any file move; no re-home, egress, or Castle Wall arm change was made by this run.`
        : `shutdown requested (${shutdownReason(ctx)}) before account, re-home, egress, or Castle Wall arm mutation; no privileged provisioning change was made by this run.`),
    rolledBack: false,
    rehomeAttempted: false,
    accountCreated,
  };
}

async function rollbackPreArmForShutdown(input: {
  ctx: ProvisionFlowContext;
  ops: ProvisionFlowOps;
  stage: string;
  rehomeResults: RehomeStepResult[];
  accountCreated: boolean;
  tearDownDaemon: boolean;
  tearDownPolicyDaemon: boolean;
  restoreEgress?: boolean;
}): Promise<Extract<ProvisionFlowOutcome, { kind: "aborted" }>> {
  reportShutdownStatus(input.ctx, {
    stage: `rollback-${input.stage}`,
    residualState:
      "shutdown rollback is in flight; the harness daemon, policy daemon, provisioned egress rules, or re-homed files may be mid-restore",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });
  const td = await teardownDaemonAndRestore(
    input.ops,
    input.rehomeResults,
    input.tearDownDaemon,
    input.tearDownPolicyDaemon,
    input.restoreEgress === true,
  );
  return {
    kind: "aborted",
    stage: input.stage,
    reason: withDaemonTeardownNote(
      shutdownRollbackReason(input.ctx, input.stage),
      td.daemonTeardownError,
      td.policyDaemonTeardownError,
      td.egressRestoreNote,
    ),
    rolledBack: td.rolledBack,
    backupPaths: td.backupPaths,
    conflictPaths: td.conflictPaths,
    failedPaths: td.failedPaths,
    daemonTeardownFailed:
      td.daemonTeardownError !== undefined || td.policyDaemonTeardownError !== undefined,
    rehomeAttempted: input.rehomeResults.some((r) => r.status === "moved"),
    accountCreated: input.accountCreated,
  };
}

async function rollbackAfterArmForShutdown(
  ctx: ProvisionFlowContext,
  ops: ProvisionFlowOps,
  uid: number,
  stage: string,
  egressProvisionedThisRun: boolean,
): Promise<ProvisionFlowOutcome> {
  reportShutdownStatus(ctx, {
    stage: `rollback-${stage}`,
    residualState:
      "shutdown rollback is in flight after Castle Wall arm; the wall disarm and pre-run egress-rule restore may not yet be observed",
    recoveryCommand: CASTLE_WALL_DISABLE_COMMAND,
  });
  let disarmObservedOff = false;
  let wallMayBeArmed = false;
  let disarmOutcome: "fast-disarmed" | "disarm-uncorroborated" = "fast-disarmed";
  try {
    const disarmResult = await ops.disarm();
    disarmObservedOff = disarmOutcomeObservedOff(disarmResult.nePreferenceOutcome);
    if (!disarmOutcomeAllowsFreshDaemonTeardown(disarmResult.nePreferenceOutcome)) {
      wallMayBeArmed = true;
      disarmOutcome = "disarm-uncorroborated";
    }
  } catch (disarmErr) {
    await auditEgressRefusalBestEffort(ops, ctx, uid, {
      stage,
      disarm_outcome: "disarm-failed",
    });
    return {
      kind: "armed-rollback-failed",
      uid,
      reason:
        `shutdown requested (${shutdownReason(ctx)}) at ${stage}; automatic shutdown rollback could not confirm the Castle Wall is off.`,
      disarmError: (disarmErr as Error).message,
    };
  }
  const restoreNote = await restoreEgressBestEffort(ops, egressProvisionedThisRun);
  await auditEgressRefusalBestEffort(ops, ctx, uid, {
    stage,
    disarm_outcome: disarmOutcome,
    egress_rules_restored_to_pre_run_state: restoreNote === "",
  });
  return {
    kind: "shutdown-after-arm-rolled-back",
    uid,
    reason:
      `shutdown requested (${shutdownReason(ctx)}) at ${stage}; fast-disarmed before exit rather than leave an unverified armed wall.` +
      (wallMayBeArmed
        ? " WARNING: disarm reported success as a dead-man lever but did NOT save the NE preference disabled; the wall may still be enabled at the preference level."
        : "") +
      egressRestoreReasonSuffix(restoreNote),
    egressRestoredToPreRunState: restoreNote === "",
    wallMayBeArmed: wallMayBeArmed ? true : undefined,
    disarmObservedOff: disarmObservedOff ? true : undefined,
  };
}

async function coarseOnlyShutdownBeforeExclusiveOutcome(
  ctx: ProvisionFlowContext,
  ops: ProvisionFlowOps,
  uid: number,
): Promise<Extract<ProvisionFlowOutcome, { kind: "exclusive-egress-unarmed-coarse-active" }>> {
  reportShutdownStatus(ctx, {
    stage: "shutdown-before-exclusive-egress-coarse-only",
    residualState:
      "coarse Castle Wall enforcement is verified live; shutdown is preserving coarse enforcement and settling the harness disposition",
    recoveryCommand: EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND,
  });
  const cleanupErrors: string[] = [];
  let harness: HarnessDisposition | undefined;
  try {
    await ops.exclusiveEgress!.startHarnessCoarse();
    harness = startedCoarseDisposition();
  } catch (err) {
    cleanupErrors.push(
      `coarse harness start failed (this run did not start the agent): ${(err as Error).message}`,
    );
  }
  if (harness === undefined) {
    harness = { disposition: "not-started", claim: await ops.exclusiveEgress!.assessHarnessParked() };
  }
  await ops.exclusiveEgress!.audit(EGRESS_PROVISION_REFUSED_AUDIT_OP, {
    stage: "shutdown-before-exclusive-egress",
    harness: ctx.agentId,
    agent_uid: uid,
    outcome: "exclusive-egress-unarmed-coarse-active",
    coarse_wall_preserved: true,
    cleanup_errors: cleanupErrors,
  });
  return {
    kind: "exclusive-egress-unarmed-coarse-active",
    uid,
    stage: "bring-up",
    reason:
      `shutdown requested (${shutdownReason(ctx)}) after coarse Castle Wall enforcement was verified and before exclusive egress armed; preserving proven-live coarse enforcement instead of disarming it.`,
    coarseCompositionRestored: true,
    harness,
    cleanupErrors,
  };
}

async function auditEgressRefusalBestEffort(
  ops: ProvisionFlowOps,
  ctx: ProvisionFlowContext,
  uid: number,
  details: Record<string, unknown>,
): Promise<void> {
  try {
    await ops.auditEgress(EGRESS_PROVISION_REFUSED_AUDIT_OP, {
      harness: ctx.agentId,
      agent_uid: uid,
      declared_endpoints: ctx.harnessEndpoints.endpoints.map((e) => `${e.host}:${e.port}`),
      ...details,
    });
  } catch {
    // Shutdown rollback audit is best-effort; the rollback outcome still has to surface.
  }
}

/**
 * Outcomes after which the harness is NOT owed a restore, because the
 * exclusive-egress stage has taken ownership of it:
 *   - `armed-exclusive` / `armed-exclusive-repark-failed`: the release barrier
 *     started the agent under a committed generation. Restoring the PRE-run
 *     plist here would tear a correctly-confined agent back to coarse.
 *   - `exclusive-egress-unarmed-coarse-active`: the S5-6 degrade path already
 *     decided the harness's disposition (`harness`) and says so loudly in its
 *     own outcome, INCLUDING the case where it could not decide -- a degrade
 *     whose claim is `alive` or `unknown` still suppresses the chokepoint
 *     restore, because restoring a plist under a live process would fight it.
 *     The suppression is right; what round 4 fixed is the CLAIM attached to
 *     it, which used to say "parked" regardless.
 *
 * Deliberately an ALLOW-LIST of "already handled", not a deny-list of aborts:
 * a new abort kind added later defaults to restoring, which is the safe
 * direction. Getting on this list has to be a deliberate act.
 */
const OUTCOMES_THAT_OWN_THE_HARNESS: ReadonlySet<string> = new Set([
  "armed-exclusive",
  "armed-exclusive-repark-failed",
  "exclusive-egress-unarmed-coarse-active",
]);

/**
 * Run the full one-flow orchestration. Every fail-closed branch below is
 * reachable purely through the injected ops, so unit tests can assert each
 * outcome without a real host.
 *
 * THE HARNESS-RESTORE CHOKEPOINT (drill-D2 fix-round, 2026-07-18). In
 * fine-grained mode the harness install is destructive: it stops the
 * operator's live agent. Everything between that step and the exclusive stage
 * can still refuse, and both gate lenses found that none of those refusals put
 * the agent back. Rather than add a restore call to each of them -- the shape
 * that guarantees the next one added is missed -- the decision is made ONCE,
 * here, from the outcome. Anything that is not an outcome where the exclusive
 * stage owns the harness gets the agent restored, including a throw.
 */
export async function runProvisionFlow(
  ctx: ProvisionFlowContext,
  ops: ProvisionFlowOps,
): Promise<ProvisionFlowOutcome> {
  reportShutdownStatus(ctx, {
    stage: "preflight",
    residualState: "no privileged provisioning mutation has run yet",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });
  const standDown: HarnessStandDownState = { owed: false };
  let outcome: ProvisionFlowOutcome;
  try {
    outcome = await runProvisionFlowSteps(ctx, ops, standDown);
  } catch (err) {
    // A step that THREW rather than returning an outcome is exactly the abort
    // path nobody enumerates. Restore, then let the original error surface.
    // FIX-ROUND 2: the restore's own verdict is PRINTED here rather than
    // swallowed. The thrown error still wins as the outcome, but a restore
    // that left the agent stopped is news the operator needs regardless of
    // what else went wrong, and this path had no way to tell them.
    if (standDown.owed) await restoreStoodDownHarnessQuietly(ops);
    throw err;
  }
  if (!standDown.owed || OUTCOMES_THAT_OWN_THE_HARNESS.has(outcome.kind)) {
    return outcome;
  }
  reportShutdownStatus(ctx, {
    stage: "harness-restore",
    residualState:
      "rollback is restoring the stood-down harness; the launchd plist or run state may be mid-restore, and re-homed files may remain on the dedicated account",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });
  const restore = await restoreStoodDownHarnessOrWeakenedClaim(ops);
  const note = harnessRestoreNote(restore, outcome.kind);
  if (!("reason" in outcome) || typeof outcome.reason !== "string") {
    // FIX-ROUND 2 (MED): the restore DECISION defaults to safe (an allow-list
    // of outcomes that own the harness, so a new abort restores). The restore
    // NOTE used to default to SILENCE -- an outcome without a `reason` field
    // dropped the message on the floor, including the loud one that names the
    // agent as stopped. Today no such outcome co-occurs with a stand-down, but
    // "currently unreachable" is how the last two blockers started. There is
    // no longer a shape of outcome that can swallow it.
    ops.print(note);
    return outcome;
  }
  return { ...outcome, reason: `${outcome.reason} ${note}` } as ProvisionFlowOutcome;
}

/** Best-effort restore on the throw path; the original error must win. */
async function restoreStoodDownHarnessQuietly(ops: ProvisionFlowOps): Promise<void> {
  try {
    ops.print(harnessRestoreNote(await restoreStoodDownHarnessOrWeakenedClaim(ops), "aborted"));
  } catch {
    // The caller is already propagating a more important failure.
  }
}

/**
 * The restore op, with a THROWN op turned into an explicitly WEAKENED claim
 * rather than into silence (fix-round 6).
 *
 * The old fallback synthesized `{ restored: false, wasRunning: true }` and
 * nothing else. Under the invariant `runStateOwed` states, that shape OWES the
 * operator a run-state sentence and had none to give -- so the renderer had no
 * choice but to invent one, which is exactly how the eleventh instance got
 * written. An op that threw is the textbook `cannotProbe` case: the claim says
 * what was NOT observed, and the advice that follows tells the operator to
 * establish the state themselves rather than to assume the agent is down.
 */
async function restoreStoodDownHarnessOrWeakenedClaim(
  ops: ProvisionFlowOps,
): Promise<Awaited<ReturnType<ProvisionFlowOps["restoreStoodDownHarness"]>>> {
  try {
    return await ops.restoreStoodDownHarness();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      restored: false,
      wasRunning: true,
      harnessRestarted: false,
      problems: [message],
      runState: runStateAdvice(
        await assessHarnessParked({
          cannotProbe: `the restore operation itself failed before any run-state read (${message})`,
        }),
      ),
    };
  }
}

/**
 * Outcomes that restore the harness but deliberately do NOT reverse the
 * re-home (they return directly, without `teardownDaemonAndRestore`). The
 * agent is put back, but under its pre-run account and home -- whose secrets
 * this run already moved to the dedicated account. Saying "restored to its
 * previous state" there is false in a way that matters: the restarted harness
 * may not find its credentials.
 */
const OUTCOMES_THAT_KEEP_THE_REHOME: ReadonlySet<string> = new Set([
  "armed-rollback-failed",
  "shutdown-after-arm-rolled-back",
]);

/**
 * The operator-facing sentence about the restore, built ONLY from observed
 * facts (fix-round 2, 2026-07-18; tightened fix-round 4, 2026-07-19).
 *
 * The rule this PR has now had to learn several times: state what was seen,
 * not what was attempted. `harnessRestarted` is true only when a restart was
 * verified against launchd, and `wasRunning` distinguishes "correctly not
 * restarted" from "should be running and is not" -- a distinction the previous
 * single boolean collapsed, which is how a stopped agent got described as
 * restarted.
 *
 * FIX-ROUND 4 found two SURVIVING run-state assertions here, and found them
 * with the round's own render-layer guard rather than by review: the failed-
 * restore branch said "The agent is STOPPED" and the never-was-running branch
 * said "is not running now". Both were derived from the restore having failed
 * or not been attempted -- control flow -- over a process nothing here probed.
 * This function is SYNCHRONOUS and has no launchd access, so the correct fix
 * is the weakened form: it now states only what this RUN did, and makes no
 * assertion about whether a process is alive. A caller that needs the run
 * state must obtain a `ParkedClaim` from `assessHarnessParked`.
 *
 * FIX-ROUND 6 found that the weakened form was not the end of it. The failed-
 * restore branch went on to say "and did not verify its run state" and to
 * instruct "Re-run ... to bring it back up" -- over a harness the run HAD
 * verified, across twenty samples, as alive at pid 9001. The observation was
 * discarded one frame away at the op boundary. Two lessons are encoded here:
 *
 *   - A weakened claim states what was NOT observed. "Did not verify its run
 *     state" states that no observation OCCURRED, which is a different and
 *     falsifiable thing -- and it was false.
 *   - An IMPERATIVE premised on a state is a claim about that state. This
 *     function no longer composes one. Where a run state is owed it prints the
 *     branded `RunStateAdvice` the op observed; where none is owed it makes no
 *     run-state claim and issues no run-state instruction.
 */
function harnessRestoreNote(
  restore: {
    restored: boolean;
    wasRunning: boolean;
    harnessRestarted: boolean;
    problems: string[];
    runState?: RunStateAdvice;
  },
  outcomeKind: string,
): string {
  if (!restore.restored) {
    // `runState` is absent EXACTLY when none is owed -- i.e. nothing was
    // running before this run, so there is no "bring it back up" to give and
    // saying otherwise would be the same defect in the opposite direction.
    const advice =
      restore.runState !== undefined
        ? restore.runState.text
        : "Nothing was running before this run began, so no restart is owed; resolve the problem(s) above " +
          "before re-running 'sudo sanctuary protect --hermes'.";
    return (
      `The agent harness this run stood down could NOT be fully restored: ${restore.problems.join("; ")}. ` +
      advice
    );
  }
  const what = restore.harnessRestarted
    ? "was restarted and is running again"
    : restore.wasRunning
      ? "was put back"
      : "was put back; it was not running before this run, and this run did not start it";
  const scope = OUTCOMES_THAT_KEEP_THE_REHOME.has(outcomeKind)
    ? " NOTE: the re-home was deliberately NOT reversed on this outcome, so the harness is back but its " +
      "secrets remain on the dedicated account. This is not a return to your previous state."
    : "";
  return `The agent harness this run stood down ${what}.${scope}`;
}

async function runProvisionFlowSteps(
  ctx: ProvisionFlowContext,
  ops: ProvisionFlowOps,
  standDown: HarnessStandDownState,
): Promise<ProvisionFlowOutcome> {
  let uid: number;
  // Re-home results accumulated so far, threaded into every restore call
  // below. Empty when `alreadyDedicated` skipped create + re-home (fix F6:
  // there is nothing to restore in that path, since neither step ran).
  let rehomeResults: RehomeStepResult[] = [];
  // FIX (round 5 / R4-2): true once THIS run's create-account succeeds, so an
  // abort at a later stage can tell the operator an orphaned hidden account
  // exists rather than falsely claiming "no account was created". Stays false
  // on the alreadyDedicated path (the account pre-existed; we did not create
  // it) and for every pre-create abort.
  let accountCreated = false;

  // S5-6 PREFLIGHT (fail-closed BEFORE any mutation): a fine-grained
  // provision without the exclusive arming stage wired is a caller contract
  // violation -- proceeding would end with a permanently parked agent (the
  // parked install has no release path) or, worse, tempt a wiring layer into
  // an un-parked install. Refuse up front; nothing has been changed.
  if (ctx.fineGrainedDeclared === true && ops.exclusiveEgress === undefined) {
    return {
      kind: "aborted",
      stage: "exclusive-egress-preflight",
      reason:
        "fine-grained (exclusive-egress) mode was declared but no exclusive-egress arming ops were " +
        "wired; refusing to provision (the parked agent would have no release path). Nothing was changed.",
      rolledBack: false,
      rehomeAttempted: false,
    };
  }

  // FIX F6 (HIGH, Codex second family, 2026-07-07 fix-round): `alreadyDedicated`
  // used to short-circuit straight to "done" -- reporting "already a
  // dedicated account" while NONE of daemon-install, verify, the uid-gate,
  // or arm ever ran. `detect.ts` now only sets `alreadyDedicated` when the
  // account name/shape was VERIFIED (not uid alone), and this branch now
  // skips ONLY create + re-home (there is genuinely nothing to move: the
  // account already exists and is presumed to already hold its config) --
  // it falls through to the SAME daemon-install -> verify -> uid-gate -> arm
  // -> post-arm-verify sequence as the fresh-provision path, never
  // returning "skipped-already-dedicated" as a terminal state on its own.
  //
  // FIX R4 (HIGH, 2026-07-07 fix-round 2): the F6 fix above introduced a
  // regression -- the plan-and-print / non-TTY-refusal / one-confirm
  // ceremony (steps 2-3) lived ONLY in the `else` (fresh-provision) branch,
  // so `alreadyDedicated` fell straight through to install-daemon -> verify
  // -> uid-gate -> ARM with no confirm and no non-TTY refusal. Arming IS a
  // privileged mutation regardless of which branch reaches it, so the
  // ceremony now runs UNCONDITIONALLY, before either branch's mutations,
  // restoring the ratified "ONE safety-confirm" + "non-TTY refuses
  // privileged steps" invariants for both paths.
  if (ctx.detectResult.alreadyDedicated && ctx.detectResult.resolved === undefined) {
    // Defensive: `alreadyDedicated` without a resolved uid is a caller
    // contract violation. Fail closed rather than dereference undefined.
    return {
      kind: "aborted",
      stage: "detect",
      reason: "detectResult.alreadyDedicated is true but no uid was resolved; refusing to proceed.",
      rolledBack: false,
      rehomeAttempted: false,
    };
  }

  reportShutdownStatus(ctx, {
    stage: "plan-and-confirm",
    residualState: "no privileged provisioning mutation has run yet; the flow is still before the operator confirmation",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });

  // Step 2: plan-and-print. No mutation yet, either branch.
  ops.print(
    ctx.detectResult.alreadyDedicated
      ? `Agent already runs as a verified dedicated account (uid ${ctx.detectResult.resolved!.uid}): ` +
          `${ctx.detectResult.reason} Skipping account creation and re-home; still installing the harness ` +
          `daemon, verifying, and arming.`
      : `Plan: create hidden account "${ctx.accountName}" (no login), move Hermes config/secrets onto it, ` +
          `install the ai.sanctuaryprotocol.agent-harness LaunchDaemon, then arm with ` +
          `--agent-uid=<new uid> --ceiling=${ctx.ceiling}.`,
  );
  // Egress-grant plan (design section 3.1(b)): every allow rule this flow will
  // provision is NAMED before the one confirm, with the exfil-risk marking on
  // messaging hosts (the operator signs that grant knowingly) and the
  // broad-authority marking on shared gateways (MED-1). Printed on BOTH
  // branches -- the alreadyDedicated path provisions egress too.
  for (const line of renderEgressPlanLines(ctx.harnessEndpoints)) {
    ops.print(line);
  }

  // Step 3: ONE confirm, scoped to the privileged sub-steps only (fix H4;
  // fix R4 extends this ceremony to the alreadyDedicated branch, since arm
  // is a privileged mutation on BOTH paths). Non-TTY refusal applies HERE
  // ONLY -- the caller (wrap/cli.ts) is responsible for letting the
  // cooperative wrap itself still complete; this function just reports that
  // provisioning was skipped so the caller knows to print the
  // "cooperative-only, re-run interactively" message.
  if (!ctx.isTty) {
    return {
      kind: "skipped-non-tty-cooperative-only",
      reason:
        "provisioning requires an interactive confirm and this run is non-interactive (no TTY); " +
        "the cooperative wrap still completed. Re-run interactively to provision the account and arm the wall.",
    };
  }

  // `--provision-agent-account[=name]` (fix L2) pre-answers the CHOICE
  // only -- it does NOT skip the confirm. If the operator pre-declined,
  // stop before printing the confirm prompt at all.
  if (ctx.preAnsweredProvision === false) {
    return { kind: "declined-by-operator" };
  }

  reportShutdownStatus(ctx, {
    stage: "exclusive-routing-residue",
    residualState: "no account, re-home, egress, or Castle Wall arm mutation has run yet; the flow is checking stale exclusive-routing residue",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });

  // EXCLUSIVE-ROUTING RESIDUE GATE, JUDGEMENT HALF (FIX F-COARSE-AFTER-EXCLUSIVE
  // class half, 2026-07-26; placement per FIX F1/F2, 2026-07-26).
  //
  // MODE-INDEPENDENT: it runs on every run, coarse or fine-grained. See
  // `ProvisionFlowOps.reconcileExclusiveRoutingResidue` for why mode cannot be
  // a condition here (the daemon composes on marker presence alone).
  //
  // PLACEMENT. This sits BELOW the non-TTY refusal and the pre-declined return
  // and ABOVE the confirm, and it is deliberately BOTH:
  //  - below the two early returns, because the first cut ran the whole gate --
  //    self-heal removal included -- ahead of them, so a scripted non-TTY run
  //    and an explicit `--no-provision-agent-account` decline both DELETED two
  //    fortress policy files and then reported that provisioning was skipped.
  //    A run that was never going to arm must not reach this op at all.
  //  - above the confirm, because a run that is already doomed must be refused
  //    before an operator is asked to approve it.
  // The removal itself waits for the confirm (see the CLEAR half below), which
  // is this function's own rule at the confirm: a step that cannot be undone
  // runs only after every step that can still say no has said yes.
  // FIX G3: the subject is the resolved run-as uid, falling back to the
  // dedicated account's own uid when this run could not resolve one (the
  // common case: the agent is simply not running). Resolved ONCE and used for
  // BOTH halves, so the clear half cannot be scoped differently from the
  // observe half that the operator confirmed.
  const residueSubjectUid = await resolveResidueSubjectUid(ops, ctx.detectResult.resolved?.uid);
  const residue = await reconcileResidueSafely(ops, residueSubjectUid, "observe");
  const refusal = exclusiveRoutingResidueRefusal(residue);
  if (refusal !== undefined) {
    return {
      kind: "aborted",
      stage: "exclusive-routing-residue",
      reason: describeExclusiveRoutingResidueRefusal(refusal),
      rolledBack: false,
      rehomeAttempted: false,
    };
  }
  if (shutdownRequested(ctx)) {
    return shutdownBeforeRehomeOutcome(ctx, "shutdown-before-confirm", false);
  }
  if (residue.kind === "orphaned") {
    // Name the removal BEFORE the confirm, so the yes covers it.
    ops.print(
      "A stale exclusive-routing marker left by an interrupted prior arm is present and will be " +
        `cleared if you proceed (${residue.detail}).`,
    );
  }

  const proceed = await ops.confirm("Proceed with account creation and arming? [y/N] ", ctx.shutdownSignal);
  if (!proceed) {
    return { kind: "declined-by-operator" };
  }
  if (shutdownRequested(ctx)) {
    return shutdownBeforeRehomeOutcome(ctx, "shutdown-after-confirm", false);
  }

  // RESIDUE GATE, CLEAR half: the FIRST mutation of this run, immediately after
  // the one confirm and still before the account create, the re-home, every
  // daemon install, provision-egress, and the arm. It RE-PROBES rather than
  // trusting the observation above: the confirm prompt is operator think-time,
  // and removing a marker whose confinement came live in that window would be a
  // de-confinement. A verdict that is no longer `orphaned` aborts here, with
  // the host still untouched.
  if (residue.kind === "orphaned") {
    reportShutdownStatus(ctx, {
      stage: "exclusive-routing-residue-clear",
      residualState:
        "a stale exclusive-routing marker may be cleared, but no account, re-home, egress, or Castle Wall arm mutation has run",
      recoveryCommand: PROTECT_RETRY_COMMAND,
    });
    const cleared = await reconcileResidueSafely(ops, residueSubjectUid, "clear");
    const clearedRefusal = exclusiveRoutingResidueRefusal(cleared);
    if (clearedRefusal !== undefined) {
      return {
        kind: "aborted",
        stage: "exclusive-routing-residue",
        reason: describeExclusiveRoutingResidueRefusal(clearedRefusal),
        rolledBack: false,
        rehomeAttempted: false,
      };
    }
    if (cleared.kind === "orphaned") {
      // The op judged the marker orphaned and did not remove it, on a call whose
      // whole purpose was removal. Refuse rather than arm over state this run
      // did not clear.
      return {
        kind: "aborted",
        stage: "exclusive-routing-residue",
        reason:
          "Refusing to provision: the exclusive-routing residue teardown reported the marker as " +
          "still orphaned instead of removing it, so the marker is still on disk and the signing " +
          "daemon would still compose exclusive. No account was created, nothing was re-homed, and " +
          "no Castle Wall change was made by this run.",
        rolledBack: false,
        rehomeAttempted: false,
      };
    }
    if (shutdownRequested(ctx)) {
      return shutdownBeforeRehomeOutcome(
        ctx,
        "shutdown-after-exclusive-routing-residue",
        false,
        `shutdown requested (${shutdownReason(ctx)}) after clearing stale exclusive-routing residue; this run did remove that stale marker, but no account was created, no files were re-homed, no provisioned egress rules were published, and the Castle Wall was not armed.`,
      );
    }
  }

  if (ctx.detectResult.alreadyDedicated) {
    uid = ctx.detectResult.resolved!.uid;
  } else {
    // Step 4: create the dedicated hidden service account.
    reportShutdownStatus(ctx, {
      stage: "create-account",
      residualState: "the dedicated account may be created, but files have not been re-homed and Castle Wall has not been armed",
      recoveryCommand: PROTECT_RETRY_COMMAND,
    });
    try {
      const created = await ops.createAccount();
      uid = created.uid;
      accountCreated = true;
      ops.print(`Account "${ctx.accountName}" ready at uid ${uid}.`);
    } catch (err) {
      return {
        kind: "aborted",
        stage: "create-account",
        reason: (err as Error).message,
        rolledBack: false,
        rehomeAttempted: false,
      };
    }
    if (shutdownRequested(ctx)) {
      return shutdownBeforeRehomeOutcome(ctx, "shutdown-after-create-account", accountCreated);
    }

    // Step 5: re-home (backup-first, reversible).
    reportShutdownStatus(ctx, {
      stage: "rehome",
      residualState: "the dedicated account exists and file re-home may be partially complete; rollback must restore moved paths from backups",
      recoveryCommand: PROTECT_RETRY_COMMAND,
    });
    try {
      const rehomed = await ops.rehome(uid, uid);
      rehomeResults = rehomed.results;
      ops.print(`Re-homed ${rehomeResults.filter((r) => r.status === "moved").length} path(s) onto the new account.`);
    } catch (err) {
      // FIX R3 (HIGH, 2026-07-07 fix-round 2): a rehome failure can be a
      // PARTIAL failure -- some paths already moved (and were backed up)
      // before the step that threw. `RehomeExecutionError` (rehome.ts)
      // carries those already-completed results; route them through
      // `safeRestore` exactly like every other post-move abort below,
      // instead of reporting `rolledBack: false` with an empty backup-path
      // list while secrets actually sit un-restored under the new account.
      const partialResults = err instanceof RehomeExecutionError ? err.partialResults : [];
      const restore = await safeRestore(ops, partialResults);
      return {
        kind: "aborted",
        stage: "rehome",
        reason: (err as Error).message,
        // FIX (round 5, item N7): use the restore result unconditionally.
        // The pre-fix `partialResults.length > 0 ? ... : false` forced
        // `rolledBack: false` when rehome failed BEFORE any move (empty
        // partialResults), which made the CLI print a false "restore FAILED /
        // manual recovery required / do not re-run" alarm even though nothing
        // was ever moved. safeRestore([]) trivially reports fullyRestored ->
        // rolledBack: true (nothing to roll back), which is the honest state.
        rolledBack: restore.rolledBack,
        backupPaths: restore.backupPaths,
        conflictPaths: restore.conflictPaths,
        failedPaths: restore.failedPaths,
        // FIX (round 5 / R3-2): only "attempted" if a move actually landed;
        // an empty-partialResults rehome throw moved nothing, so the CLI
        // shows the neutral "nothing changed" frame, not a restore claim.
        rehomeAttempted: partialResults.some((r) => r.status === "moved"),
        // FIX (round 5 / R4-2): create-account already succeeded by the time
        // re-home runs, so an orphaned hidden account exists even when nothing
        // moved -- the neutral frame must not claim "no account was created".
        accountCreated,
      };
    }
    if (shutdownRequested(ctx)) {
      return rollbackPreArmForShutdown({
        ctx,
        ops,
        stage: "shutdown-after-rehome",
        rehomeResults,
        accountCreated,
        tearDownDaemon: false,
        tearDownPolicyDaemon: false,
      });
    }
  }

  // Step 6 (Bug B, the one-flow gap): ensure a reachable Castle Wall POLICY
  // daemon for the target fortress. Arming with no policy daemon deny-all-locks
  // the box (filter on + daemon down); the arm's own probe refuses in that
  // state, so on a box with no wall for this fortress the whole flow would
  // otherwise roll back. Stand the policy daemon up here (install a fresh
  // singleton boot service on a box with no wall; (re)start a stopped one that
  // already targets this fortress; REFUSE to swap a wall that belongs to a
  // DIFFERENT fortress -- one machine runs one wall). This step NEVER arms the
  // filter and NEVER leaves the box filter-on/daemon-down.
  //
  // ORDER (drill-D2 fix-round, 2026-07-18): this used to run AFTER the harness
  // install, as "step 6.5". It moved ahead of it because the harness install in
  // fine-grained mode is DESTRUCTIVE -- it stands the operator's live agent
  // down -- while this step is the flow's most likely refusal, and the one the
  // 2026-07-18 drill actually hit ("one machine runs one wall"). Refusing here
  // used to cost the operator a stopped agent that nothing restarted; refusing
  // BEFORE the destructive step costs them nothing. The general rule the two
  // gate lenses converged on: a step that cannot be undone runs only after
  // every step that can still say no has said yes.
  reportShutdownStatus(ctx, {
    stage: "ensure-policy-daemon",
    residualState:
      "file re-home may already be complete; a fresh Castle Wall policy daemon may be installed and must be torn down on rollback",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });
  const ensure = await ops.ensurePolicyDaemon(ctx.fortressPath);
  if (!ensure.ok) {
    // Fail-closed: we never proceed to arm without a reachable policy daemon.
    // Nothing has been installed or stood down yet (that is the whole point of
    // this step's position), so the only thing to reverse is the re-home. A
    // FRESH policy daemon this attempt stood up is still torn back down.
    const td = await teardownDaemonAndRestore(ops, rehomeResults, false, ensure.freshlyInstalled);
    return {
      kind: "aborted",
      stage: "ensure-policy-daemon",
      reason: withDaemonTeardownNote(ensure.error, td.daemonTeardownError, td.policyDaemonTeardownError),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined || td.policyDaemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }
  if (shutdownRequested(ctx)) {
    return rollbackPreArmForShutdown({
      ctx,
      ops,
      stage: "shutdown-after-ensure-policy-daemon",
      rehomeResults,
      accountCreated,
      tearDownDaemon: false,
      tearDownPolicyDaemon: ensure.freshlyInstalled,
    });
  }
  // Only meaningful on the ok path: whether THIS run stood up the machine's wall
  // from nothing. Every LATER abort branch below threads this into
  // `teardownDaemonAndRestore` so a fresh install is torn back down while a
  // pre-existing (or already-reachable) wall is left untouched.
  const policyDaemonFreshlyInstalled = ensure.freshlyInstalled;
  ops.print(
    policyDaemonFreshlyInstalled
      ? "Castle Wall policy daemon installed for this fortress; ready to arm."
      : "Castle Wall policy daemon reachable for this fortress; ready to arm.",
  );

  // Step 6.5: install the harness daemon. Agent now runs at ruid = uid; wall
  // NOT yet armed. A failure here means we already moved secrets -- restore
  // them before reporting the abort (never leave a half-provisioned agent).
  reportShutdownStatus(ctx, {
    stage: "install-daemon",
    residualState:
      "the harness daemon may be installed or parked under the dedicated account; rollback must tear down this run's daemon work and restore re-homed files",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });
  const install = await ops.installHarnessDaemon(uid);
  if (!install.ok) {
    // FIX (round 5, item N3 / R8-1): a failed install may have left a fresh
    // daemon live (the belt-and-suspenders bootstrap-then-verify path). Tear it
    // down iff this attempt stood one up -- `!daemonPreexisted` is the honest
    // signal (never the `!alreadyDedicated` heuristic, which does not track
    // daemon presence): a fresh daemon this attempt left live is removed; a
    // genuinely pre-existing daemon (R6-3) is preserved.
    // ORDER CHANGE (2026-07-18): ensure-policy-daemon now runs BEFORE this
    // step, so a policy daemon this run freshly installed must be torn back
    // down here too (a pre-existing wall is still never touched).
    const td = await teardownDaemonAndRestore(
      ops,
      rehomeResults,
      !install.daemonPreexisted,
      policyDaemonFreshlyInstalled,
    );
    return {
      kind: "aborted",
      stage: "install-daemon",
      reason: withDaemonTeardownNote(install.error, td.daemonTeardownError, td.policyDaemonTeardownError),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined || td.policyDaemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }
  // FIX (round 5 / R7-1): the honest "did this run stand the daemon up" signal
  // -- the post-install abort branches key their teardown on it (never on
  // `alreadyDedicated`, which does not track daemon presence).
  const daemonBootstrappedThisRun = install.bootstrappedThisRun;
  // Drill-D2 fix-round: the SECOND, independent signal -- did this install
  // stop/overwrite a job that was already there? From here on, ANY outcome
  // that is not one where the exclusive stage owns the harness owes the
  // operator a restore, handled once at the outcome chokepoint (see
  // `runProvisionFlow`). Recorded before the barrier assertion below so even
  // that abort restores.
  standDown.owed = install.harnessStoodDown === true;

  // S5-6 BARRIER ASSERTION (fail-closed): in fine-grained mode the install
  // MUST have been the S5-5 PARKED form -- a bootstrapped (running) agent
  // before the release barrier is the exact BLOCKER-2 escape the barrier
  // exists to close. Tear the daemon back down and abort rather than proceed
  // with an agent that is already running unconfined-by-the-gate.
  if (ctx.fineGrainedDeclared === true && install.parked !== true) {
    const td = await teardownDaemonAndRestore(
      ops,
      rehomeResults,
      daemonBootstrappedThisRun,
      policyDaemonFreshlyInstalled,
    );
    return {
      kind: "aborted",
      stage: "install-daemon",
      reason: withDaemonTeardownNote(
        "fine-grained (exclusive-egress) mode requires the PARKED harness install (the release " +
          "barrier starts the agent only after the gate generation commits), but the install op " +
          "did not report parked:true; aborting fail-closed rather than run the agent before the barrier.",
        td.daemonTeardownError,
        td.policyDaemonTeardownError,
      ),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined || td.policyDaemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }
  if (shutdownRequested(ctx)) {
    return rollbackPreArmForShutdown({
      ctx,
      ops,
      stage: "shutdown-after-install-daemon",
      rehomeResults,
      accountCreated,
      tearDownDaemon: daemonBootstrappedThisRun,
      tearDownPolicyDaemon: policyDaemonFreshlyInstalled,
    });
  }
  ops.print(
    ctx.fineGrainedDeclared === true
      ? "Harness daemon PARK-installed (disabled; the release barrier starts it after the gate commits)."
      : "Harness daemon installed; agent now runs under the dedicated account.",
  );

  // D8 SELF-HEAL: NOT here any more. The reconcile used to sit at this point,
  // gated on `fineGrainedDeclared === true && ops.exclusiveEgress !== undefined`,
  // on the theory that only the fine-grained arm path runs a coarse
  // publish+reload that a stale marker could wedge. That theory was wrong in
  // the direction that matters: the daemon composes EXCLUSIVE on MARKER
  // PRESENCE ALONE, so a plain coarse run wedges identically -- which is
  // exactly what F-COARSE-AFTER-EXCLUSIVE caught on the Mini1 re-drill. The
  // gate is now MODE-INDEPENDENT, and straddles the one confirm above (judge
  // before it, remove after it); by the time control reaches here the residue
  // is provably clear or reconciled, and no mode can skip it.

  // Step 6.7 (confined-agent egress, design section 5 layer 1): provision the
  // harness's signed egress allow rules and statically verify them BEFORE
  // arming. The policy daemon is reachable by construction (step 6 just
  // passed), so the publish rides the existing pinned-signer reload path.
  // Failure aborts before arm -- arming a wall the agent cannot function
  // behind is the exact confine-into-silence outcome this step exists to
  // prevent -- and emits the DISTINCT `egress_provision_refused` audit op so
  // a fleet operator can prove the refusal happened and why.
  reportShutdownStatus(ctx, {
    stage: "provision-egress",
    residualState:
      "the harness may be parked or installed, and provisioned egress rules may be partially published; rollback must restore the pre-run rule set before arm",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });
  const egress = await ops.provisionEgress();
  if (egress.checks !== undefined) {
    for (const line of renderEndpointCheckLines(egress.checks)) {
      ops.print(line);
    }
  }
  if (!egress.ok) {
    await ops.auditEgress(EGRESS_PROVISION_REFUSED_AUDIT_OP, {
      stage: "provision-egress",
      harness: ctx.agentId,
      agent_uid: uid,
      declared_endpoints: ctx.harnessEndpoints.endpoints.map((e) => `${e.host}:${e.port}`),
      checks: egress.checks ?? [],
      dns_rule_present: egress.dnsRulePresent ?? false,
      error: egress.error,
      disarm_outcome: "not-armed",
    });
    // The publish may have PARTIALLY landed before the static verify failed;
    // scrub so a refused run never leaves orphan grants (design section 6).
    const td = await teardownDaemonAndRestore(
      ops,
      rehomeResults,
      daemonBootstrappedThisRun,
      policyDaemonFreshlyInstalled,
      true,
    );
    // FIX F-COARSE-AFTER-EXCLUSIVE (honesty half): OBSERVE before claiming.
    // See `describeObservedAgentConfinement`.
    const observedConfinement = await observeConfinementSafely(ops);
    return {
      kind: "aborted",
      stage: "provision-egress",
      reason: withDaemonTeardownNote(
        `refusing to arm: the egress path for the confined agent could not be provisioned and verified ` +
          `(${egress.error}). ${describeObservedAgentConfinement(observedConfinement)} ` +
          `The agent would have been confined into non-functionality. ` +
          describeRestoreForReason(td.rolledBack, td.conflictPaths, td.failedPaths),
        td.daemonTeardownError,
        td.policyDaemonTeardownError,
        td.egressRestoreNote,
      ),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed:
        td.daemonTeardownError !== undefined || td.policyDaemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }
  const egressProvisionedThisRun = true;
  const provisionedEgressRuleIds = egress.ruleIds;
  ops.print(
    `Egress provisioned: ${egress.ruleIds.length} signed allow rule(s) published for the agent ` +
      `(${egress.ruleIds.join(", ")}); scoped DNS allow derived.`,
  );
  if (shutdownRequested(ctx)) {
    return rollbackPreArmForShutdown({
      ctx,
      ops,
      stage: "shutdown-after-provision-egress",
      rehomeResults,
      accountCreated,
      tearDownDaemon: daemonBootstrappedThisRun,
      tearDownPolicyDaemon: policyDaemonFreshlyInstalled,
      restoreEgress: egressProvisionedThisRun,
    });
  }

  // Step 7: verify BEFORE arming (fix B2 ordering). FIX G5 (2026-07-07
  // re-gate 3): this proves DNS-resolvability + every moved credential
  // present-and-readable-by-target-uid (see verify.ts's module doc), NOT
  // reachability "as the new uid" (this process never crosses a uid
  // boundary) and NOT allow-list correctness (the wall is not armed yet).
  reportShutdownStatus(ctx, {
    stage: "verify-before-arm",
    residualState:
      "provisioned egress rules are published but Castle Wall has not been armed; rollback must restore rules, daemon state, and re-homed files",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });
  const preArmVerify: ConnectivityVerifyResult = await verifyReachabilityBeforeArm(ops.preArmEndpoints());
  if (!preArmVerify.allReachable) {
    const unreachable = preArmVerify.results.filter((r) => !r.reachable).map((r) => r.name);
    // FIX (round 5, item N3): the daemon is LIVE by now (install-daemon
    // succeeded above); tear it down before restoring the re-home so this
    // fail-closed abort does not leave the daemon running under the dedicated
    // account. Egress rules provisioned this run are scrubbed too (no orphan
    // grants on a failed run, design section 6).
    const td = await teardownDaemonAndRestore(
      ops,
      rehomeResults,
      daemonBootstrappedThisRun,
      policyDaemonFreshlyInstalled,
      egressProvisionedThisRun,
    );
    return {
      kind: "aborted",
      stage: "verify-before-arm",
      reason: withDaemonTeardownNote(
        // FIX (round 5 / R6-4): honest phrasing, matching the post-arm reason
        // (round-5 item c). The pre-arm check proves DNS-resolvability of each
        // endpoint host + each moved credential present-and-readable-by-uid --
        // it does NOT run as the agent uid or prove end-to-end reachability, so
        // "re-homed agent could not reach" overclaimed.
        `pre-arm check could not confirm DNS-resolvability + moved-credential readability for: ${unreachable.join(", ")}. ` +
          describeRestoreForReason(td.rolledBack, td.conflictPaths, td.failedPaths),
        td.daemonTeardownError,
        td.policyDaemonTeardownError,
        td.egressRestoreNote,
      ),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined || td.policyDaemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }
  if (shutdownRequested(ctx)) {
    return rollbackPreArmForShutdown({
      ctx,
      ops,
      stage: "shutdown-after-verify-before-arm",
      rehomeResults,
      accountCreated,
      tearDownDaemon: daemonBootstrappedThisRun,
      tearDownPolicyDaemon: policyDaemonFreshlyInstalled,
      restoreEgress: egressProvisionedThisRun,
    });
  }

  // Step 8: arm-time uid-existence gate (fix H1). Immediately before
  // arming, hard-check the account still exists at exactly this uid.
  reportShutdownStatus(ctx, {
    stage: "uid-existence-gate",
    residualState:
      "pre-arm checks passed and provisioned egress rules are published, but Castle Wall has not been armed; rollback must restore the pre-run state before exit",
    recoveryCommand: PROTECT_RETRY_COMMAND,
  });
  const existenceCheck = await ops.checkUidExistence(uid);
  if (!existenceCheck.ok) {
    // FIX (round 5, item N3): daemon is live; tear it down on this abort. Bug B:
    // also tear down a freshly-installed policy daemon (untouched if it
    // pre-existed or was already reachable). Provisioned egress rules are
    // scrubbed (no orphan grants on a failed run).
    const td = await teardownDaemonAndRestore(
      ops,
      rehomeResults,
      daemonBootstrappedThisRun,
      policyDaemonFreshlyInstalled,
      egressProvisionedThisRun,
    );
    return {
      kind: "aborted",
      stage: "uid-existence-gate",
      reason: withDaemonTeardownNote(
        existenceCheck.reason,
        td.daemonTeardownError,
        td.policyDaemonTeardownError,
        td.egressRestoreNote,
      ),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined || td.policyDaemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }
  if (shutdownRequested(ctx)) {
    return rollbackPreArmForShutdown({
      ctx,
      ops,
      stage: "shutdown-after-uid-existence-gate",
      rehomeResults,
      accountCreated,
      tearDownDaemon: daemonBootstrappedThisRun,
      tearDownPolicyDaemon: policyDaemonFreshlyInstalled,
      restoreEgress: egressProvisionedThisRun,
    });
  }

  // Step 9: arm via the shipped `enable --agent-uid=N --ceiling` (step 1).
  reportShutdownStatus(ctx, {
    stage: "arm",
    residualState:
      "Castle Wall arm is in progress; the content filter may become ARMED and rollback must disarm before exit",
    recoveryCommand: CASTLE_WALL_DISABLE_COMMAND,
  });
  const armResult = await ops.arm(uid, ctx.ceiling);
  if (!armResult.ok) {
    // FIX (round 5, item N3): arming failed but the harness daemon is live;
    // tear it down on this abort.
    //
    // Bug B P0/P1 (disarm-first ordering + confirmed-off teardown): `arm`
    // returning ok:false does NOT imply the content filter is off. On macOS
    // Tahoe the host app can SAVE the NE config ENABLED and THEN return non-zero
    // because its own post-change status corroboration timed out (or a build-sha
    // check tripped after the save) -- so the filter may be ON. Booting a
    // FRESHLY-INSTALLED policy daemon out in that state is filter-on +
    // daemon-down = the exact deny-all lockout (SSH included) this feature
    // exists to prevent. So when a policy daemon was freshly installed this run,
    // DISARM FIRST, and tear the daemon down ONLY when disarm AFFIRMATIVELY
    // CONFIRMS the NE preference is off. Order is ALWAYS filter-off THEN
    // daemon-down.
    //
    // P1 refinement: a non-throwing disarm can still be either a save-accepted
    // result or the fail-open-after-lease-revoke sub-case. The latter may leave
    // the NE preference enabled; removing the daemon there risks a reboot-brick
    // (provider enabled + no daemon = deny-all). Teardown therefore depends on
    // the explicit disable outcome, not merely "disarm did not throw."
    let tearDownPolicyDaemon = false;
    let wallMayBeArmed = false;
    let disarmObservedOff = false;
    let disarmNote: string | undefined;
    if (policyDaemonFreshlyInstalled) {
      try {
        const disarmResult = await ops.disarm();
        if (disarmOutcomeAllowsFreshDaemonTeardown(disarmResult.nePreferenceOutcome)) {
          tearDownPolicyDaemon = true;
          disarmObservedOff = disarmOutcomeObservedOff(
            disarmResult.nePreferenceOutcome,
          );
          disarmNote = disarmObservedOff
            ? "The content filter was observed disabled as part of this rollback; confirm current state with 'sanctuary castle-wall status'."
            : "The content-filter disable save was accepted during rollback, but status corroboration was inconclusive; observe live state before relying on it.";
        } else {
          // Disarm succeeded as a dead-man lever (not ENFORCING now) but did NOT
          // confirm the NE preference is off (fail-open after lease revoke). The
          // NE preference may still be enabled -> a reboot could come up enabled
          // with no daemon (deny-all). Treat exactly like disarm-uncertain:
          // leave the fresh daemon UP (not-enforcing + daemon-up is recoverable)
          // and surface loudly.
          wallMayBeArmed = true;
          disarmNote =
            "disarm reported success as a dead-man lever but did NOT save the NE preference disabled (fail-open after lease revoke); the wall may still be enabled at the preference level";
        }
      } catch (disarmErr) {
        // Disarm hard-failed: it could NOT confirm the filter is off. Do NOT
        // boot the fresh policy daemon out -- leave it UP (filter-on + daemon-up
        // is enforcing and RECOVERABLE, never the deny-all lockout).
        wallMayBeArmed = true;
        disarmNote = (disarmErr as Error).message;
      }
    }
    const td = await teardownDaemonAndRestore(
      ops,
      rehomeResults,
      daemonBootstrappedThisRun,
      tearDownPolicyDaemon,
      egressProvisionedThisRun,
    );
    return {
      kind: "aborted",
      stage: "arm",
      reason: withArmWallStateNote(
        withDaemonTeardownNote(
          armResult.error,
          td.daemonTeardownError,
          td.policyDaemonTeardownError,
          td.egressRestoreNote,
        ),
        wallMayBeArmed,
        disarmNote,
      ),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined || td.policyDaemonTeardownError !== undefined,
      // P0 honesty gap: when the filter may still be armed (disarm could not
      // confirm), the CLI must NOT render a clean "rolled back; re-run" line.
      wallMayBeArmed: wallMayBeArmed ? true : undefined,
      disarmObservedOff: disarmObservedOff ? true : undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }
  if (shutdownRequested(ctx)) {
    return rollbackAfterArmForShutdown(
      ctx,
      ops,
      uid,
      "shutdown-after-arm",
      egressProvisionedThisRun,
    );
  }

  // Step 10: post-arm connectivity re-check with fast disarm-rollback (fix
  // B2). Allow-list correctness is only provable now.
  reportShutdownStatus(ctx, {
    stage: "post-arm-connectivity-check",
    residualState:
      "Castle Wall is armed and provisioned egress has not completed post-arm verification; rollback must disarm and restore the pre-run rule set",
    recoveryCommand: CASTLE_WALL_DISABLE_COMMAND,
  });
  const postArmVerify: ConnectivityVerifyResult = await verifyReachabilityAfterArm(ops.postArmEndpoints());
  if (!postArmVerify.allReachable) {
    const unreachable = postArmVerify.results.filter((r) => !r.reachable).map((r) => r.name);
    // FIX (round 5, item c): honesty. The post-arm re-check runs the SAME
    // probe list as pre-arm (DNS-resolvability + moved-credential readability);
    // it does NOT and cannot prove the allow-list is what blocked anything (a
    // failed DNS lookup, a vanished credential, or a transient network fault
    // all fail these probes without the wall's allow-list being the cause).
    // Report what actually failed the re-check, and name the still-open
    // question (is the allow-list correct?) as the drill's job -- never assert
    // "the allow-list blocks" from a probe that cannot show it.
    // FIX (round 5 / R3-3): the "Fast-disarmed ..." clause is NOT part of the
    // shared base reason. It asserts a COMPLETED disarm, which is true only on
    // the armed-then-rolled-back path; on armed-rollback-failed the disarm
    // threw, so reusing it would directly contradict the disarmError we report.
    // Append it only where the disarm actually succeeded.
    const baseReason =
      `post-arm connectivity re-check failed for: ${unreachable.join(", ")}. ` +
      `This re-check proves DNS-resolvability and moved-credential readability only, not allow-list ` +
      `correctness (the Erik-present drill confirms end-to-end reachability as the agent uid).`;
    // FIX R5 (HIGH, 2026-07-07 fix-round 2): `disarm()` can itself fail (the
    // exact scenario this rollback exists for -- something about this host
    // is already unhealthy). The pre-fix-round-2 code left this call
    // uncaught: a throw here propagated past this function's return
    // entirely, the CLI's generic catch swallowed it into NO outcome, and
    // the wrap's own success banner still printed over an ARMED wall with a
    // FAILED rollback. Catch it and return a distinct, loud outcome instead.
    let disarmObservedOff: boolean;
    try {
      const disarmResult = await ops.disarm();
      disarmObservedOff = disarmOutcomeObservedOff(
        disarmResult.nePreferenceOutcome,
      );
    } catch (disarmErr) {
      return {
        kind: "armed-rollback-failed",
        uid,
        // No "Fast-disarmed" claim: the disarm FAILED (see disarmError). The
        // wall is still ARMED; the CLI render says so loudly.
        reason: baseReason,
        disarmError: (disarmErr as Error).message,
      };
    }
    // No orphan grants on a rolled-back run (design section 6): put the egress
    // rules back to their pre-run state. Best-effort + fail-loud (folded into
    // the reason); the wall is already down, so a surviving rule is inert
    // until a future arm, but it must still be surfaced, never silent.
    const restoreNote = await restoreEgressBestEffort(ops, egressProvisionedThisRun);
    return {
      kind: "armed-then-rolled-back",
      uid,
      reason: `${baseReason} Fast-disarmed rather than leave a bricked agent.${egressRestoreReasonSuffix(restoreNote)}`,
      disarmObservedOff: disarmObservedOff ? true : undefined,
    };
  }
  if (shutdownRequested(ctx)) {
    return rollbackAfterArmForShutdown(
      ctx,
      ops,
      uid,
      "shutdown-after-post-arm-connectivity-check",
      egressProvisionedThisRun,
    );
  }

  // Step 11 (confined-agent egress, design section 5): the REAL post-arm
  // egress check, run AS THE AGENT UID through the ARMED wall -- the check
  // the 2026-07-09 drill proved the DNS-only probes above cannot make
  // ((a) static without (b) dynamic is theater). Every declared endpoint
  // must complete a TCP+TLS connect as the agent uid, and the non-listed
  // negative control must stay BLOCKED. Any failure triggers the same fix-B2
  // fast-disarm rollback as step 10, plus the provisioned-rule scrub, and is
  // reported as the DISTINCT local outcome `egress-unprovisioned-rolled-back`.
  reportShutdownStatus(ctx, {
    stage: "post-arm-as-uid-egress-check",
    residualState:
      "Castle Wall is armed and as-agent-uid egress verification is in progress; rollback must disarm before exit if verification does not reach a safe outcome",
    recoveryCommand: CASTLE_WALL_DISABLE_COMMAND,
  });
  const egressVerify = await ops.verifyAgentEgressAfterArm(uid);
  for (const line of renderAgentEgressReportLines(egressVerify)) {
    ops.print(line);
  }
  if (!egressVerify.ok) {
    const failedRows = egressVerify.rows.filter((r) => !r.pass).map((r) => r.name);
    const egressBaseReason =
      `post-arm as-uid egress verification failed for: ${failedRows.join(", ")}. ` +
      `A process running as the agent uid must reach every declared endpoint through the armed wall ` +
      `and must NOT reach the negative control; anything less confines the agent into ` +
      `non-functionality or proves nothing about confinement.`;
    let disarmed: boolean;
    let disarmObservedOff: boolean;
    try {
      const disarmResult = await ops.disarm();
      disarmed = true;
      disarmObservedOff = disarmOutcomeObservedOff(
        disarmResult.nePreferenceOutcome,
      );
    } catch (disarmErr) {
      await ops.auditEgress(EGRESS_PROVISION_REFUSED_AUDIT_OP, {
        stage: "post-arm-as-uid-verify",
        harness: ctx.agentId,
        agent_uid: uid,
        declared_endpoints: ctx.harnessEndpoints.endpoints.map((e) => `${e.host}:${e.port}`),
        probe_rows: egressVerify.rows,
        disarm_outcome: "disarm-failed",
      });
      return {
        kind: "armed-rollback-failed",
        uid,
        reason: egressBaseReason,
        disarmError: (disarmErr as Error).message,
      };
    }
    const restoreNote = await restoreEgressBestEffort(ops, egressProvisionedThisRun);
    await ops.auditEgress(EGRESS_PROVISION_REFUSED_AUDIT_OP, {
      stage: "post-arm-as-uid-verify",
      harness: ctx.agentId,
      agent_uid: uid,
      declared_endpoints: ctx.harnessEndpoints.endpoints.map((e) => `${e.host}:${e.port}`),
      probe_rows: egressVerify.rows,
      disarm_outcome: "fast-disarmed",
      egress_rules_restored_to_pre_run_state: restoreNote === "",
    });
    return {
      kind: "egress-unprovisioned-rolled-back",
      uid,
      reason: `${egressBaseReason} Fast-disarmed rather than leave a bricked-or-unconfined agent.${egressRestoreReasonSuffix(restoreNote)}`,
      egressRestoredToPreRunState: disarmed && restoreNote === "",
      disarmObservedOff: disarmObservedOff ? true : undefined,
    };
  }
  if (shutdownRequested(ctx)) {
    return rollbackAfterArmForShutdown(
      ctx,
      ops,
      uid,
      "shutdown-after-post-arm-as-uid-egress-check",
      egressProvisionedThisRun,
    );
  }

  await ops.auditEgress(EGRESS_PROVISIONED_AUDIT_OP, {
    harness: ctx.agentId,
    agent_uid: uid,
    rule_ids: provisionedEgressRuleIds,
    endpoints: ctx.harnessEndpoints.endpoints.map((e) => `${e.host}:${e.port}`),
    probe_rows: egressVerify.rows,
  });

  if (ctx.fineGrainedDeclared !== true) {
    return { kind: "armed", uid };
  }

  if (shutdownRequested(ctx)) {
    return coarseOnlyShutdownBeforeExclusiveOutcome(ctx, ops, uid);
  }

  // S5-6: the exclusive-egress arming stage. Runs ONLY after the coarse
  // stages proved live (wall armed + as-uid egress verified) and only over a
  // PARKED harness (asserted at install). Every failure inside the stage is
  // handled by the stage itself (degrade-loud coarse fallback / parked), so
  // the mapping here is 1:1 outcome translation -- no failure path can fall
  // through to a green "armed".
  reportShutdownStatus(ctx, {
    stage: "exclusive-egress-arm",
    residualState:
      "coarse Castle Wall is verified, the harness may be parked, and exclusive-egress bring-up or release may be in progress",
    recoveryCommand: EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND,
  });
  ops.print("Coarse stages live; arming the exclusive-egress gate (fine-grained mode).");
  const exclusive = await runExclusiveEgressArming({ agentUid: uid }, ops.exclusiveEgress!);
  if (exclusive.kind === "exclusive-armed") {
    return { kind: "armed-exclusive", uid, generationId: exclusive.generationId };
  }
  if (exclusive.kind === "exclusive-armed-repark-failed") {
    return {
      kind: "armed-exclusive-repark-failed",
      uid,
      generationId: exclusive.generationId,
      reparkError: exclusive.reparkError,
    };
  }
  return {
    kind: "exclusive-egress-unarmed-coarse-active",
    uid,
    stage: exclusive.stage,
    reason: exclusive.reason,
    coarseCompositionRestored: exclusive.coarseCompositionRestored,
    harness: exclusive.harness,
    cleanupErrors: exclusive.cleanupErrors,
  };
}

/**
 * Best-effort provisioned-rule restore for the rolled-back branches. Returns
 * "" when the pre-run rule set was restored AND is being served again (or when
 * nothing was provisioned this run), or a bare, loud manual-recovery sentence
 * naming the recovery path otherwise. Never throws.
 *
 * FIX F-REVOKE: the note distinguishes the two failure shapes, because they
 * strand the operator differently. `restored: false` means the rule FILES may
 * be wrong on disk. `reloadOk: false` means the files are right but the
 * running daemon has not picked them up, so a still-running agent may be
 * reaching nothing until it does. The sentence is returned UNWRAPPED so the
 * two consumers (an inline reason suffix and {@link withDaemonTeardownNote})
 * punctuate it their own way without either owning a second copy of the words.
 */
async function restoreEgressBestEffort(
  ops: ProvisionFlowOps,
  egressProvisionedThisRun: boolean,
): Promise<string> {
  if (!egressProvisionedThisRun) return "";
  let result: { restored: boolean; reloadOk: boolean; problems: string[] };
  try {
    result = await ops.restoreProvisionedEgressToPreRunState();
  } catch (err) {
    result = { restored: false, reloadOk: false, problems: [(err as Error).message] };
  }
  if (!result.restored) {
    return (
      `WARNING: the agent's egress allow rules could NOT be restored to their pre-run state ` +
      `(${result.problems.join("; ")}). A CONFINED AGENT THAT IS STILL RUNNING MAY NOW REACH NOTHING. ` +
      `Recover with: sudo sanctuary protect --hermes (re-provisions and republishes the agent's grants), ` +
      `or inspect the provisioned-* rule files under <fortress>/policy/egress/rules/ directly.`
    );
  }
  if (!result.reloadOk) {
    return (
      `WARNING: the agent's egress allow rules were restored on disk but the policy daemon did NOT confirm ` +
      `a reload, so the running wall may still be serving the composition from this failed run. ` +
      `Apply it with: sudo sanctuary castle-wall reload.`
    );
  }
  return "";
}

/**
 * Run {@link ProvisionFlowOps.observeAgentConfinement} without letting it
 * change the abort's outcome. A probe that throws is UNKNOWN, never "nothing
 * is confined" -- the whole point of the fix is that an unobservable host must
 * not be described as a quiet one.
 */
async function observeConfinementSafely(ops: ProvisionFlowOps): Promise<ObservedAgentConfinement> {
  try {
    return await ops.observeAgentConfinement();
  } catch (err) {
    return { known: false, reason: `confinement probe threw: ${(err as Error).message}` };
  }
}

/**
 * Run {@link ProvisionFlowOps.reconcileExclusiveRoutingResidue} and add the ONE
 * verdict the op itself cannot return: a THROW is `unreadable`, NEVER `clear`.
 * The op throws precisely when a marker is present but cannot be parsed, so
 * treating a throw as "no residue" would mean proceeding under a routing mode
 * nothing established -- the exact wrong-allow this gate exists to prevent.
 *
 * FIX F4 (adversarial review, 2026-07-26): this function used to BUILD the
 * union out of a `{ reconciled: boolean; reason?: string }` the op handed over,
 * so "kept with no reason" silently read as `clear` and the run walked into the
 * wedge. The op returns the total union now; this wrapper only adds the throw
 * case, so a keep can no longer be spelled by omission at the boundary.
 */
async function reconcileResidueSafely(
  ops: ProvisionFlowOps,
  armTargetUid: number | undefined,
  intent: "observe" | "clear",
): Promise<ExclusiveRoutingResidue> {
  try {
    return await ops.reconcileExclusiveRoutingResidue(armTargetUid, intent);
  } catch (err) {
    // FIX G8 (re-gate, 2026-07-26): classify WHICH surface failed instead of
    // blaming the marker for every throw. `ExclusiveRoutingMarkerError` is the
    // marker load/parse contract firing; anything else came from another
    // surface the op reads (the anchor registry, the gate runtime state, a
    // removal), and on those the marker's own readability is unknown.
    const source = (err as Error)?.name === "ExclusiveRoutingMarkerError" ? "marker" : "residue-check";
    return { kind: "unreadable", source, detail: `the residue reconcile threw: ${(err as Error).message}` };
  }
}

/**
 * FIX G3 (re-gate, 2026-07-26): the residue gate's SUBJECT, with the dedicated
 * account's own uid as the fallback.
 *
 * `detectResult.resolved` comes from a harness-config probe that is hardcoded
 * `undefined` in v1 plus a `ps` grep for a RUNNING gateway, so it is `undefined`
 * on every run whose agent process is not currently up -- a stopped agent, a
 * crashed gateway, the window after a park, a boot window. That made
 * `kept-unknown-subject` the DOMINANT keep in production rather than the rare
 * one, and its remedy is a destructive teardown that parks a healthy host down.
 * The dedicated account's uid is a real subject on every host where the account
 * exists, so guard 0 can judge the marker properly there and the unknown-subject
 * refusal shrinks back to the account-actually-gone case its sentence is written
 * for.
 *
 * This does NOT relax guard 0: a lookup that finds nothing, or that fails,
 * still yields `undefined` and the run is still refused fail-closed. "Could not
 * look" is never a subject.
 */
async function resolveResidueSubjectUid(ops: ProvisionFlowOps, resolved: number | undefined): Promise<number | undefined> {
  if (resolved !== undefined) return resolved;
  try {
    return await ops.lookupDedicatedAccountUid();
  } catch {
    return undefined;
  }
}

/** Punctuate a {@link restoreEgressBestEffort} sentence for appending to an outcome reason. */
function egressRestoreReasonSuffix(note: string): string {
  return note === "" ? "" : ` (${note})`;
}

function describeRestoreForReason(
  rolledBack: boolean | "partial",
  conflictPaths: string[] = [],
  failedPaths: string[] = [],
): string {
  // FIX (round 5 / R7-3): a conflict-only restore is NOT a failure (the R5-2
  // conflict-safe render). `rolledBack` alone is `false` for a pure conflict
  // (restoredCount 0), so without conflict-awareness this said "The restore
  // FAILED ..." inside the abort reason -- directly contradicting the CLI's
  // conflict-safe frame. When conflicts occurred with NO genuine failure, say
  // so honestly and never claim a failure.
  if (conflictPaths.length > 0 && failedPaths.length === 0) {
    return "Files you recreated during provisioning were left intact; the previously re-homed copy is preserved at a .restored-conflict sibling (reconcile manually; do not overwrite from the backup).";
  }
  if (rolledBack === true) return "The re-homed paths were restored to the operator.";
  if (rolledBack === "partial") {
    return "Only SOME re-homed paths were restored; the rest require manual recovery (see the backup path(s) above).";
  }
  return "The restore FAILED; the re-homed paths require manual recovery (see the backup path(s) above).";
}

/**
 * Attempt to restore the re-homed paths and report what ACTUALLY happened.
 * FIX F2/F5 (2026-07-07 fix-round): this no longer swallows the result into
 * a hardcoded `true` -- `ops.restoreRehome`'s own `fullyRestored` flag drives
 * the returned `rolledBack` value (`true`/`false`/`"partial"`), and a THROW
 * from `ops.restoreRehome` itself is caught here (never masking the
 * ORIGINAL error that triggered the abort by re-throwing a different one)
 * but is reported as `rolledBack: false`, not `true`.
 */
async function safeRestore(
  ops: ProvisionFlowOps,
  results: RehomeStepResult[],
): Promise<{ rolledBack: boolean | "partial"; backupPaths: string[]; conflictPaths: string[]; failedPaths: string[] }> {
  try {
    const { fullyRestored, restoredCount, backupPaths, conflictPaths, failedPaths } = await ops.restoreRehome(results);
    const rolledBack: boolean | "partial" = fullyRestored ? true : restoredCount > 0 ? "partial" : false;
    // FIX (round 5 / R5-2, R6-2): surface R6 conflict paths AND genuine
    // failures separately, so the CLI can report "recovered data is safe at
    // <conflictPath>; reconcile manually" for a pure conflict, but keep the
    // LOUD "restore FAILED / backup at X" frame whenever a real failure also
    // occurred (a conflict must never mask a failure).
    return { rolledBack, backupPaths, conflictPaths: conflictPaths ?? [], failedPaths: failedPaths ?? [] };
  } catch {
    // Best-effort call, but the OUTCOME must be honest: a restore that threw
    // is a failed restore, not a successful one. The original abort reason
    // this was invoked from is preserved by the caller; this function only
    // ever reports on the restore itself. A throw means EVERY attempted path
    // failed to restore, so surface them all as failedPaths (R6-2).
    return {
      rolledBack: false,
      backupPaths: results.filter((r) => r.backupPath).map((r) => r.backupPath!),
      conflictPaths: [],
      failedPaths: results.filter((r) => r.status === "moved").map((r) => r.entry.sourcePath),
    };
  }
}

/**
 * FIX (round 5, item N3): tear the (already-bootstrapped, LIVE) harness daemon
 * back down THEN restore the re-home, for every post-install abort branch.
 * Before this, a fail-closed abort after `installHarnessDaemon` succeeded left
 * a root LaunchDaemon running under the dedicated account while the outcome
 * reported a clean re-home rollback. Best-effort + fail-loud: a teardown
 * failure is captured (folded into the abort reason by
 * {@link withDaemonTeardownNote}) but never prevents the re-home restore from
 * being attempted, and never throws.
 */
async function teardownDaemonAndRestore(
  ops: ProvisionFlowOps,
  results: RehomeStepResult[],
  tearDownDaemon: boolean,
  tearDownPolicyDaemon: boolean,
  restoreEgress = false,
): Promise<{
  rolledBack: boolean | "partial";
  backupPaths: string[];
  conflictPaths: string[];
  failedPaths: string[];
  daemonTeardownError?: string;
  policyDaemonTeardownError?: string;
  /** The loud note from {@link restoreEgressBestEffort}, or undefined when the pre-run rule set is back and being served. */
  egressRestoreNote?: string;
}> {
  // FIX (round 5 / R6-3): only tear the harness daemon down when THIS run stood
  // it up (the fresh-provision path). On the alreadyDedicated re-run path the
  // harness daemon PRE-EXISTED a prior successful provision, so booting it out
  // over a transient verify/arm failure would destroy working infrastructure --
  // and the subsequent neutral "nothing was changed" frame would be a lie.
  // Leave a pre-existing daemon in place.
  let daemonTeardownError: string | undefined;
  if (tearDownDaemon) {
    try {
      await ops.uninstallHarnessDaemon();
    } catch (err) {
      daemonTeardownError = (err as Error).message;
    }
  }
  // Bug B (the one-flow gap): tear the FRESHLY-INSTALLED policy (boot) daemon
  // back down too, so an abort after we stood up the machine's wall from
  // nothing restores the prior "no wall for this fortress" state. This is only
  // ever true when THIS run installed the boot service fresh (never for a
  // pre-existing wall -- booting that out would be destructive; and we only
  // reach these branches with the filter NOT armed, so it can never create the
  // filter-on/daemon-down lockout). Best-effort + fail-loud: a teardown failure
  // is captured and folded into the abort reason, never prevents the re-home
  // restore, and never throws.
  let policyDaemonTeardownError: string | undefined;
  if (tearDownPolicyDaemon) {
    try {
      await ops.teardownPolicyDaemon();
    } catch (err) {
      policyDaemonTeardownError = (err as Error).message;
    }
  }
  // Confined-agent egress (design section 6 + FIX F-REVOKE): the harness's
  // rules are put back to the state this run found them in, so a failed run
  // leaves neither orphan grants (first run: pre-run state is "none") nor a
  // strangled agent (re-run: a previous run's grants survive). Best-effort +
  // fail-loud (folded into the abort reason), never blocks the restore.
  const egressRestoreNote = (await restoreEgressBestEffort(ops, restoreEgress)) || undefined;
  const restore = await safeRestore(ops, results);
  return {
    rolledBack: restore.rolledBack,
    backupPaths: restore.backupPaths,
    conflictPaths: restore.conflictPaths,
    failedPaths: restore.failedPaths,
    daemonTeardownError,
    policyDaemonTeardownError,
    egressRestoreNote,
  };
}

/**
 * Fold a daemon-teardown failure into an abort reason as LOUD manual-recovery
 * guidance -- the operator must know a root LaunchDaemon may still be live so
 * they can remove it by hand. Covers both the harness daemon (fix, round 5 item
 * N3) and the freshly-installed Castle Wall policy/boot daemon (Bug B). Returns
 * the reason unchanged when every attempted teardown succeeded.
 */
function withDaemonTeardownNote(
  reason: string,
  daemonTeardownError?: string,
  policyDaemonTeardownError?: string,
  egressRestoreNote?: string,
): string {
  const notes: string[] = [];
  if (daemonTeardownError !== undefined) {
    notes.push(
      `the harness daemon could NOT be torn down automatically: ${daemonTeardownError}. ` +
        `It may still be running under the dedicated account -- run 'sudo sanctuary castle-wall disable' and remove ` +
        `the ai.sanctuaryprotocol.agent-harness LaunchDaemon manually before re-running.`,
    );
  }
  if (policyDaemonTeardownError !== undefined) {
    notes.push(
      `the freshly-installed Castle Wall policy (boot) daemon could NOT be torn down automatically: ${policyDaemonTeardownError}. ` +
        `A root LaunchDaemon may still be running -- run 'sudo sanctuary castle-wall uninstall-boot --yes' to remove it before re-running.`,
    );
  }
  if (egressRestoreNote !== undefined) {
    // FIX F-REVOKE: already a complete, actionable sentence (it names which of
    // the two failure shapes happened and the recovery command); folding it in
    // verbatim keeps ONE author of that wording rather than two that can drift.
    notes.push(egressRestoreNote);
  }
  if (notes.length === 0) {
    return reason;
  }
  return `${reason} (NOTE: ${notes.join(" ")})`;
}

/**
 * Bug B P0 (disarm-first): fold the arm-abort wall-state note into the reason.
 * When `wallMayBeArmed` (disarm could NOT confirm the filter is off), this is a
 * LOUD manual-recovery warning -- the freshly-installed policy daemon was left
 * running to avoid a lockout and the operator must run `castle-wall disable`.
 * When disarm succeeded, `disarmNote` is a milder "the wall was disarmed during
 * rollback; confirm with status" line so the outcome is never a bare clean
 * rollback that hides the wall was touched. Returns the reason unchanged when
 * no policy daemon was freshly installed (no disarm was attempted).
 */
function withArmWallStateNote(reason: string, wallMayBeArmed: boolean, disarmNote?: string): string {
  if (disarmNote === undefined) {
    return reason;
  }
  if (wallMayBeArmed) {
    return (
      `${reason} (WALL-STATE WARNING: arming reported a failure but the content filter MAY STILL BE ARMED and ` +
      `disarm could not confirm it is off: ${disarmNote}. The freshly-installed Castle Wall policy daemon was LEFT ` +
      `RUNNING to avoid a deny-all lockout (filter-on + daemon-up is enforcing and recoverable, unlike filter-on + ` +
      `daemon-down). Run 'sudo sanctuary castle-wall disable' to confirm the filter is off before re-running.)`
    );
  }
  return `${reason} (${disarmNote})`;
}
