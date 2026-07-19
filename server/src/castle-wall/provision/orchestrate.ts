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
import {
  runExclusiveEgressArming,
  type ExclusiveEgressArmOps,
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
  confirm(promptText: string): Promise<boolean>;
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
      }
    | { ok: false; error: string; daemonPreexisted: boolean }
  >;
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
   * Remove every provisioned egress rule this flow's harness owns from the
   * signed manifest source (verified: no `provisioned-<harness>-*` rule
   * survives). Used on abort/rollback after `provisionEgress` succeeded so a
   * failed provision run never leaves orphan grants (design section 6; a
   * stale allow surviving teardown would combine with any future evaluator
   * widening into a standing grant). Idempotent + fail-loud.
   */
  scrubProvisionedEgress(): Promise<void>;
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
   * Egress-provision outcome vocabulary (design section 5): a DISTINCT local
   * variant, never a widened shared enum (the file-grant round-4 lesson).
   * The wall ARMED, but the post-arm AS-UID egress verification failed (an
   * endpoint unreachable as the agent uid, or the negative control
   * reachable), so the flow fast-disarmed (fix B2) and scrubbed the
   * provisioned rules rather than leave a confined-into-silence agent or an
   * unverified grant. The agent stays re-homed under its dedicated account.
   */
  | {
      kind: "egress-unprovisioned-rolled-back";
      uid: number;
      reason: string;
      /** False when the provisioned-rule scrub after fast-disarm could not be confirmed. */
      scrubbed: boolean;
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
   * `sudo sanctuary protect --repair-egress-gate`.
   */
  | { kind: "armed-exclusive-repark-failed"; uid: number; generationId: number; reparkError: string }
  /**
   * S5-6 DEGRADE-LOUD (design answer 2 choice (b), requires S5-P on every
   * surface): fine-grained was declared but the exclusive stack could not
   * come live; the PROVEN coarse wall stays armed. The manifest was
   * explicitly recomposed to coarse scope through the audited S5-4 fallback
   * (`coarseCompositionRestored`) and the agent started in coarse mode
   * (`harnessStartedCoarse`) -- either false means the agent is PARKED (not
   * running) and the outcome says so loudly. ALWAYS a distinct non-green
   * posture (`coarse-only` / amber on every surface); NEVER silent, NEVER
   * fake-green.
   */
  | {
      kind: "exclusive-egress-unarmed-coarse-active";
      uid: number;
      stage: "bring-up" | "release";
      reason: string;
      coarseCompositionRestored: boolean;
      harnessStartedCoarse: boolean;
      cleanupErrors: string[];
    };

/**
 * Run the full one-flow orchestration. Every fail-closed branch below is
 * reachable purely through the injected ops, so unit tests can assert each
 * outcome without a real host.
 */
export async function runProvisionFlow(
  ctx: ProvisionFlowContext,
  ops: ProvisionFlowOps,
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

  const proceed = await ops.confirm("Proceed with account creation and arming? [y/N] ");
  if (!proceed) {
    return { kind: "declined-by-operator" };
  }

  if (ctx.detectResult.alreadyDedicated) {
    uid = ctx.detectResult.resolved!.uid;
  } else {
    // Step 4: create the dedicated hidden service account.
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

    // Step 5: re-home (backup-first, reversible).
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
  }

  // Step 6: install the harness daemon. Agent now runs at ruid = uid; wall
  // NOT yet armed. A failure here means we already moved secrets -- restore
  // them before reporting the abort (never leave a half-provisioned agent).
  const install = await ops.installHarnessDaemon(uid);
  if (!install.ok) {
    // FIX (round 5, item N3 / R8-1): a failed install may have left a fresh
    // daemon live (the belt-and-suspenders bootstrap-then-verify path). Tear it
    // down iff this attempt stood one up -- `!daemonPreexisted` is the honest
    // signal (never the `!alreadyDedicated` heuristic, which does not track
    // daemon presence): a fresh daemon this attempt left live is removed; a
    // genuinely pre-existing daemon (R6-3) is preserved.
    // This abort fires BEFORE the ensure-policy-daemon step (step 6.5), so no
    // policy daemon was touched this run -- never tear one down here.
    const td = await teardownDaemonAndRestore(ops, rehomeResults, !install.daemonPreexisted, false);
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

  // S5-6 BARRIER ASSERTION (fail-closed): in fine-grained mode the install
  // MUST have been the S5-5 PARKED form -- a bootstrapped (running) agent
  // before the release barrier is the exact BLOCKER-2 escape the barrier
  // exists to close. Tear the daemon back down and abort rather than proceed
  // with an agent that is already running unconfined-by-the-gate.
  if (ctx.fineGrainedDeclared === true && install.parked !== true) {
    const td = await teardownDaemonAndRestore(ops, rehomeResults, daemonBootstrappedThisRun, false);
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
  ops.print(
    ctx.fineGrainedDeclared === true
      ? "Harness daemon PARK-installed (disabled; the release barrier starts it after the gate commits)."
      : "Harness daemon installed; agent now runs under the dedicated account.",
  );

  // Step 6.5 (Bug B, the one-flow gap): ensure a reachable Castle Wall POLICY
  // daemon for the target fortress BEFORE arming. Arming with no policy daemon
  // deny-all-locks the box (filter on + daemon down); the arm's own probe
  // refuses in that state, so on a box with no wall for this fortress the whole
  // flow would otherwise roll back. Stand the policy daemon up here (install a
  // fresh singleton boot service on a box with no wall; (re)start a stopped one
  // that already targets this fortress; REFUSE to swap a wall that belongs to a
  // DIFFERENT fortress -- one machine runs one wall). This step NEVER arms the
  // filter and NEVER leaves the box filter-on/daemon-down.
  const ensure = await ops.ensurePolicyDaemon(ctx.fortressPath);
  if (!ensure.ok) {
    // Fail-closed: we never proceed to arm without a reachable policy daemon.
    // The harness daemon is LIVE by now (step 6 succeeded); tear it down iff
    // this run stood it up, tear down a FRESH policy daemon iff this attempt
    // stood one up (a refuse-to-swap abort leaves the machine's existing wall
    // untouched -- ensure.freshlyInstalled is false there), then restore the
    // re-home.
    const td = await teardownDaemonAndRestore(
      ops,
      rehomeResults,
      daemonBootstrappedThisRun,
      ensure.freshlyInstalled,
    );
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

  // Step 6.7 (confined-agent egress, design section 5 layer 1): provision the
  // harness's signed egress allow rules and statically verify them BEFORE
  // arming. The policy daemon is reachable by construction (step 6.5 just
  // passed), so the publish rides the existing pinned-signer reload path.
  // Failure aborts before arm -- arming a wall the agent cannot function
  // behind is the exact confine-into-silence outcome this step exists to
  // prevent -- and emits the DISTINCT `egress_provision_refused` audit op so
  // a fleet operator can prove the refusal happened and why.
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
    return {
      kind: "aborted",
      stage: "provision-egress",
      reason: withDaemonTeardownNote(
        `refusing to arm: the egress path for the confined agent could not be provisioned and verified ` +
          `(${egress.error}). The wall was NOT armed; the agent would have been confined into ` +
          `non-functionality. ` +
          describeRestoreForReason(td.rolledBack, td.conflictPaths, td.failedPaths),
        td.daemonTeardownError,
        td.policyDaemonTeardownError,
        td.egressScrubError,
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

  // Step 7: verify BEFORE arming (fix B2 ordering). FIX G5 (2026-07-07
  // re-gate 3): this proves DNS-resolvability + every moved credential
  // present-and-readable-by-target-uid (see verify.ts's module doc), NOT
  // reachability "as the new uid" (this process never crosses a uid
  // boundary) and NOT allow-list correctness (the wall is not armed yet).
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
        td.egressScrubError,
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

  // Step 8: arm-time uid-existence gate (fix H1). Immediately before
  // arming, hard-check the account still exists at exactly this uid.
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
        td.egressScrubError,
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

  // Step 9: arm via the shipped `enable --agent-uid=N --ceiling` (step 1).
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
          td.egressScrubError,
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

  // Step 10: post-arm connectivity re-check with fast disarm-rollback (fix
  // B2). Allow-list correctness is only provable now.
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
    // No orphan grants on a rolled-back run (design section 6): scrub the
    // egress rules this run provisioned. Best-effort + fail-loud (folded into
    // the reason); the wall is already down, so a surviving rule is inert
    // until a future arm, but it must still be surfaced, never silent.
    const scrubNote = await scrubEgressBestEffort(ops, egressProvisionedThisRun);
    return {
      kind: "armed-then-rolled-back",
      uid,
      reason: `${baseReason} Fast-disarmed rather than leave a bricked agent.${scrubNote}`,
      disarmObservedOff: disarmObservedOff ? true : undefined,
    };
  }

  // Step 11 (confined-agent egress, design section 5): the REAL post-arm
  // egress check, run AS THE AGENT UID through the ARMED wall -- the check
  // the 2026-07-09 drill proved the DNS-only probes above cannot make
  // ((a) static without (b) dynamic is theater). Every declared endpoint
  // must complete a TCP+TLS connect as the agent uid, and the non-listed
  // negative control must stay BLOCKED. Any failure triggers the same fix-B2
  // fast-disarm rollback as step 10, plus the provisioned-rule scrub, and is
  // reported as the DISTINCT local outcome `egress-unprovisioned-rolled-back`.
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
    const scrubNote = await scrubEgressBestEffort(ops, egressProvisionedThisRun);
    await ops.auditEgress(EGRESS_PROVISION_REFUSED_AUDIT_OP, {
      stage: "post-arm-as-uid-verify",
      harness: ctx.agentId,
      agent_uid: uid,
      declared_endpoints: ctx.harnessEndpoints.endpoints.map((e) => `${e.host}:${e.port}`),
      probe_rows: egressVerify.rows,
      disarm_outcome: "fast-disarmed",
      rules_scrubbed: scrubNote === "",
    });
    return {
      kind: "egress-unprovisioned-rolled-back",
      uid,
      reason: `${egressBaseReason} Fast-disarmed rather than leave a bricked-or-unconfined agent.${scrubNote}`,
      scrubbed: disarmed && scrubNote === "",
      disarmObservedOff: disarmObservedOff ? true : undefined,
    };
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

  // S5-6: the exclusive-egress arming stage. Runs ONLY after the coarse
  // stages proved live (wall armed + as-uid egress verified) and only over a
  // PARKED harness (asserted at install). Every failure inside the stage is
  // handled by the stage itself (degrade-loud coarse fallback / parked), so
  // the mapping here is 1:1 outcome translation -- no failure path can fall
  // through to a green "armed".
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
    harnessStartedCoarse: exclusive.harnessStartedCoarse,
    cleanupErrors: exclusive.cleanupErrors,
  };
}

/**
 * Best-effort provisioned-rule scrub for the rolled-back branches. Returns
 * "" on success (or when nothing was provisioned this run), or a loud
 * manual-recovery note to append to the outcome reason on failure. Never
 * throws.
 */
async function scrubEgressBestEffort(
  ops: ProvisionFlowOps,
  egressProvisionedThisRun: boolean,
): Promise<string> {
  if (!egressProvisionedThisRun) return "";
  try {
    await ops.scrubProvisionedEgress();
    return "";
  } catch (err) {
    return (
      ` (NOTE: the provisioned egress allow rules could NOT be scrubbed automatically: ` +
      `${(err as Error).message}. They are inert while the wall is disarmed, but remove the ` +
      `provisioned-* rule files under <fortress>/policy/egress/rules/ before re-arming manually.)`
    );
  }
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
  scrubEgress = false,
): Promise<{
  rolledBack: boolean | "partial";
  backupPaths: string[];
  conflictPaths: string[];
  failedPaths: string[];
  daemonTeardownError?: string;
  policyDaemonTeardownError?: string;
  egressScrubError?: string;
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
  // Confined-agent egress (design section 6): rules this run provisioned are
  // scrubbed on abort so a failed run never leaves orphan grants. Best-effort
  // + fail-loud (folded into the abort reason), never blocks the restore.
  let egressScrubError: string | undefined;
  if (scrubEgress) {
    try {
      await ops.scrubProvisionedEgress();
    } catch (err) {
      egressScrubError = (err as Error).message;
    }
  }
  const restore = await safeRestore(ops, results);
  return {
    rolledBack: restore.rolledBack,
    backupPaths: restore.backupPaths,
    conflictPaths: restore.conflictPaths,
    failedPaths: restore.failedPaths,
    daemonTeardownError,
    policyDaemonTeardownError,
    egressScrubError,
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
  egressScrubError?: string,
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
  if (egressScrubError !== undefined) {
    notes.push(
      `the provisioned egress allow rules could NOT be scrubbed automatically: ${egressScrubError}. ` +
        `Remove the provisioned-* rule files under <fortress>/policy/egress/rules/ before re-arming manually.`,
    );
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
