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
import type { AccountProvisionPlan } from "./account.js";
import type { RehomePlan, RehomeStepResult } from "./rehome.js";
import { RehomeExecutionError } from "./rehome.js";
import type { ConnectivityVerifyResult, EndpointProbeTarget } from "./verify.js";
import { verifyReachabilityAfterArm, verifyReachabilityBeforeArm } from "./verify.js";
import type { UidExistenceCheckResult } from "./uid-gate.js";

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
  ): Promise<{ ok: true; bootstrappedThisRun: boolean } | { ok: false; error: string; daemonPreexisted: boolean }>;
  /**
   * Uninstall the harness daemon (fix, round 5 item N3). `installHarnessDaemon`
   * bootstraps a LIVE root LaunchDaemon; every post-install abort branch
   * (verify-before-arm, uid-existence-gate, arm) MUST tear it back down, or a
   * fail-closed abort leaves the daemon running under the dedicated account
   * while the flow reports a clean rollback. Idempotent + fail-loud (matches
   * the shipped `uninstallAgentHarnessDaemon` teardown semantics).
   */
  uninstallHarnessDaemon(): Promise<void>;
  /** Endpoints to probe before arming (LLM / Telegram / Gmail, etc). */
  preArmEndpoints(): EndpointProbeTarget[];
  /** Hard existence + uid-match check immediately before arming (fix H1). */
  checkUidExistence(uid: number): Promise<UidExistenceCheckResult>;
  /** Arm via the shipped `enable --agent-uid=N --ceiling` (step 1). */
  arm(uid: number, ceiling: number): Promise<{ ok: true } | { ok: false; error: string }>;
  /** Endpoints to re-probe after arming (same list, post-arm). */
  postArmEndpoints(): EndpointProbeTarget[];
  /** Fast disarm, used only when the post-arm re-check fails (fix B2 rollback). */
  disarm(): Promise<void>;
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
    }
  | { kind: "armed-then-rolled-back"; uid: number; reason: string }
  | { kind: "armed-rollback-failed"; uid: number; reason: string; disarmError: string };

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
    const td = await teardownDaemonAndRestore(ops, rehomeResults, !install.daemonPreexisted);
    return {
      kind: "aborted",
      stage: "install-daemon",
      reason: withDaemonTeardownNote(install.error, td.daemonTeardownError),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }
  // FIX (round 5 / R7-1): the honest "did this run stand the daemon up" signal
  // -- the post-install abort branches key their teardown on it (never on
  // `alreadyDedicated`, which does not track daemon presence).
  const daemonBootstrappedThisRun = install.bootstrappedThisRun;
  ops.print("Harness daemon installed; agent now runs under the dedicated account.");

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
    // account.
    const td = await teardownDaemonAndRestore(ops, rehomeResults, daemonBootstrappedThisRun);
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
      ),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }

  // Step 8: arm-time uid-existence gate (fix H1). Immediately before
  // arming, hard-check the account still exists at exactly this uid.
  const existenceCheck = await ops.checkUidExistence(uid);
  if (!existenceCheck.ok) {
    // FIX (round 5, item N3): daemon is live; tear it down on this abort.
    const td = await teardownDaemonAndRestore(ops, rehomeResults, daemonBootstrappedThisRun);
    return {
      kind: "aborted",
      stage: "uid-existence-gate",
      reason: withDaemonTeardownNote(existenceCheck.reason, td.daemonTeardownError),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined,
      rehomeAttempted: rehomeResults.some((r) => r.status === "moved"),
      accountCreated,
    };
  }

  // Step 9: arm via the shipped `enable --agent-uid=N --ceiling` (step 1).
  const armResult = await ops.arm(uid, ctx.ceiling);
  if (!armResult.ok) {
    // FIX (round 5, item N3): arming failed but the daemon is live; tear it
    // down on this abort (the wall never armed, so there is nothing to
    // disarm -- only the daemon to remove).
    const td = await teardownDaemonAndRestore(ops, rehomeResults, daemonBootstrappedThisRun);
    return {
      kind: "aborted",
      stage: "arm",
      reason: withDaemonTeardownNote(armResult.error, td.daemonTeardownError),
      rolledBack: td.rolledBack,
      backupPaths: td.backupPaths,
      conflictPaths: td.conflictPaths,
      failedPaths: td.failedPaths,
      daemonTeardownFailed: td.daemonTeardownError !== undefined,
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
    try {
      await ops.disarm();
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
    return {
      kind: "armed-then-rolled-back",
      uid,
      reason: `${baseReason} Fast-disarmed rather than leave a bricked agent.`,
    };
  }

  return { kind: "armed", uid };
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
): Promise<{
  rolledBack: boolean | "partial";
  backupPaths: string[];
  conflictPaths: string[];
  failedPaths: string[];
  daemonTeardownError?: string;
}> {
  // FIX (round 5 / R6-3): only tear the daemon down when THIS run stood it up
  // (the fresh-provision path). On the alreadyDedicated re-run path the harness
  // daemon PRE-EXISTED a prior successful provision, so booting it out over a
  // transient verify/arm failure would destroy working infrastructure -- and
  // the subsequent neutral "nothing was changed" frame would be a lie. Leave a
  // pre-existing daemon in place.
  let daemonTeardownError: string | undefined;
  if (tearDownDaemon) {
    try {
      await ops.uninstallHarnessDaemon();
    } catch (err) {
      daemonTeardownError = (err as Error).message;
    }
  }
  const restore = await safeRestore(ops, results);
  return {
    rolledBack: restore.rolledBack,
    backupPaths: restore.backupPaths,
    conflictPaths: restore.conflictPaths,
    failedPaths: restore.failedPaths,
    daemonTeardownError,
  };
}

/**
 * Fold a harness-daemon teardown failure (fix, round 5 item N3) into an abort
 * reason as LOUD manual-recovery guidance -- the operator must know a root
 * LaunchDaemon may still be live so they can remove it by hand. Returns the
 * reason unchanged when teardown succeeded.
 */
function withDaemonTeardownNote(reason: string, daemonTeardownError?: string): string {
  if (daemonTeardownError === undefined) {
    return reason;
  }
  return (
    `${reason} (NOTE: the harness daemon could NOT be torn down automatically: ${daemonTeardownError}. ` +
    `It may still be running under the dedicated account -- run 'sudo sanctuary castle-wall disable' and remove ` +
    `the ai.sanctuaryprotocol.agent-harness LaunchDaemon manually before re-running.)`
  );
}
