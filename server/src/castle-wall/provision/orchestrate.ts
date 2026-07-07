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
  /** Install the harness daemon for the given uid. */
  installHarnessDaemon(uid: number): Promise<void>;
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
  }>;
}

/**
 * Terminal outcome of the whole flow, for the CLI layer to render + exit-code
 * on. FIX F2/F5 (2026-07-07 fix-round): `rolledBack` on `aborted` is now
 * `boolean | "partial"` -- `"partial"` means SOME but not all re-homed paths
 * came back, which must render loud manual-recovery guidance at the CLI
 * layer, never be collapsed into a clean `true`. `backupPath` threads the
 * custody-copy location through so the CLI can print it for manual recovery.
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
    }
  | { kind: "armed-then-rolled-back"; uid: number; reason: string };

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
  if (ctx.detectResult.alreadyDedicated) {
    if (ctx.detectResult.resolved === undefined) {
      // Defensive: `alreadyDedicated` without a resolved uid is a caller
      // contract violation. Fail closed rather than dereference undefined.
      return {
        kind: "aborted",
        stage: "detect",
        reason: "detectResult.alreadyDedicated is true but no uid was resolved; refusing to proceed.",
        rolledBack: false,
      };
    }
    uid = ctx.detectResult.resolved.uid;
    ops.print(
      `Agent already runs as a verified dedicated account (uid ${uid}): ${ctx.detectResult.reason} ` +
        `Skipping account creation and re-home; still installing the harness daemon, verifying, and arming.`,
    );
  } else {
    // Step 2: plan-and-print. No mutation yet.
    ops.print(
      `Plan: create hidden account "${ctx.accountName}" (no login), move Hermes config/secrets onto it, ` +
        `install the ai.sanctuaryprotocol.agent-harness LaunchDaemon, then arm with ` +
        `--agent-uid=<new uid> --ceiling=${ctx.ceiling}.`,
    );

    // Step 3: ONE confirm, scoped to the privileged sub-steps only (fix H4).
    // Non-TTY refusal applies HERE ONLY -- the caller (wrap/cli.ts) is
    // responsible for letting the cooperative wrap itself still complete;
    // this function just reports that provisioning was skipped so the caller
    // knows to print the "cooperative-only, re-run interactively" message.
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

    // Step 4: create the dedicated hidden service account.
    try {
      const created = await ops.createAccount();
      uid = created.uid;
      ops.print(`Account "${ctx.accountName}" ready at uid ${uid}.`);
    } catch (err) {
      return { kind: "aborted", stage: "create-account", reason: (err as Error).message, rolledBack: false };
    }

    // Step 5: re-home (backup-first, reversible).
    try {
      const rehomed = await ops.rehome(uid, uid);
      rehomeResults = rehomed.results;
      ops.print(`Re-homed ${rehomeResults.filter((r) => r.status === "moved").length} path(s) onto the new account.`);
    } catch (err) {
      return { kind: "aborted", stage: "rehome", reason: (err as Error).message, rolledBack: false };
    }
  }

  // Step 6: install the harness daemon. Agent now runs at ruid = uid; wall
  // NOT yet armed. A failure here means we already moved secrets -- restore
  // them before reporting the abort (never leave a half-provisioned agent).
  try {
    await ops.installHarnessDaemon(uid);
    ops.print("Harness daemon installed; agent now runs under the dedicated account.");
  } catch (err) {
    const restore = await safeRestore(ops, rehomeResults);
    return {
      kind: "aborted",
      stage: "install-daemon",
      reason: (err as Error).message,
      rolledBack: restore.rolledBack,
      backupPaths: restore.backupPaths,
    };
  }

  // Step 7: verify BEFORE arming (fix B2 ordering) -- unfiltered
  // reachability as the new uid. This proves re-home correctness, NOT
  // allow-list correctness (the wall is not armed yet).
  const preArmVerify: ConnectivityVerifyResult = await verifyReachabilityBeforeArm(ops.preArmEndpoints());
  if (!preArmVerify.allReachable) {
    const unreachable = preArmVerify.results.filter((r) => !r.reachable).map((r) => r.name);
    const restore = await safeRestore(ops, rehomeResults);
    return {
      kind: "aborted",
      stage: "verify-before-arm",
      reason:
        `re-homed agent could not reach: ${unreachable.join(", ")}. ` +
        describeRestoreForReason(restore.rolledBack),
      rolledBack: restore.rolledBack,
      backupPaths: restore.backupPaths,
    };
  }

  // Step 8: arm-time uid-existence gate (fix H1). Immediately before
  // arming, hard-check the account still exists at exactly this uid.
  const existenceCheck = await ops.checkUidExistence(uid);
  if (!existenceCheck.ok) {
    const restore = await safeRestore(ops, rehomeResults);
    return {
      kind: "aborted",
      stage: "uid-existence-gate",
      reason: existenceCheck.reason,
      rolledBack: restore.rolledBack,
      backupPaths: restore.backupPaths,
    };
  }

  // Step 9: arm via the shipped `enable --agent-uid=N --ceiling` (step 1).
  const armResult = await ops.arm(uid, ctx.ceiling);
  if (!armResult.ok) {
    const restore = await safeRestore(ops, rehomeResults);
    return {
      kind: "aborted",
      stage: "arm",
      reason: armResult.error,
      rolledBack: restore.rolledBack,
      backupPaths: restore.backupPaths,
    };
  }

  // Step 10: post-arm connectivity re-check with fast disarm-rollback (fix
  // B2). Allow-list correctness is only provable now.
  const postArmVerify: ConnectivityVerifyResult = await verifyReachabilityAfterArm(ops.postArmEndpoints());
  if (!postArmVerify.allReachable) {
    const unreachable = postArmVerify.results.filter((r) => !r.reachable).map((r) => r.name);
    await ops.disarm();
    return {
      kind: "armed-then-rolled-back",
      uid,
      reason: `post-arm check found the allow-list blocks: ${unreachable.join(", ")}. Fast-disarmed rather than leave a bricked agent.`,
    };
  }

  return { kind: "armed", uid };
}

function describeRestoreForReason(rolledBack: boolean | "partial"): string {
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
): Promise<{ rolledBack: boolean | "partial"; backupPaths: string[] }> {
  try {
    const { fullyRestored, restoredCount, backupPaths } = await ops.restoreRehome(results);
    const rolledBack: boolean | "partial" = fullyRestored ? true : restoredCount > 0 ? "partial" : false;
    return { rolledBack, backupPaths };
  } catch {
    // Best-effort call, but the OUTCOME must be honest: a restore that threw
    // is a failed restore, not a successful one. The original abort reason
    // this was invoked from is preserved by the caller; this function only
    // ever reports on the restore itself.
    return { rolledBack: false, backupPaths: results.filter((r) => r.backupPath).map((r) => r.backupPath!) };
  }
}
