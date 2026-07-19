/**
 * Auto-provision Step 2 (Build 1): `unprovision` rollback (fix H2, split a).
 *
 * FIX H2 (folded from the adversarial review) splits `unprovision` in two:
 *   (a) THIS MODULE -- daemon-uninstall + disarm + restore-backup. Reuses
 *       the shipped `uninstallAgentHarnessDaemon` (egress-gate/harness-daemon.ts)
 *       and the shipped `disable` arm-path, plus `restoreRehomeSteps`
 *       (rehome.ts). Idempotent + fail-loud: every step tolerates "already
 *       torn down" but a genuine failure propagates rather than being
 *       swallowed, matching `uninstallAgentHarnessDaemon`'s own fail-loud
 *       teardown semantics.
 *   (b) Account REMOVAL is explicitly OUT OF SCOPE for this module and this
 *       PR. It is a separate, Erik-present `[M]` build item: `--keepHome`
 *       stays the default (never auto-delete the home directory), and
 *       account removal must NEVER be bundled into the install one-confirm
 *       ceremony. Fresh-create failure rollback has a separate, bounded
 *       `deleteCreatedUser` primitive that keeps the home and is only reached
 *       after observing the planned uid; this module still does not expose or
 *       call routine account removal.
 *
 * Callers inject the daemon uninstall + disarm functions (rather than this
 * module importing egress-gate/harness-daemon.ts and cli/castle-wall.ts
 * directly) so unit tests can assert the ORDER and ARGUMENTS of the
 * rollback without needing real launchctl/host-app plumbing wired up.
 */

import type { RehomeOps, RehomeStepResult } from "./rehome.js";
import { restoreRehomeSteps } from "./rehome.js";

/** Injected rollback operations for daemon teardown + disarm. */
export interface UnprovisionOps {
  /** Uninstall the harness daemon (production: `uninstallAgentHarnessDaemon`). Idempotent. */
  uninstallHarnessDaemon(): Promise<void>;
  /** Disarm the wall (production: `runDisable` / `castle-wall disable`). Unconditional, no preconditions. */
  disarm(): Promise<void>;
  /**
   * Remove every `provisioned-<harness>-*` egress allow rule from the signed
   * manifest source and VERIFY none survive (production:
   * `scrubProvisionedEgressRules`, egress.ts). Rules follow the AGENT
   * lifecycle, not the arm lifecycle (design section 6): a bare disarm keeps
   * them (inert while disarmed, correct again at re-arm), but unprovision
   * removes the agent's provisioning, so its grants must not survive as
   * orphans. Ordering note (review L2): account REMOVAL is explicitly out of
   * scope here (a separate, Erik-present build); when that build lands, this
   * scrub MUST run before the account deletion so a stale allow never
   * outlives the account. Idempotent + fail-loud.
   */
  scrubProvisionedEgressRules(): Promise<void>;
}

/** What to roll back: the daemon/disarm ops plus the re-home steps to restore. */
export interface UnprovisionInput {
  rehomeResults: RehomeStepResult[];
  rehomeOps: RehomeOps;
  unprovisionOps: UnprovisionOps;
  /** The operator's uid/gid, so restored secrets get their custody handed back (fix F3). */
  operatorUidGid: { uid: number; gid: number };
}

/** Outcome of one rollback step, for reporting. */
export interface UnprovisionStepOutcome {
  step: "disarm" | "uninstall-daemon" | "scrub-egress-rules" | "restore-rehome";
  ok: boolean;
  error?: string;
}

/**
 * Roll back a provision attempt: disarm first (so the wall stops enforcing
 * before anything else changes -- never leave an armed wall while its
 * supporting daemon/files are being torn out from under it), then uninstall
 * the harness daemon, then restore the re-homed files from backup.
 *
 * Fail-loud per step: a step's failure is recorded in the returned outcome
 * list (so the caller can report exactly what did and did not roll back)
 * but does NOT stop later steps from being attempted -- an operator
 * recovering from a bad provision wants every possible recovery action
 * attempted, not a rollback that stops at the first snag and leaves the
 * rest undone.
 */
export async function unprovision(input: UnprovisionInput): Promise<UnprovisionStepOutcome[]> {
  const outcomes: UnprovisionStepOutcome[] = [];

  try {
    await input.unprovisionOps.disarm();
    outcomes.push({ step: "disarm", ok: true });
  } catch (err) {
    outcomes.push({ step: "disarm", ok: false, error: (err as Error).message });
  }

  try {
    await input.unprovisionOps.uninstallHarnessDaemon();
    outcomes.push({ step: "uninstall-daemon", ok: true });
  } catch (err) {
    outcomes.push({ step: "uninstall-daemon", ok: false, error: (err as Error).message });
  }

  // Confined-agent egress (design section 6): scrub the harness's
  // provisioned allow rules so unprovision never leaves orphan grants in the
  // signed manifest source. Runs AFTER disarm (the wall stops enforcing
  // first) and after daemon teardown; fail-loud per step like every other
  // rollback action here.
  try {
    await input.unprovisionOps.scrubProvisionedEgressRules();
    outcomes.push({ step: "scrub-egress-rules", ok: true });
  } catch (err) {
    outcomes.push({ step: "scrub-egress-rules", ok: false, error: (err as Error).message });
  }

  try {
    // FIX F2/F5 (2026-07-07 fix-round): `restoreRehomeSteps` now reports
    // whether it ACTUALLY restored every path, rather than this block
    // inferring success from "did not throw". A partial restore (some
    // paths came back, some did not) must surface as `ok: false` with the
    // per-step detail, never a blanket "restore-rehome: ok".
    const restoreResult = await restoreRehomeSteps(input.rehomeResults, input.rehomeOps, input.operatorUidGid);
    if (restoreResult.fullyRestored) {
      outcomes.push({ step: "restore-rehome", ok: true });
    } else {
      const failed = restoreResult.steps.filter((s) => s.status === "failed");
      // FIX R6 (2026-07-07 fix-round 2): a "conflict" step (the source path
      // was recreated during re-home) is a distinct, non-destructive outcome
      // from a bare failure -- surface it by name with its conflict path so
      // the operator knows their recreated file is safe and where the
      // recovered data actually landed.
      const conflicts = restoreResult.steps.filter((s) => s.status === "conflict");
      const details = [
        ...failed.map((s) => `${s.sourcePath} (${s.error ?? "unknown error"})`),
        ...conflicts.map((s) => `${s.sourcePath} (recreated during re-home; recovered data at ${s.conflictPath})`),
      ];
      outcomes.push({
        step: "restore-rehome",
        ok: false,
        error:
          details.length > 0
            ? `${details.length} path(s) did not restore cleanly: ${details.join(", ")}`
            : "restore did not complete for all paths",
      });
    }
  } catch (err) {
    outcomes.push({ step: "restore-rehome", ok: false, error: (err as Error).message });
  }

  return outcomes;
}

/**
 * True only when every rollback step reported ok. Callers use this to
 * decide whether to print a clean "rolled back successfully" versus a
 * "partial rollback, manual recovery needed" message (never silently claim
 * success on a partial rollback).
 */
export function unprovisionFullyOk(outcomes: UnprovisionStepOutcome[]): boolean {
  return outcomes.every((o) => o.ok);
}
