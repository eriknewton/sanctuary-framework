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
 *       ceremony. This module does not import, call, or stub any account-
 *       deletion primitive; there is deliberately no `deleteUser`-shaped
 *       function anywhere in this PR's diff.
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
  step: "disarm" | "uninstall-daemon" | "restore-rehome";
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
      outcomes.push({
        step: "restore-rehome",
        ok: false,
        error:
          failed.length > 0
            ? `${failed.length} path(s) did not restore: ${failed
                .map((s) => `${s.sourcePath} (${s.error ?? "unknown error"})`)
                .join(", ")}`
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
