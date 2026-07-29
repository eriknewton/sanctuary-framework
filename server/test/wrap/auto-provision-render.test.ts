/**
 * Round-2 chokepoint (fix round-5 R2-2/R2-3): the CLI render of a
 * ProvisionFlowOutcome was previously an unexported, console-only function
 * with ZERO unit coverage -- which is exactly how R2-2 (a failed daemon
 * teardown getting the soft "Note:" frame) and R2-3 (the non-TTY reason
 * rendered silently) survived. `renderAutoProvisionOutcomeLines` is now a pure
 * exported function returning the operator-facing lines, so every framing
 * decision is driven directly here.
 */

import { describe, it, expect, vi } from "vitest";
import {
  autoProvisionCeilingFromSummary,
  renderAutoProvisionOutcome,
  renderAutoProvisionOutcomeLines,
} from "../../src/wrap/cli.js";
import {
  describeNoAccountResidueTeardown,
  describeStandDownAgentForCli,
  ensureStandDownAgentAcknowledgedForCli,
  runEgressGateRepairForCli,
  runEgressGateUnprotectForCli,
  type AutoProvisionSummary,
} from "../../src/wrap/auto-provision.js";
import {
  assessHarnessParked,
  startedCoarseDisposition,
  type HarnessDisposition,
  type ParkedClaim,
} from "../../src/egress-gate/parked-claim.js";
import type { HarnessDaemonStatus } from "../../src/egress-gate/harness-daemon.js";
import { describeExclusiveRoutingResidueRefusal } from "../../src/castle-wall/provision/orchestrate.js";

function lines(summary: AutoProvisionSummary): string[] {
  return renderAutoProvisionOutcomeLines(summary);
}

describe("wrap/cli renderAutoProvisionOutcomeLines", () => {
  it("not-ran or no-outcome -> no lines", () => {
    expect(lines({ ran: false })).toEqual([]);
    expect(lines({ ran: true })).toEqual([]);
  });

  it("R8: guarded printer reports an unrenderable outcome instead of throwing past wrap success", () => {
    // Fails with the R8 fix reverted: the `never` default throw from
    // renderAutoProvisionOutcomeLines propagates out of the printer.
    const printed: string[] = [];
    expect(() =>
      renderAutoProvisionOutcome(
        {
          ran: true,
          outcome: { kind: "future-outcome", reason: "new branch" } as unknown as AutoProvisionSummary["outcome"],
        },
        (line) => printed.push(line),
      ),
    ).not.toThrow();
    expect(printed.join("\n")).toMatch(/could not display/i);
  });

  it("armed -> a single quiet confirmation with the uid", () => {
    const out = lines({ ran: true, outcome: { kind: "armed", uid: 502 } });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/armed \(uid 502\)/);
  });

  it("skipped-already-dedicated stays SILENT (orchestrator already printed its plan-and-print line)", () => {
    expect(lines({ ran: true, outcome: { kind: "skipped-already-dedicated", reason: "already dedicated" } })).toEqual([]);
  });

  it("FIX R2-3: skipped-non-tty-cooperative-only SURFACES the reason (was silently dropped)", () => {
    const reason =
      "provisioning requires an interactive confirm and this run is non-interactive (no TTY); " +
      "the cooperative wrap still completed. Re-run interactively to provision the account and arm the wall.";
    const out = lines({ ran: true, outcome: { kind: "skipped-non-tty-cooperative-only", reason } });
    expect(out).toHaveLength(1);
    expect(out[0]).toContain("Re-run interactively to provision the account and arm the wall");
  });

  it("declined-by-operator -> informational, never a failure/retry frame", () => {
    const out = lines({ ran: true, outcome: { kind: "declined-by-operator" } });
    expect(out[0]).toMatch(/declined/);
    expect(out[0]).not.toMatch(/WARNING/);
  });

  it("armed-then-rolled-back copy is HONEST -- no 'allow-list' (R2 / N5)", () => {
    const out = lines({
      ran: true,
      outcome: { kind: "armed-then-rolled-back", uid: 502, reason: "post-arm connectivity re-check failed for: LLM (Venice)" },
    });
    expect(out[0]).not.toMatch(/allow-list/);
    expect(out[0]).toMatch(/connectivity re-check passes/);
  });

  it("egress-unprovisioned-rolled-back -> honest Note frame: fast-disarmed, agent stays re-homed, egress-restore state surfaced, retry guidance", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "egress-unprovisioned-rolled-back",
        uid: 503,
        reason: "post-arm as-uid egress verification failed for: LLM (Venice). Fast-disarmed rather than leave a bricked-or-unconfined agent.",
        egressRestoredToPreRunState: true,
      },
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/fast-disarmed/i);
    expect(out[0]).toMatch(/as-agent-uid egress verification failed/);
    // FIX F-REVOKE: the claim is "restored to their pre-run state", not
    // "scrubbed" -- on a re-run the pre-run state includes a previous run's
    // live grants, and asserting removal there was the agent-strangling case.
    expect(out[0]).toMatch(/provisioned egress rules were restored to their pre-run state/);
    expect(out[0]).toMatch(/still runs under its dedicated, re-homed account/);
    expect(out[0]).toMatch(/Re-run 'sanctuary protect --hermes'/);
  });

  it("egress-unprovisioned-rolled-back with egressRestoredToPreRunState:false does NOT claim the pre-run rule state was restored", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "egress-unprovisioned-rolled-back",
        uid: 503,
        reason: "post-arm as-uid egress verification failed for: negative control.",
        egressRestoredToPreRunState: false,
      },
    });
    expect(out[0]).not.toMatch(/were restored to their pre-run state/);
  });

  it("armed-rollback-failed -> LOUDEST manual-disarm guidance", () => {
    const out = lines({
      ran: true,
      outcome: { kind: "armed-rollback-failed", uid: 502, reason: "post-arm re-check failed", disarmError: "disable exited 1" },
    });
    expect(out[0]).toMatch(/^ {2}WARNING: Castle Wall is ARMED/);
    expect(out[0]).toMatch(/sudo sanctuary castle-wall disable/);
  });

  it("R1: save-accepted-but-inconclusive disarm contributes an unknown CEILING, never an uncapped protected claim", () => {
    // Fails with the disarm-ceiling guard reverted: `save_accepted_inconclusive`
    // carries neither disarmObservedOff nor wallMayBeArmed, so the ceiling
    // would be undefined and a later green probe could pass through.
    const claim = autoProvisionCeilingFromSummary({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "arm",
        reason: "disable save accepted but status reread was inconclusive",
        rolledBack: true,
        disarmOutcome: "save_accepted_inconclusive",
      },
    });
    expect(claim?.state).toBe("unknown");
    expect(claim?.basis).toBe("provision_outcome_not_observation");
  });

  it("safe-direction: aborted wallMayBeArmed now contributes an unknown CEILING", () => {
    // Fails if the safe-direction R3 change is reverted: the aborted kind would
    // be uncapped and could print protected over an inconclusive arm-abort.
    const claim = autoProvisionCeilingFromSummary({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "arm",
        reason: "arm returned nonzero after enabling the host app preference",
        rolledBack: true,
        wallMayBeArmed: true,
      },
    });
    expect(claim?.state).toBe("unknown");
    expect(claim?.basis).toBe("provision_outcome_not_observation");
  });

  it("aborted rolledBack:true (no daemon issue) -> soft Note frame with retry", () => {
    const out = lines({ ran: true, outcome: { kind: "aborted", stage: "rehome", reason: "boom", rolledBack: true } });
    expect(out[0]).toMatch(/^ {2}Note:/);
    expect(out[0]).toMatch(/Re-run 'sanctuary protect --hermes' to retry/);
  });

  it("aborted rolledBack:false -> LOUD manual-recovery frame with backup paths", () => {
    const out = lines({
      ran: true,
      outcome: { kind: "aborted", stage: "install-daemon", reason: "boom", rolledBack: false, backupPaths: ["/var/root/x.bak"] },
    });
    expect(out[0]).toMatch(/^ {2}WARNING:/);
    expect(out[0]).toMatch(/manual recovery is required/);
    expect(out[0]).toContain("/var/root/x.bak");
  });

  it("aborted rolledBack:'partial' -> LOUD 'only SOME restored' frame", () => {
    const out = lines({ ran: true, outcome: { kind: "aborted", stage: "arm", reason: "boom", rolledBack: "partial" } });
    expect(out[0]).toMatch(/^ {2}WARNING:/);
    expect(out[0]).toMatch(/Only SOME of your re-homed files were restored/);
  });

  it("FIX R2-2: a FAILED daemon teardown forces the LOUD frame EVEN WHEN the re-home restore succeeded (rolledBack:true)", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "verify-before-arm",
        reason:
          "re-homed agent could not reach: X (NOTE: the harness daemon could NOT be torn down automatically: launchctl bootout failed).",
        rolledBack: true,
        daemonTeardownFailed: true,
      },
    });
    expect(out).toHaveLength(1);
    // Must be the loud WARNING frame, not the soft rolledBack:true "Note:" line.
    expect(out[0]).toMatch(/^ {2}WARNING:/);
    expect(out[0]).toMatch(/root harness LaunchDaemon may still be running/);
    expect(out[0]).not.toMatch(/Re-homed paths were restored to your account\. Re-run/);
  });

  it("Bug B P0 (disarm-first): a wallMayBeArmed arm-abort forces the LOUD 'MAY STILL BE ARMED / castle-wall disable' frame and NEVER the clean 'rolled back; re-run' line -- EVEN WHEN rolledBack:true (the honesty gap)", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "arm",
        reason:
          "castle-wall enable exited 1 (WALL-STATE WARNING: arming reported a failure but the content filter MAY STILL BE ARMED and disarm could not confirm it is off: castle-wall disable exited 1. ... Run 'sudo sanctuary castle-wall disable' to confirm the filter is off before re-running.)",
        rolledBack: true,
        rehomeAttempted: true,
        wallMayBeArmed: true,
      },
    });
    expect(out).toHaveLength(1);
    // Loud WARNING frame, NOT the soft rolledBack:true "re-run to retry" line.
    expect(out[0]).toMatch(/^ {2}WARNING:/);
    expect(out[0]).toMatch(/MAY STILL BE ARMED/);
    expect(out[0]).toMatch(/castle-wall disable/);
    expect(out[0]).not.toMatch(/Re-homed paths were restored to your account\. Re-run/);
  });

  it("FIX R2-2: succeeded daemon teardown (daemonTeardownFailed:false) with rolledBack:true uses the soft Note frame (no false loud warning)", () => {
    const out = lines({
      ran: true,
      outcome: { kind: "aborted", stage: "verify-before-arm", reason: "re-homed agent could not reach: X.", rolledBack: true, daemonTeardownFailed: false, rehomeAttempted: true },
    });
    expect(out[0]).toMatch(/^ {2}Note:/);
  });

  it("FIX R3-2: a pre-re-home abort (rehomeAttempted:false) renders a NEUTRAL 'nothing was changed' Note, never the 'restore FAILED' alarm (the common no-sudo first attempt)", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "root-check",
        reason: "auto-provisioning requires root; re-run with sudo.",
        rolledBack: false,
        rehomeAttempted: false,
      },
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/^ {2}Note:/);
    expect(out[0]).toMatch(/No files were moved before this stop/);
    expect(out[0]).not.toMatch(/restore of your re-homed files FAILED/);
    expect(out[0]).not.toMatch(/WARNING/);
  });

  it("FIX F-COARSE-AFTER-EXCLUSIVE: the exclusive-routing-residue abort renders NEUTRAL (it is pre-mutation), never the 'restore FAILED' alarm", () => {
    // The residue gate is the earliest abort in the flow: nothing has been
    // created, moved, installed, or armed. If it ever stopped reporting
    // `rehomeAttempted: false` this renderer would tell the operator their
    // re-homed files need manual recovery, over a run that moved none.
    const out = lines({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "exclusive-routing-residue",
        reason: describeExclusiveRoutingResidueRefusal({
          kind: "kept-live",
          reason: "a gate daemon owns port 40001 under gate uid 708",
        }),
        rolledBack: false,
        rehomeAttempted: false,
      },
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/^ {2}Note:/);
    expect(out[0]).toMatch(/No files were moved before this stop/);
    expect(out[0]).toMatch(/--unprotect-egress-gate/);
    expect(out[0]).not.toMatch(/restore of your re-homed files FAILED/);
    expect(out[0]).not.toMatch(/WARNING/);
  });

  it("FIX R3-2: rolledBack:false WITHOUT rehomeAttempted:false still shows the LOUD restore-failed frame (a genuine failed restore after a real re-home)", () => {
    const out = lines({
      ran: true,
      outcome: { kind: "aborted", stage: "verify-before-arm", reason: "boom", rolledBack: false, rehomeAttempted: true },
    });
    expect(out[0]).toMatch(/^ {2}WARNING:/);
    expect(out[0]).toMatch(/restore of your re-homed files FAILED/);
  });

  it("FIX R4-2: a rehome-stage neutral abort with accountCreated:true does NOT falsely claim 'No dedicated account was created' (an orphaned account exists)", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "rehome",
        reason: "backup destination not writable",
        rolledBack: true,
        rehomeAttempted: false,
        accountCreated: true,
      },
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/^ {2}Note:/);
    expect(out[0]).not.toMatch(/No dedicated account was created/);
    expect(out[0]).toMatch(/The dedicated account was created but no files were moved/);
  });

  it("B1 round 2: a neutral abort with no observed account status does NOT claim no account was created", () => {
    const out = lines({
      ran: true,
      outcome: { kind: "aborted", stage: "root-check", reason: "requires root", rolledBack: false, rehomeAttempted: false },
    });
    expect(out[0]).toMatch(/No files were moved before this stop/);
    expect(out[0]).not.toMatch(/No dedicated account was created/);
  });

  it("FIX R5-2: a restore CONFLICT (conflictPaths set) renders a data-safe Note, surfaces the conflict path, and NEVER says 'restore FAILED' or overwrite-from-backup", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "install-daemon",
        reason: "launchctl bootstrap exited 5",
        rolledBack: false,
        rehomeAttempted: true,
        backupPaths: ["/var/root/.sanctuary-rehome-backups/x.bak"],
        conflictPaths: ["/Users/op/.hermes/.env.restored-conflict"],
      },
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/^ {2}Note:/);
    expect(out[0]).not.toMatch(/restore of your re-homed files FAILED/);
    expect(out[0]).toContain("/Users/op/.hermes/.env.restored-conflict");
    expect(out[0]).toMatch(/reconcile/i);
    expect(out[0]).toMatch(/do NOT overwrite/);
  });

  it("FIX R5-2: a daemon-teardown failure WITH a conflict still WARNs (daemon live) but also surfaces the conflict path and no overwrite-from-backup", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "verify-before-arm",
        reason: "unreachable",
        rolledBack: false,
        daemonTeardownFailed: true,
        conflictPaths: ["/Users/op/.hermes/.env.restored-conflict"],
      },
    });
    expect(out[0]).toMatch(/^ {2}WARNING:/);
    expect(out[0]).toContain("/Users/op/.hermes/.env.restored-conflict");
    expect(out[0]).toMatch(/do NOT overwrite/);
  });

  it("FIX R6-2: a conflict co-occurring with a GENUINE failure (failedPaths set) stays LOUD (WARNING) and surfaces BOTH the backup and the conflict path -- the conflict never masks the failure", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "install-daemon",
        reason: "boom",
        rolledBack: false,
        rehomeAttempted: true,
        backupPaths: ["/var/root/x.bak"],
        conflictPaths: ["/Users/op/.hermes/.env.restored-conflict"],
        failedPaths: ["/Users/op/.hermes/auth.json"],
      },
    });
    expect(out[0]).toMatch(/^ {2}WARNING:/);
    expect(out[0]).toMatch(/restore of your re-homed files FAILED/);
    expect(out[0]).toContain("/var/root/x.bak");
    expect(out[0]).toContain("/Users/op/.hermes/.env.restored-conflict");
  });
});

describe("describeStandDownAgentForCli", () => {
  it("plainly says the repair flag acknowledges the required agent stop", () => {
    const line = describeStandDownAgentForCli("--repair-egress-gate");
    expect(line).toContain("--repair-egress-gate --stand-down-agent");
    expect(line).toContain("acknowledged operator opt-in");
    expect(line).toContain("stop and disable the agent harness");
  });

  it("refuses repair/unprotect when the required stand-down acknowledgement is absent", () => {
    const printed: string[] = [];
    const ok = ensureStandDownAgentAcknowledgedForCli(
      undefined,
      (line) => printed.push(line),
      "--unprotect-egress-gate",
    );
    expect(ok).toBe(false);
    expect(printed.join("\n")).toContain("--unprotect-egress-gate stops and disables the agent harness");
    expect(printed.join("\n")).toContain("--unprotect-egress-gate --stand-down-agent");
  });

  it("allows repair/unprotect when the stand-down acknowledgement is present", () => {
    const printed: string[] = [];
    const ok = ensureStandDownAgentAcknowledgedForCli(
      true,
      (line) => printed.push(line),
      "--repair-egress-gate",
    );
    expect(ok).toBe(true);
    expect(printed).toEqual([]);
  });

  it("runEgressGateRepairForCli refuses missing stand-down acknowledgement before platform/root/identity gates", async () => {
    const printed: string[] = [];
    const resolveOperatorIdentity = vi.fn(async () => {
      throw new Error("identity should not be reached");
    });

    const code = await runEgressGateRepairForCli({
      isTty: false,
      overrideTransientPfRules: false,
      print: (line) => printed.push(line),
      getuid: () => 0,
      resolveOperatorIdentity,
    });

    expect(code).toBe(2);
    expect(printed.join("\n")).toContain("--repair-egress-gate stops and disables the agent harness");
    expect(printed.join("\n")).toContain("sudo sanctuary protect --repair-egress-gate --stand-down-agent");
    expect(printed.join("\n")).not.toContain("macOS-only");
    expect(resolveOperatorIdentity).not.toHaveBeenCalled();
  });

  it("runEgressGateUnprotectForCli refuses missing stand-down acknowledgement before platform/root/identity gates", async () => {
    const printed: string[] = [];
    const resolveOperatorIdentity = vi.fn(async () => {
      throw new Error("identity should not be reached");
    });

    const code = await runEgressGateUnprotectForCli({
      print: (line) => printed.push(line),
      getuid: () => 0,
      resolveOperatorIdentity,
    });

    expect(code).toBe(2);
    expect(printed.join("\n")).toContain("--unprotect-egress-gate stops and disables the agent harness");
    expect(printed.join("\n")).toContain("sudo sanctuary protect --unprotect-egress-gate --stand-down-agent");
    expect(printed.join("\n")).not.toContain("macOS-only");
    expect(resolveOperatorIdentity).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// FIX-ROUND 4: the render layer, which had ZERO register rows and ZERO tests
// for what the operator is told about the agent's run state.
// ---------------------------------------------------------------------------

/**
 * The round-4 HIGH printed HERE. `grep -rn "remains parked\|PARKED (not
 * running)" test/` returned nothing before this block: the barrier gate had
 * regression tests, and nothing asserted what the operator READS when it
 * fires. These tests are Claude's E3 probe reproduced end to end -- the
 * degrade outcome that arises when a live process survived the bootout, driven
 * through the real render function, asserting on the character stream.
 */
describe("wrap/cli: the degrade line never asserts a run state it did not observe", () => {
  function degradeSummary(harness: HarnessDisposition): AutoProvisionSummary {
    return {
      ran: true,
      outcome: {
        kind: "exclusive-egress-unarmed-coarse-active",
        uid: 502,
        stage: "release",
        reason:
          "release barrier parked at stage reassert-parked: the parked state was not asserted: " +
          "a settled launchd read still reports a pid (9001) for the harness job",
        coarseCompositionRestored: true,
        harness,
        cleanupErrors: [],
      },
    };
  }

  async function claim(status: Partial<HarnessDaemonStatus>): Promise<ParkedClaim> {
    return assessHarnessParked({
      probe: {
        harnessStatus: async (): Promise<HarnessDaemonStatus> => ({
          known: true,
          installed: true,
          running: false,
          ...status,
        }),
        sleepMs: async () => undefined,
      },
    });
  }

  it("a SURVIVING process is never described as parked (the round-4 HIGH)", async () => {
    // Ground truth: pid 9001 is alive throughout, which is the entire reason
    // the barrier refused. The pre-fix render said, in the same sentence that
    // reported the pid: "The agent is PARKED (not running)".
    const out = lines(
      degradeSummary({ disposition: "not-started", claim: await claim({ running: true, pid: 9001 }) }),
    ).join(" ");
    expect(out).toContain("9001");
    expect(out).toContain("The agent is RUNNING (pid 9001)");
    expect(out).not.toContain("PARKED");
    expect(out).not.toContain("not running");
    // Still LOUD and still routed to the repair verb.
    expect(out).toContain("WARNING");
    expect(out).toContain("--repair-egress-gate");
  });

  it("an UNKNOWABLE run state is rendered as possibly-running, never as parked", async () => {
    const out = lines(
      degradeSummary({ disposition: "not-started", claim: await claim({ known: false }) }),
    ).join(" ");
    expect(out).toContain("POSSIBLY RUNNING");
    expect(out).not.toContain("is PARKED");
  });

  it("a genuinely stopped agent IS described as parked (the fix is not blanket hedging)", async () => {
    const out = lines(
      degradeSummary({ disposition: "not-started", claim: await claim({}) }),
    ).join(" ");
    expect(out).toContain("The agent is PARKED (not running)");
  });

  it("a coarse-started agent is still described as running in coarse-only mode", () => {
    const out = lines(degradeSummary(startedCoarseDisposition())).join(" ");
    expect(out).toContain("RUNNING in coarse-only mode");
    expect(out).not.toContain("PARKED");
  });

  it("a FAILED coarse restore is reported as a manifest fact, not as a run-state claim", async () => {
    // The `coarseCompositionRestored: false` sub-case. Pre-fix this printed
    // "The agent is PARKED (not running) and the manifest could NOT be
    // restored" -- one clause observed, one invented.
    const summary = degradeSummary({
      disposition: "not-started",
      claim: await claim({ running: true, pid: 9001 }),
    });
    (summary.outcome as { coarseCompositionRestored: boolean }).coarseCompositionRestored = false;
    const out = lines(summary).join(" ");
    expect(out).toContain("manifest could NOT be restored to coarse scope");
    expect(out).toContain("The agent is RUNNING (pid 9001)");
    expect(out).not.toContain("PARKED");
  });
});

// ---------------------------------------------------------------------------
// FIX G2/G5 (re-gate, 2026-07-26): the NO-ACCOUNT residue teardown's operator
// sentence. `runEgressGateUnprotectForCli` is darwin+root gated, so the mapping
// verdict -> sentence is exported and asserted here directly.
// ---------------------------------------------------------------------------
describe("describeNoAccountResidueTeardown (the --unprotect-egress-gate exit when the agent account is gone)", () => {
  const ACCOUNT = "sanctuary-hermes";

  it("cleared -> exit 0 and says provisioning can now run", () => {
    const out = describeNoAccountResidueTeardown(ACCOUNT, {
      kind: "cleared",
      detail: "no registry entry and no serving gate for uid 503",
    });
    expect(out.code).toBe(0);
    expect(out.line).toMatch(/provisioning can now run/);
  });

  it("G2: refused -> the operator is given a REAL path out, not just 'Re-create the dedicated agent account'", () => {
    // The pre-fix sentence ended at "Re-create the dedicated agent account,
    // then re-run this command", which names NO product verb: there is no
    // command that creates the account without provisioning, and provisioning
    // is refused by the same residue gate that sends the operator here. That
    // restored the closed loop one state over.
    const out = describeNoAccountResidueTeardown(ACCOUNT, {
      kind: "refused",
      reason: "the S5-1 anchor registry still has an entry for uid 503",
    });
    expect(out.code).toBe(2);
    // File-level statement of what carries the confinement: available in EVERY
    // state, including the one where no verb applies.
    expect(out.line).toMatch(/\/var\/db\/sanctuary\/egress-anchor-registry\.json/);
    expect(out.line).toMatch(/\/Library\/LaunchDaemons\/ai\.sanctuaryprotocol\.egress-gate\.<uid>\.plist/);
    // And a named verb for the state where one does apply.
    expect(out.line).toMatch(/--repair-egress-gate/);
    expect(out.line).toMatch(/Nothing was changed/);
  });

  it("G5: partial -> states what WAS removed and never claims nothing was changed", () => {
    const out = describeNoAccountResidueTeardown(ACCOUNT, {
      kind: "partial",
      reason: "removing the exclusive-egress gate policy file (/f/policy/egress/x.json) failed: EROFS",
      removed: ["the exclusive-routing marker (/f/allowlist/exclusive-routing.json)"],
    });
    expect(out.code).toBe(2);
    expect(out.line).not.toMatch(/Nothing was changed/);
    expect(out.line).toMatch(/FAILED part way/);
    expect(out.line).toMatch(/This run DID remove the exclusive-routing marker/);
    expect(out.line).toMatch(/mixed state/);
  });
});
