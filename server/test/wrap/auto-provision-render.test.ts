/**
 * Round-2 chokepoint (fix round-5 R2-2/R2-3): the CLI render of a
 * ProvisionFlowOutcome was previously an unexported, console-only function
 * with ZERO unit coverage -- which is exactly how R2-2 (a failed daemon
 * teardown getting the soft "Note:" frame) and R2-3 (the non-TTY reason
 * rendered silently) survived. `renderAutoProvisionOutcomeLines` is now a pure
 * exported function returning the operator-facing lines, so every framing
 * decision is driven directly here.
 */

import { describe, it, expect } from "vitest";
import { renderAutoProvisionOutcomeLines } from "../../src/wrap/cli.js";
import type { AutoProvisionSummary } from "../../src/wrap/auto-provision.js";

function lines(summary: AutoProvisionSummary): string[] {
  return renderAutoProvisionOutcomeLines(summary);
}

describe("wrap/cli renderAutoProvisionOutcomeLines", () => {
  it("not-ran or no-outcome -> no lines", () => {
    expect(lines({ ran: false })).toEqual([]);
    expect(lines({ ran: true })).toEqual([]);
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

  it("egress-unprovisioned-rolled-back -> honest Note frame: fast-disarmed, agent stays re-homed, scrub state surfaced, retry guidance", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "egress-unprovisioned-rolled-back",
        uid: 503,
        reason: "post-arm as-uid egress verification failed for: LLM (Venice). Fast-disarmed rather than leave a bricked-or-unconfined agent.",
        scrubbed: true,
      },
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/fast-disarmed/i);
    expect(out[0]).toMatch(/as-agent-uid egress verification failed/);
    expect(out[0]).toMatch(/provisioned egress rules were scrubbed/);
    expect(out[0]).toMatch(/still runs under its dedicated, re-homed account/);
    expect(out[0]).toMatch(/Re-run 'sanctuary protect --hermes'/);
  });

  it("egress-unprovisioned-rolled-back with scrubbed:false does NOT claim the rules were scrubbed", () => {
    const out = lines({
      ran: true,
      outcome: {
        kind: "egress-unprovisioned-rolled-back",
        uid: 503,
        reason: "post-arm as-uid egress verification failed for: negative control.",
        scrubbed: false,
      },
    });
    expect(out[0]).not.toMatch(/were scrubbed/);
  });

  it("armed-rollback-failed -> LOUDEST manual-disarm guidance", () => {
    const out = lines({
      ran: true,
      outcome: { kind: "armed-rollback-failed", uid: 502, reason: "post-arm re-check failed", disarmError: "disable exited 1" },
    });
    expect(out[0]).toMatch(/^ {2}WARNING: Castle Wall is ARMED/);
    expect(out[0]).toMatch(/sudo sanctuary castle-wall disable/);
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
    expect(out[0]).toMatch(/No dedicated account was created and nothing was moved/);
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

  it("FIX R4-2: a pre-create neutral abort (accountCreated falsy) DOES say 'No dedicated account was created'", () => {
    const out = lines({
      ran: true,
      outcome: { kind: "aborted", stage: "root-check", reason: "requires root", rolledBack: false, rehomeAttempted: false },
    });
    expect(out[0]).toMatch(/No dedicated account was created and nothing was moved/);
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
