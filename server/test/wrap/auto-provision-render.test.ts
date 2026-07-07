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
});
