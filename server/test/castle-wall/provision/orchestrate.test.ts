/**
 * Tests for the one-flow orchestration (fold of the target flow's steps 1
 * through 11, folded fixes B2/H1/H3/H4/L2): every fail-closed branch is
 * driven purely through injected ops, so this exercises the FULL corrected
 * sequencing without touching a real host, TTY, or privileged binary.
 */

import { describe, it, expect, vi } from "vitest";

import { runProvisionFlow, type ProvisionFlowContext, type ProvisionFlowOps } from "../../../src/castle-wall/provision/orchestrate.js";
import type { ProvisionNeedResult } from "../../../src/castle-wall/provision/detect.js";
import type { RehomeStepResult } from "../../../src/castle-wall/provision/rehome.js";

const CEILING = 500;
const AGENT_UID = 502;

const NEEDS_PROVISIONING: ProvisionNeedResult = {
  needsProvisioning: true,
  alreadyDedicated: false,
  reason: "shared account",
};

const ALREADY_DEDICATED: ProvisionNeedResult = {
  needsProvisioning: false,
  alreadyDedicated: true,
  resolved: { uid: AGENT_UID, source: "harness-config" },
  reason: "already dedicated",
};

const REHOME_RESULTS: RehomeStepResult[] = [
  {
    entry: { sourcePath: "/Users/operator/.hermes/.env", destRelativePath: ".hermes/.env", isSecret: true },
    destPath: "/var/sanctuary-agents/sanctuary-hermes/.hermes/.env",
    status: "moved",
    backupPath: "/root/backup/.hermes/.env.bak",
  },
];

const FORTRESS_PATH = "/Users/operator/.sanctuary";

/** Minimal harness endpoint set for the confined-agent egress steps. */
const TEST_ENDPOINT_SET = {
  harnessId: "hermes",
  endpoints: [
    {
      name: "LLM (Venice)",
      host: "api.venice.ai",
      port: 443,
      protocol: "tcp" as const,
      riskClass: "standard" as const,
    },
  ],
};

function baseCtx(overrides: Partial<ProvisionFlowContext> = {}): ProvisionFlowContext {
  return {
    agentId: "hermes",
    accountName: "sanctuary-hermes",
    ceiling: CEILING,
    detectResult: NEEDS_PROVISIONING,
    isTty: true,
    fortressPath: FORTRESS_PATH,
    harnessEndpoints: TEST_ENDPOINT_SET,
    ...overrides,
  };
}

/** A passing as-uid egress report matching TEST_ENDPOINT_SET + the negative control. */
function passingEgressReport() {
  return {
    ok: true,
    rows: [
      {
        name: "LLM (Venice)",
        host: "api.venice.ai",
        port: 443,
        expected: "reachable" as const,
        observed: "reachable" as const,
        pass: true,
      },
      {
        name: "negative control (non-listed host must be blocked)",
        host: "example.com",
        port: 443,
        expected: "blocked" as const,
        observed: "blocked" as const,
        pass: true,
      },
    ],
  };
}

function happyPathOps(overrides: Partial<ProvisionFlowOps> = {}): ProvisionFlowOps {
  return {
    confirm: vi.fn(async () => true),
    print: vi.fn(),
    provisionEgress: vi.fn(async () => ({
      ok: true as const,
      ruleIds: ["provisioned-hermes-abc123def456"],
      checks: [{ name: "LLM (Venice)", host: "api.venice.ai", port: 443, allowed: true }],
      dnsRulePresent: true,
    })),
    scrubProvisionedEgress: vi.fn(async () => undefined),
    verifyAgentEgressAfterArm: vi.fn(async () => passingEgressReport()),
    auditEgress: vi.fn(async () => undefined),
    createAccount: vi.fn(async () => ({
      plan: { action: "create", accountName: "sanctuary-hermes", uid: AGENT_UID },
      uid: AGENT_UID,
    })),
    rehome: vi.fn(async () => ({
      plan: { harnessId: "hermes", steps: [], requiresInteractiveReconsent: false },
      results: REHOME_RESULTS,
    })),
    installHarnessDaemon: vi.fn(async () => ({ ok: true as const, bootstrappedThisRun: true })),
    uninstallHarnessDaemon: vi.fn(async () => undefined),
    // The common case the chokepoint exists for: a RUNNING agent was stood
    // down and was verifiably restarted. `harnessRestarted` is the field the
    // fix-round-2 wording keys on -- the production op used to discard it, so
    // a stopped agent read as "was restarted".
    restoreStoodDownHarness: vi.fn(async () => ({
      restored: true,
      wasRunning: true,
      harnessRestarted: true,
      problems: [] as string[],
    })),
    ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: false })),
    teardownPolicyDaemon: vi.fn(async () => undefined),
    preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => true }]),
    checkUidExistence: vi.fn(async () => ({ ok: true, accountName: "sanctuary-hermes", uid: AGENT_UID })),
    arm: vi.fn(async () => ({ ok: true as const })),
    postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => true }]),
    disarm: vi.fn(async () => ({ neConfirmedOff: true as const })),
    restoreRehome: vi.fn(async () => ({
      fullyRestored: true,
      restoredCount: REHOME_RESULTS.length,
      attemptedCount: REHOME_RESULTS.length,
      backupPaths: REHOME_RESULTS.filter((r) => r.backupPath).map((r) => r.backupPath!),
      conflictPaths: [],
    })),
    ...overrides,
  };
}

describe("castle-wall/provision/orchestrate", () => {
  it("happy path: runs every step in order and arms", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
    expect(ops.createAccount).toHaveBeenCalledTimes(1);
    expect(ops.rehome).toHaveBeenCalledWith(AGENT_UID, AGENT_UID);
    expect(ops.installHarnessDaemon).toHaveBeenCalledWith(AGENT_UID);
    expect(ops.checkUidExistence).toHaveBeenCalledWith(AGENT_UID);
    expect(ops.arm).toHaveBeenCalledWith(AGENT_UID, CEILING);
    expect(ops.disarm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).not.toHaveBeenCalled();
  });

  it("fix F6: already-dedicated (VERIFIED) skips ONLY create + re-home, but still reaches daemon-install, verify, uid-gate, and arm", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    // Fix F6: this must NEVER short-circuit to a bare "skipped" outcome --
    // it must actually reach arm, exactly like the fresh-provision path.
    expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
    expect(ops.createAccount).not.toHaveBeenCalled();
    expect(ops.rehome).not.toHaveBeenCalled();
    // FIX R4 (HIGH, 2026-07-07 fix-round 2): arming IS a privileged mutation
    // on the already-dedicated path too, so the confirm ceremony MUST still
    // run here -- the F6 fix's removal of the "skip straight to done" defect
    // must not itself skip the confirm gate.
    expect(ops.confirm).toHaveBeenCalledTimes(1);
    // But daemon-install, verify, uid-gate, and arm ALL still ran.
    expect(ops.installHarnessDaemon).toHaveBeenCalledWith(AGENT_UID);
    expect(ops.checkUidExistence).toHaveBeenCalledWith(AGENT_UID);
    expect(ops.arm).toHaveBeenCalledWith(AGENT_UID, CEILING);
  });

  it("fix R4: already-dedicated on a non-TTY run refuses (no confirm ceremony possible) rather than arming silently", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED, isTty: false }), ops);
    expect(result.kind).toBe("skipped-non-tty-cooperative-only");
    expect(ops.confirm).not.toHaveBeenCalled();
    expect(ops.installHarnessDaemon).not.toHaveBeenCalled();
    expect(ops.arm).not.toHaveBeenCalled();
  });

  it("fix R4: already-dedicated with the interactive confirm declined stops before arming", async () => {
    const ops = happyPathOps({ confirm: vi.fn(async () => false) });
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    expect(result.kind).toBe("declined-by-operator");
    expect(ops.installHarnessDaemon).not.toHaveBeenCalled();
    expect(ops.arm).not.toHaveBeenCalled();
  });

  it("fix F6: an already-dedicated abort mid-flow (e.g. daemon-install fails) does not attempt a restore (nothing was re-homed this run)", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => ({ ok: false as const, error: "launchctl bootstrap exited 5", daemonPreexisted: false })),
    });
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon" });
    // restoreRehome IS still called (with an empty array) so the reported
    // rolledBack is trivially/honestly true; nothing was actually moved.
    expect(ops.restoreRehome).toHaveBeenCalledWith([]);
  });

  it("fix H4: non-TTY skips provisioning (cooperative-wrap-only) WITHOUT ever confirming or mutating", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ isTty: false }), ops);
    expect(result.kind).toBe("skipped-non-tty-cooperative-only");
    expect(ops.confirm).not.toHaveBeenCalled();
    expect(ops.createAccount).not.toHaveBeenCalled();
  });

  it("fix L2: a pre-answered decline (--provision-agent-account not passed / declined) stops before the confirm prompt", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ preAnsweredProvision: false }), ops);
    expect(result.kind).toBe("declined-by-operator");
    expect(ops.confirm).not.toHaveBeenCalled();
    expect(ops.createAccount).not.toHaveBeenCalled();
  });

  it("fix L2: a pre-answered accept STILL shows the confirm prompt (pre-answers the choice only, not the mutation gate)", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ preAnsweredProvision: true }), ops);
    expect(result.kind).toBe("armed");
    expect(ops.confirm).toHaveBeenCalledTimes(1);
  });

  it("operator declines the interactive confirm: stops before any mutation", async () => {
    const ops = happyPathOps({ confirm: vi.fn(async () => false) });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result.kind).toBe("declined-by-operator");
    expect(ops.createAccount).not.toHaveBeenCalled();
  });

  it("fail-closed: account creation failure aborts before re-home, no rollback needed (nothing moved yet)", async () => {
    const ops = happyPathOps({
      createAccount: vi.fn(async () => {
        throw new Error("sysadminctl exit 1");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "create-account", rolledBack: false });
    expect(ops.rehome).not.toHaveBeenCalled();
  });

  it("fail-closed: re-home failure aborts, no daemon install attempted", async () => {
    const ops = happyPathOps({
      rehome: vi.fn(async () => {
        // A PLAIN (non-RehomeExecutionError) throw means nothing moved yet
        // (in production the only plain-error path is the pre-move base-dir
        // setup; a post-move failure re-throws RehomeExecutionError carrying
        // the moved results). FIX (round 5, N7): nothing moved = trivially
        // rolled back, so rolledBack is true here -- the pre-fix code forced
        // false and produced a spurious "restore FAILED / do not re-run" alarm.
        throw new Error("could not normalize the agent-home base directory");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "rehome", rolledBack: true });
    expect(ops.installHarnessDaemon).not.toHaveBeenCalled();
    // FIX (round 5, R3-2): nothing moved -> rehomeAttempted:false so the CLI
    // shows the neutral "nothing changed" frame, not a restore claim/alarm.
    expect((result as { rehomeAttempted?: boolean }).rehomeAttempted).toBe(false);
  });

  it("FIX (round 5, R3-2): a create-account abort reports rehomeAttempted:false (no account, nothing moved -> neutral CLI frame, not a false 'restore FAILED')", async () => {
    const ops = happyPathOps({
      createAccount: vi.fn(async () => {
        throw new Error("sysadminctl -addUser failed");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "create-account", rehomeAttempted: false });
    expect(ops.rehome).not.toHaveBeenCalled();
  });

  it("FIX (round 5, R3-2): a post-install abort AFTER a real re-home reports rehomeAttempted:true (there ARE moved paths to reason about)", async () => {
    const ops = happyPathOps({
      preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm", rehomeAttempted: true });
  });

  it("FIX (round 5, R3-3): armed-rollback-failed reason does NOT claim 'Fast-disarmed' (the disarm failed); armed-then-rolled-back DOES", async () => {
    const failOps = happyPathOps({
      postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
      disarm: vi.fn(async () => {
        throw new Error("castle-wall disable exited 1");
      }),
    });
    const failResult = await runProvisionFlow(baseCtx(), failOps);
    expect(failResult).toMatchObject({ kind: "armed-rollback-failed", uid: AGENT_UID });
    expect((failResult as { reason: string }).reason).not.toMatch(/Fast-disarmed/);

    const okOps = happyPathOps({
      postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
    });
    const okResult = await runProvisionFlow(baseCtx(), okOps);
    expect(okResult).toMatchObject({ kind: "armed-then-rolled-back", uid: AGENT_UID });
    expect((okResult as { reason: string }).reason).toMatch(/Fast-disarmed rather than leave a bricked agent/);
  });

  it("fail-closed: daemon install failure restores the backup and aborts before verify/arm", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => ({ ok: false as const, error: "launchctl bootstrap exited 5", daemonPreexisted: false })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon", rolledBack: true });
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
    expect(ops.checkUidExistence).not.toHaveBeenCalled();
    expect(ops.arm).not.toHaveBeenCalled();
  });

  it("fix B2 ordering: pre-arm verify runs AFTER daemon install, and failure restores + STOPS before arming", async () => {
    const callOrder: string[] = [];
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => {
        callOrder.push("install-daemon");
        return { ok: true as const, bootstrappedThisRun: true };
      }),
      preArmEndpoints: vi.fn(() => {
        callOrder.push("pre-arm-verify");
        return [{ name: "Gmail", probe: async () => false }];
      }),
      arm: vi.fn(async () => {
        callOrder.push("arm");
        return { ok: true as const };
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm", rolledBack: true });
    expect(callOrder).toEqual(["install-daemon", "pre-arm-verify"]);
    expect(ops.arm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("fix H1: uid-existence-gate failure (account missing/mismatched) aborts before arm, with restore", async () => {
    const ops = happyPathOps({
      checkUidExistence: vi.fn(async () => ({
        ok: false,
        accountName: "sanctuary-hermes",
        reason: "account does not exist",
      })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "uid-existence-gate", rolledBack: true });
    expect(ops.arm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("arm failure (the shipped enable path refuses) aborts with restore", async () => {
    const ops = happyPathOps({
      arm: vi.fn(async () => ({ ok: false as const, error: "no agent-origin descriptor" })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "arm", rolledBack: true });
    expect(ops.disarm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("fix B2 rollback: post-arm verify failure fast-disarms rather than restoring re-home (agent stays re-homed, wall comes down)", async () => {
    const ops = happyPathOps({
      postArmEndpoints: vi.fn(() => [{ name: "Gmail", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "armed-then-rolled-back", uid: AGENT_UID });
    expect(ops.disarm).toHaveBeenCalledTimes(1);
    // Post-arm rollback is a fast DISARM, not a re-home restore: the agent
    // stays on its dedicated, re-homed account; only enforcement comes down.
    expect(ops.restoreRehome).not.toHaveBeenCalled();
    // FIX (round 5, item c): the reason must be HONEST about what the post-arm
    // re-check can and cannot prove (DNS-resolvability + credential readability,
    // NOT allow-list correctness), so it must not assert "the allow-list blocks".
    const reason = (result as { reason: string }).reason;
    expect(reason).not.toMatch(/allow-list blocks/);
    expect(reason).toMatch(/post-arm connectivity re-check failed/);
    expect(reason).toMatch(/not allow-list correctness/);
    // Post-arm rollback leaves the daemon running (agent stays re-homed); the
    // daemon is only torn down on PRE-arm aborts (N3).
    expect(ops.uninstallHarnessDaemon).not.toHaveBeenCalled();
  });

  it("FIX (round 5, N3): a verify-before-arm abort tears the LIVE harness daemon down (not just restore re-home) before reporting the abort", async () => {
    const ops = happyPathOps({
      preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm", rolledBack: true });
    // The daemon was bootstrapped by install-daemon and MUST be torn down on
    // this fail-closed abort, or a live root LaunchDaemon is left running
    // under the dedicated account while the flow reports a clean rollback.
    expect(ops.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("FIX (round 5, N3): the uid-existence-gate and arm aborts also tear the daemon down", async () => {
    const uidGateOps = happyPathOps({
      checkUidExistence: vi.fn(async () => ({ ok: false as const, accountName: "sanctuary-hermes", reason: "account does not exist" })),
    });
    await runProvisionFlow(baseCtx(), uidGateOps);
    expect(uidGateOps.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);

    const armOps = happyPathOps({
      arm: vi.fn(async () => ({ ok: false as const, error: "no agent-origin descriptor" })),
    });
    await runProvisionFlow(baseCtx(), armOps);
    expect(armOps.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);
  });

  it("FIX (round 5, N3): a FAILED daemon teardown on abort is surfaced LOUDLY in the reason (never silently swallowed)", async () => {
    const ops = happyPathOps({
      preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
      uninstallHarnessDaemon: vi.fn(async () => {
        throw new Error("launchctl bootout failed: Operation not permitted");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm" });
    const reason = (result as { reason: string }).reason;
    expect(reason).toMatch(/could NOT be torn down automatically/);
    expect(reason).toMatch(/launchctl bootout failed: Operation not permitted/);
    // A teardown failure must not prevent the re-home restore from being attempted.
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("FIX (round 5, N7): a rehome failure BEFORE any move (empty partialResults) reports rolledBack:true (nothing moved = trivially rolled back), not a false 'restore FAILED'", async () => {
    const { RehomeExecutionError } = await import("../../../src/castle-wall/provision/rehome.js");
    const ops = happyPathOps({
      rehome: vi.fn(async () => {
        throw new RehomeExecutionError("backup destination not root-only writable", []);
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    // The pre-fix code special-cased empty partialResults to rolledBack:false,
    // producing a false "restore FAILED / do not re-run" warning when nothing
    // was ever moved. Nothing moved = trivially rolled back.
    expect(result).toMatchObject({ kind: "aborted", stage: "rehome", rolledBack: true });
    // No daemon was installed yet at the rehome stage, so it is not torn down here.
    expect(ops.uninstallHarnessDaemon).not.toHaveBeenCalled();
  });

  it("FIX G1 (re-gate 3): a non-throwing-but-nonzero disarm, wired through the REAL disarmExitCodeDecision chokepoint, yields armed-rollback-failed -- never armed-then-rolled-back", async () => {
    // This wires the mock `disarm` op the SAME way `wrap/auto-provision.ts`'s
    // real closure does: call the injected "runDisable", get back a number
    // (never a throw from runDisable itself), run it through the real,
    // exported `throwIfDisarmFailed`-equivalent chokepoint decision, and
    // throw only if that decision says so. Before the G1 fix, the
    // production closure never made this call at all -- it discarded the
    // code -- so this test proves the WIRED-UP real decision logic, not a
    // hand-rolled throw, is what routes this outcome.
    const { disarmExitCodeDecision } = await import("../../../src/wrap/auto-provision.js");
    const runDisableThatFailsWithoutThrowing = async (): Promise<number> => 1;
    const ops = happyPathOps({
      postArmEndpoints: vi.fn(() => [{ name: "Gmail", probe: async () => false }]),
      disarm: vi.fn(async () => {
        const code = await runDisableThatFailsWithoutThrowing();
        const err = disarmExitCodeDecision(code);
        if (err !== undefined) {
          throw err;
        }
        return { neConfirmedOff: true };
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({
      kind: "armed-rollback-failed",
      uid: AGENT_UID,
      disarmError: "castle-wall disable exited 1",
    });
    expect(ops.disarm).toHaveBeenCalledTimes(1);
  });

  it("fix F1 (BLOCKER): an empty pre-arm endpoint list REFUSES to arm (fail-closed, not vacuous-true)", async () => {
    const ops = happyPathOps({
      preArmEndpoints: vi.fn(() => []),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm", rolledBack: true });
    expect(ops.arm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("fix F1 (BLOCKER): an empty post-arm endpoint list fast-disarms rather than reporting a clean arm", async () => {
    const ops = happyPathOps({
      postArmEndpoints: vi.fn(() => []),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "armed-then-rolled-back", uid: AGENT_UID });
    expect(ops.disarm).toHaveBeenCalledTimes(1);
  });

  it("a restore failure during rollback does not mask the original abort reason, and reports rolledBack: false honestly (fix F2/F5)", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => ({ ok: false as const, error: "launchctl bootstrap exited 5", daemonPreexisted: false })),
      restoreRehome: vi.fn(async () => {
        throw new Error("restore also failed");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    // FIX F2/F5: a restore that THROWS is a failed restore, not a hardcoded
    // clean rollback -- rolledBack must be false, never true, and the
    // ORIGINAL abort reason (the daemon-install failure) must still survive.
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon", rolledBack: false });
    if (result.kind === "aborted") {
      expect(result.reason).toMatch(/launchctl bootstrap exited 5/);
    }
  });

  it("fix F2/F5: a PARTIAL restore (some but not all paths recovered) reports rolledBack: 'partial', not a clean true", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => ({ ok: false as const, error: "launchctl bootstrap exited 5", daemonPreexisted: false })),
      restoreRehome: vi.fn(async () => ({
        fullyRestored: false,
        restoredCount: 1,
        attemptedCount: 2,
        backupPaths: ["/root/backup/.hermes/.env.bak"],
        conflictPaths: [],
      })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon", rolledBack: "partial" });
    if (result.kind === "aborted") {
      expect(result.backupPaths).toEqual(["/root/backup/.hermes/.env.bak"]);
    }
  });

  it("FIX (round 5, R5-2): a post-install abort whose restore hit an R6 CONFLICT carries conflictPaths onto the outcome (so the CLI surfaces it, not a false 'restore FAILED')", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => ({ ok: false as const, error: "launchctl bootstrap exited 5", daemonPreexisted: false })),
      restoreRehome: vi.fn(async () => ({
        fullyRestored: false,
        restoredCount: 0,
        attemptedCount: 1,
        backupPaths: ["/root/backup/.hermes/.env.bak"],
        conflictPaths: ["/Users/operator/.hermes/.env.restored-conflict"],
      })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon" });
    expect((result as { conflictPaths?: string[] }).conflictPaths).toEqual([
      "/Users/operator/.hermes/.env.restored-conflict",
    ]);
  });

  it("FIX (round 5, R5-3): an abort where every re-home entry was skipped-absent reports rehomeAttempted:false (nothing MOVED, so no false 'restored' claim)", async () => {
    const ops = happyPathOps({
      rehome: vi.fn(async () => ({
        plan: { harnessId: "hermes", steps: [], requiresInteractiveReconsent: false },
        results: [
          {
            entry: { sourcePath: "/Users/op/.hermes/.env", destRelativePath: ".hermes/.env", isSecret: true },
            destPath: "/var/sanctuary-agents/sanctuary-hermes/.hermes/.env",
            status: "skipped-absent" as const,
          },
        ],
      })),
      checkUidExistence: vi.fn(async () => ({ ok: false as const, accountName: "sanctuary-hermes", reason: "account does not exist" })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "uid-existence-gate", rehomeAttempted: false });
  });

  it("FIX (round 5, R6-3): an abort does NOT tear down a daemon that GENUINELY PRE-EXISTED (installHarnessDaemon reports bootstrappedThisRun:false) -- booting out working infrastructure over a transient failure would be destructive", async () => {
    const ops = happyPathOps({
      // The daemon was already loaded -> this run bootstrapped nothing.
      installHarnessDaemon: vi.fn(async () => ({ ok: true as const, bootstrappedThisRun: false })),
      preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm" });
    expect(ops.uninstallHarnessDaemon).not.toHaveBeenCalled();
  });

  it("FIX (round 5, R7-1): an alreadyDedicated abort DOES tear the daemon down when THIS RUN bootstrapped it (bootstrappedThisRun:true) -- a fresh daemon on the alreadyDedicated path must not be stranded", async () => {
    const ops = happyPathOps({
      // alreadyDedicated (account shape verified) but the daemon did NOT
      // pre-exist -- this run stood it up (e.g. a prior run created the account
      // then failed at install-daemon; account persists, daemon did not).
      installHarnessDaemon: vi.fn(async () => ({ ok: true as const, bootstrappedThisRun: true })),
      preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm" });
    // The freshly-installed daemon MUST be torn down (not stranded with a
    // false "nothing was changed" all-clear).
    expect(ops.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);
  });

  it("FIX (round 5, R8-1): an install-daemon FAILURE that left a FRESH daemon live (daemonPreexisted:false) tears it down -- even on the alreadyDedicated path", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => ({
        ok: false as const,
        error: "launchctl bootstrap exited 5 (service left live)",
        daemonPreexisted: false,
      })),
    });
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon" });
    // The fresh daemon this attempt left live MUST be torn down (the pre-R8-1
    // !alreadyDedicated heuristic stranded it here).
    expect(ops.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);
  });

  it("FIX (round 5, R8-1): an install-daemon FAILURE over a genuinely PRE-EXISTING daemon (daemonPreexisted:true) does NOT tear it down (R6-3 preserve)", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => ({
        ok: false as const,
        error: "plist refresh writeFile failed",
        daemonPreexisted: true,
      })),
    });
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon" });
    expect(ops.uninstallHarnessDaemon).not.toHaveBeenCalled();
  });

  it("FIX (round 5, R6-4): the verify-before-arm abort reason is honest (no 're-homed agent could not reach' overclaim -- matches the post-arm phrasing)", async () => {
    const ops = happyPathOps({
      preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm" });
    const reason = (result as { reason: string }).reason;
    expect(reason).not.toMatch(/re-homed agent could not reach/);
    expect(reason).toMatch(/pre-arm check could not confirm DNS-resolvability/);
  });

  it("FIX (round 5, R7-2): a fresh provision that re-homed ZERO secrets fails the pre-arm verify (the synthetic guard probe), never arming with a vacuous credential gate", async () => {
    // Real probe wiring is exercised by the realops seam; here drive the
    // orchestrator with an empty pre-arm list shape via a false guard probe to
    // confirm the flow aborts at verify-before-arm rather than arming.
    const ops = happyPathOps({
      preArmEndpoints: vi.fn(() => [{ name: "no credential was re-homed onto the account (nothing to confine)", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm" });
    expect(ops.arm).not.toHaveBeenCalled();
  });

  it("FIX (round 5, R7-3): a verify-before-arm abort whose restore hit a CONFLICT-only outcome does NOT say 'restore FAILED' in its reason (matches the R5-2 conflict-safe render)", async () => {
    const ops = happyPathOps({
      preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
      restoreRehome: vi.fn(async () => ({
        fullyRestored: false,
        restoredCount: 0,
        attemptedCount: 1,
        backupPaths: ["/root/backup/.hermes/.env.bak"],
        conflictPaths: ["/Users/op/.hermes/.env.restored-conflict"],
        failedPaths: [],
      })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    const reason = (result as { reason: string }).reason;
    expect(reason).not.toMatch(/restore FAILED/);
    expect(reason).toMatch(/left intact|reconcile/i);
  });

  // ── Bug B (the one-flow gap): ensure a policy daemon before arming ──────────
  describe("Bug B: ensurePolicyDaemon step (single-wall-per-machine, refuse-not-swap)", () => {
    it("happy path calls ensurePolicyDaemon with ctx.fortressPath BEFORE the harness install and before arm, still arms, tears down nothing", async () => {
      const ops = happyPathOps();
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
      expect(ops.ensurePolicyDaemon).toHaveBeenCalledWith(FORTRESS_PATH);
      // ORDER CHANGE (drill-D2 fix-round, 2026-07-18): the policy daemon is
      // now ensured BEFORE the harness install, not after it. In fine-grained
      // mode the harness install STOPS the operator's live agent, and this
      // step -- the one-wall-per-machine refusal -- is the flow's most likely
      // refusal and the one the 2026-07-18 drill actually hit. Refusing after
      // the destructive step left the agent dead; refusing before it costs
      // nothing. Still strictly before arming, which is the constraint this
      // step originally existed for (arming with no policy daemon deny-all-
      // locks the box).
      const ensureOrder = (ops.ensurePolicyDaemon as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      const installOrder = (ops.installHarnessDaemon as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      const armOrder = (ops.arm as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      expect(ensureOrder).toBeLessThan(installOrder);
      expect(ensureOrder).toBeLessThan(armOrder);
      expect(ops.teardownPolicyDaemon).not.toHaveBeenCalled();
    });

    it("a FRESH install (freshlyInstalled:true) still arms and tears down nothing on success", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
      expect(ops.teardownPolicyDaemon).not.toHaveBeenCalled();
    });

    it("REFUSES a different-fortress wall (ok:false, freshlyInstalled:false): aborts at ensure-policy-daemon, never arms, tears the HARNESS daemon down, leaves the existing wall untouched, restores the re-home", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({
          ok: false as const,
          error:
            "a Castle Wall is already installed for a different fortress; one machine runs one wall -- arming would replace it.",
          freshlyInstalled: false,
        })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "ensure-policy-daemon", rolledBack: true });
      expect(ops.arm).not.toHaveBeenCalled();
      // ORDER CHANGE: the harness is never installed OR stood down on this
      // path any more, because this refusal now happens first. That is the
      // whole point -- the 2026-07-18 drill hit exactly this refusal, and
      // post-D2-fix it would have left the operator's agent stopped with
      // nothing to restart it. There is now nothing to tear down or restore.
      expect(ops.installHarnessDaemon).not.toHaveBeenCalled();
      expect(ops.uninstallHarnessDaemon).not.toHaveBeenCalled();
      expect(ops.restoreStoodDownHarness).not.toHaveBeenCalled();
      expect(ops.teardownPolicyDaemon).not.toHaveBeenCalled();
      expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
      expect((result as { reason: string }).reason).toMatch(/different fortress/);
    });

    it("an abort AFTER a fresh install (verify-before-arm) tears BOTH the harness daemon AND the fresh policy daemon back down (restores the prior 'no wall' state)", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
        preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm" });
      expect(ops.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);
      expect(ops.teardownPolicyDaemon).toHaveBeenCalledTimes(1);
    });

    it("an abort after an ALREADY-reachable policy daemon (freshlyInstalled:false) tears the harness daemon down but LEAVES the pre-existing wall untouched", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: false })),
        preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm" });
      expect(ops.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);
      // Booting out a wall this run did NOT install would be destructive.
      expect(ops.teardownPolicyDaemon).not.toHaveBeenCalled();
    });

    it("ensurePolicyDaemon failing AFTER standing up a fresh daemon (ok:false, freshlyInstalled:true) tears that fresh daemon back down on the abort", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({
          ok: false as const,
          error: "the policy daemon was installed but its socket never became reachable within 10s; not arming.",
          freshlyInstalled: true,
        })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "ensure-policy-daemon" });
      expect(ops.arm).not.toHaveBeenCalled();
      expect(ops.teardownPolicyDaemon).toHaveBeenCalledTimes(1);
      // Reordered: no harness was installed yet, so there is nothing to tear
      // down -- only the fresh wall this run stood up.
      expect(ops.uninstallHarnessDaemon).not.toHaveBeenCalled();
    });

    it("a FAILED policy-daemon teardown on abort is surfaced LOUDLY (daemonTeardownFailed + a manual uninstall-boot note), never silently swallowed", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
        preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
        teardownPolicyDaemon: vi.fn(async () => {
          throw new Error("launchctl bootout failed: Operation not permitted");
        }),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm", daemonTeardownFailed: true });
      const reason = (result as { reason: string }).reason;
      expect(reason).toMatch(/uninstall-boot --yes/);
      expect(reason).toMatch(/launchctl bootout failed: Operation not permitted/);
      // A teardown failure never prevents the re-home restore.
      expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
    });

    it("a fresh policy daemon is torn back down when the LATER harness install fails (it now runs first, so its rollback must reach this branch)", async () => {
      // The mirror of the old "ensurePolicyDaemon is strictly downstream of
      // install-daemon" test. Reversing the order moved the rollback
      // obligation with it: install-daemon aborting must now undo the wall
      // this run stood up, which it did not have to before.
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
        installHarnessDaemon: vi.fn(async () => ({
          ok: false as const,
          error: "launchctl bootstrap exited 5",
          daemonPreexisted: false,
        })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon" });
      expect(ops.ensurePolicyDaemon).toHaveBeenCalledTimes(1);
      expect(ops.teardownPolicyDaemon).toHaveBeenCalledTimes(1);
      expect(ops.arm).not.toHaveBeenCalled();
    });

    it("a PRE-EXISTING wall is still never torn down when the later harness install fails", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: false })),
        installHarnessDaemon: vi.fn(async () => ({
          ok: false as const,
          error: "launchctl bootstrap exited 5",
          daemonPreexisted: false,
        })),
      });
      await runProvisionFlow(baseCtx(), ops);
      expect(ops.teardownPolicyDaemon).not.toHaveBeenCalled();
    });

    // ── P0 (disarm-first ordering on the arm-STAGE abort) ─────────────────────
    // `arm` returning ok:false does NOT imply the content filter is off (macOS
    // Tahoe can SAVE the NE config ENABLED then report non-zero). Booting a
    // FRESHLY-INSTALLED policy daemon out in that state = filter-on/daemon-down
    // = deny-all lockout. So we DISARM FIRST, and only tear the fresh daemon
    // down once disarm confirms the filter is off.
    it("P0: arm ok:false with a FRESHLY-INSTALLED daemon disarms FIRST, THEN tears the policy daemon down (order: filter-off before daemon-down)", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "arm" });
      // Disarm was attempted and succeeded, so the fresh daemon IS torn down...
      expect(ops.disarm).toHaveBeenCalledTimes(1);
      expect(ops.teardownPolicyDaemon).toHaveBeenCalledTimes(1);
      // ...and STRICTLY in filter-off-THEN-daemon-down order.
      const disarmOrder = (ops.disarm as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      const teardownOrder = (ops.teardownPolicyDaemon as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      expect(disarmOrder).toBeLessThan(teardownOrder);
      // A confirmed disarm is not flagged "may be armed", but the outcome is NOT
      // a bare clean rollback -- it records that the wall was disarmed and tells
      // the operator to confirm with `status`.
      expect((result as { wallMayBeArmed?: boolean }).wallMayBeArmed).toBeUndefined();
      expect((result as { reason: string }).reason).toMatch(/disarmed as part of this rollback|castle-wall status/i);
    });

    it("P0 honesty gap: arm ok:false + fresh daemon + disarm THROWS leaves the policy daemon UP (never boots it out into a lockout), sets wallMayBeArmed, and is NOT a clean rollback", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        // Disarm cannot confirm the filter is off (e.g. Tahoe corroboration
        // affirmatively still shows enabled, or the disable save itself failed).
        disarm: vi.fn(async () => {
          throw new Error("castle-wall disable exited 1");
        }),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "arm", wallMayBeArmed: true });
      expect(ops.disarm).toHaveBeenCalledTimes(1);
      // CRITICAL: the freshly-installed policy daemon is LEFT RUNNING -- booting
      // it out with the filter possibly ON is the exact deny-all lockout.
      expect(ops.teardownPolicyDaemon).not.toHaveBeenCalled();
      // The harness daemon (not the wall) is still torn down normally.
      expect(ops.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);
      const reason = (result as { reason: string }).reason;
      expect(reason).toMatch(/MAY STILL BE ARMED/);
      expect(reason).toMatch(/castle-wall disable/);
    });

    it("P1 (fail-open-after-lease-revoke): arm ok:false + fresh daemon + disarm returns neConfirmedOff:FALSE leaves the daemon UP (never a reboot-brick) + sets wallMayBeArmed, even though disarm did NOT throw", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        // Disarm did NOT throw (it succeeded as a dead-man lever, fail-open),
        // but the NE preference was NOT confirmed off -- the exact P1 sub-case.
        disarm: vi.fn(async () => ({ neConfirmedOff: false })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "arm", wallMayBeArmed: true });
      expect(ops.disarm).toHaveBeenCalledTimes(1);
      // CRITICAL: a non-throwing-but-not-confirmed disarm must NOT tear the fresh
      // daemon down -- removing it while the NE preference may still be enabled
      // risks a reboot-brick (provider up enabled + no daemon = deny-all).
      expect(ops.teardownPolicyDaemon).not.toHaveBeenCalled();
      const reason = (result as { reason: string }).reason;
      expect(reason).toMatch(/MAY STILL BE ARMED/);
      expect(reason).toMatch(/fail-open after lease revoke/);
      expect(reason).toMatch(/castle-wall disable/);
    });

    it("P0: the disarm-first guard is scoped to a FRESH install -- an arm ok:false over an ALREADY-reachable (freshlyInstalled:false) wall does NOT disarm and does NOT tear the wall down", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: false })),
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "arm" });
      // Nothing this run stood up -> no disarm, no wall teardown (leaving the
      // pre-existing wall untouched; filter-on + daemon-up is recoverable).
      expect(ops.disarm).not.toHaveBeenCalled();
      expect(ops.teardownPolicyDaemon).not.toHaveBeenCalled();
      expect((result as { wallMayBeArmed?: boolean }).wallMayBeArmed).toBeUndefined();
    });
  });

  // ── Confined-agent egress (design 2026-07-10): provision-egress step,
  //    refuse-to-arm, post-arm as-uid verify, scrub, audit ops ──────────────
  describe("confined-agent egress: provision + verify + refuse-to-arm", () => {
    it("happy path: provisionEgress runs AFTER ensure-policy-daemon and BEFORE arm; as-uid verify runs AFTER arm; egress_provisioned is audited with the rule ids", async () => {
      const ops = happyPathOps();
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
      const order = (fn: unknown) => (fn as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      expect(order(ops.ensurePolicyDaemon)).toBeLessThan(order(ops.provisionEgress));
      expect(order(ops.provisionEgress)).toBeLessThan(order(ops.arm));
      expect(order(ops.arm)).toBeLessThan(order(ops.verifyAgentEgressAfterArm));
      expect(ops.verifyAgentEgressAfterArm).toHaveBeenCalledWith(AGENT_UID);
      expect(ops.auditEgress).toHaveBeenCalledTimes(1);
      expect(ops.auditEgress).toHaveBeenCalledWith(
        "egress_provisioned",
        expect.objectContaining({
          harness: "hermes",
          agent_uid: AGENT_UID,
          rule_ids: ["provisioned-hermes-abc123def456"],
        }),
      );
      expect(ops.scrubProvisionedEgress).not.toHaveBeenCalled();
    });

    it("refuse-to-arm (fail-closed): provisionEgress ok:false aborts at 'provision-egress' BEFORE arm, scrubs any partial publish, and audits egress_provision_refused", async () => {
      const ops = happyPathOps({
        provisionEgress: vi.fn(async () => ({
          ok: false as const,
          error: "static egress verification failed: no allow match for LLM (Venice)",
          checks: [{ name: "LLM (Venice)", host: "api.venice.ai", port: 443, allowed: false }],
          dnsRulePresent: true,
        })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "provision-egress", rolledBack: true });
      expect(ops.arm).not.toHaveBeenCalled();
      // A partial publish must never survive a refused run (no orphan grants).
      expect(ops.scrubProvisionedEgress).toHaveBeenCalledTimes(1);
      expect(ops.auditEgress).toHaveBeenCalledWith(
        "egress_provision_refused",
        expect.objectContaining({ stage: "provision-egress", disarm_outcome: "not-armed" }),
      );
      const reason = (result as { reason: string }).reason;
      // The operator sees the refusal named as fail-closed (the wall was NOT
      // armed over a non-functional agent) and what failed.
      expect(reason).toMatch(/refusing to arm/i);
      expect(reason).toMatch(/could not be provisioned and verified/);
      // The per-endpoint table was printed.
      const printed = (ops.print as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
      expect(printed.some((line) => /\[FAIL\] LLM \(Venice\)/.test(line))).toBe(true);
    });

    it("post-arm as-uid verify failure fast-disarms, scrubs the provisioned rules, audits egress_provision_refused, and returns the DISTINCT egress-unprovisioned-rolled-back outcome", async () => {
      const failingReport = {
        ok: false,
        rows: [
          {
            name: "LLM (Venice)",
            host: "api.venice.ai",
            port: 443,
            expected: "reachable" as const,
            observed: "blocked" as const,
            pass: false,
          },
        ],
      };
      const ops = happyPathOps({
        verifyAgentEgressAfterArm: vi.fn(async () => failingReport),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({
        kind: "egress-unprovisioned-rolled-back",
        uid: AGENT_UID,
        scrubbed: true,
      });
      expect(ops.disarm).toHaveBeenCalledTimes(1);
      expect(ops.scrubProvisionedEgress).toHaveBeenCalledTimes(1);
      // Fast-disarm ordering: filter off BEFORE the rule scrub.
      const disarmOrder = (ops.disarm as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      const scrubOrder = (ops.scrubProvisionedEgress as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      expect(disarmOrder).toBeLessThan(scrubOrder);
      expect(ops.auditEgress).toHaveBeenCalledWith(
        "egress_provision_refused",
        expect.objectContaining({
          stage: "post-arm-as-uid-verify",
          disarm_outcome: "fast-disarmed",
        }),
      );
      // The agent stays re-homed: no restore on this rollback.
      expect(ops.restoreRehome).not.toHaveBeenCalled();
      const reason = (result as { reason: string }).reason;
      expect(reason).toMatch(/post-arm as-uid egress verification failed/);
      expect(reason).toMatch(/Fast-disarmed/);
    });

    it("post-arm as-uid verify failure where the NEGATIVE CONTROL was reachable also rolls back (a reachable non-listed host proves nothing is confined)", async () => {
      const report = {
        ok: false,
        rows: [
          {
            name: "LLM (Venice)",
            host: "api.venice.ai",
            port: 443,
            expected: "reachable" as const,
            observed: "reachable" as const,
            pass: true,
          },
          {
            name: "negative control (non-listed host must be blocked)",
            host: "example.com",
            port: 443,
            expected: "blocked" as const,
            observed: "reachable" as const,
            pass: false,
          },
        ],
      };
      const ops = happyPathOps({ verifyAgentEgressAfterArm: vi.fn(async () => report) });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "egress-unprovisioned-rolled-back", uid: AGENT_UID });
      expect(ops.disarm).toHaveBeenCalledTimes(1);
      expect((result as { reason: string }).reason).toMatch(/negative control/);
    });

    it("post-arm as-uid verify failure + disarm THROW routes to armed-rollback-failed (the wall is still up; loud manual recovery)", async () => {
      const ops = happyPathOps({
        verifyAgentEgressAfterArm: vi.fn(async () => ({
          ok: false,
          rows: [
            {
              name: "LLM (Venice)",
              host: "api.venice.ai",
              port: 443,
              expected: "reachable" as const,
              observed: "blocked" as const,
              pass: false,
            },
          ],
        })),
        disarm: vi.fn(async () => {
          throw new Error("castle-wall disable exited 1");
        }),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({
        kind: "armed-rollback-failed",
        uid: AGENT_UID,
        disarmError: "castle-wall disable exited 1",
      });
      expect(ops.auditEgress).toHaveBeenCalledWith(
        "egress_provision_refused",
        expect.objectContaining({ disarm_outcome: "disarm-failed" }),
      );
    });

    it("a later abort (uid-existence-gate) after a successful provisionEgress scrubs the provisioned rules (no orphan grants on a failed run)", async () => {
      const ops = happyPathOps({
        checkUidExistence: vi.fn(async () => ({
          ok: false as const,
          accountName: "sanctuary-hermes",
          reason: "account does not exist",
        })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "uid-existence-gate" });
      expect(ops.scrubProvisionedEgress).toHaveBeenCalledTimes(1);
    });

    it("a FAILED egress scrub on abort is surfaced LOUDLY in the reason, never silently swallowed", async () => {
      const ops = happyPathOps({
        checkUidExistence: vi.fn(async () => ({
          ok: false as const,
          accountName: "sanctuary-hermes",
          reason: "account does not exist",
        })),
        scrubProvisionedEgress: vi.fn(async () => {
          throw new Error("EACCES: rules dir not writable");
        }),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      const reason = (result as { reason: string }).reason;
      expect(reason).toMatch(/provisioned egress allow rules could NOT be scrubbed/);
      expect(reason).toMatch(/EACCES: rules dir not writable/);
    });

    it("an abort BEFORE provisionEgress (ensure-policy-daemon) does NOT scrub (nothing was provisioned this run)", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({
          ok: false as const,
          error: "socket never became reachable",
          freshlyInstalled: false,
        })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "ensure-policy-daemon" });
      expect(ops.provisionEgress).not.toHaveBeenCalled();
      expect(ops.scrubProvisionedEgress).not.toHaveBeenCalled();
    });

    it("the Tier-1 confirm plan-print names every egress grant BEFORE the confirm, with the exfil-risk marking on messaging hosts", async () => {
      const ops = happyPathOps({ confirm: vi.fn(async () => false) });
      const ctx = baseCtx({
        harnessEndpoints: {
          harnessId: "hermes",
          endpoints: [
            ...TEST_ENDPOINT_SET.endpoints,
            {
              name: "Telegram Bot API",
              host: "api.telegram.org",
              port: 443,
              protocol: "tcp" as const,
              riskClass: "standard" as const,
            },
          ],
        },
      });
      const result = await runProvisionFlow(ctx, ops);
      // Declined AFTER the plan-print: the grants were named before consent.
      expect(result.kind).toBe("declined-by-operator");
      const printed = (ops.print as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
      expect(printed.some((line) => line.includes("Egress grants to provision"))).toBe(true);
      expect(printed.some((line) => line.includes("api.venice.ai:443/tcp"))).toBe(true);
      const telegramLine = printed.find((line) => line.includes("api.telegram.org"));
      expect(telegramLine).toBeDefined();
      expect(telegramLine).toMatch(/EXFIL-RISK/);
      const orderConfirm = (ops.confirm as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
      const printCalls = (ops.print as ReturnType<typeof vi.fn>).mock.invocationCallOrder;
      expect(Math.min(...printCalls)).toBeLessThan(orderConfirm);
    });

    it("armed-then-rolled-back (post-arm DNS/credential re-check failure) also scrubs the provisioned rules", async () => {
      const ops = happyPathOps({
        postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "armed-then-rolled-back", uid: AGENT_UID });
      expect(ops.scrubProvisionedEgress).toHaveBeenCalledTimes(1);
    });
  });

  describe("S5-6 exclusive-egress (fine-grained) stage", () => {
    const COMMITTED = { generation_id: 4, agent_uid: AGENT_UID, gate_port: 40001 };

    /** Exclusive ops whose bring-up + release succeed. */
    function happyExclusiveOps() {
      return {
        bringUpGeneration: vi.fn(async () => COMMITTED),
        runReleaseSequence: vi.fn(async () => ({ kind: "released" as const, generation_id: COMMITTED.generation_id })),
        restoreCoarseComposition: vi.fn(async () => undefined),
        startHarnessCoarse: vi.fn(async () => undefined),
        audit: vi.fn(async () => undefined),
        print: vi.fn(),
      };
    }

    /** happyPathOps with the PARKED install form the fine-grained mode requires. */
    function fineGrainedOps(exclusive = happyExclusiveOps(), overrides: Partial<ProvisionFlowOps> = {}) {
      return {
        ops: happyPathOps({
          installHarnessDaemon: vi.fn(async () => ({
            ok: true as const,
            bootstrappedThisRun: false,
            parked: true,
          })),
          exclusiveEgress: exclusive,
          ...overrides,
        }),
        exclusive,
      };
    }

    it("PREFLIGHT (fail-closed, before ANY mutation): fine-grained declared with no exclusive ops wired aborts with nothing changed", async () => {
      const ops = happyPathOps();
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "exclusive-egress-preflight" });
      // Nothing ran: no confirm ceremony, no account, no daemon, no arm.
      expect(ops.confirm).not.toHaveBeenCalled();
      expect(ops.createAccount).not.toHaveBeenCalled();
      expect(ops.installHarnessDaemon).not.toHaveBeenCalled();
      expect(ops.arm).not.toHaveBeenCalled();
    });

    it("BARRIER ASSERTION: a non-parked install in fine-grained mode aborts at install-daemon and tears the daemon down (never an agent running before the barrier)", async () => {
      const { ops } = fineGrainedOps(happyExclusiveOps(), {
        // The install "succeeds" but NOT in the parked form.
        installHarnessDaemon: vi.fn(async () => ({ ok: true as const, bootstrappedThisRun: true })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon" });
      expect(String((result as { reason: string }).reason)).toMatch(/parked/i);
      expect(ops.uninstallHarnessDaemon).toHaveBeenCalled();
      expect(ops.arm).not.toHaveBeenCalled();
    });

    it("happy fine-grained path: coarse stages first, then the exclusive stage, terminal outcome armed-exclusive (never plain armed)", async () => {
      const { ops, exclusive } = fineGrainedOps();
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toEqual({ kind: "armed-exclusive", uid: AGENT_UID, generationId: COMMITTED.generation_id });
      // The exclusive stage ran strictly AFTER the coarse arm proved live.
      const armOrder = (ops.arm as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
      const bringUpOrder = exclusive.bringUpGeneration.mock.invocationCallOrder[0]!;
      expect(armOrder).toBeLessThan(bringUpOrder);
      expect(exclusive.runReleaseSequence).toHaveBeenCalledWith(COMMITTED);
      // No degrade surfaces touched on the happy path.
      expect(exclusive.restoreCoarseComposition).not.toHaveBeenCalled();
      expect(exclusive.startHarnessCoarse).not.toHaveBeenCalled();
    });

    it("released-repark-failed maps to the DISTINCT armed-exclusive-repark-failed outcome (amber, never green)", async () => {
      const exclusive = happyExclusiveOps();
      exclusive.runReleaseSequence = vi.fn(async () => ({
        kind: "released-repark-failed" as const,
        generation_id: COMMITTED.generation_id,
        reparkError: "launchctl disable exited 1",
      }));
      const { ops } = fineGrainedOps(exclusive);
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toEqual({
        kind: "armed-exclusive-repark-failed",
        uid: AGENT_UID,
        generationId: COMMITTED.generation_id,
        reparkError: "launchctl disable exited 1",
      });
    });

    it("DEGRADE-LOUD: a failed bring-up maps to exclusive-egress-unarmed-coarse-active carrying the stage/reason/restore/start signals", async () => {
      const exclusive = happyExclusiveOps();
      exclusive.bringUpGeneration = vi.fn(async () => {
        throw new Error("pf anchor liveness probe reported NOT live");
      });
      const { ops } = fineGrainedOps(exclusive);
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toMatchObject({
        kind: "exclusive-egress-unarmed-coarse-active",
        uid: AGENT_UID,
        stage: "bring-up",
        coarseCompositionRestored: true,
        harness: { disposition: "started-coarse" },
      });
      expect(String((result as { reason: string }).reason)).toMatch(/NOT live/);
      // The proven coarse wall was NOT disarmed by the degrade path.
      expect(ops.disarm).not.toHaveBeenCalled();
    });

    it("coarse mode (fineGrainedDeclared absent) never invokes the exclusive stage even when ops are wired", async () => {
      const { ops, exclusive } = fineGrainedOps(happyExclusiveOps(), {
        installHarnessDaemon: vi.fn(async () => ({ ok: true as const, bootstrappedThisRun: true })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
      expect(exclusive.bringUpGeneration).not.toHaveBeenCalled();
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // Drill-D2 fix-round (2026-07-18): the harness-restore chokepoint.
  //
  // In fine-grained mode the harness install STOPS the operator's live agent.
  // Both adversarial gate lenses found that every abort between that step and
  // the exclusive stage left it dead, with an unrecoverable plist and printed
  // guidance that could not work. These assert the OUTCOME -- the agent is put
  // back -- rather than that a particular internal was invoked, because the
  // gates specifically noted the prior tests would pass against subtly wrong
  // implementations.
  // ────────────────────────────────────────────────────────────────────────
  describe("harness-restore chokepoint (the fine-grained install is destructive, so it is reversible)", () => {
    const COMMITTED = { generation_id: 4, agent_uid: AGENT_UID, gate_port: 40001 };

    function exclusiveOps() {
      return {
        bringUpGeneration: vi.fn(async () => COMMITTED),
        runReleaseSequence: vi.fn(async () => ({ kind: "released" as const, generation_id: COMMITTED.generation_id })),
        restoreCoarseComposition: vi.fn(async () => undefined),
        startHarnessCoarse: vi.fn(async () => undefined),
        audit: vi.fn(async () => undefined),
        print: vi.fn(),
      };
    }

    /** A fine-grained run whose parked install STOOD A PRE-EXISTING AGENT DOWN. */
    function stoodDownOps(overrides: Partial<ProvisionFlowOps> = {}) {
      return happyPathOps({
        installHarnessDaemon: vi.fn(async () => ({
          ok: true as const,
          bootstrappedThisRun: false,
          parked: true,
          harnessStoodDown: true,
        })),
        exclusiveEgress: exclusiveOps(),
        ...overrides,
      });
    }

    // The exhaustive form of the gate's "seven abort sites" finding. Each of
    // these is a real refusal the flow can reach after the agent is stopped;
    // ALL of them must put it back. Table-driven deliberately: adding a stage
    // here is cheaper than discovering the eighth one on a drill host.
    const abortSites: Array<{ stage: string; overrides: Partial<ProvisionFlowOps> }> = [
      {
        stage: "provision-egress",
        overrides: {
          provisionEgress: vi.fn(async () => ({ ok: false as const, error: "reload refused" })),
        },
      },
      {
        stage: "verify-before-arm",
        overrides: { preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]) },
      },
      {
        stage: "uid-existence-gate",
        overrides: {
          checkUidExistence: vi.fn(async () => ({ ok: false as const, reason: "uid 503 no longer exists" })),
        },
      },
      {
        stage: "arm",
        overrides: { arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })) },
      },
    ];

    for (const { stage, overrides } of abortSites) {
      it(`restores the stood-down agent when the flow aborts at ${stage}`, async () => {
        const ops = stoodDownOps(overrides);
        const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
        expect(result).toMatchObject({ kind: "aborted", stage });
        expect(ops.restoreStoodDownHarness).toHaveBeenCalledTimes(1);
        // The operator is TOLD, not left to infer it from silence.
        expect(String((result as { reason: string }).reason)).toMatch(/stood down was restarted/i);
      });
    }

    it("restores the agent on the post-arm rollback paths too (the outcomes that never routed through the teardown helper)", async () => {
      // These two return `armed-then-rolled-back` / `egress-unprovisioned-
      // rolled-back` instead of `aborted`, so a per-site restore bolted onto
      // `teardownDaemonAndRestore` would have missed them entirely. Deciding
      // from the OUTCOME is what covers them.
      const postArm = stoodDownOps({
        postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
      });
      const postArmResult = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), postArm);
      expect(postArmResult.kind).toBe("armed-then-rolled-back");
      expect(postArm.restoreStoodDownHarness).toHaveBeenCalledTimes(1);

      const asUid = stoodDownOps({
        verifyAgentEgressAfterArm: vi.fn(async () => ({
          ok: false as const,
          rows: [{ name: "LLM", kind: "allow" as const, pass: false, detail: "blocked" }],
        })),
      });
      const asUidResult = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), asUid);
      expect(asUidResult.kind).toBe("egress-unprovisioned-rolled-back");
      expect(asUid.restoreStoodDownHarness).toHaveBeenCalledTimes(1);
    });

    it("restores the agent when the barrier assertion rejects a non-parked install", async () => {
      const ops = happyPathOps({
        installHarnessDaemon: vi.fn(async () => ({
          ok: true as const,
          bootstrappedThisRun: false,
          harnessStoodDown: true,
        })),
        exclusiveEgress: exclusiveOps(),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon" });
      expect(ops.restoreStoodDownHarness).toHaveBeenCalledTimes(1);
    });

    it("restores the agent when a step THROWS rather than returning an outcome, and still surfaces the original error", async () => {
      // The abort path nobody enumerates. A restore driven off the outcome
      // would miss it, so the chokepoint covers the throw explicitly.
      const ops = stoodDownOps({
        checkUidExistence: vi.fn(async () => {
          throw new Error("dscl blew up");
        }),
      });
      await expect(runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops)).rejects.toThrow(/dscl blew up/);
      expect(ops.restoreStoodDownHarness).toHaveBeenCalledTimes(1);
    });

    it("does NOT restore when the exclusive stage succeeded -- that would tear a correctly-confined agent back to coarse", async () => {
      const ops = stoodDownOps();
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result.kind).toBe("armed-exclusive");
      expect(ops.restoreStoodDownHarness).not.toHaveBeenCalled();
    });

    it("does NOT restore on the degrade-loud path -- that stage already decided the harness's disposition", async () => {
      const exclusive = exclusiveOps();
      exclusive.bringUpGeneration = vi.fn(async () => {
        throw new Error("pf anchor liveness probe reported NOT live");
      });
      const ops = stoodDownOps({ exclusiveEgress: exclusive });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result.kind).toBe("exclusive-egress-unarmed-coarse-active");
      expect(ops.restoreStoodDownHarness).not.toHaveBeenCalled();
    });

    it("does NOT restore when the install never stood anything down (a clean host has nothing to put back)", async () => {
      const ops = happyPathOps({
        installHarnessDaemon: vi.fn(async () => ({
          ok: true as const,
          bootstrappedThisRun: false,
          parked: true,
          harnessStoodDown: false,
        })),
        exclusiveEgress: exclusiveOps(),
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
      });
      await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(ops.restoreStoodDownHarness).not.toHaveBeenCalled();
    });

    it("a FAILED restore is LOUD: names the agent as stopped and gives a command, never a silent omission", async () => {
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: false,
          wasRunning: true,
          harnessRestarted: false,
          problems: ["launchctl bootstrap exited 5"],
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).toMatch(/could NOT be fully restored/);
      expect(reason).toMatch(/launchctl bootstrap exited 5/);
      expect(reason).toMatch(/This run did NOT bring it back up, and did not verify its run state/);
      expect(reason).toMatch(/sanctuary protect --hermes/);
      // The ORIGINAL abort reason is never displaced by the cleanup note.
      expect(reason).toMatch(/castle-wall enable exited 1/);
    });

    it("a THROWING restore op cannot take the flow down with it", async () => {
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => {
          throw new Error("EROFS");
        }),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "arm" });
      expect(String((result as { reason: string }).reason)).toMatch(/EROFS/);
    });

    // ────────────────────────────────────────────────────────────────────
    // FIX-ROUND 2 (2026-07-18). Round 1's note was derived from a single
    // boolean the production op computed from an empty error list. These
    // assert the note is a function of what was OBSERVED, in each of the
    // three shapes that boolean collapsed together.
    // ────────────────────────────────────────────────────────────────────

    it("B2: a restore that did NOT restart a running agent is never described as restarted", async () => {
      // The exact case both lenses built: the job was running, it could not be
      // restarted, and NOTHING raised an error. Under the old
      // `errors.length === 0` rule this printed "was restarted and restored to
      // its previous state" over a stopped agent.
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: false,
          wasRunning: true,
          harnessRestarted: false,
          problems: ["the agent harness was running before this run and is STOPPED now"],
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).not.toMatch(/was restarted/i);
      expect(reason).not.toMatch(/restored to its previous state/i);
      expect(reason).toMatch(/This run did NOT bring it back up, and did not verify its run state/);
      expect(reason).toMatch(/sanctuary protect --hermes/);
    });

    it("B2: the note keys on the VERDICT, not on the error list -- a silent failed restore is still loud", async () => {
      // The literal shape the brief named: was running, could not be
      // restarted, and NO errors raised. Production cannot produce this any
      // more (the revert turns that silence into an error), which is exactly
      // why it is pinned here: the note must be a function of `restored`, so
      // that a future op which forgets to complain still cannot print
      // "restarted" over a stopped agent.
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: false,
          wasRunning: true,
          harnessRestarted: false,
          problems: [] as string[],
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).not.toMatch(/was restarted/i);
      expect(reason).toMatch(/This run did NOT bring it back up, and did not verify its run state/);
    });

    it("B2: a job that was NOT running before is described as put back, not as restarted", async () => {
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: true,
          wasRunning: false,
          harnessRestarted: false,
          problems: [] as string[],
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).toMatch(/was put back/i);
      expect(reason).toMatch(/not running before this run, and this run did not start it/i);
      expect(reason).not.toMatch(/was restarted/i);
    });

    it("MED: armed-rollback-failed restores the harness but NOT the re-home, and stops claiming otherwise", async () => {
      // Sites 14/16 return directly, without `teardownDaemonAndRestore`, so
      // the re-home stands. Restoring the harness there runs the agent under
      // its PRE-run account and home -- whose secrets this run already moved.
      // "Restored to its previous state" was simply false.
      const ops = stoodDownOps({
        postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
        disarm: vi.fn(async () => {
          throw new Error("pfctl -d exited 1");
        }),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result.kind).toBe("armed-rollback-failed");
      const reason = String((result as { reason: string }).reason);
      expect(reason).toMatch(/re-home was deliberately NOT reversed/i);
      expect(reason).toMatch(/not a return to your previous state/i);
    });

    it("MED: the restore note cannot be silenced by an outcome that has no `reason` field", async () => {
      // The restore DECISION defaults to safe (an allow-list). The NOTE used
      // to default to SILENCE: `withHarnessRestoreNote` returned the outcome
      // untouched when it had no `reason`, dropping even the loud
      // agent-is-stopped message. No outcome shape can swallow it now.
      const printed: string[] = [];
      const reasonless = stoodDownOps({
        print: vi.fn((line: string) => printed.push(line)),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: false,
          wasRunning: true,
          harnessRestarted: false,
          problems: ["launchctl bootstrap exited 5"],
        })),
        // `armed` carries no `reason`. It cannot co-occur with a parked
        // install today, which is exactly why the silence went unnoticed --
        // so drive it explicitly rather than trust that it stays unreachable.
        exclusiveEgress: undefined,
      });
      const coarse = await runProvisionFlow(baseCtx({ fineGrainedDeclared: false }), reasonless);
      expect(coarse.kind).toBe("armed");
      expect(printed.join("\n")).toMatch(/This run did NOT bring it back up, and did not verify its run state/);
    });

    it("MED: a restore on the THROW path is reported too, instead of being swallowed with the error", async () => {
      const printed: string[] = [];
      const ops = stoodDownOps({
        print: vi.fn((line: string) => printed.push(line)),
        checkUidExistence: vi.fn(async () => {
          throw new Error("dscl blew up");
        }),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: false,
          wasRunning: true,
          harnessRestarted: false,
          problems: ["launchctl bootstrap exited 5"],
        })),
      });
      await expect(runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops)).rejects.toThrow(/dscl blew up/);
      // The original error still wins as the outcome, but the operator is no
      // longer left to discover their agent is down by noticing it is down.
      expect(printed.join("\n")).toMatch(/This run did NOT bring it back up, and did not verify its run state/);
    });
  });
});
