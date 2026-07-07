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

function baseCtx(overrides: Partial<ProvisionFlowContext> = {}): ProvisionFlowContext {
  return {
    agentId: "hermes",
    accountName: "sanctuary-hermes",
    ceiling: CEILING,
    detectResult: NEEDS_PROVISIONING,
    isTty: true,
    ...overrides,
  };
}

function happyPathOps(overrides: Partial<ProvisionFlowOps> = {}): ProvisionFlowOps {
  return {
    confirm: vi.fn(async () => true),
    print: vi.fn(),
    createAccount: vi.fn(async () => ({
      plan: { action: "create", accountName: "sanctuary-hermes", uid: AGENT_UID },
      uid: AGENT_UID,
    })),
    rehome: vi.fn(async () => ({
      plan: { harnessId: "hermes", steps: [], requiresInteractiveReconsent: false },
      results: REHOME_RESULTS,
    })),
    installHarnessDaemon: vi.fn(async () => ({ bootstrappedThisRun: true })),
    uninstallHarnessDaemon: vi.fn(async () => undefined),
    preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => true }]),
    checkUidExistence: vi.fn(async () => ({ ok: true, accountName: "sanctuary-hermes", uid: AGENT_UID })),
    arm: vi.fn(async () => ({ ok: true as const })),
    postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => true }]),
    disarm: vi.fn(async () => undefined),
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
      installHarnessDaemon: vi.fn(async () => {
        throw new Error("launchctl bootstrap exited 5");
      }),
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
      installHarnessDaemon: vi.fn(async () => {
        throw new Error("launchctl bootstrap exited 5");
      }),
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
        return { bootstrappedThisRun: true };
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
      installHarnessDaemon: vi.fn(async () => {
        throw new Error("launchctl bootstrap exited 5");
      }),
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
      installHarnessDaemon: vi.fn(async () => {
        throw new Error("launchctl bootstrap exited 5");
      }),
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
      installHarnessDaemon: vi.fn(async () => {
        throw new Error("launchctl bootstrap exited 5");
      }),
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
      installHarnessDaemon: vi.fn(async () => ({ bootstrappedThisRun: false })),
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
      installHarnessDaemon: vi.fn(async () => ({ bootstrappedThisRun: true })),
      preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm" });
    // The freshly-installed daemon MUST be torn down (not stranded with a
    // false "nothing was changed" all-clear).
    expect(ops.uninstallHarnessDaemon).toHaveBeenCalledTimes(1);
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
});
