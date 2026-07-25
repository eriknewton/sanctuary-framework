/**
 * Tests for the one-flow orchestration (fold of the target flow's steps 1
 * through 11, folded fixes B2/H1/H3/H4/L2): every fail-closed branch is
 * driven purely through injected ops, so this exercises the FULL corrected
 * sequencing without touching a real host, TTY, or privileged binary.
 */

import { describe, it, expect, vi } from "vitest";

import {
  runProvisionFlow,
  describeObservedAgentConfinement,
  describeExclusiveRoutingResidueRefusal,
  exclusiveRoutingResidueRefusal,
  type ProvisionFlowContext,
  type ProvisionFlowOps,
} from "../../../src/castle-wall/provision/orchestrate.js";
import type { ProvisionNeedResult } from "../../../src/castle-wall/provision/detect.js";
import type { RehomeStepResult } from "../../../src/castle-wall/provision/rehome.js";
import {
  assessHarnessParked,
  runStateAdvice,
  type RunStateAdvice,
} from "../../../src/egress-gate/parked-claim.js";
import {
  projectRevertToRestoreReport,
  revertParkedHarnessInstall,
  runStateOwed,
  type ParkedInstallRevertOps,
} from "../../../src/egress-gate/release-barrier.js";
import type { HarnessDaemonStatus } from "../../../src/egress-gate/harness-daemon.js";

const HARNESS_LOCATOR = {
  plistPath: "/Library/LaunchDaemons/ai.sanctuaryprotocol.agent-harness.plist",
  harnessLabel: "ai.sanctuaryprotocol.agent-harness",
};

/**
 * Build a run-state advice the way production must: through the chokepoint.
 *
 * FIX-ROUND 6. These tests cannot hand-roll one -- `RunStateAdvice` is branded
 * and `runStateAdvice` is its sole constructor -- which is deliberate. The
 * eleventh instance of this subsystem's defect existed precisely because the
 * op boundary let a caller render run-state prose with NO claim in hand. A
 * test that could fake one would be pinning the same hole.
 */
async function observedRunState(status: HarnessDaemonStatus): Promise<RunStateAdvice> {
  const claim = await assessHarnessParked({
    probe: { harnessStatus: async () => status, sleepMs: async () => {} },
  });
  return runStateAdvice(claim, { locator: HARNESS_LOCATOR });
}

const PARKED_STATUS: HarnessDaemonStatus = { known: true, installed: true, running: false };
const LIVE_STATUS: HarnessDaemonStatus = { known: true, installed: true, running: true, pid: 9001 };

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
    restoreProvisionedEgressToPreRunState: vi.fn(async () => ({ restored: true, reloadOk: true, problems: [] })),
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
    disarm: vi.fn(async () => ({ nePreferenceOutcome: "corroborated_off" as const })),
    restoreRehome: vi.fn(async () => ({
      fullyRestored: true,
      restoredCount: REHOME_RESULTS.length,
      attemptedCount: REHOME_RESULTS.length,
      backupPaths: REHOME_RESULTS.filter((r) => r.backupPath).map((r) => r.backupPath!),
      conflictPaths: [],
    })),
    // FIX F-COARSE-AFTER-EXCLUSIVE (honesty half): the default is a host with
    // NOTHING confined, which is what the pre-fix flat sentence assumed. The
    // regression tests below override it with the drill's actual state.
    observeAgentConfinement: vi.fn(async () => ({
      known: true as const,
      confinedUids: [],
      exclusiveRoutingMarkerPresent: false,
    })),
    // FIX F-COARSE-AFTER-EXCLUSIVE (class half): the mode-independent residue
    // gate. Default = no marker on disk, so the gate is a no-op for every test
    // that is not about it.
    reconcileExclusiveRoutingResidue: vi.fn(async () => ({ kind: "clear" as const })),
    ...overrides,
  };
}

/**
 * A residue op for a marker that is PROVABLY ORPHANED. The `"observe"` call
 * judges it without touching anything; only the `"clear"` call removes it. This
 * split is the whole point of FIX F1: the judgement may run before the operator
 * confirm, the removal may not.
 */
function residueOp(): ReturnType<typeof vi.fn> {
  const detail = "no S5-1 registry entry and no serving gate for uid 707";
  return vi.fn(async (_armTargetUid: number | undefined, intent: "observe" | "clear") =>
    intent === "observe" ? { kind: "orphaned" as const, detail } : { kind: "reconciled" as const, detail },
  );
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
        return { nePreferenceOutcome: "corroborated_off" as const };
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

    it("B1: save-accepted-but-inconclusive disarm does not become observed-off evidence", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        disarm: vi.fn(async () => ({
          nePreferenceOutcome: "save_accepted_inconclusive" as const,
        })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "arm" });
      expect(ops.teardownPolicyDaemon).toHaveBeenCalledTimes(1);
      expect((result as { disarmObservedOff?: true }).disarmObservedOff).toBeUndefined();
      expect((result as { wallMayBeArmed?: true }).wallMayBeArmed).toBeUndefined();
      expect((result as { reason: string }).reason).toContain("status corroboration was inconclusive");
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

    it("P1 (fail-open-after-lease-revoke): arm ok:false + fresh daemon + disarm returns fail_open_deadman leaves the daemon UP (never a reboot-brick) + sets wallMayBeArmed, even though disarm did NOT throw", async () => {
      const ops = happyPathOps({
        ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: true })),
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        // Disarm did NOT throw (it succeeded as a dead-man lever, fail-open),
        // but the NE preference was NOT observed off -- the exact P1 sub-case.
        disarm: vi.fn(async () => ({ nePreferenceOutcome: "fail_open_deadman" as const })),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "arm", wallMayBeArmed: true });
      expect(ops.disarm).toHaveBeenCalledTimes(1);
      // CRITICAL: a non-throwing-but-not-observed-off disarm must NOT tear the fresh
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
      expect(ops.restoreProvisionedEgressToPreRunState).not.toHaveBeenCalled();
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
      expect(ops.restoreProvisionedEgressToPreRunState).toHaveBeenCalledTimes(1);
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

    // -----------------------------------------------------------------------
    // FIX F-COARSE-AFTER-EXCLUSIVE, honesty half (HIGH, Mini1 re-drill
    // 2026-07-26). This abort printed the flat sentence "The wall was NOT
    // armed". At the instant it printed on the drill host, pf was
    // `Status: Enabled`, the gate registry showed
    // `committed: [{agent_uid: 503, generation_id: 23}]`, and the confined
    // agent was 0/9 reachable INCLUDING its own manifest. The sentence was
    // true about the CODE PATH and false about the HOST.
    // -----------------------------------------------------------------------
    const refusingEgressOps = (
      observe: ProvisionFlowOps["observeAgentConfinement"],
    ): ProvisionFlowOps =>
      happyPathOps({
        provisionEgress: vi.fn(async () => ({
          ok: false as const,
          error: "policy reload after publishing egress rules failed: Exclusive routing composition rejected",
          checks: [],
          dnsRulePresent: true,
        })),
        observeAgentConfinement: observe,
      });

    it("REGRESSION (F-COARSE-AFTER-EXCLUSIVE): a refused run over an ALREADY-CONFINED host never claims nothing is armed", async () => {
      const result = await runProvisionFlow(
        baseCtx(),
        refusingEgressOps(
          vi.fn(async () => ({
            known: true as const,
            confinedUids: [503],
            exclusiveRoutingMarkerPresent: true,
          })),
        ),
      );
      const reason = (result as { reason: string }).reason;
      // The pre-fix sentence, verbatim, must not be reachable.
      expect(reason).not.toMatch(/The wall was NOT armed/);
      // What IS said comes from the observation.
      expect(reason).toMatch(/This run did not arm the wall, BUT/);
      expect(reason).toMatch(/uid\(s\) 503 are confined/);
      expect(reason).toMatch(/exclusive-routing marker/);
      // And it names the product path that provably clears it (the drill's D9).
      expect(reason).toMatch(/--unprotect-egress-gate/);
    });

    it("REGRESSION (F-COARSE-AFTER-EXCLUSIVE): a clean host is described as clean, and an UNOBSERVABLE host as unknown", async () => {
      const clean = await runProvisionFlow(baseCtx(), refusingEgressOps(
        vi.fn(async () => ({ known: true as const, confinedUids: [], exclusiveRoutingMarkerPresent: false })),
      ));
      expect((clean as { reason: string }).reason).toMatch(/no per-agent egress confinement was observed/);
      expect((clean as { reason: string }).reason).not.toMatch(/unprotect-egress-gate/);

      // "Could not look" must never collapse into "nothing is armed".
      const unknown = await runProvisionFlow(baseCtx(), refusingEgressOps(
        vi.fn(async () => ({ known: false as const, reason: "the egress-gate registry could not be read: EACCES" })),
      ));
      const unknownReason = (unknown as { reason: string }).reason;
      expect(unknownReason).toMatch(/could NOT be observed/);
      expect(unknownReason).toMatch(/EACCES/);
      expect(unknownReason).not.toMatch(/no per-agent egress confinement was observed/);

      // A THROWING probe is also unknown, never quiet, and never fatal.
      const threw = await runProvisionFlow(baseCtx(), refusingEgressOps(
        vi.fn(async () => Promise.reject(new Error("probe exploded"))),
      ));
      expect((threw as { reason: string }).reason).toMatch(/probe threw: probe exploded/);
    });

    it("REGRESSION (F-COARSE-AFTER-EXCLUSIVE): describeObservedAgentConfinement is a pure function of the observation", () => {
      // The render chokepoint asserted directly: the same observation must
      // produce the same sentence regardless of which caller reached it.
      expect(
        describeObservedAgentConfinement({ known: true, confinedUids: [], exclusiveRoutingMarkerPresent: false }),
      ).toBe("This run did not arm the wall, and no per-agent egress confinement was observed on this host.");
      const markerOnly = describeObservedAgentConfinement({
        known: true,
        confinedUids: [],
        exclusiveRoutingMarkerPresent: true,
      });
      // A marker with NO committed uid is still exclusive composition, and is
      // still enough to refuse the coarse path -- so it must not read clean.
      expect(markerOnly).toMatch(/exclusive-routing marker/);
      expect(markerOnly).toMatch(/--unprotect-egress-gate/);
      expect(markerOnly).not.toMatch(/no per-agent egress confinement was observed/);
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
        egressRestoredToPreRunState: true,
      });
      expect(ops.disarm).toHaveBeenCalledTimes(1);
      expect(ops.restoreProvisionedEgressToPreRunState).toHaveBeenCalledTimes(1);
      // Fast-disarm ordering: filter off BEFORE the rule scrub.
      const disarmOrder = (ops.disarm as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
      const scrubOrder = (ops.restoreProvisionedEgressToPreRunState as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
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
      expect(ops.restoreProvisionedEgressToPreRunState).toHaveBeenCalledTimes(1);
    });

    it("a FAILED egress scrub on abort is surfaced LOUDLY in the reason, never silently swallowed", async () => {
      const ops = happyPathOps({
        checkUidExistence: vi.fn(async () => ({
          ok: false as const,
          accountName: "sanctuary-hermes",
          reason: "account does not exist",
        })),
        restoreProvisionedEgressToPreRunState: vi.fn(async () => {
          throw new Error("EACCES: rules dir not writable");
        }),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      const reason = (result as { reason: string }).reason;
      expect(reason).toMatch(/egress allow rules could NOT be restored to their pre-run state/);
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
      expect(ops.restoreProvisionedEgressToPreRunState).not.toHaveBeenCalled();
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
      expect(ops.restoreProvisionedEgressToPreRunState).toHaveBeenCalledTimes(1);
    });

    /**
     * FIX F-REVOKE (Mini1 confined-Hermes drill 2026-07-26): the rollback is
     * only allowed to read as clean when the pre-run rule state was OBSERVED
     * back AND is being served. On hardware the operator got "the re-homed
     * paths were restored to your account" while six signed allow rules a
     * previous run had published were gone and the live agent could reach
     * nothing.
     */
    describe("F-REVOKE: a rollback that did not restore the agent's grants says so loudly", () => {
      it("REGRESSION: an unrestored rule set warns that a still-running agent may reach nothing, and names the recovery command", async () => {
        const ops = happyPathOps({
          checkUidExistence: vi.fn(async () => ({
            ok: false as const,
            accountName: "sanctuary-hermes",
            reason: "account does not exist",
          })),
          restoreProvisionedEgressToPreRunState: vi.fn(async () => ({
            restored: false,
            reloadOk: false,
            problems: ["provisioned-hermes-abc123def456 was not restored"],
          })),
        });
        const result = await runProvisionFlow(baseCtx(), ops);
        const reason = (result as { reason: string }).reason;
        expect(reason).toMatch(/MAY NOW REACH NOTHING/);
        expect(reason).toMatch(/sudo sanctuary protect --hermes/);
        expect(reason).toMatch(/provisioned-hermes-abc123def456 was not restored/);
      });

      it("REGRESSION: rules back on disk but no confirmed reload is reported as not-yet-serving, with the reload command", async () => {
        const ops = happyPathOps({
          checkUidExistence: vi.fn(async () => ({
            ok: false as const,
            accountName: "sanctuary-hermes",
            reason: "account does not exist",
          })),
          restoreProvisionedEgressToPreRunState: vi.fn(async () => ({
            restored: true,
            reloadOk: false,
            problems: [],
          })),
        });
        const result = await runProvisionFlow(baseCtx(), ops);
        const reason = (result as { reason: string }).reason;
        expect(reason).toMatch(/restored on disk but the policy daemon did NOT confirm/);
        expect(reason).toMatch(/sanctuary castle-wall reload/);
      });

      it("REGRESSION: the post-arm outcome does NOT claim the pre-run rule state was restored when the reload was unconfirmed", async () => {
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
          restoreProvisionedEgressToPreRunState: vi.fn(async () => ({
            restored: true,
            reloadOk: false,
            problems: [],
          })),
        });
        const result = await runProvisionFlow(baseCtx(), ops);
        expect(result).toMatchObject({
          kind: "egress-unprovisioned-rolled-back",
          egressRestoredToPreRunState: false,
        });
        expect(ops.auditEgress).toHaveBeenCalledWith(
          "egress_provision_refused",
          expect.objectContaining({ egress_rules_restored_to_pre_run_state: false }),
        );
      });
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

    it("D8 REGRESSION: a stale exclusive-routing marker from a crashed prior arm is cleared BEFORE ANY MUTATION, and the arm PROCEEDS to a live exclusive arm", async () => {
      // The 2026-07-21 hardware wedge: an interrupted prior arm left a stale
      // marker on the fortress. The gate self-heals it (orphaned, no live
      // confinement present); pre-fix, the daemon composed EXCLUSIVE over the
      // coarse rules provision-egress publishes and failed closed, so the flow
      // never got past provision-egress.
      const { ops, exclusive } = fineGrainedOps(happyExclusiveOps(), {
        reconcileExclusiveRoutingResidue: residueOp(),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      // The flow proceeded all the way to a live exclusive arm.
      expect(result).toEqual({ kind: "armed-exclusive", uid: AGENT_UID, generationId: COMMITTED.generation_id });
      const residue = ops.reconcileExclusiveRoutingResidue as ReturnType<typeof vi.fn>;
      // Judged once, cleared once.
      expect(residue.mock.calls.map((c) => c[1])).toEqual(["observe", "clear"]);
      // The clear ran strictly BEFORE the first mutation (createAccount) and
      // therefore before provision-egress (the wedge point) and the arm.
      const clearOrder = residue.mock.invocationCallOrder[1]!;
      const createOrder = (ops.createAccount as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
      const provisionOrder = (ops.provisionEgress as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
      expect(clearOrder).toBeLessThan(createOrder);
      expect(clearOrder).toBeLessThan(provisionOrder);
      expect(exclusive.bringUpGeneration).toHaveBeenCalledTimes(1);
    });

    it("D8 fail-closed: a marker the gate cannot read (throws) ABORTS with nothing changed -- never arms over an unreadable routing mode", async () => {
      const { ops, exclusive } = fineGrainedOps(happyExclusiveOps(), {
        reconcileExclusiveRoutingResidue: vi.fn(async () => {
          throw new Error("exclusive-routing marker: exclusive-routing.json is not valid JSON");
        }),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "exclusive-routing-residue", rolledBack: false });
      expect((result as { reason: string }).reason).toMatch(/could NOT be read/);
      expect((result as { reason: string }).reason).toMatch(/not valid JSON/);
      // Nothing mutated: no account, no install, no egress publish, no arm.
      expect(ops.createAccount).not.toHaveBeenCalled();
      expect(ops.installHarnessDaemon).not.toHaveBeenCalled();
      expect(ops.provisionEgress).not.toHaveBeenCalled();
      expect(exclusive.bringUpGeneration).not.toHaveBeenCalled();
    });

    it("D8 fail-closed: a marker that is KEPT (confinement may be live) REFUSES pre-mutation and names the way out", async () => {
      // Pre-fix this printed the reason and CONTINUED, straight into the
      // provision-egress wedge. A kept marker means the daemon will compose
      // exclusive against this run's coarse rules, so continuing can only end
      // in a refusal AFTER the host has been changed.
      const { ops, exclusive } = fineGrainedOps(happyExclusiveOps(), {
        reconcileExclusiveRoutingResidue: vi.fn(async () => ({
          kind: "kept-uncertain" as const,
          reason: "the S1 anchor registry is in an uncertain state (dirty=true, quarantined=0)",
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "exclusive-routing-residue" });
      expect((result as { reason: string }).reason).toMatch(/uncertain state/);
      expect((result as { reason: string }).reason).toMatch(/sudo sanctuary protect --unprotect-egress-gate/);
      expect(ops.createAccount).not.toHaveBeenCalled();
      expect(exclusive.bringUpGeneration).not.toHaveBeenCalled();
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // FIX F-COARSE-AFTER-EXCLUSIVE, CLASS half (Mini1 re-drill, 2026-07-26).
  //
  // The instance was fixed on 2026-07-25 (the repair verb restores coarse
  // composition; the abort sentence is derived from an observation). The CLASS
  // was not: the residue self-heal was reachable ONLY when
  // `fineGrainedDeclared === true` AND the exclusive ops were wired, so the
  // plain COARSE `protect --hermes --provision-agent-account` run -- the exact
  // command that hit the defect on the drill host -- never ran it, was judged
  // by the exclusive composition rules the leftover marker imposes, and was
  // refused AFTER mutating the host.
  //
  // The gate is now mode-independent, and its irreversible half sits AFTER the
  // one confirm (FIX F1/F2, 2026-07-26). These assert both properties on the
  // COARSE path, where every one of them was previously absent.
  // ────────────────────────────────────────────────────────────────────────
  describe("exclusive-routing residue gate (mode-independent, consent-ordered)", () => {
    it("REGRESSION (coarse): a run with NO exclusive mode declared and NO exclusive ops wired STILL runs the residue gate", async () => {
      const ops = happyPathOps();
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
      // Pre-fix this op did not exist on the coarse path at all: the self-heal
      // was gated on a mode the wedging component (the signing daemon) does
      // not read. With no marker on disk the judgement is the only call.
      expect(ops.reconcileExclusiveRoutingResidue).toHaveBeenCalledTimes(1);
      expect(ops.reconcileExclusiveRoutingResidue).toHaveBeenCalledWith(undefined, "observe");
      expect(ops.exclusiveEgress).toBeUndefined();
    });

    it("REGRESSION (coarse, the drill command): a live gate REFUSES before any mutation and names the way out", async () => {
      // The drill: a failed exclusive arm left exclusive-routing.json +
      // exclusive-egress-gate.json behind, and the next plain coarse
      // `protect --hermes --provision-agent-account` run was refused with the
      // host already changed. It must now refuse with nothing changed. On the
      // real F-COARSE-AFTER-EXCLUSIVE host the S5-1 registry held a committed
      // entry, so this -- KEPT, not self-healed -- is the drill's own verdict.
      const ops = happyPathOps({
        reconcileExclusiveRoutingResidue: vi.fn(async () => ({
          kind: "kept-live" as const,
          reason: "the S5-1 anchor registry still has an entry for uid 503 (committed or mid-bring-up)",
        })),
      });
      const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
      expect(result).toMatchObject({
        kind: "aborted",
        stage: "exclusive-routing-residue",
        rolledBack: false,
        rehomeAttempted: false,
      });
      const reason = (result as { reason: string }).reason;
      expect(reason).toMatch(/entry for uid 503/);
      expect(reason).toMatch(/No account was created, nothing was re-homed, and no Castle Wall change was made/);
      expect(reason).toMatch(/sudo sanctuary protect --unprotect-egress-gate/);
      // Refused before the confirm, and before every mutation.
      expect(ops.confirm).not.toHaveBeenCalled();
      expect(ops.createAccount).not.toHaveBeenCalled();
      expect(ops.rehome).not.toHaveBeenCalled();
      expect(ops.installHarnessDaemon).not.toHaveBeenCalled();
      expect(ops.ensurePolicyDaemon).not.toHaveBeenCalled();
      expect(ops.provisionEgress).not.toHaveBeenCalled();
      expect(ops.arm).not.toHaveBeenCalled();
    });

    it("REGRESSION (coarse): a marker that cannot be READ refuses fail-closed -- 'could not look' is never 'nothing there'", async () => {
      const ops = happyPathOps({
        reconcileExclusiveRoutingResidue: vi.fn(async () => {
          throw new Error("exclusive-routing marker: unknown version 2");
        }),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "exclusive-routing-residue" });
      expect((result as { reason: string }).reason).toMatch(/could NOT be read/);
      expect((result as { reason: string }).reason).toMatch(/unknown version 2/);
      expect(ops.arm).not.toHaveBeenCalled();
      expect(ops.createAccount).not.toHaveBeenCalled();
    });

    it("REGRESSION (coarse): a provably-orphaned marker is SELF-HEALED and the coarse run proceeds to arm", async () => {
      const ops = happyPathOps({ reconcileExclusiveRoutingResidue: residueOp() });
      const printed: string[] = [];
      (ops as { print: (line: string) => void }).print = (line: string) => printed.push(line);
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
      // The removal is NAMED before the confirm, so the operator's yes covers it.
      expect(printed.join("\n")).toMatch(/will be cleared if you proceed/);
      // FIX F7: the flow does NOT re-print the self-heal fact. The production
      // reconcile prints it (with the uid) at the moment it removes the files;
      // both printing meant the operator read the same fact twice.
      expect(printed.filter((l) => /Reconciled a stale exclusive-routing marker/.test(l))).toEqual([]);
    });

    it("scopes the reconcile to the uid this run RESOLVED, and passes undefined when none is resolved", async () => {
      const dedicated = happyPathOps();
      await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), dedicated);
      expect(dedicated.reconcileExclusiveRoutingResidue).toHaveBeenCalledWith(AGENT_UID, "observe");

      const fresh = happyPathOps();
      await runProvisionFlow(baseCtx({ detectResult: NEEDS_PROVISIONING }), fresh);
      // NEEDS_PROVISIONING resolved nothing; a marker then has no subject to be
      // judged against, and the production reconcile keeps it fail-closed.
      expect(fresh.reconcileExclusiveRoutingResidue).toHaveBeenCalledWith(undefined, "observe");
    });

    // ── FIX F1 (adversarial review, 2026-07-26) ──────────────────────────
    // The first cut ran the WHOLE gate -- the self-heal's two `rm`s included --
    // above the non-TTY refusal and the pre-declined return. A scripted run and
    // an explicit decline therefore deleted `exclusive-routing.json` and
    // `exclusive-egress-gate.json` from the operator's fortress and then
    // reported that provisioning had been skipped. These three assert the
    // property the PR claimed and did not have.
    it("F1: a NON-TTY run never reaches the residue gate at all (it was never going to arm)", async () => {
      const ops = happyPathOps({ reconcileExclusiveRoutingResidue: residueOp() });
      const result = await runProvisionFlow(baseCtx({ isTty: false }), ops);
      expect(result).toMatchObject({ kind: "skipped-non-tty-cooperative-only" });
      // Pre-fix: called, and the marker + gate policy were already deleted.
      expect(ops.reconcileExclusiveRoutingResidue).not.toHaveBeenCalled();
    });

    it("F1: an explicitly DECLINED run (--no-provision-agent-account) never reaches the residue gate", async () => {
      const ops = happyPathOps({ reconcileExclusiveRoutingResidue: residueOp() });
      const result = await runProvisionFlow(baseCtx({ preAnsweredProvision: false }), ops);
      expect(result).toEqual({ kind: "declined-by-operator" });
      expect(ops.reconcileExclusiveRoutingResidue).not.toHaveBeenCalled();
    });

    it("F1: an operator who answers 'n' at the confirm leaves the marker ON DISK -- the irreversible half never runs", async () => {
      // The gate JUDGES before the confirm (so a doomed run is not confirmed)
      // and REMOVES after it. This is the case the placement-only fix misses:
      // the judgement is allowed, the removal is not.
      const residue = residueOp();
      const ops = happyPathOps({
        reconcileExclusiveRoutingResidue: residue,
        confirm: vi.fn(async () => false),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toEqual({ kind: "declined-by-operator" });
      expect(residue.mock.calls.map((c) => c[1])).toEqual(["observe"]);
      expect(residue).not.toHaveBeenCalledWith(expect.anything(), "clear");
    });

    it("F1: the CLEAR half re-probes, and a marker that went live during the confirm ABORTS with the host untouched", async () => {
      // The judgement-to-removal window spans operator think-time. Trusting the
      // observation across it would mean removing a marker whose confinement
      // came live in between -- a de-confinement. The clear call is authoritative.
      const ops = happyPathOps({
        reconcileExclusiveRoutingResidue: vi.fn(async (_uid: number | undefined, intent: "observe" | "clear") =>
          intent === "observe"
            ? { kind: "orphaned" as const, detail: "no registry entry and no serving gate for uid 707" }
            : { kind: "kept-live" as const, reason: "a gate daemon now owns port 40001 under gate uid 708" },
        ),
      });
      const result = await runProvisionFlow(baseCtx(), ops);
      expect(result).toMatchObject({ kind: "aborted", stage: "exclusive-routing-residue" });
      expect((result as { reason: string }).reason).toMatch(/owns port 40001/);
      expect(ops.createAccount).not.toHaveBeenCalled();
      expect(ops.rehome).not.toHaveBeenCalled();
      expect(ops.arm).not.toHaveBeenCalled();
    });

    // ── FIX F2/F3/F5 (adversarial review, 2026-07-26): the sentences ─────
    it("the refusal sentence is built from the VERDICT, and makes no claim about whether the wall is armed", () => {
      const sentences = [
        describeExclusiveRoutingResidueRefusal({ kind: "kept-live", reason: "a gate is serving port 40001" }),
        describeExclusiveRoutingResidueRefusal({ kind: "kept-uncertain", reason: "the registry is dirty" }),
        describeExclusiveRoutingResidueRefusal({
          kind: "kept-unknown-subject",
          reason: "no subject",
          markerAgentUid: 707,
        }),
        describeExclusiveRoutingResidueRefusal({ kind: "unreadable", detail: "EACCES" }),
      ];
      for (const sentence of sentences) {
        // The armed/not-armed claim belongs to describeObservedAgentConfinement,
        // which derives it from a probe. This sentence must not invent one.
        expect(sentence).not.toMatch(/wall was NOT armed/i);
        expect(sentence).not.toMatch(/did not arm the wall/i);
        // FIX F2: no counterfactual about a step this run does not reach. The
        // refusing run never gets to arming, so it cannot report what arming
        // would have done -- that is the same shape as the defect this whole
        // fix exists downstream of.
        expect(sentence).not.toMatch(/would be refused at the arming step/);
        // FIX F5: "Nothing has been changed." was false at the command level --
        // the cooperative wrap has already rewritten config by this point. The
        // claim is scoped to what this flow did not do.
        expect(sentence).not.toMatch(/Nothing has been changed/);
        expect(sentence).toMatch(
          /No account was created, nothing was re-homed, and no Castle Wall change was made by this run\./,
        );
        expect(sentence).toMatch(/--unprotect-egress-gate/);
      }
    });

    it("F2: a LIVE gate and an UNCERTAIN surface get different sentences and different remedies", () => {
      const live = describeExclusiveRoutingResidueRefusal({
        kind: "kept-live",
        reason: "the S5-1 anchor registry still has an entry for uid 503",
      });
      // The common instance of this refusal is a HEALTHY, correctly armed host.
      // Telling that operator to unprotect tells them to de-confine a working
      // agent and leave the harness parked and down, so "nothing needs doing"
      // comes first and the cost of the teardown is stated.
      expect(live).toMatch(/already has exclusive-egress confinement in place/);
      expect(live).toMatch(/If the confinement already in place is the one you want, nothing needs doing/);
      expect(live).toMatch(/leaves the harness parked and down/);
      expect(live).not.toMatch(/could NOT be shown to be stale/);

      const uncertain = describeExclusiveRoutingResidueRefusal({
        kind: "kept-uncertain",
        reason: "the S5-1 anchor registry is in an uncertain state (dirty=true, quarantined=0)",
      });
      expect(uncertain).toMatch(/could NOT be shown to be stale/);
      expect(uncertain).toMatch(/--repair-egress-gate/);
      expect(uncertain).not.toMatch(/nothing needs doing/);
    });

    it("F3: the unknown-subject refusal names the verb that actually works when the agent account is gone", () => {
      // The accepted wrong-refuse. Its old justification -- "it names the verb
      // that clears it" -- was false: both named verbs resolved their subject
      // with lookupAccountUid("_sanctuary-hermes"), so with the account gone
      // unprotect exited 2 ("nothing to unprotect") and repair exited 2 telling
      // the operator to run the very command this gate refuses. The sentence
      // now names ONE verb, and that verb has a no-account residue teardown.
      const sentence = describeExclusiveRoutingResidueRefusal({
        kind: "kept-unknown-subject",
        reason: "this run has not resolved an agent uid to scope it against",
        markerAgentUid: 707,
      });
      expect(sentence).toMatch(/marker for agent uid 707/);
      expect(sentence).toMatch(/resolved no agent uid to scope it against/);
      expect(sentence).toMatch(/--unprotect-egress-gate/);
      expect(sentence).toMatch(/removes this residue even when the dedicated agent account is gone/);
      // Repair is NOT offered here: it exits 2 in exactly this state.
      expect(sentence).not.toMatch(/--repair-egress-gate/);
    });

    it("F4: the op boundary is a TOTAL union -- a keep can no longer be spelled by omission", () => {
      // The op used to return `{ reconciled: boolean; reason?: string }`, so a
      // wiring that KEPT a marker but omitted the reason read as "clear" and the
      // run walked into the wedge. That is the two-fields-that-can-disagree
      // shape #1006 deleted at the park boundary. Every verdict now carries its
      // own discriminant, and the refusal narrowing is a switch: a new kind is
      // a type error at this seam, not a silent "keep going".
      expect(exclusiveRoutingResidueRefusal({ kind: "clear" })).toBeUndefined();
      expect(exclusiveRoutingResidueRefusal({ kind: "orphaned", detail: "d" })).toBeUndefined();
      expect(exclusiveRoutingResidueRefusal({ kind: "reconciled", detail: "d" })).toBeUndefined();
      expect(exclusiveRoutingResidueRefusal({ kind: "kept-live", reason: "r" })).toMatchObject({ kind: "kept-live" });
      expect(exclusiveRoutingResidueRefusal({ kind: "kept-uncertain", reason: "r" })).toMatchObject({
        kind: "kept-uncertain",
      });
      expect(
        exclusiveRoutingResidueRefusal({ kind: "kept-unknown-subject", reason: "r", markerAgentUid: 707 }),
      ).toMatchObject({ kind: "kept-unknown-subject" });
      expect(exclusiveRoutingResidueRefusal({ kind: "unreadable", detail: "d" })).toMatchObject({
        kind: "unreadable",
      });
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

    it("a FAILED restore is LOUD: it prints the OBSERVED run state and the recovery step that follows from it", async () => {
      // FIX-ROUND 6. This test used to be titled "names the agent as stopped
      // and gives a command" and pinned the sentence "This run did NOT bring
      // it back up, and did not verify its run state" plus an unconditional
      // "re-run protect --hermes". Round 4 had already stopped the note naming
      // the agent as stopped; the title and the ungated command survived, and
      // the round-6 gate reproduced that exact pair being printed over a
      // harness the run had observed ALIVE. The note is now the observation.
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: false,
          wasRunning: true,
          harnessRestarted: false,
          problems: ["launchctl bootstrap exited 5"],
          runState: await observedRunState(PARKED_STATUS),
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).toMatch(/could NOT be fully restored/);
      expect(reason).toMatch(/launchctl bootstrap exited 5/);
      // The run state is the OBSERVED one, and the recovery step follows from
      // it: over a genuine park, "bring it back up" is the right instruction.
      expect(reason).toMatch(/The agent is PARKED \(not running\)/);
      expect(reason).toMatch(/to bring it back up/);
      // ...and the claim the round-6 gate falsified is gone for good.
      expect(reason).not.toMatch(/did not verify its run state/i);
      // The ORIGINAL abort reason is never displaced by the cleanup note.
      expect(reason).toMatch(/castle-wall enable exited 1/);
    });

    // ────────────────────────────────────────────────────────────────────
    // FIX-ROUND 6 (2026-07-19) -- THE ELEVENTH INSTANCE.
    //
    // The caller-side chokepoint routed the restore DECISION to one place and
    // rebuilt the CLAIM at each consumer. The production op spent a full
    // 20-sample settle loop, received `alive (pid 9001)`, and DISCARDED it at
    // the op boundary, whose result type had no run-state field -- after which
    // this note told the operator the run "did not verify its run state" and
    // sent them to re-run over the live agent.
    //
    // These assert on the RENDERED operator message, driven through the real
    // flow, over a modelled harness that is alive on every sample.
    // ────────────────────────────────────────────────────────────────────

    it("R6: an OBSERVED LIVE harness is never described as unverified, and never draws a bring-it-back-up", async () => {
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: false,
          wasRunning: true,
          harnessRestarted: false,
          problems: ["the agent harness was stopped by this run and could NOT be restarted: bootstrap exited 5"],
          runState: await observedRunState(LIVE_STATUS),
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);

      // 1. The falsehood: an observation DID occur, so the run may not say none did.
      expect(reason, "the round-6 HIGH").not.toMatch(/did not verify its run state/i);
      // 2. The imperative: following it stands a live agent down again.
      expect(reason, "the round-5 HIGH's imperative, at the sibling site").not.toMatch(
        /to bring it back up/i,
      );
      // 3. What the operator gets instead: the observation, and advice premised on it.
      expect(reason).toMatch(/The agent is RUNNING \(pid 9001\)/);
      expect(reason).toMatch(/Do NOT re-run/);
      // The original abort still wins the message.
      expect(reason).toMatch(/castle-wall enable exited 1/);
    });

    it("R6: the REAL revert's observed claim survives the production op projection end to end", async () => {
      // The gate's probes K + K2, as a regression test. K drove the REAL
      // `revertParkedHarnessInstall` over a crash-loop survivor (launchd
      // returns pid 9001 on every sample) and showed the claim being dropped
      // by the projection at `wrap/auto-provision.ts`; K2 fed that projection
      // into the REAL `runProvisionFlow` and captured the false sentence.
      // Nothing here is a mock of the thing under test: the claim comes from
      // the real revert, and the prose from the real flow.
      let statusCalls = 0;
      const revertOps: ParkedInstallRevertOps = {
        harnessStatus: async (): Promise<HarnessDaemonStatus> => {
          statusCalls += 1;
          return LIVE_STATUS;
        },
        sleepMs: async () => {},
        restoreRunningHarness: async () => {
          throw new Error("launchctl bootstrap exited 5");
        },
        clearJobDisable: async () => {},
        writeFile: async () => {},
        readFile: async () => "<plist>prior</plist>",
        removeFile: async () => {},
      };
      const revert = await revertParkedHarnessInstall(
        {
          wasInstalled: true,
          wasRunning: true,
          preexistingJobModified: true,
          priorPlistContent: "<plist>prior</plist>",
          plistPath: HARNESS_LOCATOR.plistPath,
          harnessLabel: HARNESS_LOCATOR.harnessLabel,
        },
        revertOps,
      );

      // Ground truth: the run really did read the harness, and read it alive.
      expect(statusCalls).toBeGreaterThan(0);
      expect(revert.runState?.claim.state).toBe("alive");
      // The invariant that makes the projection below safe.
      expect(revert.runState !== undefined).toBe(runStateOwed(revert));

      // THE REAL PROJECTION -- the same function `wrap/auto-provision.ts`
      // calls, not a copy of it. Copying it here is what the production op did,
      // and the copy is where the claim was lost.
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => projectRevertToRestoreReport(revert)),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);

      expect(reason).toMatch(/The agent is RUNNING \(pid 9001\)/);
      expect(reason).not.toMatch(/did not verify its run state/i);
      expect(reason).not.toMatch(/to bring it back up/i);
      expect(reason).toMatch(/Do NOT re-run/);
    });

    it("R6: a THROWING restore op yields an explicitly WEAKENED claim, not an invented one", async () => {
      // The op threw, so nothing was observed -- but the old fallback
      // synthesized `wasRunning: true` with no claim, which under
      // `runStateOwed` OWES a run-state sentence and had none. That is how the
      // renderer came to invent one. "I could not tell" is now said out loud.
      const printed: string[] = [];
      const ops = stoodDownOps({
        print: vi.fn((line: string) => printed.push(line)),
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => {
          throw new Error("EROFS");
        }),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).toMatch(/EROFS/);
      expect(reason).toMatch(/could NOT be established/);
      expect(reason).toMatch(/Treat the agent as POSSIBLY RUNNING/);
      // No park was observed, so no bring-it-back-up may be issued.
      expect(reason).not.toMatch(/to bring it back up/i);
      expect(reason).toMatch(/Establish the harness's state before re-running/);
    });

    it("R6: a job that was NOT running before gets no run-state claim and no restart instruction", async () => {
      // The other direction of the same rule. `runStateOwed` is false here, so
      // there is no claim -- and a note that invented "re-run to bring it back
      // up" would be the identical defect with the sign flipped.
      const ops = stoodDownOps({
        arm: vi.fn(async () => ({ ok: false as const, error: "castle-wall enable exited 1" })),
        restoreStoodDownHarness: vi.fn(async () => ({
          restored: false,
          wasRunning: false,
          harnessRestarted: false,
          problems: ["the parked harness plist is STILL PRESENT after removing it"],
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).toMatch(/STILL PRESENT/);
      expect(reason).toMatch(/Nothing was running before this run began/);
      expect(reason).not.toMatch(/to bring it back up/i);
      // ...and it makes no claim about what the agent is doing NOW.
      expect(reason).not.toMatch(/The agent is/);
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
          problems: ["the agent harness was running before this run and this run did not restart it"],
          runState: await observedRunState(PARKED_STATUS),
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).not.toMatch(/was restarted/i);
      expect(reason).not.toMatch(/restored to its previous state/i);
      // FIX-ROUND 6: this used to pin "did not verify its run state" -- a
      // sentence that was false whenever the op HAD verified it. What the note
      // owes the operator is the observation, and it is here.
      expect(reason).toMatch(/The agent is PARKED \(not running\)/);
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
          runState: await observedRunState(PARKED_STATUS),
        })),
      });
      const result = await runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops);
      const reason = String((result as { reason: string }).reason);
      expect(reason).not.toMatch(/was restarted/i);
      expect(reason).toMatch(/could NOT be fully restored/);
      expect(reason).toMatch(/The agent is PARKED \(not running\)/);
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
          runState: await observedRunState(PARKED_STATUS),
        })),
        // `armed` carries no `reason`. It cannot co-occur with a parked
        // install today, which is exactly why the silence went unnoticed --
        // so drive it explicitly rather than trust that it stays unreachable.
        exclusiveEgress: undefined,
      });
      const coarse = await runProvisionFlow(baseCtx({ fineGrainedDeclared: false }), reasonless);
      expect(coarse.kind).toBe("armed");
      expect(printed.join("\n")).toMatch(/could NOT be fully restored/);
      expect(printed.join("\n")).toMatch(/The agent is PARKED \(not running\)/);
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
          runState: await observedRunState(PARKED_STATUS),
        })),
      });
      await expect(runProvisionFlow(baseCtx({ fineGrainedDeclared: true }), ops)).rejects.toThrow(/dscl blew up/);
      // The original error still wins as the outcome, but the operator is no
      // longer left to discover their agent is down by noticing it is down.
      expect(printed.join("\n")).toMatch(/could NOT be fully restored/);
      expect(printed.join("\n")).toMatch(/The agent is PARKED \(not running\)/);
    });
  });
});
