/**
 * Unified Protect Slice 5 S5-6: the exclusive-egress arming stage, the
 * repair verb sequence, and the boot release driver -- every abort/degrade
 * branch driven host-free through injected ops, with fail-closed assertions
 * (no path may leave the flow claiming green without the barrier's released
 * outcome; every degrade is audited + distinct).
 */

import { describe, it, expect, vi } from "vitest";

import {
  runExclusiveEgressArming,
  runEgressGateRepair,
  runBootExclusiveEgressRelease,
  EXCLUSIVE_EGRESS_ARMED_AUDIT_OP,
  EXCLUSIVE_EGRESS_DEGRADED_AUDIT_OP,
  EGRESS_GATE_REPAIR_AUDIT_OP,
  EGRESS_GATE_REPAIR_OVERRIDE_AUDIT_OP,
  EGRESS_GATE_REPAIR_QUARANTINE_AUDIT_OP,
  EGRESS_GATE_REPAIR_REFUSED_AUDIT_OP,
  type ExclusiveEgressArmOps,
  type EgressGateRepairOps,
} from "../../../src/castle-wall/provision/exclusive-arm.js";
import type { ReleaseBarrierOutcome } from "../../../src/egress-gate/release-barrier.js";
import { assessHarnessParked, type ParkedClaim } from "../../../src/egress-gate/parked-claim.js";
import type { HarnessDaemonStatus } from "../../../src/egress-gate/harness-daemon.js";

const AGENT_UID = 502;
const COMMITTED = { generation_id: 7, agent_uid: AGENT_UID, gate_port: 49152 };
const RELEASED: ReleaseBarrierOutcome = { kind: "released", generation_id: 7 };

/**
 * A `ParkedClaim` cannot be hand-rolled -- the type is branded so that
 * `assessHarnessParked` is its only constructor. Tests therefore build claims
 * the same way production does: by MODELLING launchd and letting the real
 * chokepoint classify it. That is the point, not a nuisance: a test that could
 * fabricate a "parked" claim would be able to assert the exact falsehood these
 * four gate rounds kept shipping.
 */
async function claimFrom(status: Partial<HarnessDaemonStatus>): Promise<ParkedClaim> {
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

/** A barrier abort over a genuinely stopped harness. */
async function parkedBarrierOutcome(
  status: Partial<HarnessDaemonStatus> = {},
): Promise<ReleaseBarrierOutcome> {
  return {
    kind: "parked",
    stage: "gate-verify",
    reason: "gate verification failed: oracle not live",
    holdFileRemoved: true,
    jobDisabled: true,
    cleanupErrors: [],
    parkedClaim: await claimFrom(status),
  };
}

function armOps(overrides: Partial<ExclusiveEgressArmOps> = {}): ExclusiveEgressArmOps {
  return {
    bringUpGeneration: vi.fn(async () => ({ ...COMMITTED })),
    runReleaseSequence: vi.fn(async () => RELEASED),
    restoreCoarseComposition: vi.fn(async () => undefined),
    startHarnessCoarse: vi.fn(async () => undefined),
    assessHarnessParked: vi.fn(async () => claimFrom({})),
    audit: vi.fn(async () => undefined),
    print: vi.fn(),
    ...overrides,
  };
}

describe("runExclusiveEgressArming", () => {
  it("success: bring-up then release -> exclusive-armed, audited, no degrade ops touched", async () => {
    const ops = armOps();
    const outcome = await runExclusiveEgressArming({ agentUid: AGENT_UID }, ops);
    expect(outcome).toEqual({ kind: "exclusive-armed", generationId: 7 });
    expect(ops.runReleaseSequence).toHaveBeenCalledWith(COMMITTED);
    expect(ops.restoreCoarseComposition).not.toHaveBeenCalled();
    expect(ops.startHarnessCoarse).not.toHaveBeenCalled();
    expect(ops.audit).toHaveBeenCalledWith(
      EXCLUSIVE_EGRESS_ARMED_AUDIT_OP,
      expect.objectContaining({ agent_uid: AGENT_UID, generation_id: 7 }),
    );
  });

  it("released-repark-failed maps to the DISTINCT amber outcome (never plain armed)", async () => {
    const ops = armOps({
      runReleaseSequence: vi.fn(async () => ({
        kind: "released-repark-failed" as const,
        generation_id: 7,
        reparkError: "launchctl disable exited 5",
      })),
    });
    const outcome = await runExclusiveEgressArming({ agentUid: AGENT_UID }, ops);
    expect(outcome).toEqual({
      kind: "exclusive-armed-repark-failed",
      generationId: 7,
      reparkError: "launchctl disable exited 5",
    });
    // Never silently degraded and never plain-green.
    expect(ops.restoreCoarseComposition).not.toHaveBeenCalled();
  });

  it("bring-up throw -> degrade-loud: coarse restore + coarse start + degraded audit, distinct outcome", async () => {
    const ops = armOps({
      bringUpGeneration: vi.fn(async () => {
        throw new Error("pfctl -E exited 1");
      }),
    });
    const outcome = await runExclusiveEgressArming({ agentUid: AGENT_UID }, ops);
    expect(outcome).toMatchObject({
      kind: "degraded-coarse-active",
      stage: "bring-up",
      coarseCompositionRestored: true,
      harness: { disposition: "started-coarse" },
      cleanupErrors: [],
    });
    expect((outcome as { reason: string }).reason).toContain("pfctl -E exited 1");
    expect(ops.restoreCoarseComposition).toHaveBeenCalledTimes(1);
    expect(ops.startHarnessCoarse).toHaveBeenCalledTimes(1);
    expect(ops.audit).toHaveBeenCalledWith(
      EXCLUSIVE_EGRESS_DEGRADED_AUDIT_OP,
      expect.objectContaining({
        agent_uid: AGENT_UID,
        stage: "bring-up",
        coarse_composition_restored: true,
        harness_run_state: "running-coarse",
      }),
    );
    // The release barrier must never run after a failed bring-up.
    expect(ops.runReleaseSequence).not.toHaveBeenCalled();
  });

  it("cross-uid commit is refused (degrade), never released", async () => {
    const ops = armOps({
      bringUpGeneration: vi.fn(async () => ({ ...COMMITTED, agent_uid: 999 })),
    });
    const outcome = await runExclusiveEgressArming({ agentUid: AGENT_UID }, ops);
    expect(outcome.kind).toBe("degraded-coarse-active");
    expect(ops.runReleaseSequence).not.toHaveBeenCalled();
  });

  it("release parked -> degrade-loud, carrying the barrier's cleanup errors forward", async () => {
    const ops = armOps({
      runReleaseSequence: vi.fn(async () => ({
        ...(await parkedBarrierOutcome()),
        cleanupErrors: ["disable failed: launchctl timed out"],
      })),
    });
    const outcome = await runExclusiveEgressArming({ agentUid: AGENT_UID }, ops);
    expect(outcome).toMatchObject({
      kind: "degraded-coarse-active",
      stage: "release",
      coarseCompositionRestored: true,
      harness: { disposition: "started-coarse" },
    });
    expect((outcome as { cleanupErrors: string[] }).cleanupErrors).toContain(
      "disable failed: launchctl timed out",
    );
    expect((outcome as { reason: string }).reason).toContain("gate-verify");
  });

  it("release sequence THROW is fail-closed to degrade (never an unhandled escape)", async () => {
    const ops = armOps({
      runReleaseSequence: vi.fn(async () => {
        throw new Error("launchctl vanished");
      }),
    });
    const outcome = await runExclusiveEgressArming({ agentUid: AGENT_UID }, ops);
    expect(outcome).toMatchObject({ kind: "degraded-coarse-active", stage: "release" });
    expect((outcome as { reason: string }).reason).toContain("launchctl vanished");
  });

  it("degrade path: coarse restore FAILS -> harness is NOT started (agent stays parked), loudly reported", async () => {
    const ops = armOps({
      bringUpGeneration: vi.fn(async () => {
        throw new Error("boom");
      }),
      restoreCoarseComposition: vi.fn(async () => {
        throw new Error("republish failed");
      }),
    });
    const outcome = await runExclusiveEgressArming({ agentUid: AGENT_UID }, ops);
    expect(outcome).toMatchObject({
      kind: "degraded-coarse-active",
      coarseCompositionRestored: false,
      harness: { disposition: "not-started" },
    });
    // FAIL-CLOSED: never start the agent over a manifest that may still be
    // exclusive-scoped with no live gate.
    expect(ops.startHarnessCoarse).not.toHaveBeenCalled();
    expect((outcome as { cleanupErrors: string[] }).cleanupErrors.join(" ")).toContain(
      "republish failed",
    );
    // The degraded audit still fires with the honest false flags.
    expect(ops.audit).toHaveBeenCalledWith(
      EXCLUSIVE_EGRESS_DEGRADED_AUDIT_OP,
      expect.objectContaining({
        coarse_composition_restored: false,
        harness_disposition: "not-started",
        harness_run_state: "parked",
      }),
    );
  });

  it("degrade path: coarse start FAILS -> not-started with a PROBED claim, restore still true", async () => {
    const ops = armOps({
      bringUpGeneration: vi.fn(async () => {
        throw new Error("boom");
      }),
      startHarnessCoarse: vi.fn(async () => {
        throw new Error("bootstrap refused");
      }),
    });
    const outcome = await runExclusiveEgressArming({ agentUid: AGENT_UID }, ops);
    expect(outcome).toMatchObject({
      kind: "degraded-coarse-active",
      coarseCompositionRestored: true,
      harness: { disposition: "not-started" },
    });
    expect((outcome as { cleanupErrors: string[] }).cleanupErrors.join(" ")).toContain(
      "bootstrap refused",
    );
    // Fix-round 4: the run state came from the PROBE, not from the start
    // having thrown.
    expect(ops.assessHarnessParked).toHaveBeenCalledTimes(1);
  });
});

function repairOps(overrides: Partial<EgressGateRepairOps> = {}): EgressGateRepairOps {
  return {
    diffTransientPfRules: vi.fn(async () => ({ foreign: [] })),
    parkHarness: vi.fn(async () => undefined),
    verifyParkedPersistent: vi.fn(async () => ({ ok: true as const })),
    repairQuarantinedRegistry: vi.fn(async () => ({
      repaired: false,
      findings: [],
      forensicPath: null,
      remaining: [],
    })),
    recoverGeneration: vi.fn(async () => undefined),
    bringUpGeneration: vi.fn(async () => ({ ...COMMITTED })),
    runReleaseSequence: vi.fn(async () => RELEASED),
    audit: vi.fn(async () => undefined),
    print: vi.fn(),
    ...overrides,
  };
}

const REPAIR_CTX = { agentUid: AGENT_UID, isTty: true, overrideTransientPfRules: false };

describe("runEgressGateRepair", () => {
  it("clean path: diff clean -> recover -> bring-up -> release -> repaired + audited", async () => {
    const ops = repairOps();
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toEqual({ kind: "repaired", generationId: 7 });
    expect(ops.recoverGeneration).toHaveBeenCalledTimes(1);
    expect(ops.audit).toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_AUDIT_OP,
      expect.objectContaining({ agent_uid: AGENT_UID, generation_id: 7, override_used: false }),
    );
  });

  it("MED-7: foreign transient rules with NO override -> REFUSES before any mutation, audited", async () => {
    const ops = repairOps({
      diffTransientPfRules: vi.fn(async () => ({ foreign: ["pass in quick on utun3 all"] })),
    });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toEqual({
      kind: "refused-foreign-transient-rules",
      foreign: ["pass in quick on utun3 all"],
    });
    // NO mutation op may run on a refusal.
    expect(ops.recoverGeneration).not.toHaveBeenCalled();
    expect(ops.bringUpGeneration).not.toHaveBeenCalled();
    expect(ops.runReleaseSequence).not.toHaveBeenCalled();
    expect(ops.audit).toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_REFUSED_AUDIT_OP,
      expect.objectContaining({ foreign_rules: ["pass in quick on utun3 all"] }),
    );
  });

  it("MED-7 override: TTY + --override-transient-pf-rules proceeds, with the override AUDITED BEFORE any mutation", async () => {
    const calls: string[] = [];
    const ops = repairOps({
      diffTransientPfRules: vi.fn(async () => ({ foreign: ["pass in quick on utun3 all"] })),
      audit: vi.fn(async (op: string) => {
        calls.push(`audit:${op}`);
      }),
      recoverGeneration: vi.fn(async () => {
        calls.push("recover");
      }),
    });
    const outcome = await runEgressGateRepair(
      { ...REPAIR_CTX, overrideTransientPfRules: true },
      ops,
    );
    expect(outcome).toMatchObject({ kind: "repaired", generationId: 7 });
    const overrideIdx = calls.indexOf(`audit:${EGRESS_GATE_REPAIR_OVERRIDE_AUDIT_OP}`);
    const recoverIdx = calls.indexOf("recover");
    expect(overrideIdx).toBeGreaterThanOrEqual(0);
    expect(recoverIdx).toBeGreaterThan(overrideIdx);
    expect(ops.audit).toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_AUDIT_OP,
      expect.objectContaining({ override_used: true }),
    );
  });

  it("override WITHOUT a TTY is refused unconditionally (never proceeds, never diffs)", async () => {
    const ops = repairOps({
      diffTransientPfRules: vi.fn(async () => ({ foreign: [] })),
    });
    const outcome = await runEgressGateRepair(
      { ...REPAIR_CTX, isTty: false, overrideTransientPfRules: true },
      ops,
    );
    expect(outcome).toEqual({ kind: "refused-non-tty-override" });
    expect(ops.diffTransientPfRules).not.toHaveBeenCalled();
    expect(ops.recoverGeneration).not.toHaveBeenCalled();
  });

  it("a THROWING drift diff refuses (never hook-installs blind), audited", async () => {
    const ops = repairOps({
      diffTransientPfRules: vi.fn(async () => {
        throw new Error("pfctl -sr exited 1");
      }),
    });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toMatchObject({ kind: "refused-diff-unavailable" });
    expect((outcome as { reason: string }).reason).toContain("pfctl -sr exited 1");
    expect(ops.recoverGeneration).not.toHaveBeenCalled();
    expect(ops.audit).toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_REFUSED_AUDIT_OP,
      expect.objectContaining({ reason: expect.stringContaining("pfctl -sr exited 1") }),
    );
  });

  it("recover / bring-up / release failures each map to repair-failed at the right stage (agent stays parked)", async () => {
    for (const [stage, overrides] of [
      ["recover", { recoverGeneration: vi.fn(async () => Promise.reject(new Error("locked"))) }],
      ["bring-up", { bringUpGeneration: vi.fn(async () => Promise.reject(new Error("bind failed"))) }],
      ["release", { runReleaseSequence: vi.fn(async () => Promise.reject(new Error("launchctl"))) }],
    ] as const) {
      const ops = repairOps(overrides as Partial<EgressGateRepairOps>);
      const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
      expect(outcome).toMatchObject({
        kind: "repair-failed",
        stage,
        parkedStateVerified: true,
        parkedStateProblems: [],
      });
    }
  });

  it("fix-round BLOCKER-3: the harness is PARKED (verified) after the drift gate and BEFORE any mutation", async () => {
    const calls: string[] = [];
    const ops = repairOps({
      diffTransientPfRules: vi.fn(async () => {
        calls.push("diff");
        return { foreign: [] };
      }),
      parkHarness: vi.fn(async () => {
        calls.push("park");
      }),
      recoverGeneration: vi.fn(async () => {
        calls.push("recover");
      }),
      bringUpGeneration: vi.fn(async () => {
        calls.push("bring-up");
        return { ...COMMITTED };
      }),
    });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toMatchObject({ kind: "repaired" });
    expect(calls).toEqual(["diff", "park", "recover", "bring-up"]);
  });

  it("fix-round BLOCKER-3: a park failure is repair-failed at stage 'park'; NO mutation runs", async () => {
    const ops = repairOps({
      parkHarness: vi.fn(async () => {
        throw new Error("harness still reports RUNNING");
      }),
      verifyParkedPersistent: vi.fn(async () => ({ ok: false as const, problems: ["pid 4242 alive"] })),
    });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toMatchObject({
      kind: "repair-failed",
      stage: "park",
      parkedStateVerified: false,
      parkedStateProblems: ["pid 4242 alive"],
    });
    expect((outcome as { reason: string }).reason).toContain("harness still reports RUNNING");
    expect(ops.recoverGeneration).not.toHaveBeenCalled();
    expect(ops.bringUpGeneration).not.toHaveBeenCalled();
    expect(ops.runReleaseSequence).not.toHaveBeenCalled();
  });

  it("fix-round BLOCKER-3 + fix-round-2 HIGH-2: repair-failed never claims PARKED unverified, and the problems are ENUMERATED", async () => {
    const notOk = repairOps({
      runReleaseSequence: vi.fn(async () => await parkedBarrierOutcome()),
      verifyParkedPersistent: vi.fn(async () => ({
        ok: false as const,
        // The HIGH-2 scenario: stopped NOW, but stale release material remains.
        problems: [
          "launchd's override database does not show the job disabled",
          "the release hold file is still present (stale release material)",
        ],
      })),
    });
    const outcome1 = await runEgressGateRepair(REPAIR_CTX, notOk);
    expect(outcome1).toMatchObject({
      kind: "repair-failed",
      stage: "release",
      parkedStateVerified: false,
    });
    expect((outcome1 as { parkedStateProblems: string[] }).parkedStateProblems).toHaveLength(2);
    expect((outcome1 as { parkedStateProblems: string[] }).parkedStateProblems.join(" ")).toContain(
      "override database",
    );
    const throwing = repairOps({
      runReleaseSequence: vi.fn(async () => await parkedBarrierOutcome()),
      verifyParkedPersistent: vi.fn(async () => {
        throw new Error("probe died");
      }),
    });
    const outcome2 = await runEgressGateRepair(REPAIR_CTX, throwing);
    expect(outcome2).toMatchObject({ kind: "repair-failed", parkedStateVerified: false });
    expect((outcome2 as { parkedStateProblems: string[] }).parkedStateProblems.join(" ")).toContain(
      "probe died",
    );
  });

  it("fix-round BLOCKER-3: refusals never touch the harness (no park on foreign rules / non-TTY / diff failure)", async () => {
    for (const overrides of [
      { diffTransientPfRules: vi.fn(async () => ({ foreign: ["pass in quick on utun3 all"] })) },
      {
        diffTransientPfRules: vi.fn(async () => {
          throw new Error("pfctl gone");
        }),
      },
    ]) {
      const ops = repairOps(overrides as Partial<EgressGateRepairOps>);
      await runEgressGateRepair(REPAIR_CTX, ops);
      expect(ops.parkHarness).not.toHaveBeenCalled();
    }
    const nonTty = repairOps();
    await runEgressGateRepair({ ...REPAIR_CTX, isTty: false, overrideTransientPfRules: true }, nonTty);
    expect(nonTty.parkHarness).not.toHaveBeenCalled();
  });

  it("a PARKED release outcome is repair-failed (never repaired without the barrier's released verdict)", async () => {
    const ops = repairOps({ runReleaseSequence: vi.fn(async () => await parkedBarrierOutcome()) });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toMatchObject({ kind: "repair-failed", stage: "release" });
    expect((outcome as { reason: string }).reason).toContain("gate-verify");
    // The success audit must not fire.
    expect(ops.audit).not.toHaveBeenCalledWith(EGRESS_GATE_REPAIR_AUDIT_OP, expect.anything());
  });

  it("repaired-repark-failed is a DISTINCT non-clean outcome", async () => {
    const ops = repairOps({
      runReleaseSequence: vi.fn(async () => ({
        kind: "released-repark-failed" as const,
        generation_id: 7,
        reparkError: "disable failed",
      })),
    });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toEqual({
      kind: "repaired-repark-failed",
      generationId: 7,
      reparkError: "disable failed",
    });
  });
});

describe("runBootExclusiveEgressRelease", () => {
  it("per-agent isolation: one parked/throwing agent never blocks or releases another; all audited; never throws", async () => {
    const releaseAgent = vi.fn(async (uid: number): Promise<ReleaseBarrierOutcome> => {
      if (uid === 501) return RELEASED;
      if (uid === 502) return await parkedBarrierOutcome();
      throw new Error("registry corrupt for 503");
    });
    const audit = vi.fn(async () => undefined);
    const print = vi.fn();
    const results = await runBootExclusiveEgressRelease(
      [{ agent_uid: 501 }, { agent_uid: 502 }, { agent_uid: 503 }],
      { releaseAgent, audit, print },
    );
    expect(results).toHaveLength(3);
    expect(results[0]!.outcome).toEqual({ kind: "released", generationId: 7 });
    // The barrier-parked agent's outcome carries the REAL re-park flags
    // (fix-round-2 BLOCKER-1).
    expect(results[1]!.outcome).toMatchObject({
      kind: "parked",
      reason: expect.stringContaining("gate-verify"),
      holdFileRemoved: true,
      jobDisabled: true,
      cleanupErrors: [],
      parkedClaim: { state: "parked" },
    });
    // Fix-round-2 BLOCKER-1: a THROWING release attempt is NOT a synthetic
    // "parked" -- no re-park op verifiably ran, and the outcome says so.
    expect(results[2]!.outcome.kind).toBe("park-not-verified");
    expect((results[2]!.outcome as { reason: string }).reason).toContain("registry corrupt");
    expect(audit).toHaveBeenCalledTimes(3);
    // The parked agent gets the LOUD repair guidance; the not-verified one
    // gets the LOUDER possibly-startable warning.
    const printed = print.mock.calls.map((c) => String(c[0])).join("\n");
    expect(printed).toContain("is PARKED (not running)");
    expect(printed).toContain("NOT verified");
    expect(printed).toContain("possibly startable");
    expect(printed).toContain("--repair-egress-gate");
  });

  it("fix-round-2 BLOCKER-1: parked cleanup FAILURES surface in the print and the audit record, never swallowed", async () => {
    const audit = vi.fn(async () => undefined);
    const print = vi.fn();
    const results = await runBootExclusiveEgressRelease([{ agent_uid: 502 }], {
      releaseAgent: async () => ({
        ...(await parkedBarrierOutcome()),
        jobDisabled: false,
        cleanupErrors: ["disable failed: launchctl exited 5: override db locked"],
      }),
      audit,
      print,
    });
    expect(results[0]!.outcome).toMatchObject({
      kind: "parked",
      jobDisabled: false,
      cleanupErrors: ["disable failed: launchctl exited 5: override db locked"],
    });
    const printed = print.mock.calls.map((c) => String(c[0])).join("\n");
    expect(printed).toContain("re-park ops reported failures");
    expect(printed).toContain("override db locked");
    expect(audit).toHaveBeenCalledWith(
      "exclusive_egress_boot_release",
      expect.objectContaining({
        agent_uid: 502,
        outcome: "parked",
        hold_file_removed: true,
        job_disabled: false,
        cleanup_errors: ["disable failed: launchctl exited 5: override db locked"],
      }),
    );
  });

  it("repark-failed boot release is surfaced as a WARNING, never a clean green line", async () => {
    const print = vi.fn();
    const results = await runBootExclusiveEgressRelease([{ agent_uid: 501 }], {
      releaseAgent: async () => ({
        kind: "released-repark-failed" as const,
        generation_id: 3,
        reparkError: "disable failed",
      }),
      audit: async () => undefined,
      print,
    });
    expect(results[0]!.outcome).toMatchObject({ kind: "released-repark-failed" });
    expect(print.mock.calls.map((c) => String(c[0])).join("\n")).toContain("WARNING");
  });
});

describe("runEgressGateRepair quarantine-repair stage (fix-round-4 P2)", () => {
  const QUARANTINE_RESULT = {
    repaired: true,
    findings: [
      {
        index: 1,
        reason: "malformed committed entry (failed the fail-closed entry validation)",
        agent_uid: 601,
        disposition: "removed" as const,
      },
      {
        index: 2,
        reason: "malformed committed entry (failed the fail-closed entry validation)",
        agent_uid: 602,
        disposition: "tombstoned" as const,
      },
    ],
    forensicPath: "/var/db/sanctuary/egress-anchor-registry.json.quarantine-t.json",
    remaining: [{ agent_uid: AGENT_UID, gate_port: 49152, fortress_path: "/f/a" }],
  };

  it("runs AFTER park and BEFORE any other registry mutation; a repaired quarantine is audited + loud, then the sequence proceeds", async () => {
    const calls: string[] = [];
    const printed: string[] = [];
    const ops = repairOps({
      parkHarness: vi.fn(async () => {
        calls.push("park");
      }),
      repairQuarantinedRegistry: vi.fn(async () => {
        calls.push("quarantine");
        return QUARANTINE_RESULT;
      }),
      recoverGeneration: vi.fn(async () => {
        calls.push("recover");
      }),
      print: vi.fn((line: string) => {
        printed.push(line);
      }),
    });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toEqual({ kind: "repaired", generationId: 7 });
    // Ordering: the coded quarantine path must precede every wholesale-
    // normalizing mutation (pre-fix, recover/bring-up threw on the malformed
    // entry before repair could rewrite anything).
    expect(calls).toEqual(["park", "quarantine", "recover"]);
    expect(ops.audit).toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_QUARANTINE_AUDIT_OP,
      expect.objectContaining({
        agent_uid: AGENT_UID,
        forensic_path: QUARANTINE_RESULT.forensicPath,
        quarantined: [
          expect.objectContaining({ index: 1, agent_uid: 601, disposition: "removed" }),
          expect.objectContaining({ index: 2, agent_uid: 602, disposition: "tombstoned" }),
        ],
      }),
    );
    // The log names what was quarantined, where the forensic copy lives, and
    // the re-provision debt -- per finding.
    const log = printed.join("\n");
    expect(log).toContain("entry #1 (uid 601)");
    expect(log).toContain("REMOVED");
    expect(log).toContain("entry #2 (uid 602)");
    expect(log).toContain("TOMBSTONED");
    expect(log).toContain(QUARANTINE_RESULT.forensicPath);
    expect(log).toContain("RE-PROVISIONED");
  });

  it("a removed structurally VALID duplicate is LOUD: kept + removed generations named in the log and the audit record (fix-round-5 P1)", async () => {
    const printed: string[] = [];
    const ops = repairOps({
      repairQuarantinedRegistry: vi.fn(async () => ({
        ...QUARANTINE_RESULT,
        findings: [
          {
            index: 1,
            reason: "duplicate committed agent_uid 502",
            agent_uid: 502,
            disposition: "removed" as const,
            duplicate: { kept_generation_id: 7, removed_generation_id: 8 },
          },
        ],
      })),
      print: vi.fn((line: string) => {
        printed.push(line);
      }),
    });
    await runEgressGateRepair(REPAIR_CTX, ops);
    const log = printed.join("\n");
    expect(log).toContain("entry #1 (uid 502)");
    expect(log).toContain("structurally VALID DUPLICATE");
    expect(log).toContain("kept generation 7");
    expect(log).toContain("removed generation 8");
    expect(log).toContain("generation floor");
    expect(ops.audit).toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_QUARANTINE_AUDIT_OP,
      expect.objectContaining({
        quarantined: [
          expect.objectContaining({
            agent_uid: 502,
            disposition: "removed",
            duplicate: { kept_generation_id: 7, removed_generation_id: 8 },
          }),
        ],
      }),
    );
  });

  it("an unrecoverable uid is still reported loudly (no silent finding)", async () => {
    const printed: string[] = [];
    const ops = repairOps({
      repairQuarantinedRegistry: vi.fn(async () => ({
        ...QUARANTINE_RESULT,
        findings: [{ index: 3, reason: "malformed committed entry (failed the fail-closed entry validation)", agent_uid: null, disposition: "removed" as const }],
      })),
      print: vi.fn((line: string) => {
        printed.push(line);
      }),
    });
    await runEgressGateRepair(REPAIR_CTX, ops);
    expect(printed.join("\n")).toContain("entry #3 (an unrecoverable uid)");
  });

  it("a repaired PARSEABLE malformed generation floor is LOUD and audited (fix-round-6 F1)", async () => {
    const printed: string[] = [];
    const floorRepair = { raw: "8", parsed: 8, resolved_floor: 8, unrecoverable: false };
    const ops = repairOps({
      repairQuarantinedRegistry: vi.fn(async () => ({
        ...QUARANTINE_RESULT,
        findings: [],
        floorRepair,
      })),
      print: vi.fn((line: string) => {
        printed.push(line);
      }),
    });
    await runEgressGateRepair(REPAIR_CTX, ops);
    const log = printed.join("\n");
    expect(log).toContain("generation floor was malformed");
    expect(log).toContain('"8"');
    expect(log).toContain("parsed to 8");
    expect(log).toContain("folded into the repaired floor (8)");
    expect(ops.audit).toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_QUARANTINE_AUDIT_OP,
      expect.objectContaining({ generation_floor_repair: floorRepair }),
    );
  });

  it("an UNRECOVERABLE malformed generation floor is LOUD: reset named, re-provision advised, audited (fix-round-6 F1)", async () => {
    const printed: string[] = [];
    const floorRepair = {
      raw: { bogus: true },
      parsed: null,
      resolved_floor: 9,
      unrecoverable: true,
    };
    const ops = repairOps({
      repairQuarantinedRegistry: vi.fn(async () => ({
        ...QUARANTINE_RESULT,
        findings: [],
        floorRepair,
      })),
      print: vi.fn((line: string) => {
        printed.push(line);
      }),
    });
    await runEgressGateRepair(REPAIR_CTX, ops);
    const log = printed.join("\n");
    expect(log).toContain("UNRECOVERABLE");
    expect(log).toContain("reset to the maximum generation still observable");
    expect(log).toContain("(9)");
    expect(log).toContain("RE-PROVISIONING");
    expect(ops.audit).toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_QUARANTINE_AUDIT_OP,
      expect.objectContaining({ generation_floor_repair: floorRepair }),
    );
  });

  it("a quarantine-repair failure -> repair-failed at the DISTINCT quarantine-repair stage, honest park, no downstream mutation", async () => {
    const ops = repairOps({
      repairQuarantinedRegistry: vi.fn(async () => {
        throw new Error("forensic sink full");
      }),
    });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toMatchObject({
      kind: "repair-failed",
      stage: "quarantine-repair",
      parkedStateVerified: true,
    });
    const reason = (outcome as { reason: string }).reason;
    expect(reason).toContain("forensic sink full");
    expect(reason).toContain("untouched");
    expect(ops.recoverGeneration).not.toHaveBeenCalled();
    expect(ops.bringUpGeneration).not.toHaveBeenCalled();
    expect(ops.runReleaseSequence).not.toHaveBeenCalled();
  });

  it("a clean registry is a silent no-op (no quarantine audit, no quarantine print)", async () => {
    const printed: string[] = [];
    const ops = repairOps({
      print: vi.fn((line: string) => {
        printed.push(line);
      }),
    });
    const outcome = await runEgressGateRepair(REPAIR_CTX, ops);
    expect(outcome).toEqual({ kind: "repaired", generationId: 7 });
    expect(ops.audit).not.toHaveBeenCalledWith(
      EGRESS_GATE_REPAIR_QUARANTINE_AUDIT_OP,
      expect.anything(),
    );
    expect(printed.join("\n")).not.toContain("Quarantined");
  });

  it("a refusal (foreign transient rules, no override) never reaches the quarantine step", async () => {
    const ops = repairOps({
      diffTransientPfRules: vi.fn(async () => ({ foreign: ["pass in quick on utun3 all"] })),
    });
    await runEgressGateRepair(REPAIR_CTX, ops);
    expect(ops.repairQuarantinedRegistry).not.toHaveBeenCalled();
  });
});
