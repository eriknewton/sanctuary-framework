/**
 * Release-barrier sequence (Unified Protect Slice 5 S5-5): every orchestration
 * branch, host-free over injected ops. The pinned invariants are the design's
 * barrier line: enable strictly after commit + hold-file, bootstrap strictly
 * after enable, EVERY abort branch removes the hold file and leaves the job
 * disabled, and cleanup failures are loud (never swallowed).
 */

import { describe, it, expect } from "vitest";

import { AGENT_HARNESS_DAEMON_LABEL } from "../../src/egress-gate/harness-daemon.js";
import {
  RELEASE_REFUSAL_RECORD_HEADER,
  ReleaseBarrierError,
  computeHarnessArgvDigest,
  runReleaseBarrierSequence,
  type CommittedGenerationIdentity,
  type HarnessReleaseHoldRecord,
  type ReleaseBarrierContext,
  type ReleaseBarrierOps,
} from "../../src/egress-gate/release-barrier.js";

const CTX: ReleaseBarrierContext = {
  agentUid: 503,
  harnessLabel: AGENT_HARNESS_DAEMON_LABEL,
  harnessArgv: ["/usr/local/bin/node", "/opt/harness.js"],
};

const matchingWrapperRefusal = {
  header: RELEASE_REFUSAL_RECORD_HEADER,
  reason: "hold file absent; no committed generation has released this uid",
  observations: {
    expected_generation: "7",
    gate_port: "49152",
    proxy_username_shape: "valid",
    expected_label: AGENT_HARNESS_DAEMON_LABEL,
    runtime_uid: "503",
    hold_file_exists: "no",
    hold_file_readable: "not_checked",
    hold_header: "not_checked",
    hold_generation: "not_checked",
    hold_label: "not_checked",
    hold_uid: "not_checked",
    boot_session: "not_checked",
    argv_digest: "not_checked",
    token_file_exists: "not_checked",
    token_file_readable: "not_checked",
    token_generation: "not_checked",
    token_secret_shape: "not_checked",
  },
} as const;

interface SpyOps {
  ops: ReleaseBarrierOps;
  calls: string[];
  written: HarnessReleaseHoldRecord[];
  releasedPlists: CommittedGenerationIdentity[];
}

function makeOps(overrides?: Partial<Record<keyof ReleaseBarrierOps, unknown>>): SpyOps {
  const calls: string[] = [];
  const written: HarnessReleaseHoldRecord[] = [];
  const releasedPlists: CommittedGenerationIdentity[] = [];
  // A MINI-HOST, not a per-verb stub (fix-round 3, 2026-07-19). The old base
  // ops answered `harnessStatus` with "running" unconditionally, including
  // BEFORE the bootstrap -- which is precisely the state the round-3 blocker
  // says must refuse, and precisely why no test caught that the sequence never
  // asked. The flag now tracks the launchd verbs.
  let running = false;
  const base: ReleaseBarrierOps = {
    async disableJob() {
      calls.push("disable");
    },
    async enableJob() {
      calls.push("enable");
    },
    async bootstrapJob() {
      calls.push("bootstrap");
      running = true;
    },
    async bootoutJob() {
      calls.push("bootout");
      running = false;
    },
    async removeHoldFile() {
      calls.push("removeHold");
    },
    async writeHoldFile(record) {
      calls.push("writeHold");
      written.push(record);
    },
    async bootSessionUuid() {
      calls.push("bootUuid");
      return "1A2B3C4D-0000-4444-8888-ABCDEFABCDEF";
    },
    async rearmAnchor() {
      calls.push("rearm");
      return { ok: true as const };
    },
    async verifyGate() {
      calls.push("verifyGate");
      return { ok: true as const, observed: { generation_id: 7, agent_uid: 503, gate_port: 49152 } };
    },
    async commitGeneration(): Promise<CommittedGenerationIdentity> {
      calls.push("commit");
      return { generation_id: 7, agent_uid: 503, gate_port: 49152 };
    },
    async writeReleasedPlist(committed) {
      calls.push("writeReleasedPlist");
      releasedPlists.push(committed);
    },
    async restoreParkedPlist() {
      calls.push("restoreParkedPlist");
    },
    async readWrapperRefusalRecord() {
      calls.push("readWrapperRefusalRecord");
      return { status: "absent" as const };
    },
    async harnessStatus() {
      calls.push("harnessStatus");
      return running
        ? { known: true, installed: true, running: true, pid: 4242 }
        : { known: true, installed: true, running: false };
    },
    sleepMs: async () => {},
  };
  const ops = { ...base, ...(overrides as Partial<ReleaseBarrierOps>) };
  return { ops, calls, written, releasedPlists };
}

describe("runReleaseBarrierSequence: happy path", () => {
  it("releases with the exact stage ordering and re-parks the boot state last", async () => {
    const { ops, calls, written, releasedPlists } = makeOps();
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome).toEqual({ kind: "released", generation_id: 7 });
    expect(calls).toEqual([
      "bootout", // reassert-parked (fix-round BLOCKER-3): any live job stopped FIRST
      "removeHold", // reassert-parked: stale hold cleared
      "disable", // reassert-parked: persistent park asserted
      "restoreParkedPlist", // reassert-parked: a crashed run's released plist cleared
      // Fix-round 3 BLOCKER: the park is now OBSERVED before anything else
      // runs. Without this probe the sequence proceeded on the strength of
      // `bootoutJob` not throwing, and the later running checks could not tell
      // the released process from a pre-G5 one that survived the park.
      "harnessStatus",
      "rearm",
      "verifyGate",
      "commit",
      "verifyGate", // verify-committed: committed identity re-verified live
      "bootUuid",
      "writeHold",
      "writeReleasedPlist", // released plist embeds the committed generation
      "enable",
      "bootstrap",
      "harnessStatus", // verify-running: post-bootstrap liveness probe
      "disable", // repark-boot-state (enable persists; boot path re-parked)
      "restoreParkedPlist", // repark-boot-state: parked plist restored
      "harnessStatus", // verify-running: the re-park must not kill the session
    ]);
    // The barrier line: enable strictly after commit, hold-file write, AND the
    // released-plist write (a parked plist embeds generation 0 and the wrapper
    // refuses it, so enabling before the re-render can never exec the harness).
    expect(calls.indexOf("enable")).toBeGreaterThan(calls.indexOf("commit"));
    expect(calls.indexOf("enable")).toBeGreaterThan(calls.indexOf("writeHold"));
    expect(calls.indexOf("enable")).toBeGreaterThan(calls.indexOf("writeReleasedPlist"));
    expect(calls.indexOf("bootstrap")).toBeGreaterThan(calls.indexOf("enable"));
    // The hold file names the committed generation, this uid, and the argv digest.
    expect(written).toEqual([
      {
        generation_id: 7,
        agent_uid: 503,
        harness_label: AGENT_HARNESS_DAEMON_LABEL,
        argv_digest: computeHarnessArgvDigest(CTX.harnessArgv),
        boot_session_uuid: "1A2B3C4D-0000-4444-8888-ABCDEFABCDEF",
      },
    ]);
    // The released plist re-render received the exact committed identity.
    expect(releasedPlists).toEqual([{ generation_id: 7, agent_uid: 503, gate_port: 49152 }]);
  });

  it("refuses invalid contexts outright (bad uid, unsafe label)", async () => {
    const { ops } = makeOps();
    await expect(runReleaseBarrierSequence({ ...CTX, agentUid: 0 }, ops)).rejects.toThrow(ReleaseBarrierError);
    await expect(runReleaseBarrierSequence({ ...CTX, harnessLabel: "bad label" }, ops)).rejects.toThrow(
      ReleaseBarrierError,
    );
  });
});

describe("runReleaseBarrierSequence: abort branches (fail-closed, hold removed, job disabled)", () => {
  it("reassert-parked failure refuses to proceed and reports the cleanup error loudly", async () => {
    const { ops, calls } = makeOps({
      disableJob: async () => {
        calls.push("disable");
        throw new Error("launchctl down");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("reassert-parked");
    expect(outcome.jobDisabled).toBe(false);
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.cleanupErrors.join(" ")).toContain("launchctl down");
    // Nothing past the park assertion ran.
    expect(calls).not.toContain("rearm");
    expect(calls).not.toContain("enable");
    expect(calls).not.toContain("bootstrap");
  });

  it("fix-round BLOCKER-3: reassert-parked BOOTS OUT any live job FIRST; a bootout failure refuses to proceed", async () => {
    const { ops, calls } = makeOps({
      bootoutJob: async () => {
        calls.push("bootout");
        throw new Error("still running, bootout refused");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("reassert-parked");
    expect(outcome.cleanupErrors.join(" ")).toContain("still running, bootout refused");
    // The bootout is the FIRST op of the sequence -- a live harness from a
    // crashed run (or the repair path's coarse-mode harness) is stopped
    // before ANY release work.
    expect(calls[0]).toBe("bootout");
    expect(calls).not.toContain("rearm");
    expect(calls).not.toContain("enable");
    expect(calls).not.toContain("bootstrap");
  });

  it("stale-hold-removal failure at reassert-parked also refuses to proceed", async () => {
    const { ops, calls } = makeOps({
      removeHoldFile: async () => {
        calls.push("removeHold");
        throw new Error("EACCES");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("reassert-parked");
    expect(outcome.holdFileRemoved).toBe(false);
    expect(outcome.jobDisabled).toBe(true);
    expect(calls).not.toContain("rearm");
  });

  it("rearm-anchor failure parks (already-asserted park state stands; no enable, no bootstrap)", async () => {
    const { ops, calls } = makeOps({
      rearmAnchor: async () => {
        calls.push("rearm");
        return { ok: false as const, reason: "pfctl exited 1" };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome).toMatchObject({
      kind: "parked",
      stage: "rearm-anchor",
      reason: "pf anchor re-arm failed: pfctl exited 1",
      holdFileRemoved: true,
      jobDisabled: true,
      cleanupErrors: [],
    });
    expect(calls).not.toContain("verifyGate");
    expect(calls).not.toContain("writeHold");
    expect(calls).not.toContain("enable");
    expect(calls).not.toContain("bootstrap");
  });

  it("gate-verify failure parks with the reasons vector and never enables", async () => {
    const { ops, calls } = makeOps({
      verifyGate: async () => {
        calls.push("verifyGate");
        return { ok: false as const, reasons: ["gate down", "generation mismatch"] };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("gate-verify");
    expect(outcome.reason).toContain("gate down; generation mismatch");
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(calls).not.toContain("commit");
    expect(calls).not.toContain("enable");
  });

  it("commit failure parks, re-runs the park cleanup, and never writes the hold file", async () => {
    const { ops, calls } = makeOps({
      commitGeneration: async () => {
        calls.push("commit");
        throw new Error("G3 pf load failed");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("commit-generation");
    expect(outcome.reason).toContain("G3 pf load failed");
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(calls.filter((c) => c === "removeHold")).toHaveLength(2);
    expect(calls.filter((c) => c === "disable")).toHaveLength(2);
    expect(calls).not.toContain("writeHold");
    expect(calls).not.toContain("enable");
  });

  it("a commit naming a DIFFERENT uid parks (identity keying; never releases another agent's commit)", async () => {
    const { ops, calls } = makeOps({
      commitGeneration: async () => {
        calls.push("commit");
        return { generation_id: 7, agent_uid: 601, gate_port: 49152 };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("commit-generation");
    expect(outcome.reason).toContain("identity mismatch");
    expect(calls).not.toContain("writeHold");
    expect(calls).not.toContain("enable");
  });

  it("a commit with a non-positive generation id parks", async () => {
    const { ops } = makeOps({
      commitGeneration: async () => ({ generation_id: 0, agent_uid: 503, gate_port: 49152 }),
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("commit-generation");
  });

  it("hold-file write failure parks and removes the (possibly partial) hold file", async () => {
    const { ops, calls } = makeOps({
      writeHoldFile: async () => {
        calls.push("writeHold");
        throw new Error("disk full");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("write-hold-file");
    expect(outcome.reason).toContain("disk full");
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(calls).not.toContain("enable");
    expect(calls).not.toContain("bootstrap");
  });

  it("boot-session-uuid read failure parks at write-hold-file (fail-closed; no unverifiable hold file)", async () => {
    const { ops, calls } = makeOps({
      bootSessionUuid: async () => {
        calls.push("bootUuid");
        throw new Error("sysctl unavailable");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("write-hold-file");
    expect(outcome.reason).toContain("sysctl unavailable");
    expect(calls).not.toContain("writeHold");
    expect(calls).not.toContain("enable");
  });

  it("enable failure parks: hold file removed, job re-disabled, bootstrap never attempted", async () => {
    const { ops, calls } = makeOps({
      enableJob: async () => {
        calls.push("enable");
        throw new Error("enable refused");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("enable");
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(outcome.cleanupErrors).toEqual([]);
    expect(calls).not.toContain("bootstrap");
    // The hold write happened before enable; the abort removed it again.
    expect(calls.indexOf("removeHold", calls.indexOf("writeHold"))).toBeGreaterThan(calls.indexOf("writeHold"));
  });

  it("bootstrap failure parks: bootout attempted, hold file removed, job disabled", async () => {
    const { ops, calls } = makeOps({
      bootstrapJob: async () => {
        calls.push("bootstrap");
        throw new Error("bootstrap 5: input/output error");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("bootstrap");
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(calls).toContain("bootout");
    // The ABORT-cleanup bootout (the last one; reassert-parked also boots
    // out at the very start) follows the failed bootstrap.
    expect(calls.lastIndexOf("bootout")).toBeGreaterThan(calls.indexOf("bootstrap"));
  });

  it("cleanup failures inside an abort are LOUD: booleans false + errors named", async () => {
    let removeCount = 0;
    const { ops } = makeOps({
      enableJob: async () => {
        throw new Error("enable refused");
      },
      removeHoldFile: async () => {
        removeCount += 1;
        // First call (reassert-parked) succeeds; the abort-cleanup call fails.
        if (removeCount > 1) throw new Error("EROFS");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("enable");
    expect(outcome.holdFileRemoved).toBe(false);
    expect(outcome.cleanupErrors.join(" ")).toContain("EROFS");
  });

  it("bootstrap-abort with failing bootout still removes the hold file and disables, reporting the bootout error", async () => {
    let bootoutCount = 0;
    const { ops, calls } = makeOps({
      bootstrapJob: async () => {
        throw new Error("io error");
      },
      bootoutJob: async () => {
        calls.push("bootout");
        bootoutCount += 1;
        // First call (reassert-parked) succeeds; the abort-cleanup call fails.
        if (bootoutCount > 1) throw new Error("bootout refused");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(outcome.cleanupErrors.join(" ")).toContain("bootout refused");
  });
});

describe("runReleaseBarrierSequence: repark-boot-state", () => {
  it("a failed final re-disable is a DISTINCT loud outcome, never a clean release", async () => {
    let disableCount = 0;
    const { ops } = makeOps({
      disableJob: async () => {
        disableCount += 1;
        // First call (reassert-parked) succeeds; the final re-park fails.
        if (disableCount > 1) throw new Error("override db locked");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome).toEqual({
      kind: "released-repark-failed",
      generation_id: 7,
      reparkError: "override db locked",
    });
  });

  it("a failed parked-plist restore during re-park is the same loud amber outcome", async () => {
    let restoreCount = 0;
    const { ops } = makeOps({
      restoreParkedPlist: async () => {
        restoreCount += 1;
        // First call (reassert-parked) succeeds; the re-park restore fails.
        if (restoreCount > 1) throw new Error("EROFS");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome).toEqual({
      kind: "released-repark-failed",
      generation_id: 7,
      reparkError: "EROFS",
    });
  });
});

describe("runReleaseBarrierSequence: verify-committed (TOCTOU binding; fix-round HIGH-2)", () => {
  it("parks when the post-commit re-verify observes a DIFFERENT generation than the commit", async () => {
    let verifyCount = 0;
    const { ops, calls } = makeOps({
      verifyGate: async () => {
        verifyCount += 1;
        calls.push("verifyGate");
        // Pre-commit verify sees generation 6; the commit returns 7; the
        // post-commit re-verify still sees 6 (the commit did not become the
        // live gate generation). The hold file must never be written.
        return { ok: true as const, observed: { generation_id: 6, agent_uid: 503, gate_port: 49152 } };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("verify-committed");
    expect(outcome.reason).toContain("observed uid 503 generation 6");
    expect(outcome.reason).toContain("commit named uid 503 generation 7");
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(verifyCount).toBe(2);
    expect(calls).not.toContain("writeHold");
    expect(calls).not.toContain("writeReleasedPlist");
    expect(calls).not.toContain("enable");
  });

  it("parks when the post-commit re-verify observes a DIFFERENT uid", async () => {
    let verifyCount = 0;
    const { ops, calls } = makeOps({
      verifyGate: async () => {
        verifyCount += 1;
        return verifyCount === 1
          ? { ok: true as const, observed: { generation_id: 7, agent_uid: 503, gate_port: 49152 } }
          : { ok: true as const, observed: { generation_id: 7, agent_uid: 601, gate_port: 49152 } };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("verify-committed");
    expect(calls).not.toContain("writeHold");
  });

  it("parks when the post-commit re-verify observes a DIFFERENT gate port", async () => {
    let verifyCount = 0;
    const { ops, calls } = makeOps({
      verifyGate: async () => {
        verifyCount += 1;
        return verifyCount === 1
          ? { ok: true as const, observed: { generation_id: 7, agent_uid: 503, gate_port: 49152 } }
          : { ok: true as const, observed: { generation_id: 7, agent_uid: 503, gate_port: 49153 } };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("verify-committed");
    expect(outcome.reason).toContain("gate port 49153");
    expect(outcome.reason).toContain("gate port 49152");
    expect(calls).not.toContain("writeHold");
    expect(calls).not.toContain("writeReleasedPlist");
  });

  it("parks when the post-commit re-verify itself fails or throws (fail-closed)", async () => {
    let verifyCount = 0;
    const { ops: failOps, calls: failCalls } = makeOps({
      verifyGate: async () => {
        verifyCount += 1;
        return verifyCount === 1
          ? { ok: true as const, observed: { generation_id: 7, agent_uid: 503, gate_port: 49152 } }
          : { ok: false as const, reasons: ["gate went down mid-release"] };
      },
    });
    const failed = await runReleaseBarrierSequence(CTX, failOps);
    expect(failed.kind).toBe("parked");
    if (failed.kind !== "parked") return;
    expect(failed.stage).toBe("verify-committed");
    expect(failed.reason).toContain("gate went down mid-release");
    expect(failCalls).not.toContain("writeHold");

    let throwCount = 0;
    const { ops: throwOps } = makeOps({
      verifyGate: async () => {
        throwCount += 1;
        if (throwCount > 1) throw new Error("oracle timeout");
        return { ok: true as const, observed: { generation_id: 7, agent_uid: 503, gate_port: 49152 } };
      },
    });
    const threw = await runReleaseBarrierSequence(CTX, throwOps);
    expect(threw.kind).toBe("parked");
    if (threw.kind !== "parked") return;
    expect(threw.stage).toBe("verify-committed");
    expect(threw.reason).toContain("oracle timeout");
  });
});

describe("runReleaseBarrierSequence: write-released-plist (fix-round HIGH-1)", () => {
  it("the released-plist write receives the committed identity and precedes enable", async () => {
    const { ops, calls, releasedPlists } = makeOps();
    await runReleaseBarrierSequence(CTX, ops);
    expect(releasedPlists).toEqual([{ generation_id: 7, agent_uid: 503, gate_port: 49152 }]);
    expect(calls.indexOf("writeReleasedPlist")).toBeGreaterThan(calls.indexOf("writeHold"));
    expect(calls.indexOf("writeReleasedPlist")).toBeLessThan(calls.indexOf("enable"));
  });

  it("a failed released-plist write parks: hold removed, disabled, parked plist restored, never enabled", async () => {
    const { ops, calls } = makeOps({
      writeReleasedPlist: async () => {
        calls.push("writeReleasedPlist");
        throw new Error("disk full");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("write-released-plist");
    expect(outcome.reason).toContain("disk full");
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(outcome.cleanupErrors).toEqual([]);
    // The abort restored the parked plist (2nd restore; 1st was reassert-parked).
    expect(calls.filter((c) => c === "restoreParkedPlist")).toHaveLength(2);
    expect(calls).not.toContain("enable");
    expect(calls).not.toContain("bootstrap");
  });

  it("enable/bootstrap aborts restore the parked plist so no released plist survives an abort", async () => {
    const { ops, calls } = makeOps({
      bootstrapJob: async () => {
        calls.push("bootstrap");
        throw new Error("io error");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("bootstrap");
    expect(calls.filter((c) => c === "restoreParkedPlist")).toHaveLength(2);
  });
});

describe("runReleaseBarrierSequence: verify-running (liveness; fix-round HIGH-3)", () => {
  it("parks when the harness is not running after bootstrap (no silent green-on-down)", async () => {
    const { ops, calls } = makeOps({
      harnessStatus: async () => {
        calls.push("harnessStatus");
        return { known: true, installed: true, running: false };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("verify-running");
    expect(outcome.reason).toContain("did not reach a stable running state after bootstrap");
    expect(outcome.reason).toContain("could not determine whether the job spawned or exec'd");
    expect(outcome.reason).toContain("no matching wrapper refusal record");
    expect(outcome.reason).not.toContain("may be refusing");
    expect(outcome.holdFileRemoved).toBe(true);
    expect(outcome.jobDisabled).toBe(true);
    expect(calls).toContain("bootout");
    expect(calls.filter((c) => c === "restoreParkedPlist")).toHaveLength(2);
  });

  it("quotes the recorded wrapper refusal reason and observations when the diagnostic record matches this release", async () => {
    let bootstrapped = false;
    const { ops } = makeOps({
      bootstrapJob: async () => {
        bootstrapped = true;
      },
      harnessStatus: async () =>
        bootstrapped
          ? { known: true, installed: true, running: false }
          : { known: true, installed: true, running: false },
      readWrapperRefusalRecord: async () => ({ status: "present" as const, record: matchingWrapperRefusal }),
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("verify-running");
    expect(outcome.reason).toContain(
      "the job spawned and the release wrapper refused: hold file absent; no committed generation has released this uid",
    );
    expect(outcome.reason).toContain("hold_file_exists=no");
    expect(outcome.reason).toContain("token_secret_shape=not_checked");
    expect(outcome.reason).not.toContain("deadbeef");
    expect(outcome.reason).not.toContain("PROXY_URL");
    expect(outcome.reason).not.toContain("may be refusing");
  });

  it("distinguishes a job that never spawned from a wrapper refusal", async () => {
    let bootstrapped = false;
    const { ops } = makeOps({
      bootstrapJob: async () => {
        bootstrapped = true;
      },
      harnessStatus: async () =>
        bootstrapped
          ? { known: true, installed: false, running: false }
          : { known: true, installed: true, running: false },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.reason).toContain("the job never spawned");
    expect(outcome.reason).not.toContain("wrapper refused");
    expect(outcome.reason).not.toContain("may be refusing");
  });

  it("distinguishes a spawned process that did not stay up when launchd observed a pid and no wrapper refusal record matched", async () => {
    let bootstrapped = false;
    const { ops } = makeOps({
      bootstrapJob: async () => {
        bootstrapped = true;
      },
      harnessStatus: async () =>
        bootstrapped
          ? { known: true, installed: true, running: false, pid: 4242 }
          : { known: true, installed: true, running: false },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.reason).toContain("the job spawned but did not stay up: launchd observed pid 4242");
    expect(outcome.reason).not.toContain("wrapper refused");
    expect(outcome.reason).not.toContain("may be refusing");
  });

  it("says could not determine when the only refusal record is stale or unreadable", async () => {
    let bootstrapped = false;
    const staleRecord = {
      ...matchingWrapperRefusal,
      observations: { ...matchingWrapperRefusal.observations, expected_generation: "6" },
    };
    const { ops: staleOps } = makeOps({
      bootstrapJob: async () => {
        bootstrapped = true;
      },
      harnessStatus: async () =>
        bootstrapped
          ? { known: true, installed: true, running: false }
          : { known: true, installed: true, running: false },
      readWrapperRefusalRecord: async () => ({ status: "present" as const, record: staleRecord }),
    });
    const stale = await runReleaseBarrierSequence(CTX, staleOps);
    expect(stale.kind).toBe("parked");
    if (stale.kind !== "parked") return;
    expect(stale.reason).toContain("could not determine whether this launch's wrapper refused");
    expect(stale.reason).toContain("generation 6");

    bootstrapped = false;
    const { ops: unreadableOps } = makeOps({
      bootstrapJob: async () => {
        bootstrapped = true;
      },
      harnessStatus: async () =>
        bootstrapped
          ? { known: true, installed: true, running: false }
          : { known: true, installed: true, running: false },
      readWrapperRefusalRecord: async () => ({ status: "unreadable" as const, reason: "EACCES" }),
    });
    const unreadable = await runReleaseBarrierSequence(CTX, unreadableOps);
    expect(unreadable.kind).toBe("parked");
    if (unreadable.kind !== "parked") return;
    expect(unreadable.reason).toContain("could not determine whether the wrapper refused: EACCES");
    expect(unreadable.reason).not.toContain("may be refusing");
  });

  it("parks fail-closed when the status is untrustworthy or the probe throws", async () => {
    // Untrustworthy only AFTER the bootstrap, so this stays a verify-running
    // test; the reassert-parked equivalents are asserted separately below.
    let bootstrapped = false;
    const { ops: unknownOps } = makeOps({
      bootstrapJob: async () => {
        bootstrapped = true;
      },
      harnessStatus: async () =>
        bootstrapped
          ? { known: false, installed: false, running: false }
          : { known: true, installed: true, running: false },
    });
    const unknown = await runReleaseBarrierSequence(CTX, unknownOps);
    expect(unknown.kind).toBe("parked");
    if (unknown.kind !== "parked") return;
    expect(unknown.stage).toBe("verify-running");
    expect(unknown.reason).toContain("trustworthy");

    let threwArmed = false;
    const { ops: throwOps } = makeOps({
      bootstrapJob: async () => {
        threwArmed = true;
      },
      harnessStatus: async () => {
        if (!threwArmed) return { known: true, installed: true, running: false };
        throw new Error("launchctl hung");
      },
    });
    const threw = await runReleaseBarrierSequence(CTX, throwOps);
    expect(threw.kind).toBe("parked");
    if (threw.kind !== "parked") return;
    expect(threw.stage).toBe("verify-running");
    expect(threw.reason).toContain("launchctl hung");
  });

  // ROUND-3 BLOCKER (Codex finding 1). `parkCleanup` reports success when
  // `bootoutJob`/`removeHoldFile`/`disableJob`/`restoreParkedPlist` did not
  // throw -- an intent. Production's `bootoutJob` accepts success through the
  // shared not-loaded predicate, so a launchd shape that tolerates the bootout
  // while the job keeps running used to carry a LIVE pre-G5 harness straight
  // into rearm/verify/commit, and the final stable-running check could not
  // tell it from the released one.
  describe("reassert-parked is OBSERVED, not intended (fix-round 3 BLOCKER)", () => {
    it("refuses BEFORE rearm when bootout resolves but the job is still running", async () => {
      const { ops, calls } = makeOps({
        // Resolves -- exactly what the shared predicate tolerates.
        bootoutJob: async () => {
          calls.push("bootout");
        },
        harnessStatus: async () => {
          calls.push("harnessStatus");
          return { known: true, installed: true, running: true, pid: 4242 };
        },
      });
      const outcome = await runReleaseBarrierSequence(CTX, ops);
      expect(outcome.kind).toBe("parked");
      if (outcome.kind !== "parked") return;
      expect(outcome.stage).toBe("reassert-parked");
      expect(outcome.reason).toContain("still reports a pid");
      // THE POINT: nothing downstream of the barrier line ran.
      expect(calls).not.toContain("rearm");
      expect(calls).not.toContain("commit");
      expect(calls).not.toContain("writeHold");
      expect(calls).not.toContain("enable");
      expect(calls).not.toContain("bootstrap");
    });

    it("refuses when launchd's state is unknowable after the bootout", async () => {
      const { ops, calls } = makeOps({
        harnessStatus: async () => ({ known: false, installed: false, running: false }),
      });
      const outcome = await runReleaseBarrierSequence(CTX, ops);
      expect(outcome.kind).toBe("parked");
      if (outcome.kind !== "parked") return;
      expect(outcome.stage).toBe("reassert-parked");
      expect(outcome.reason).toContain("trustworthy");
      expect(calls).not.toContain("rearm");
    });

    it("refuses when the probe throws, and when a pid survives an unstable-downgraded status", async () => {
      const { ops: throwOps } = makeOps({
        harnessStatus: async () => {
          throw new Error("launchctl hung");
        },
      });
      const threw = await runReleaseBarrierSequence(CTX, throwOps);
      expect(threw.kind).toBe("parked");
      if (threw.kind !== "parked") return;
      expect(threw.stage).toBe("reassert-parked");

      // Production downgrades `running` to false for a pid that is not STABLE
      // across samples -- the right bar for "did it come up", the wrong one for
      // "is it gone". A crash-looping pre-G5 harness is a live process.
      const { ops: flapOps, calls } = makeOps({
        harnessStatus: async () => ({ known: true, installed: true, running: false, pid: 9001 }),
      });
      const flapped = await runReleaseBarrierSequence(CTX, flapOps);
      expect(flapped.kind).toBe("parked");
      if (flapped.kind !== "parked") return;
      expect(flapped.stage).toBe("reassert-parked");
      expect(flapped.reason).toContain("9001");
      expect(calls).not.toContain("rearm");
    });
  });

  it("parks when the harness dies across the boot-state re-park (released is never claimed for a dead harness)", async () => {
    let probeCount = 0;
    const { ops, calls } = makeOps({
      harnessStatus: async () => {
        probeCount += 1;
        calls.push("harnessStatus");
        // Probe 1 is reassert-parked (must be STOPPED); probe 2 is
        // post-bootstrap (alive); probe 3 is post-re-park (dead).
        return probeCount === 2
          ? { known: true, installed: true, running: true, pid: 4242 }
          : { known: true, installed: true, running: false };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.stage).toBe("verify-running");
    expect(outcome.reason).toContain("re-park");
    expect(outcome.holdFileRemoved).toBe(true);
    // The re-park already disabled the job; the cleanup boots the dead job out.
    expect(outcome.jobDisabled).toBe(true);
    expect(calls).toContain("bootout");
  });
});

// ---------------------------------------------------------------------------
// FIX-ROUND 4: the parked-claim chokepoint
// ---------------------------------------------------------------------------

/**
 * Round 3 fixed the "parked by intent" pattern at ONE site and both remaining
 * sites of the identical shape survived. These tests are Codex's round-4
 * counterexample, reproduced: `bootoutJob` resolves, launchd still reports a
 * live pid, and the abort must NOT come back claiming the agent is parked.
 *
 * They assert on OBSERVED STATE and on the claim the outcome carries, not on
 * which ops were called: "the probe was invoked" is exactly the kind of
 * control-flow assertion this whole branch exists to stop trusting.
 */
describe("runReleaseBarrierSequence: no abort claims parked over a live process", () => {
  /** A mini-host whose bootout is a LIAR: it resolves and the process lives. */
  function makeSurvivorOps(overrides?: Partial<Record<keyof ReleaseBarrierOps, unknown>>) {
    const made = makeOps({
      // Codex's counterexample: the bootout resolves cleanly...
      async bootoutJob() {
        /* resolves, changes nothing */
      },
      // ...and launchd keeps reporting the live pid throughout.
      async harnessStatus() {
        return { known: true, installed: true, running: true, pid: 4242 };
      },
      ...overrides,
    });
    return made;
  }

  it("bootstrap abort: a surviving pid makes the outcome refuse the parked claim (Codex round-4 HIGH-1)", async () => {
    const { ops } = makeSurvivorOps({
      async bootstrapJob() {
        throw new Error("kickstart failed after start");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    // The barrier did not release -- but that is a fact about the RELEASE.
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    // ...and the run-state claim is the honest one. Before fix-round 4 this
    // outcome came back clean with no claim at all.
    expect(outcome.parkedClaim.state).toBe("alive");
    expect(outcome.parkedClaim.observed).toContain("4242");
    // THE RENDERED SENTENCE, which is what a human actually reads.
    expect(outcome.parkedClaim.sentence).toContain("RUNNING (pid 4242)");
    expect(outcome.parkedClaim.sentence).not.toContain("PARKED");
  });

  it("verify-running abort: same shape, same refusal", async () => {
    // A STATEFUL host, so this test reaches verify-running rather than being
    // turned back at the initial reassert (which would make it pass for the
    // wrong reason). Timeline: reassert observes genuinely stopped -> bootstrap
    // starts a process -> the wrapper refuses, so `running` downgrades to false
    // while the pid PERSISTS -> the abort's bootout lies and the pid survives.
    let phase: "before" | "after" = "before";
    const { ops } = makeOps({
      async bootstrapJob() {
        phase = "after";
      },
      async bootoutJob() {
        /* resolves, changes nothing -- the round-4 lying bootout */
      },
      async harnessStatus() {
        return phase === "before"
          ? { known: true, installed: true, running: false }
          : { known: true, installed: true, running: false, pid: 4242 };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    // Proves we got past the reassert gate and aborted where intended.
    expect(outcome.stage).toBe("verify-running");
    // `running: false` with a pid is the crash-looping survivor: the pid check
    // is separate from `running` precisely so this reads ALIVE, not parked.
    expect(outcome.parkedClaim.state).toBe("alive");
    expect(outcome.parkedClaim.sentence).toContain("4242");
    expect(outcome.parkedClaim.sentence).not.toContain("PARKED");
  });

  it("an UNKNOWABLE launchd state is never a park (fail-closed both ways)", async () => {
    const { ops } = makeOps({
      async bootstrapJob() {
        throw new Error("kickstart failed after start");
      },
      async harnessStatus() {
        return { known: false, installed: false, running: false };
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.parkedClaim.state).toBe("unknown");
    expect(outcome.parkedClaim.sentence).toContain("POSSIBLY RUNNING");
    expect(outcome.parkedClaim.sentence).not.toContain("PARKED");
  });

  it("a genuinely stopped harness DOES get the parked claim (the guard is not just 'always refuse')", async () => {
    const { ops } = makeOps({
      async bootstrapJob() {
        throw new Error("kickstart failed after start");
      },
    });
    const outcome = await runReleaseBarrierSequence(CTX, ops);
    expect(outcome.kind).toBe("parked");
    if (outcome.kind !== "parked") return;
    expect(outcome.parkedClaim.state).toBe("parked");
    expect(outcome.parkedClaim.sentence).toContain("is PARKED (not running)");
  });

  it("EVERY parked outcome carries a claim -- no abort stage is exempt", async () => {
    // The point of a chokepoint is that it has no holes, so enumerate the
    // abort stages rather than spot-checking the two a reviewer named.
    const aborts: Array<[string, Partial<Record<keyof ReleaseBarrierOps, unknown>>]> = [
      ["rearm-anchor", { async rearmAnchor() { return { ok: false as const, reason: "pf down" }; } }],
      ["gate-verify", { async verifyGate() { return { ok: false as const, reasons: ["oracle dead"] }; } }],
      ["commit-generation", { async commitGeneration() { throw new Error("commit failed"); } }],
      ["write-hold-file", { async writeHoldFile() { throw new Error("disk full"); } }],
      ["write-released-plist", { async writeReleasedPlist() { throw new Error("plist write failed"); } }],
      ["enable", { async enableJob() { throw new Error("enable refused"); } }],
      ["bootstrap", { async bootstrapJob() { throw new Error("bootstrap refused"); } }],
    ];
    for (const [stage, override] of aborts) {
      const { ops } = makeOps(override);
      const outcome = await runReleaseBarrierSequence(CTX, ops);
      expect(outcome.kind, `${stage} must park`).toBe("parked");
      if (outcome.kind !== "parked") continue;
      expect(outcome.stage, `${stage} stage`).toBe(stage);
      // A ParkedClaim cannot be forged, so its mere presence proves the
      // chokepoint ran. Its VALUE proves what was observed.
      expect(outcome.parkedClaim.state, `${stage} claim state`).toBe("parked");
    }
  });
});
