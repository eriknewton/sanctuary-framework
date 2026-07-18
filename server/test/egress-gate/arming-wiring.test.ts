/**
 * Tests for the pure/injectable pieces of the S5-6 production wiring
 * (`egress-gate/arming-wiring.ts`): the lsof-backed loopback TCP port-owner
 * check's fail-closed contract, including the fix-round pid_start
 * enforcement (the runtime state's pid-reuse defense token was previously
 * stored but never verified). The wiring module's side-effecting factories
 * (launchctl, pfctl, real fs under /var/db) are production-only by design and
 * are exercised through the pure S5-1..S5-5 libraries they compose (their own
 * suites) + the S5-DRILL; this suite pins the seams that take injected exec
 * functions.
 */

import { describe, expect, it, vi } from "vitest";

import {
  restoreCoarseCompositionProduction,
  verifyLoopbackTcpPortOwner,
  PID_START_TOLERANCE_MS,
  type ExclusiveEgressWiringInput,
} from "../../src/egress-gate/arming-wiring.js";

function lsofOutput(pid: number, uid: number): string {
  return `p${pid}\nu${uid}\nnlocalhost:40001\n`;
}

/** exec stub answering lsof (owner) and ps (lstart) with injected values. */
function execStub(input: { pid: number; uid: number; lstart?: string | Error }) {
  return vi.fn(async (file: string, args: string[]) => {
    if (file === "lsof") return { stdout: lsofOutput(input.pid, input.uid), stderr: "" };
    if (file === "ps") {
      expect(args).toEqual(["-p", String(input.pid), "-o", "lstart="]);
      if (input.lstart instanceof Error) throw input.lstart;
      return { stdout: `${input.lstart ?? ""}\n`, stderr: "" };
    }
    throw new Error(`unexpected exec: ${file}`);
  });
}

describe("egress-gate/arming-wiring verifyLoopbackTcpPortOwner", () => {
  it("true when the listener pid (and uid, when expected) match", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(991, 503), stderr: "" }));
    await expect(
      verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, expectedUid: 503, execFileFn: execFileFn as never }),
    ).resolves.toBe(true);
    expect(execFileFn).toHaveBeenCalledWith("lsof", ["-nP", "-iTCP:40001", "-sTCP:LISTEN", "-Fpu"]);
  });

  it("false on a pid mismatch (a squatter on the committed port is never owner-verified)", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(1234, 503), stderr: "" }));
    await expect(
      verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never }),
    ).resolves.toBe(false);
  });

  it("false on a uid mismatch when an expected uid is given (wrong service account)", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(991, 0), stderr: "" }));
    await expect(
      verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, expectedUid: 503, execFileFn: execFileFn as never }),
    ).resolves.toBe(false);
  });

  it("fail-closed: no listener / lsof failure resolves false, never throws", async () => {
    const execFileFn = vi.fn(async () => {
      throw new Error("lsof exited 1");
    });
    await expect(
      verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never }),
    ).resolves.toBe(false);
  });

  it("fail-closed: empty lsof output (no pid line) is not owner-verified", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: "", stderr: "" }));
    await expect(
      verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never }),
    ).resolves.toBe(false);
  });

  it("pid_start ENFORCED: a kernel start time within tolerance verifies", async () => {
    const start = new Date("2026-07-17T10:00:00");
    const token = `991-${start.getTime() + 2_000}`; // 2s of Date.now()/uptime jitter
    const execFileFn = execStub({ pid: 991, uid: 503, lstart: "Fri Jul 17 10:00:00 2026" });
    await expect(
      verifyLoopbackTcpPortOwner({
        port: 40001,
        expectedPid: 991,
        expectedUid: 503,
        expectedPidStart: token,
        execFileFn: execFileFn as never,
      }),
    ).resolves.toBe(true);
    expect(execFileFn).toHaveBeenCalledWith("ps", ["-p", "991", "-o", "lstart="]);
  });

  it("pid_start ENFORCED: a start time beyond the tolerance is NOT owner-verified (pid reuse)", async () => {
    const start = new Date("2026-07-17T10:00:00");
    const token = `991-${start.getTime() + PID_START_TOLERANCE_MS + 60_000}`;
    const execFileFn = execStub({ pid: 991, uid: 503, lstart: "Fri Jul 17 10:00:00 2026" });
    await expect(
      verifyLoopbackTcpPortOwner({
        port: 40001,
        expectedPid: 991,
        expectedPidStart: token,
        execFileFn: execFileFn as never,
      }),
    ).resolves.toBe(false);
  });

  it("pid_start fail-closed: malformed token, cross-pid token, empty/failed/unparseable ps are all false", async () => {
    const goodLstart = "Fri Jul 17 10:00:00 2026";
    const cases: { token: string; lstart?: string | Error }[] = [
      { token: "pid-991", lstart: goodLstart }, // non-authoritative placeholder form
      { token: "1234-1000", lstart: goodLstart }, // token names another pid
      { token: "991-1000", lstart: "" }, // ps returned nothing (process gone)
      { token: "991-1000", lstart: new Error("ps exited 1") },
      { token: "991-1000", lstart: "not a date" },
    ];
    for (const c of cases) {
      const execFileFn = execStub({ pid: 991, uid: 503, lstart: c.lstart });
      await expect(
        verifyLoopbackTcpPortOwner({
          port: 40001,
          expectedPid: 991,
          expectedPidStart: c.token,
          execFileFn: execFileFn as never,
        }),
      ).resolves.toBe(false);
    }
  });
});

describe("restoreCoarseCompositionProduction (fix-round M5: gate daemon stopped FIRST, loudly)", () => {
  it("boots the gate daemon out BEFORE any teardown; a real bootout failure THROWS with nothing removed", async () => {
    const calls: string[] = [];
    // Only agentUid is reached before the loud throw; the rest of the wiring
    // input is deliberately untouched (host-free).
    const input = { agentUid: 502, agentId: "hermes", fortressPath: "/tmp/fortress-x" } as ExclusiveEgressWiringInput;
    await expect(
      restoreCoarseCompositionProduction(input, "test-reason", {
        runLaunchctl: async (args) => {
          calls.push(`launchctl ${args.join(" ")}`);
          return { code: 5, stdout: "", stderr: "Boot-out failed: 5: Input/output error" };
        },
        removeFile: async (path) => {
          calls.push(`rm ${path}`);
        },
      }),
    ).rejects.toThrow(/could not stop the egress-gate daemon/);
    // The bootout was the FIRST and ONLY side effect: no marker/policy/config
    // removal ran under a possibly-live gate (pre-fix code swallowed the
    // bootout failure AND removed files before attempting the stop).
    expect(calls).toEqual(["launchctl bootout system/ai.sanctuaryprotocol.egress-gate.502"]);
  });
});
