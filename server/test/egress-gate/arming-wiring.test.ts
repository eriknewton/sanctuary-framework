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
  parkHarnessPersistently,
  restoreCoarseCompositionProduction,
  verifyHarnessJobDisabled,
  verifyHarnessParkedPersistent,
  verifyLoopbackTcpPortOwner,
  PID_START_TOLERANCE_MS,
  type ExclusiveEgressWiringInput,
  type PersistentParkContext,
} from "../../src/egress-gate/arming-wiring.js";
import { AGENT_HARNESS_DAEMON_LABEL } from "../../src/egress-gate/harness-daemon.js";
import { holdFilePathForUid, planParkedHarnessInstall } from "../../src/egress-gate/release-barrier.js";

function lsofOutput(pid: number, uid: number): string {
  return `p${pid}\nu${uid}\nnlocalhost:40001\n`;
}

/** exec stub answering lsof (owner) and ps (lstart) with injected values. */
function execStub(input: { pid: number; uid: number; lstart?: string | Error }) {
  return vi.fn(async (file: string, args: string[], options?: { env?: Record<string, string> }) => {
    if (file === "lsof") return { stdout: lsofOutput(input.pid, input.uid), stderr: "" };
    if (file === "ps") {
      expect(args).toEqual(["-p", String(input.pid), "-o", "lstart="]);
      // Fix-round-2 MED-4: ps runs under LC_ALL=C so lstart is Date.parse-able
      // regardless of the operator locale sudo inherited.
      expect(options?.env?.LC_ALL).toBe("C");
      if (input.lstart instanceof Error) throw input.lstart;
      return { stdout: `${input.lstart ?? ""}\n`, stderr: "" };
    }
    throw new Error(`unexpected exec: ${file}`);
  });
}

describe("egress-gate/arming-wiring verifyLoopbackTcpPortOwner", () => {
  it("ok when the listener pid (and uid, when expected) match", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(991, 503), stderr: "" }));
    await expect(
      verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, expectedUid: 503, execFileFn: execFileFn as never }),
    ).resolves.toEqual({ ok: true });
    expect(execFileFn).toHaveBeenCalledWith("lsof", ["-nP", "-iTCP:40001", "-sTCP:LISTEN", "-Fpu"]);
  });

  it("pid mismatch names the PID check (a squatter on the committed port is never owner-verified)", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(1234, 503), stderr: "" }));
    const verdict = await verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never });
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toContain("pid check failed");
    expect((verdict as { reason: string }).reason).toContain("1234");
  });

  it("uid mismatch names the UID check when an expected uid is given (wrong service account)", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(991, 0), stderr: "" }));
    const verdict = await verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, expectedUid: 503, execFileFn: execFileFn as never });
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toContain("uid check failed");
  });

  it("fail-closed: no listener / lsof failure is a named not-verified verdict, never a throw", async () => {
    const execFileFn = vi.fn(async () => {
      throw new Error("lsof exited 1");
    });
    const verdict = await verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never });
    expect(verdict).toEqual({ ok: false, reason: expect.stringContaining("lsof exited 1") });
  });

  it("fail-closed: empty lsof output (no pid line) is not owner-verified", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: "", stderr: "" }));
    const verdict = await verifyLoopbackTcpPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never });
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toContain("pid check failed");
  });

  it("pid_start ENFORCED: a kernel start time within tolerance verifies, with ps pinned to LC_ALL=C (MED-4)", async () => {
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
    ).resolves.toEqual({ ok: true });
    expect(execFileFn).toHaveBeenCalledWith(
      "ps",
      ["-p", "991", "-o", "lstart="],
      expect.objectContaining({ env: expect.objectContaining({ LC_ALL: "C" }) }),
    );
  });

  it("pid_start ENFORCED: a start time beyond the tolerance is NOT owner-verified (pid reuse), reason named", async () => {
    const start = new Date("2026-07-17T10:00:00");
    const token = `991-${start.getTime() + PID_START_TOLERANCE_MS + 60_000}`;
    const execFileFn = execStub({ pid: 991, uid: 503, lstart: "Fri Jul 17 10:00:00 2026" });
    const verdict = await verifyLoopbackTcpPortOwner({
      port: 40001,
      expectedPid: 991,
      expectedPidStart: token,
      execFileFn: execFileFn as never,
    });
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toContain("pid_start check failed");
  });

  it("pid_start fail-closed: malformed token, cross-pid token, empty/failed/unparseable ps each name their check", async () => {
    const goodLstart = "Fri Jul 17 10:00:00 2026";
    const cases: { token: string; lstart?: string | Error; reason: string }[] = [
      { token: "pid-991", lstart: goodLstart, reason: "malformed" }, // non-authoritative placeholder form
      { token: "1234-1000", lstart: goodLstart, reason: "names pid 1234" }, // token names another pid
      { token: "991-1000", lstart: "", reason: "no start time" }, // ps returned nothing (process gone)
      { token: "991-1000", lstart: new Error("ps exited 1"), reason: "ps exited 1" },
      // The MED-4 scenario: a French-locale (Date.parse-NaN) lstart string
      // must name the PARSE check, not silently read as a generic false.
      { token: "991-1000", lstart: "ven. 17 juil. 10:00:00 2026", reason: "pid_start-parse check failed" },
    ];
    for (const c of cases) {
      const execFileFn = execStub({ pid: 991, uid: 503, lstart: c.lstart });
      const verdict = await verifyLoopbackTcpPortOwner({
        port: 40001,
        expectedPid: 991,
        expectedPidStart: c.token,
        execFileFn: execFileFn as never,
      });
      expect(verdict.ok).toBe(false);
      expect((verdict as { reason: string }).reason).toContain(c.reason);
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

// ---------------------------------------------------------------------------
// Fix-round-2 HIGH-2: the persistent park (park = bootout + disable +
// hold-file removal + parked-plist restore, each captured; PARKED is claimed
// only when the FULL persistent posture is verified).
// ---------------------------------------------------------------------------

const PARK_CTX: PersistentParkContext = {
  agentUid: 502,
  agentAccount: "sanctuary-hermes",
  harnessArgv: ["/usr/local/bin/hermes"],
  fortressPath: "/fortress/a",
  harnessLogDir: "/var/sanctuary-agents/sanctuary-hermes/logs",
};

const PARKED_PLAN = planParkedHarnessInstall({
  agentAccount: PARK_CTX.agentAccount,
  agentUid: PARK_CTX.agentUid,
  harnessArgv: PARK_CTX.harnessArgv,
  fortressPath: PARK_CTX.fortressPath,
  logDir: PARK_CTX.harnessLogDir,
});

const HOLD_PATH = holdFilePathForUid(PARK_CTX.agentUid);

/** launchctl fake for the park verbs; every call is recorded. */
function parkLaunchctl(overrides: {
  bootout?: { code: number; stderr?: string };
  disable?: { code: number; stderr?: string };
  printDisabled?: { code: number; stdout: string };
  print?: { code: number; stdout: string; stderr?: string };
} = {}) {
  const calls: string[] = [];
  const fn = async (args: readonly string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
    calls.push(args.join(" "));
    const verb = args[0];
    if (verb === "bootout") {
      return { code: overrides.bootout?.code ?? 0, stdout: "", stderr: overrides.bootout?.stderr ?? "" };
    }
    if (verb === "disable") {
      return { code: overrides.disable?.code ?? 0, stdout: "", stderr: overrides.disable?.stderr ?? "" };
    }
    if (verb === "print-disabled") {
      return {
        code: overrides.printDisabled?.code ?? 0,
        stdout: overrides.printDisabled?.stdout ?? `\t"${AGENT_HARNESS_DAEMON_LABEL}" => disabled\n`,
        stderr: "",
      };
    }
    if (verb === "print") {
      // Default: launchd does not know the service (code 3 = not loaded).
      return {
        code: overrides.print?.code ?? 3,
        stdout: overrides.print?.stdout ?? "",
        stderr: overrides.print?.stderr ?? "Could not find service",
      };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  return { fn, calls };
}

/** In-memory fs seam (readFileFn ENOENTs on absent paths). */
function parkFs(initial: Record<string, string> = {}) {
  const files = new Map(Object.entries(initial));
  return {
    files,
    readFileFn: async (p: string): Promise<string> => {
      const v = files.get(p);
      if (v === undefined) {
        const e = new Error(`ENOENT: ${p}`) as NodeJS.ErrnoException;
        e.code = "ENOENT";
        throw e;
      }
      return v;
    },
    writeFileFn: async (p: string, c: string): Promise<void> => {
      files.set(p, c);
    },
    removeFileFn: async (p: string): Promise<void> => {
      files.delete(p);
    },
  };
}

describe("parkHarnessPersistently (fix-round-2 HIGH-2: full persistent park)", () => {
  it("runs bootout + disable + hold-file removal + parked-plist restore, verifies the posture, and resolves", async () => {
    const { fn, calls } = parkLaunchctl();
    const fs = parkFs({ [HOLD_PATH]: "stale hold file" });
    await parkHarnessPersistently(PARK_CTX, { runLaunchctlFn: fn, ...fs });
    // The stale hold file is GONE and the parked plist is back on disk.
    expect(fs.files.has(HOLD_PATH)).toBe(false);
    expect(fs.files.get(PARKED_PLAN.plistPath)).toBe(PARKED_PLAN.plistContent);
    // All three launchctl legs ran: bootout, disable, and the PERSISTENT
    // disable read-back (print-disabled), plus the not-running probe (print).
    expect(calls).toContain(`bootout system/${AGENT_HARNESS_DAEMON_LABEL}`);
    expect(calls).toContain(`disable system/${AGENT_HARNESS_DAEMON_LABEL}`);
    expect(calls).toContain("print-disabled system");
    expect(calls.some((c) => c.startsWith("print system/"))).toBe(true);
  });

  it("the reviewed defect: bootout ok + disable FAILS + probe says stopped must THROW, never a silent park claim", async () => {
    const { fn } = parkLaunchctl({
      disable: { code: 5, stderr: "override db locked" },
      // The override db never took the disable either.
      printDisabled: { code: 0, stdout: "" },
    });
    const fs = parkFs();
    await expect(parkHarnessPersistently(PARK_CTX, { runLaunchctlFn: fn, ...fs })).rejects.toThrow(
      /park not verified: .*disable exited 5/,
    );
  });

  it("a disable that EXITS 0 but did not persist in the override db is NOT a park (read-back enforced)", async () => {
    const { fn } = parkLaunchctl({
      disable: { code: 0 },
      printDisabled: { code: 0, stdout: `\t"${AGENT_HARNESS_DAEMON_LABEL}" => enabled\n` },
    });
    const fs = parkFs();
    await expect(parkHarnessPersistently(PARK_CTX, { runLaunchctlFn: fn, ...fs })).rejects.toThrow(
      /override database does not show/,
    );
  });

  it("a still-RUNNING harness after the park ops fails the verify loudly", async () => {
    const { fn } = parkLaunchctl({
      print: { code: 0, stdout: "\tstate = running\n\tpid = 4242\n" },
    });
    const fs = parkFs();
    await expect(parkHarnessPersistently(PARK_CTX, { runLaunchctlFn: fn, ...fs })).rejects.toThrow(
      /reports RUNNING \(pid 4242\)/,
    );
  });
});

describe("verifyHarnessParkedPersistent (fix-round-2 HIGH-2: posture verify enumerates every failed check)", () => {
  it("ok only when: not running + disabled in the override db + hold file absent + parked plist (or no plist)", async () => {
    const { fn } = parkLaunchctl();
    // Parked plist on disk: ok.
    await expect(
      verifyHarnessParkedPersistent(PARK_CTX, {
        runLaunchctlFn: fn,
        ...parkFs({ [PARKED_PLAN.plistPath]: PARKED_PLAN.plistContent }),
      }),
    ).resolves.toEqual({ ok: true });
    // No plist at all (nothing launchd can boot): also ok.
    await expect(
      verifyHarnessParkedPersistent(PARK_CTX, { runLaunchctlFn: fn, ...parkFs() }),
    ).resolves.toEqual({ ok: true });
  });

  it("STALE RELEASE MATERIAL is enumerated: lingering hold file and a non-parked (released) plist are each named", async () => {
    const releasedPlan = planParkedHarnessInstall({
      agentAccount: PARK_CTX.agentAccount,
      agentUid: PARK_CTX.agentUid,
      harnessArgv: PARK_CTX.harnessArgv,
      fortressPath: PARK_CTX.fortressPath,
      logDir: PARK_CTX.harnessLogDir,
      expectedGenerationId: 7, // a RELEASED plist form
    });
    const { fn } = parkLaunchctl();
    const verdict = await verifyHarnessParkedPersistent(PARK_CTX, {
      runLaunchctlFn: fn,
      ...parkFs({
        [HOLD_PATH]: "hold file left behind",
        [PARKED_PLAN.plistPath]: releasedPlan.plistContent,
      }),
    });
    expect(verdict.ok).toBe(false);
    const problems = (verdict as { problems: string[] }).problems.join(" | ");
    expect(problems).toContain("hold file");
    expect(problems).toContain("still present");
    expect(problems).toContain("not the parked barrier form");
  });

  it("an untrustworthy launchctl status is NOT a verified park (fail-closed)", async () => {
    const { fn } = parkLaunchctl({ print: { code: 1, stdout: "", stderr: "launchctl wedged" } });
    const verdict = await verifyHarnessParkedPersistent(PARK_CTX, { runLaunchctlFn: fn, ...parkFs() });
    expect(verdict.ok).toBe(false);
    expect((verdict as { problems: string[] }).problems.join(" ")).toContain("trustworthy");
  });
});

describe("verifyHarnessJobDisabled (persistent override-db read-back)", () => {
  it("accepts both macOS print-disabled formats (=> disabled and => true)", async () => {
    for (const stdout of [
      `\t"${AGENT_HARNESS_DAEMON_LABEL}" => disabled\n`,
      `\t"${AGENT_HARNESS_DAEMON_LABEL}" => true\n`,
    ]) {
      const { fn } = parkLaunchctl({ printDisabled: { code: 0, stdout } });
      await expect(verifyHarnessJobDisabled(fn)).resolves.toEqual({ ok: true });
    }
  });

  it("an absent label, an enabled label, or a failing launchctl are each NOT disabled-verified", async () => {
    const cases = [
      { printDisabled: { code: 0, stdout: "" } },
      { printDisabled: { code: 0, stdout: `\t"${AGENT_HARNESS_DAEMON_LABEL}" => enabled\n` } },
      { printDisabled: { code: 1, stdout: "" } },
    ];
    for (const c of cases) {
      const { fn } = parkLaunchctl(c);
      const verdict = await verifyHarnessJobDisabled(fn);
      expect(verdict.ok).toBe(false);
    }
  });
});
