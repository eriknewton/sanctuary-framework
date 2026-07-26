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
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createExclusiveEgressPostureProducer,
  applyRootOwnedDirEnsure,
  createInstallExclusiveEgressOps,
  createProductionReleaseBarrierOps,
  createRepairExclusiveEgressOps,
  createUnprotectExclusiveEgressOps,
  ensureGateAccountHomeLayout,
  parkHarnessPersistently,
  type GateAccountHomeLayoutOps,
  type RootOwnedDirEnsureOps,
  restoreCoarseCompositionProduction,
  clearExclusiveRoutingResidueWithoutAccount,
  reconcileStaleExclusiveRoutingProduction,
  reloadPeerResolverDaemonForBringUp,
  reloadLaunchdDaemonForBringUp,
  describeGateDaemonStderrTail,
  waitForGateRuntime,
  GATE_DAEMON_STDERR_TAIL_MAX_LINES,
  verifyHarnessJobDisabled,
  verifyHarnessParkedPersistent,
  verifyLoopbackTcpPortOwner,
  PID_START_TOLERANCE_MS,
  type ExclusiveEgressWiringInput,
  type PersistentParkContext,
} from "../../src/egress-gate/arming-wiring.js";
import {
  PfAnchorRegistry,
  PfAnchorRegistryStateError,
} from "../../src/egress-gate/anchor-registry.js";
import {
  gateCredentialAcceptPath,
  gateCredentialTokenPath,
} from "../../src/egress-gate/gate-credential.js";
import {
  egressGateDaemonLabel,
  egressGateDaemonLogPaths,
  egressGateDaemonPlistPath,
  egressGatePolicyConfigPath,
  egressGateRulesConfigPath,
  egressGateRuntimeUidDirPath,
} from "../../src/egress-gate/gate-daemon.js";
import { gateLivenessTokenPath } from "../../src/egress-gate/liveness-oracle.js";
import { peerResolverDaemonLabel, peerResolverDaemonPlistPath } from "../../src/egress-gate/peer-resolver-daemon.js";
import {
  AGENT_HARNESS_DAEMON_LABEL,
  HARNESS_STOP_SETTLE_INTERVAL_MS,
  HARNESS_STOP_SETTLE_SAMPLES,
  harnessLaunchSpec,
} from "../../src/egress-gate/harness-daemon.js";
import {
  holdFilePathForUid,
  planParkedHarnessInstall,
  type ReleaseBarrierOps,
} from "../../src/egress-gate/release-barrier.js";
import {
  exclusiveRoutingMarkerPath,
  ExclusiveRoutingMarkerError,
  type ExclusiveRoutingMarker,
} from "../../src/castle-wall/allowlist/routing-marker.js";
import { EXCLUSIVE_ROUTING_STALE_MARKER_RECONCILED_AUDIT_OP } from "../../src/castle-wall/provision/exclusive-arm.js";
import { EXCLUSIVE_EGRESS_GATE_FILENAME } from "../../src/castle-wall/allowlist/gate-derivation.js";
import { ProvisionLockHeldError } from "../../src/castle-wall/provision/lockfile.js";

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

describe("egress-gate/arming-wiring posture producer", () => {
  it("B3: corrupt registry state throws instead of collapsing to no fine-grained agent", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-egress-producer-"));
    try {
      const producer = createExclusiveEgressPostureProducer(
        {
          fortressPath,
          coarseWallArmed: async () => true,
        },
        {
          registry: {
            list: async () => {
              throw new PfAnchorRegistryStateError("corrupt registry");
            },
          },
        },
      );
      await expect(producer()).rejects.toBeInstanceOf(PfAnchorRegistryStateError);
    } finally {
      await rm(fortressPath, { recursive: true, force: true });
    }
  });
});

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

const TEST_LAUNCH = harnessLaunchSpec({
  programArguments: ["/usr/local/bin/hermes"],
  environment: {
    HOME: "/var/sanctuary-agents/sanctuary-hermes",
    PYTHONPATH: "/var/sanctuary-agents/sanctuary-hermes/.hermes/hermes-agent",
  },
});

const PARK_CTX: PersistentParkContext = {
  agentUid: 502,
  agentAccount: "sanctuary-hermes",
  harnessLaunch: TEST_LAUNCH,
  fortressPath: "/fortress/a",
  harnessLogDir: "/var/sanctuary-agents/sanctuary-hermes/logs",
};

const PARKED_PLAN = planParkedHarnessInstall({
  agentAccount: PARK_CTX.agentAccount,
  agentUid: PARK_CTX.agentUid,
  harnessLaunch: TEST_LAUNCH,
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
    // F8 (2026-07-18 fix-round): DISABLE precedes BOOTOUT, the same order
    // `executeParkedHarnessInstall` asserts and for the same reason -- the
    // harness plist carries KeepAlive, so booting out an enabled job leaves a
    // window for launchd to restart it. The codebase previously stated two
    // different orders for one invariant.
    expect(calls.indexOf(`disable system/${AGENT_HARNESS_DAEMON_LABEL}`)).toBeLessThan(
      calls.indexOf(`bootout system/${AGENT_HARNESS_DAEMON_LABEL}`),
    );
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
      /still RUNNING after waiting .* across .* samples \(pid 4242\)/,
    );
  });

  it("REGRESSION (F-HARNESSENV): the parked-plist RESTORE carries the harness environment", async () => {
    // The drill's park re-render dropped HOME/PYTHONPATH and kept only
    // SANCTUARY_STORAGE_PATH, so the plist the park left behind (and the one
    // the release re-rendered from) could not start the re-homed gateway.
    const { fn } = parkLaunchctl();
    const fs = parkFs();
    await parkHarnessPersistently(PARK_CTX, { runLaunchctlFn: fn, ...fs });
    const written = fs.files.get(PARKED_PLAN.plistPath)!;
    for (const [name, value] of Object.entries(TEST_LAUNCH.environment)) {
      expect(written, `parked plist is missing ${name}`).toContain(`<key>${name}</key>`);
      expect(written).toContain(`<string>${value}</string>`);
    }
  });

  it("REGRESSION (F-HARNESSENV): with NO resolvable harness launch the park REFUSES to write a placeholder plist", async () => {
    // Pre-fix, an unresolvable launch was papered over with a `/usr/bin/false`
    // placeholder argv, which the parked-form COMPARISON then rendered against.
    // A restore that cannot render the real form must fail loudly; the
    // plist-REMOVAL park (the S5-7 MED-1 disposition) owns that condition.
    const { fn } = parkLaunchctl();
    const fs = parkFs();
    const noLaunch = { ...PARK_CTX, harnessLaunch: undefined } as PersistentParkContext;
    await expect(parkHarnessPersistently(noLaunch, { runLaunchctlFn: fn, ...fs })).rejects.toThrow(
      /parked-plist restore failed: .*could not be resolved/,
    );
    expect(fs.files.has(PARKED_PLAN.plistPath)).toBe(false);
  });

  it("REGRESSION (F-HARNESSENV): with no resolvable launch the parked POSTURE requires an ABSENT plist", async () => {
    const { fn } = parkLaunchctl();
    const noLaunch = { ...PARK_CTX, harnessLaunch: undefined } as PersistentParkContext;
    // Absent plist === unbootable === parked.
    await expect(
      verifyHarnessParkedPersistent(noLaunch, { runLaunchctlFn: fn, ...parkFs() }),
    ).resolves.toEqual({ ok: true });
    // A plist that is still on disk cannot be verified against any rendered
    // form, so the posture fails LOUDLY rather than comparing against a
    // placeholder nobody would ever write.
    const verdict = await verifyHarnessParkedPersistent(noLaunch, {
      runLaunchctlFn: fn,
      ...parkFs({ [PARKED_PLAN.plistPath]: PARKED_PLAN.plistContent }),
    });
    expect(verdict.ok).toBe(false);
    expect((verdict as { problems: string[] }).problems.join(" ")).toMatch(/still present/);
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

  it("settles a transient running launchd readback before claiming parked", async () => {
    let printSamples = 0;
    const calls: string[] = [];
    const fn = async (args: readonly string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
      calls.push(args.join(" "));
      if (args[0] === "print-disabled") {
        return { code: 0, stdout: `\t"${AGENT_HARNESS_DAEMON_LABEL}" => disabled\n`, stderr: "" };
      }
      if (args[0] === "print") {
        printSamples += 1;
        if (printSamples === 1) {
          return { code: 0, stdout: "\tstate = running\n\tpid = 4242\n", stderr: "" };
        }
        return { code: 3, stdout: "", stderr: "Could not find service" };
      }
      return { code: 0, stdout: "", stderr: "" };
    };
    await expect(
      verifyHarnessParkedPersistent(PARK_CTX, {
        runLaunchctlFn: fn,
        sleepMs: async () => undefined,
        ...parkFs({ [PARKED_PLAN.plistPath]: PARKED_PLAN.plistContent }),
      }),
    ).resolves.toEqual({ ok: true });
    expect(printSamples).toBeGreaterThan(1);
    expect(calls.filter((c) => c.startsWith("print system/"))).toHaveLength(2);
  });

  it("fails closed when launchd never settles stopped and names the measured wait and sample count", async () => {
    let printSamples = 0;
    const fn = async (args: readonly string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
      if (args[0] === "print-disabled") {
        return { code: 0, stdout: `\t"${AGENT_HARNESS_DAEMON_LABEL}" => disabled\n`, stderr: "" };
      }
      if (args[0] === "print") {
        printSamples += 1;
        return { code: 0, stdout: "\tstate = running\n\tpid = 4242\n", stderr: "" };
      }
      return { code: 0, stdout: "", stderr: "" };
    };
    const verdict = await verifyHarnessParkedPersistent(PARK_CTX, {
      runLaunchctlFn: fn,
      sleepMs: async () => undefined,
      ...parkFs({ [PARKED_PLAN.plistPath]: PARKED_PLAN.plistContent }),
    });
    expect(verdict.ok).toBe(false);
    expect(printSamples).toBe(HARNESS_STOP_SETTLE_SAMPLES);
    const problem = (verdict as { problems: string[] }).problems.join(" ");
    expect(problem).toMatch(/still RUNNING after waiting \d+ ms across 20 samples \(pid 4242\)/);
    expect(problem).not.toContain(`${(HARNESS_STOP_SETTLE_SAMPLES - 1) * HARNESS_STOP_SETTLE_INTERVAL_MS} ms`);
  });

  it("fails closed on an untrustworthy launchd status without fabricating a wait", async () => {
    let printSamples = 0;
    const fn = async (args: readonly string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
      if (args[0] === "print-disabled") {
        return { code: 0, stdout: `\t"${AGENT_HARNESS_DAEMON_LABEL}" => disabled\n`, stderr: "" };
      }
      if (args[0] === "print") {
        printSamples += 1;
        return { code: 5, stdout: "", stderr: "launchd transient failure" };
      }
      return { code: 0, stdout: "", stderr: "" };
    };
    const verdict = await verifyHarnessParkedPersistent(PARK_CTX, {
      runLaunchctlFn: fn,
      sleepMs: async () => undefined,
      ...parkFs({ [PARKED_PLAN.plistPath]: PARKED_PLAN.plistContent }),
    });
    expect(verdict.ok).toBe(false);
    expect(printSamples).toBe(1);
    const problem = (verdict as { problems: string[] }).problems.join(" ");
    expect(problem).toContain("launchctl did not return a trustworthy harness status");
    expect(problem).toContain("sampling once with no settle wait");
    expect(problem).not.toContain(`${(HARNESS_STOP_SETTLE_SAMPLES - 1) * HARNESS_STOP_SETTLE_INTERVAL_MS} ms`);
  });

  it("STALE RELEASE MATERIAL is enumerated: lingering hold file and a non-parked (released) plist are each named", async () => {
    const releasedPlan = planParkedHarnessInstall({
      agentAccount: PARK_CTX.agentAccount,
      agentUid: PARK_CTX.agentUid,
      harnessLaunch: TEST_LAUNCH,
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

describe("createProductionReleaseBarrierOps rearmAnchor (fix-round-3 MED-3: quarantine-aware registry reads)", () => {
  const VALID_ENTRY = { agent_uid: 502, gate_port: 40001, fortress_path: "/fortress/a", generation_id: 7 };

  function memRegistry(
    committed: unknown[],
    armCalls: unknown[] = [],
  ): import("../../src/egress-gate/anchor-registry.js").PfAnchorRegistry {
    let current: unknown = { version: 1, committed, enable_token: "12345" };
    return new PfAnchorRegistry({
      store: {
        load: async () => JSON.parse(JSON.stringify(current)) as never,
        save: async (s) => {
          current = JSON.parse(JSON.stringify(s));
        },
      },
      lock: { acquire: async () => undefined, release: async () => undefined },
      runner: { run: async () => ({ code: 0, stdout: "", stderr: "" }) } as never,
      armUnion: (async (entries: unknown) => {
        armCalls.push(entries);
        return { enableToken: "12345" };
      }) as never,
      unionLiveness: async () => ({ live: true, reasons: [] }),
      disarm: async () => undefined,
    });
  }

  function mkOps(input: {
    registry: import("../../src/egress-gate/anchor-registry.js").PfAnchorRegistry;
    live: boolean;
    liveReasons?: string[];
    printed: string[];
    runLaunchctl?: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
  }) {
    return createProductionReleaseBarrierOps({
      agentUid: 502,
      agentAccount: "sanctuary-hermes",
      harnessLaunch: TEST_LAUNCH,
      fortressPath: "/fortress/a",
      harnessLogDir: "/tmp/sanctuary-test-logs",
      gateUid: 511,
      oracle: {} as never,
      rearm: "boot-rearm",
      print: (line) => input.printed.push(line),
      internals: {
        registry: input.registry,
        probeAnchorLiveness: async () => ({ live: input.live, reasons: input.liveReasons ?? [] }),
        ...(input.runLaunchctl === undefined ? {} : { runLaunchctl: input.runLaunchctl }),
      },
    });
  }

  // ------------------------------------------------------------------
  // FIX-ROUND 2 (2026-07-18), Codex MED + LOW. This factory's `bootoutJob`
  // was the LAST production bootout still carrying its own narrow regex
  // (stderr-only, `No such process` / `Could not find`) after the F4 "one
  // predicate" fix. It is reachable from the release sequence's
  // reassert-parked and bootstrap-cleanup steps, so a clean host reporting a
  // not-loaded shape the regex did not know refused the fine-grained arm for
  // no reason. Same predicate, same shapes, now covered here.
  // ------------------------------------------------------------------

  it("bootoutJob tolerates every not-loaded shape the shared predicate does (a clean host must not refuse)", async () => {
    const notLoaded: Array<{ code: number; stdout: string; stderr: string }> = [
      { code: 3, stdout: "", stderr: "" }, // standalone ESRCH, no phrase
      { code: 113, stdout: "", stderr: "" }, // standalone "could not find specified service"
      { code: 1, stdout: "", stderr: "service not loaded" },
      { code: 1, stdout: "", stderr: "Service is not loaded" },
      { code: 1, stdout: "", stderr: "No such service" },
      { code: 1, stdout: "", stderr: "does not exist" },
      { code: 1, stdout: "Could not find service", stderr: "" }, // stdout, not stderr
    ];
    for (const result of notLoaded) {
      const ops = mkOps({
        registry: memRegistry([VALID_ENTRY]),
        live: true,
        printed: [],
        runLaunchctl: async () => result,
      });
      await expect(
        ops.bootoutJob(),
        `bootout ${result.code} / ${JSON.stringify(result.stderr || result.stdout)} must read as not-loaded`,
      ).resolves.toBeUndefined();
    }
  });

  it("bootoutJob still THROWS on a genuine failure -- the tolerance widened, it did not vanish", async () => {
    const ops = mkOps({
      registry: memRegistry([VALID_ENTRY]),
      live: true,
      printed: [],
      runLaunchctl: async () => ({ code: 5, stdout: "", stderr: "Operation not permitted" }),
    });
    await expect(ops.bootoutJob()).rejects.toThrow(/bootout exited 5/);
  });

  it("a malformed SIBLING entry no longer fails the valid uid's rearm: live rules verify ok, the sibling is LOUD", async () => {
    const printed: string[] = [];
    const ops = mkOps({
      registry: memRegistry([VALID_ENTRY, { bogus: true }]),
      live: true,
      printed,
    });
    // Pre-fix: registry.list() threw "a committed entry is malformed" and the
    // valid uid parked at rearm-anchor with that bare reason.
    const rearm = await ops.rearmAnchor();
    expect(rearm).toEqual({ ok: true });
    const log = printed.join("\n");
    expect(log).toContain("QUARANTINED");
    expect(log).toContain("registry entry #1");
    expect(log).toContain("uid 502");
    expect(log).toContain("repair-egress-gate");
  });

  it("a quarantined sibling with this uid's rules NOT live fails LOUD (no partial union re-render, ever)", async () => {
    const printed: string[] = [];
    const armCalls: unknown[] = [];
    const ops = mkOps({
      registry: memRegistry([VALID_ENTRY, { bogus: true }], armCalls),
      live: false,
      liveReasons: ["anchor not loaded"],
      printed,
    });
    const rearm = await ops.rearmAnchor();
    expect(rearm.ok).toBe(false);
    const reason = (rearm as { ok: false; reason: string }).reason;
    expect(reason).toContain("uid 502");
    expect(reason).toContain("anchor not loaded");
    expect(reason).toContain("quarantined");
    expect(reason).toContain("repair-egress-gate");
    // The fail-open direction is pinned shut: no union was ever re-rendered
    // over the partially-valid baseline (it would drop the quarantined uid's
    // block rules from the anchor).
    expect(armCalls).toHaveLength(0);
  });

  it("a CLEAN registry still takes the full locked re-arm path (addOrUpdate re-renders + re-verifies the union)", async () => {
    const printed: string[] = [];
    const armCalls: unknown[] = [];
    const ops = mkOps({ registry: memRegistry([VALID_ENTRY], armCalls), live: false, printed });
    const rearm = await ops.rearmAnchor();
    expect(rearm).toEqual({ ok: true });
    // The union was re-armed through the registry mutation, NOT skipped via
    // the quarantine-path liveness probe (live:false above would have failed).
    expect(armCalls).toHaveLength(1);
    expect(printed).toHaveLength(0);
  });
});

describe("createInstallExclusiveEgressOps runReleaseSequence (fix-round-4 P1: release binds to the CAPTURED generation)", () => {
  function mkBarrierOps(commitGen: number, calls: string[]): ReleaseBarrierOps {
    // Stateful running flag (fix-round 3, 2026-07-19): reassert-parked now
    // OBSERVES the stop, so an always-running stub refuses at stage one --
    // which is the correct new behaviour and would have masked these tests.
    let running = false;
    return {
      disableJob: async () => {
        calls.push("disableJob");
      },
      enableJob: async () => {
        calls.push("enableJob");
      },
      bootstrapJob: async () => {
        calls.push("bootstrapJob");
        running = true;
      },
      bootoutJob: async () => {
        calls.push("bootoutJob");
        running = false;
      },
      removeHoldFile: async () => undefined,
      writeHoldFile: async () => undefined,
      bootSessionUuid: async () => "ABCDEF01-2345-6789-ABCD-EF0123456789",
      rearmAnchor: async () => ({ ok: true }),
      verifyGate: async () => ({ ok: true, observed: { generation_id: commitGen, agent_uid: 502 } }),
      commitGeneration: async () => ({ generation_id: commitGen, agent_uid: 502 }),
      writeReleasedPlist: async () => undefined,
      restoreParkedPlist: async () => undefined,
      harnessStatus: async () =>
        running
          ? { known: true, installed: true, running: true, pid: 4242 }
          : { known: true, installed: true, running: false },
      sleepMs: async () => {},
    };
  }

  function wiringInput(barrierOps: ReleaseBarrierOps): ExclusiveEgressWiringInput {
    return {
      agentId: "hermes",
      agentUid: 502,
      agentAccount: "sanctuary-hermes",
      fortressPath: "/fortress/a",
      harnessLaunch: TEST_LAUNCH,
      harnessLogDir: "/tmp/sanctuary-test-logs",
      agentTemplate: "hermes",
      gateDaemonArgvPrefix: ["sanctuary"],
      excludeUids: [501],
      gateAccountCeiling: 599,
      gateHomeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
      reloadPolicy: async () => ({ ok: true }),
      publishProvisionedRules: async () => ({ ok: true, ruleIds: [] }),
      audit: async () => undefined,
      print: () => undefined,
      accountOps: {} as never,
      internals: { barrierOps },
    };
  }

  const CAPTURED = { generation_id: 7, agent_uid: 502, gate_port: 49152 };

  it("a registry generation advanced between bring-up and release parks LOUDLY at commit-generation, never releases", async () => {
    const calls: string[] = [];
    // This run brought up generation 7; a concurrent repair/install advanced
    // the registry to generation 8 before the barrier committed. Pre-fix, the
    // barrier bound to generation 8 (the re-read) and RELEASED it with this
    // run's stale context while the caller audited generation 7.
    const ops = createInstallExclusiveEgressOps(wiringInput(mkBarrierOps(8, calls)));
    const outcome = await ops.runReleaseSequence(CAPTURED);
    expect(outcome.kind).toBe("parked");
    expect((outcome as { stage: string }).stage).toBe("commit-generation");
    const reason = (outcome as { reason: string }).reason;
    expect(reason).toContain("registry changed during release for uid 502");
    expect(reason).toContain("generation 7");
    expect(reason).toContain("generation 8");
    expect(reason).toContain("re-run the repair");
    // The release surfaces were never touched (fail-closed park, agent stays
    // parked: no enable, no bootstrap).
    expect(calls).not.toContain("enableJob");
    expect(calls).not.toContain("bootstrapJob");
  });

  it("a matching generation at commit still releases (no false park from the guard)", async () => {
    const ops = createInstallExclusiveEgressOps(wiringInput(mkBarrierOps(7, [])));
    const outcome = await ops.runReleaseSequence(CAPTURED);
    expect(outcome).toEqual({ kind: "released", generation_id: 7 });
  });

  it("the REPAIR ops reuse the guarded install release path (repair run A cannot release repair run B's generation)", async () => {
    const calls: string[] = [];
    const repair = createRepairExclusiveEgressOps(wiringInput(mkBarrierOps(8, calls)));
    const outcome = await repair.runReleaseSequence(CAPTURED);
    expect(outcome.kind).toBe("parked");
    expect((outcome as { stage: string }).stage).toBe("commit-generation");
    expect((outcome as { reason: string }).reason).toContain("registry changed during release for uid 502");
    expect(calls).not.toContain("enableJob");
    // And the matching case releases through the same repair surface.
    const ok = createRepairExclusiveEgressOps(wiringInput(mkBarrierOps(7, [])));
    expect(await ok.runReleaseSequence(CAPTURED)).toEqual({ kind: "released", generation_id: 7 });
  });
});

// ---------------------------------------------------------------------------
// S5-7: createUnprotectExclusiveEgressOps -- the production mapping of the
// unprotect sequence's injected ops (the sequence itself is pinned in
// castle-wall/provision/exclusive-unprotect.test.ts).
// ---------------------------------------------------------------------------

describe("createUnprotectExclusiveEgressOps (S5-7 production wiring)", () => {
  const UNPROTECT_INPUT = {
    agentUid: 601,
    agentId: "hermes",
    agentAccount: "sanctuary-hermes",
    fortressPath: "/fortress/a",
    harnessLaunch: TEST_LAUNCH,
    harnessLogDir: "/var/sanctuary-agents/sanctuary-hermes/logs",
    audit: async () => {},
    print: () => {},
  } as unknown as ExclusiveEgressWiringInput;

  /**
   * A registry whose `list()` returns a fixed committed set -- the only method
   * `assertSoleUserInvariant` reads. Everything else is undefined (the teardown
   * ops under test never call it).
   */
  function stubListRegistry(
    entries: Array<{ agent_uid: number; gate_port: number; fortress_path: string; tombstone?: boolean }>,
  ): PfAnchorRegistry {
    return { list: async () => ({ entries, dirty: false }) } as unknown as PfAnchorRegistry;
  }

  /** A registry whose `list()` throws (an unreadable registry). */
  function throwingListRegistry(): PfAnchorRegistry {
    return {
      list: async () => {
        throw new Error("EACCES: egress-anchor-registry.json");
      },
    } as unknown as PfAnchorRegistry;
  }

  it("assertSoleUserInvariant: the sole committed uid is OK (no conflicting uids)", async () => {
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      registry: stubListRegistry([{ agent_uid: 601, gate_port: 20000, fortress_path: "/fortress/a" }]),
    });
    await expect(ops.assertSoleUserInvariant()).resolves.toEqual({ ok: true });
  });

  it("assertSoleUserInvariant: ANY other committed non-tombstone entry (shared fortress OR harness) is a conflict -> NOT ok", async () => {
    // Same fortress sibling.
    const sameFortress = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      registry: stubListRegistry([
        { agent_uid: 601, gate_port: 20000, fortress_path: "/fortress/a" },
        { agent_uid: 602, gate_port: 20001, fortress_path: "/fortress/a" },
      ]),
    });
    await expect(sameFortress.assertSoleUserInvariant()).resolves.toEqual({ ok: false, conflictingUids: [602] });
    // Different fortress but the single v1 harness (no per-entry harness id) ->
    // still a conflict, fail-closed.
    const otherFortress = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      registry: stubListRegistry([
        { agent_uid: 601, gate_port: 20000, fortress_path: "/fortress/a" },
        { agent_uid: 603, gate_port: 20002, fortress_path: "/fortress/b" },
      ]),
    });
    await expect(otherFortress.assertSoleUserInvariant()).resolves.toEqual({ ok: false, conflictingUids: [603] });
  });

  it("assertSoleUserInvariant: a TOMBSTONE-only other entry is excluded (block-only residue is not a live sibling) -> ok", async () => {
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      registry: stubListRegistry([
        { agent_uid: 601, gate_port: 20000, fortress_path: "/fortress/a" },
        { agent_uid: 602, gate_port: 20001, fortress_path: "/fortress/a", tombstone: true },
      ]),
    });
    await expect(ops.assertSoleUserInvariant()).resolves.toEqual({ ok: true });
  });

  it("assertSoleUserInvariant: an unreadable registry THROWS (the sequence maps that to a fail-closed refusal)", async () => {
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, { registry: throwingListRegistry() });
    await expect(ops.assertSoleUserInvariant()).rejects.toThrow(/egress-anchor-registry\.json/);
  });

  it("withUnprotectLock: brackets fn with the injected O_EXCL lock acquire/release around PROVISION_LOCK_PATH", async () => {
    const events: string[] = [];
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      lockOps: {
        acquire: async (p) => {
          events.push(`acquire ${p}`);
        },
        release: async (p) => {
          events.push(`release ${p}`);
        },
      },
    });
    const result = await ops.withUnprotectLock(async () => {
      events.push("body");
      return 42;
    });
    expect(result).toBe(42);
    expect(events).toEqual([
      "acquire /var/run/sanctuary-provision.lock",
      "body",
      "release /var/run/sanctuary-provision.lock",
    ]);
  });

  it("withUnprotectLock: a held lock (acquire EEXIST) throws ProvisionLockHeldError; the body never runs", async () => {
    let bodyRan = false;
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      lockOps: {
        acquire: async () => {
          const err = new Error("EEXIST") as NodeJS.ErrnoException;
          err.code = "EEXIST";
          throw err;
        },
        release: async () => {},
      },
    });
    await expect(
      ops.withUnprotectLock(async () => {
        bodyRan = true;
      }),
    ).rejects.toBeInstanceOf(ProvisionLockHeldError);
    expect(bodyRan).toBe(false);
  });

  it("bootoutGateDaemon: not-running/not-found is SUCCESS; a genuine failure THROWS with the label named", async () => {
    const mk = (code: number, stderr: string) =>
      createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
        runLaunchctl: async () => ({ code, stdout: "", stderr }),
      });
    await expect(mk(0, "").bootoutGateDaemon()).resolves.toBeUndefined();
    await expect(mk(3, "Boot-out failed: 3: No such process").bootoutGateDaemon()).resolves.toBeUndefined();
    await expect(mk(113, "Could not find service").bootoutGateDaemon()).resolves.toBeUndefined();
    await expect(mk(5, "Boot-out failed: 5: Input/output error").bootoutGateDaemon()).rejects.toThrow(
      /bootout ai\.sanctuaryprotocol\.egress-gate\.601 exited 5/,
    );
  });

  it("bootoutGateDaemon (2026-07-24 S5-3 fix): ALSO boots out the peer-resolver daemon, gate FIRST", async () => {
    const calls: string[] = [];
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      runLaunchctl: async (args) => {
        calls.push(args.join(" "));
        return { code: 0, stdout: "", stderr: "" };
      },
    });
    await ops.bootoutGateDaemon();
    expect(calls).toEqual([
      "bootout system/ai.sanctuaryprotocol.egress-gate.601",
      "bootout system/ai.sanctuaryprotocol.egress-gate-peer-resolver.601",
    ]);
  });

  it("bootoutGateDaemon: a peer-resolver-only failure (gate stops fine) THROWS with the resolver label named", async () => {
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      runLaunchctl: async (args) => {
        if (args.join(" ").includes("peer-resolver")) {
          return { code: 5, stdout: "", stderr: "Boot-out failed: 5: Input/output error" };
        }
        return { code: 0, stdout: "", stderr: "" };
      },
    });
    await expect(ops.bootoutGateDaemon()).rejects.toThrow(
      /bootout ai\.sanctuaryprotocol\.egress-gate-peer-resolver\.601 exited 5/,
    );
  });

  it("credential + oracle teardown removes EXACTLY the single-source uid-keyed paths (no constructed authority needed)", async () => {
    const removed: string[] = [];
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      removeFile: async (path) => {
        removed.push(path);
      },
    });
    await ops.invalidateOracleToken();
    await ops.revokeCredential();
    expect(removed).toEqual([
      gateLivenessTokenPath(601),
      gateCredentialAcceptPath(601),
      gateCredentialTokenPath(601),
    ]);
  });

  it("removeGateSurfaces (sole user, asserted): per-uid surfaces first, then the fortress marker + policy file -- every surface goes", async () => {
    const removed: string[] = [];
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      removeFile: async (path) => {
        removed.push(path);
      },
    });
    await ops.removeGateSurfaces();
    expect(removed).toEqual([
      egressGateDaemonPlistPath(601),
      peerResolverDaemonPlistPath(601),
      egressGatePolicyConfigPath(601),
      egressGateRulesConfigPath(601),
      egressGateRuntimeUidDirPath(601),
      exclusiveRoutingMarkerPath("/fortress/a"),
      `/fortress/a/policy/egress/${EXCLUSIVE_EGRESS_GATE_FILENAME}`,
    ]);
  });

  it("removeRegistryEntry routes through the locked registry remove and maps remaining/flushed/dirty", async () => {
    const removeCalls: number[] = [];
    const stubRegistry = {
      remove: async (uid: number) => {
        removeCalls.push(uid);
        return {
          committed: [{ agent_uid: 602, gate_port: 20001, fortress_path: "/fortress/b" }],
          dirty: false,
        };
      },
    } as unknown as PfAnchorRegistry;
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, { registry: stubRegistry });
    await expect(ops.removeRegistryEntry()).resolves.toEqual({
      remainingUids: [602],
      flushed: false,
      dirty: false,
    });
    expect(removeCalls).toEqual([601]);

    const emptyRegistry = {
      remove: async () => ({ committed: [], dirty: true }),
    } as unknown as PfAnchorRegistry;
    const last = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, { registry: emptyRegistry });
    await expect(last.removeRegistryEntry()).resolves.toEqual({
      remainingUids: [],
      flushed: true,
      dirty: true,
    });
  });

  it("recoverGeneration + scrubProvisionedRules route through their injected seams with this uid/harness", async () => {
    const recovered: number[] = [];
    const ops = createUnprotectExclusiveEgressOps(UNPROTECT_INPUT, {
      recoverGeneration: async (uid) => {
        recovered.push(uid);
      },
      scrubRules: async () => ({ removedRuleIds: ["provisioned-hermes-api"], reloadOk: true }),
    });
    await ops.recoverGeneration();
    expect(recovered).toEqual([601]);
    await expect(ops.scrubProvisionedRules()).resolves.toEqual({
      removedRuleIds: ["provisioned-hermes-api"],
      reloadOk: true,
    });
  });

  const PARK_INPUT = {
    ...UNPROTECT_INPUT,
    agentUid: PARK_CTX.agentUid,
    agentAccount: PARK_CTX.agentAccount,
    harnessLaunch: TEST_LAUNCH,
    fortressPath: PARK_CTX.fortressPath,
    harnessLogDir: PARK_CTX.harnessLogDir,
  } as unknown as ExclusiveEgressWiringInput;

  it("parkHarness (sole user) runs the full persistent park: bootout + disable + parked-plist restore, verified", async () => {
    const { fn, calls } = parkLaunchctl();
    const fs = parkFs();
    const ops = createUnprotectExclusiveEgressOps(PARK_INPUT, {
      parkDeps: { runLaunchctlFn: fn, ...fs },
    });
    await ops.parkHarness();
    expect(calls.some((c) => c.startsWith("bootout"))).toBe(true);
    expect(calls.some((c) => c.startsWith("disable"))).toBe(true);
    expect(fs.files.get(PARKED_PLAN.plistPath)).toBe(PARKED_PLAN.plistContent);
    await expect(ops.verifyParkedPersistent()).resolves.toEqual({ ok: true });
  });

  it("parkHarness (MED-1 argv-unavailable fallback) REMOVES the plist instead of restoring it; verified parked", async () => {
    const { fn, calls } = parkLaunchctl();
    // Simulate a stale released plist on disk that the fallback must remove,
    // plus a stale hold file that the park removes.
    const fs = parkFs({
      [PARKED_PLAN.plistPath]: "<plist>stale released form</plist>",
      [HOLD_PATH]: "stale hold file",
    });
    const ops = createUnprotectExclusiveEgressOps(
      { ...PARK_INPUT, harnessLaunch: undefined } as unknown as ExclusiveEgressWiringInput,
      {
        parkDeps: { runLaunchctlFn: fn, ...fs },
      },
    );
    await ops.parkHarness();
    expect(calls.some((c) => c.startsWith("bootout"))).toBe(true);
    expect(calls.some((c) => c.startsWith("disable"))).toBe(true);
    // The plist is REMOVED (absent === unbootable), never re-rendered, and the
    // leaving uid's hold file is gone.
    expect(fs.files.has(PARKED_PLAN.plistPath)).toBe(false);
    expect(fs.files.has(HOLD_PATH)).toBe(false);
    await expect(ops.verifyParkedPersistent()).resolves.toEqual({ ok: true });
  });
});

/**
 * The root-owned runtime-directory ensure policy (drill D1 + the 2026-07-18
 * two-family gate's F5/F7 findings).
 *
 * Asserted against the POLICY function over injected ops rather than the real
 * filesystem, because the two steps that matter most -- `chown(0,0)` and the
 * symlink refusal -- cannot be exercised by a non-root test process against
 * real `fs`. The previous coverage substituted a hand-written ensure that
 * DROPPED the chown, so deleting the production chown line changed no test.
 */
describe("applyRootOwnedDirEnsure (root-owned runtime directory policy)", () => {
  interface EnsureLog {
    sequence: string[];
  }

  function makeEnsureOps(kinds: Record<string, "dir" | "symlink" | "other"> = {}): {
    ops: RootOwnedDirEnsureOps;
    log: EnsureLog;
  } {
    const log: EnsureLog = { sequence: [] };
    return {
      log,
      ops: {
        async mkdir(path) {
          log.sequence.push(`mkdir:${path}`);
        },
        async lstatKind(path) {
          log.sequence.push(`lstat:${path}`);
          return kinds[path] ?? "dir";
        },
        async chown(path, uid, gid) {
          log.sequence.push(`chown:${path}:${uid}:${gid}`);
        },
        async chmod(path, mode) {
          log.sequence.push(`chmod:${path}:${mode.toString(8)}`);
        },
      },
    };
  }

  const HOLD = "/var/db/sanctuary/agent-harness";
  const PARENT = "/var/db/sanctuary";

  it("chowns the directory to root:wheel -- the step the old non-root test branch silently dropped", async () => {
    const { ops, log } = makeEnsureOps();
    await applyRootOwnedDirEnsure(HOLD, 0o755, ops);
    expect(log.sequence).toContain(`chown:${HOLD}:0:0`);
    // chown BEFORE chmod: mode on a directory someone else owns is meaningless.
    expect(log.sequence.indexOf(`chown:${HOLD}:0:0`)).toBeLessThan(
      log.sequence.indexOf(`chmod:${HOLD}:755`),
    );
  });

  it("applies an EXPLICIT chmod, because mkdir's mode argument is umask-masked", async () => {
    const { ops, log } = makeEnsureOps();
    await applyRootOwnedDirEnsure(HOLD, 0o755, ops);
    expect(log.sequence).toContain(`chmod:${HOLD}:755`);
    expect(log.sequence.indexOf(`mkdir:${HOLD}`)).toBeLessThan(
      log.sequence.indexOf(`chmod:${HOLD}:755`),
    );
  });

  it("F5: ensures the PARENT too, so a first-ever install does not leave /var/db/sanctuary at umask mercy", async () => {
    // The leaf-only version left the parent at `0777 & ~umask`; under a
    // hardened umask the agent uid could not traverse to its own hold file,
    // and the only thing that healed it was a LATER, unpinned step.
    const { ops, log } = makeEnsureOps();
    await applyRootOwnedDirEnsure(HOLD, 0o755, ops);
    expect(log.sequence).toContain(`chmod:${PARENT}:755`);
    expect(log.sequence).toContain(`chown:${PARENT}:0:0`);
    // Parent fully established before the leaf is touched at all.
    expect(log.sequence.indexOf(`chmod:${PARENT}:755`)).toBeLessThan(
      log.sequence.indexOf(`mkdir:${HOLD}`),
    );
  });

  it("F7: REFUSES a symlink-shaped directory before applying any ownership or mode to its target", async () => {
    // Empirically demonstrated by the Codex lens: mkdir(p,{recursive:true})
    // succeeds when p is a symlink to a directory, and the following chmod
    // then changes the TARGET's mode. Root-run installer code must not do
    // that, whatever /var/db's ownership makes "unlikely".
    const { ops, log } = makeEnsureOps({ [HOLD]: "symlink" });
    await expect(applyRootOwnedDirEnsure(HOLD, 0o755, ops)).rejects.toThrow(/symlink/);
    expect(log.sequence).not.toContain(`chown:${HOLD}:0:0`);
    expect(log.sequence).not.toContain(`chmod:${HOLD}:755`);
  });

  it("F7: refuses a symlink at the PARENT as well, before touching the leaf", async () => {
    const { ops, log } = makeEnsureOps({ [PARENT]: "symlink" });
    await expect(applyRootOwnedDirEnsure(HOLD, 0o755, ops)).rejects.toThrow(/symlink/);
    expect(log.sequence).not.toContain(`mkdir:${HOLD}`);
  });

  it("F7: refuses a plain FILE sitting where the directory should be", async () => {
    const { ops } = makeEnsureOps({ [HOLD]: "other" });
    await expect(applyRootOwnedDirEnsure(HOLD, 0o755, ops)).rejects.toThrow(/not a real directory/);
  });
});

describe("ensureGateAccountHomeLayout (D6 gate-owned log directory invariant)", () => {
  interface FakeStat {
    kind: "dir" | "file" | "symlink" | "other";
    uid: number;
    gid: number;
    mode: number;
  }

  function makeGateHomeOps(initial: Record<string, FakeStat> = {}): {
    ops: GateAccountHomeLayoutOps;
    stats: Map<string, FakeStat>;
    sequence: string[];
  } {
    const stats = new Map<string, FakeStat>(Object.entries(initial));
    const sequence: string[] = [];
    const dirStat = (uid = 0, gid = 0, mode = 0o755): FakeStat => ({ kind: "dir", uid, gid, mode });
    const fileStat = (uid = 0, gid = 0, mode = 0o600): FakeStat => ({ kind: "file", uid, gid, mode });
    return {
      stats,
      sequence,
      ops: {
        async mkdir(path) {
          sequence.push(`mkdir:${path}`);
          if (!stats.has(path)) stats.set(path, dirStat());
        },
        async ensureFile(path, mode) {
          sequence.push(`ensureFile:${path}:${mode.toString(8)}`);
          if (!stats.has(path)) stats.set(path, fileStat(0, 0, mode));
        },
        async chown(path, uid, gid) {
          sequence.push(`chown:${path}:${uid}:${gid}`);
          const st = stats.get(path);
          if (st !== undefined) stats.set(path, { ...st, uid, gid });
        },
        async chmod(path, mode) {
          sequence.push(`chmod:${path}:${mode.toString(8)}`);
          const st = stats.get(path);
          if (st !== undefined) stats.set(path, { ...st, mode });
        },
        async lstat(path) {
          sequence.push(`lstat:${path}`);
          const st = stats.get(path);
          if (st === undefined) {
            const err = new Error(`ENOENT: ${path}`) as NodeJS.ErrnoException;
            err.code = "ENOENT";
            throw err;
          }
          return {
            uid: st.uid,
            gid: st.gid,
            mode: st.mode,
            isDirectory: () => st.kind === "dir",
            isFile: () => st.kind === "file",
            isSymbolicLink: () => st.kind === "symlink",
          };
        },
      },
    };
  }

  it("prepares the gate home and logs under the gate uid, not under the agent harness log dir", async () => {
    const home = "/var/sanctuary-agents/sanctuary-gate-hermes";
    const logDir = `${home}/logs`;
    const { ops, stats, sequence } = makeGateHomeOps();
    await expect(
      ensureGateAccountHomeLayout(
        { agentUid: 502, gateAccount: "sanctuary-gate-hermes", gateUid: 505, gateHomeDirectory: home },
        ops,
      ),
    ).resolves.toEqual({ logDir });

    const { stdoutPath, stderrPath } = egressGateDaemonLogPaths({
      agentUid: 502,
      gateAccount: "sanctuary-gate-hermes",
      gateHomeDirectory: home,
    });
    expect(stats.get("/var/sanctuary-agents")).toMatchObject({ uid: 0, mode: 0o711 });
    expect(stats.get(home)).toMatchObject({ uid: 505, gid: 505, mode: 0o700 });
    expect(stats.get(logDir)).toMatchObject({ uid: 505, gid: 505, mode: 0o700 });
    expect(stats.get(stdoutPath)).toMatchObject({ kind: "file", uid: 505, gid: 505, mode: 0o600 });
    expect(stats.get(stderrPath)).toMatchObject({ kind: "file", uid: 505, gid: 505, mode: 0o600 });
    expect(sequence).toContain(`chown:${logDir}:505:505`);
    expect(sequence).toContain(`chown:${stdoutPath}:505:505`);
    expect(sequence).toContain(`chown:${stderrPath}:505:505`);
    expect(logDir).not.toBe("/var/sanctuary-agents/sanctuary-hermes/logs");
  });

  it("refuses an agent-account home paired with the gate account before touching it", async () => {
    const { ops, sequence } = makeGateHomeOps();
    await expect(
      ensureGateAccountHomeLayout(
        {
          agentUid: 502,
          gateAccount: "sanctuary-gate-hermes",
          gateUid: 505,
          gateHomeDirectory: "/var/sanctuary-agents/sanctuary-hermes",
        },
        ops,
      ),
    ).rejects.toThrow(/cross-account logs/);
    expect(sequence).toEqual([]);
  });

  it("refuses a symlink-shaped gate log dir before chown/chmod can apply through it", async () => {
    const home = "/var/sanctuary-agents/sanctuary-gate-hermes";
    const logDir = `${home}/logs`;
    const { ops, sequence } = makeGateHomeOps({ [logDir]: { kind: "symlink", uid: 0, gid: 0, mode: 0o777 } });
    await expect(
      ensureGateAccountHomeLayout(
        { agentUid: 502, gateAccount: "sanctuary-gate-hermes", gateUid: 505, gateHomeDirectory: home },
        ops,
      ),
    ).rejects.toThrow(/symlink/);
    expect(sequence).not.toContain(`chown:${logDir}:505:505`);
    expect(sequence).not.toContain(`chmod:${logDir}:700`);
  });

  it("H2: refuses a caller-supplied home outside the Sanctuary account base before any mutation", async () => {
    const { ops, sequence } = makeGateHomeOps();
    await expect(
      ensureGateAccountHomeLayout(
        {
          agentUid: 502,
          gateAccount: "sanctuary-gate-hermes",
          gateUid: 505,
          gateHomeDirectory: "/sanctuary-gate-hermes",
        },
        ops,
      ),
    ).rejects.toThrow(/outside \/var\/sanctuary-agents/);
    expect(sequence).toEqual([]);
  });

  it("H3: re-owns stale launchd log files from a prior gate uid before reporting the layout verified", async () => {
    const home = "/var/sanctuary-agents/sanctuary-gate-hermes";
    const { stdoutPath, stderrPath } = egressGateDaemonLogPaths({
      agentUid: 502,
      gateAccount: "sanctuary-gate-hermes",
      gateHomeDirectory: home,
    });
    const { ops, stats, sequence } = makeGateHomeOps({
      [stdoutPath]: { kind: "file", uid: 505, gid: 505, mode: 0o600 },
      [stderrPath]: { kind: "file", uid: 505, gid: 505, mode: 0o600 },
    });
    await ensureGateAccountHomeLayout(
      { agentUid: 502, gateAccount: "sanctuary-gate-hermes", gateUid: 506, gateHomeDirectory: home },
      ops,
    );
    expect(sequence).toContain(`lstat:${stdoutPath}`);
    expect(sequence).toContain(`chown:${stdoutPath}:506:506`);
    expect(sequence).toContain(`chmod:${stdoutPath}:600`);
    expect(stats.get(stdoutPath)).toMatchObject({ kind: "file", uid: 506, gid: 506, mode: 0o600 });
    expect(stats.get(stderrPath)).toMatchObject({ kind: "file", uid: 506, gid: 506, mode: 0o600 });
  });
});

// ---------------------------------------------------------------------------
// D8 self-heal (2026-07-22): reconcileStaleExclusiveRoutingProduction removes
// an ORPHANED exclusive-routing marker before re-arm, but ONLY when it can
// prove no live confinement exists (invariant 2, fail toward confinement). The
// side effects are seamed so the decision is asserted host-free.
// ---------------------------------------------------------------------------

describe("reconcileStaleExclusiveRoutingProduction (D8 stale-marker self-heal)", () => {
  const FORTRESS = "/fortress/recon";
  const MARKER: ExclusiveRoutingMarker = {
    version: 1,
    mode: "exclusive",
    agent_uid: 707,
    gate_uid: 708,
    agent_id: "hermes",
    agent_template: "hermes",
  };
  const MARKER_PATH = exclusiveRoutingMarkerPath(FORTRESS);
  const GATE_POLICY_PATH = join(FORTRESS, "policy", "egress", EXCLUSIVE_EGRESS_GATE_FILENAME);

  function reconInput(): {
    agentUid: number;
    intent: "observe" | "clear";
    fortressPath: string;
    audit: ReturnType<typeof vi.fn>;
    print: ReturnType<typeof vi.fn>;
  } {
    return {
      agentUid: MARKER.agent_uid,
      // FIX F1 (2026-07-26): the reconcile is now two-intent. The default here
      // is "clear" (judge AND remove), which is what every pre-existing
      // liveness assertion below is about; the "observe" half has its own test.
      intent: "clear",
      fortressPath: FORTRESS,
      audit: vi.fn(async () => undefined),
      print: vi.fn(),
    };
  }
  /** The refusal-reason field of a keep verdict, without narrowing gymnastics. */
  const keptReason = (r: unknown): string => (r as { reason: string }).reason;
  const enoent = (): NodeJS.ErrnoException => Object.assign(new Error("ENOENT"), { code: "ENOENT" });
  /** Clean registry snapshot (not dirty, nothing quarantined) with optional entries. */
  const cleanRegistry = (
    entries: { agent_uid: number }[] = [],
  ): { entries: { agent_uid: number }[]; dirty: boolean; quarantined: { index: number; reason: string }[] } => ({
    entries,
    dirty: false,
    quarantined: [],
  });
  const noPlist = async (): Promise<boolean> => false;
  function runtimeStateJson(
    overrides: Partial<{ agent_uid: number; gate_port: number; generation_id: number; pid: number; pid_start: string }> = {},
  ): string {
    return JSON.stringify({
      agent_uid: MARKER.agent_uid,
      gate_port: 49222,
      generation_id: 5,
      pid: 4242,
      pid_start: "4242-1721600000000",
      ...overrides,
    });
  }

  it("marker ABSENT -> no-op {kind:'clear'}, no writes, no audit", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => null,
      listRegistry: async () => cleanRegistry(),
      removeFile,
    });
    expect(result).toEqual({ kind: "clear" });
    expect(removeFile).not.toHaveBeenCalled();
    expect(input.audit).not.toHaveBeenCalled();
  });

  it("FIX-1 cross-uid: a marker declaring a DIFFERENT uid than the arm target is KEPT fail-closed (never judged against the wrong subject)", async () => {
    // Arm target 999; marker declares 707. Another uid may be live, so we must
    // not reconcile this marker against uid 999's liveness.
    const input = {
      agentUid: 999,
      intent: "clear" as const,
      fortressPath: FORTRESS,
      audit: vi.fn(async () => undefined),
      print: vi.fn(),
    };
    const removeFile = vi.fn(async () => undefined);
    const listRegistry = vi.fn(async () => cleanRegistry());
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry,
      removeFile,
    });
    // A marker we cannot scope to this run is UNCERTAIN, not a live-gate
    // observation: the operator sentence for it must not read as "you already
    // have a working gate".
    expect(result.kind).toBe("kept-uncertain");
    expect(keptReason(result)).toMatch(/cross-uid marker/);
    // The guard is BEFORE any liveness probe: no registry read, no removal.
    expect(listRegistry).not.toHaveBeenCalled();
    expect(removeFile).not.toHaveBeenCalled();
    expect(input.audit).not.toHaveBeenCalled();
  });

  it("FIX F-COARSE-AFTER-EXCLUSIVE: an UNKNOWN subject uid (the pre-mutation gate on a fresh run) KEEPS the marker fail-closed and is never a wildcard", async () => {
    // The mode-independent residue gate runs BEFORE the account exists, so it
    // can have no uid to scope the marker against. `undefined` must take the
    // same fail-closed branch as a cross-uid mismatch: no subject, no scoped
    // liveness judgement, no removal.
    const input = {
      agentUid: undefined,
      intent: "clear" as const,
      fortressPath: FORTRESS,
      audit: vi.fn(async () => undefined),
      print: vi.fn(),
    };
    const removeFile = vi.fn(async () => undefined);
    const listRegistry = vi.fn(async () => cleanRegistry());
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry,
      // Everything below says "provably orphaned"; the guard must still keep it.
      readRuntimeState: async () => {
        throw enoent();
      },
      plistExists: noPlist,
      removeFile,
    });
    // FIX F3 (2026-07-26): its OWN verdict kind, carrying the marker's uid --
    // this is the one keep whose subject account may be gone entirely, so it
    // needs a different sentence and a different way out.
    expect(result).toMatchObject({ kind: "kept-unknown-subject", markerAgentUid: MARKER.agent_uid });
    expect(keptReason(result)).toMatch(/has not resolved an agent uid/);
    expect(listRegistry).not.toHaveBeenCalled();
    expect(removeFile).not.toHaveBeenCalled();
    expect(input.audit).not.toHaveBeenCalled();
  });

  it("ORPHANED (no registry entry for the uid, clean registry, no runtime state, no plist) -> removes marker + gate policy, distinct audit, {reconciled:true}", async () => {
    const input = reconInput();
    const removed: string[] = [];
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      // A SIBLING uid is present, not ours -- so no entry for THIS uid.
      listRegistry: async () => cleanRegistry([{ agent_uid: 999 }]),
      readRuntimeState: async () => {
        throw enoent();
      },
      plistExists: noPlist,
      removeFile: async (p) => {
        removed.push(p);
      },
    });
    expect(result).toMatchObject({ kind: "reconciled" });
    // EXACT restoreCoarseComposition removal pair, in order.
    expect(removed).toEqual([MARKER_PATH, GATE_POLICY_PATH]);
    expect(input.audit).toHaveBeenCalledWith(
      EXCLUSIVE_ROUTING_STALE_MARKER_RECONCILED_AUDIT_OP,
      expect.objectContaining({ agent_uid: MARKER.agent_uid, marker_gate_uid: MARKER.gate_uid }),
    );
  });

  it("FIX F1: intent 'observe' on the SAME provably-orphaned marker judges it ORPHANED and writes NOTHING", async () => {
    // The consent-ordering half of the fix. The gate judges before the operator
    // confirm so a doomed run is never confirmed, and it must be able to do that
    // without deleting two fortress policy files first. Identical inputs to the
    // ORPHANED test above; the ONLY difference is the intent.
    const input = { ...reconInput(), intent: "observe" as const };
    const removeFile = vi.fn(async () => undefined);
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry: async () => cleanRegistry([{ agent_uid: 999 }]),
      readRuntimeState: async () => {
        throw enoent();
      },
      plistExists: noPlist,
      removeFile,
    });
    expect(result).toMatchObject({ kind: "orphaned" });
    expect((result as { detail: string }).detail).toMatch(/no S5-1 registry entry and no serving gate/);
    // Nothing on the fortress changed: no files, no audit record, no narration.
    expect(removeFile).not.toHaveBeenCalled();
    expect(input.audit).not.toHaveBeenCalled();
    expect(input.print).not.toHaveBeenCalled();
  });

  it("G7: a registry entry with NO verified live listener KEEPS the marker as kept-UNCERTAIN (a record is not an observation)", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry: async () => cleanRegistry([{ agent_uid: MARKER.agent_uid }]),
      readRuntimeState: async () => {
        throw enoent();
      },
      plistExists: noPlist,
      removeFile,
    });
    // FIX G7 (re-gate 2026-07-26): a registry entry is a RECORD, and by its own
    // reason string it covers a "mid-bring-up" generation -- i.e. possibly the
    // interrupted arm this gate exists for. `kept-live`'s sentence offers
    // "nothing needs doing", which is the WRONG advice on a wedged host, so the
    // entry alone can no longer earn it. The marker is still KEPT either way.
    expect(result.kind).toBe("kept-uncertain");
    expect(keptReason(result)).toMatch(/registry still has an entry/);
    expect(keptReason(result)).toMatch(/no live gate listener was verified/);
    expect(removeFile).not.toHaveBeenCalled();
    expect(input.audit).not.toHaveBeenCalled();
  });

  it("G7: a registry entry PLUS an owner-verified serving gate is kept-LIVE (the healthy armed host keeps its 'nothing needs doing')", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry: async () => cleanRegistry([{ agent_uid: MARKER.agent_uid }]),
      readRuntimeState: async () => runtimeStateJson(),
      verifyPortOwner: async () => ({ ok: true as const }),
      plistExists: noPlist,
      removeFile,
    });
    expect(result.kind).toBe("kept-live");
    expect(keptReason(result)).toMatch(/gate liveness .* is yes/);
    expect(keptReason(result)).toMatch(/registry has an entry for that uid/);
    expect(removeFile).not.toHaveBeenCalled();
  });

  it("FIX-2 crashed-mid-bring-up: a DIRTY registry (a G3 generation staged but never committed forces dirty) is KEPT fail-closed", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    // A generation the coordinator armed at G3 but a crash never committed at G5
    // forces the registry DIRTY. That is an uncertain S5-1 state; the repair
    // verb, not this preflight, recovers it. Runtime state ENOENT + no plist
    // would otherwise pass dimension 2, proving the DIRTY guard is what keeps it.
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry: async () => ({ entries: [{ agent_uid: MARKER.agent_uid }], dirty: true, quarantined: [] }),
      readRuntimeState: async () => {
        throw enoent();
      },
      plistExists: noPlist,
      removeFile,
    });
    expect(result.kind).toBe("kept-uncertain");
    expect(keptReason(result)).toMatch(/uncertain state.*dirty=true/);
    expect(removeFile).not.toHaveBeenCalled();
  });

  it("FIX-2 KEEPS the marker when the registry has a QUARANTINED entry (uncertain S5-1 state), even with no entry for the uid", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry: async () => ({ entries: [], dirty: false, quarantined: [{ index: 0, reason: "malformed" }] }),
      readRuntimeState: async () => {
        throw enoent();
      },
      plistExists: noPlist,
      removeFile,
    });
    expect(result.kind).toBe("kept-uncertain");
    expect(keptReason(result)).toMatch(/uncertain state.*quarantined=1/);
    expect(removeFile).not.toHaveBeenCalled();
  });

  it("KEEPS the marker when a gate daemon is owner-verified serving (second liveness dimension)", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    const verifyPortOwner = vi.fn(async () => ({ ok: true as const }));
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      // No registry entry -> reach the gate check; a live gate keeps the marker.
      listRegistry: async () => cleanRegistry(),
      readRuntimeState: async () => runtimeStateJson(),
      verifyPortOwner,
      removeFile,
    });
    // An owner-verified live listener is LIVE, not uncertain.
    expect(result.kind).toBe("kept-live");
    expect(keptReason(result)).toMatch(/gate liveness .* is yes/);
    // The owner check ran against the MARKER's gate uid and the recorded port.
    expect(verifyPortOwner).toHaveBeenCalledWith(
      expect.objectContaining({ port: 49222, expectedUid: MARKER.gate_uid, expectedPid: 4242 }),
    );
    expect(removeFile).not.toHaveBeenCalled();
  });

  it("KEEPS the marker when a runtime state exists but does NOT owner-verify (uncertain -> fail toward confinement)", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry: async () => cleanRegistry(),
      readRuntimeState: async () => runtimeStateJson(),
      verifyPortOwner: async () => ({ ok: false as const, reason: "listener lookup failed: no listener" }),
      removeFile,
    });
    expect(result.kind).toBe("kept-uncertain");
    expect(keptReason(result)).toMatch(/uncertain/);
    expect(removeFile).not.toHaveBeenCalled();
  });

  it("FIX-3 partial-teardown TOCTOU: runtime state ABSENT but the gate daemon PLIST survives -> uncertain -> KEEP (launchd could restart the gate)", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    const result = await reconcileStaleExclusiveRoutingProduction(input, {
      loadMarker: async () => ({ ...MARKER }),
      listRegistry: async () => cleanRegistry(),
      readRuntimeState: async () => {
        throw enoent();
      },
      plistExists: async () => true,
      removeFile,
    });
    expect(result.kind).toBe("kept-uncertain");
    expect(keptReason(result)).toMatch(/plist is present/);
    expect(removeFile).not.toHaveBeenCalled();
  });

  it("MALFORMED marker SURFACES (throws) -- does NOT silently proceed or remove", async () => {
    const input = reconInput();
    const removeFile = vi.fn(async () => undefined);
    await expect(
      reconcileStaleExclusiveRoutingProduction(input, {
        loadMarker: async () => {
          throw new ExclusiveRoutingMarkerError("not valid JSON");
        },
        listRegistry: async () => cleanRegistry(),
        removeFile,
      }),
    ).rejects.toThrow(ExclusiveRoutingMarkerError);
    expect(removeFile).not.toHaveBeenCalled();
    expect(input.audit).not.toHaveBeenCalled();
  });

  it("is IDEMPOTENT: a second run over the now-removed marker is a no-op", async () => {
    const input = reconInput();
    const removed: string[] = [];
    let markerPresent = true;
    const deps = {
      loadMarker: async (): Promise<ExclusiveRoutingMarker | null> => (markerPresent ? { ...MARKER } : null),
      listRegistry: async (): Promise<{
        entries: { agent_uid: number }[];
        dirty: boolean;
        quarantined: { index: number; reason: string }[];
      }> => cleanRegistry(),
      readRuntimeState: async (): Promise<string> => {
        throw enoent();
      },
      plistExists: noPlist,
      removeFile: async (p: string): Promise<void> => {
        removed.push(p);
        markerPresent = false;
      },
    };
    const first = await reconcileStaleExclusiveRoutingProduction(input, deps);
    const second = await reconcileStaleExclusiveRoutingProduction(input, deps);
    expect(first).toMatchObject({ kind: "reconciled" });
    expect(second).toEqual({ kind: "clear" });
    // Exactly ONE removal pair total (marker + gate policy), never four.
    expect(removed).toEqual([MARKER_PATH, GATE_POLICY_PATH]);
  });

  // ────────────────────────────────────────────────────────────────────────
  // FIX F3 (adversarial review, 2026-07-26): the no-account residue teardown.
  //
  // With the dedicated agent account gone but the fortress still carrying its
  // exclusive-routing files, `--unprotect-egress-gate` exited 2 ("nothing to
  // unprotect"), `--repair-egress-gate` exited 2 pointing at the provision
  // command the residue gate refuses, and the provision command refused. A
  // closed loop whose only exit was an undocumented manual `rm`. This function
  // is what makes the verb the refusal names actually work.
  // ────────────────────────────────────────────────────────────────────────
  describe("clearExclusiveRoutingResidueWithoutAccount (F3: the way out when the account is gone)", () => {
    it("no marker on disk -> 'no-residue', nothing removed (the verb still has nothing to do)", async () => {
      const input = reconInput();
      const removeFile = vi.fn(async () => undefined);
      const reconcile = vi.fn(async () => ({ kind: "clear" as const }));
      const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
        loadMarker: async () => null,
        reconcile,
        removeFile,
      });
      expect(result).toEqual({ kind: "no-residue" });
      expect(reconcile).not.toHaveBeenCalled();
      expect(removeFile).not.toHaveBeenCalled();
    });

    it("orphaned residue -> CLEARED, and the reconcile is scoped to the MARKER's own uid (guard 0 is not relaxed, it is supplied a subject)", async () => {
      const input = reconInput();
      const reconcile = vi.fn(async () => ({ kind: "reconciled" as const, detail: "no registry entry, no gate" }));
      const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
        loadMarker: async () => ({ ...MARKER }),
        reconcile,
      });
      expect(result).toEqual({ kind: "cleared", detail: "no registry entry, no gate" });
      expect(reconcile).toHaveBeenCalledWith(MARKER.agent_uid);
    });

    it("live confinement for the marker's uid -> REFUSED, nothing removed (a marker-only removal would leave pf armed)", async () => {
      const input = reconInput();
      const removeFile = vi.fn(async () => undefined);
      const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
        loadMarker: async () => ({ ...MARKER }),
        reconcile: async () => ({ kind: "kept-live" as const, reason: "the S5-1 registry still has an entry" }),
        removeFile,
      });
      expect(result).toEqual({ kind: "refused", reason: "the S5-1 registry still has an entry" });
      expect(removeFile).not.toHaveBeenCalled();
    });

    // ──────────────────────────────────────────────────────────────────────
    // FIX G1 (re-gate, 2026-07-26). The pre-fix unreadable branch removed the
    // marker + gate policy with NO orphan proof at all, reasoning "with no
    // account there is nothing running at the uid it names". But
    // `loadExclusiveRoutingMarker` returns null ONLY on ENOENT and THROWS on
    // every other read failure, so "unreadable" includes a PERFECTLY VALID
    // marker that merely could not be read (EACCES, EIO, EISDIR, a
    // root-squashed network fortress). "Could not look" must never authorise a
    // destructive action.
    // ──────────────────────────────────────────────────────────────────────
    it("G1 REGRESSION (the reviewer's EACCES scenario): a VALID marker declaring uid 503, made unreadable, is NOT deleted while confinement exists", async () => {
      const input = reconInput();
      const removeFile = vi.fn(async () => undefined);
      // The real EACCES shape: `loadExclusiveRoutingMarker` wraps the readFile
      // failure, so the marker's agent_uid (503) is present and valid on disk
      // and simply was not read. The registry still carries an entry -- the
      // interrupted arm this whole gate is about.
      const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
        loadMarker: async () => {
          throw new ExclusiveRoutingMarkerError(
            `cannot read ${MARKER_PATH} (EACCES: permission denied, open '${MARKER_PATH}'); ` +
              "refusing to compose a manifest under an unknown routing mode",
          );
        },
        listRegistry: async () => cleanRegistry([{ agent_uid: 503 }]),
        removeFile,
      });
      expect(result.kind).toBe("refused");
      expect((result as { reason: string }).reason).toMatch(/EACCES/);
      expect((result as { reason: string }).reason).toMatch(/NOT provably empty/);
      // The whole point: nothing was removed and nothing was audited as removed.
      expect(removeFile).not.toHaveBeenCalled();
      expect(input.audit).not.toHaveBeenCalled();
    });

    it("G1: an unreadable marker with a DIRTY or QUARANTINED registry is REFUSED too (uncertainty is not a proof of absence)", async () => {
      for (const registry of [
        { entries: [], dirty: true, quarantined: [] },
        { entries: [], dirty: false, quarantined: [{ index: 0, reason: "malformed" }] },
      ]) {
        const input = reconInput();
        const removeFile = vi.fn(async () => undefined);
        const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
          loadMarker: async () => {
            throw new ExclusiveRoutingMarkerError("EIO: i/o error");
          },
          listRegistry: async () => registry,
          removeFile,
        });
        expect(result.kind).toBe("refused");
        expect(removeFile).not.toHaveBeenCalled();
      }
    });

    it("G1: an unreadable marker whose ORPHAN PROOF itself cannot be read is REFUSED (could-not-look never authorises a delete)", async () => {
      const input = reconInput();
      const removeFile = vi.fn(async () => undefined);
      const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
        loadMarker: async () => {
          throw new ExclusiveRoutingMarkerError("EACCES: permission denied");
        },
        listRegistry: async () => {
          throw new Error("registry file /var/db/sanctuary/egress-anchor-registry.json is not valid JSON");
        },
        removeFile,
      });
      expect(result.kind).toBe("refused");
      expect((result as { reason: string }).reason).toMatch(/could not be read either/);
      expect(removeFile).not.toHaveBeenCalled();
      expect(input.audit).not.toHaveBeenCalled();
    });

    it("G1: an unreadable marker IS cleared once the registry is PROVABLY clean and empty (the way out is preserved, on a proof)", async () => {
      const input = reconInput();
      const removed: string[] = [];
      const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
        loadMarker: async () => {
          throw new ExclusiveRoutingMarkerError("not valid JSON");
        },
        listRegistry: async () => cleanRegistry(),
        removeFile: async (p) => {
          removed.push(p);
        },
      });
      expect(result).toMatchObject({ kind: "cleared" });
      expect((result as { detail: string }).detail).toMatch(/could not be read/);
      expect((result as { detail: string }).detail).toMatch(/holds NO entries at all/);
      expect(removed).toEqual([MARKER_PATH, GATE_POLICY_PATH]);
      expect(input.audit).toHaveBeenCalledWith(
        EXCLUSIVE_ROUTING_STALE_MARKER_RECONCILED_AUDIT_OP,
        expect.objectContaining({ agent_uid: null }),
      );
    });

    it("G4: a THROW from the scoped reconcile is a refusal, not an unhandled rejection (wrap/cli.ts awaits this with no try/catch)", async () => {
      const input = reconInput();
      const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
        loadMarker: async () => ({ ...MARKER }),
        reconcile: async () => {
          throw new Error("PfAnchorRegistryStateError: registry file is not valid JSON");
        },
      });
      expect(result.kind).toBe("refused");
      expect((result as { reason: string }).reason).toMatch(/could not complete/);
      expect((result as { reason: string }).reason).toMatch(/PfAnchorRegistryStateError/);
    });

    it("G5: a reconcile that removed part of the pair reports PARTIAL with what it removed (never the 'nothing changed' frame)", async () => {
      const input = reconInput();
      const result = await clearExclusiveRoutingResidueWithoutAccount(input, {
        loadMarker: async () => ({ ...MARKER }),
        reconcile: async () => ({
          kind: "removal-failed" as const,
          detail: `removing the exclusive-egress gate policy file (${GATE_POLICY_PATH}) failed: EROFS`,
          removed: [`the exclusive-routing marker (${MARKER_PATH})`],
        }),
      });
      expect(result).toMatchObject({
        kind: "partial",
        removed: [`the exclusive-routing marker (${MARKER_PATH})`],
      });
      expect((result as { reason: string }).reason).toMatch(/EROFS/);
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // FIX G5 (re-gate, 2026-07-26): the CLEAR half's removal is tracked, and the
  // audit is written BEFORE the first removal. Pre-fix the order was remove,
  // remove, audit -- so a gate-policy removal that threw after the marker
  // removal succeeded left NO audit record (invariant 3) and let the caller
  // render "no Castle Wall change was made by this run" over a fortress that
  // had just been put back on coarse composition.
  // ────────────────────────────────────────────────────────────────────────
  describe("reconcileStaleExclusiveRoutingProduction clear-half removal disposition (G5)", () => {
    const FORTRESS = "/fortress/recon";
    const MARKER: ExclusiveRoutingMarker = {
      version: 1,
      mode: "exclusive",
      agent_uid: 707,
      gate_uid: 708,
      agent_id: "hermes",
      agent_template: "hermes",
    };
    const MARKER_PATH = exclusiveRoutingMarkerPath(FORTRESS);
    const GATE_POLICY_PATH = join(FORTRESS, "policy", "egress", EXCLUSIVE_EGRESS_GATE_FILENAME);
    const enoent = (): NodeJS.ErrnoException => Object.assign(new Error("ENOENT"), { code: "ENOENT" });

    function clearInput(): {
      agentUid: number;
      intent: "clear";
      fortressPath: string;
      audit: ReturnType<typeof vi.fn>;
      print: ReturnType<typeof vi.fn>;
    } {
      return {
        agentUid: MARKER.agent_uid,
        intent: "clear",
        fortressPath: FORTRESS,
        audit: vi.fn(async () => undefined),
        print: vi.fn(),
      };
    }

    it("a gate-policy removal that FAILS after the marker was removed reports removal-failed naming the marker (not a throw, not 'reconciled')", async () => {
      const input = clearInput();
      const result = await reconcileStaleExclusiveRoutingProduction(input, {
        loadMarker: async () => ({ ...MARKER }),
        listRegistry: async () => ({ entries: [], dirty: false, quarantined: [] }),
        readRuntimeState: async () => {
          throw enoent();
        },
        plistExists: async () => false,
        removeFile: async (p) => {
          if (p === GATE_POLICY_PATH) throw new Error("EROFS: read-only file system");
        },
      });
      expect(result).toMatchObject({ kind: "removal-failed" });
      expect((result as { removed: string[] }).removed).toEqual([`the exclusive-routing marker (${MARKER_PATH})`]);
      expect((result as { detail: string }).detail).toMatch(/EROFS/);
      // Invariant 3: the removal is on the record even though it did not finish.
      expect(input.audit).toHaveBeenCalledWith(
        EXCLUSIVE_ROUTING_STALE_MARKER_RECONCILED_AUDIT_OP,
        expect.objectContaining({ agent_uid: MARKER.agent_uid }),
      );
      // No success narration for a removal that did not complete.
      expect(input.print).not.toHaveBeenCalled();
    });

    it("the happy clear still reports reconciled, removes the pair in order, and audits BEFORE removing", async () => {
      const input = clearInput();
      const order: string[] = [];
      input.audit.mockImplementation(async () => {
        order.push("audit");
      });
      const result = await reconcileStaleExclusiveRoutingProduction(input, {
        loadMarker: async () => ({ ...MARKER }),
        listRegistry: async () => ({ entries: [], dirty: false, quarantined: [] }),
        readRuntimeState: async () => {
          throw enoent();
        },
        plistExists: async () => false,
        removeFile: async (p) => {
          order.push(p);
        },
      });
      expect(result).toMatchObject({ kind: "reconciled" });
      expect(order).toEqual(["audit", MARKER_PATH, GATE_POLICY_PATH]);
    });
  });
});

// ---------------------------------------------------------------------------
// Change 2 (2026-07-22): the arm's 15s "did not publish runtime state" timeout
// is self-describing -- it folds a BOUNDED, secret-scrubbed tail of the gate
// daemon's stderr log (its real exit reason) into the thrown error.
// ---------------------------------------------------------------------------

describe("describeGateDaemonStderrTail (bounded gate-daemon stderr diagnostics)", () => {
  it("present + readable -> returns the log path and its content (real bounded read)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gate-stderr-"));
    try {
      const p = join(dir, "egress-gate-707.err.log");
      await writeFile(p, "bind: address already in use\nexiting non-zero\n");
      const out = await describeGateDaemonStderrTail(p);
      expect(out).toContain(p);
      expect(out).toContain("bind: address already in use");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("absent -> names the path and says the log was not present (no throw)", async () => {
    const out = await describeGateDaemonStderrTail("/no/such/gate/err.log");
    expect(out).toContain("/no/such/gate/err.log");
    expect(out).toMatch(/not present/);
  });

  it("unreadable (non-ENOENT) -> names the path and says it could not be read (no throw, no swallow)", async () => {
    const out = await describeGateDaemonStderrTail("/x/err.log", {
      readTail: async () => {
        throw Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
      },
    });
    expect(out).toContain("/x/err.log");
    expect(out).toMatch(/could not be read/);
    expect(out).toContain("EACCES");
  });

  it("oversized log -> tail is byte- AND line-bounded (only the last N lines survive)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gate-stderr-big-"));
    try {
      const p = join(dir, "egress-gate-707.err.log");
      // 200 lines, ~37 bytes each => ~7.4KB, far past the 2KB byte cap.
      const lines = Array.from({ length: 200 }, (_, i) => `line ${i} ${"x".repeat(30)}`);
      await writeFile(p, lines.join("\n") + "\n");
      const out = await describeGateDaemonStderrTail(p);
      expect(out).toContain("(tail truncated)");
      // The earliest lines are gone (byte + line bounded).
      expect(out).not.toContain("line 0 ");
      expect(out).not.toContain("line 100 ");
      // At most N content lines survive in the tail body.
      const body = out.split("real exit reason:\n")[1] ?? "";
      const bodyLines = body.split("\n").filter((l) => l.length > 0);
      expect(bodyLines.length).toBeLessThanOrEqual(GATE_DAEMON_STDERR_TAIL_MAX_LINES);
      // And the LAST line is retained.
      expect(out).toContain("line 199 ");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("PEM private-key material in the tail is REDACTED (invariant 6 defense-in-depth)", async () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nMIGkAgEBBDAsecretsecretsecret\n-----END PRIVATE KEY-----";
    const out = await describeGateDaemonStderrTail("/x/err.log", {
      readTail: async () => ({ text: `startup ok\n${pem}\nlistening`, truncated: false }),
    });
    expect(out).toContain("[REDACTED PEM PRIVATE-KEY BLOCK]");
    expect(out).not.toContain("MIGkAgEBBDAsecretsecretsecret");
  });

  it("FIX-4 boundary-split PEM: a tail that STARTS mid-key body ending in END (BEGIN fell before the window) is redacted", async () => {
    // The 2KB byte-tail cut can start inside a key: the leading base64 body up
    // to a dangling END is secret and must not leak.
    const out = await describeGateDaemonStderrTail("/x/err.log", {
      readTail: async () => ({
        text: "c2VjcmV0Ym9keWJhc2U2NGtleW1hdGVyaWFs\n-----END PRIVATE KEY-----\nlistening on port 49222",
        truncated: true,
      }),
    });
    expect(out).toContain("[REDACTED PARTIAL PEM PRIVATE-KEY BLOCK]");
    expect(out).not.toContain("c2VjcmV0Ym9keWJhc2U2NGtleW1hdGVyaWFs");
    // Ordinary diagnostics after the key are preserved.
    expect(out).toContain("listening on port 49222");
  });

  it("FIX-4 boundary-split PEM: a DANGLING BEGIN with no END (truncated key write) redacts the body to tail end", async () => {
    const out = await describeGateDaemonStderrTail("/x/err.log", {
      readTail: async () => ({
        text: "starting up\n-----BEGIN PRIVATE KEY-----\nMIGkAgEBBDAtruncatedbodybytes",
        truncated: false,
      }),
    });
    expect(out).toContain("[REDACTED PARTIAL PEM PRIVATE-KEY BLOCK]");
    expect(out).not.toContain("MIGkAgEBBDAtruncatedbodybytes");
    expect(out).toContain("starting up");
  });
});

describe("waitForGateRuntime timeout diagnostics (Change 2)", () => {
  const NEVER_ENOENT = async (): Promise<string> => {
    throw Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" });
  };

  it("times out with a readable gate-daemon err.log present -> error CONTAINS the path and a bounded tail", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gate-wait-"));
    try {
      const errLog = join(dir, "egress-gate-707.err.log");
      await writeFile(errLog, "launchd: could not bind gate port 49222 (EADDRINUSE)\n");
      const call = (): Promise<unknown> =>
        waitForGateRuntime(707, 5, 49222, {
          readState: NEVER_ENOENT,
          budgetMs: 5,
          intervalMs: 1,
          gateDaemonStderrPath: errLog,
        });
      // The daemon's REAL exit reason (from its stderr) is now in the error.
      await expect(call()).rejects.toThrow(/did not publish a matching runtime state[\s\S]*EADDRINUSE/);
      // And the log's absolute path is named. `toThrow(string)` is a CONTAINS
      // check, so assert the literal path (a stricter, escaping-free check than
      // building a regex from a filesystem path).
      await expect(call()).rejects.toThrow(errLog);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("times out with the err.log ABSENT -> error names the path and says it was unavailable (still throws)", async () => {
    const missing = "/no/such/gate/egress-gate-707.err.log";
    const call = (): Promise<unknown> =>
      waitForGateRuntime(707, 5, 49222, {
        readState: NEVER_ENOENT,
        budgetMs: 5,
        intervalMs: 1,
        gateDaemonStderrPath: missing,
      });
    await expect(call()).rejects.toThrow(/did not publish a matching runtime state/);
    await expect(call()).rejects.toThrow(/not present/);
  });

  it("without a stderr path -> unchanged bare timeout error (pure addition to the error path)", async () => {
    await expect(
      waitForGateRuntime(707, 5, 49222, { readState: NEVER_ENOENT, budgetMs: 5, intervalMs: 1 }),
    ).rejects.toThrow(/did not publish a matching runtime state within 5ms/);
  });
});

// ---------------------------------------------------------------------------
// Fix-round-2 BLOCKER (2026-07-24 re-gate): the peer-resolver RELOAD on a
// production bring-up must force-replace the loaded launchd job (bootout
// FIRST, then bootstrap + kickstart) so a rewritten `--gate-port` argv is
// guaranteed loaded after a repair/rotation. A plain bootstrap of an
// already-loaded label + a plain kickstart (no -k) would leave the running
// resolver on its OLD port -> the stale-resolver fail-open the re-gate caught.
//
// FIX-ROUND-3 (2026-07-24 THIRD re-gate, both lenses, SOUND-WITH-FIXES): the
// round-2 fix above went straight from a tolerated bootout to bootstrap,
// which does not prove the old process was reaped (F2, the reap race) and
// threw on a transient EINPROGRESS bootout that would have settled a moment
// later (F1). The reload now mirrors `uninstallAgentHarnessDaemon`'s settle
// discipline (`harness-daemon.ts:429-451`): tolerate EINPROGRESS same as
// not-loaded, settle via `launchctl print` before bootstrapping, and fail
// closed if the old job will not settle.
// ---------------------------------------------------------------------------
describe("reloadPeerResolverDaemonForBringUp (fix-round-2 BLOCKER + fix-round-3 settle discipline)", () => {
  const AGENT_UID = 502;
  const RESOLVER_LABEL = peerResolverDaemonLabel(AGENT_UID);
  const RESOLVER_PLIST = peerResolverDaemonPlistPath(AGENT_UID);

  /** `launchctl print system/<RESOLVER_LABEL>` stdout reporting a running pid. */
  function runningPrintStdout(pid: number): string {
    return `system/${RESOLVER_LABEL} = {\n\tpid = ${pid}\n\tstate = running\n}\n`;
  }

  function recordingLaunchctl(
    handlers: Partial<Record<"bootout" | "bootstrap" | "kickstart", { code: number; stderr?: string }>> & {
      /**
       * `launchctl print system/<label>` response(s) for the settle loop. A
       * single response repeats for every sample; an array is consumed
       * in call order and its LAST entry repeats once exhausted. Defaults to
       * "not loaded" so the settle loop resolves on its first sample when a
       * test does not care about the settle behavior itself.
       */
      print?: { code: number; stdout?: string; stderr?: string } | Array<{ code: number; stdout?: string; stderr?: string }>;
    } = {},
  ): {
    fn: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
    calls: string[];
  } {
    const calls: string[] = [];
    let printCallCount = 0;
    return {
      calls,
      fn: (args) => {
        const verb = args[0] as "bootout" | "bootstrap" | "kickstart" | "print";
        calls.push(args.join(" "));
        if (verb === "print") {
          const responses = handlers.print;
          const fallback = { code: 113, stdout: "", stderr: "Could not find service" };
          if (Array.isArray(responses)) {
            const idx = Math.min(printCallCount, responses.length - 1);
            printCallCount += 1;
            const resp = responses[idx] ?? fallback;
            return Promise.resolve({ code: resp.code, stdout: resp.stdout ?? "", stderr: resp.stderr ?? "" });
          }
          printCallCount += 1;
          const resp = responses ?? fallback;
          return Promise.resolve({ code: resp.code, stdout: resp.stdout ?? "", stderr: resp.stderr ?? "" });
        }
        const h = handlers[verb];
        return Promise.resolve({ code: h?.code ?? 0, stdout: "", stderr: h?.stderr ?? "" });
      },
    };
  }

  /** Calls the function under test with a no-op sleep so settle-loop tests run instantly. */
  function reload(
    fn: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>,
  ): Promise<void> {
    return reloadPeerResolverDaemonForBringUp({
      agentUid: AGENT_UID,
      resolverPlistPath: RESOLVER_PLIST,
      runLaunchctlFn: fn,
      sleepMs: async () => {},
    });
  }

  it("boots the OLD job OUT, settles via print, THEN bootstraps the rewritten plist, then kickstarts (exact order)", async () => {
    const { fn, calls } = recordingLaunchctl();
    await expect(reload(fn)).resolves.toBeUndefined();
    expect(calls).toEqual([
      `bootout system/${RESOLVER_LABEL}`,
      `print system/${RESOLVER_LABEL}`,
      `bootstrap system ${RESOLVER_PLIST}`,
      `kickstart system/${RESOLVER_LABEL}`,
    ]);
    // The bootout MUST precede the settle print, which MUST precede the
    // bootstrap (the whole point of both the round-2 and round-3 fixes).
    expect(calls.indexOf(`bootout system/${RESOLVER_LABEL}`)).toBeLessThan(
      calls.indexOf(`print system/${RESOLVER_LABEL}`),
    );
    expect(calls.indexOf(`print system/${RESOLVER_LABEL}`)).toBeLessThan(
      calls.indexOf(`bootstrap system ${RESOLVER_PLIST}`),
    );
  });

  it("TOLERATES a not-loaded bootout (clean first install: nothing was running) and proceeds to bootstrap", async () => {
    for (const notLoaded of [
      { code: 3, stderr: "Boot-out failed: 3: No such process" },
      { code: 113, stderr: "Could not find service" },
      { code: 1, stderr: "service not loaded" },
    ]) {
      const { fn, calls } = recordingLaunchctl({ bootout: notLoaded });
      await expect(reload(fn)).resolves.toBeUndefined();
      // It did not throw AND it went on to bootstrap + kickstart.
      expect(calls).toContain(`bootstrap system ${RESOLVER_PLIST}`);
      expect(calls).toContain(`kickstart system/${RESOLVER_LABEL}`);
    }
  });

  it("THROWS on a GENUINE bootout failure (the tolerance did not swallow a real stop failure), never proceeding to settle or bootstrap", async () => {
    const { fn, calls } = recordingLaunchctl({
      bootout: { code: 5, stderr: "Boot-out failed: 5: Input/output error" },
    });
    await expect(reload(fn)).rejects.toThrow(/bootout .* exited 5/);
    expect(calls).not.toContain(`print system/${RESOLVER_LABEL}`);
    expect(calls).not.toContain(`bootstrap system ${RESOLVER_PLIST}`);
  });

  // -------------------------------------------------------------------------
  // FIX-ROUND-3 regression tests (THIRD re-gate, both lenses SOUND-WITH-FIXES,
  // 2026-07-24). Mirrors `uninstallAgentHarnessDaemon`'s settle discipline
  // (harness-daemon.ts:429-451): tolerate EINPROGRESS (F1), settle before
  // bootstrap (F2a), and fail closed if the old job never settles (F2b).
  // -------------------------------------------------------------------------

  it("T-F1: TOLERATES an EINPROGRESS bootout (transient in-flight stop) and settles before bootstrapping", async () => {
    const { fn, calls } = recordingLaunchctl({
      bootout: { code: 36, stderr: "Boot-out failed: 36: Operation now in progress" },
      print: [
        { code: 0, stdout: runningPrintStdout(4242) }, // still tearing down
        { code: 113, stderr: "Could not find service" }, // now gone
      ],
    });
    await expect(reload(fn)).resolves.toBeUndefined();
    const printCalls = calls.filter((c) => c === `print system/${RESOLVER_LABEL}`);
    expect(printCalls.length).toBe(2); // it settled, not a single sample
    expect(calls).toContain(`bootstrap system ${RESOLVER_PLIST}`);
    expect(calls).toContain(`kickstart system/${RESOLVER_LABEL}`);
    // Bootstrap only fires after the settle loop's LAST print call.
    expect(calls.lastIndexOf(`print system/${RESOLVER_LABEL}`)).toBeLessThan(
      calls.indexOf(`bootstrap system ${RESOLVER_PLIST}`),
    );
  });

  it("T-F2a: SETTLES before bootstrapping -- bootout returns 0 but the job reports RUNNING for several samples, bootstrap fires only once print reports STOPPED", async () => {
    const { fn, calls } = recordingLaunchctl({
      print: [
        { code: 0, stdout: runningPrintStdout(4242) },
        { code: 0, stdout: runningPrintStdout(4242) },
        { code: 0, stdout: runningPrintStdout(4242) },
        { code: 113, stderr: "Could not find service" },
      ],
    });
    await expect(reload(fn)).resolves.toBeUndefined();
    const printCalls = calls.filter((c) => c === `print system/${RESOLVER_LABEL}`);
    expect(printCalls.length).toBe(4);
    expect(calls.lastIndexOf(`print system/${RESOLVER_LABEL}`)).toBeLessThan(
      calls.indexOf(`bootstrap system ${RESOLVER_PLIST}`),
    );
    expect(calls).toContain(`kickstart system/${RESOLVER_LABEL}`);
  });

  it("T-F2b: FAILS CLOSED when the old job never settles -- still running through every sample, THROWS and never bootstraps+kickstarts a stale resolver", async () => {
    const { fn, calls } = recordingLaunchctl({
      print: { code: 0, stdout: runningPrintStdout(4242) }, // always running
    });
    await expect(reload(fn)).rejects.toThrow(/STILL RUNNING after bootout/);
    expect(calls).not.toContain(`bootstrap system ${RESOLVER_PLIST}`);
    expect(calls).not.toContain(`kickstart system/${RESOLVER_LABEL}`);
    // Bounded, not infinite: exactly HARNESS_STOP_SETTLE_SAMPLES print samples.
    const printCalls = calls.filter((c) => c === `print system/${RESOLVER_LABEL}`);
    expect(printCalls.length).toBe(HARNESS_STOP_SETTLE_SAMPLES);
  });

  it("after a PROVEN-unloaded settle, an 'already loaded' bootstrap contradicts the readback and THROWS rather than being tolerated", async () => {
    // Point 4 of the fix-round-3 spec: unlike the boot path (which may
    // legitimately race a concurrent load), this reload just OBSERVED the
    // label unloaded via the settle loop, so a bootstrap that now reports
    // "already loaded" means the readback was wrong -- refuse rather than
    // report success over a state that contradicts what was just proven.
    const { fn, calls } = recordingLaunchctl({
      bootstrap: { code: 1, stderr: "service already loaded" },
      // default print => not loaded on the first sample, so settle proves
      // the label unloaded before bootstrap ever runs.
    });
    await expect(reload(fn)).rejects.toThrow(/bootstrap .* exited 1/);
    expect(calls).not.toContain(`kickstart system/${RESOLVER_LABEL}`);
  });
});

// ---------------------------------------------------------------------------
// FIX-ROUND-4 BLOCKER (2026-07-25, hardware-proven N=2): the GATE-DAEMON reload
// in `productionBringUp` must force-replace the running gate the SAME way the
// peer-resolver reload does. The pre-fix gate block used a raw
// `bootstrap + kickstart(no -k)` that no-ops on an already-running daemon, so a
// `sudo sanctuary protect --repair-egress-gate --stand-down-agent` rotated the pf anchor + port
// but never restarted the gate -> pf confined the agent to a port nothing
// served -> the agent was strangled (fail-CLOSED, not a wrong-allow). The fix
// routes the gate through the SHARED `reloadLaunchdDaemonForBringUp` chokepoint
// (bootout FIRST -> settle-until-reaped -> bootstrap -> kickstart), so the gate
// reload inherits the resolver's proven settle discipline by construction.
// These tests pin that chokepoint against the GATE label so a future
// regression cannot quietly drop the gate back to the raw no-op'ing pattern.
// ---------------------------------------------------------------------------
describe("reloadLaunchdDaemonForBringUp (fix-round-4: shared chokepoint; the GATE reload settles like the resolver)", () => {
  const AGENT_UID = 507;
  const GATE_LABEL = egressGateDaemonLabel(AGENT_UID);
  const GATE_PLIST = egressGateDaemonPlistPath(AGENT_UID);

  /** `launchctl print system/<GATE_LABEL>` stdout reporting a running pid. */
  function runningPrintStdout(pid: number): string {
    return `system/${GATE_LABEL} = {\n\tpid = ${pid}\n\tstate = running\n}\n`;
  }

  function recordingLaunchctl(
    handlers: Partial<Record<"bootout" | "bootstrap" | "kickstart", { code: number; stderr?: string }>> & {
      print?: { code: number; stdout?: string; stderr?: string } | Array<{ code: number; stdout?: string; stderr?: string }>;
    } = {},
  ): {
    fn: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
    calls: string[];
  } {
    const calls: string[] = [];
    let printCallCount = 0;
    return {
      calls,
      fn: (args) => {
        const verb = args[0] as "bootout" | "bootstrap" | "kickstart" | "print";
        calls.push(args.join(" "));
        if (verb === "print") {
          const responses = handlers.print;
          const fallback = { code: 113, stdout: "", stderr: "Could not find service" };
          if (Array.isArray(responses)) {
            const idx = Math.min(printCallCount, responses.length - 1);
            printCallCount += 1;
            const resp = responses[idx] ?? fallback;
            return Promise.resolve({ code: resp.code, stdout: resp.stdout ?? "", stderr: resp.stderr ?? "" });
          }
          printCallCount += 1;
          const resp = responses ?? fallback;
          return Promise.resolve({ code: resp.code, stdout: resp.stdout ?? "", stderr: resp.stderr ?? "" });
        }
        const h = handlers[verb];
        return Promise.resolve({ code: h?.code ?? 0, stdout: "", stderr: h?.stderr ?? "" });
      },
    };
  }

  /** Calls the chokepoint with the GATE label + a no-op sleep. */
  function reload(
    fn: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>,
  ): Promise<void> {
    return reloadLaunchdDaemonForBringUp({
      label: GATE_LABEL,
      plistPath: GATE_PLIST,
      runLaunchctlFn: fn,
      sleepMs: async () => {},
    });
  }

  it("boots the OLD gate job OUT, settles via print, THEN bootstraps the rewritten plist, then kickstarts (exact order) -- the repair/rotation replace-the-running-process fix", async () => {
    const { fn, calls } = recordingLaunchctl();
    await expect(reload(fn)).resolves.toBeUndefined();
    expect(calls).toEqual([
      `bootout system/${GATE_LABEL}`,
      `print system/${GATE_LABEL}`,
      `bootstrap system ${GATE_PLIST}`,
      `kickstart system/${GATE_LABEL}`,
    ]);
    // The bootout MUST precede the settle print, which MUST precede the
    // bootstrap: this is the whole point of the fix -- a raw bootstrap on the
    // still-running gate no-ops and leaves the strangling old process serving.
    expect(calls.indexOf(`bootout system/${GATE_LABEL}`)).toBeLessThan(
      calls.indexOf(`print system/${GATE_LABEL}`),
    );
    expect(calls.indexOf(`print system/${GATE_LABEL}`)).toBeLessThan(
      calls.indexOf(`bootstrap system ${GATE_PLIST}`),
    );
  });

  it("TOLERATES a not-loaded bootout (fresh arm: nothing running yet) and proceeds to bootstrap + kickstart", async () => {
    const { fn, calls } = recordingLaunchctl({ bootout: { code: 113, stderr: "Could not find service" } });
    await expect(reload(fn)).resolves.toBeUndefined();
    expect(calls).toContain(`bootstrap system ${GATE_PLIST}`);
    expect(calls).toContain(`kickstart system/${GATE_LABEL}`);
  });

  it("FAILS CLOSED when the OLD gate never settles -- still running through every sample, THROWS and never bootstraps+kickstarts a gate over the strangled agent", async () => {
    const { fn, calls } = recordingLaunchctl({
      print: { code: 0, stdout: runningPrintStdout(13651) }, // the hardware-proven strangling pid, always running
    });
    await expect(reload(fn)).rejects.toThrow(/STILL RUNNING after bootout/);
    expect(calls).not.toContain(`bootstrap system ${GATE_PLIST}`);
    expect(calls).not.toContain(`kickstart system/${GATE_LABEL}`);
    // Bounded, not infinite: exactly HARNESS_STOP_SETTLE_SAMPLES print samples.
    const printCalls = calls.filter((c) => c === `print system/${GATE_LABEL}`);
    expect(printCalls.length).toBe(HARNESS_STOP_SETTLE_SAMPLES);
  });

  it("no longer TOLERATES a Bootstrap IO error after a proven-unloaded settle (matches the resolver's strict semantics; the pre-fix gate block swallowed this)", async () => {
    // The raw gate block this fix removed tolerated
    // `Bootstrap failed: 5: Input/output error`. Post-settle the label is
    // PROVEN unloaded, so an IO-error bootstrap is a real failure, not the
    // benign already-loaded race -- it must THROW, not be swallowed.
    const { fn, calls } = recordingLaunchctl({
      bootstrap: { code: 5, stderr: "Bootstrap failed: 5: Input/output error" },
      // default print => not loaded, so settle proves unloaded before bootstrap.
    });
    await expect(reload(fn)).rejects.toThrow(/bootstrap .* exited 5/);
    expect(calls).not.toContain(`kickstart system/${GATE_LABEL}`);
  });
});
