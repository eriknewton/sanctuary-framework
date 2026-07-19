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
  verifyHarnessJobDisabled,
  verifyHarnessParkedPersistent,
  verifyLoopbackTcpPortOwner,
  PID_START_TOLERANCE_MS,
  type ExclusiveEgressWiringInput,
  type PersistentParkContext,
} from "../../src/egress-gate/arming-wiring.js";
import { PfAnchorRegistry } from "../../src/egress-gate/anchor-registry.js";
import {
  gateCredentialAcceptPath,
  gateCredentialTokenPath,
} from "../../src/egress-gate/gate-credential.js";
import {
  egressGateDaemonPlistPath,
  egressGatePolicyConfigPath,
  egressGateRulesConfigPath,
  egressGateRuntimeUidDirPath,
} from "../../src/egress-gate/gate-daemon.js";
import { gateLivenessTokenPath } from "../../src/egress-gate/liveness-oracle.js";
import { AGENT_HARNESS_DAEMON_LABEL } from "../../src/egress-gate/harness-daemon.js";
import {
  holdFilePathForUid,
  planParkedHarnessInstall,
  type ReleaseBarrierOps,
} from "../../src/egress-gate/release-barrier.js";
import { exclusiveRoutingMarkerPath } from "../../src/castle-wall/allowlist/routing-marker.js";
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
      harnessArgv: ["/usr/local/bin/hermes"],
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
      harnessArgv: ["/usr/local/bin/hermes"],
      harnessLogDir: "/tmp/sanctuary-test-logs",
      agentTemplate: "hermes",
      gateDaemonArgvPrefix: ["sanctuary"],
      excludeUids: [501],
      gateAccountCeiling: 599,
      gateHomeDirectory: "/var/empty",
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
    harnessArgv: ["/usr/local/bin/hermes"],
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
    harnessArgv: PARK_CTX.harnessArgv,
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
      { ...PARK_INPUT, parkPlistFallbackRemoval: true } as unknown as ExclusiveEgressWiringInput,
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
    kind: "dir" | "symlink" | "other";
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
    return {
      stats,
      sequence,
      ops: {
        async mkdir(path) {
          sequence.push(`mkdir:${path}`);
          if (!stats.has(path)) stats.set(path, dirStat());
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
          const st = stats.get(path) ?? dirStat();
          return {
            uid: st.uid,
            gid: st.gid,
            mode: st.mode,
            isDirectory: () => st.kind === "dir",
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
        { gateAccount: "sanctuary-gate-hermes", gateUid: 505, gateHomeDirectory: home },
        ops,
      ),
    ).resolves.toEqual({ logDir });

    expect(stats.get("/var/sanctuary-agents")).toMatchObject({ uid: 0, mode: 0o711 });
    expect(stats.get(home)).toMatchObject({ uid: 505, gid: 505, mode: 0o700 });
    expect(stats.get(logDir)).toMatchObject({ uid: 505, gid: 505, mode: 0o700 });
    expect(sequence).toContain(`chown:${logDir}:505:505`);
    expect(logDir).not.toBe("/var/sanctuary-agents/sanctuary-hermes/logs");
  });

  it("refuses an agent-account home paired with the gate account before touching it", async () => {
    const { ops, sequence } = makeGateHomeOps();
    await expect(
      ensureGateAccountHomeLayout(
        {
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
        { gateAccount: "sanctuary-gate-hermes", gateUid: 505, gateHomeDirectory: home },
        ops,
      ),
    ).rejects.toThrow(/symlink/);
    expect(sequence).not.toContain(`chown:${logDir}:505:505`);
    expect(sequence).not.toContain(`chmod:${logDir}:700`);
  });
});
