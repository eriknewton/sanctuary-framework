/**
 * Fix-round tests for the exclusive-egress BOOT SUPERVISOR
 * (`arming-wiring.ts` `startExclusiveEgressBootSupervisor`), host-free via
 * the internals seams:
 *
 *  - H1: an UNRESOLVABLE agent (no marker / non-Hermes) is parked FOR REAL
 *    (bootout + hold-file removal + disable, actual results reported) --
 *    never the pre-fix synthetic "parked" with no ops run;
 *  - H2: the per-uid gate daemon (RunAtLoad=false) is BOOTSTRAPPED +
 *    kickstarted BEFORE the release barrier runs -- the pre-fix boot path
 *    never started it, so verifyGate parked every agent forever;
 *  - H3: the oracle freshness loop RE-SCANS the registry each tick, so an
 *    agent armed AFTER boot (install CLI path) gets its token refreshed by
 *    the always-running daemon -- the pre-fix loop only covered boot-release
 *    results;
 *  - M6: the non-Hermes park reason names the deliberate v1 scope bound.
 */

import { describe, expect, it, vi } from "vitest";

import { assessHarnessParked } from "../../src/egress-gate/parked-claim.js";
import { generateKeyPairSync } from "node:crypto";

import {
  clearExclusiveEgressOracleRefreshStatus,
  getExclusiveEgressOracleRefreshStatus,
  NON_HERMES_BOOT_PARK_REASON,
  startExclusiveEgressBootSupervisor,
  type BootAgentResolution,
  type BootRegistryEntry,
  type ExclusiveEgressBootSupervisorInternals,
} from "../../src/egress-gate/arming-wiring.js";
import {
  PfAnchorRegistry,
  PF_ANCHOR_REGISTRY_STATE_VERSION,
  type PfAnchorRegistryState,
} from "../../src/egress-gate/anchor-registry.js";
import { AGENT_HARNESS_DAEMON_LABEL, harnessLaunchSpec } from "../../src/egress-gate/harness-daemon.js";
import {
  runReleaseBarrierSequence,
  type ReleaseBarrierOps,
  type ReleaseBarrierOutcome,
} from "../../src/egress-gate/release-barrier.js";

const KEYS = ((): { privateKey: never; publicKey: never } => {
  const pair = generateKeyPairSync("ed25519");
  return { privateKey: pair.privateKey as never, publicKey: pair.publicKey as never };
})();

const ENTRY: BootRegistryEntry = {
  agent_uid: 502,
  gate_port: 40001,
  fortress_path: "/fortress/a",
  generation_id: 7,
};

const RELEASED: ReleaseBarrierOutcome = { kind: "released", generation_id: 7 };

function okLaunchctl(calls: string[]) {
  return async (args: readonly string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
    calls.push(`launchctl ${args.join(" ")}`);
    return { code: 0, stdout: "", stderr: "" };
  };
}

function baseInternals(overrides: ExclusiveEgressBootSupervisorInternals = {}): ExclusiveEgressBootSupervisorInternals {
  return {
    listRegistryEntries: async () => ({ entries: [ENTRY], quarantined: [], dirty: false }),
    ensureKeys: async () => KEYS,
    runLaunchctlFn: async () => ({ code: 0, stdout: "", stderr: "" }),
    runBarrier: async () => RELEASED,
    createBarrierOps: (() => ({})) as never,
    createOracle: () => ({ refresh: vi.fn(async () => null) }) as never,
    removeHoldFile: async () => undefined,
    readRuntimeState: async () =>
      JSON.stringify({ agent_uid: 502, gate_port: 40001, generation_id: 7, pid: 991, pid_start: "991-1000" }),
    gateWaitBudgetMs: 50,
    gateWaitIntervalMs: 1,
    loadMarker: async () => null,
    ensureRuntimeFs: async () => undefined,
    ensureGateHomeLayout: async () => ({ logDir: "/var/sanctuary-agents/sanctuary-gate-hermes/logs" }),
    ...overrides,
  };
}

const OK_CTX: BootAgentResolution = {
  kind: "ok",
  agentAccount: "sanctuary-hermes",
  harnessLaunch: harnessLaunchSpec({
    programArguments: ["/usr/local/bin/hermes"],
    environment: { HOME: "/var/sanctuary-agents/sanctuary-hermes", PYTHONPATH: "/var/sanctuary-agents/sanctuary-hermes/.hermes/hermes-agent" },
  }),
  harnessLogDir: "/var/sanctuary-agents/sanctuary-hermes/logs",
  gateAccount: "sanctuary-gate-hermes",
  gateHomeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
  gateUid: 511,
};

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

describe("startExclusiveEgressBootSupervisor (fix-round H1: no synthetic parked)", () => {
  it("an unresolvable agent is parked FOR REAL: bootout + hold-file removal + disable, flags TRUE when they succeed", async () => {
    const calls: string[] = [];
    const removeHoldFile = vi.fn(async (uid: number) => void calls.push(`removeHold ${uid}`));
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => ({ kind: "unresolvable", reason: "no marker for uid 502" }),
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 60_000,
      internals: baseInternals({ runLaunchctlFn: okLaunchctl(calls), removeHoldFile }),
    });
    handle.stopOracleLoop();
    expect(handle.results).toHaveLength(1);
    // Fix-round-2 BLOCKER-1: the parked outcome carries the REAL reassert
    // flags, so a caller can audit exactly what held the park.
    expect(handle.results[0]!.outcome).toMatchObject({
      kind: "parked",
      reason: expect.stringContaining("no marker for uid 502"),
      holdFileRemoved: true,
      jobDisabled: true,
      cleanupErrors: [],
    });
    // The REAL park ops ran, in order: bootout, hold-file removal, disable
    // (the shared-label ops are allowed: no other entry resolved for release).
    expect(calls).toEqual([
      `launchctl bootout system/${AGENT_HARNESS_DAEMON_LABEL}`,
      "removeHold 502",
      `launchctl disable system/${AGENT_HARNESS_DAEMON_LABEL}`,
      // Fix-round 4: the contextless re-park was the SEVENTH site claiming
      // "parked" from control flow -- it reported a park whenever these three
      // ops resolved. It now settles a launchd read before claiming anything,
      // and throws to the distinct `park-not-verified` if it does not observe
      // the job stopped.
      `launchctl print system/${AGENT_HARNESS_DAEMON_LABEL}`,
    ]);
  });

  it("a failing disable during the contextless re-park is LOUD: jobDisabled false + cleanup error + warning print", async () => {
    const printed: string[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => ({ kind: "unresolvable", reason: NON_HERMES_BOOT_PARK_REASON }),
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        runLaunchctlFn: async (args) =>
          args[0] === "disable"
            ? { code: 5, stdout: "", stderr: "override db locked" }
            : { code: 0, stdout: "", stderr: "" },
      }),
    });
    handle.stopOracleLoop();
    const outcome = handle.results[0]!.outcome;
    expect(outcome.kind).toBe("parked");
    expect(printed.join("\n")).toContain("could NOT be fully re-parked");
    expect(printed.join("\n")).toContain("override db locked");
  });

  it("M6: the non-Hermes reason names the deliberate v1 scope bound, not a fault", async () => {
    expect(NON_HERMES_BOOT_PARK_REASON).toBe(
      "v1 releases only Hermes; other confined agents stay parked by design.",
    );
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => ({ kind: "unresolvable", reason: NON_HERMES_BOOT_PARK_REASON }),
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 60_000,
      internals: baseInternals(),
    });
    handle.stopOracleLoop();
    const outcome = handle.results[0]!.outcome as { kind: string; reason: string };
    expect(outcome.reason).toContain("v1 releases only Hermes");
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round H2: gate daemon boot bootstrap)", () => {
  it("bootstraps + kickstarts the per-uid gate daemon and awaits its runtime state BEFORE the release barrier", async () => {
    const events: string[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        runLaunchctlFn: async (args) => {
          events.push(`launchctl ${args.join(" ")}`);
          return { code: 0, stdout: "", stderr: "" };
        },
        ensureRuntimeFs: async () => {
          events.push("ensureRuntimeFs");
        },
        ensureGateHomeLayout: async (input) => {
          events.push(`ensureGateHomeLayout ${input.gateAccount} ${input.gateUid} ${input.gateHomeDirectory}`);
          return { logDir: `${input.gateHomeDirectory}/logs` };
        },
        readRuntimeState: async () => {
          events.push("readRuntimeState");
          return JSON.stringify({ agent_uid: 502, gate_port: 40001, generation_id: 7, pid: 991, pid_start: "991-1000" });
        },
        runBarrier: async () => {
          events.push("barrier");
          return RELEASED;
        },
      }),
    });
    handle.stopOracleLoop();
    expect(handle.results[0]!.outcome).toEqual({ kind: "released", generationId: 7 });
    const bootstrapIdx = events.indexOf(
      "launchctl bootstrap system /Library/LaunchDaemons/ai.sanctuaryprotocol.egress-gate.502.plist",
    );
    const runtimeFsIdx = events.indexOf("ensureRuntimeFs");
    const homeLayoutIdx = events.indexOf(
      "ensureGateHomeLayout sanctuary-gate-hermes 511 /var/sanctuary-agents/sanctuary-gate-hermes",
    );
    const kickIdx = events.indexOf("launchctl kickstart system/ai.sanctuaryprotocol.egress-gate.502");
    const readIdx = events.indexOf("readRuntimeState");
    const barrierIdx = events.indexOf("barrier");
    expect(runtimeFsIdx).toBeGreaterThanOrEqual(0);
    expect(homeLayoutIdx).toBeGreaterThan(runtimeFsIdx);
    expect(bootstrapIdx).toBeGreaterThanOrEqual(0);
    expect(bootstrapIdx).toBeGreaterThan(homeLayoutIdx);
    expect(kickIdx).toBeGreaterThan(bootstrapIdx);
    expect(readIdx).toBeGreaterThan(kickIdx);
    expect(barrierIdx).toBeGreaterThan(readIdx);
    // 2026-07-24 S5-3 fix: the PRIVILEGED peer-resolver daemon is ALSO
    // bootstrapped on every boot (RunAtLoad=false, same H2 rationale) --
    // BEFORE the gate daemon's own bootstrap, so the gate's first CONNECT
    // after a reboot has somewhere to resolve peers from immediately.
    const resolverBootstrapIdx = events.indexOf(
      "launchctl bootstrap system /Library/LaunchDaemons/ai.sanctuaryprotocol.egress-gate-peer-resolver.502.plist",
    );
    const resolverKickIdx = events.indexOf(
      "launchctl kickstart system/ai.sanctuaryprotocol.egress-gate-peer-resolver.502",
    );
    expect(resolverBootstrapIdx).toBeGreaterThanOrEqual(0);
    expect(resolverKickIdx).toBeGreaterThan(resolverBootstrapIdx);
    expect(bootstrapIdx).toBeGreaterThan(resolverKickIdx);
  });

  it("a boot gate-home layout failure logs LOUDLY and forces the release barrier to park fail-closed", async () => {
    const printed: string[] = [];
    const audits: Array<{ operation: string; details: Record<string, unknown> }> = [];
    const barrierEvents: string[] = [];
    const barrierOps: ReleaseBarrierOps = {
      bootoutJob: async () => void barrierEvents.push("bootout"),
      removeHoldFile: async () => void barrierEvents.push("removeHold"),
      disableJob: async () => void barrierEvents.push("disable"),
      restoreParkedPlist: async () => void barrierEvents.push("restoreParkedPlist"),
      rearmAnchor: async () => {
        barrierEvents.push("rearm");
        return { ok: true };
      },
      verifyGate: async () => {
        barrierEvents.push("verifyGate");
        return { ok: true };
      },
      commitGeneration: async () => {
        barrierEvents.push("commit");
        throw new Error("commit must not run after gate verification fails");
      },
      bootSessionUuid: async () => "boot-session",
      writeHoldFile: async () => {
        throw new Error("hold file must not be written after gate verification fails");
      },
      writeReleasedPlist: async () => {
        throw new Error("released plist must not be written after gate verification fails");
      },
      enableJob: async () => {
        throw new Error("job must not be enabled after gate verification fails");
      },
      bootstrapJob: async () => {
        throw new Error("harness must not bootstrap after gate verification fails");
      },
      harnessStatus: async () => ({ known: true, installed: true, running: false }),
      sleepMs: async () => undefined,
    };
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async (operation, details) => void audits.push({ operation, details }),
      print: (line) => printed.push(line),
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        ensureGateHomeLayout: async () => {
          throw new Error("stale log owner uid=505 expected uid=511");
        },
        runBarrier: runReleaseBarrierSequence,
        createBarrierOps: (() => barrierOps) as never,
      }),
    });
    handle.stopOracleLoop();
    expect(printed.join("\n")).toContain("gate account home layout assert failed");
    expect(printed.join("\n")).toContain("stale log owner");
    expect(printed.join("\n")).toContain("refuse release");
    expect(printed.join("\n")).toContain("repair-egress-gate");
    expect(barrierEvents).toEqual(["bootout", "removeHold", "disable", "restoreParkedPlist", "rearm", "verifyGate"]);
    const layoutAudit = audits.find((entry) => entry.operation === "exclusive_egress_gate_home_layout_failed");
    expect(layoutAudit?.details).toMatchObject({
      agent_uid: 502,
      gate_account: "sanctuary-gate-hermes",
      gate_uid: 511,
      gate_home_directory: "/var/sanctuary-agents/sanctuary-gate-hermes",
      reason: "stale log owner uid=505 expected uid=511",
      barrier_continues_fail_closed: true,
    });
    const outcome = handle.results[0]!.outcome;
    expect(outcome.kind).toBe("parked");
    if (outcome.kind === "parked") {
      expect(outcome.reason).toContain("release barrier parked at stage gate-verify");
      expect(outcome.reason).toContain("gate account home layout assertion failed before release");
      expect(outcome.reason).toContain("stale log owner uid=505 expected uid=511");
      expect(outcome.parkedClaim.state).toBe("parked");
    }
  });

  it("a gate bootstrap failure logs LOUDLY and still runs the barrier (which parks fail-closed)", async () => {
    const printed: string[] = [];
    let barrierRan = false;
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        runLaunchctlFn: async (args) =>
          args[0] === "bootstrap"
            ? { code: 5, stdout: "", stderr: "Bootstrap failed: 125: Unknown error" }
            : { code: 0, stdout: "", stderr: "" },
        runBarrier: async () => {
          barrierRan = true;
          return {
            kind: "parked",
            stage: "gate-verify",
            reason: "gate runtime state unreadable",
            holdFileRemoved: true,
            jobDisabled: true,
            cleanupErrors: [],
            // Fix-round 4: a parked outcome REQUIRES a run-state claim, and a
            // claim cannot be hand-rolled -- tests model launchd and let the
            // real chokepoint classify it, exactly as production does.
            parkedClaim: await assessHarnessParked({
              probe: {
                harnessStatus: async () => ({ known: true, installed: true, running: false }),
                sleepMs: async () => undefined,
              },
            }),
          };
        },
      }),
    });
    handle.stopOracleLoop();
    expect(printed.join("\n")).toContain("gate daemon bootstrap failed");
    expect(barrierRan).toBe(true);
    expect(handle.results[0]!.outcome.kind).toBe("parked");
  });

  it("'already bootstrapped' from launchctl is tolerated (idempotent boot)", async () => {
    let kicked = false;
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        runLaunchctlFn: async (args) => {
          if (args[0] === "bootstrap") {
            return { code: 37, stdout: "", stderr: "Bootstrap failed: 37: already bootstrapped" };
          }
          if (args[0] === "kickstart") kicked = true;
          return { code: 0, stdout: "", stderr: "" };
        },
      }),
    });
    handle.stopOracleLoop();
    expect(kicked).toBe(true);
    expect(handle.results[0]!.outcome).toEqual({ kind: "released", generationId: 7 });
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round H3: persistent registry-rescan refresh loop)", () => {
  it("refreshes an agent ARMED AFTER BOOT: the loop re-lists the registry and resolves its gate uid from the marker", async () => {
    const lateEntry: BootRegistryEntry = {
      agent_uid: 601,
      gate_port: 40002,
      fortress_path: "/fortress/b",
      generation_id: 3,
    };
    let scans = 0;
    const refreshCalls: unknown[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 5,
      internals: baseInternals({
        listRegistryEntries: async () => {
          scans += 1;
          // First list (boot release) sees only ENTRY; later ticks see the
          // post-boot-armed agent too (the install CLI added it).
          return { entries: scans <= 1 ? [ENTRY] : [ENTRY, lateEntry], quarantined: [], dirty: false };
        },
        loadMarker: async (fortressPath) =>
          fortressPath === "/fortress/b" ? { agent_uid: 601, gate_uid: 612 } : null,
        createOracle: ((_priv: never, gateUid: number) => ({
          refresh: async (binding: unknown) => {
            refreshCalls.push({ gateUid, binding });
            return null;
          },
        })) as never,
      }),
    });
    await sleep(80);
    handle.stopOracleLoop();
    const late = refreshCalls.filter(
      (c) => (c as { gateUid: number }).gateUid === 612,
    ) as { gateUid: number; binding: { agentUid: number; gatePort: number; generationId: number } }[];
    expect(late.length).toBeGreaterThan(0);
    expect(late[0]!.binding).toEqual({ agentUid: 601, gatePort: 40002, generationId: 3 });
    // The boot-released agent keeps refreshing too (cached gate uid, no marker read needed).
    const seed = refreshCalls.filter((c) => (c as { gateUid: number }).gateUid === 511);
    expect(seed.length).toBeGreaterThan(0);
  });

  it("skips tombstoned and uncommitted entries (no token for a dead or in-flight generation)", async () => {
    const refreshCalls: unknown[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 5,
      internals: baseInternals({
        listRegistryEntries: async () => ({
          entries: [
            ENTRY,
            { agent_uid: 700, gate_port: 40003, fortress_path: "/fortress/c", generation_id: 2, tombstone: true },
            { agent_uid: 701, gate_port: 40004, fortress_path: "/fortress/d" },
          ],
          quarantined: [],
          dirty: false,
        }),
        createOracle: ((_priv: never, gateUid: number) => ({
          refresh: async (binding: { agentUid: number }) => {
            refreshCalls.push(binding.agentUid);
            void gateUid;
            return null;
          },
        })) as never,
      }),
    });
    await sleep(60);
    handle.stopOracleLoop();
    expect(refreshCalls.length).toBeGreaterThan(0);
    expect(new Set(refreshCalls as number[])).toEqual(new Set([502]));
  });

  it("an agent armed AFTER a boot with an EMPTY registry still gets its token refreshed (the loop starts regardless)", async () => {
    // The 2026-07-23 S5 positive-through-gate drill defect: when the boot
    // daemon starts with an EMPTY registry (a fresh boot with no prior confined
    // agent, or any start after an unprotect emptied it) the pre-fix code
    // early-returned with a NO-OP stopOracleLoop, so the persistent refresh loop
    // never existed. An agent armed LATER (its arm mints exactly one token)
    // then never got a refresh, its short-TTL liveness token expired, and its
    // gate denied ALL egress (fail-closed non-functional) until the next daemon
    // restart with a non-empty registry. The loop must start regardless so a
    // later-armed agent is picked up by the re-scan.
    const lateEntry: BootRegistryEntry = {
      agent_uid: 601,
      gate_port: 40002,
      fortress_path: "/fortress/b",
      generation_id: 3,
    };
    let scans = 0;
    const refreshCalls: {
      gateUid: number;
      binding: { agentUid: number; gatePort: number; generationId: number };
    }[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX, // never called: no entries at boot
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 5,
      internals: baseInternals({
        listRegistryEntries: async () => {
          scans += 1;
          // Boot read (scan 1): EMPTY. Later ticks: the post-boot-armed agent
          // (the install CLI committed it after the daemon was already up).
          return { entries: scans <= 1 ? [] : [lateEntry], quarantined: [], dirty: false };
        },
        loadMarker: async (fortressPath) =>
          fortressPath === "/fortress/b" ? { agent_uid: 601, gate_uid: 612 } : null,
        createOracle: ((_priv: never, gateUid: number) => ({
          refresh: async (binding: { agentUid: number; gatePort: number; generationId: number }) => {
            refreshCalls.push({ gateUid, binding });
            return null;
          },
        })) as never,
      }),
    });
    // No boot-release ran (empty registry), but the loop must be LIVE, not the
    // pre-fix no-op: stopOracleLoop clears a REAL running timer.
    expect(handle.results).toHaveLength(0);
    await sleep(80);
    handle.stopOracleLoop();
    // Pre-fix: refreshCalls stays EMPTY (no loop ever ran) and this fails.
    const late = refreshCalls.filter((c) => c.gateUid === 612);
    expect(late.length).toBeGreaterThan(0);
    expect(late[0]!.binding).toEqual({ agentUid: 601, gatePort: 40002, generationId: 3 });
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round-2 BLOCKER-1: throws never bypass the real re-park)", () => {
  it("a THROWING resolver routes into the contextless re-park: the ops actually run and the outcome carries real flags", async () => {
    const calls: string[] = [];
    const removeHoldFile = vi.fn(async (uid: number) => void calls.push(`removeHold ${uid}`));
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => {
        // The production failure mode: resolveHermesGatewayArgv throws when
        // the Hermes runtime is missing from the agent home.
        throw new Error("hermes gateway entrypoint not found under /var/sanctuary-agents");
      },
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 60_000,
      internals: baseInternals({ runLaunchctlFn: okLaunchctl(calls), removeHoldFile }),
    });
    handle.stopOracleLoop();
    expect(handle.results[0]!.outcome).toMatchObject({
      kind: "parked",
      reason: expect.stringContaining("release-context resolver threw: hermes gateway entrypoint not found"),
      holdFileRemoved: true,
      jobDisabled: true,
      cleanupErrors: [],
    });
    // Pre-fix: the throw escaped to runBootExclusiveEgressRelease's catch and
    // NO op ran. Now the full contextless re-park runs.
    expect(calls).toEqual([
      `launchctl bootout system/${AGENT_HARNESS_DAEMON_LABEL}`,
      "removeHold 502",
      `launchctl disable system/${AGENT_HARNESS_DAEMON_LABEL}`,
      // Fix-round 4: the contextless re-park was the SEVENTH site claiming
      // "parked" from control flow -- it reported a park whenever these three
      // ops resolved. It now settles a launchd read before claiming anything,
      // and throws to the distinct `park-not-verified` if it does not observe
      // the job stopped.
      `launchctl print system/${AGENT_HARNESS_DAEMON_LABEL}`,
    ]);
  });

  it("a PRE-LOOP throw (ensureKeys) yields the LOUD park-not-verified outcome per agent, never a synthetic PARKED", async () => {
    const printed: string[] = [];
    const audits: { op: string; details: Record<string, unknown> }[] = [];
    const launchctlCalls: string[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async (op, details) => void audits.push({ op, details }),
      print: (line) => printed.push(line),
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        ensureKeys: async () => {
          throw new Error("EACCES: /var/db/sanctuary/gate-liveness");
        },
        runLaunchctlFn: okLaunchctl(launchctlCalls),
      }),
    });
    handle.stopOracleLoop();
    expect(handle.results).toHaveLength(1);
    expect(handle.results[0]!.outcome.kind).toBe("park-not-verified");
    expect((handle.results[0]!.outcome as { reason: string }).reason).toContain("EACCES");
    expect((handle.results[0]!.outcome as { reason: string }).reason).toContain("NOT verified");
    // LOUD + honest: no re-park op ran, and we never claimed one did.
    expect(launchctlCalls).toEqual([]);
    expect(printed.join("\n")).toContain("possibly startable");
    expect(audits).toEqual([
      {
        op: "exclusive_egress_boot_release",
        details: expect.objectContaining({ agent_uid: 502, outcome: "park-not-verified" }),
      },
    ]);
  });

  it("keys-failure on an EMPTY registry says the oracle loop did NOT start (loud + audited), not a silent no-op", async () => {
    // Follow-up to the empty-registry fall-through (#988). With the early-return
    // gone, an ensureKeys failure is now REACHED on an empty registry: the
    // per-entry park loop emits nothing (no entries) AND the oracle refresh loop
    // cannot start (it needs these keys), so #988's promise that a later-armed
    // agent gets picked up is BROKEN. The pre-fix path returned a SILENT no-op;
    // this asserts the supervisor says so loudly + records it, so an operator is
    // not left to discover it as an unexplained 503 on the next arm.
    const printed: string[] = [];
    const audits: { op: string; details: Record<string, unknown> }[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX, // never called: empty registry
      audit: async (op, details) => void audits.push({ op, details }),
      print: (line) => printed.push(line),
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        listRegistryEntries: async () => ({ entries: [], quarantined: [], dirty: false }),
        ensureKeys: async () => {
          throw new Error("EACCES: /var/db/sanctuary/gate-liveness");
        },
      }),
    });
    handle.stopOracleLoop(); // must be safe: the loop never started
    expect(handle.results).toHaveLength(0);
    // The loud honesty line names the not-started loop + the repair verb.
    const loud = printed.find(
      (l) => /refresh loop did NOT start/.test(l) && /repair-egress-gate/.test(l),
    );
    expect(loud, `printed: ${JSON.stringify(printed)}`).toBeDefined();
    expect(loud!).toContain("EACCES");
    // ...and a durable audit record (distinct from the per-agent park outcome).
    expect(audits).toEqual([
      {
        op: "exclusive_egress_boot_release",
        details: expect.objectContaining({ outcome: "oracle-loop-not-started" }),
      },
    ]);
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round-2 HIGH-3: host-singleton label protected across uids)", () => {
  it("a stale unresolvable entry must NOT bootout/disable the shared label when another uid resolved; its re-park runs FIRST", async () => {
    const staleEntry: BootRegistryEntry = { agent_uid: 502, gate_port: 40001, fortress_path: "/fortress/stale" };
    // No generation_id on the ok entry: the gate-daemon runtime wait is skipped.
    const okEntry: BootRegistryEntry = { agent_uid: 601, gate_port: 40002, fortress_path: "/fortress/b" };
    const events: string[] = [];
    const printed: string[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async (entry) =>
        entry.agent_uid === 601
          ? { ...OK_CTX, gateUid: 612 }
          : { kind: "unresolvable" as const, reason: "no marker for uid 502" },
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        // Registry order puts the RESOLVABLE entry FIRST: the supervisor must
        // still run the stale entry's contextless re-park before the release.
        listRegistryEntries: async () => ({ entries: [okEntry, staleEntry], quarantined: [], dirty: false }),
        runLaunchctlFn: async (args) => {
          events.push(`launchctl ${args.join(" ")}`);
          return { code: 0, stdout: "", stderr: "" };
        },
        removeHoldFile: async (uid: number) => void events.push(`removeHold ${uid}`),
        runBarrier: async (ctx: { agentUid: number }) => {
          events.push(`barrier ${ctx.agentUid}`);
          return RELEASED;
        },
      }),
    });
    handle.stopOracleLoop();
    // The shared harness label was NEVER booted out or disabled by the stale
    // entry's contextless re-park (it would kill uid 601's harness).
    expect(events).not.toContain(`launchctl bootout system/${AGENT_HARNESS_DAEMON_LABEL}`);
    expect(events).not.toContain(`launchctl disable system/${AGENT_HARNESS_DAEMON_LABEL}`);
    // The per-uid park (hold-file removal) DID run, strictly BEFORE the
    // resolvable agent's release barrier (ordering pinned).
    const holdIdx = events.indexOf("removeHold 502");
    const barrierIdx = events.indexOf("barrier 601");
    expect(holdIdx).toBeGreaterThanOrEqual(0);
    expect(barrierIdx).toBeGreaterThan(holdIdx);
    // Honest attribution: the log says WHAT was skipped for WHICH uid and why.
    const log = printed.join("\n");
    expect(log).toContain("uid 502");
    expect(log).toContain("SKIPPED");
    expect(log).toContain("601");
    // The stale agent's outcome is honest: hold file removed, job NOT disabled.
    const stale = handle.results.find((r) => r.agent_uid === 502)!;
    expect(stale.outcome).toMatchObject({ kind: "parked", holdFileRemoved: true, jobDisabled: false });
    // The resolvable agent's release survived.
    const ok = handle.results.find((r) => r.agent_uid === 601)!;
    expect(ok.outcome).toEqual({ kind: "released", generationId: 7 });
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round-2 MED-5: refresh loop re-entrancy guard)", () => {
  it("an overlapping tick is SKIPPED (no piled-up concurrent refreshes) and consecutive skips warn loudly", async () => {
    let listCalls = 0;
    // The first refresh read hangs UNTIL the test releases it, so ticks pile
    // up deterministically regardless of host load.
    let releaseHang: () => void = () => undefined;
    const printed: string[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 5,
      internals: baseInternals({
        listRegistryEntries: async () => {
          listCalls += 1;
          if (listCalls > 1) {
            await new Promise<void>((resolve) => {
              releaseHang = resolve;
            });
          }
          return { entries: [ENTRY], quarantined: [], dirty: false };
        },
      }),
    });
    // Poll until the consecutive-skip warning fires (load-robust deadline).
    const deadline = Date.now() + 10_000;
    while (!printed.some((l) => l.includes("consecutive tick(s) skipped")) && Date.now() < deadline) {
      await sleep(5);
    }
    handle.stopOracleLoop();
    releaseHang();
    expect(printed.join("\n")).toContain("consecutive tick(s) skipped");
    // One boot read + exactly ONE in-flight refresh read: every overlapping
    // tick was skipped instead of piling a concurrent read on the slow host.
    expect(listCalls).toBe(2);
  });

  it("a hung refresh is timed out, surfaced as stuck, and the next tick can start", async () => {
    clearExclusiveEgressOracleRefreshStatus();
    let listCalls = 0;
    const releases: Array<() => void> = [];
    const printed: string[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 5,
      internals: baseInternals({
        oracleRefreshTimeoutMs: 20,
        oracleRefreshStuckThreshold: 1,
        listRegistryEntries: async () => {
          listCalls += 1;
          if (listCalls > 1) {
            await new Promise<void>((resolve) => {
              releases.push(resolve);
            });
          }
          return { entries: [ENTRY], quarantined: [], dirty: false };
        },
      }),
    });
    const deadline = Date.now() + 2_000;
    while (listCalls < 3 && Date.now() < deadline) {
      await sleep(5);
    }
    const stuck = getExclusiveEgressOracleRefreshStatus(ENTRY.agent_uid);
    handle.stopOracleLoop();
    for (const release of releases) release();
    expect(listCalls).toBeGreaterThanOrEqual(3);
    expect(printed.join("\n")).toContain("oracle refresh STUCK");
    expect(stuck?.reason).toContain("could not observe fresh registry/pf liveness");
    expect(stuck?.consecutive_misses).toBeGreaterThanOrEqual(1);
    clearExclusiveEgressOracleRefreshStatus();
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round-2 MED-6 + fix-round-3 HIGH-2: quarantine + warn-once logs)", () => {
  it("a quarantined entry is warn-once AND (fix-round-3) forces dirty: the sibling's token is WITHHELD until repair", async () => {
    const refreshed: number[] = [];
    const printed: string[] = [];
    let listCalls = 0;
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 5,
      internals: baseInternals({
        listRegistryEntries: async () => {
          listCalls += 1;
          // Production semantics: listQuarantined FORCES dirty on quarantine.
          return {
            entries: [ENTRY],
            quarantined: [{ index: 1, reason: "malformed committed entry (failed the fail-closed entry validation)" }],
            dirty: true,
          };
        },
        createOracle: (() => ({
          refresh: async (binding: { agentUid: number }) => {
            refreshed.push(binding.agentUid);
            return null;
          },
        })) as never,
      }),
    });
    // Poll until several full ticks completed (load-robust deadline).
    const deadline = Date.now() + 10_000;
    while (listCalls < 5 && Date.now() < deadline) {
      await sleep(5);
    }
    handle.stopOracleLoop();
    // Fix-round-3 HIGH-2: the sibling entry got NO token across many ticks --
    // per-uid liveness cannot rule out extra permissive rules on a dirty
    // anchor, so re-signing freshness would be an unverifiable claim.
    expect(refreshed).toHaveLength(0);
    // The quarantine finding is individually identified and WARN-ONCE in the
    // refresh loop (plus the one boot-phase line), never a per-tick flood.
    const bootLines = printed.filter((l) => l.includes("boot: registry entry #1"));
    const refreshLines = printed.filter((l) => l.includes("oracle refresh: registry entry #1"));
    expect(bootLines).toHaveLength(1);
    expect(refreshLines).toHaveLength(1);
    expect(refreshLines[0]).toContain("QUARANTINED");
    // The withholding is warn-once per uid, naming the uid and the reason.
    const withheldLines = printed.filter((l) => l.includes("WITHHELD") && l.includes("uid 502"));
    expect(withheldLines).toHaveLength(1);
    expect(withheldLines[0]).toContain("DIRTY");
  });

  it("an unreadable registry in the refresh loop is warn-once (not a 1-per-tick flood), re-armed on recovery", async () => {
    let listCalls = 0;
    const printed: string[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 5,
      internals: baseInternals({
        listRegistryEntries: async () => {
          listCalls += 1;
          if (listCalls > 1) throw new Error("EIO reading registry");
          return { entries: [ENTRY], quarantined: [], dirty: false };
        },
      }),
    });
    // Poll until many failing ticks actually ran (load-robust deadline).
    const deadline = Date.now() + 10_000;
    while (listCalls < 5 && Date.now() < deadline) {
      await sleep(5);
    }
    handle.stopOracleLoop();
    expect(listCalls).toBeGreaterThanOrEqual(5); // many ticks actually ran
    const unreadableLines = printed.filter((l) => l.includes("registry unreadable"));
    expect(unreadableLines).toHaveLength(1);
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round-3 HIGH-1: shared-label skip verifies not-running)", () => {
  const staleEntry: BootRegistryEntry = { agent_uid: 502, gate_port: 40001, fortress_path: "/fortress/stale" };
  // No generation_id on the ok entry: the gate-daemon runtime wait is skipped.
  const okEntry: BootRegistryEntry = { agent_uid: 601, gate_port: 40002, fortress_path: "/fortress/b" };

  function skipPathInput(printOutput: { code: number; stdout: string; stderr: string }, printed: string[]) {
    const launchctlCalls: string[] = [];
    return {
      launchctlCalls,
      input: {
        resolveAgent: async (entry: { agent_uid: number }) =>
          entry.agent_uid === 601
            ? { ...OK_CTX, gateUid: 612 }
            : ({ kind: "unresolvable" as const, reason: "no marker for uid 502" } as BootAgentResolution),
        audit: async () => undefined,
        print: (line: string) => void printed.push(line),
        refreshIntervalMs: 60_000,
        internals: baseInternals({
          listRegistryEntries: async () => ({ entries: [okEntry, staleEntry], quarantined: [], dirty: false }),
          runLaunchctlFn: async (args: readonly string[]) => {
            launchctlCalls.push(`launchctl ${args.join(" ")}`);
            if (args[0] === "print") return printOutput;
            return { code: 0, stdout: "", stderr: "" };
          },
          removeHoldFile: async () => undefined,
          runBarrier: async () => RELEASED,
        }),
      },
    };
  }

  it("a harness RUNNING from stale launchd state while bootout is withheld is a LOUD park-not-verified, never a silent PARKED", async () => {
    const printed: string[] = [];
    // The status probe (launchctl print system/<label>) reports a live pid.
    const { input, launchctlCalls } = skipPathInput(
      { code: 0, stdout: "\tstate = running\n\tpid = 4242\n", stderr: "" },
      printed,
    );
    const handle = await startExclusiveEgressBootSupervisor(input);
    handle.stopOracleLoop();
    const stale = handle.results.find((r) => r.agent_uid === 502)!;
    // Pre-fix: this was a quiet {kind:"parked"} while the process kept running.
    expect(stale.outcome.kind).toBe("park-not-verified");
    const reason = (stale.outcome as { reason: string }).reason;
    expect(reason).toContain("uid 502");
    expect(reason).toContain("still reports a pid (4242)");
    expect(reason).toContain("withheld");
    expect(reason).toContain("601");
    // The shared-label ops stayed withheld (never issued for the stale uid).
    expect(launchctlCalls).not.toContain(`launchctl bootout system/${AGENT_HARNESS_DAEMON_LABEL}`);
    expect(launchctlCalls).not.toContain(`launchctl disable system/${AGENT_HARNESS_DAEMON_LABEL}`);
    // The loud boot log names the unverified park.
    expect(printed.join("\n")).toContain("NOT verified");
    // The resolvable uid's release still proceeded.
    const ok = handle.results.find((r) => r.agent_uid === 601)!;
    expect(ok.outcome).toEqual({ kind: "released", generationId: 7 });
  });

  it("an UNTRUSTWORTHY launchctl status in the skip path is also park-not-verified (fail-closed toward loud)", async () => {
    const printed: string[] = [];
    // launchctl print fails in a way that is neither running nor not-loaded.
    const { input } = skipPathInput({ code: 150, stdout: "", stderr: "Bad system call" }, printed);
    const handle = await startExclusiveEgressBootSupervisor(input);
    handle.stopOracleLoop();
    const stale = handle.results.find((r) => r.agent_uid === 502)!;
    expect(stale.outcome.kind).toBe("park-not-verified");
    expect((stale.outcome as { reason: string }).reason).toContain("trustworthy");
  });

  it("the skip path with NO running process still parks quietly (kind parked, shared-label ops honestly skipped)", async () => {
    const printed: string[] = [];
    // launchctl print: job loaded but no pid line = not running.
    const { input } = skipPathInput({ code: 0, stdout: "\tstate = not running\n", stderr: "" }, printed);
    const handle = await startExclusiveEgressBootSupervisor(input);
    handle.stopOracleLoop();
    const stale = handle.results.find((r) => r.agent_uid === 502)!;
    expect(stale.outcome).toMatchObject({ kind: "parked", holdFileRemoved: true, jobDisabled: false });
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round-3 HIGH-2: dirty registry withholds freshness tokens)", () => {
  it("no token is refreshed while the listing is dirty (warn-once per uid); refresh RESUMES when the registry is clean", async () => {
    const refreshed: number[] = [];
    const printed: string[] = [];
    let listCalls = 0;
    let dirtyNow = true;
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 5,
      internals: baseInternals({
        listRegistryEntries: async () => {
          listCalls += 1;
          return { entries: [ENTRY], quarantined: [], dirty: dirtyNow };
        },
        createOracle: (() => ({
          refresh: async (binding: { agentUid: number }) => {
            refreshed.push(binding.agentUid);
            return null;
          },
        })) as never,
      }),
    });
    // Phase 1: many dirty ticks (load-robust deadline). Pre-fix, the loop
    // ignored the dirty bit and kept re-signing tokens for a dirty anchor.
    const deadline = Date.now() + 10_000;
    while (listCalls < 6 && Date.now() < deadline) {
      await sleep(5);
    }
    expect(refreshed).toHaveLength(0);
    const withheldLines = printed.filter((l) => l.includes("WITHHELD") && l.includes("uid 502"));
    expect(withheldLines).toHaveLength(1);
    // Phase 2: the registry recovers (repair ran); tokens flow again for the
    // clean entry and the warn-once state is re-armed via the resume line.
    dirtyNow = false;
    const resumeDeadline = Date.now() + 10_000;
    while (refreshed.length === 0 && Date.now() < resumeDeadline) {
      await sleep(5);
    }
    handle.stopOracleLoop();
    expect(refreshed.length).toBeGreaterThan(0);
    expect(new Set(refreshed)).toEqual(new Set([502]));
    expect(printed.filter((l) => l.includes("token refresh resumed"))).toHaveLength(1);
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round-3 MED-4: generation re-check before release)", () => {
  function mkBarrierOps(commitGen: number): ReleaseBarrierOps {
    // Stateful (fix-round 3, 2026-07-19): reassert-parked OBSERVES the stop.
    let running = false;
    return {
      disableJob: async () => undefined,
      enableJob: async () => undefined,
      bootstrapJob: async () => {
        running = true;
      },
      bootoutJob: async () => {
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

  it("a registry generation advanced between resolution and release parks LOUDLY at commit-generation, never releases", async () => {
    const printed: string[] = [];
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        // ENTRY was resolved at generation 7; a concurrent repair/install
        // advanced the registry to generation 8 before the barrier committed.
        runBarrier: runReleaseBarrierSequence,
        createBarrierOps: (() => mkBarrierOps(8)) as never,
      }),
    });
    handle.stopOracleLoop();
    const outcome = handle.results[0]!.outcome;
    // Pre-fix: the barrier verified generation 8 and RELEASED with the stale
    // generation-7 resolved context (fortressPath/argv).
    expect(outcome.kind).toBe("parked");
    const reason = (outcome as { reason: string }).reason;
    expect(reason).toContain("commit-generation");
    expect(reason).toContain("registry changed during boot release for uid 502");
    expect(reason).toContain("generation 7");
    expect(reason).toContain("generation 8");
  });

  it("a matching generation at commit still releases (no false park from the re-check)", async () => {
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: () => undefined,
      refreshIntervalMs: 60_000,
      internals: baseInternals({
        runBarrier: runReleaseBarrierSequence,
        createBarrierOps: (() => mkBarrierOps(7)) as never,
      }),
    });
    handle.stopOracleLoop();
    expect(handle.results[0]!.outcome).toEqual({ kind: "released", generationId: 7 });
  });
});

describe("startExclusiveEgressBootSupervisor (fix-round-6 F2: malformed generation_floor withholds tokens through the REAL quarantine listing)", () => {
  it("the boot refresh withholds every token while the registry's generation_floor is malformed", async () => {
    // A REAL PfAnchorRegistry over an in-memory store: the boot supervisor's
    // listing seam routes through the PRODUCTION listQuarantined semantics,
    // so this refutes the pre-fix behavior where a malformed floor was
    // invisible on this read path (dirty: false -> tokens kept flowing over a
    // generation-monotonicity hole).
    const state: PfAnchorRegistryState = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [
        { agent_uid: 502, gate_port: 40001, fortress_path: "/fortress/a", generation_id: 7 },
      ],
      enable_token: "1",
      generation_floor: "9" as never,
    };
    const registry = new PfAnchorRegistry({
      store: {
        load: async () => structuredClone(state),
        save: async () => undefined,
      },
      lock: { acquire: async () => undefined, release: async () => undefined },
      runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
      armUnion: async () => ({ settleProbes: 1, enableToken: "1" }),
      disarm: async () => undefined,
      unionLiveness: async () => ({ live: true, reasons: [] }),
    });
    const refreshed: number[] = [];
    const printed: string[] = [];
    let listCalls = 0;
    const handle = await startExclusiveEgressBootSupervisor({
      resolveAgent: async () => OK_CTX,
      audit: async () => undefined,
      print: (line) => printed.push(line),
      refreshIntervalMs: 5,
      internals: baseInternals({
        listRegistryEntries: async () => {
          listCalls += 1;
          const listed = await registry.listQuarantined();
          return { entries: listed.entries, quarantined: listed.quarantined, dirty: listed.dirty };
        },
        createOracle: (() => ({
          refresh: async (binding: { agentUid: number }) => {
            refreshed.push(binding.agentUid);
            return null;
          },
        })) as never,
      }),
    });
    // Many full refresh ticks (load-robust deadline).
    const deadline = Date.now() + 10_000;
    while (listCalls < 5 && Date.now() < deadline) {
      await sleep(5);
    }
    handle.stopOracleLoop();
    // Pre-fix: listQuarantined read GREEN over the malformed floor (dirty
    // false, no finding), so the uid's token was re-signed every tick.
    expect(refreshed).toHaveLength(0);
    const log = printed.join("\n");
    // The distinct registry-level finding is loud on the boot path...
    expect(log).toContain("generation_floor is malformed");
    // ...and the withholding names the uid and the dirty fail-closed rule.
    const withheldLines = printed.filter((l) => l.includes("WITHHELD") && l.includes("uid 502"));
    expect(withheldLines).toHaveLength(1);
  });
});
