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
import { generateKeyPairSync } from "node:crypto";

import {
  NON_HERMES_BOOT_PARK_REASON,
  startExclusiveEgressBootSupervisor,
  type BootAgentResolution,
  type BootRegistryEntry,
  type ExclusiveEgressBootSupervisorInternals,
} from "../../src/egress-gate/arming-wiring.js";
import { AGENT_HARNESS_DAEMON_LABEL } from "../../src/egress-gate/harness-daemon.js";
import type { ReleaseBarrierOutcome } from "../../src/egress-gate/release-barrier.js";

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
    listRegistryEntries: async () => [ENTRY],
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
    ...overrides,
  };
}

const OK_CTX: BootAgentResolution = {
  kind: "ok",
  agentAccount: "sanctuary-hermes",
  harnessArgv: ["/usr/local/bin/hermes"],
  harnessLogDir: "/var/sanctuary-agents/sanctuary-hermes/logs",
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
    expect(handle.results[0]!.outcome).toEqual({
      kind: "parked",
      reason: expect.stringContaining("no marker for uid 502"),
    });
    // The REAL park ops ran, in order: bootout, hold-file removal, disable.
    expect(calls).toEqual([
      `launchctl bootout system/${AGENT_HARNESS_DAEMON_LABEL}`,
      "removeHold 502",
      `launchctl disable system/${AGENT_HARNESS_DAEMON_LABEL}`,
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
    const kickIdx = events.indexOf("launchctl kickstart system/ai.sanctuaryprotocol.egress-gate.502");
    const readIdx = events.indexOf("readRuntimeState");
    const barrierIdx = events.indexOf("barrier");
    expect(bootstrapIdx).toBeGreaterThanOrEqual(0);
    expect(kickIdx).toBeGreaterThan(bootstrapIdx);
    expect(readIdx).toBeGreaterThan(kickIdx);
    expect(barrierIdx).toBeGreaterThan(readIdx);
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
          return scans <= 1 ? [ENTRY] : [ENTRY, lateEntry];
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
        listRegistryEntries: async () => [
          ENTRY,
          { agent_uid: 700, gate_port: 40003, fortress_path: "/fortress/c", generation_id: 2, tombstone: true },
          { agent_uid: 701, gate_port: 40004, fortress_path: "/fortress/d" },
        ],
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
});
