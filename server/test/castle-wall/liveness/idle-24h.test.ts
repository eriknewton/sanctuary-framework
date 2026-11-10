/**
 * An idle 24 hours driven through the observer and the census sampler: the
 * canary fires every CANARY_PERIOD up to the fixture leeway late, observer
 * cycles and census ticks run within LOCAL_JITTER, and the gateway's counter
 * grows once per long poll. After the first recovery completes, the wall and
 * the agent read OK at every observer cycle.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CANARY_PERIOD, CENSUS_PERIOD, OBSERVER_PERIOD, SECOND } from "../../../src/castle-wall/liveness/constants.js";
import { CensusSampler, CensusSeries } from "../../../src/castle-wall/liveness/census-sampler.js";
import { evaluateLiveness, type LivenessEnvelope } from "../../../src/castle-wall/liveness/evaluate.js";
import { generateCanaryPlist, parseSystemJobPrint } from "../../../src/castle-wall/liveness/launchd-plists.js";
import { LivenessObserver, type ObserverCollectors } from "../../../src/castle-wall/liveness/observer.js";
import { parseProcessRead, type ProcessRow } from "../../../src/castle-wall/liveness/process-census.js";

const FIX = join(__dirname, "fixtures");
const SCHEDULE = JSON.parse(readFileSync(join(FIX, "idle-jitter.json"), "utf8")) as {
  duration_ms: number; launchd_leeway_s: number; canary_lateness_ms: number[]; observer_jitter_ms: number[]; census_jitter_ms: number[];
  long_poll_ms: number; growth_bytes_per_poll: number; canary_confirm_delay_ms: number;
};
const STATES = JSON.parse(readFileSync(join(FIX, "states.json"), "utf8"));
const PRINTS = JSON.parse(readFileSync(join(FIX, "launchctl-print.json"), "utf8")).entries;
const PS = (() => { const p = parseProcessRead((JSON.parse(readFileSync(join(FIX, "process-census.json"), "utf8")) as { text: string }).text); if (p.status !== "ok") throw new Error("fixture"); return p.rows; })();
const IDLE = readFileSync(join(FIX, "census", "netstat-anv-reference-host-idle.txt"), "utf8").split("\n");
const GATEWAY_ROW = IDLE.find(line => line.includes("192.0.2.1.64719"))!;
const netstat = (rx: number) => [IDLE[1], IDLE[2], GATEWAY_ROW.replace(/ESTABLISHED\s+49560/, `ESTABLISHED ${String(rx).padStart(12)}`), ""].join("\n");
const NAME = "sanctuary-agent-fixture";
const AGENT_UID = 502;
const T0: number = STATES.base.nowMs;
const UP0: number = STATES.base.host.uptimeMs;
const OPERATOR: number = STATES.base.local.operator_uid;
const FORTRESS_ID: string = STATES.base.local.fortress_id;
const BOOT: string = STATES.base.host.bootId;

class World {
  now = T0;
  up = UP0;
  confirmation: { captured_at_ms: number; confirmed_at_ms: number } | null = null;
  sequence = 100;
  observerRecord: unknown = null;
  rx = 49_560;
  config: Record<string, unknown> = { ...structuredClone(STATES.base.config.value), launchd_leeway_s: SCHEDULE.launchd_leeway_s };
  set(at: number): void { this.up += at - this.now; this.now = at; }
  daemonRecord(): Record<string, unknown> {
    const d = structuredClone(STATES.base.daemon.value);
    const at = this.now - SECOND;
    d.sequence = this.sequence++;
    d.observed_at = new Date(at).toISOString();
    d.observed_uptime_ms = this.up - SECOND;
    d.collection = { started_at_ms: at, ended_at_ms: at };
    d.raw.detector.last_evaluate_at_ms = at;
    d.raw.heartbeat.last_durable_flush_at_ms = at;
    d.raw.canary.last_confirmation = this.confirmation === null ? null : { ...d.raw.canary.last_confirmation, ...this.confirmation };
    return d;
  }
  collectors(): ObserverCollectors {
    const bytes = Buffer.from(generateCanaryPlist(NAME));
    return {
      readRecords: async () => ({
        directory: { status: "ok" as const }, daemon: { status: "present" as const, value: this.daemonRecord() },
        observer: this.observerRecord === null ? { status: "absent" as const } : { status: "present" as const, value: structuredClone(this.observerRecord) },
        config: { status: "present" as const, value: structuredClone(this.config) }, readDeadlineHit: false,
      }),
      readBootId: async () => BOOT,
      queryAvailability: async () => "live",
      printFullAgent: async () => ({ loaded: true, pid: 4242 }),
      readFullAgentState: async () => ({ latched: false, charges_ms: [] }),
      readProcesses: async () => [PS, PS],
      printHarness: async () => 75400,
      collectCanaryFacts: async () => ({
        plistStat: { status: "ok", value: { isFile: true, isSymbolicLink: false, uid: 0, gid: 0, mode: 0o100644, size: bytes.byteLength } },
        plistBytes: { status: "ok", value: bytes },
        account: { status: "ok", value: { name: NAME, reverseUid: AGENT_UID } },
        print: { status: "ok", value: parseSystemJobPrint(PRINTS.canary_system.stdout) },
      }),
    };
  }
  envelope(): LivenessEnvelope {
    return evaluateLiveness({
      nowMs: this.now, platform: "darwin", host: { ok: true, bootId: BOOT, uptimeMs: this.up },
      local: { fortress_id: FORTRESS_ID, platform: "darwin", operator_uid: OPERATOR }, directory: { status: "ok" },
      daemon: { status: "present", value: this.daemonRecord() },
      observer: this.observerRecord === null ? { status: "absent" } : { status: "present", value: this.observerRecord },
      config: { status: "present", value: this.config },
    });
  }
}

type Event = { at: number; order: number; kind: "canary" | "confirm" | "census" | "observer" };

describe("idle 24 hours", () => {
  it("keeps wall OK and agent OK at every observer cycle after the first recovery completes", async () => {
    const world = new World();
    const timers = {
      setTimeout: (fire: () => void, ms: number) => setTimeout(fire, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout),
      setInterval: () => 0, clearInterval: () => undefined,
    };
    const series = new CensusSeries();
    let observer: LivenessObserver | null = null;
    const sampler = new CensusSampler({
      series, runNetstat: async () => ({ status: "ok", stdout: netstat(world.rx) }), context: () => observer!.samplingContext(),
      clock: { nowMs: () => world.now, uptimeMs: () => world.up }, timers,
    });
    observer = new LivenessObserver({
      fortressId: FORTRESS_ID, hostId: "host-fixture", operatorUid: OPERATOR, collectors: world.collectors(), sampler, series,
      publisher: { publish: async record => { world.observerRecord = JSON.parse(JSON.stringify(record)); } },
      clock: { nowMs: () => world.now, uptimeMs: () => world.up }, timers, instance: "observer-idle-1",
    });

    const pick = (list: number[], i: number) => list[i % list.length]!;
    const events: Event[] = [];
    for (let i = 0; i * OBSERVER_PERIOD <= SCHEDULE.duration_ms; i++) events.push({ at: T0 + SECOND + i * OBSERVER_PERIOD + pick(SCHEDULE.observer_jitter_ms, i), order: 3, kind: "observer" });
    for (let j = 0; j * CENSUS_PERIOD <= SCHEDULE.duration_ms; j++) events.push({ at: T0 + 2 * SECOND + j * CENSUS_PERIOD + pick(SCHEDULE.census_jitter_ms, j), order: 2, kind: "census" });
    for (let k = 0; k * CANARY_PERIOD <= SCHEDULE.duration_ms; k++) {
      const fired = T0 + 3 * SECOND + k * CANARY_PERIOD + pick(SCHEDULE.canary_lateness_ms, k);
      events.push({ at: fired, order: 0, kind: "canary" }, { at: fired + SCHEDULE.canary_confirm_delay_ms, order: 1, kind: "confirm" });
    }
    events.sort((a, b) => a.at - b.at || a.order - b.order);

    let pendingCapture: number | null = null;
    let recoveredAt: number | null = null;
    let cycles = 0;
    let checked = 0;
    for (const event of events) {
      world.set(event.at);
      // One long poll completes every long_poll_ms, so the received counter grows with elapsed polls.
      world.rx = 49_560 + SCHEDULE.growth_bytes_per_poll * Math.floor((event.at - T0) / SCHEDULE.long_poll_ms);
      if (event.kind === "canary") { pendingCapture = event.at; continue; }
      if (event.kind === "confirm") { world.confirmation = { captured_at_ms: pendingCapture!, confirmed_at_ms: event.at }; continue; }
      if (event.kind === "census") { await sampler.tick(); continue; }
      await observer.tick();
      await new Promise<void>(resolve => setImmediate(resolve));
      cycles++;
      const envelope = world.envelope();
      const ok = envelope.wall.state.startsWith("wall_OK_") && envelope.agent.state.startsWith("agent_OK");
      if (recoveredAt === null) { if (ok) recoveredAt = event.at; continue; }
      checked++;
      if (!ok) {
        expect({ at: event.at - T0, wall: envelope.wall.reasons, agent: envelope.agent.reasons }).toEqual({ at: event.at - T0, wall: ["none"], agent: ["none"] });
      }
    }
    expect(recoveredAt).not.toBeNull();
    expect(recoveredAt! - T0).toBeLessThan(10 * 60 * SECOND);
    expect(cycles).toBeGreaterThanOrEqual(SCHEDULE.duration_ms / OBSERVER_PERIOD);
    expect(checked).toBeGreaterThan(cycles - 100);
    expect(series.length).toBeGreaterThan(0);
  }, 300_000);
});
