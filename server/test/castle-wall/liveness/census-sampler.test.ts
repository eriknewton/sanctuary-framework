/**
 * The census sampler and its retained series: retention and resets, the
 * short-series consequence through the evaluator, bounded work over many
 * ticks, the sampler's own cadence, and the bounded netstat child.
 */
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AGENT_WINDOW_MAX,
  CENSUS_INPUT_BYTES,
  CENSUS_INPUT_ROWS,
  CENSUS_PAIR_MAX,
  CENSUS_PAIR_MIN,
  CENSUS_PERIOD,
  CENSUS_PID_ROWS,
  CENSUS_RUN,
  CENSUS_SAMPLES_MAX,
  COUNTER_MAX,
  LOCAL_JITTER,
  POLL_BACKOFF_CAP_MAX,
  SECOND,
  agentWindow,
} from "../../../src/castle-wall/liveness/constants.js";
import { parseIpv4Prefix, type StoredCensusSample } from "../../../src/castle-wall/liveness/census.js";
import { CensusSampler, CensusSeries, type CensusChildResult, type CensusSamplingContext } from "../../../src/castle-wall/liveness/census-sampler.js";
import { evaluateLiveness, type LivenessEnvelope, type LivenessInput } from "../../../src/castle-wall/liveness/evaluate.js";
import { BoundedChildRunner, WATCH_CHILD_ENV, createWatchCollectors, type WatchChild, type WatchSpawn } from "../../../src/cli/castle-wall-watch-collectors.js";

const FIXTURES = join(__dirname, "fixtures");
const STATES = JSON.parse(readFileSync(join(FIXTURES, "states.json"), "utf8")) as { base: LivenessInput };
const IDLE = readFileSync(join(FIXTURES, "census", "netstat-anv-reference-host-idle.txt"), "utf8").split("\n");
const PREAMBLE = IDLE[1]!;
const HEADER = IDLE[2]!;
const GATEWAY_ROW = IDLE.find(line => line.includes("192.0.2.1.64719"))!;
const OTHER_ROW = IDLE.find(line => line.includes("node:75439") && line.includes("ESTABLISHED"))!;
const BOOT = (STATES.base.host as { bootId: string }).bootId;
const BASE_NOW = (STATES.base as unknown as { nowMs: number }).nowMs;
const BASE_UP = (STATES.base.host as { uptimeMs: number }).uptimeMs;
const GATEWAY = { pid: 75399, start_identity: "gateway-start-fixture", uid: 502, generation: "generation-fixture-1" };
const MESSAGING = [parseIpv4Prefix("203.0.113.0/24")!];

/** A gateway row for socket `n` with the given received-byte counter. */
function gatewayRow(rx: number, n = 0): string {
  const local = `192.0.2.1.${64719 + n}`;
  const gencnt = (0x968d6d + n).toString(16).padStart(16, "0");
  return GATEWAY_ROW.replace("192.0.2.1.64719", local).replace(/ESTABLISHED\s+49560/, `ESTABLISHED ${String(rx).padStart(12)}`).replace("0000000000968d6d", gencnt);
}
/** A netstat output with `sockets` qualifying gateway rows at counter `rx`. */
const netstat = (rx: number, sockets = 1): string => [PREAMBLE, HEADER, ...Array.from({ length: sockets }, (_, n) => gatewayRow(rx + n, n)), OTHER_ROW, ""].join("\n");

const context = (over: Partial<CensusSamplingContext> = {}): CensusSamplingContext => ({ gateway: { ...GATEWAY }, gatewayAlive: true, ipv4Set: MESSAGING, bootId: BOOT, ...over });

/** A manual interval scheduler: records the requested period and fires on demand. */
class ManualTimers {
  periods: number[] = [];
  private fire: (() => void) | null = null;
  setInterval(fire: () => void, ms: number): unknown { this.periods.push(ms); this.fire = fire; return 1; }
  clearInterval(): void { this.fire = null; }
  tick(): void { this.fire?.(); }
}

interface Harness { sampler: CensusSampler; series: CensusSeries; clock: { now: number; up: number }; output: { next: () => Promise<CensusChildResult> }; ctx: { value: CensusSamplingContext }; timers: ManualTimers }
function harness(): Harness {
  const series = new CensusSeries();
  const clock = { now: BASE_NOW, up: BASE_UP };
  const output = { next: async (): Promise<CensusChildResult> => ({ status: "ok", stdout: netstat(1000) }) };
  const ctx = { value: context() };
  const timers = new ManualTimers();
  const sampler = new CensusSampler({ series, runNetstat: () => output.next(), context: () => ctx.value, clock: { nowMs: () => clock.now, uptimeMs: () => clock.up }, timers });
  return { sampler, series, clock, output, ctx, timers };
}
const advance = (h: Harness, ms: number) => { h.clock.now += ms; h.clock.up += ms; };

/** Evaluate the published series against the base fixture, shifted so the reader clock sits at `nowMs`. */
function evaluateAt(nowMs: number, uptimeMs: number, samples: StoredCensusSample[], config: Record<string, unknown> = {}): LivenessEnvelope {
  const dT = nowMs - BASE_NOW;
  const dU = uptimeMs - BASE_UP;
  const shift = (value: unknown, key: string): unknown => {
    if (Array.isArray(value)) return value.map(item => shift(item, ""));
    if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, shift(v, k)]));
    if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) return new Date(Date.parse(value) + dT).toISOString();
    if (typeof value === "number" && /uptime/i.test(key)) return value + dU;
    if (typeof value === "number" && (/_ms$/.test(key) || key === "nowMs") && Math.abs(value - BASE_NOW) < 86_400_000) return value + dT;
    return value;
  };
  const input = shift(structuredClone(STATES.base), "") as Record<string, any>;
  input.nowMs = nowMs;
  input.host.uptimeMs = uptimeMs;
  input.observer.value.raw.census = { status: "ok", samples };
  input.config.value.poll_backoff_cap_s = 0;
  Object.assign(input.config.value, config);
  return evaluateLiveness(input as LivenessInput);
}
const evaluateHarness = (h: Harness, config?: Record<string, unknown>) => evaluateAt(h.clock.now, h.clock.up, h.series.snapshot(), config);

// ---------------------------------------------------------------------------
describe("retention", () => {
  it("appends to CENSUS_SAMPLES_MAX, then evicts exactly the oldest per append", async () => {
    const h = harness();
    const seen: number[] = [];
    for (let i = 0; i < CENSUS_SAMPLES_MAX + 3; i++) {
      await h.sampler.tick();
      seen.push(h.clock.up);
      expect(h.series.length).toBe(Math.min(i + 1, CENSUS_SAMPLES_MAX));
      expect(h.series.snapshot().map(s => s.observed_uptime_ms)).toEqual(seen.slice(-CENSUS_SAMPLES_MAX));
      advance(h, CENSUS_PERIOD);
    }
  });

  it.each([
    ["a generation change", (h: Harness) => { h.ctx.value = context({ gateway: { ...GATEWAY, generation: "generation-fixture-2" } }); }],
    ["a boot change", (h: Harness) => { h.ctx.value = context({ bootId: "boot-fixture-next" }); }],
  ])("resets to the one new sample on %s", async (_case, change) => {
    const h = harness();
    for (let i = 0; i < 5; i++) { await h.sampler.tick(); advance(h, CENSUS_PERIOD); }
    change(h);
    await h.sampler.tick();
    expect(h.series.length).toBe(1);
    expect(h.series.snapshot()[0]!.observed_uptime_ms).toBe(h.clock.up);
  });

  it("never credits the earlier gateway's sockets to the new generation when a netstat in flight resolves after the gateway changed", async () => {
    const h = harness();
    for (let i = 0; i < 5; i++) { await h.sampler.tick(); advance(h, CENSUS_PERIOD); }
    const switchedAtUptime = h.clock.up;
    let resolve: (result: CensusChildResult) => void = () => undefined;
    h.output.next = () => new Promise<CensusChildResult>(done => { resolve = done; });
    const attempt = h.sampler.tick();
    // The observer selects a new gateway generation while the read started under the old one is still running.
    const G2 = { ...GATEWAY, pid: GATEWAY.pid + 2, generation: "generation-fixture-2" };
    h.ctx.value = context({ gateway: G2 });
    resolve({ status: "ok", stdout: netstat(5000, 2) });
    await attempt;
    for (const sample of h.series.snapshot()) {
      if (sample.gateway.generation === G2.generation) {
        // Rows are taken for the new generation's pid only, so the old gateway's counters never enter its series.
        expect(sample.gateway.pid).toBe(G2.pid);
        expect(sample.rows).toEqual([]);
      } else {
        expect(sample.gateway.generation).toBe(GATEWAY.generation);
        expect(sample.observed_uptime_ms).toBeLessThan(switchedAtUptime);
      }
    }
    expect(new Set(h.series.snapshot().map(sample => sample.gateway.generation)).size).toBe(1);
  });

  it("appends nothing on a failed attempt and keeps the series", async () => {
    const h = harness();
    for (let i = 0; i < 5; i++) { await h.sampler.tick(); advance(h, CENSUS_PERIOD); }
    const before = JSON.stringify(h.series.snapshot());
    for (const fail of [
      () => { h.output.next = async () => ({ status: "failed" }); },
      () => { h.output.next = async () => { throw new Error("spawn"); }; },
      () => { h.output.next = async () => ({ status: "ok", stdout: "garbage\n" }); },
      () => { h.output.next = async () => ({ status: "ok", stdout: netstat(1000, CENSUS_PID_ROWS + 1) }); },
      () => { h.output.next = async () => ({ status: "ok", stdout: netstat(1000) }); h.ctx.value = context({ gateway: null }); },
      () => { h.ctx.value = context({ gatewayAlive: false }); },
      () => { h.ctx.value = context({ ipv4Set: null }); },
      () => { h.ctx.value = context({ bootId: null }); },
    ]) {
      fail();
      await h.sampler.tick();
      expect(h.sampler.latestAttemptOk()).toBe(false);
      expect(JSON.stringify(h.series.snapshot())).toBe(before);
    }
  });
});

describe("short-series consequence", () => {
  it.each([0, Math.floor(POLL_BACKOFF_CAP_MAX / SECOND)])(
    "a gateway alive with no counter growth for longer than the agent window reads agent_DOWN agent_flow_stale (poll backoff cap %i s)", async capS => {
      const h = harness();
      let rx = 1000;
      // One healthy run, then a dead updater: the counters stop while the gateway stays alive.
      for (let i = 0; i <= CENSUS_RUN; i++) { h.output.next = async () => ({ status: "ok", stdout: netstat(rx) }); rx += 500; await h.sampler.tick(); advance(h, CENSUS_PERIOD); }
      advance(h, -CENSUS_PERIOD);
      expect(evaluateHarness(h, { poll_backoff_cap_s: capS }).agent.state).toBe("agent_OK_PASSIVE");
      const lastGrowthAt = h.clock.now;
      const window = agentWindow(capS * SECOND);
      expect(window).toBeLessThanOrEqual(AGENT_WINDOW_MAX);
      h.output.next = async () => ({ status: "ok", stdout: netstat(rx - 500) });
      while (h.clock.now - lastGrowthAt <= window) { advance(h, CENSUS_PERIOD); await h.sampler.tick(); }
      const env = evaluateHarness(h, { poll_backoff_cap_s: capS });
      expect(env.agent.state).toBe("agent_DOWN");
      expect(env.agent.reasons).toContain("agent_flow_stale");
      expect(env.agent.state).not.toBe("agent_INITIALIZING");
      expect(h.series.length).toBeLessThanOrEqual(CENSUS_SAMPLES_MAX);
    });
});

describe("complexity", () => {
  /** Exactly CENSUS_INPUT_ROWS lines: header, CENSUS_PID_ROWS qualifying rows, real other rows, then blank padding lines. */
  const atRowCap = (rx: number): string => {
    const lines = [PREAMBLE, HEADER, ...Array.from({ length: CENSUS_PID_ROWS }, (_, n) => gatewayRow(rx + n, n)), ...Array<string>(64).fill(OTHER_ROW)];
    while (lines.length < CENSUS_INPUT_ROWS) lines.push("");
    return lines.join("\n");
  };
  const ROW_VISIT_BOUND = CENSUS_INPUT_ROWS + 4 * CENSUS_SAMPLES_MAX;

  it("keeps the series and the per-tick row visits bounded over 10,000 ticks of row-cap inputs", async () => {
    const h = harness();
    const text = atRowCap(1000);
    expect(text.split("\n")).toHaveLength(CENSUS_INPUT_ROWS);
    h.output.next = async () => ({ status: "ok", stdout: text });
    for (let i = 0; i < 10_000; i++) {
      await h.sampler.tick();
      // Stop on the first excess, so a missing cap fails here and never by timeout or memory.
      if (h.series.length > CENSUS_SAMPLES_MAX || h.sampler.stats().lastRowVisits > ROW_VISIT_BOUND) {
        expect({ tick: i, length: h.series.length }).toEqual({ tick: i, length: Math.min(h.series.length, CENSUS_SAMPLES_MAX) });
        expect(h.sampler.stats().lastRowVisits).toBeLessThanOrEqual(ROW_VISIT_BOUND);
        break;
      }
      advance(h, CENSUS_PERIOD);
    }
    expect(h.series.length).toBe(CENSUS_SAMPLES_MAX);
    expect(h.series.snapshot().every(s => s.rows.length === CENSUS_PID_ROWS)).toBe(true);
    expect(h.sampler.stats().attempts).toBe(10_000);
  });

  it("keeps the row-visit bound on one input of CENSUS_INPUT_ROWS parsed rows", async () => {
    const h = harness();
    for (let i = 0; i < CENSUS_SAMPLES_MAX; i++) { await h.sampler.tick(); advance(h, CENSUS_PERIOD); }
    const full = [HEADER, gatewayRow(5000), ...Array<string>(CENSUS_INPUT_ROWS - 2).fill(OTHER_ROW)].join("\n");
    h.output.next = async () => ({ status: "ok", stdout: full });
    await h.sampler.tick();
    expect(h.sampler.latestAttemptOk()).toBe(true);
    expect(h.sampler.stats().lastRowVisits).toBeLessThanOrEqual(ROW_VISIT_BOUND);
  });

  it("keeps length 1 when the generation alternates every tick", async () => {
    const h = harness();
    for (let i = 0; i < 1000; i++) {
      h.ctx.value = context({ gateway: { ...GATEWAY, generation: i % 2 === 0 ? "generation-fixture-1" : "generation-fixture-2" } });
      await h.sampler.tick();
      expect(h.series.length).toBe(1);
      advance(h, CENSUS_PERIOD);
    }
  });

  it("saturates the skipped-attempt counter at COUNTER_MAX", async () => {
    const h = harness();
    h.sampler.primeSkippedForTest(COUNTER_MAX - 1);
    let release!: () => void;
    h.output.next = () => new Promise(resolve => { release = () => resolve({ status: "ok", stdout: netstat(1000) }); });
    const first = h.sampler.tick();
    for (let i = 0; i < 5; i++) void h.sampler.tick();
    expect(h.sampler.stats().skipped).toBe(COUNTER_MAX);
    release();
    await first;
    expect(h.sampler.stats().attempts).toBe(1);
  });
});

describe("cadence", () => {
  /** Deterministic jitter in [-LOCAL_JITTER/2, LOCAL_JITTER/2], so consecutive attempts are within LOCAL_JITTER of CENSUS_PERIOD. */
  const jitter = (i: number) => Math.round(((((i * 7919) % 101) / 100) - 0.5) * LOCAL_JITTER);

  it("owns its CENSUS_PERIOD timer; jittered samples stay inside the pair bounds and a growing series reads agent OK", async () => {
    const h = harness();
    h.sampler.start();
    expect(h.timers.periods).toEqual([CENSUS_PERIOD]);
    const nominal = { now: h.clock.now, up: h.clock.up };
    let rx = 1000;
    for (let i = 0; i < 2 * CENSUS_SAMPLES_MAX; i++) {
      h.clock.now = nominal.now + i * CENSUS_PERIOD + jitter(i);
      h.clock.up = nominal.up + i * CENSUS_PERIOD + jitter(i);
      h.output.next = async () => ({ status: "ok", stdout: netstat(rx) });
      rx += 700;
      h.timers.tick();
      await h.sampler.pending();
      const samples = h.series.snapshot();
      for (let k = 1; k < samples.length; k++) {
        const gap = samples[k]!.observed_uptime_ms - samples[k - 1]!.observed_uptime_ms;
        expect(gap, `tick ${i}`).toBeGreaterThanOrEqual(CENSUS_PAIR_MIN);
        expect(gap, `tick ${i}`).toBeLessThanOrEqual(CENSUS_PAIR_MAX);
      }
      if (i >= CENSUS_RUN) expect(evaluateHarness(h).agent.state, `tick ${i}`).toBe("agent_OK_PASSIVE");
    }
    h.sampler.stop();
  });

  it("a tick skipped behind a slow attempt breaks the run, which reads not OK until a full run forms after it", async () => {
    const h = harness();
    h.sampler.start();
    let rx = 1000;
    const states: string[] = [];
    for (let i = 0; i < 8; i++) {
      if (i > 0) advance(h, CENSUS_PERIOD);
      h.output.next = async () => ({ status: "ok", stdout: netstat(rx) });
      rx += 700;
      if (i === 2) {
        // The attempt at tick 2 is still in flight when tick 3 fires, so tick 3 is skipped; it then fails late.
        let release!: () => void;
        h.output.next = () => new Promise(resolve => { release = () => resolve({ status: "failed" }); });
        h.timers.tick();
        advance(h, CENSUS_PERIOD);
        h.timers.tick();
        expect(h.sampler.stats().skipped).toBe(1);
        release();
        await h.sampler.pending();
        states.push("skipped");
        i++;
        continue;
      }
      h.timers.tick();
      await h.sampler.pending();
      states.push(evaluateHarness(h).agent.state);
    }
    // Samples at ticks 0, 1, 4, 5, 6, 7: the pair 1 to 4 is outside the bounds, so no run forms until 4 to 7.
    expect(states).toEqual(["agent_INITIALIZING", "agent_INITIALIZING", "skipped", "agent_INITIALIZING", "agent_INITIALIZING", "agent_INITIALIZING", "agent_OK_PASSIVE"]);
    h.sampler.stop();
  });
});

describe("netstat child", () => {
  const timers = { setTimeout: (fire: () => void, ms: number) => setTimeout(fire, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout) };
  function spawnWith(stdout: string, seen: Array<{ file: string; args: readonly string[]; options: unknown }>): WatchSpawn {
    return (file, args, options) => {
      seen.push({ file, args, options });
      const child = Object.assign(new EventEmitter(), { pid: 4100 + seen.length, stdout: new EventEmitter(), stderr: new EventEmitter() }) as unknown as WatchChild & EventEmitter & { stdout: EventEmitter };
      child.kill = () => { queueMicrotask(() => { child.emit("exit", null, "SIGTERM"); child.emit("close", null, "SIGTERM"); }); return true; };
      queueMicrotask(() => { child.stdout.emit("data", Buffer.from(stdout)); child.emit("exit", 0, null); child.emit("close", 0, null); });
      return child;
    };
  }
  /** A valid census whose total size is exactly `bytes`: a valid prefix, then one blank line of spaces. */
  const sized = (bytes: number): string => {
    const prefix = `${netstat(1000)}`;
    return prefix + " ".repeat(bytes - Buffer.byteLength(prefix));
  };
  async function sampleThrough(stdout: string): Promise<{ appended: boolean; seen: Array<{ file: string; args: readonly string[]; options: unknown }> }> {
    const seen: Array<{ file: string; args: readonly string[]; options: unknown }> = [];
    const runner = new BoundedChildRunner({ spawn: spawnWith(stdout, seen), timers });
    const collectors = createWatchCollectors({ runner, timers, fortressPath: "/nonexistent-fixture", operatorUid: 501 });
    const series = new CensusSeries();
    const sampler = new CensusSampler({ series, runNetstat: () => collectors.runNetstat(), context: () => context(), clock: { nowMs: () => BASE_NOW, uptimeMs: () => BASE_UP }, timers: new ManualTimers() });
    await sampler.tick();
    return { appended: series.length === 1 && sampler.latestAttemptOk(), seen };
  }

  it("runs exactly /usr/sbin/netstat -anv -p tcp with the fixed environment, no shell, cwd /", async () => {
    const { appended, seen } = await sampleThrough(sized(CENSUS_INPUT_BYTES));
    expect(appended).toBe(true);
    expect(seen).toEqual([{ file: "/usr/sbin/netstat", args: ["-anv", "-p", "tcp"], options: { env: { ...WATCH_CHILD_ENV }, cwd: "/", stdio: ["ignore", "pipe", "pipe"], shell: false } }]);
    expect(WATCH_CHILD_ENV).toEqual({ PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C" });
  });

  it("reads one byte over CENSUS_INPUT_BYTES as census unavailable and parses no prefix", async () => {
    expect((await sampleThrough(sized(CENSUS_INPUT_BYTES + 1))).appended).toBe(false);
  });

  it("reads one row over CENSUS_INPUT_ROWS as census unavailable and parses no prefix", async () => {
    const lines = [PREAMBLE, HEADER, gatewayRow(1000)];
    while (lines.length < CENSUS_INPUT_ROWS) lines.push(OTHER_ROW);
    expect((await sampleThrough(lines.join("\n"))).appended).toBe(true);
    lines.push(OTHER_ROW);
    expect((await sampleThrough(lines.join("\n"))).appended).toBe(false);
  });
});
