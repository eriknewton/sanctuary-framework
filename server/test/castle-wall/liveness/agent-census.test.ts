/** The agent census predicate through the evaluator: the real reference-host idle series, rotations, reader-time bound and commissioning. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AGENT_WINDOW_BASE,
  CENSUS_PAIR_MAX,
  CENSUS_PAIR_MIN,
  CENSUS_PERIOD,
  CENSUS_RUN,
  SECOND,
  agentWindow,
} from "../../../src/castle-wall/liveness/constants.js";
import { buildStoredSample, parseCensus, parseIpv4Prefix, type CensusRow, type StoredCensusSample } from "../../../src/castle-wall/liveness/census.js";
import { evaluateLiveness, type LivenessEnvelope, type LivenessInput } from "../../../src/castle-wall/liveness/evaluate.js";

const FIXTURES = join(__dirname, "fixtures");
const IDLE = readFileSync(join(FIXTURES, "census", "netstat-anv-reference-host-idle.txt"), "utf8");
const STATES = JSON.parse(readFileSync(join(FIXTURES, "states.json"), "utf8")) as { base: LivenessInput };
const GATEWAY_PID = 75399;
const AGENT_UID = 502;
const GENERATION = "generation-fixture-1";
const MESSAGING = [parseIpv4Prefix("203.0.113.0/24")!];
const SEPARATOR = /^=== SAMPLE (\d+) observed_at=(\S+) observed_uptime_ms=(\d+)$/;
/** Fixture value, not a commissioned one: the reference series is evaluated with no poll backoff cap. */
const FIXTURE_POLL_BACKOFF_CAP_S = 0;

interface RawSample { observedAtMs: number; uptimeMs: number; rows: CensusRow[] }

/** Split the series on its separator lines and parse each block unchanged. */
function referenceSeries(): RawSample[] {
  const out: RawSample[] = [];
  let current: { observedAtMs: number; uptimeMs: number; lines: string[] } | null = null;
  const flush = () => {
    if (current === null) return;
    const parsed = parseCensus(current.lines.join("\n"), { gatewayPid: GATEWAY_PID });
    if (parsed.status !== "ok") throw new Error(parsed.detail);
    out.push({ observedAtMs: current.observedAtMs, uptimeMs: current.uptimeMs, rows: parsed.rows });
  };
  for (const line of IDLE.split("\n")) {
    const match = SEPARATOR.exec(line);
    if (match) { flush(); current = { observedAtMs: Date.parse(match[2]!), uptimeMs: Number(match[3]), lines: [] }; }
    else current?.lines.push(line);
  }
  flush();
  return out;
}
const SERIES = referenceSeries();
const LAST = SERIES[SERIES.length - 1]!;

function store(raw: RawSample, options: { generation?: string; pid?: number; bootId?: string } = {}): StoredCensusSample {
  const stored = buildStoredSample({ status: "ok", rows: raw.rows }, {
    gateway: { pid: options.pid ?? GATEWAY_PID, start_identity: "gateway-start-fixture", uid: AGENT_UID, generation: options.generation ?? GENERATION },
    ipv4Set: MESSAGING, observed_at: new Date(raw.observedAtMs).toISOString(), observed_uptime_ms: raw.uptimeMs, boot_id: options.bootId ?? BOOT,
  });
  if (stored.status !== "ok") throw new Error(stored.detail);
  return stored.sample;
}
const BOOT = (STATES.base.host as { bootId: string }).bootId;

/** Extend a parsed series with derived samples at CENSUS_PERIOD, advancing the qualifying socket's rx by `grow` bytes. */
function extend(series: RawSample[], count: number, grow: number, spacing = CENSUS_PERIOD): RawSample[] {
  const out = [...series];
  for (let i = 0; i < count; i++) {
    const prior = out[out.length - 1]!;
    out.push({
      observedAtMs: prior.observedAtMs + spacing, uptimeMs: prior.uptimeMs + spacing,
      rows: prior.rows.map(row => row.local === "192.0.2.1.64719" ? { ...row, rxbytes: row.rxbytes + grow } : row),
    });
  }
  return out;
}
const editRows = (series: RawSample[], edit: (row: CensusRow) => CensusRow): RawSample[] =>
  series.map(sample => ({ ...sample, rows: sample.rows.map(row => row.local === "192.0.2.1.64719" ? edit(row) : row) }));

/** Shift every base time so the reader clock sits at `nowMs` and `uptimeMs`, keeping each record's age. */
function inputAt(nowMs: number, uptimeMs: number, samples: StoredCensusSample[], config: Record<string, unknown> = {}, gateway: Record<string, unknown> = {}): LivenessInput {
  const base = STATES.base as unknown as { nowMs: number; host: { uptimeMs: number } };
  const dT = nowMs - base.nowMs;
  const dU = uptimeMs - base.host.uptimeMs;
  const shift = (value: unknown, key: string): unknown => {
    if (Array.isArray(value)) return value.map(item => shift(item, ""));
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, shift(v, k)]));
    }
    if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) return new Date(Date.parse(value) + dT).toISOString();
    if (typeof value === "number" && /uptime/i.test(key)) return value + dU;
    if (typeof value === "number" && (/_ms$/.test(key) || key === "nowMs") && Math.abs(value - base.nowMs) < 86_400_000) return value + dT;
    return value;
  };
  const input = shift(structuredClone(STATES.base), "") as Record<string, any>;
  input.nowMs = nowMs;
  input.host.uptimeMs = uptimeMs;
  input.observer.value.raw.census.samples = samples;
  input.config.value.poll_backoff_cap_s = FIXTURE_POLL_BACKOFF_CAP_S;
  Object.assign(input.config.value, config);
  Object.assign(input.observer.value.raw.gateway, gateway);
  return input as LivenessInput;
}
function evaluateSeries(series: RawSample[], options: { nowMs?: number; config?: Record<string, unknown>; gateway?: Record<string, unknown>; store?: Parameters<typeof store>[1] } = {}): LivenessEnvelope {
  const last = series[series.length - 1]!;
  const nowMs = options.nowMs ?? last.observedAtMs;
  const uptimeMs = last.uptimeMs + (nowMs - last.observedAtMs);
  return evaluateLiveness(inputAt(nowMs, uptimeMs, series.map(sample => store(sample, options.store)), options.config, options.gateway));
}
const expectWallOk = (envelope: LivenessEnvelope) => expect(envelope.wall.state.startsWith("wall_OK_"), envelope.wall.reasons.join(",")).toBe(true);

describe("reference-host idle series", () => {
  it("pins its inputs", () => {
    expect(SERIES).toHaveLength(6);
    expect(LAST.uptimeMs).toBe(1769976000);
    expect(new Date(LAST.observedAtMs).toISOString()).toBe("2026-11-09T04:59:24.000Z");
    expect(SERIES.slice(1).map((s, i) => s.uptimeMs - SERIES[i]!.uptimeMs)).toEqual(Array(5).fill(CENSUS_PERIOD));
    const stored = store(SERIES[0]!);
    expect(stored.rows).toEqual([{ local: "192.0.2.1.64719", foreign: "203.0.113.10.443", tcp_state: "ESTABLISHED", rxbytes: 49560, txbytes: 42247, gencnt: "0000000000968d6d" }]);
    expect(stored.other_rows).toBe(3);
  });

  it("reads agent_OK_PASSIVE at sample 6", () => {
    const envelope = evaluateSeries(SERIES);
    expect(envelope.agent.state).toBe("agent_OK_PASSIVE");
    expect(envelope.agent.reasons).toEqual(["none"]);
    expect(envelope.agent.evidence.census_run_age_ms).toBe(0);
    expectWallOk(envelope);
    expect(envelope.exit_code).toBe(0);
  });

  it("keeps the reader-time bound: OK at exactly AGENT_WINDOW after one healthy run, DOWN one second later", () => {
    const flat = extend(SERIES, 6, 0);
    const window = agentWindow(FIXTURE_POLL_BACKOFF_CAP_S * SECOND);
    expect(evaluateSeries(flat, { nowMs: LAST.observedAtMs + window }).agent.state).toBe("agent_OK_PASSIVE");
    const stale = evaluateSeries(flat, { nowMs: LAST.observedAtMs + window + SECOND });
    expect(stale.agent.state).toBe("agent_DOWN");
    expect(stale.agent.reasons).toEqual(["agent_flow_stale"]);
    expectWallOk(stale);
  });
});

describe("never qualifying", () => {
  const long = extend(SERIES, 2, 0);
  it("derives the long series from parsed samples so its earliest sample is beyond AGENT_WINDOW", () => {
    const span = long[long.length - 1]!.observedAtMs - long[0]!.observedAtMs;
    expect(long.length).toBeGreaterThanOrEqual(8);
    expect(span).toBeGreaterThan(AGENT_WINDOW_BASE);
  });

  const cases: Array<[string, (s: RawSample[]) => RawSample[], Parameters<typeof evaluateSeries>[1]?]> = [
    ["flat counters", s => editRows(s, row => ({ ...row, rxbytes: 49560 }))],
    ["wrong pid", s => s, { store: { pid: 75400 }, gateway: { pid: 75400 } }],
    ["address outside the set", s => editRows(s, row => ({ ...row, foreign: "198.51.100.10.443", foreignEndpoint: { ...row.foreignEndpoint, host: "198.51.100.10", ipv4: 3325256714 } }))],
    ["port other than 443", s => editRows(s, row => ({ ...row, foreign: "203.0.113.10.8443", foreignEndpoint: { ...row.foreignEndpoint, port: "8443", portNumber: 8443 } }))],
    ["CLOSE_WAIT", s => editRows(s, row => ({ ...row, tcp_state: "CLOSE_WAIT" }))],
    ["an IPv6 row inside a commissioned IPv6 prefix", s => editRows(s, row => ({ ...row, foreign: "2001:db8::10.443", foreignEndpoint: { host: "2001:db8::10", port: "443", ipv6: true, ipv4: null, portNumber: 443 } })),
      { config: { messaging: { ipv4: [{ prefix: "203.0.113.0/24", source: "fixture" }], ipv6: [{ prefix: "2001:db8::/32", source: "fixture" }] } } }],
  ];
  it.each(cases)("%s: the six-sample series reads agent_INITIALIZING and the long series agent_DOWN", (_name, edit, options) => {
    const short = evaluateSeries(edit(SERIES), options);
    expect(short.agent.state).toBe("agent_INITIALIZING");
    const down = evaluateSeries(edit(long), options);
    expect(down.agent.state).toBe("agent_DOWN");
    expect(down.agent.reasons).toContain("agent_flow_stale");
    expectWallOk(down);
  });

  it("a wrong generation is never credited", () => {
    const envelope = evaluateSeries(SERIES, { store: { generation: "generation-fixture-0" } });
    expect(envelope.agent.state).toBe("agent_DOWN");
    expect(envelope.agent.reasons).toEqual(["agent_flow_stale"]);
  });

  it("a sample from another boot is never credited", () => {
    expect(evaluateSeries(SERIES, { store: { bootId: "boot-fixture-previous" } }).agent.state).not.toBe("agent_OK_PASSIVE");
  });
});

describe("rotation and spacing", () => {
  /** A rotated identity is a new socket: a new local port and a new gencnt. */
  const rotate = (sample: RawSample, rx: number): RawSample => ({
    ...sample, rows: sample.rows.map(row => row.local === "192.0.2.1.64719" || row.local === "192.0.2.1.64720" ? { ...row, local: "192.0.2.1.64720", gencnt: "0000000000968e00", rxbytes: rx } : row),
  });

  it("one rotation at the worst phase stays OK at every reader time", () => {
    const spaced = extend(SERIES.slice(0, 1), CENSUS_RUN, 1000, CENSUS_PAIR_MAX);
    const rotated = extend(spaced, CENSUS_RUN + 1, 0, CENSUS_PAIR_MAX).map((sample, index) => index > CENSUS_RUN ? rotate(sample, 1000 * index) : sample);
    const lastOld = rotated[CENSUS_RUN]!;
    const end = rotated[rotated.length - 1]!;
    expect((CENSUS_RUN + 1) * CENSUS_PAIR_MAX).toBeLessThanOrEqual(agentWindow(0));
    for (let t = lastOld.observedAtMs; t <= end.observedAtMs; t += SECOND) {
      const visible = rotated.filter(sample => sample.observedAtMs <= t);
      expect(evaluateSeries(visible, { nowMs: t }).agent.state, `t=${t - lastOld.observedAtMs}`).toBe("agent_OK_PASSIVE");
    }
  });

  it("a rotation every 30 s never forms a run and reads DOWN", () => {
    const base = extend(SERIES, 4, 500);
    const churned = base.map((sample, index) => ({
      ...sample,
      rows: sample.rows.map(row => row.local === "192.0.2.1.64719"
        ? { ...row, local: `192.0.2.1.${65000 + Math.floor(index / 2)}`, gencnt: (0x968d6d + Math.floor(index / 2)).toString(16) }
        : row),
    }));
    const envelope = evaluateSeries(churned);
    expect(envelope.agent.state).toBe("agent_DOWN");
    expect(envelope.agent.reasons).toEqual(["agent_flow_stale"]);
  });

  it("a pair spaced under CENSUS_PAIR_MIN breaks the run", () => {
    const tight = SERIES.map((sample, index) => index >= 3 ? { ...sample, observedAtMs: sample.observedAtMs - (CENSUS_PERIOD - CENSUS_PAIR_MIN + SECOND), uptimeMs: sample.uptimeMs - (CENSUS_PERIOD - CENSUS_PAIR_MIN + SECOND) } : sample);
    expect(tight[3]!.uptimeMs - tight[2]!.uptimeMs).toBeLessThan(CENSUS_PAIR_MIN);
    expect(evaluateSeries(tight).agent.state).toBe("agent_INITIALIZING");
  });

  it("a dead updater: a flat polling socket while send responses grow on other connections in alternating pairs reads DOWN", () => {
    const flat = editRows(extend(SERIES.slice(0, 1), 8, 0), row => row);
    const withSends = flat.map((sample, index) => {
      const template = sample.rows.find(row => row.local === "192.0.2.1.64719")!;
      // The send growth alternates between two connections, so every pair grows somewhere but no one identity grows in consecutive pairs.
      const a = { ...template, local: "192.0.2.1.64800", gencnt: "0000000000970001", rxbytes: 1000 + 500 * Math.ceil(index / 2) };
      const b = { ...template, local: "192.0.2.1.64801", gencnt: "0000000000970002", rxbytes: 1000 + 500 * Math.floor(index / 2) };
      return { ...sample, rows: [...sample.rows, a, b] };
    });
    for (let i = 1; i < withSends.length; i++) {
      const grew = withSends[i]!.rows.filter((row, r) => row.rxbytes > withSends[i - 1]!.rows[r]!.rxbytes);
      expect(grew.length, `pair ${i}`).toBe(1);
    }
    const down = evaluateSeries(withSends);
    expect(down.agent.state).toBe("agent_DOWN");
    expect(down.agent.reasons).toEqual(["agent_flow_stale"]);
    const short = evaluateSeries(withSends.slice(0, 6));
    expect(short.agent.state).toBe("agent_INITIALIZING");
  });
});

describe("census availability and commissioning", () => {
  it("census_unavailable on a commissioned host is agent DOWN and leaves the wall unchanged", () => {
    const input = inputAt(LAST.observedAtMs, LAST.uptimeMs, SERIES.map(sample => store(sample)));
    (input.observer as any).value.raw.census.status = "unavailable";
    const envelope = evaluateLiveness(input);
    expect(envelope.agent.state).toBe("agent_DOWN");
    expect(envelope.agent.reasons).toContain("census_unavailable");
    expectWallOk(envelope);
  });

  it("census_unavailable on an uncommissioned host is agent UNMONITORED and leaves the wall unchanged", () => {
    const input = inputAt(LAST.observedAtMs, LAST.uptimeMs, SERIES.map(sample => store(sample)), { commissioning: { wall: true, agent: false, alert_drill: true } });
    (input.observer as any).value.raw.census.status = "unavailable";
    const envelope = evaluateLiveness(input);
    expect(envelope.agent.state).toBe("agent_UNMONITORED");
    expectWallOk(envelope);
  });

  it("gate_proxied egress on a commissioned host is agent DOWN census_unavailable", () => {
    const envelope = evaluateSeries(SERIES, { config: { gateway_egress: "gate_proxied" } });
    expect(envelope.agent.state).toBe("agent_DOWN");
    expect(envelope.agent.reasons).toContain("census_unavailable");
    expect(envelope.agent.reasons).not.toContain("commissioning_unproven");
    expectWallOk(envelope);
  });

  it("http_version 2 is both commissioning_unproven and census_unavailable, labelled agent_UNMONITORED", () => {
    const ptb = { version: "22.6", timeout_s: 10, poll_interval_s: 0, separate_get_updates_request: true, http_version: "2", hermes_read_timeout_s: 20 };
    const envelope = evaluateSeries(SERIES, { config: { ptb } });
    expect(envelope.agent.reasons).toEqual(expect.arrayContaining(["commissioning_unproven", "census_unavailable"]));
    expect(envelope.agent.state).toBe("agent_UNMONITORED");
    expectWallOk(envelope);
  });

  it("a generation that began less than AGENT_WINDOW ago with no qualifying run is INITIALIZING, and DOWN after", () => {
    const early = SERIES.slice(0, 2);
    expect(evaluateSeries(early).agent.state).toBe("agent_INITIALIZING");
    const window = agentWindow(0);
    const atWindow = evaluateSeries(early, { nowMs: SERIES[0]!.observedAtMs + window });
    expect(atWindow.agent.reasons).toContain("initializing");
    const later = evaluateSeries(early, { nowMs: SERIES[0]!.observedAtMs + window + SECOND });
    expect(later.agent.state).toBe("agent_DOWN");
    expect(later.agent.reasons).toContain("agent_flow_stale");
  });

  it("with no stored sample of the current generation, a young daemon instance reads initializing and an old one agent_flow_stale", () => {
    const old = evaluateLiveness(inputAt(LAST.observedAtMs, LAST.uptimeMs, []));
    expect(old.agent.reasons).toEqual(["agent_flow_stale"]);
    const youngInput = inputAt(LAST.observedAtMs, LAST.uptimeMs, []);
    (youngInput.daemon as any).value.instance_started_uptime_ms = LAST.uptimeMs - 30 * SECOND;
    expect(evaluateLiveness(youngInput).agent.state).toBe("agent_INITIALIZING");
  });

  it("an absent observer record is agent DOWN observer_missing", () => {
    const input = inputAt(LAST.observedAtMs, LAST.uptimeMs, SERIES.map(sample => store(sample)));
    const envelope = evaluateLiveness({ ...input, observer: { status: "absent" } });
    expect(envelope.agent.state).toBe("agent_DOWN");
    expect(envelope.agent.reasons).toEqual(["observer_missing"]);
  });
});
