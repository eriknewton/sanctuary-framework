/**
 * The census sampler: its own fixed-rate CENSUS_PERIOD timer inside the
 * observer process, single-flight, feeding one retained series owner that the
 * observer publishes as it stands at the end of each observer cycle.
 */
import {
  AGENT_WINDOW_MAX,
  CENSUS_INPUT_ROWS,
  CENSUS_PAIR_MAX,
  CENSUS_PAIR_MIN,
  CENSUS_PERIOD,
  CENSUS_RUN,
  CENSUS_SAMPLES_MAX,
  COUNTER_MAX,
} from "./constants.js";
import { buildStoredSample, parseCensus, type CensusGatewayIdentity, type Ipv4Prefix, type StoredCensusSample } from "./census.js";

/**
 * The one owner of the retained series. Its only mutators are `append` and
 * `reset`, so the sampler and the observer cannot disagree about retention.
 */
export class CensusSeries {
  private samples: StoredCensusSample[] = [];

  /** Append one sample under the retention rule. */
  append(sample: StoredCensusSample): void {
    const last = this.samples[this.samples.length - 1];
    // A boot or gateway generation change drops every retained sample, so no run can span two processes or two boots.
    if (last !== undefined && (last.boot_id !== sample.boot_id || last.gateway.generation !== sample.gateway.generation)) this.samples = [];
    // At the cap drop exactly the oldest: (CENSUS_SAMPLES_MAX - 1) * CENSUS_PAIR_MIN exceeds AGENT_WINDOW_MAX + CENSUS_RUN * CENSUS_PAIR_MAX,
    // so a full series already reaches past any agent window and a dead updater reads agent_flow_stale, never initializing.
    if (this.samples.length >= CENSUS_SAMPLES_MAX) this.samples.shift();
    this.samples.push(sample);
  }

  reset(): void {
    this.samples = [];
  }

  /** A copy of the retained series, oldest first. */
  snapshot(): StoredCensusSample[] {
    return this.samples.slice();
  }

  get length(): number {
    return this.samples.length;
  }
}

/** The retention span inequality the eviction relies on; asserted by the constants witness. */
export const CENSUS_RETENTION_SPAN_HOLDS = (CENSUS_SAMPLES_MAX - 1) * CENSUS_PAIR_MIN > AGENT_WINDOW_MAX + CENSUS_RUN * CENSUS_PAIR_MAX;

/** One bounded `netstat` child result from the runner. */
export type CensusChildResult = { status: "ok"; stdout: string } | { status: "failed" };

/** What the sampler needs from the observer's latest cycle; null fields fail the attempt. */
export interface CensusSamplingContext {
  gateway: CensusGatewayIdentity | null;
  gatewayAlive: boolean;
  ipv4Set: readonly Ipv4Prefix[] | null;
  bootId: string | null;
}

/** True when two sampling contexts name the same boot and the same full gateway identity (pid, start, uid, generation). */
export function sameSamplingIdentity(a: CensusSamplingContext, b: CensusSamplingContext): boolean {
  if (a.bootId !== b.bootId) return false;
  if (a.gateway === null || b.gateway === null) return a.gateway === b.gateway;
  return a.gateway.pid === b.gateway.pid && a.gateway.start_identity === b.gateway.start_identity &&
    a.gateway.uid === b.gateway.uid && a.gateway.generation === b.gateway.generation;
}

export interface SamplerTimers {
  setInterval(fire: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
}

export interface CensusSamplerDeps {
  series: CensusSeries;
  runNetstat: () => Promise<CensusChildResult>;
  context: () => CensusSamplingContext;
  clock: { nowMs(): number; uptimeMs(): number };
  timers: SamplerTimers;
}

export type SamplerState = "sampler_IDLE" | "sampler_SAMPLING" | "sampler_STOPPED";

/** Fixed-rate sampler; a tick while a read is in flight is skipped and counted, never queued. */
export class CensusSampler {
  private state: SamplerState = "sampler_IDLE";
  private handle: unknown = null;
  private inFlight: Promise<void> | null = null;
  private skipped = 0;
  private attempts = 0;
  private lastOk = false;
  private lastRowVisits = 0;

  constructor(private readonly deps: CensusSamplerDeps) {
    for (const key of ["series", "runNetstat", "context", "clock", "timers"] as const) {
      if (deps[key] === undefined || deps[key] === null) throw new Error(`census sampler requires ${key}`);
    }
  }

  /** Start the CENSUS_PERIOD timer; the period is owned here, never taken from the observer cycle. */
  start(): void {
    if (this.handle !== null || this.state === "sampler_STOPPED") return;
    this.handle = this.deps.timers.setInterval(() => { void this.tick(); }, CENSUS_PERIOD);
  }

  stop(): void {
    if (this.handle !== null) this.deps.timers.clearInterval(this.handle);
    this.handle = null;
    this.state = "sampler_STOPPED";
  }

  /** The in-flight attempt, if any, so shutdown can await it. */
  pending(): Promise<void> | null {
    return this.inFlight;
  }

  tick(): Promise<void> {
    if (this.state === "sampler_STOPPED") return Promise.resolve();
    if (this.inFlight !== null) {
      this.skipped = Math.min(COUNTER_MAX, this.skipped + 1);
      return this.inFlight;
    }
    this.state = "sampler_SAMPLING";
    this.inFlight = this.attempt().finally(() => {
      this.inFlight = null;
      if (this.state === "sampler_SAMPLING") this.state = "sampler_IDLE";
    });
    return this.inFlight;
  }

  /** True when the latest completed attempt appended a sample. */
  latestAttemptOk(): boolean {
    return this.lastOk;
  }

  stats(): { skipped: number; attempts: number; lastRowVisits: number } {
    return { skipped: this.skipped, attempts: this.attempts, lastRowVisits: this.lastRowVisits };
  }

  /** Test hook: start the skip counter near its cap. */
  primeSkippedForTest(value: number): void {
    this.skipped = Math.min(COUNTER_MAX, value);
  }

  private async attempt(): Promise<void> {
    this.attempts = Math.min(COUNTER_MAX, this.attempts + 1);
    this.lastRowVisits = 0;
    // The boot and gateway identity are fixed before the read starts. A read is credited only to the generation it was
    // taken under: if either changed while netstat ran (including a new start of the same pid), the attempt is refused,
    // because the output may describe the earlier process.
    const started = this.deps.context();
    let result: CensusChildResult;
    try { result = await this.deps.runNetstat(); }
    catch { result = { status: "failed" }; }
    const context = this.deps.context();
    if (!sameSamplingIdentity(started, context)) {
      this.lastOk = false;
      return;
    }
    // A failed attempt appends nothing; the retained same-generation samples stay because the evaluator's spacing refuses a gap.
    if (result.status !== "ok" || context.gateway === null || !context.gatewayAlive || context.ipv4Set === null || context.bootId === null) {
      this.lastOk = false;
      return;
    }
    const lines = result.stdout.split("\n").length;
    this.lastRowVisits = Math.min(lines, CENSUS_INPUT_ROWS + 1);
    const parsed = parseCensus(result.stdout, { gatewayPid: context.gateway.pid });
    const observed_uptime_ms = this.deps.clock.uptimeMs();
    const built = buildStoredSample(parsed, {
      gateway: context.gateway,
      ipv4Set: context.ipv4Set,
      observed_at: new Date(this.deps.clock.nowMs()).toISOString(),
      observed_uptime_ms,
      boot_id: context.bootId,
    });
    if (built.status !== "ok") { this.lastOk = false; return; }
    this.deps.series.append(built.sample);
    this.lastRowVisits += this.deps.series.snapshot().reduce((sum, sample) => sum + sample.rows.length, 0);
    this.lastOk = true;
  }
}
