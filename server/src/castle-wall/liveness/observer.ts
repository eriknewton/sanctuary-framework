/**
 * The user-session liveness observer: one fixed-rate OBSERVER_PERIOD cycle,
 * single-flight, that collects through injected collectors under
 * COLLECT_DEADLINE, evaluates its candidate record with the shared evaluator,
 * tracks recovery and the canary allow sighting, and hands the record to the
 * single-flight publisher. It reads no credential and writes only
 * `observer.json` through the publisher.
 */
import { createHash, randomBytes } from "node:crypto";
import {
  COLLECT_DEADLINE,
  COUNTER_MAX,
  EVIDENCE_FAILURES_MAX,
  HISTORY_WINDOW,
  IPC_DEADLINE,
  LIVENESS_SCHEMA_VERSION,
  OBSERVER_PERIOD,
  RECOVERY_GAP,
  RECOVERY_SAMPLES_PER_COMPONENT,
} from "./constants.js";
import type { CensusSampler, CensusSeries, CensusSamplingContext } from "./census-sampler.js";
import { checkCanaryIntegrity, type CanaryIntegrityFacts } from "./canary-integrity.js";
import { evaluateLiveness, type HostClock, type LivenessEnvelope, type RecordRead } from "./evaluate.js";
import { checkMcpStaleChild, selectGateway, stableStartIdentity, type GatewayIdentity, type ProcessRow } from "./process-census.js";
import type { LivenessReadResult } from "./read-status.js";
import {
  parseConfigRecord,
  parseDaemonRecord,
  parseObserverRecord,
  type ComponentRecovery,
  type EvidenceFailure,
  type LivenessComponent,
  type LivenessConfig,
  type ObserverAgentPart,
  type ObserverWallPart,
  type RetainedCanaryAllowSighting,
} from "./schema.js";

// ---------------------------------------------------------------------------
// Injected surfaces.
// ---------------------------------------------------------------------------
/** The enforcement availability as the daemon resolved it. */
export type AvailabilityStatus = "live" | "non_green" | "undetermined";

/** Every collector the cycle uses; each is required, and each may reject to signal a failure. */
export interface ObserverCollectors {
  /** The three records through the shared reader (this observer's own record seeds the allow sighting once). */
  readRecords(): Promise<LivenessReadResult>;
  /** `kern.bootsessionuuid`; a reject is an evidence failure, never a boot change. */
  readBootId(): Promise<string>;
  queryAvailability(): Promise<AvailabilityStatus>;
  /** `launchctl print gui/<uid>/<FULL_AGENT_LABEL>` through the bounded runner and `parseFullAgentPrint`. */
  printFullAgent(): Promise<{ loaded: boolean; pid: number | null }>;
  /** The full agent's crash state; null when no state file exists. */
  readFullAgentState(): Promise<{ latched: boolean; charges_ms: readonly number[] } | null>;
  /** Two process reads CENSUS_REREAD apart. */
  readProcesses(): Promise<[ProcessRow[], ProcessRow[]]>;
  /** `launchctl print system/<harness label>`; the harness pid or null. */
  printHarness(label: string): Promise<number | null>;
  /** The canary integrity facts for one agent uid. */
  collectCanaryFacts(agentUid: number): Promise<Omit<CanaryIntegrityFacts, "agentUid">>;
}

export interface ObserverClock { nowMs(): number; uptimeMs(): number }
export interface ObserverTimers {
  setInterval(fire: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
  setTimeout(fire: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}
export interface ObserverPublisher { publish(record: unknown): Promise<void> }

export interface LivenessObserverDeps {
  fortressId: string;
  hostId: string;
  operatorUid: number;
  collectors: ObserverCollectors;
  sampler: CensusSampler;
  series: CensusSeries;
  publisher: ObserverPublisher;
  clock: ObserverClock;
  timers: ObserverTimers;
  /** A fixed instance label for tests; production draws a random one per process start. */
  instance?: string;
}

/** Bytes of randomness in an instance label: 16 bytes is 32 hex characters, inside LABEL_BYTES with the prefix. */
const INSTANCE_RANDOM_BYTES = 16;
/** 16 hex digits retain 64 digest bits for an informational host label without publishing the hostname. */
const HOST_ID_HEX_DIGITS = 16;

/** The informational host id, derived the way the daemon writes it. */
export function observerHostId(hostname: string): string {
  // Must match host_id in createLivenessRecorder in server/src/castle-wall/runtime/macos-daemon.ts; both consumers use this derivation.
  return `host-${createHash("sha256").update(hostname).digest("hex").slice(0, HOST_ID_HEX_DIGITS)}`;
}

// ---------------------------------------------------------------------------
// Evidence failures.
// ---------------------------------------------------------------------------
/** Slots held back so each component can always carry one saturation entry. */
const SATURATION_RESERVE = 2;

/** Deduplicated, bounded evidence failures; overflow saturates into one observation_invalid per component. */
export class EvidenceFailureSet {
  private readonly entries: EvidenceFailure[] = [];
  private readonly saturated = new Set<LivenessComponent>();

  add(component: LivenessComponent, reason: string): void {
    if (this.entries.some(entry => entry.component === component && entry.reason === reason)) return;
    if (this.entries.length < EVIDENCE_FAILURES_MAX - SATURATION_RESERVE) this.entries.push({ component, reason });
    else this.saturated.add(component);
  }

  list(): EvidenceFailure[] {
    const out = this.entries.slice();
    for (const component of ["wall", "agent"] as const) {
      if (this.saturated.has(component) && !out.some(entry => entry.component === component && entry.reason === "observation_invalid")) {
        out.push({ component, reason: "observation_invalid" });
      }
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Clean predicate and recovery.
// ---------------------------------------------------------------------------
const sameSet = (reasons: readonly string[], one: string): boolean => reasons.length === 1 && reasons[0] === one;

/** Recovery is earned only by cycles the shared evaluator found clean, so the observer cannot grant health the evaluator would refuse. */
export function wallCycleClean(envelope: LivenessEnvelope): boolean {
  return sameSet(envelope.wall.reasons, "none") || sameSet(envelope.wall.reasons, "recovering");
}
/** Agent absence is not an agent fault, so `agent_unmonitored` alone is clean too. */
export function agentCycleClean(envelope: LivenessEnvelope): boolean {
  const r = envelope.agent.reasons;
  return sameSet(r, "none") || sameSet(r, "recovering") || sameSet(r, "agent_unmonitored");
}

function emptyRecovery(): ComponentRecovery {
  return { samples: [], fault_uptime_ms: null };
}

/** Apply one cycle to a component's recovery state. */
export function advanceRecovery(state: ComponentRecovery, clean: boolean, sample: { sequence: number; observed_uptime_ms: number }): ComponentRecovery {
  if (!clean) return { samples: [], fault_uptime_ms: sample.observed_uptime_ms };
  const samples = state.samples.slice();
  if (samples.length === 0) samples.push(sample);
  else if (samples.length === 1) { if (sample.observed_uptime_ms - samples[0]!.observed_uptime_ms >= RECOVERY_GAP) samples.push(sample); }
  // With two samples the first stays and the second advances, so the pair spans the clean run.
  else samples[RECOVERY_SAMPLES_PER_COMPONENT - 1] = sample;
  return { samples: samples.slice(0, RECOVERY_SAMPLES_PER_COMPONENT), fault_uptime_ms: state.fault_uptime_ms };
}

// ---------------------------------------------------------------------------
// Allow-sighting retention time.
// ---------------------------------------------------------------------------
/**
 * The capture time the observer retains for an allow sighting. A sighting
 * stamped after this cycle's observation time is retained as seen now: keeping
 * the future stamp would never age out under HISTORY_WINDOW, and dropping it
 * would clear a fault, so the stamp is clamped and the fault ages from now.
 */
export function retainedCaptureTime(capturedAtMs: number, observedAtMs: number): number {
  return Math.min(capturedAtMs, observedAtMs);
}

// ---------------------------------------------------------------------------
// Instance-start seed read.
// ---------------------------------------------------------------------------
/**
 * This observer's own record as one completed read, or null when the read did not complete. Only a read that reached a
 * verdict resolves the start: absent (no file, or no liveness directory), present, or unparsable bytes. A deadline, or a
 * custody refusal of the file or its directory, says nothing about what the file holds, so it is never proof that no
 * seed exists and the instance keeps withholding its own record rather than replacing one it could not read.
 */
export function resolvedSeedRead(read: LivenessReadResult): RecordRead | null {
  if (read.readDeadlineHit || read.directory.status === "custody_invalid") return null;
  if (read.directory.status === "absent") return { status: "absent" };
  return read.observer.status === "custody_invalid" ? null : read.observer;
}

// ---------------------------------------------------------------------------
// Observer.
// ---------------------------------------------------------------------------
export type ObserverState = "observer_IDLE" | "observer_COLLECTING" | "observer_EVALUATING" | "observer_PUBLISHING" | "observer_STOPPING";

type Settled<T> = { ok: true; value: T } | { ok: false };
const FAILED: Settled<never> = Object.freeze({ ok: false }) as Settled<never>;

const REQUIRED_DEPS = ["fortressId", "hostId", "operatorUid", "collectors", "sampler", "series", "publisher", "clock", "timers"] as const;
const REQUIRED_COLLECTORS = [
  "readRecords", "readBootId", "queryAvailability", "printFullAgent", "readFullAgentState", "readProcesses", "printHarness", "collectCanaryFacts",
] as const;

export class LivenessObserver {
  readonly instance: string;
  private state: ObserverState = "observer_IDLE";
  private handle: unknown = null;
  private inFlight: Promise<void> | null = null;
  private lastPublish: Promise<void> | null = null;
  /**
   * The publisher drain in flight and the one handled continuation subscribed to it. A cycle whose publish returns the
   * same drain reuses it, so a stalled drain retains one continuation however many cycles complete behind it.
   */
  private publishing: { drain: Promise<void>; handled: Promise<void> } | null = null;
  private skipped = 0;
  private sequence = 0;
  private completedCycles = 0;
  private publishFailures = 0;
  private bootId: string | null = null;
  private wallRecovery = emptyRecovery();
  private agentRecovery = emptyRecovery();
  private sighting: RetainedCanaryAllowSighting | null = null;
  /**
   * True until this instance has resolved its start: a validated boot read AND a completed read of its own record
   * file. Until then the instance publishes nothing, because its record would replace a predecessor's record that may
   * carry the only durable copy of an allow sighting.
   */
  private seedPending = true;
  private withheldCycles = 0;
  private priorGateway: GatewayIdentity | null = null;
  private censusContext: CensusSamplingContext = { gateway: null, gatewayAlive: false, ipv4Set: null, bootId: null };
  private lastRecord: Record<string, unknown> | null = null;

  constructor(private readonly deps: LivenessObserverDeps) {
    // The production composition passes every collector, the sampler, the publisher and the clock; a missing one fails here, never silently.
    for (const key of REQUIRED_DEPS) if (deps[key] === undefined || deps[key] === null) throw new Error(`liveness observer requires ${key}`);
    for (const key of REQUIRED_COLLECTORS) if (typeof deps.collectors[key] !== "function") throw new Error(`liveness observer requires collector ${key}`);
    this.instance = deps.instance ?? `observer-${randomBytes(INSTANCE_RANDOM_BYTES).toString("hex")}`;
  }

  /** The sampler reads the gateway and boot of the latest observer cycle. */
  samplingContext(): CensusSamplingContext {
    return this.censusContext;
  }

  /** The last positively read boot identity; null until a boot read has validated. A failed read never clears it. */
  validatedBootId(): string | null {
    return this.bootId;
  }

  start(): void {
    if (this.handle !== null || this.state === "observer_STOPPING") return;
    this.deps.sampler.start();
    this.handle = this.deps.timers.setInterval(() => { void this.tick(); }, OBSERVER_PERIOD);
    void this.tick();
  }

  /** One timer tick: a tick during an in-flight cycle is skipped and counted, never queued. */
  tick(): Promise<void> {
    if (this.state === "observer_STOPPING") return Promise.resolve();
    if (this.inFlight !== null) {
      this.skipped = Math.min(COUNTER_MAX, this.skipped + 1);
      return this.inFlight;
    }
    this.inFlight = this.runCycle().finally(() => {
      this.inFlight = null;
      if (this.state !== "observer_STOPPING") this.state = "observer_IDLE";
    });
    return this.inFlight;
  }

  /** Stop timers, wait for the in-flight cycle and publish up to COLLECT_DEADLINE, and stop the sampler. */
  async stop(): Promise<void> {
    this.state = "observer_STOPPING";
    if (this.handle !== null) this.deps.timers.clearInterval(this.handle);
    this.handle = null;
    this.deps.sampler.stop();
    const waits = [this.inFlight, this.lastPublish, this.deps.sampler.pending()].filter((p): p is Promise<void> => p !== null);
    if (waits.length === 0) return;
    await this.race(Promise.allSettled(waits).then(() => undefined), COLLECT_DEADLINE, undefined);
  }

  stats(): { state: ObserverState; skipped: number; cycles: number; sequence: number; publishFailures: number; withheldCycles: number; startResolved: boolean } {
    return {
      state: this.state, skipped: this.skipped, cycles: this.completedCycles, sequence: this.sequence, publishFailures: this.publishFailures,
      withheldCycles: this.withheldCycles, startResolved: !this.seedPending,
    };
  }

  /** The most recently assembled record, for tests and diagnostics. */
  latestRecord(): Record<string, unknown> | null {
    return this.lastRecord;
  }

  /** Test hook: start the skip counter near its cap. */
  primeSkippedForTest(value: number): void {
    this.skipped = Math.min(COUNTER_MAX, value);
  }

  private race<T>(operation: Promise<T>, ms: number, fallback: T): Promise<T> {
    return new Promise<T>(resolve => {
      let done = false;
      const handle = this.deps.timers.setTimeout(() => { if (!done) { done = true; resolve(fallback); } }, ms);
      operation.then(
        value => { if (!done) { done = true; this.deps.timers.clearTimeout(handle); resolve(value); } },
        () => { if (!done) { done = true; this.deps.timers.clearTimeout(handle); resolve(fallback); } },
      );
    });
  }

  /** Availability under IPC_DEADLINE; a late resolution after the deadline never changes the published value. */
  private availability(): Promise<ObserverWallPart["availability"]> {
    const unresponsive: ObserverWallPart["availability"] = { status: "unresponsive", resolved_at_ms: null };
    const mapped = this.deps.collectors.queryAvailability().then(status => ({
      status: status === "live" ? "live" as const : "not_live" as const,
      resolved_at_ms: this.deps.clock.nowMs(),
    }));
    return this.race(mapped, IPC_DEADLINE, unresponsive);
  }

  private async runCycle(): Promise<void> {
    const { collectors, clock } = this.deps;
    // observer_COLLECTING: every collector races one cycle deadline, and a late result is discarded.
    this.state = "observer_COLLECTING";
    const startedAt = clock.nowMs();
    let expire: () => void = () => undefined;
    const deadline = new Promise<Settled<never>>(resolve => { expire = () => resolve(FAILED); });
    const deadlineHandle = this.deps.timers.setTimeout(() => expire(), COLLECT_DEADLINE);
    const within = <T>(start: () => Promise<T>): Promise<Settled<T>> => {
      let operation: Promise<T>;
      try { operation = start(); } catch { return Promise.resolve(FAILED); }
      return Promise.race([operation.then(value => ({ ok: true as const, value }), () => FAILED), deadline]);
    };
    const recordsP = within(() => collectors.readRecords());
    const bootP = within(() => collectors.readBootId());
    const availabilityP = within(() => this.availability());
    const printP = within(() => collectors.printFullAgent());
    const stateP = within(() => collectors.readFullAgentState());
    const processP = within(() => collectors.readProcesses());
    const records = await recordsP;
    const configRead: RecordRead = records.ok ? records.value.config : { status: "absent" };
    const parsedConfig = configRead.status === "present" ? parseConfigRecord(configRead.value) : null;
    const config: LivenessConfig | null = parsedConfig !== null && parsedConfig.ok ? parsedConfig.value : null;
    const agentUid = config?.agent_uid;
    const factsP = agentUid !== undefined ? within(() => collectors.collectCanaryFacts(agentUid)) : Promise.resolve(null);
    const mcpConfig = config?.mcp;
    const harnessP = agentUid !== undefined && mcpConfig ? within(() => collectors.printHarness(mcpConfig.harness_label)) : Promise.resolve(null);
    const [boot, availability, print, fullState, processes, facts, harness] =
      await Promise.all([bootP, availabilityP, printP, stateP, processP, factsP, harnessP]);
    this.deps.timers.clearTimeout(deadlineHandle);
    const endedAt = clock.nowMs();
    const uptimeMs = clock.uptimeMs();

    // observer_EVALUATING.
    this.state = "observer_EVALUATING";
    const failures = new EvidenceFailureSet();
    const agentKnown = agentUid !== undefined;
    const agentFailure = (reason: string): void => { if (agentKnown) failures.add("agent", reason); };
    if (!records.ok || records.value.readDeadlineHit) failures.add("wall", "observation_invalid");

    // A failed boot read is failed evidence for this cycle, never proof of a boot change: it runs no boot-change reset and
    // keeps the last validated boot and the retained sighting. Both components carry time_untrusted, and the cycle is
    // faulted by the ordinary recovery rule below; only a positively read different boot resets.
    const bootId = boot.ok && boot.value.length > 0 ? boot.value : null;
    if (bootId === null) { failures.add("wall", "time_untrusted"); failures.add("agent", "time_untrusted"); }
    else if (this.bootId !== null && bootId !== this.bootId) this.resetForBoot();
    if (bootId !== null) this.bootId = bootId;
    // The record names the last validated boot even when this cycle's read failed, so a restarted observer can still
    // seed a sighting it carries; retaining the identity does not make this cycle's clock read trusted.
    const recordBootId = bootId ?? this.bootId;

    // The instance-start seed: this observer's own current-boot record can only add a retained allow sighting. A seed
    // read that did not complete is never proof that no seed exists, so the start stays unresolved and nothing publishes.
    let withhold = false;
    if (this.seedPending) {
      const seedRead = records.ok ? resolvedSeedRead(records.value) : null;
      if (bootId !== null && seedRead !== null) {
        this.applySeed(seedRead, bootId, endedAt);
        this.seedPending = false;
      } else {
        withhold = true;
      }
    }

    // Daemon reference and allow-sighting retention.
    let daemonRef: ObserverWallPart["daemon_ref"] = null;
    if (records.ok && records.value.daemon.status === "present" && bootId !== null) {
      const parsed = parseDaemonRecord(records.value.daemon.value);
      if (parsed.ok && parsed.value.boot_id === bootId) {
        daemonRef = { daemon_instance: parsed.value.daemon_instance, sequence: parsed.value.sequence };
        const seen = parsed.value.raw.canary.last_destination_allowed;
        // An allow on the canary tuple is a wall fault that must outlive the daemon instance that saw it, so the newest sighting is kept across instances.
        if (seen !== null && (seen.principal === "agent" || seen.principal === "gate") &&
            (this.sighting === null || seen.captured_at_ms > this.sighting.captured_at_ms)) {
          this.sighting = { captured_at_ms: retainedCaptureTime(seen.captured_at_ms, endedAt), principal: seen.principal, daemon_instance: parsed.value.daemon_instance };
        }
      }
    }
    if (this.sighting !== null && endedAt - this.sighting.captured_at_ms > HISTORY_WINDOW) this.sighting = null;

    if (!availability.ok) failures.add("wall", "daemon_unresponsive");
    const availabilityValue: ObserverWallPart["availability"] = availability.ok ? availability.value : { status: "unresponsive", resolved_at_ms: null };
    if (availabilityValue.status === "unresponsive") failures.add("wall", "daemon_unresponsive");

    if (!print.ok) failures.add("wall", "observation_invalid");
    if (!fullState.ok) failures.add("wall", "observation_invalid");
    const reads = processes.ok ? processes.value : null;
    if (reads === null) { failures.add("wall", "process_identity_unknown"); agentFailure("process_identity_unknown"); }
    const fullPid = print.ok ? print.value.pid : null;
    const charges = fullState.ok && fullState.value !== null ? fullState.value.charges_ms : [];
    const fullService: ObserverWallPart["full_service"] = {
      loaded: print.ok ? print.value.loaded : false,
      latched: fullState.ok && fullState.value !== null ? fullState.value.latched : false,
      pid: fullPid,
      start_identity: reads === null ? null : stableStartIdentity(reads, fullPid),
      last_charge_at_ms: charges.length === 0 ? null : Math.max(...charges),
    };

    // Canary integrity from this cycle's facts only; any child failure reads passed false inside the checker.
    let canaryIntegrity: ObserverWallPart["canary_integrity"] = null;
    if (agentUid !== undefined) {
      const collected = facts !== null && facts.ok ? facts.value : null;
      const failed = { status: "failed" as const };
      canaryIntegrity = checkCanaryIntegrity(collected === null
        ? { agentUid, plistStat: failed, plistBytes: failed, account: failed, print: failed }
        : { agentUid, ...collected }, endedAt);
      if (canaryIntegrity !== null && !canaryIntegrity.passed && collected === null) failures.add("wall", "canary_unprovisioned");
    }

    // Gateway, census and MCP.
    let gateway: ObserverAgentPart["gateway"] = null;
    if (agentUid !== undefined && config?.gateway_selector !== undefined && reads !== null) {
      gateway = selectGateway(reads, { agentUid, processName: config.gateway_selector.process_name }, this.priorGateway);
      if (gateway !== null && gateway.alive) this.priorGateway = gateway;
    }
    this.censusContext = {
      gateway: gateway !== null && gateway.alive ? { pid: gateway.pid, start_identity: gateway.start_identity, uid: gateway.uid, generation: gateway.generation } : null,
      gatewayAlive: gateway !== null && gateway.alive,
      ipv4Set: config?.messaging_ipv4 ?? null,
      bootId,
    };
    const censusOk = agentUid !== undefined && gateway !== null && gateway.alive && this.deps.sampler.latestAttemptOk();
    const census: ObserverAgentPart["census"] = censusOk ? { status: "ok", samples: this.deps.series.snapshot() } : { status: "unavailable", samples: [] };
    if (!censusOk) agentFailure("census_unavailable");
    let mcp: ObserverAgentPart["mcp"] = null;
    if (agentUid !== undefined && mcpConfig) {
      const check = reads === null || harness === null || !harness.ok ? null : checkMcpStaleChild(reads, harness.value, { agentUid, mcp: mcpConfig });
      // Detection only: a stale child is reported and never signalled, killed or restarted.
      if (check !== null && check.status === "ok") mcp = { stale_child: check.stale_child };
      else agentFailure("observation_invalid");
    }

    // Assemble the candidate. The raw keys must match OBSERVER_WALL_RAW and OBSERVER_AGENT_RAW in server/src/castle-wall/liveness/schema.ts.
    // A withheld cycle makes no publish attempt, so it consumes no sequence number.
    const sequence = Math.min(COUNTER_MAX, this.sequence + 1);
    if (!withhold) this.sequence = sequence;
    const build = (wall: ComponentRecovery, agent: ComponentRecovery): Record<string, unknown> => ({
      schema_version: LIVENESS_SCHEMA_VERSION,
      record: "observer",
      subject: { fortress_id: this.deps.fortressId, host_id: this.deps.hostId, platform: "darwin", operator_uid: this.deps.operatorUid, agent_uid: agentUid ?? null },
      boot_id: recordBootId,
      config_generation: 0,
      sequence,
      observed_at: new Date(endedAt).toISOString(),
      observed_uptime_ms: uptimeMs,
      collection: { started_at_ms: startedAt, ended_at_ms: Math.max(startedAt, endedAt) },
      evidence_failures: failures.list(),
      observer_instance: this.instance,
      observer_period_ms: OBSERVER_PERIOD,
      raw: {
        daemon_ref: daemonRef,
        availability: availabilityValue,
        full_service: fullService,
        session: "full",
        canary_integrity: canaryIntegrity,
        canary_allow_sighting: this.sighting === null ? null : { ...this.sighting },
        census,
        gateway,
        optional_reply: null,
        mcp,
      },
      recovery: { wall, agent },
    });
    const candidate = build(this.wallRecovery, this.agentRecovery);
    const host: HostClock = bootId === null ? { ok: false } : { ok: true, bootId, uptimeMs };
    const envelope = evaluateLiveness({
      nowMs: endedAt,
      platform: "darwin",
      host,
      local: { fortress_id: this.deps.fortressId, platform: "darwin", operator_uid: this.deps.operatorUid },
      directory: records.ok ? records.value.directory : { status: "ok" },
      daemon: records.ok ? records.value.daemon : { status: "absent" },
      observer: { status: "present", value: candidate },
      config: configRead,
    });
    // A new instance cannot know whether a fault was in progress when the previous one stopped, so its first cycle records one.
    // A withheld cycle is faulted too: its evidence is incomplete, and a sample must never name a sequence that was not published.
    const faulted = this.completedCycles === 0 || withhold;
    const sample = { sequence, observed_uptime_ms: uptimeMs };
    this.wallRecovery = advanceRecovery(this.wallRecovery, !faulted && wallCycleClean(envelope), sample);
    this.agentRecovery = advanceRecovery(this.agentRecovery, !faulted && agentCycleClean(envelope), sample);
    const record = build(this.wallRecovery, this.agentRecovery);
    this.lastRecord = record;
    this.completedCycles = Math.min(COUNTER_MAX, this.completedCycles + 1);

    if (withhold) {
      // The predecessor's record stays in place and ages stale on its own; readers see observer_stale, never a lost fault.
      this.withheldCycles = Math.min(COUNTER_MAX, this.withheldCycles + 1);
      return;
    }
    // observer_PUBLISHING: the sequence is consumed by the attempt, because a publish that reported failure may still have landed.
    this.state = "observer_PUBLISHING";
    this.lastPublish = this.handledPublish(this.deps.publisher.publish(record));
  }

  /**
   * One handled continuation per distinct drain. The publisher returns its in-flight drain to every call made while
   * that drain runs (the call only replaces the one waiting record), so attaching a handler per call would grow without
   * bound behind a stalled write. A failure is counted once per drain that rejected, which is the publisher's own unit:
   * a record replaced while waiting was never attempted.
   */
  private handledPublish(drain: Promise<void>): Promise<void> {
    if (this.publishing !== null && this.publishing.drain === drain) return this.publishing.handled;
    const settle = (failed: boolean): void => {
      if (failed) this.publishFailures = Math.min(COUNTER_MAX, this.publishFailures + 1);
      if (this.publishing?.drain === drain) this.publishing = null;
    };
    const handled = drain.then(() => settle(false), () => settle(true));
    this.publishing = { drain, handled };
    return handled;
  }

  private resetForBoot(): void {
    this.wallRecovery = emptyRecovery();
    this.agentRecovery = emptyRecovery();
    this.sighting = null;
    this.priorGateway = null;
    this.deps.series.reset();
  }

  /** A seed only adds a fault: it can set a sighting when none is newer, never clear one. */
  private applySeed(read: RecordRead, bootId: string, nowMs: number): void {
    if (read.status !== "present") return;
    const parsed = parseObserverRecord(read.value);
    if (!parsed.ok || parsed.envelope.boot_id !== bootId || !parsed.wall.ok) return;
    const seed = parsed.wall.value.canary_allow_sighting;
    if (seed === null || nowMs - seed.captured_at_ms > HISTORY_WINDOW) return;
    if (this.sighting === null || seed.captured_at_ms > this.sighting.captured_at_ms) this.sighting = { ...seed, captured_at_ms: retainedCaptureTime(seed.captured_at_ms, nowMs) };
  }
}
