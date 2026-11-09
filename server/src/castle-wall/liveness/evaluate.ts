/**
 * The pure liveness evaluator. Every consumer calls it at read time over raw
 * stored evidence plus the current clock, boot and uptime; nothing it returns
 * is ever stored as a verdict. It imports no filesystem, network or process
 * module so the same code ships in the contract bundle.
 */
import { parseIsoInstantWithOffset } from "../../core/time.js";
import {
  AGENT_WINDOW_BASE,
  AVAILABILITY_WINDOW,
  CANARY_IP,
  CANARY_PORT,
  CANARY_PROTOCOL,
  COMMISSIONED_PTB,
  COUNTER_MAX,
  DAEMON_WINDOW,
  DETECTOR_WINDOW,
  HEARTBEAT_WINDOW,
  HISTORY_WINDOW,
  LIVENESS_EVALUATOR_VERSION,
  LIVENESS_EXIT_DOWN,
  LIVENESS_EXIT_OK,
  LIVENESS_EXIT_WARNING,
  LIVENESS_SCHEMA_VERSION,
  LIVENESS_STATUS_INTERNAL_EXIT_CODE,
  LOCAL_JITTER,
  OBSERVER_WINDOW,
  PENDING_WRITE_WINDOW,
  RECOVERY_GAP,
  agentWindow,
  canaryWindow,
  reasonEntry,
  reasonPosition,
  type AgentState,
  type CoverageState,
  type WallState,
} from "./constants.js";
import { evaluateCensusRun } from "./census.js";
import {
  parseConfigRecord,
  parseDaemonRecord,
  parseObserverRecord,
  REQUIRED_RECORDER_HOOKS,
  type DaemonRecord,
  type EvidenceFailure,
  type LivenessConfig,
  type LivenessSubject,
  type ObserverAgentPart,
  type ObserverEnvelope,
  type ObserverWallPart,
} from "./schema.js";

// ---------------------------------------------------------------------------
// Inputs.
// ---------------------------------------------------------------------------
/** Why a reader refused a record or directory before parsing it. */
export type CustodyCause = "not_regular_file" | "read_deadline" | "owner" | "mode" | "size" | "not_directory";
/** One record as the reader found it; the evaluator alone parses the value. */
export type RecordRead =
  | { status: "absent" }
  | { status: "present"; value: unknown }
  | { status: "unparsable" }
  | { status: "custody_invalid"; cause: CustodyCause };
/** The reader's current boot and uptime, from an injected provider. */
export type HostClock = { ok: true; bootId: string; uptimeMs: number } | { ok: false };

export interface LivenessInput {
  /** Reader UTC time in epoch milliseconds. */
  nowMs: number;
  platform: string;
  host: HostClock;
  /** The fortress being read and the reading process. */
  local: { fortress_id: string; platform: string; operator_uid: number };
  /** Custody of `<fortress>/liveness/` itself. */
  directory: { status: "ok" } | { status: "absent" } | { status: "custody_invalid"; cause: CustodyCause };
  daemon: RecordRead;
  observer: RecordRead;
  config: RecordRead;
  /** True when a reader operation hit the read deadline; the envelope then carries the internal exit. */
  readDeadlineHit?: boolean;
  /** Legacy collector input (a later job); fixture only here. */
  legacyCollectorOnly?: boolean;
}

// ---------------------------------------------------------------------------
// Output.
// ---------------------------------------------------------------------------
export interface ComponentEvidence {
  daemon_instance?: string;
  daemon_sequence?: number;
  daemon_age_ms?: number;
  observer_instance?: string;
  observer_sequence?: number;
  observer_age_ms?: number;
  canary_age_ms?: number;
  census_run_age_ms?: number;
  cause?: CustodyCause;
}
export interface ComponentVerdict<S extends string> {
  state: S;
  alarm: boolean;
  reasons: string[];
  evidence: ComponentEvidence;
}
export interface LivenessEnvelope {
  schema_version: number;
  evaluator_version: number;
  evaluated_at: string;
  subject: { fortress_id: string; platform: string; operator_uid: number; agent_uid: number | null };
  wall: ComponentVerdict<WallState>;
  agent: ComponentVerdict<AgentState>;
  coverage: ComponentVerdict<CoverageState>;
  alarm: boolean;
  exit_code: number;
  notifications_silenced_until: null;
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------
const ABSENCE_REASONS: ReadonlySet<string> = new Set(["observer_missing", "daemon_telemetry_stale", "canary_failed"]);

class ReasonSet {
  private readonly set = new Set<string>();
  add(reason: string): void { this.set.add(reason); }
  has(reason: string): boolean { return this.set.has(reason); }
  delete(reason: string): void { this.set.delete(reason); }
  get size(): number { return this.set.size; }
  values(): string[] { return [...this.set]; }
  /** Most severe first, by registry position. */
  ordered(): string[] {
    return this.values().sort((a, b) => (reasonPosition(b) ?? 0) - (reasonPosition(a) ?? 0));
  }
}

type Timing = { ok: true; ageMs: number } | { ok: false };

/** Age of a record from both clocks; a future time or a divergence beyond LOCAL_JITTER is untrusted. */
function recordTiming(observedAt: string, observedUptimeMs: number, nowMs: number, uptimeMs: number): Timing {
  // Timestamps entering freshness arithmetic go through the one strict instant predicate; an unparsable time is untrusted.
  const utcAge = nowMs - (parseIsoInstantWithOffset(observedAt) ?? Number.NaN);
  const uptimeAge = uptimeMs - observedUptimeMs;
  if (!Number.isFinite(utcAge) || utcAge < -LOCAL_JITTER || uptimeAge < 0) return { ok: false };
  // Within one boot the two clocks progress together; a larger gap means one of them moved.
  if (Math.abs(utcAge - uptimeAge) > LOCAL_JITTER) return { ok: false };
  return { ok: true, ageMs: Math.max(0, utcAge, uptimeAge) };
}

/** Age of an embedded UTC time; null when absent, and undefined when it lies beyond LOCAL_JITTER in the future. */
function stampAge(atMs: number | null, nowMs: number): number | null | undefined {
  if (atMs === null) return null;
  const age = nowMs - atMs;
  return age < -LOCAL_JITTER ? undefined : Math.max(0, age);
}

/** Gate 14: a record's subject must name the fortress being read and the commissioned agent. */
function subjectMatches(subject: LivenessSubject, local: LivenessInput["local"], agentUid: number | undefined): boolean {
  return subject.fortress_id === local.fortress_id &&
    subject.platform === local.platform &&
    subject.operator_uid === local.operator_uid &&
    agentUid !== undefined && subject.agent_uid === agentUid;
}

/** Apply typed evidence failures; an unknown or foreign reason stays on its own component as observation_invalid. */
function applyEvidenceFailures(failures: readonly EvidenceFailure[], wall: ReasonSet | null, agent: ReasonSet | null): void {
  for (const failure of failures) {
    const target = failure.component === "wall" ? wall : agent;
    if (!target) continue;
    const known = reasonEntry(failure.reason);
    const carriable = known !== undefined && known.producer === "evaluator" && known.reason !== "none" &&
      (failure.component === "wall" ? known.wall !== "n/a" : known.agent !== "n/a");
    target.add(carriable ? failure.reason : "observation_invalid");
  }
}

function ptbMatches(config: LivenessConfig): boolean {
  const ptb = config.ptb;
  return ptb !== undefined &&
    ptb.version === COMMISSIONED_PTB.version &&
    ptb.timeout_s === COMMISSIONED_PTB.timeout_s &&
    ptb.poll_interval_s === COMMISSIONED_PTB.poll_interval_s &&
    ptb.separate_get_updates_request === COMMISSIONED_PTB.separate_get_updates_request &&
    ptb.http_version === COMMISSIONED_PTB.http_version &&
    ptb.hermes_read_timeout_s === COMMISSIONED_PTB.hermes_read_timeout_s;
}

function wallExitFor(state: WallState): number {
  if (state.startsWith("wall_OK_")) return LIVENESS_EXIT_OK;
  if (state === "wall_TTL_WARNING" || state === "wall_DEGRADED") return LIVENESS_EXIT_WARNING;
  return LIVENESS_EXIT_DOWN;
}

function hasClass(reasons: ReasonSet, component: "wall" | "agent", cls: string): boolean {
  return reasons.values().some(reason => reasonEntry(reason)?.[component] === cls);
}

// ---------------------------------------------------------------------------
// Evaluation.
// ---------------------------------------------------------------------------
interface CurrentRecords {
  daemon: DaemonRecord | null;
  daemonAgeMs: number | null;
  observer: ObserverEnvelope | null;
  observerAgeMs: number | null;
  observerFresh: boolean;
  wallPart: ObserverWallPart | null;
  agentPart: ObserverAgentPart | null;
}

/** Evaluate wall, agent and coverage from raw records. Pure and deterministic. */
export function evaluateLiveness(input: LivenessInput): LivenessEnvelope {
  const wall = new ReasonSet();
  const agent = new ReasonSet();
  const coverage = new ReasonSet();
  const wallEvidence: ComponentEvidence = {};
  const agentEvidence: ComponentEvidence = {};
  const now = input.nowMs;

  // -------- Config (commissioning facts) --------
  let config: LivenessConfig | null = null;
  // An untrusted liveness directory makes every record in it untrusted; a missing directory makes them absent.
  const throughDirectory = (read: RecordRead): RecordRead =>
    input.directory.status === "ok" ? read
      : input.directory.status === "absent" ? { status: "absent" }
        : { status: "custody_invalid", cause: input.directory.cause };
  const configRead = throughDirectory(input.config);
  if (configRead.status === "custody_invalid") {
    wall.add("custody_invalid"); agent.add("custody_invalid");
    wallEvidence.cause ??= configRead.cause; agentEvidence.cause ??= configRead.cause;
  } else if (configRead.status === "unparsable") {
    wall.add("observation_invalid");
  } else if (configRead.status === "present") {
    const parsed = parseConfigRecord(configRead.value);
    if (!parsed.ok) wall.add("observation_invalid");
    else {
      config = parsed.value;
      if (parsed.wallInvalid.length > 0) wall.add("observation_invalid");
      if (parsed.agentInvalid.length > 0 && config.commissioning.agent === true) agent.add("observation_invalid");
    }
  }
  const agentUid = config?.agent_uid;
  const leewayMs = config?.launchd_leeway_ms;
  const canaryWindowMs = canaryWindow(leewayMs ?? 0);
  const wallCommissioned = config !== null && config.commissioning.wall === true && agentUid !== undefined && leewayMs !== undefined;
  const agentFlagged = config !== null && config.commissioning.agent === true;
  // Gate 13 and gate 11: an unset or invalid wall commissioning fact is never read as commissioned.
  if (!wallCommissioned && !wall.has("custody_invalid")) wall.add("commissioning_unproven");

  const subject = { fortress_id: input.local.fortress_id, platform: input.local.platform, operator_uid: input.local.operator_uid, agent_uid: agentUid ?? null };

  // -------- Platform and host clock --------
  if (input.platform !== "darwin") {
    return finish(input, subject, single("unsupported_adapter"), single("unsupported_adapter"), single("unsupported_adapter"), {}, {}, null, null);
  }
  if (!input.host.ok) {
    // Without the current boot no record can be placed in time; both components read untrusted time.
    coverage.add("observer_stale");
    return finish(input, subject, single("time_untrusted"), single("time_untrusted"), coverage, {}, {}, null, null);
  }
  const { bootId, uptimeMs } = input.host;

  // -------- Records --------
  const current: CurrentRecords = { daemon: null, daemonAgeMs: null, observer: null, observerAgeMs: null, observerFresh: false, wallPart: null, agentPart: null };
  const daemonRead = throughDirectory(input.daemon);
  const observerRead = throughDirectory(input.observer);
  let daemonAbsent = false;
  let observerAbsent = false;

  if (daemonRead.status === "custody_invalid") {
    wall.add("custody_invalid"); wallEvidence.cause ??= daemonRead.cause;
  } else if (daemonRead.status === "unparsable") {
    wall.add("observation_invalid");
  } else if (daemonRead.status === "absent") {
    daemonAbsent = true;
  } else {
    const parsed = parseDaemonRecord(daemonRead.value);
    if (!parsed.ok) wall.add("observation_invalid");
    else if (parsed.value.boot_id === null) wall.add("time_untrusted");
    // A record from another boot is absent, never untrusted time.
    else if (parsed.value.boot_id !== bootId) daemonAbsent = true;
    else {
      const d = parsed.value;
      const timing = recordTiming(d.observed_at, d.observed_uptime_ms, now, uptimeMs);
      if (!timing.ok) wall.add("time_untrusted");
      else {
        current.daemon = d;
        current.daemonAgeMs = timing.ageMs;
        wallEvidence.daemon_instance = d.daemon_instance;
        wallEvidence.daemon_sequence = d.sequence;
        wallEvidence.daemon_age_ms = timing.ageMs;
        if (timing.ageMs > DAEMON_WINDOW) wall.add("daemon_telemetry_stale");
      }
      // Gate 14: a record bound to another fortress, platform, operator or agent is wrong evidence, and wrong subject is DOWN.
      if (!subjectMatches(d.subject, input.local, agentUid)) wall.add("observation_invalid");
      applyEvidenceFailures(d.evidence_failures, wall, null);
    }
  }

  if (observerRead.status === "custody_invalid") {
    wall.add("custody_invalid"); agent.add("custody_invalid");
    wallEvidence.cause ??= observerRead.cause; agentEvidence.cause ??= observerRead.cause;
    coverage.add("custody_invalid");
  } else if (observerRead.status === "unparsable") {
    wall.add("observation_invalid"); agent.add("observation_invalid");
  } else if (observerRead.status === "absent") {
    observerAbsent = true;
  } else {
    const parsed = parseObserverRecord(observerRead.value);
    if (!parsed.ok) { wall.add("observation_invalid"); agent.add("observation_invalid"); }
    else if (parsed.envelope.boot_id === null) { wall.add("time_untrusted"); agent.add("time_untrusted"); }
    else if (parsed.envelope.boot_id !== bootId) observerAbsent = true;
    else {
      const o = parsed.envelope;
      const timing = recordTiming(o.observed_at, o.observed_uptime_ms, now, uptimeMs);
      if (!timing.ok) { wall.add("time_untrusted"); agent.add("time_untrusted"); }
      else {
        current.observer = o;
        current.observerAgeMs = timing.ageMs;
        current.observerFresh = timing.ageMs <= OBSERVER_WINDOW;
        for (const evidence of [wallEvidence, agentEvidence]) {
          evidence.observer_instance = o.observer_instance;
          evidence.observer_sequence = o.sequence;
          evidence.observer_age_ms = timing.ageMs;
        }
        if (!current.observerFresh) { wall.add("observer_stale"); agent.add("observer_stale"); }
      }
      if (!subjectMatches(o.subject, input.local, agentUid)) { wall.add("observation_invalid"); agent.add("observation_invalid"); }
      applyEvidenceFailures(o.evidence_failures, wall, agent);
      if (parsed.wall.ok) current.wallPart = parsed.wall.value; else wall.add("observation_invalid");
      if (parsed.agent.ok) current.agentPart = parsed.agent.value; else agent.add("observation_invalid");
    }
  }

  // Instance age: reader uptime minus the current-boot daemon's start uptime, else the reader uptime itself.
  const instanceAgeMs = current.daemon !== null && current.daemon.instance_started_uptime_ms !== null
    ? Math.max(0, uptimeMs - current.daemon.instance_started_uptime_ms)
    : uptimeMs;

  // -------- Wall gates over a current-boot daemon record --------
  let canaryAccepted = false;
  let canaryCapturedAtMs: number | null = null;
  let ttlKnownAboveWarning = false;
  let agedHistory = false;
  let naturalActive = false;
  if (daemonAbsent) wall.add("daemon_telemetry_stale");
  if (current.daemon !== null) {
    const d = current.daemon;
    const raw = d.raw;
    const stamp = (atMs: number | null): number | null => {
      const age = stampAge(atMs, now);
      if (age === undefined) { wall.add("time_untrusted"); return null; }
      return age;
    };
    // Gate 6: a missing wired flag or an uninstrumented lock field is incomplete evidence, never a pass.
    for (const hook of REQUIRED_RECORDER_HOOKS) if (raw.hooks[hook] !== true) wall.add("evidence_incomplete");
    if (raw.lock_recovery.state === "not_instrumented") wall.add("evidence_incomplete");
    else {
      if (raw.lock_recovery.count >= COUNTER_MAX) wall.add("observation_invalid");
      const lockAge = stamp(raw.lock_recovery.last_at_ms);
      if (lockAge !== null && lockAge <= HISTORY_WINDOW) wall.add("write_lock_recovery");
      else if (lockAge !== null) agedHistory = true;
    }
    // Gate 4.
    const detectorAge = stamp(raw.detector.last_evaluate_at_ms);
    if (raw.detector.last_evaluate_at_ms === null || (detectorAge !== null && detectorAge > DETECTOR_WINDOW)) wall.add("detector_stale");
    if (raw.detector.stalled) wall.add("emission_stall");
    // Gate 5.
    const flushAge = stamp(raw.heartbeat.last_durable_flush_at_ms);
    if (raw.heartbeat.last_durable_flush_at_ms === null || (flushAge !== null && flushAge > HEARTBEAT_WINDOW)) wall.add("heartbeat_stale");
    // Pending evidence: the published age keeps growing for as long as the record has been on disk.
    const pending = raw.pending_evidence;
    if (pending.oldest_unresolved_age_ms !== null && pending.oldest_unresolved_age_ms + (current.daemonAgeMs ?? 0) > PENDING_WRITE_WINDOW) wall.add("audit_backlog");
    if (pending.ingress_loss_pending > 0) wall.add("audit_loss");
    const rejectionAge = stamp(pending.last_rejection_at_ms);
    if (rejectionAge !== null && rejectionAge <= HISTORY_WINDOW) wall.add("audit_rejected");
    if (pending.ingress_loss_pending >= COUNTER_MAX || pending.coalesced_pending >= COUNTER_MAX ||
        raw.decisions.verified_admissions >= COUNTER_MAX || raw.decisions.primary_confirmations >= COUNTER_MAX) wall.add("observation_invalid");
    const naturalAge = stamp(raw.decisions.last_natural_primary_at_ms);
    naturalActive = naturalAge !== null && naturalAge <= canaryWindowMs;
    // Lease countdown: an explicit null deadline is no TTL; a zero or past deadline is expired.
    if (raw.lease.deadline_ms !== null) {
      const ttl = raw.lease.deadline_ms - now;
      if (ttl <= 0) wall.add("lease_expired");
      else if (ttl <= canaryWindowMs) wall.add("ttl_expiring");
      else ttlKnownAboveWarning = true;
    }
    // Gate 8: the canary acceptance conjuncts.
    const canary = raw.canary;
    if (canary.failure_count >= COUNTER_MAX || canary.late_count >= COUNTER_MAX) wall.add("observation_invalid");
    if (canary.adapter !== "uid") wall.add("unsupported_adapter");
    else {
      const c = canary.last_confirmation;
      const accepted = c !== null &&
        c.delivery === "live" &&
        c.confirmed_at_ms >= c.captured_at_ms &&
        agentUid !== undefined && c.subject_uid === agentUid &&
        c.dest_ip === CANARY_IP && c.dest_port === CANARY_PORT && c.dest_protocol === CANARY_PROTOCOL &&
        now - c.captured_at_ms <= canaryWindowMs &&
        c.captured_at_ms - now <= LOCAL_JITTER;
      if (accepted) {
        canaryAccepted = true;
        canaryCapturedAtMs = c.captured_at_ms;
        wallEvidence.canary_age_ms = Math.max(0, now - c.captured_at_ms);
        const laterMiss = Math.max(canary.last_failure?.failed_at_ms ?? 0, canary.last_late?.settled_at_ms ?? 0);
        if (laterMiss > c.confirmed_at_ms) wall.add("recording_unconfirmed");
      } else wall.add("canary_failed");
    }
    // Gate 10: an agent or gate allow to the canary tuple means the wall let the monitoring flow through.
    const allowedAge = stamp(canary.last_destination_allowed?.captured_at_ms ?? null);
    if (allowedAge !== null && allowedAge <= HISTORY_WINDOW) wall.add("canary_destination_allowed");
  } else {
    // An absent or other-boot daemon record contributes only its absence reasons.
    wall.add("canary_failed");
  }

  // -------- Wall gates over a current-boot observer record --------
  if (observerAbsent) {
    wall.add("observer_missing"); agent.add("observer_missing"); coverage.add("observer_missing");
  } else if (current.observer !== null && !current.observerFresh) {
    coverage.add("observer_stale");
  }
  let recoveryMet = false;
  if (current.wallPart !== null && current.observer !== null) {
    const p = current.wallPart;
    const stamp = (atMs: number | null): number | null => {
      const age = stampAge(atMs, now);
      if (age === undefined) { wall.add("time_untrusted"); return null; }
      return age;
    };
    // Gate 1 has two separate halves. Instance consistency: an observer whose daemon reference names another
    // instance observed a different process, so none of its wall evidence is credited toward OK for the current
    // instance; the wall reads recovering until a fresh observer record references the current instance. A matching
    // PID is not instance evidence, since a restarted daemon can reuse it.
    const observerInstanceMismatch = p.daemon_ref !== null && current.daemon !== null &&
      p.daemon_ref.daemon_instance !== current.daemon.daemon_instance;
    if (observerInstanceMismatch) wall.add("recovering");
    // Sequence monotonicity, compared only within one instance: the observer saw a later sequence of this same
    // instance than the one on disk. The daemon publishes independently, so its sequence may run ahead of the reference.
    if (p.daemon_ref !== null && current.daemon !== null && !observerInstanceMismatch &&
        current.daemon.sequence < p.daemon_ref.sequence) wall.add("counter_regression");
    // Gate 3.
    const availabilityAge = stamp(p.availability.resolved_at_ms);
    if (p.availability.status === "unresponsive") wall.add("daemon_unresponsive");
    else if (p.availability.status !== "live" || availabilityAge === null || availabilityAge > AVAILABILITY_WINDOW) wall.add("enforcement_not_live");
    // Gate 7.
    if (p.full_service.latched) wall.add("crash_latched");
    if (!p.full_service.loaded) wall.add("daemon_missing");
    else if (p.full_service.pid === null || p.full_service.start_identity === null ||
      (current.daemon !== null && p.full_service.pid !== current.daemon.raw.process.pid)) wall.add("process_identity_unknown");
    const chargeAge = stamp(p.full_service.last_charge_at_ms);
    if (chargeAge !== null && chargeAge <= HISTORY_WINDOW) wall.add("recent_restart");
    else if (chargeAge !== null) agedHistory = true;
    if (p.session === "safe_mode_only") wall.add("safe_mode_only");
    if (p.session === "logged_out") wall.add("session_logged_out");
    if (p.session === "reboot_no_login") wall.add("reboot_no_login");
    // Gate 9: an integrity miss means the canary itself is not provisioned, so it is canary_unprovisioned and never canary_failed.
    const integrity = p.canary_integrity;
    const integrityAge = integrity === null ? null : stamp(integrity.checked_at_ms);
    if (integrity === null || !integrity.passed || integrityAge === null || integrityAge > OBSERVER_WINDOW) {
      wall.add("canary_unprovisioned"); coverage.add("canary_unprovisioned");
    }
    // Gate 12: two distinct recovery samples RECOVERY_GAP apart, after any fault, with a post-fault canary.
    const samples = p.recovery.samples;
    if (samples.length === 2) {
      const [a, b] = samples as [typeof samples[0], typeof samples[0]];
      const fault = p.recovery.fault_uptime_ms;
      const canaryUptime = canaryCapturedAtMs === null ? null : uptimeMs - (now - canaryCapturedAtMs);
      recoveryMet = a.sequence !== b.sequence &&
        Math.abs(b.observed_uptime_ms - a.observed_uptime_ms) >= RECOVERY_GAP &&
        Math.max(a.observed_uptime_ms, b.observed_uptime_ms) <= current.observer.observed_uptime_ms &&
        (fault === null || (Math.min(a.observed_uptime_ms, b.observed_uptime_ms) > fault && canaryUptime !== null && canaryUptime > fault));
    }
  }

  // -------- Absence rewrite --------
  // A young instance has no complete first observation yet, so its absence reasons read initializing, never OK.
  if (instanceAgeMs < canaryWindowMs) {
    let rewrote = false;
    for (const reason of ABSENCE_REASONS) if (wall.has(reason)) { wall.delete(reason); rewrote = true; }
    if (rewrote) wall.add("initializing");
  }
  // Fail safe: a gate that was not evaluated never passes.
  if (wall.size === 0 && (current.daemon === null || current.wallPart === null)) wall.add("evidence_incomplete");
  if (wall.size === 0 && !canaryAccepted) wall.add("canary_failed");
  if (wall.size === 0 && !recoveryMet) wall.add("recovering");

  // -------- Agent --------
  let agentCommissioned = false;
  let optionalReplyOk = false;
  const agentWindowMs = agentWindow(config?.poll_backoff_cap_ms ?? 0);
  if (!agentFlagged) {
    if (!agent.has("custody_invalid")) agent.add("agent_unmonitored");
  } else if (config !== null) {
    const complete = agentUid !== undefined && config.poll_backoff_cap_ms !== undefined && ptbMatches(config) &&
      config.messaging_ipv4 !== undefined && config.messaging_ipv4.length > 0 &&
      config.gateway_selector !== undefined && config.gateway_egress !== undefined;
    if (!complete) agent.add("commissioning_unproven");
    else agentCommissioned = true;
    if (config.ptb !== undefined && config.ptb.http_version !== COMMISSIONED_PTB.http_version) agent.add("census_unavailable");
    if (config.gateway_egress === "gate_proxied") agent.add("census_unavailable");
  }
  if (agentCommissioned && config !== null && current.agentPart !== null && current.observer !== null) {
    const p = current.agentPart;
    if (p.census.status === "unavailable") agent.add("census_unavailable");
    if (p.gateway === null) agent.add("process_identity_unknown");
    else {
      if (!p.gateway.alive) agent.add("agent_process_missing");
      if (p.gateway.uid !== agentUid) agent.add("process_identity_unknown");
    }
    if (p.mcp?.stale_child) agent.add("stale_mcp_child");
    if (p.optional_reply !== null) {
      const success = p.optional_reply.last_success_at_ms;
      const failure = p.optional_reply.last_failure_at_ms;
      const failedLast = failure !== null && (success === null || failure > success);
      if (failedLast && p.optional_reply.required) agent.add("optional_reply_failed");
      optionalReplyOk = !failedLast && success !== null && now - success <= agentWindowMs && now - success >= -LOCAL_JITTER;
    }
    if (p.gateway !== null && p.census.status === "ok") {
      const result = evaluateCensusRun({
        samples: p.census.samples,
        gateway: { pid: p.gateway.pid, generation: p.gateway.generation },
        ipv4Set: config.messaging_ipv4 ?? [],
        bootId,
        nowMs: now,
        agentWindowMs,
      });
      if (result.invalid) agent.add("observation_invalid");
      if (result.counterRegression) agent.add("counter_regression");
      if (result.run === null) {
        const startMs = result.generationStartMs;
        // agent_flow_stale only once the generation start is known and more than the agent window ago.
        const stale = startMs !== null ? now - startMs > agentWindowMs : instanceAgeMs > agentWindowMs;
        agent.add(stale ? "agent_flow_stale" : "initializing");
      } else {
        agentEvidence.census_run_age_ms = Math.max(0, now - result.run.latestObservedAtMs);
        const fault = p.recovery.fault_uptime_ms;
        if (fault !== null) {
          const s = p.recovery.samples;
          const runFirstUptime = uptimeMs - (now - result.run.firstObservedAtMs);
          const met = s.length === 2 && s[0]!.sequence !== s[1]!.sequence &&
            Math.abs(s[1]!.observed_uptime_ms - s[0]!.observed_uptime_ms) >= RECOVERY_GAP && runFirstUptime > fault;
          if (!met) agent.add("recovering");
        }
      }
    }
  }

  // -------- Coverage --------
  if (wall.has("custody_invalid") || agent.has("custody_invalid")) coverage.add("custody_invalid");
  if (wall.has("commissioning_unproven")) coverage.add("commissioning_unproven");
  if ((current.observer === null || current.wallPart === null) && !observerAbsent) coverage.add("observer_stale");
  if (input.legacyCollectorOnly) coverage.add("monitoring_incomplete");
  const agentState = agentLabel(agent, agentCommissioned, optionalReplyOk);
  if (agentState === "agent_UNMONITORED") coverage.add(agent.has("commissioning_unproven") ? "commissioning_unproven" : "agent_unmonitored");
  // An unrecorded alert drill caps coverage below COMPLETE.
  if (config === null || config.commissioning.alert_drill !== true) coverage.add("commissioning_unproven");

  return finish(input, subject, wall, agent, coverage, wallEvidence, agentEvidence, { ttlKnownAboveWarning, agedHistory, naturalActive }, agentState);
}

function single(reason: string): ReasonSet {
  const set = new ReasonSet();
  set.add(reason);
  return set;
}

function agentLabel(agent: ReasonSet, commissioned: boolean, optionalReplyOk: boolean): AgentState {
  const classes = agent.values().map(reason => {
    const cls = reasonEntry(reason)?.agent ?? "DOWN";
    if (cls === "DOWN_IF_COMMISSIONED") return commissioned ? "DOWN" : "UNMONITORED";
    // optional_reply_failed is only raised for a required reply.
    if (cls === "DOWN_IF_REQUIRED") return "DOWN";
    return cls;
  });
  if (classes.includes("UNMONITORED")) return "agent_UNMONITORED";
  if (classes.includes("DOWN")) return "agent_DOWN";
  if (classes.includes("INITIALIZING")) return "agent_INITIALIZING";
  if (classes.includes("DEGRADED_STALE_MCP")) return "agent_DEGRADED_STALE_MCP";
  if (classes.includes("RECOVERING")) return "agent_RECOVERING";
  if (!commissioned) return "agent_UNMONITORED";
  if (optionalReplyOk) return "agent_OK_OPTIONAL_REPLY";
  // Never OK without a qualifying run: every no-run path above added a reason.
  return "agent_OK_PASSIVE";
}

function wallLabel(wall: ReasonSet, flags: { ttlKnownAboveWarning: boolean; agedHistory: boolean; naturalActive: boolean } | null): WallState {
  if (wall.has("crash_latched") || wall.has("canary_destination_allowed")) return "wall_DOWN";
  if (wall.has("reboot_no_login")) return "wall_REBOOT_NO_LOGIN";
  if (wall.has("session_logged_out")) return "wall_LOGGED_OUT";
  if (wall.has("safe_mode_only")) return "wall_SAFE_MODE";
  if (wall.values().some(reason => reason !== "initializing" && (reasonEntry(reason)?.wall ?? "DOWN") === "DOWN")) return "wall_DOWN";
  if (wall.has("initializing")) return "wall_INITIALIZING";
  // TTL_WARNING ranks above DEGRADED.
  if (wall.has("ttl_expiring")) return "wall_TTL_WARNING";
  if (hasClass(wall, "wall", "DEGRADED")) return "wall_DEGRADED";
  if (wall.has("recovering")) return "wall_RECOVERING";
  if (wall.size > 0 || flags === null) return "wall_DOWN";
  if (flags.ttlKnownAboveWarning) return "wall_OK_TTL_COUNTDOWN";
  if (flags.agedHistory) return "wall_OK_AGED_HISTORY";
  if (flags.naturalActive) return "wall_OK_ACTIVE";
  return "wall_OK_IDLE";
}

/** Coverage precedence: UNAVAILABLE, then LEGACY_PARTIAL, then WALL_ONLY, then COMPLETE. */
function coverageLabel(coverage: ReasonSet, wallCarriesCommissioning: boolean): CoverageState {
  const effects = coverage.values().map(reason => {
    const effect = reasonEntry(reason)?.coverage ?? "UNAVAILABLE";
    // commissioning_unproven is UNAVAILABLE when the wall carries it, and WALL_ONLY when only the agent or the drill does.
    if (effect === "UNAVAILABLE_IF_WALL") return wallCarriesCommissioning ? "UNAVAILABLE" : "WALL_ONLY";
    return effect;
  });
  if (effects.includes("UNAVAILABLE")) return "coverage_UNAVAILABLE";
  if (effects.includes("LEGACY_PARTIAL")) return "coverage_LEGACY_PARTIAL";
  if (effects.includes("WALL_ONLY")) return "coverage_WALL_ONLY";
  return "coverage_COMPLETE";
}

function finish(
  input: LivenessInput,
  subject: LivenessEnvelope["subject"],
  wall: ReasonSet,
  agent: ReasonSet,
  coverage: ReasonSet,
  wallEvidence: ComponentEvidence,
  agentEvidence: ComponentEvidence,
  flags: { ttlKnownAboveWarning: boolean; agedHistory: boolean; naturalActive: boolean } | null,
  agentState: AgentState | null,
): LivenessEnvelope {
  const coverageState = coverageLabel(coverage, wall.has("commissioning_unproven"));
  const wallState = wallLabel(wall, flags);
  const finalAgent = agentState ?? agentLabel(agent, false, false);
  const wallReasons = wall.size === 0 ? ["none"] : wall.ordered();
  const agentReasons = agent.size === 0 ? ["none"] : agent.ordered();
  const coverageReasons = coverageState === "coverage_COMPLETE" ? ["none"] : coverage.ordered();
  const wallAlarm = !wallState.startsWith("wall_OK_");
  // The exit comes from the wall alone; agent and coverage never change it.
  const evaluatedExit = wallExitFor(wallState);
  const exitCode = input.readDeadlineHit ? LIVENESS_STATUS_INTERNAL_EXIT_CODE : evaluatedExit;
  return {
    schema_version: LIVENESS_SCHEMA_VERSION,
    evaluator_version: LIVENESS_EVALUATOR_VERSION,
    evaluated_at: new Date(input.nowMs).toISOString(),
    subject,
    wall: { state: wallState, alarm: wallAlarm, reasons: wallReasons, evidence: wallEvidence },
    agent: { state: finalAgent, alarm: !finalAgent.startsWith("agent_OK_"), reasons: agentReasons, evidence: agentEvidence },
    coverage: { state: coverageState, alarm: coverageState !== "coverage_COMPLETE", reasons: coverageReasons, evidence: {} },
    alarm: wallAlarm,
    exit_code: exitCode,
    notifications_silenced_until: null,
  };
}

/** The minimum agent window, used by tests to check rotation recovery fits. */
export const MIN_AGENT_WINDOW = AGENT_WINDOW_BASE;
