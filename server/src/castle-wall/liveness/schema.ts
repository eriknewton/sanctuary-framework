/**
 * Strict parsers for the three liveness records under `<fortress>/liveness/`.
 *
 * Every element, enum, finite number and subject is checked. An unknown field
 * or unknown version is `observation_invalid` for the component it belongs to,
 * and a component whose part of a record fails is never partially read.
 */
import { parseIsoInstantWithOffset } from "../../core/time.js";
import {
  CENSUS_ADDRESS_TEXT_MAX,
  CENSUS_PID_ROWS,
  CENSUS_SAMPLES_MAX,
  COUNTER_MAX,
  DAEMON_PERIOD,
  EVIDENCE_FAILURES_MAX,
  GENCNT_HEX_DIGITS,
  LABEL_BYTES,
  LAUNCHD_LEEWAY_MAX,
  LIVENESS_SCHEMA_VERSION,
  MAX_MCP_SCRIPT_PATHS,
  MAX_MESSAGING_PREFIXES,
  OBSERVER_PERIOD,
  PATH_BYTES,
  POLL_BACKOFF_CAP_MAX,
  RECOVERY_SAMPLES_PER_COMPONENT,
  SECOND,
} from "./constants.js";
import {
  TCP_STATES,
  parseIpv4Prefix,
  type Ipv4Prefix,
  type StoredCensusSample,
} from "./census.js";

export type LivenessComponent = "wall" | "agent";
const UINT32_MAX = 0xffffffff; // Unix uids are 32-bit unsigned.
const PORT_MAX = 65535; // TCP and UDP ports have sixteen bits.
const HEX = /^[0-9a-f]+$/;
/** Printable ASCII without quote or backslash, so a label's JSON encoding is exactly its length. */
const LABEL_TEXT = /^[\x20\x21\x23-\x5b\x5d-\x7e]+$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

/** Collects failing field paths; the first failure is enough to refuse a component. */
class Checker {
  readonly failures: string[] = [];
  fail(path: string): undefined {
    this.failures.push(path);
    return undefined;
  }
  object(value: unknown, path: string, known: readonly string[], required: readonly string[] = known): Record<string, unknown> | undefined {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return this.fail(path);
    const record = value as Record<string, unknown>;
    // A stored OK, healthy or increased verdict is never trusted; it is simply an unknown field.
    for (const key of Object.keys(record)) if (!known.includes(key)) this.fail(`${path}.${key}`);
    for (const key of required) if (!(key in record)) this.fail(`${path}.${key}`);
    return record;
  }
  uint(value: unknown, path: string, max: number = COUNTER_MAX): number | undefined {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) return this.fail(path);
    return value;
  }
  nullableUint(value: unknown, path: string, max: number = COUNTER_MAX): number | null | undefined {
    return value === null ? null : this.uint(value, path, max);
  }
  bool(value: unknown, path: string): boolean | undefined {
    return typeof value === "boolean" ? value : this.fail(path);
  }
  label(value: unknown, path: string): string | undefined {
    if (typeof value !== "string" || value.length > LABEL_BYTES || !LABEL_TEXT.test(value)) return this.fail(path);
    return value;
  }
  nullableLabel(value: unknown, path: string): string | null | undefined {
    return value === null ? null : this.label(value, path);
  }
  enumeration<T extends string>(value: unknown, path: string, options: readonly T[]): T | undefined {
    return typeof value === "string" && (options as readonly string[]).includes(value) ? (value as T) : this.fail(path);
  }
  instant(value: unknown, path: string): string | undefined {
    if (typeof value !== "string" || !ISO_INSTANT.test(value) || parseIsoInstantWithOffset(value) === undefined) return this.fail(path);
    return value;
  }
  array(value: unknown, path: string, max: number): unknown[] | undefined {
    if (!Array.isArray(value) || value.length > max) return this.fail(path);
    return value;
  }
}

// ---------------------------------------------------------------------------
// Shared envelope parts.
// ---------------------------------------------------------------------------
export interface LivenessSubject {
  fortress_id: string;
  host_id: string;
  platform: string;
  operator_uid: number;
  agent_uid: number | null;
}
export interface EvidenceFailure {
  component: LivenessComponent;
  reason: string;
}

function subject(c: Checker, value: unknown, path: string): LivenessSubject | undefined {
  const o = c.object(value, path, ["fortress_id", "host_id", "platform", "operator_uid", "agent_uid"]);
  if (!o) return undefined;
  const fortress_id = c.label(o.fortress_id, `${path}.fortress_id`);
  const host_id = c.label(o.host_id, `${path}.host_id`);
  const platform = c.label(o.platform, `${path}.platform`);
  const operator_uid = c.uint(o.operator_uid, `${path}.operator_uid`, UINT32_MAX);
  const agent_uid = c.nullableUint(o.agent_uid, `${path}.agent_uid`, UINT32_MAX);
  if (fortress_id === undefined || host_id === undefined || platform === undefined || operator_uid === undefined || agent_uid === undefined) return undefined;
  return { fortress_id, host_id, platform, operator_uid, agent_uid };
}

function evidenceFailures(c: Checker, value: unknown, path: string): EvidenceFailure[] | undefined {
  const list = c.array(value, path, EVIDENCE_FAILURES_MAX);
  if (!list) return undefined;
  const out: EvidenceFailure[] = [];
  list.forEach((item, index) => {
    const o = c.object(item, `${path}[${index}]`, ["component", "reason"]);
    if (!o) return;
    const component = c.enumeration(o.component, `${path}[${index}].component`, ["wall", "agent"] as const);
    // The reason name is checked against the registry by the evaluator, so an unknown name stays on its own component.
    const reason = c.label(o.reason, `${path}[${index}].reason`);
    if (component && reason) out.push({ component, reason });
  });
  return out;
}

function collection(c: Checker, value: unknown, path: string): { started_at_ms: number; ended_at_ms: number } | undefined {
  const o = c.object(value, path, ["started_at_ms", "ended_at_ms"]);
  if (!o) return undefined;
  const started_at_ms = c.uint(o.started_at_ms, `${path}.started_at_ms`);
  const ended_at_ms = c.uint(o.ended_at_ms, `${path}.ended_at_ms`);
  if (started_at_ms === undefined || ended_at_ms === undefined) return undefined;
  if (ended_at_ms < started_at_ms) return c.fail(path);
  return { started_at_ms, ended_at_ms };
}

const ENVELOPE_COMMON = [
  "schema_version", "record", "subject", "boot_id", "config_generation", "sequence",
  "observed_at", "observed_uptime_ms", "collection", "evidence_failures", "raw",
] as const;

interface EnvelopeCommon {
  subject: LivenessSubject;
  boot_id: string | null;
  config_generation: number;
  sequence: number;
  observed_at: string;
  observed_uptime_ms: number;
  collection: { started_at_ms: number; ended_at_ms: number };
  evidence_failures: EvidenceFailure[];
}

function envelope(c: Checker, o: Record<string, unknown>, record: string): EnvelopeCommon | undefined {
  if (o.schema_version !== LIVENESS_SCHEMA_VERSION) c.fail("schema_version");
  if (o.record !== record) c.fail("record");
  const s = subject(c, o.subject, "subject");
  const boot_id = c.nullableLabel(o.boot_id, "boot_id");
  const config_generation = c.uint(o.config_generation, "config_generation");
  const sequence = c.uint(o.sequence, "sequence");
  if (sequence === 0) c.fail("sequence");
  const observed_at = c.instant(o.observed_at, "observed_at");
  const observed_uptime_ms = c.uint(o.observed_uptime_ms, "observed_uptime_ms");
  const col = collection(c, o.collection, "collection");
  const failures = evidenceFailures(c, o.evidence_failures, "evidence_failures");
  if (c.failures.length > 0 || !s || boot_id === undefined || config_generation === undefined || sequence === undefined ||
      observed_at === undefined || observed_uptime_ms === undefined || !col || !failures) return undefined;
  return { subject: s, boot_id, config_generation, sequence, observed_at, observed_uptime_ms, collection: col, evidence_failures: failures };
}

// ---------------------------------------------------------------------------
// daemon.json
// ---------------------------------------------------------------------------
/** The recorder hooks the full daemon must report wired; a missing flag reads evidence_incomplete. */
export const REQUIRED_RECORDER_HOOKS = Object.freeze([
  "emission_tick", "verified_admission", "primary_confirmation", "pending_evidence", "canary_slot", "heartbeat_flush",
] as const);
export type RecorderHook = (typeof REQUIRED_RECORDER_HOOKS)[number];

export type LockRecoveryField =
  | { state: "not_instrumented" }
  | { state: "instrumented"; count: number; last_at_ms: number | null };

export interface CanaryConfirmationRecord {
  seq: number;
  captured_at_ms: number;
  confirmed_at_ms: number;
  subject_uid: number;
  dest_ip: string;
  dest_port: number;
  dest_protocol: "tcp" | "udp";
  delivery: "live" | "durable_wal";
}
export interface CanaryFailureRecord { seq: number; admitted_at_ms: number; failed_at_ms: number }
export interface CanaryLateRecord { seq: number; admitted_at_ms: number; settled_at_ms: number }
export interface CanaryAllowSighting { captured_at_ms: number; principal: "agent" | "gate" }
/** The observer's retained allow sighting: the daemon's sighting tagged with the daemon instance that reported it. */
export interface RetainedCanaryAllowSighting extends CanaryAllowSighting { daemon_instance: string }
export interface DaemonCanaryEvidence {
  adapter: "uid" | "unsupported";
  last_confirmation: CanaryConfirmationRecord | null;
  last_failure: CanaryFailureRecord | null;
  last_late: CanaryLateRecord | null;
  failure_count: number;
  late_count: number;
  last_destination_allowed: CanaryAllowSighting | null;
}

export interface DaemonRecord extends EnvelopeCommon {
  daemon_instance: string;
  /** The daemon's uptime at instance start, from the same uptime clock as the reader. */
  instance_started_uptime_ms: number | null;
  daemon_period_ms: number;
  raw: {
    process: { pid: number };
    hooks: Partial<Record<RecorderHook, boolean>>;
    lock_recovery: LockRecoveryField;
    detector: { last_evaluate_at_ms: number | null; stalled: boolean };
    heartbeat: { last_durable_flush_at_ms: number | null };
    pending_evidence: { oldest_unresolved_age_ms: number | null; ingress_loss_pending: number; coalesced_pending: number; last_rejection_at_ms: number | null };
    decisions: { verified_admissions: number; primary_confirmations: number; last_natural_primary_at_ms: number | null };
    canary: DaemonCanaryEvidence;
    lease: { deadline_ms: number | null };
  };
}

function canaryEvidence(c: Checker, value: unknown, path: string): DaemonCanaryEvidence | undefined {
  const o = c.object(value, path, ["adapter", "last_confirmation", "last_failure", "last_late", "failure_count", "late_count", "last_destination_allowed"]);
  if (!o) return undefined;
  const adapter = c.enumeration(o.adapter, `${path}.adapter`, ["uid", "unsupported"] as const);
  let last_confirmation: CanaryConfirmationRecord | null | undefined = null;
  if (o.last_confirmation !== null) {
    const p = `${path}.last_confirmation`;
    const r = c.object(o.last_confirmation, p, ["seq", "captured_at_ms", "confirmed_at_ms", "subject_uid", "dest_ip", "dest_port", "dest_protocol", "delivery"]);
    if (r) {
      const seq = c.uint(r.seq, `${p}.seq`);
      const captured_at_ms = c.uint(r.captured_at_ms, `${p}.captured_at_ms`);
      const confirmed_at_ms = c.uint(r.confirmed_at_ms, `${p}.confirmed_at_ms`);
      const subject_uid = c.uint(r.subject_uid, `${p}.subject_uid`, UINT32_MAX);
      const dest_ip = c.label(r.dest_ip, `${p}.dest_ip`);
      const dest_port = c.uint(r.dest_port, `${p}.dest_port`, PORT_MAX);
      const dest_protocol = c.enumeration(r.dest_protocol, `${p}.dest_protocol`, ["tcp", "udp"] as const);
      const delivery = c.enumeration(r.delivery, `${p}.delivery`, ["live", "durable_wal"] as const);
      last_confirmation = seq === undefined || captured_at_ms === undefined || confirmed_at_ms === undefined || subject_uid === undefined ||
        dest_ip === undefined || dest_port === undefined || !dest_protocol || !delivery
        ? undefined
        : { seq, captured_at_ms, confirmed_at_ms, subject_uid, dest_ip, dest_port, dest_protocol, delivery };
    } else last_confirmation = undefined;
  }
  let last_failure: CanaryFailureRecord | null | undefined = null;
  if (o.last_failure !== null) {
    const p = `${path}.last_failure`;
    const r = c.object(o.last_failure, p, ["seq", "admitted_at_ms", "failed_at_ms"]);
    const seq = r ? c.uint(r.seq, `${p}.seq`) : undefined;
    const admitted_at_ms = r ? c.uint(r.admitted_at_ms, `${p}.admitted_at_ms`) : undefined;
    const failed_at_ms = r ? c.uint(r.failed_at_ms, `${p}.failed_at_ms`) : undefined;
    last_failure = seq === undefined || admitted_at_ms === undefined || failed_at_ms === undefined ? undefined : { seq, admitted_at_ms, failed_at_ms };
  }
  let last_late: CanaryLateRecord | null | undefined = null;
  if (o.last_late !== null) {
    const p = `${path}.last_late`;
    const r = c.object(o.last_late, p, ["seq", "admitted_at_ms", "settled_at_ms"]);
    const seq = r ? c.uint(r.seq, `${p}.seq`) : undefined;
    const admitted_at_ms = r ? c.uint(r.admitted_at_ms, `${p}.admitted_at_ms`) : undefined;
    const settled_at_ms = r ? c.uint(r.settled_at_ms, `${p}.settled_at_ms`) : undefined;
    last_late = seq === undefined || admitted_at_ms === undefined || settled_at_ms === undefined ? undefined : { seq, admitted_at_ms, settled_at_ms };
  }
  const failure_count = c.uint(o.failure_count, `${path}.failure_count`);
  const late_count = c.uint(o.late_count, `${path}.late_count`);
  let last_destination_allowed: CanaryAllowSighting | null | undefined = null;
  if (o.last_destination_allowed !== null) {
    const p = `${path}.last_destination_allowed`;
    const r = c.object(o.last_destination_allowed, p, ["captured_at_ms", "principal"]);
    const captured_at_ms = r ? c.uint(r.captured_at_ms, `${p}.captured_at_ms`) : undefined;
    const principal = r ? c.enumeration(r.principal, `${p}.principal`, ["agent", "gate"] as const) : undefined;
    last_destination_allowed = captured_at_ms === undefined || !principal ? undefined : { captured_at_ms, principal };
  }
  if (!adapter || last_confirmation === undefined || last_failure === undefined || last_late === undefined ||
      failure_count === undefined || late_count === undefined || last_destination_allowed === undefined) return undefined;
  return { adapter, last_confirmation, last_failure, last_late, failure_count, late_count, last_destination_allowed };
}

export type ParsedRecord<T> = { ok: true; value: T } | { ok: false; failures: string[] };

/** Strictly parse a daemon record; any failure refuses the whole record for the wall. */
export function parseDaemonRecord(value: unknown): ParsedRecord<DaemonRecord> {
  const c = new Checker();
  const o = c.object(value, "daemon", [...ENVELOPE_COMMON, "daemon_instance", "instance_started_uptime_ms", "daemon_period_ms"],
    [...ENVELOPE_COMMON, "daemon_instance", "daemon_period_ms"]);
  if (!o) return { ok: false, failures: c.failures };
  const env = envelope(c, o, "daemon");
  const daemon_instance = c.label(o.daemon_instance, "daemon_instance");
  const instance_started_uptime_ms = "instance_started_uptime_ms" in o ? c.uint(o.instance_started_uptime_ms, "instance_started_uptime_ms") : null;
  // A record cannot nominate a longer trusted lifetime than the installed schema.
  if (o.daemon_period_ms !== DAEMON_PERIOD) c.fail("daemon_period_ms");
  const raw = c.object(o.raw, "raw", ["process", "hooks", "lock_recovery", "detector", "heartbeat", "pending_evidence", "decisions", "canary", "lease"]);
  if (!raw || !env || daemon_instance === undefined || instance_started_uptime_ms === undefined) return { ok: false, failures: c.failures };

  const proc = c.object(raw.process, "raw.process", ["pid"]);
  const pid = proc ? c.uint(proc.pid, "raw.process.pid", UINT32_MAX) : undefined;
  if (pid === 0) c.fail("raw.process.pid");
  const hooksObject = c.object(raw.hooks, "raw.hooks", REQUIRED_RECORDER_HOOKS, []);
  const hooks: Partial<Record<RecorderHook, boolean>> = {};
  if (hooksObject) for (const name of REQUIRED_RECORDER_HOOKS) {
    if (name in hooksObject) { const v = c.bool(hooksObject[name], `raw.hooks.${name}`); if (v !== undefined) hooks[name] = v; }
  }
  let lock_recovery: LockRecoveryField | undefined;
  const lock = raw.lock_recovery as Record<string, unknown> | null;
  if (lock !== null && typeof lock === "object" && !Array.isArray(lock) && lock.state === "not_instrumented") {
    if (c.object(lock, "raw.lock_recovery", ["state"])) lock_recovery = { state: "not_instrumented" };
  } else {
    const l = c.object(raw.lock_recovery, "raw.lock_recovery", ["state", "count", "last_at_ms"]);
    if (l) {
      if (l.state !== "instrumented") c.fail("raw.lock_recovery.state");
      const count = c.uint(l.count, "raw.lock_recovery.count");
      const last_at_ms = c.nullableUint(l.last_at_ms, "raw.lock_recovery.last_at_ms");
      if (l.state === "instrumented" && count !== undefined && last_at_ms !== undefined) lock_recovery = { state: "instrumented", count, last_at_ms };
    }
  }
  const det = c.object(raw.detector, "raw.detector", ["last_evaluate_at_ms", "stalled"]);
  const last_evaluate_at_ms = det ? c.nullableUint(det.last_evaluate_at_ms, "raw.detector.last_evaluate_at_ms") : undefined;
  const stalled = det ? c.bool(det.stalled, "raw.detector.stalled") : undefined;
  const hb = c.object(raw.heartbeat, "raw.heartbeat", ["last_durable_flush_at_ms"]);
  const last_durable_flush_at_ms = hb ? c.nullableUint(hb.last_durable_flush_at_ms, "raw.heartbeat.last_durable_flush_at_ms") : undefined;
  const pe = c.object(raw.pending_evidence, "raw.pending_evidence", ["oldest_unresolved_age_ms", "ingress_loss_pending", "coalesced_pending", "last_rejection_at_ms"]);
  const oldest_unresolved_age_ms = pe ? c.nullableUint(pe.oldest_unresolved_age_ms, "raw.pending_evidence.oldest_unresolved_age_ms") : undefined;
  const ingress_loss_pending = pe ? c.uint(pe.ingress_loss_pending, "raw.pending_evidence.ingress_loss_pending") : undefined;
  const coalesced_pending = pe ? c.uint(pe.coalesced_pending, "raw.pending_evidence.coalesced_pending") : undefined;
  const last_rejection_at_ms = pe ? c.nullableUint(pe.last_rejection_at_ms, "raw.pending_evidence.last_rejection_at_ms") : undefined;
  const dec = c.object(raw.decisions, "raw.decisions", ["verified_admissions", "primary_confirmations", "last_natural_primary_at_ms"]);
  const verified_admissions = dec ? c.uint(dec.verified_admissions, "raw.decisions.verified_admissions") : undefined;
  const primary_confirmations = dec ? c.uint(dec.primary_confirmations, "raw.decisions.primary_confirmations") : undefined;
  const last_natural_primary_at_ms = dec ? c.nullableUint(dec.last_natural_primary_at_ms, "raw.decisions.last_natural_primary_at_ms") : undefined;
  const canary = canaryEvidence(c, raw.canary, "raw.canary");
  const lease = c.object(raw.lease, "raw.lease", ["deadline_ms"]);
  const deadline_ms = lease ? c.nullableUint(lease.deadline_ms, "raw.lease.deadline_ms") : undefined;
  if (c.failures.length > 0 || pid === undefined || !lock_recovery || last_evaluate_at_ms === undefined || stalled === undefined ||
      last_durable_flush_at_ms === undefined || oldest_unresolved_age_ms === undefined || ingress_loss_pending === undefined ||
      coalesced_pending === undefined || last_rejection_at_ms === undefined || verified_admissions === undefined ||
      primary_confirmations === undefined || last_natural_primary_at_ms === undefined || !canary || deadline_ms === undefined) {
    return { ok: false, failures: c.failures.length > 0 ? c.failures : ["raw"] };
  }
  return {
    ok: true,
    value: {
      ...env, daemon_instance, instance_started_uptime_ms, daemon_period_ms: DAEMON_PERIOD,
      raw: {
        process: { pid }, hooks, lock_recovery,
        detector: { last_evaluate_at_ms, stalled },
        heartbeat: { last_durable_flush_at_ms },
        pending_evidence: { oldest_unresolved_age_ms, ingress_loss_pending, coalesced_pending, last_rejection_at_ms },
        decisions: { verified_admissions, primary_confirmations, last_natural_primary_at_ms },
        canary, lease: { deadline_ms },
      },
    },
  };
}

// ---------------------------------------------------------------------------
// observer.json
// ---------------------------------------------------------------------------
export interface RecoverySampleRef { sequence: number; observed_uptime_ms: number }
export interface ComponentRecovery { samples: RecoverySampleRef[]; fault_uptime_ms: number | null }
export interface ObserverWallPart {
  daemon_ref: { daemon_instance: string; sequence: number } | null;
  availability: { status: "live" | "not_live" | "unresponsive"; resolved_at_ms: number | null };
  full_service: { loaded: boolean; latched: boolean; pid: number | null; start_identity: string | null; last_charge_at_ms: number | null };
  session: "full" | "safe_mode_only" | "logged_out" | "reboot_no_login";
  canary_integrity: { passed: boolean; checked_at_ms: number } | null;
  /** Required and nullable: a missing key never parses, so a missing fault carrier can never read as no fault. */
  canary_allow_sighting: RetainedCanaryAllowSighting | null;
  recovery: ComponentRecovery;
}
export interface ObserverAgentPart {
  census: { status: "ok" | "unavailable"; samples: StoredCensusSample[] };
  gateway: { pid: number; uid: number; start_identity: string; generation: string; alive: boolean } | null;
  optional_reply: { required: boolean; last_success_at_ms: number | null; last_failure_at_ms: number | null } | null;
  mcp: { stale_child: boolean } | null;
  recovery: ComponentRecovery;
}
export interface ObserverEnvelope extends EnvelopeCommon {
  observer_instance: string;
  observer_period_ms: number;
}
/** Each component part parses on its own, so a bad agent subtree never stops the wall reading its own part. */
export type ParsedObserver =
  | { ok: false; failures: string[] }
  | { ok: true; envelope: ObserverEnvelope; wall: ParsedRecord<ObserverWallPart>; agent: ParsedRecord<ObserverAgentPart> };

function recovery(c: Checker, value: unknown, path: string): ComponentRecovery | undefined {
  const o = c.object(value, path, ["samples", "fault_uptime_ms"]);
  if (!o) return undefined;
  const list = c.array(o.samples, `${path}.samples`, RECOVERY_SAMPLES_PER_COMPONENT);
  const samples: RecoverySampleRef[] = [];
  list?.forEach((item, index) => {
    const r = c.object(item, `${path}.samples[${index}]`, ["sequence", "observed_uptime_ms"]);
    const sequence = r ? c.uint(r.sequence, `${path}.samples[${index}].sequence`) : undefined;
    const observed_uptime_ms = r ? c.uint(r.observed_uptime_ms, `${path}.samples[${index}].observed_uptime_ms`) : undefined;
    if (sequence !== undefined && observed_uptime_ms !== undefined) samples.push({ sequence, observed_uptime_ms });
  });
  const fault_uptime_ms = c.nullableUint(o.fault_uptime_ms, `${path}.fault_uptime_ms`);
  if (!list || fault_uptime_ms === undefined) return undefined;
  return { samples, fault_uptime_ms };
}

function wallPart(raw: Record<string, unknown>, recoveryValue: unknown): ParsedRecord<ObserverWallPart> {
  const c = new Checker();
  let daemon_ref: ObserverWallPart["daemon_ref"] | undefined = null;
  if (raw.daemon_ref !== null) {
    const r = c.object(raw.daemon_ref, "raw.daemon_ref", ["daemon_instance", "sequence"]);
    const daemon_instance = r ? c.label(r.daemon_instance, "raw.daemon_ref.daemon_instance") : undefined;
    const sequence = r ? c.uint(r.sequence, "raw.daemon_ref.sequence") : undefined;
    daemon_ref = daemon_instance === undefined || sequence === undefined ? undefined : { daemon_instance, sequence };
  }
  const av = c.object(raw.availability, "raw.availability", ["status", "resolved_at_ms"]);
  const status = av ? c.enumeration(av.status, "raw.availability.status", ["live", "not_live", "unresponsive"] as const) : undefined;
  const resolved_at_ms = av ? c.nullableUint(av.resolved_at_ms, "raw.availability.resolved_at_ms") : undefined;
  const fs = c.object(raw.full_service, "raw.full_service", ["loaded", "latched", "pid", "start_identity", "last_charge_at_ms"]);
  const loaded = fs ? c.bool(fs.loaded, "raw.full_service.loaded") : undefined;
  const latched = fs ? c.bool(fs.latched, "raw.full_service.latched") : undefined;
  const pid = fs ? c.nullableUint(fs.pid, "raw.full_service.pid", UINT32_MAX) : undefined;
  const start_identity = fs ? c.nullableLabel(fs.start_identity, "raw.full_service.start_identity") : undefined;
  const last_charge_at_ms = fs ? c.nullableUint(fs.last_charge_at_ms, "raw.full_service.last_charge_at_ms") : undefined;
  const session = c.enumeration(raw.session, "raw.session", ["full", "safe_mode_only", "logged_out", "reboot_no_login"] as const);
  let canary_integrity: ObserverWallPart["canary_integrity"] | undefined = null;
  if (raw.canary_integrity !== null) {
    const r = c.object(raw.canary_integrity, "raw.canary_integrity", ["passed", "checked_at_ms"]);
    const passed = r ? c.bool(r.passed, "raw.canary_integrity.passed") : undefined;
    const checked_at_ms = r ? c.uint(r.checked_at_ms, "raw.canary_integrity.checked_at_ms") : undefined;
    canary_integrity = passed === undefined || checked_at_ms === undefined ? undefined : { passed, checked_at_ms };
  }
  let canary_allow_sighting: ObserverWallPart["canary_allow_sighting"] | undefined = null;
  if (raw.canary_allow_sighting !== null) {
    const p = "raw.canary_allow_sighting";
    const r = c.object(raw.canary_allow_sighting, p, ["captured_at_ms", "principal", "daemon_instance"]);
    const captured_at_ms = r ? c.uint(r.captured_at_ms, `${p}.captured_at_ms`) : undefined;
    // The same closed principal set as the daemon's sighting: operator and other subjects never parse.
    const principal = r ? c.enumeration(r.principal, `${p}.principal`, ["agent", "gate"] as const) : undefined;
    const daemon_instance = r ? c.label(r.daemon_instance, `${p}.daemon_instance`) : undefined;
    canary_allow_sighting = captured_at_ms === undefined || !principal || daemon_instance === undefined ? undefined : { captured_at_ms, principal, daemon_instance };
  }
  const rec = recovery(c, recoveryValue, "recovery.wall");
  if (c.failures.length > 0 || daemon_ref === undefined || !status || resolved_at_ms === undefined || loaded === undefined ||
      latched === undefined || pid === undefined || start_identity === undefined || last_charge_at_ms === undefined ||
      !session || canary_integrity === undefined || canary_allow_sighting === undefined || !rec) return { ok: false, failures: c.failures.length > 0 ? c.failures : ["raw"] };
  return {
    ok: true,
    value: { daemon_ref, availability: { status, resolved_at_ms }, full_service: { loaded, latched, pid, start_identity, last_charge_at_ms }, session, canary_integrity, canary_allow_sighting, recovery: rec },
  };
}

/** Strictly parse one stored census sample. */
export function parseStoredCensusSample(c: Checker, value: unknown, path: string): StoredCensusSample | undefined {
  const o = c.object(value, path, ["observed_at", "observed_uptime_ms", "boot_id", "gateway", "rows", "other_rows"]);
  if (!o) return undefined;
  const observed_at = c.instant(o.observed_at, `${path}.observed_at`);
  const observed_uptime_ms = c.uint(o.observed_uptime_ms, `${path}.observed_uptime_ms`);
  const boot_id = c.label(o.boot_id, `${path}.boot_id`);
  const g = c.object(o.gateway, `${path}.gateway`, ["pid", "start_identity", "uid", "generation"]);
  const pid = g ? c.uint(g.pid, `${path}.gateway.pid`, UINT32_MAX) : undefined;
  const start_identity = g ? c.label(g.start_identity, `${path}.gateway.start_identity`) : undefined;
  const uid = g ? c.uint(g.uid, `${path}.gateway.uid`, UINT32_MAX) : undefined;
  const generation = g ? c.label(g.generation, `${path}.gateway.generation`) : undefined;
  const list = c.array(o.rows, `${path}.rows`, CENSUS_PID_ROWS);
  const rows: StoredCensusSample["rows"] = [];
  list?.forEach((item, index) => {
    const p = `${path}.rows[${index}]`;
    const r = c.object(item, p, ["local", "foreign", "tcp_state", "rxbytes", "txbytes", "gencnt"]);
    if (!r) return;
    const address = (value: unknown, at: string) => typeof value === "string" && value.length <= CENSUS_ADDRESS_TEXT_MAX ? c.label(value, at) : c.fail(at);
    const local = address(r.local, `${p}.local`);
    const foreign = address(r.foreign, `${p}.foreign`);
    const tcp_state = typeof r.tcp_state === "string" && TCP_STATES.has(r.tcp_state) ? r.tcp_state : c.fail(`${p}.tcp_state`);
    const rxbytes = c.uint(r.rxbytes, `${p}.rxbytes`);
    const txbytes = c.uint(r.txbytes, `${p}.txbytes`);
    const gencnt = typeof r.gencnt === "string" && HEX.test(r.gencnt) && r.gencnt.length <= GENCNT_HEX_DIGITS ? r.gencnt : c.fail(`${p}.gencnt`);
    if (local && foreign && tcp_state && rxbytes !== undefined && txbytes !== undefined && gencnt) rows.push({ local, foreign, tcp_state, rxbytes, txbytes, gencnt });
  });
  const other_rows = c.uint(o.other_rows, `${path}.other_rows`);
  if (!observed_at || observed_uptime_ms === undefined || !boot_id || pid === undefined || !start_identity || uid === undefined ||
      !generation || !list || other_rows === undefined) return undefined;
  return { observed_at, observed_uptime_ms, boot_id, gateway: { pid, start_identity, uid, generation }, rows, other_rows };
}

function agentPart(raw: Record<string, unknown>, recoveryValue: unknown): ParsedRecord<ObserverAgentPart> {
  const c = new Checker();
  const cen = c.object(raw.census, "raw.census", ["status", "samples"]);
  const status = cen ? c.enumeration(cen.status, "raw.census.status", ["ok", "unavailable"] as const) : undefined;
  // A stored series longer than a reader can need is refused rather than truncated.
  const list = cen ? c.array(cen.samples, "raw.census.samples", CENSUS_SAMPLES_MAX) : undefined;
  const samples: StoredCensusSample[] = [];
  list?.forEach((item, index) => { const s = parseStoredCensusSample(c, item, `raw.census.samples[${index}]`); if (s) samples.push(s); });
  let gateway: ObserverAgentPart["gateway"] | undefined = null;
  if (raw.gateway !== null) {
    const g = c.object(raw.gateway, "raw.gateway", ["pid", "uid", "start_identity", "generation", "alive"]);
    const pid = g ? c.uint(g.pid, "raw.gateway.pid", UINT32_MAX) : undefined;
    const uid = g ? c.uint(g.uid, "raw.gateway.uid", UINT32_MAX) : undefined;
    const start_identity = g ? c.label(g.start_identity, "raw.gateway.start_identity") : undefined;
    const generation = g ? c.label(g.generation, "raw.gateway.generation") : undefined;
    const alive = g ? c.bool(g.alive, "raw.gateway.alive") : undefined;
    gateway = pid === undefined || uid === undefined || !start_identity || !generation || alive === undefined ? undefined : { pid, uid, start_identity, generation, alive };
  }
  let optional_reply: ObserverAgentPart["optional_reply"] | undefined = null;
  if (raw.optional_reply !== null) {
    const r = c.object(raw.optional_reply, "raw.optional_reply", ["required", "last_success_at_ms", "last_failure_at_ms"]);
    const required = r ? c.bool(r.required, "raw.optional_reply.required") : undefined;
    const last_success_at_ms = r ? c.nullableUint(r.last_success_at_ms, "raw.optional_reply.last_success_at_ms") : undefined;
    const last_failure_at_ms = r ? c.nullableUint(r.last_failure_at_ms, "raw.optional_reply.last_failure_at_ms") : undefined;
    optional_reply = required === undefined || last_success_at_ms === undefined || last_failure_at_ms === undefined ? undefined : { required, last_success_at_ms, last_failure_at_ms };
  }
  let mcp: ObserverAgentPart["mcp"] | undefined = null;
  if (raw.mcp !== null) {
    const r = c.object(raw.mcp, "raw.mcp", ["stale_child"]);
    const stale_child = r ? c.bool(r.stale_child, "raw.mcp.stale_child") : undefined;
    mcp = stale_child === undefined ? undefined : { stale_child };
  }
  const rec = recovery(c, recoveryValue, "recovery.agent");
  if (c.failures.length > 0 || !status || !list || gateway === undefined || optional_reply === undefined || mcp === undefined || !rec) {
    return { ok: false, failures: c.failures.length > 0 ? c.failures : ["raw"] };
  }
  return { ok: true, value: { census: { status, samples }, gateway, optional_reply, mcp, recovery: rec } };
}

// Must match the record assembly in server/src/castle-wall/liveness/observer.ts; the observer parity test reads both lists.
export const OBSERVER_WALL_RAW = ["daemon_ref", "availability", "full_service", "session", "canary_integrity", "canary_allow_sighting"] as const;
export const OBSERVER_AGENT_RAW = ["census", "gateway", "optional_reply", "mcp"] as const;

/** Strictly parse an observer record. Envelope failures refuse both components. */
export function parseObserverRecord(value: unknown): ParsedObserver {
  const c = new Checker();
  const o = c.object(value, "observer", [...ENVELOPE_COMMON, "observer_instance", "observer_period_ms", "recovery"]);
  if (!o) return { ok: false, failures: c.failures };
  const env = envelope(c, o, "observer");
  const observer_instance = c.label(o.observer_instance, "observer_instance");
  if (o.observer_period_ms !== OBSERVER_PERIOD) c.fail("observer_period_ms");
  const raw = c.object(o.raw, "raw", [...OBSERVER_WALL_RAW, ...OBSERVER_AGENT_RAW]);
  const rec = c.object(o.recovery, "recovery", ["wall", "agent"]);
  if (c.failures.length > 0 || !env || observer_instance === undefined || !raw || !rec) return { ok: false, failures: c.failures.length > 0 ? c.failures : ["observer"] };
  return {
    ok: true,
    envelope: { ...env, observer_instance, observer_period_ms: OBSERVER_PERIOD },
    wall: wallPart(raw, rec.wall),
    agent: agentPart(raw, rec.agent),
  };
}

// ---------------------------------------------------------------------------
// config.json
// ---------------------------------------------------------------------------
export interface MessagingPrefix { prefix: string; source: string }
/** The optional MCP stale-child commissioning block. */
export interface McpConfig { harness_label: string; script_paths: string[] }
export interface PtbConfirmation {
  version: string;
  timeout_s: number;
  poll_interval_s: number;
  separate_get_updates_request: boolean;
  http_version: string;
  hermes_read_timeout_s: number;
}
/** Commissioning facts with every invalid or out-of-cap value already counted as unset. */
export interface LivenessConfig {
  agent_uid: number | undefined;
  gate_uid: number | null | undefined;
  launchd_leeway_ms: number | undefined;
  poll_backoff_cap_ms: number | undefined;
  messaging_ipv4: Ipv4Prefix[] | undefined;
  messaging_ipv6: MessagingPrefix[] | undefined;
  gateway_selector: { process_name: string } | undefined;
  ptb: PtbConfirmation | undefined;
  gateway_egress: "direct" | "gate_proxied" | undefined;
  /** null when the block is absent (no check), undefined when it is invalid. */
  mcp: McpConfig | null | undefined;
  commissioning: { wall: boolean | undefined; agent: boolean | undefined; alert_drill: boolean | undefined };
}
export type ParsedConfig =
  | { ok: false; failures: string[] }
  | { ok: true; value: LivenessConfig; wallInvalid: string[]; agentInvalid: string[] };

const CONFIG_FIELDS = [
  "schema_version", "record", "agent_uid", "gate_uid", "launchd_leeway_s", "poll_backoff_cap_s", "messaging",
  "gateway_selector", "ptb", "gateway_egress", "commissioning", "mcp",
] as const;
/** The launchd label charset, narrower than the general label rule, so no `/` or space reaches a launchctl argv. */
const LAUNCHD_LABEL_TEXT = /^[A-Za-z0-9._-]+$/;
// eslint-disable-next-line no-control-regex
const CONTROL_TEXT = /[\x00-\x1f\x7f]/;
/** Any character the process census splits argv on; must match the split in parseProcessRead in server/src/castle-wall/liveness/process-census.ts. */
const ARGV_SEPARATOR_TEXT = /\s/;

/**
 * Parse `config.json`. A bad `agent_uid`, `gate_uid`, `launchd_leeway_s`, wall
 * commissioned flag or a whole-file failure belongs to the wall; every other
 * field belongs to the agent. A bad value counts as unset.
 */
export function parseConfigRecord(value: unknown): ParsedConfig {
  const file = new Checker();
  const o = file.object(value, "config", CONFIG_FIELDS, ["schema_version", "record"]);
  if (o) {
    if (o.schema_version !== LIVENESS_SCHEMA_VERSION) file.fail("schema_version");
    if (o.record !== "config") file.fail("record");
  }
  if (!o || file.failures.length > 0) return { ok: false, failures: file.failures };
  const wall = new Checker();
  const agent = new Checker();
  const agent_uid = "agent_uid" in o ? wall.uint(o.agent_uid, "agent_uid", UINT32_MAX) : undefined;
  if (agent_uid === 0) wall.fail("agent_uid");
  const gate_uid = "gate_uid" in o ? wall.nullableUint(o.gate_uid, "gate_uid", UINT32_MAX) : null;
  const leeway = "launchd_leeway_s" in o ? wall.uint(o.launchd_leeway_s, "launchd_leeway_s", LAUNCHD_LEEWAY_MAX / SECOND) : undefined;
  const backoff = "poll_backoff_cap_s" in o ? agent.uint(o.poll_backoff_cap_s, "poll_backoff_cap_s", POLL_BACKOFF_CAP_MAX / SECOND) : undefined;
  let messaging_ipv4: Ipv4Prefix[] | undefined;
  let messaging_ipv6: MessagingPrefix[] | undefined;
  if ("messaging" in o) {
    const m = agent.object(o.messaging, "messaging", ["ipv4", "ipv6"]);
    const prefixes = (list: unknown, path: string): MessagingPrefix[] | undefined => {
      const items = agent.array(list, path, MAX_MESSAGING_PREFIXES);
      if (!items) return undefined;
      const out: MessagingPrefix[] = [];
      items.forEach((item, index) => {
        const r = agent.object(item, `${path}[${index}]`, ["prefix", "source"]);
        const prefix = r ? agent.label(r.prefix, `${path}[${index}].prefix`) : undefined;
        const source = r ? agent.label(r.source, `${path}[${index}].source`) : undefined;
        if (prefix && source) out.push({ prefix, source });
      });
      return out;
    };
    const v4 = m ? prefixes(m.ipv4, "messaging.ipv4") : undefined;
    const v6 = m ? prefixes(m.ipv6, "messaging.ipv6") : undefined;
    if (v4) {
      const parsed = v4.map(item => parseIpv4Prefix(item.prefix));
      parsed.forEach((p, index) => { if (p === null) agent.fail(`messaging.ipv4[${index}].prefix`); });
      if (parsed.every(p => p !== null)) messaging_ipv4 = parsed as Ipv4Prefix[];
    }
    // IPv6 prefixes are stored for a later census and never credited here.
    if (v6) {
      v6.forEach((item, index) => { if (!item.prefix.includes(":") || !item.prefix.includes("/")) agent.fail(`messaging.ipv6[${index}].prefix`); });
      messaging_ipv6 = v6;
    }
  }
  let gateway_selector: LivenessConfig["gateway_selector"];
  if ("gateway_selector" in o) {
    const g = agent.object(o.gateway_selector, "gateway_selector", ["process_name"]);
    const process_name = g ? agent.label(g.process_name, "gateway_selector.process_name") : undefined;
    if (process_name) gateway_selector = { process_name };
  }
  let ptb: PtbConfirmation | undefined;
  if ("ptb" in o) {
    const p = agent.object(o.ptb, "ptb", ["version", "timeout_s", "poll_interval_s", "separate_get_updates_request", "http_version", "hermes_read_timeout_s"]);
    const version = p ? agent.label(p.version, "ptb.version") : undefined;
    const timeout_s = p && typeof p.timeout_s === "number" && Number.isFinite(p.timeout_s) && p.timeout_s >= 0 ? p.timeout_s : agent.fail("ptb.timeout_s");
    const poll_interval_s = p && typeof p.poll_interval_s === "number" && Number.isFinite(p.poll_interval_s) && p.poll_interval_s >= 0 ? p.poll_interval_s : agent.fail("ptb.poll_interval_s");
    const separate = p ? agent.bool(p.separate_get_updates_request, "ptb.separate_get_updates_request") : undefined;
    const http_version = p ? agent.label(p.http_version, "ptb.http_version") : undefined;
    const read_s = p && typeof p.hermes_read_timeout_s === "number" && Number.isFinite(p.hermes_read_timeout_s) && p.hermes_read_timeout_s >= 0 ? p.hermes_read_timeout_s : agent.fail("ptb.hermes_read_timeout_s");
    if (version && timeout_s !== undefined && poll_interval_s !== undefined && separate !== undefined && http_version && read_s !== undefined) {
      ptb = { version, timeout_s, poll_interval_s, separate_get_updates_request: separate, http_version, hermes_read_timeout_s: read_s };
    }
  }
  const gateway_egress = "gateway_egress" in o ? agent.enumeration(o.gateway_egress, "gateway_egress", ["direct", "gate_proxied"] as const) : undefined;
  let mcp: McpConfig | null | undefined = null;
  if ("mcp" in o) {
    const m = agent.object(o.mcp, "mcp", ["harness_label", "script_paths"]);
    const harness_label = m && typeof m.harness_label === "string" && m.harness_label.length <= LABEL_BYTES && LAUNCHD_LABEL_TEXT.test(m.harness_label)
      ? m.harness_label : agent.fail("mcp.harness_label");
    const list = m ? agent.array(m.script_paths, "mcp.script_paths", MAX_MCP_SCRIPT_PATHS) : undefined;
    const script_paths: string[] = [];
    if (list && list.length === 0) agent.fail("mcp.script_paths");
    list?.forEach((item, index) => {
      // A path with whitespace can never equal one ps argv token, so its stale child would read not-stale; it is refused instead.
      // The whitespace class must match the argv token split in parseProcessRead in server/src/castle-wall/liveness/process-census.ts.
      const valid = typeof item === "string" && item.startsWith("/") && !CONTROL_TEXT.test(item) && !ARGV_SEPARATOR_TEXT.test(item) &&
        new TextEncoder().encode(item).length <= PATH_BYTES;
      if (valid) script_paths.push(item); else agent.fail(`mcp.script_paths[${index}]`);
    });
    mcp = harness_label !== undefined && list !== undefined && list.length > 0 && script_paths.length === list.length ? { harness_label, script_paths } : undefined;
  }
  let commissioning: LivenessConfig["commissioning"] = { wall: undefined, agent: undefined, alert_drill: undefined };
  if ("commissioning" in o) {
    const raw = o.commissioning;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) wall.fail("commissioning");
    else {
      const record = raw as Record<string, unknown>;
      for (const key of Object.keys(record)) if (!["wall", "agent", "alert_drill"].includes(key)) wall.fail(`commissioning.${key}`);
      commissioning = {
        wall: "wall" in record ? wall.bool(record.wall, "commissioning.wall") : undefined,
        agent: "agent" in record ? agent.bool(record.agent, "commissioning.agent") : undefined,
        alert_drill: "alert_drill" in record ? agent.bool(record.alert_drill, "commissioning.alert_drill") : undefined,
      };
    }
  }
  return {
    ok: true,
    value: {
      agent_uid, gate_uid, launchd_leeway_ms: leeway === undefined ? undefined : leeway * SECOND,
      poll_backoff_cap_ms: backoff === undefined ? undefined : backoff * SECOND,
      messaging_ipv4, messaging_ipv6, gateway_selector, ptb, gateway_egress, mcp, commissioning,
    },
    wallInvalid: wall.failures,
    agentInvalid: agent.failures,
  };
}

export { Checker as LivenessSchemaChecker };
