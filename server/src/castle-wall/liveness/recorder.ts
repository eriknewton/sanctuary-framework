/**
 * The full daemon's independent liveness telemetry recorder and the canary
 * drop-recording primary slot.
 *
 * The recorder publishes `daemon.json` after each emission tick evaluation and
 * never from an audit-append continuation, so a held audit sink cannot stop
 * it. A telemetry failure never disables enforcement or releases an audit
 * lock; it only makes observation fail closed. It adds no timers.
 */
import type { EmissionLivenessNotes, EmissionLivenessSnapshot } from "../audit/emission-liveness.js";
import {
  CANARY_SETTLE,
  CANARY_SLOT_REARM,
  COUNTER_MAX,
  DAEMON_PERIOD,
  DAEMON_RECORD_FILE,
  LIVENESS_SCHEMA_VERSION,
} from "./constants.js";
import { LivenessRecordPublisher, type PublisherFs } from "./record-store.js";
import {
  REQUIRED_RECORDER_HOOKS,
  type CanaryAllowSighting,
  type CanaryConfirmationRecord,
  type CanaryFailureRecord,
  type CanaryLateRecord,
  type DaemonCanaryEvidence,
  type RecorderHook,
} from "./schema.js";

/** Add one, saturating at COUNTER_MAX; a saturated count reads observation_invalid. */
export function saturatingIncrement(value: number): number {
  return value >= COUNTER_MAX ? COUNTER_MAX : value + 1;
}

// ---------------------------------------------------------------------------
// Canary slot.
// ---------------------------------------------------------------------------
export type CanarySlotState = "canary_IDLE" | "canary_PENDING" | "canary_EXPIRED" | "canary_COOLDOWN";

/** A verified live agent-subject drop for the exact canary tuple, as the audit consumer found it. */
export interface CanaryCandidate {
  seq: number;
  capturedAtMs: number;
  subjectUid: number;
  destIp: string;
  destPort: number;
  destProtocol: "tcp" | "udp";
}

/** The protection subjects whose canary drops and allows count, re-read per admission. */
export interface CanaryOriginSubjects {
  adapter: "uid" | "unsupported";
  agentUid: number | null;
  gateUid: number | null;
  /** Protection subject ids, `<fortress>/uid-<n>`, for the agent and gate uids. */
  agentSubject: string | null;
  gateSubject: string | null;
}

/**
 * The slot surface the audit consumer calls. Must match the `canarySlot`
 * option consumed in server/src/castle-wall/runtime/audit-consumer.ts.
 */
export interface CanarySlotPort {
  subjects(): CanaryOriginSubjects;
  admit(candidate: CanaryCandidate | null): boolean;
  settled(confirmed: boolean): void;
  noteDestinationAllowed(sighting: CanaryAllowSighting): void;
  stop(): void;
}

/**
 * One owned forced-primary canary slot. It admits only from IDLE, settles once,
 * expires past CANARY_SETTLE without releasing ownership, and re-arms only from
 * COOLDOWN once CANARY_SLOT_REARM has passed since admission.
 */
export class CanaryRecordingSlot implements CanarySlotPort {
  private state: CanarySlotState = "canary_IDLE";
  private pending: (CanaryCandidate & { admittedAtMs: number }) | null = null;
  private admittedAtMs: number | null = null;
  private stopped = false;
  private lastConfirmation: CanaryConfirmationRecord | null = null;
  private lastFailure: CanaryFailureRecord | null = null;
  private lastLate: CanaryLateRecord | null = null;
  private failureCount = 0;
  private lateCount = 0;
  private lastDestinationAllowed: CanaryAllowSighting | null = null;
  private justConfirmed = false;
  private admissions = 0;

  constructor(
    private readonly origin: () => CanaryOriginSubjects,
    private readonly now: () => number = Date.now,
  ) {}

  subjects(): CanaryOriginSubjects {
    return this.origin();
  }

  /** Advance time-driven transitions; the slot keeps no timer of its own. */
  private advance(): void {
    const now = this.now();
    // Past CANARY_SETTLE the slot expires but stays owned: it never releases on a deadline, only on settlement.
    if (this.state === "canary_PENDING" && this.pending !== null && now - this.pending.admittedAtMs > CANARY_SETTLE) {
      this.state = "canary_EXPIRED";
    }
    if (this.state === "canary_COOLDOWN" && this.admittedAtMs !== null && now - this.admittedAtMs >= CANARY_SLOT_REARM) {
      this.state = "canary_IDLE";
    }
  }

  currentState(): CanarySlotState {
    this.advance();
    return this.state;
  }

  admit(candidate: CanaryCandidate | null): boolean {
    if (candidate === null || this.stopped) return false;
    this.advance();
    if (this.state !== "canary_IDLE") return false;
    const now = this.now();
    this.state = "canary_PENDING";
    this.pending = { ...candidate, admittedAtMs: now };
    this.admittedAtMs = now;
    this.admissions = saturatingIncrement(this.admissions);
    return true;
  }

  settled(confirmed: boolean): void {
    // A settlement after a stop-time failure is ignored, never a confirmation.
    if (this.stopped) return;
    this.settle(confirmed);
  }

  private settle(confirmed: boolean): void {
    this.advance();
    const pending = this.pending;
    if (pending === null) return;
    const now = this.now();
    if (this.state === "canary_EXPIRED") {
      // A late settlement is recorded as late and never as a confirmation.
      this.lastLate = { seq: pending.seq, admitted_at_ms: pending.admittedAtMs, settled_at_ms: now };
      this.lateCount = saturatingIncrement(this.lateCount);
    } else if (this.state === "canary_PENDING") {
      if (confirmed) {
        this.lastConfirmation = {
          seq: pending.seq,
          captured_at_ms: pending.capturedAtMs,
          confirmed_at_ms: now,
          subject_uid: pending.subjectUid,
          dest_ip: pending.destIp,
          dest_port: pending.destPort,
          dest_protocol: pending.destProtocol,
          delivery: "live",
        };
        this.justConfirmed = true;
      } else {
        this.lastFailure = { seq: pending.seq, admitted_at_ms: pending.admittedAtMs, failed_at_ms: now };
        this.failureCount = saturatingIncrement(this.failureCount);
      }
    } else return;
    this.pending = null;
    this.state = "canary_COOLDOWN";
    this.advance();
  }

  noteDestinationAllowed(sighting: CanaryAllowSighting): void {
    this.lastDestinationAllowed = { ...sighting };
  }

  /** Consumer stop settles an owned slot as a failure, and every later settlement is ignored. */
  stop(): void {
    if (this.stopped) return;
    this.settle(false);
    this.stopped = true;
  }

  /** True once after a canary confirmation, so the recorder does not count it as natural workload. */
  takeJustConfirmed(): boolean {
    const value = this.justConfirmed;
    this.justConfirmed = false;
    return value;
  }

  admissionCount(): number {
    return this.admissions;
  }

  evidence(): DaemonCanaryEvidence {
    return {
      adapter: this.origin().adapter,
      last_confirmation: this.lastConfirmation === null ? null : { ...this.lastConfirmation },
      last_failure: this.lastFailure === null ? null : { ...this.lastFailure },
      last_late: this.lastLate === null ? null : { ...this.lastLate },
      failure_count: this.failureCount,
      late_count: this.lateCount,
      last_destination_allowed: this.lastDestinationAllowed === null ? null : { ...this.lastDestinationAllowed },
    };
  }
}

// ---------------------------------------------------------------------------
// Recorder.
// ---------------------------------------------------------------------------
export interface PendingEvidenceCounts {
  ingressLossPending: number;
  coalescedPending: number;
}

export interface LivenessRecorderOptions {
  fortressPath: string;
  subject: { fortress_id: string; host_id: string; platform: string; operator_uid: number };
  /** Read once at start; null publishes `boot_id: null`, which reads time_untrusted. */
  bootId: string | null;
  /** The daemon's uptime at instance start, from the same uptime clock as the reader. */
  instanceStartedUptimeMs: number;
  /** Current uptime in milliseconds, the same non-pausing clock the reader uses. */
  uptimeMs: () => number;
  now?: () => number;
  pid: number;
  instance: string;
  origin: () => CanaryOriginSubjects;
  publisherFs?: PublisherFs;
  /** Must match createLivenessRecorder in runtime/macos-daemon.ts: seed before observing subsequent events. */
  lockRecovery: {
    count: number;
    lastAtMs: number | null;
    subscribe: (listener: (atMs: number) => void) => void;
  };
}

export class LivenessRecorder {
  readonly canarySlot: CanaryRecordingSlot;
  private readonly now: () => number;
  private readonly publisher: LivenessRecordPublisher;
  private readonly wired = new Set<RecorderHook>();
  private sequence = 0;
  private detector: (() => Pick<EmissionLivenessSnapshot, "lastEvaluateAtMs" | "stalled" | "firstUnemittedDecisionAtMs">) | null = null;
  private pending: (() => PendingEvidenceCounts) | null = null;
  private lease: () => number | null = () => null;
  private lastDurableFlushAtMs: number | null = null;
  private lastRejectionAtMs: number | null = null;
  private lastNaturalPrimaryAtMs: number | null = null;
  private verifiedAdmissions = 0;
  private primaryConfirmations = 0;
  private publishFailures = 0;
  private lockRecoveryCount: number;
  private lastLockRecoveryAtMs: number | null;
  /** The drain in flight and the one handled continuation subscribed to it; queued ticks reuse it. */
  private publishing: { drain: Promise<void>; handled: Promise<void> } | null = null;

  constructor(private readonly options: LivenessRecorderOptions) {
    this.now = options.now ?? Date.now;
    // Require this daemon's audit source so missing instrumentation cannot silently publish complete evidence.
    this.lockRecoveryCount = Math.min(COUNTER_MAX, options.lockRecovery.count);
    this.lastLockRecoveryAtMs = options.lockRecovery.lastAtMs;
    options.lockRecovery.subscribe(atMs => {
      // Recovery observation has constant space and no audit writes or asynchronous work.
      this.lockRecoveryCount = saturatingIncrement(this.lockRecoveryCount);
      this.lastLockRecoveryAtMs = atMs;
    });
    this.canarySlot = new CanaryRecordingSlot(options.origin, this.now);
    this.publisher = new LivenessRecordPublisher({
      fortressPath: options.fortressPath,
      fileName: DAEMON_RECORD_FILE,
      instance: options.instance,
      // The claim orders this instance by the same boot and start uptime the record publishes.
      bootId: options.bootId,
      instanceStartedUptimeMs: options.instanceStartedUptimeMs,
      operatorUid: options.subject.operator_uid,
      fs: options.publisherFs,
    });
  }

  /** Wrap the emission-liveness feed so verified admissions and primary confirmations are counted. */
  bindEmissionNotes(inner: EmissionLivenessNotes): EmissionLivenessNotes {
    this.wired.add("verified_admission");
    this.wired.add("primary_confirmation");
    return {
      noteDecision: source => {
        this.verifiedAdmissions = saturatingIncrement(this.verifiedAdmissions);
        inner.noteDecision(source);
      },
      noteEmission: () => {
        this.primaryConfirmations = saturatingIncrement(this.primaryConfirmations);
        if (!this.canarySlot.takeJustConfirmed()) this.lastNaturalPrimaryAtMs = this.now();
        inner.noteEmission();
      },
      noteRejection: reason => {
        this.lastRejectionAtMs = this.now();
        inner.noteRejection(reason);
      },
    };
  }

  /** Bind the emission tick's detector snapshot; the daemon calls `emissionTick()` after each evaluation. */
  bindEmissionTick(snapshot: () => Pick<EmissionLivenessSnapshot, "lastEvaluateAtMs" | "stalled" | "firstUnemittedDecisionAtMs">): void {
    this.detector = snapshot;
    this.wired.add("emission_tick");
  }

  bindPendingEvidence(snapshot: () => PendingEvidenceCounts): void {
    this.pending = snapshot;
    this.wired.add("pending_evidence");
  }

  /** Hand the canary slot to the flow consumer. */
  bindCanarySlot(): CanaryRecordingSlot {
    this.wired.add("canary_slot");
    return this.canarySlot;
  }

  bindHeartbeatFlush(): void {
    this.wired.add("heartbeat_flush");
  }

  bindLeaseDeadline(deadline: () => number | null): void {
    this.lease = deadline;
  }

  /**
   * Run one durable heartbeat flush. The flush time is recorded only after the
   * flush resolves, and never when the stop budget skipped it.
   */
  async flushHeartbeat(stopBudgetLapsed: boolean, flush: () => Promise<void>): Promise<void> {
    if (stopBudgetLapsed) return;
    await flush();
    this.lastDurableFlushAtMs = this.now();
  }

  /** Publish after an emission tick evaluation; never awaited by the tick, never tied to an audit append. */
  emissionTick(): Promise<void> {
    let record: unknown;
    try {
      record = this.buildRecord();
    } catch {
      this.publishFailures = saturatingIncrement(this.publishFailures);
      return Promise.resolve();
    }
    const drain = this.publisher.publish(record);
    // A tick queued behind a stalled drain gets that drain back from the publisher. The error accounting is attached
    // once per drain, never once per tick, so a publication that never settles retains one continuation, not one per tick.
    if (this.publishing !== null && this.publishing.drain === drain) return this.publishing.handled;
    const settle = (failed: boolean): void => {
      if (failed) this.publishFailures = saturatingIncrement(this.publishFailures);
      if (this.publishing?.drain === drain) this.publishing = null;
    };
    const handled = drain.then(() => settle(false), () => settle(true));
    this.publishing = { drain, handled };
    return handled;
  }

  /**
   * Retire publication at daemon stop: the waiting snapshot is dropped and no
   * later one is created or committed, so a stopping instance can never land a
   * record after its successor's.
   */
  retire(): void {
    this.publisher.retire();
  }

  stats(): { published: number; failures: number } {
    const s = this.publisher.stats();
    return { published: s.published, failures: Math.max(s.failures, this.publishFailures) };
  }

  buildRecord(): Record<string, unknown> {
    const started = this.now();
    const startedUptime = this.options.uptimeMs();
    this.sequence = saturatingIncrement(this.sequence);
    const detector = this.detector?.() ?? null;
    const pending = this.pending?.() ?? null;
    const hooks: Record<string, boolean> = {};
    for (const hook of REQUIRED_RECORDER_HOOKS) if (this.wired.has(hook)) hooks[hook] = true;
    const origin = this.options.origin();
    const ended = this.now();
    return {
      schema_version: LIVENESS_SCHEMA_VERSION,
      record: "daemon",
      subject: { ...this.options.subject, agent_uid: origin.agentUid },
      boot_id: this.options.bootId,
      config_generation: 0,
      sequence: this.sequence,
      observed_at: new Date(started).toISOString(),
      observed_uptime_ms: Math.floor(startedUptime),
      collection: { started_at_ms: started, ended_at_ms: Math.max(started, ended) },
      evidence_failures: [],
      daemon_instance: this.options.instance,
      instance_started_uptime_ms: Math.floor(this.options.instanceStartedUptimeMs),
      daemon_period_ms: DAEMON_PERIOD,
      raw: {
        process: { pid: this.options.pid },
        hooks,
        lock_recovery: { state: "instrumented", count: this.lockRecoveryCount, last_at_ms: this.lastLockRecoveryAtMs },
        detector: {
          last_evaluate_at_ms: detector?.lastEvaluateAtMs ?? null,
          stalled: detector?.stalled ?? false,
        },
        heartbeat: { last_durable_flush_at_ms: this.lastDurableFlushAtMs },
        pending_evidence: {
          oldest_unresolved_age_ms: detector?.firstUnemittedDecisionAtMs == null ? null : Math.max(0, started - detector.firstUnemittedDecisionAtMs),
          ingress_loss_pending: Math.min(COUNTER_MAX, pending?.ingressLossPending ?? 0),
          coalesced_pending: Math.min(COUNTER_MAX, pending?.coalescedPending ?? 0),
          last_rejection_at_ms: this.lastRejectionAtMs,
        },
        decisions: {
          verified_admissions: this.verifiedAdmissions,
          primary_confirmations: this.primaryConfirmations,
          last_natural_primary_at_ms: this.lastNaturalPrimaryAtMs,
        },
        canary: this.canarySlot.evidence(),
        lease: { deadline_ms: this.lease() },
      },
    };
  }
}
