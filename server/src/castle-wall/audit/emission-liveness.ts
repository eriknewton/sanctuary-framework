/**
 * Emission-liveness watchdog: the decided-vs-emitted divergence detector.
 *
 * WHY THIS EXISTS (Slice M, drill 2026-07-15 + 2026-07-17): the Castle Wall
 * macOS sysext kept ENFORCING (30/30 correct verdicts in the 07-17 re-drill)
 * while per-flow audit emission had silently STOPPED, and the #946 per-sign
 * watchdog could not fire because the stall is UPSTREAM of the sign call
 * (verdicts stop reaching `notifyVerdict` at all; root-cause analysis:
 * `Review/Sanctuary/SliceM_Emission_Stall_RootCause_2026-07-17.md`).
 * Per-call instrumentation cannot see flows that never produce calls, so the
 * loud-failure requirement needs a DIFFERENT layer: compare evidence that
 * enforcement decisions are happening against evidence that audit emission is
 * landing, and fail LOUD on divergence (AGENTS.md rule 5: never silently
 * degrade).
 *
 * WHAT IT IS: a small, pure state machine over three monotonic counters
 * (decided / emitted / rejected) plus an injected clock. The daemon feeds it
 * from every decision signal it can observe and ticks it periodically; when
 * decisions keep arriving but no emission has landed for a full grace window,
 * it transitions to STALLED exactly once and invokes the loud callback. The
 * first emission after a stall transitions back and invokes the recovery
 * callback. Zero decisions NEVER fire it: an idle wall with no traffic is
 * healthy, not stalled.
 *
 * DECISION SOURCES the daemon wires today:
 *   - `flow_decision_recorded` receipts from the sysext (each receipt is a
 *     decision the wall reports having made, whether or not it persists).
 *   - The periodic as-agent-uid egress probe (a daemon-initiated flow that an
 *     armed wall MUST adjudicate; counted only while a sysext subscriber is
 *     connected).
 *
 * HONEST BOUND (stated in the root-cause doc and the PR): under the confirmed
 * 07-17 stall localization, the sysext stops reporting decisions entirely, so
 * the receipt-fed signal goes quiet WITH the emission signal and this
 * watchdog stays quiet too. The signals that survive that failure mode are
 * (a) a Swift decided-counter taken at the very top of `handleNewFlow`,
 * heartbeat-piggybacked to the daemon, and (b) the as-uid egress probe
 * correlated with its own audit entry. (b) is wired here (slow cadence);
 * (a) is a Swift-side follow-up. This module deliberately accepts ANY
 * decision source so those feeds plug in without changing the detector.
 * Building this watchdog does NOT close Slice M; the real-world firing is
 * drill-owed on the signed host.
 */

/** Audit operation appended (result: "failure") when a stall is detected. */
export const EMISSION_STALL_AUDIT_OP = "audit_emission_stall";

/** Audit operation appended (result: "success") when emission recovers. */
export const EMISSION_STALL_RECOVERED_AUDIT_OP =
  "audit_emission_stall_recovered";

/** Greppable stderr prefix for the stall / recovery loud lines. */
export const EMISSION_STALL_LOG_PREFIX = "[slice-m-emission-stall]";

/**
 * Default grace window: decisions must keep arriving with NO emission for
 * this long before the stall fires. Generous relative to the per-event
 * persist latency (milliseconds) so an in-flight receipt-then-persist pair
 * can never false-positive, and short enough that the 07-17 signature
 * (12 minutes of decided traffic, zero entries) would have fired loudly
 * within the first minute.
 */
export const DEFAULT_EMISSION_STALL_GRACE_MS = 60_000;

/**
 * Default minimum decided-without-emission count before a stall may fire.
 * Two, not one: a single decision followed by a crash of its own persist is
 * already surfaced by the existing rejection/persistence-failure paths; the
 * divergence signature is decisions CONTINUING while emission stays flat.
 */
export const DEFAULT_EMISSION_STALL_MIN_DECISIONS = 2;

/** Read-only view of the watchdog's counters and stall state. */
export interface EmissionLivenessSnapshot {
  decidedTotal: number;
  emittedTotal: number;
  rejectedTotal: number;
  decidedSinceLastEmission: number;
  decidedBySource: Record<string, number>;
  lastEmissionAtMs: number | null;
  firstUnemittedDecisionAtMs: number | null;
  stalled: boolean;
  stallStartedAtMs: number | null;
}

/** Payload handed to `onStall` exactly once per stall episode. */
export interface EmissionStallFinding {
  kind: "emission_stall";
  decidedTotal: number;
  emittedTotal: number;
  rejectedTotal: number;
  decidedSinceLastEmission: number;
  decidedBySource: Record<string, number>;
  /** ms since the last successful emission; null when none has EVER landed. */
  msSinceLastEmissionMs: number | null;
  /** ms since the first decision of the current unemitted run. */
  msSinceFirstUnemittedDecisionMs: number;
}

/** Payload handed to `onRecovery` when an emission lands during a stall. */
export interface EmissionRecoveryFinding {
  kind: "emission_recovered";
  decidedTotal: number;
  emittedTotal: number;
  rejectedTotal: number;
  /** How many decisions arrived while the stall episode was active. */
  decidedDuringStall: number;
  stallDurationMs: number;
}

export interface EmissionLivenessWatchdogOptions {
  /** Injected clock (epoch ms). Defaults to Date.now. */
  now?: () => number;
  /** Grace window, ms. Must be a positive finite number. */
  graceMs?: number;
  /** Minimum decided-without-emission count. Must be an integer >= 1. */
  minDecisions?: number;
  /**
   * Invoked exactly once per stall episode, synchronously from `evaluate()`.
   * CONTRACT: the wirer owns its own error handling; a throwing callback
   * propagates out of `evaluate()` (fail-loud, never swallowed here). The
   * stall state transition has already been committed by the time the
   * callback runs, so a throwing callback can never cause a re-fire loop.
   */
  onStall: (finding: EmissionStallFinding) => void;
  /** Invoked once when emission resumes during a stall. Same error contract. */
  onRecovery: (finding: EmissionRecoveryFinding) => void;
}

/**
 * Decision/emission note surface the flow-event consumer depends on. Kept
 * narrow so the consumer does not care about clocks, ticking, or callbacks.
 */
export interface EmissionLivenessNotes {
  noteDecision(source: string): void;
  noteEmission(): void;
  noteRejection(reason: string): void;
}

export class EmissionLivenessWatchdog implements EmissionLivenessNotes {
  private readonly now: () => number;
  private readonly graceMs: number;
  private readonly minDecisions: number;
  private readonly onStall: (finding: EmissionStallFinding) => void;
  private readonly onRecovery: (finding: EmissionRecoveryFinding) => void;

  private decidedTotal = 0;
  private emittedTotal = 0;
  private rejectedTotal = 0;
  private decidedSinceLastEmission = 0;
  private decidedBySource = new Map<string, number>();
  private lastEmissionAtMs: number | null = null;
  private firstUnemittedDecisionAtMs: number | null = null;
  private stalled = false;
  private stallStartedAtMs: number | null = null;
  private decidedTotalAtStallStart = 0;

  constructor(options: EmissionLivenessWatchdogOptions) {
    const graceMs = options.graceMs ?? DEFAULT_EMISSION_STALL_GRACE_MS;
    if (!Number.isFinite(graceMs) || graceMs <= 0) {
      throw new Error(
        `EmissionLivenessWatchdog: graceMs must be a positive finite number (got ${String(
          options.graceMs
        )})`
      );
    }
    const minDecisions =
      options.minDecisions ?? DEFAULT_EMISSION_STALL_MIN_DECISIONS;
    if (!Number.isInteger(minDecisions) || minDecisions < 1) {
      throw new Error(
        `EmissionLivenessWatchdog: minDecisions must be an integer >= 1 (got ${String(
          options.minDecisions
        )})`
      );
    }
    this.now = options.now ?? Date.now;
    this.graceMs = graceMs;
    this.minDecisions = minDecisions;
    this.onStall = options.onStall;
    this.onRecovery = options.onRecovery;
  }

  /** Record one observed enforcement decision from `source`. */
  noteDecision(source: string): void {
    this.decidedTotal += 1;
    this.decidedSinceLastEmission += 1;
    this.decidedBySource.set(
      source,
      (this.decidedBySource.get(source) ?? 0) + 1
    );
    if (this.firstUnemittedDecisionAtMs === null) {
      this.firstUnemittedDecisionAtMs = this.now();
    }
  }

  /**
   * Record one successfully persisted enforcement emission. Resets the
   * unemitted run; if a stall episode is active, commits the recovery
   * transition BEFORE invoking the recovery callback.
   */
  noteEmission(): void {
    const nowMs = this.now();
    this.emittedTotal += 1;
    const wasStalled = this.stalled;
    const stallStartedAtMs = this.stallStartedAtMs;
    const decidedDuringStall =
      this.decidedTotal - this.decidedTotalAtStallStart;
    this.decidedSinceLastEmission = 0;
    this.firstUnemittedDecisionAtMs = null;
    this.lastEmissionAtMs = nowMs;
    this.stalled = false;
    this.stallStartedAtMs = null;
    if (wasStalled) {
      this.onRecovery({
        kind: "emission_recovered",
        decidedTotal: this.decidedTotal,
        emittedTotal: this.emittedTotal,
        rejectedTotal: this.rejectedTotal,
        decidedDuringStall,
        stallDurationMs:
          stallStartedAtMs === null ? 0 : Math.max(0, nowMs - stallStartedAtMs),
      });
    }
  }

  /**
   * Record a decision that arrived but was definitively NOT persisted as
   * enforcement evidence (validation reject, chain/signature reject, persist
   * error). Diagnostic counter only: the decision itself was already counted
   * by `noteDecision`, and a rejection is by definition not an emission, so
   * the divergence math needs no extra input here.
   */
  noteRejection(_reason: string): void {
    this.rejectedTotal += 1;
  }

  /**
   * Evaluate the divergence rule. Called periodically by the daemon's tick
   * timer (and directly by tests). Returns the finding when THIS call
   * committed the stall transition; null otherwise. Fires at most once per
   * stall episode.
   */
  evaluate(): EmissionStallFinding | null {
    if (this.stalled) return null;
    if (this.decidedSinceLastEmission < this.minDecisions) return null;
    const anchor = this.firstUnemittedDecisionAtMs;
    if (anchor === null) return null;
    const nowMs = this.now();
    if (nowMs - anchor < this.graceMs) return null;

    // Commit the transition BEFORE the callback so a throwing callback can
    // never re-fire the same episode.
    this.stalled = true;
    this.stallStartedAtMs = nowMs;
    this.decidedTotalAtStallStart = this.decidedTotal;
    const finding: EmissionStallFinding = {
      kind: "emission_stall",
      decidedTotal: this.decidedTotal,
      emittedTotal: this.emittedTotal,
      rejectedTotal: this.rejectedTotal,
      decidedSinceLastEmission: this.decidedSinceLastEmission,
      decidedBySource: this.decidedBySourceSnapshot(),
      msSinceLastEmissionMs:
        this.lastEmissionAtMs === null
          ? null
          : Math.max(0, nowMs - this.lastEmissionAtMs),
      msSinceFirstUnemittedDecisionMs: Math.max(0, nowMs - anchor),
    };
    this.onStall(finding);
    return finding;
  }

  /** Read-only snapshot for status surfaces and tests. */
  snapshot(): EmissionLivenessSnapshot {
    return {
      decidedTotal: this.decidedTotal,
      emittedTotal: this.emittedTotal,
      rejectedTotal: this.rejectedTotal,
      decidedSinceLastEmission: this.decidedSinceLastEmission,
      decidedBySource: this.decidedBySourceSnapshot(),
      lastEmissionAtMs: this.lastEmissionAtMs,
      firstUnemittedDecisionAtMs: this.firstUnemittedDecisionAtMs,
      stalled: this.stalled,
      stallStartedAtMs: this.stallStartedAtMs,
    };
  }

  private decidedBySourceSnapshot(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const [source, count] of this.decidedBySource) {
      out[source] = count;
    }
    return out;
  }
}
