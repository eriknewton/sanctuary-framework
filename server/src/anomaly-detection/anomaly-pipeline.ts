/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-1 Anomaly Detection Pipeline.
 *
 * Per-fortress dispatcher that drives the anomaly detector tick:
 *   1. For every registered detector, call evaluate() to extract +
 *      observe + predict.
 *   2. Persist updated classifier state via train() (fortress-unlock
 *      cadence; same shape as Phi-1 sentinel dispatcher).
 *   3. Each above-threshold finding routes to:
 *      - the existing SentinelFindingStore (Phi-1 surface) so the
 *        operator sees anomaly findings in the same inbox they use
 *        for Sentinel findings.
 *      - the audit log (`anomaly_finding_emitted`).
 *      - in-process subscribers (dashboard SSE wires through this).
 *   4. Per-detector exceptions log `anomaly_evaluation_failed` and
 *      the dispatcher continues with the next detector.
 *
 * Dispatcher is one-per-fortress. The fortress id is stamped on
 * every finding before persistence + emission so multi-fortress
 * isolation holds at both cryptographic + structural layers.
 *
 * Castle-walking discipline:
 *  - No outbound surface. Reads audit log, writes encrypted
 *    classifier state + Phi-1 finding store + audit log.
 *  - Substrate selector NOT exercised at v1.3 Chi-1 (statistical
 *    classifier only). Chi-2+ may opt into substrate when ML scope
 *    opens.
 */

import { randomUUID } from "node:crypto";

import type { AuditLog } from "../operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type {
  AnomalyClassifier,
  AnomalyContext,
  AnomalyDetector,
  AnomalyFinding,
} from "./types.js";
import { CUSUM_CLASSIFIER_ID } from "./classifiers/cusum.js";
import { PSI_CLASSIFIER_ID } from "./classifiers/psi.js";
import { AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID } from "./detectors/audit-event-class-distribution-detector.js";
import { enrichDetailsWithRootCauseHints } from "./root-cause-hints.js";

export const ANOMALY_AUDIT_OPS = {
  DETECTOR_REGISTERED: "anomaly_detector_registered",
  DETECTOR_UNREGISTERED: "anomaly_detector_unregistered",
  FINDING_EMITTED: "anomaly_finding_emitted",
  EVALUATION_FAILED: "anomaly_evaluation_failed",
  TRAINING_COMPLETED: "anomaly_training_completed",
  TRAINING_FAILED: "anomaly_training_failed",
  /** Chi-2: a classifier was attached to an existing detector. */
  CLASSIFIER_SUBSCRIBED: "anomaly_classifier_subscribed",
  /** Chi-2: a classifier was detached from an existing detector. */
  CLASSIFIER_UNSUBSCRIBED: "anomaly_classifier_unsubscribed",
  /** Chi-2: CUSUM-flagged mean-shift drift on a per-agent feature. */
  CUSUM_DRIFT_DETECTED: "anomaly_cusum_drift_detected",
  /** Chi-2: PSI-flagged distribution shift on a per-agent feature. */
  PSI_DISTRIBUTION_SHIFT_DETECTED:
    "anomaly_psi_distribution_shift_detected",
} as const;

export type AnomalyAuditOp =
  (typeof ANOMALY_AUDIT_OPS)[keyof typeof ANOMALY_AUDIT_OPS];

export type AnomalyDispatcherUnsubscribe = () => void;

export interface AnomalyDispatcherEmit {
  type: "finding";
  finding: AnomalyFinding;
}

export interface AnomalyDispatcherFailureEmit {
  type: "evaluation_failed";
  detector_id: string;
  error_message: string;
  observed_at: string;
}

export type AnomalyDispatcherAnyEmit =
  | AnomalyDispatcherEmit
  | AnomalyDispatcherFailureEmit;

/**
 * Outcome of removeClassifierOrUnregisterDetector. Consumers branch on
 * `outcome`; `removed` reports whether the selected mutation removed an
 * active registration or classifier.
 */
export type RemoveClassifierOrUnregisterOutcome =
  | { outcome: "not_subscribed" }
  | { outcome: "primary_has_dependents" }
  | { outcome: "detector_unregistered"; removed: boolean }
  | { outcome: "classifier_removed"; removed: boolean };

export interface AnomalyPipelineDispatcherDeps {
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  identityId: string;
  now?: () => Date;
  /** Tick interval, ms. Default 60s. Set to 0 to disable auto-tick. */
  tickIntervalMs?: number;
}

const DEFAULT_TICK_INTERVAL_MS = 60_000;

/**
 * Per-fortress anomaly dispatcher. Mirrors the Phi-1 sentinel
 * dispatcher's lifecycle shape so server-boot wiring stays uniform.
 */
export class AnomalyPipelineDispatcher {
  private readonly findingStore: SentinelFindingStore;
  private readonly auditLog: AuditLog;
  private readonly storage: StorageBackend;
  private readonly masterKey: Uint8Array;
  private readonly fortressId: string;
  private readonly identityId: string;
  private readonly now: () => Date;
  private readonly tickIntervalMs: number;
  private readonly detectors = new Map<string, AnomalyDetector>();
  private readonly listeners = new Set<
    (event: AnomalyDispatcherAnyEmit) => void
  >();
  private tickTimer: NodeJS.Timeout | null = null;
  private tickInFlight = false;
  /**
   * Per-detector-id serialization chains for registry mutations. See
   * withDetectorMutationLock for the invariant this map enforces.
   */
  private readonly detectorMutationChains = new Map<string, Promise<void>>();

  constructor(deps: AnomalyPipelineDispatcherDeps) {
    this.findingStore = deps.findingStore;
    this.auditLog = deps.auditLog;
    this.storage = deps.storage;
    this.masterKey = deps.masterKey;
    this.fortressId = deps.fortressId;
    this.identityId = deps.identityId;
    this.now = deps.now ?? (() => new Date());
    this.tickIntervalMs = deps.tickIntervalMs ?? DEFAULT_TICK_INTERVAL_MS;
  }

  onEvent(
    listener: (event: AnomalyDispatcherAnyEmit) => void,
  ): AnomalyDispatcherUnsubscribe {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Run one registry operation for a detector id after every earlier
   * operation for the same id has settled. Registration and every
   * classifier mutation (attach and detach) for one detector id are
   * serialized here because each verb is a check-then-await-then-commit
   * sequence over the live registry, and those sequences are only
   * correct when they cannot interleave; settled reads join the same
   * chain so an already-live decision observes only committed state
   * (register id: ic-sweep-auto-trigger-thresholds-consumed).
   * Serialization is per detector id: operations for distinct detectors
   * never wait on each other. The map entry is deleted once its chain
   * drains, so retired detector ids do not accumulate.
   */
  private withDetectorMutationLock<T>(
    detectorId: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    const tail =
      this.detectorMutationChains.get(detectorId) ?? Promise.resolve();
    // The stored tail settles to undefined on both arms, so a failed
    // operation surfaces only to its own caller and never poisons later
    // operations queued on the same detector id.
    const run = tail.then(operation);
    const settled: Promise<void> = run.then(
      () => undefined,
      () => undefined,
    );
    this.detectorMutationChains.set(detectorId, settled);
    void settled.then(() => {
      if (this.detectorMutationChains.get(detectorId) === settled) {
        this.detectorMutationChains.delete(detectorId);
      }
    });
    return run;
  }

  /**
   * Register + subscribe a detector to this fortress. Idempotent: a
   * second call with the same detectorId returns the already-
   * registered instance without re-subscribing.
   */
  async registerDetector(detector: AnomalyDetector): Promise<AnomalyDetector> {
    // Serialized per detector id: the fresh-registration check and the
    // commit below bracket an await, and the idempotency contract (a
    // second same-id call returns the already-registered instance) holds
    // only when same-id sequences run one at a time.
    return this.withDetectorMutationLock(detector.detectorId, async () => {
      const existing = this.detectors.get(detector.detectorId);
      if (existing) return existing;
      const context: AnomalyContext = {
        fortressId: this.fortressId,
        auditLog: this.auditLog,
        storage: this.storage,
        masterKey: this.masterKey,
        now: this.now,
      };
      await detector.subscribe(context);
      this.detectors.set(detector.detectorId, detector);
      void this.auditLog.append(
        "l2",
        ANOMALY_AUDIT_OPS.DETECTOR_REGISTERED,
        this.identityId,
        { detector_id: detector.detectorId, fortress_id: this.fortressId },
      );
      return detector;
    });
  }

  /**
   * Unregister + tear down a detector. Idempotent. Returns true when
   * an active registration was removed.
   */
  async unregisterDetector(detectorId: string): Promise<boolean> {
    // Serialized per detector id: teardown must observe the registration
    // a completed register committed, never a half-registered one.
    return this.withDetectorMutationLock(detectorId, () =>
      this.unregisterDetectorHoldingLock(detectorId),
    );
  }

  /**
   * Teardown body. Callers MUST already hold this detector id's
   * mutation lock (the public wrapper above, or a compound operation
   * that decides and mutates in one hold); acquiring it here again
   * would queue behind the caller's own hold.
   */
  private async unregisterDetectorHoldingLock(
    detectorId: string,
  ): Promise<boolean> {
    const detector = this.detectors.get(detectorId);
    if (!detector) return false;
    try {
      await detector.unsubscribe();
    } finally {
      this.detectors.delete(detectorId);
    }
    void this.auditLog.append(
      "l2",
      ANOMALY_AUDIT_OPS.DETECTOR_UNREGISTERED,
      this.identityId,
      { detector_id: detectorId, fortress_id: this.fortressId },
    );
    return true;
  }

  listDetectors(): string[] {
    return [...this.detectors.keys()];
  }

  listDetectorClassifiers(detectorId: string): string[] {
    return this.detectors.get(detectorId)?.listClassifierIds() ?? [];
  }

  /**
   * Live classifier ids for a detector id, read after every in-flight
   * operation for that id has settled. A snapshot taken mid-mutation
   * can name classifier ids no live registration backs (a teardown
   * still holds its registry entry while its unsubscribe is in flight),
   * so a caller deciding "already subscribed" reads through this
   * chokepoint rather than the instantaneous list (register id:
   * ic-sweep-auto-trigger-thresholds-consumed).
   */
  async getSettledDetectorClassifiers(detectorId: string): Promise<string[]> {
    return this.withDetectorMutationLock(detectorId, async () =>
      this.listDetectorClassifiers(detectorId),
    );
  }

  /** Run one evaluation pass over every registered detector. */
  async tick(): Promise<AnomalyFinding[]> {
    if (this.tickInFlight) return [];
    this.tickInFlight = true;
    try {
      const findings: AnomalyFinding[] = [];
      for (const [detectorId, detector] of this.detectors.entries()) {
        try {
          const detectorFindings = await detector.evaluate();
          for (const raw of detectorFindings) {
            const stamped = await this.routeFinding(detectorId, raw);
            findings.push(stamped);
          }
          // Chi-2: train every attached classifier on this detector;
          // each gets its own audit emission so the operator can see
          // per-classifier training cadence in the audit log.
          for (const classifier of detector.getAllClassifiers()) {
            try {
              const trainingResult = await classifier.train();
              void this.auditLog.append(
                "l2",
                ANOMALY_AUDIT_OPS.TRAINING_COMPLETED,
                this.identityId,
                {
                  detector_id: detectorId,
                  classifier_id: classifier.classifierId,
                  trained_at: trainingResult.trained_at,
                  sample_count: trainingResult.sample_count,
                  agent_count: trainingResult.agent_count,
                  fortress_id: this.fortressId,
                },
              );
            } catch (trainErr) {
              const message =
                trainErr instanceof Error
                  ? trainErr.message
                  : String(trainErr);
              void this.auditLog.append(
                "l2",
                ANOMALY_AUDIT_OPS.TRAINING_FAILED,
                this.identityId,
                {
                  detector_id: detectorId,
                  classifier_id: classifier.classifierId,
                  error_message: message,
                  fortress_id: this.fortressId,
                },
                "failure",
              );
            }
          }
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          const observedAt = this.now().toISOString();
          void this.auditLog.append(
            "l2",
            ANOMALY_AUDIT_OPS.EVALUATION_FAILED,
            this.identityId,
            {
              detector_id: detectorId,
              error_message: message,
              fortress_id: this.fortressId,
            },
            "failure",
          );
          this.emit({
            type: "evaluation_failed",
            detector_id: detectorId,
            error_message: message,
            observed_at: observedAt,
          });
        }
      }
      return findings;
    } finally {
      this.tickInFlight = false;
    }
  }

  start(): void {
    if (this.tickTimer !== null) return;
    if (this.tickIntervalMs <= 0) return;
    this.tickTimer = setInterval(() => {
      void this.tick();
    }, this.tickIntervalMs);
    if (typeof this.tickTimer.unref === "function") {
      this.tickTimer.unref();
    }
  }

  stop(): void {
    if (this.tickTimer === null) return;
    clearInterval(this.tickTimer);
    this.tickTimer = null;
  }

  async dispose(): Promise<void> {
    this.stop();
    const ids = [...this.detectors.keys()];
    for (const id of ids) {
      try {
        await this.unregisterDetector(id);
      } catch {
        // Continue draining.
      }
    }
    this.listeners.clear();
  }

  private async routeFinding(
    detectorId: string,
    raw: AnomalyFinding,
  ): Promise<AnomalyFinding> {
    const stamped: AnomalyFinding = {
      ...raw,
      finding_id: raw.finding_id || randomUUID(),
      fortress_id: this.fortressId,
      observed_at: raw.observed_at || this.now().toISOString(),
      // Chi-8: attach operator-facing root-cause hints derived from
      // the finding's existing drift attribution. Fail-closed: hint
      // generation errors degrade to empty hints / unchanged details;
      // they never block or drop the finding.
      details: enrichDetailsWithRootCauseHints(raw.details),
    };
    await this.findingStore.saveFinding(stamped);
    const classifierId = (
      stamped.details["classifier_id"] as string | undefined
    ) ?? null;
    void this.auditLog.append(
      "l2",
      ANOMALY_AUDIT_OPS.FINDING_EMITTED,
      this.identityId,
      {
        detector_id: detectorId,
        finding_id: stamped.finding_id,
        severity: stamped.severity,
        anomaly_score: (stamped.details["anomaly_score"] as number | undefined) ?? null,
        ...(classifierId !== null ? { classifier_id: classifierId } : {}),
        ...(stamped.agent_id !== undefined ? { agent_id: stamped.agent_id } : {}),
        fortress_id: this.fortressId,
      },
    );
    // Chi-2: classifier-specific audit event in addition to the
    // generic FINDING_EMITTED. Lets operators filter the audit log
    // for "show me only CUSUM drifts" or "only PSI shifts" without
    // walking finding details.
    const specificOp = classifierSpecificAuditOp(classifierId);
    if (specificOp !== null) {
      void this.auditLog.append("l2", specificOp, this.identityId, {
        detector_id: detectorId,
        finding_id: stamped.finding_id,
        severity: stamped.severity,
        anomaly_score:
          (stamped.details["anomaly_score"] as number | undefined) ?? null,
        ...(stamped.agent_id !== undefined
          ? { agent_id: stamped.agent_id }
          : {}),
        fortress_id: this.fortressId,
      });
    }
    this.emit({ type: "finding", finding: stamped });
    return stamped;
  }

  /**
   * Chi-2: attach an additional classifier to an already-registered
   * detector. Emits ANOMALY_CLASSIFIER_SUBSCRIBED on success. The
   * factory is called with the fortress AnomalyContext so the
   * classifier can build its own state-store binding. Idempotent: a
   * second call with the same classifierId returns false. The factory
   * may be async (IC-29: the CUSUM entry reads persisted threshold
   * overrides before construction), so its result is always awaited
   * even when the factory itself is synchronous.
   */
  async addClassifierToDetector(
    detectorId: string,
    factory: (
      context: AnomalyContext,
    ) => AnomalyClassifier | Promise<AnomalyClassifier>,
  ): Promise<boolean> {
    // Serialized per detector id: the detector instance captured before
    // the awaited factory call must still be the live registration when
    // the classifier attaches, which holds only when same-id mutations
    // run one at a time.
    return this.withDetectorMutationLock(detectorId, async () => {
      const detector = this.detectors.get(detectorId);
      if (!detector) return false;
      const context: AnomalyContext = {
        fortressId: this.fortressId,
        auditLog: this.auditLog,
        storage: this.storage,
        masterKey: this.masterKey,
        now: this.now,
      };
      const classifier = await factory(context);
      const added = detector.addClassifier(classifier);
      if (!added) return false;
      void this.auditLog.append(
        "l2",
        ANOMALY_AUDIT_OPS.CLASSIFIER_SUBSCRIBED,
        this.identityId,
        {
          detector_id: detectorId,
          classifier_id: classifier.classifierId,
          fortress_id: this.fortressId,
        },
      );
      return true;
    });
  }

  /**
   * Chi-2: detach an additional classifier from an already-registered
   * detector. Emits ANOMALY_CLASSIFIER_UNSUBSCRIBED on success. The
   * primary classifier cannot be detached (returns false).
   */
  async removeClassifierFromDetector(
    detectorId: string,
    classifierId: string,
  ): Promise<boolean> {
    // Serialized per detector id: the detach must observe the classifier
    // set as committed by completed mutations, never a set another
    // in-flight operation is still building.
    return this.withDetectorMutationLock(detectorId, () =>
      this.removeClassifierHoldingLock(detectorId, classifierId),
    );
  }

  /**
   * Detach body. Callers MUST already hold this detector id's mutation
   * lock (the public wrapper above, or a compound operation that
   * decides and mutates in one hold); acquiring it here again would
   * queue behind the caller's own hold.
   */
  private async removeClassifierHoldingLock(
    detectorId: string,
    classifierId: string,
  ): Promise<boolean> {
    const detector = this.detectors.get(detectorId);
    if (!detector) return false;
    const removed = detector.removeClassifier(classifierId);
    if (!removed) return false;
    void this.auditLog.append(
      "l2",
      ANOMALY_AUDIT_OPS.CLASSIFIER_UNSUBSCRIBED,
      this.identityId,
      {
        detector_id: detectorId,
        classifier_id: classifierId,
        fortress_id: this.fortressId,
      },
    );
    return true;
  }

  /**
   * Unsubscribe policy decided and applied in ONE lock hold: an
   * unsubscribed classifier id is a no-op; the primary classifier with
   * dependents attached is refused; the primary alone tears down the
   * whole detector; a non-primary classifier detaches alone. The
   * decision reads the live classifier set and the mutation it selects
   * runs before the hold is released, because the policy is only
   * correct against the state it mutates — a decision taken in one
   * hold and applied in another can act on a set that an operation
   * queued between them has changed (register id:
   * ic-sweep-auto-trigger-thresholds-consumed).
   */
  async removeClassifierOrUnregisterDetector(
    detectorId: string,
    classifierId: string,
  ): Promise<RemoveClassifierOrUnregisterOutcome> {
    return this.withDetectorMutationLock(detectorId, async () => {
      const classifierIds = this.listDetectorClassifiers(detectorId);
      if (!classifierIds.includes(classifierId)) {
        return { outcome: "not_subscribed" as const };
      }
      // The primary classifier occupies the first position; must match
      // the primary-first ordering of listClassifierIds in types.ts.
      const primaryClassifierId = classifierIds[0];
      if (classifierId === primaryClassifierId) {
        if (classifierIds.length > 1) {
          return { outcome: "primary_has_dependents" as const };
        }
        const removed = await this.unregisterDetectorHoldingLock(detectorId);
        return { outcome: "detector_unregistered" as const, removed };
      }
      const removed = await this.removeClassifierHoldingLock(
        detectorId,
        classifierId,
      );
      return { outcome: "classifier_removed" as const, removed };
    });
  }

  private emit(event: AnomalyDispatcherAnyEmit): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listener exceptions never fail the dispatcher tick.
      }
    }
  }
}

/**
 * Map a classifier id to its Chi-2 specific audit op, or null when
 * the classifier does not have a specific op (e.g. rolling-baseline
 * uses the generic FINDING_EMITTED only).
 */
function classifierSpecificAuditOp(
  classifierId: string | null,
): string | null {
  if (classifierId === null) return null;
  if (classifierId === CUSUM_CLASSIFIER_ID) {
    return ANOMALY_AUDIT_OPS.CUSUM_DRIFT_DETECTED;
  }
  if (classifierId === PSI_CLASSIFIER_ID) {
    return ANOMALY_AUDIT_OPS.PSI_DISTRIBUTION_SHIFT_DETECTED;
  }
  if (classifierId === AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID) {
    return ANOMALY_AUDIT_OPS.PSI_DISTRIBUTION_SHIFT_DETECTED;
  }
  return null;
}

// Re-export the foundation types from one place so consumers import a
// single module path. AnomalyDetector is exported as both a type and
// a runtime class so subclasses can extend it.
export type {
  FeatureVector,
  AnomalyContext,
  AnomalyClassifier,
  AnomalyPrediction,
  AnomalyFinding,
  FeatureContribution,
  TrainingResult,
} from "./types.js";
export {
  AnomalyDetector,
  severityFromAnomalyScore,
  ANOMALY_SENTINEL_ID_PREFIX,
} from "./types.js";
// Chi-8: root-cause hint surface re-exported alongside the pipeline so
// consumers keep a single import path for anomaly primitives.
export type { RootCauseHint } from "./root-cause-hints.js";
export {
  buildRootCauseHints,
  enrichDetailsWithRootCauseHints,
  ROOT_CAUSE_HINTS_DETAILS_KEY,
  ROOT_CAUSE_HINT_Z_THRESHOLD,
  ROOT_CAUSE_HINT_MAX_HINTS,
  ROOT_CAUSE_HINT_MAX_CLASS_HINTS,
  ROOT_CAUSE_HINT_NAME_MAX_LENGTH,
} from "./root-cause-hints.js";
