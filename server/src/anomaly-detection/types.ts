/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-1 Anomaly Detection Pipeline (Castle Layer 2)
 *
 * Sibling to the rule-based Sentinel Baseline Pack (WP-V1.3-1). Where
 * Sentinels surface known-shape anomalies (egress spike, credential
 * misuse, lateral movement, suspicious tool calls), the Anomaly
 * Detection Pipeline learns each agent's normal pattern locally and
 * surfaces statistical drift.
 *
 * Sovereignty-critical invariants enforced at the type level:
 *  - Feature vectors are NUMERIC ONLY at v1.3 (categorical encoding
 *    deferred). Keeps the trainable surface small and auditable.
 *  - Training state is per-fortress. AnomalyContext carries a
 *    fortress-scoped storage backend; classifiers MUST NOT reach
 *    outside that boundary.
 *  - Findings reuse the SentinelFinding shape (Phi-1) so they flow
 *    through the existing finding-store + audit + dashboard pipeline
 *    without parallel infrastructure.
 *
 * Castle-walking discipline:
 *  - Castle Layer 1 (Castle Wall): no new outbound surface. Classifier
 *    state never leaves the fortress.
 *  - Castle Layer 2: this pipeline IS the statistical-drift complement
 *    to the rule-based Sentinel surface.
 *  - Castle Layer 3 (Cooperative MCP): the substrate selector remains
 *    the only outbound LLM channel. Chi-1 statistical classifier does
 *    NOT exercise it; ML-substrate work waits for Chi-2+ where the
 *    substrate choice gets coordinator-CTO attention.
 *
 * Chi-1 ships the foundation: feature extractor + classifier interface
 * + rolling-baseline classifier + drift detection skeleton + first
 * detector. Chi-2 through Chi-N expand.
 */

import type { AuditLog } from "../l2-operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import type {
  SentinelFinding,
  SentinelSeverity,
} from "../sentinel/types.js";

/**
 * Numeric per-agent feature observation. v1.3 Chi-1 keeps the field
 * set to plain numbers; categorical features (e.g. one-hot encoded
 * tool names) wait for Chi-2+ when feature-engineering scope opens.
 */
export interface FeatureVector {
  agent_id: string;
  observed_at: string;
  /** Field name -> numeric value. Stable per detector. */
  features: Record<string, number>;
  /** Window label (e.g. "24h_rolling", "1h_rolling") for diagnostics. */
  window_label: string;
}

/**
 * Read-only context handed to feature extractors + classifiers. Same
 * shape posture as Phi-1's SentinelContext: extractors observe; they
 * do NOT mutate audit log. Classifier state lives in the encrypted
 * storage backend the AnomalyContext provides.
 */
export interface AnomalyContext {
  /** Stable per-fortress identifier; multi-fortress isolation pivot. */
  fortressId: string;
  /** Audit log read API. Extractors MUST NOT call append() through this. */
  auditLog: AuditLog;
  /** Storage backend for at-rest classifier state. */
  storage: StorageBackend;
  /** Fortress master key; classifier-state stores derive HKDF subkeys from this. */
  masterKey: Uint8Array;
  /** Wall-clock provider. Tests inject a deterministic clock. */
  now: () => Date;
}

/**
 * Classifier prediction shape. `anomaly_score` is in units of
 * standard deviations from the trained baseline (Mahalanobis-like
 * sum-of-squares of per-feature z-scores). Higher = more anomalous.
 * `explanation` is a flat list of per-feature diagnostic strings,
 * sorted highest-deviation-first, populated when the classifier has
 * a baseline. `feature_contributions` mirrors that as a structured
 * payload for finding details.
 */
export interface AnomalyPrediction {
  anomaly_score: number;
  explanation: string[];
  feature_contributions: FeatureContribution[];
  /** True once enough samples have been observed for predictions. */
  baseline_ready: boolean;
}

export interface FeatureContribution {
  feature_name: string;
  observed: number;
  baseline_mean: number;
  baseline_stddev: number;
  z_score: number;
}

/**
 * Classifier interface. Implementations: Chi-1 ships a simple rolling
 * baseline (Welford's running mean + variance per feature). Chi-2+
 * may add one-class SVM / isolation forest / autoencoders against the
 * substrate selector when ML scope opens.
 */
export interface AnomalyClassifier {
  readonly classifierId: string;
  /** Add a feature vector to the training set + update internal state. */
  observe(vector: FeatureVector): Promise<void>;
  /** Score a vector against the trained baseline. */
  predict(vector: FeatureVector): Promise<AnomalyPrediction>;
  /**
   * Persist current classifier state. Called periodically by the
   * dispatcher; safe to call multiple times. Returns metadata for
   * audit emission.
   */
  train(): Promise<TrainingResult>;
}

export interface TrainingResult {
  trained_at: string;
  /** Number of feature observations across all agents tracked. */
  sample_count: number;
  /** Number of agent_id buckets the classifier has seen. */
  agent_count: number;
}

/**
 * Detector surface. A detector composes ONE feature extractor + ONE
 * classifier and emits AnomalyFinding entries. v1.3 Chi-1 ships one
 * detector (per-agent activity); Chi-4+ adds intra-agent timing,
 * cross-agent correlation, etc.
 */
export abstract class AnomalyDetector {
  abstract readonly detectorId: string;
  abstract readonly description: string;
  abstract readonly classifier: AnomalyClassifier;

  /**
   * Extract one FeatureVector per known agent in the current window.
   * Returns an empty array when there is nothing observable.
   */
  abstract featureExtract(context: AnomalyContext): Promise<FeatureVector[]>;

  /**
   * Bind the detector to a fortress context. Default stores it on
   * `this`; subclasses with priming logic override.
   */
  async subscribe(context: AnomalyContext): Promise<void> {
    this.context = context;
  }

  async unsubscribe(): Promise<void> {
    this.context = undefined;
  }

  /**
   * One evaluation pass. Default impl: extract -> predict (drift
   * against the prior baseline) -> observe (only when the prediction
   * is in-baseline, so outliers do not contaminate the rolling mean
   * and pull future predictions toward themselves) -> emit findings
   * above threshold. Subclasses with custom routing override.
   *
   * Predict-then-observe (with conditional observe) is the standard
   * online anomaly-detection pattern. The spawn prompt called for
   * observe-then-predict; CTO call: changed to predict-then-observe
   * because observe-then-predict measures the sample against itself
   * after one-sample contamination, which is structurally incorrect
   * for drift detection. Documented as a deviation.
   */
  async evaluate(): Promise<AnomalyFinding[]> {
    const ctx = this.requireContext();
    const vectors = await this.featureExtract(ctx);
    const findings: AnomalyFinding[] = [];
    for (const vector of vectors) {
      const prediction = await this.classifier.predict(vector);
      if (!prediction.baseline_ready) {
        // Still warming up; absorb every sample to build the baseline.
        await this.classifier.observe(vector);
        continue;
      }
      const severity = severityFromAnomalyScore(prediction.anomaly_score);
      if (severity === null) {
        // Sample is ordinary; absorb into the rolling baseline.
        await this.classifier.observe(vector);
        continue;
      }
      // Drift detected: emit a finding but DO NOT absorb the outlier.
      // Future predictions remain anchored to the pre-drift baseline
      // until the operator decides whether the new pattern is the
      // intended one (Chi-3 ships the operator-visible decision UI).
      findings.push(buildAnomalyFinding(this, vector, prediction, severity));
    }
    return findings;
  }

  protected context: AnomalyContext | undefined;

  protected requireContext(): AnomalyContext {
    if (!this.context) {
      throw new Error(
        `anomaly-detector ${this.detectorId}: evaluate() called before subscribe()`,
      );
    }
    return this.context;
  }
}

/**
 * AnomalyFinding is shape-compatible with SentinelFinding so it
 * persists through the same store + audit + dashboard pipeline. A
 * type alias avoids a duplicate parallel inbox surface; the
 * sentinel_id field carries the prefix `anomaly:` to distinguish
 * detector findings from rule-based sentinel findings in the
 * operator dashboard.
 */
export type AnomalyFinding = SentinelFinding;

/**
 * Sentinel-id prefix for detector findings. Lets the operator
 * dashboard distinguish anomaly findings from Phi-1 sentinel
 * findings by their sentinel_id.
 */
export const ANOMALY_SENTINEL_ID_PREFIX = "anomaly:" as const;

/**
 * Severity mapping per spawn-prompt: anomaly_score in units of sigma.
 *  - score < 1: no finding (within 1 sigma is ordinary noise).
 *  - 1 <= score < 3: info.
 *  - 3 <= score < 6: warn.
 *  - score >= 6: alert.
 *
 * Returns null when no finding should fire.
 */
export function severityFromAnomalyScore(
  score: number,
): SentinelSeverity | null {
  if (!Number.isFinite(score)) return null;
  if (score < 1) return null;
  if (score < 3) return "info";
  if (score < 6) return "warn";
  return "alert";
}

/**
 * Build an AnomalyFinding from a prediction. Caller is the detector;
 * the dispatcher stamps the fortress_id + finding_id when persisting.
 */
function buildAnomalyFinding(
  detector: AnomalyDetector,
  vector: FeatureVector,
  prediction: AnomalyPrediction,
  severity: SentinelSeverity,
): AnomalyFinding {
  const summary = formatAnomalySummary(detector, vector, prediction, severity);
  return {
    finding_id: "",
    sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}${detector.detectorId}`,
    severity,
    summary,
    details: {
      detector_id: detector.detectorId,
      classifier_id: detector.classifier.classifierId,
      anomaly_score: prediction.anomaly_score,
      window_label: vector.window_label,
      observed_features: vector.features,
      feature_contributions: prediction.feature_contributions,
      explanation: prediction.explanation,
    },
    observed_at: vector.observed_at,
    agent_id: vector.agent_id,
    evidence_audit_ids: [],
    fortress_id: "",
  };
}

function formatAnomalySummary(
  detector: AnomalyDetector,
  vector: FeatureVector,
  prediction: AnomalyPrediction,
  severity: SentinelSeverity,
): string {
  const top = prediction.explanation.slice(0, 3).join("; ");
  return `${detector.detectorId} ${severity}: agent ${vector.agent_id} drifted ${prediction.anomaly_score.toFixed(2)} sigma from baseline. Top contributors: ${top || "(none)"}.`;
}
