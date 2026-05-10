/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-1 Rolling-baseline classifier.
 *
 * Per-feature running mean + variance (Welford's online algorithm)
 * per agent. NOT a real ML model: this is the explicit
 * simple-statistical baseline for the v1.3 foundation. ML training
 * pipelines (one-class SVM, isolation forest, autoencoders) are
 * deferred to Chi-2+ where the substrate choice gets coordinator-CTO
 * attention.
 *
 * Why Welford and not "store the last N samples":
 *  - Bounded storage per agent (one number per feature per moment).
 *  - Numerically stable for incremental updates.
 *  - Mean and variance recoverable directly from persisted state.
 *  - Survives restart cleanly (state -> store -> reload preserves
 *    all statistics).
 *
 * Anomaly score = sum of per-feature z-score-squared (Mahalanobis-
 * like under independent-feature assumption). Per-feature
 * contributions returned for explanation.
 *
 * Sovereignty: state stored encrypted at rest via ClassifierStateStore.
 * Never aggregated centrally; never leaves the fortress.
 */

import type {
  AnomalyClassifier,
  AnomalyPrediction,
  FeatureContribution,
  FeatureVector,
  TrainingResult,
} from "../types.js";
import type { ClassifierStateStore } from "../classifier-state-store.js";

export const ROLLING_BASELINE_CLASSIFIER_ID = "rolling-baseline" as const;

/** Default minimum sample count before predictions fire. */
export const DEFAULT_MIN_SAMPLES_FOR_PREDICTION = 7;

/** Minimum stddev floor; avoids divide-by-zero on perfectly stable features. */
const STDDEV_FLOOR = 0.5;

/**
 * Per-(agent, feature) Welford state. Persisted; do NOT change shape
 * without a version bump in classifier-state-store.
 */
interface FeatureWelford {
  /** Running sample count. */
  n: number;
  /** Running mean. */
  mean: number;
  /** Running sum of squared deviations from mean (M2 in Welford). */
  m2: number;
}

interface AgentClassifierState {
  /** Total feature observations recorded for this agent. */
  observation_count: number;
  /** ISO timestamp of last observation. */
  last_observed_at: string | null;
  /** Per-feature running statistics. */
  features: Record<string, FeatureWelford>;
}

export interface RollingBaselineClassifierOptions {
  stateStore: ClassifierStateStore;
  /** Minimum observations before predict() returns baseline_ready=true. Default 7. */
  minSamplesForPrediction?: number;
}

export class RollingBaselineClassifier implements AnomalyClassifier {
  readonly classifierId = ROLLING_BASELINE_CLASSIFIER_ID;
  private readonly stateStore: ClassifierStateStore;
  private readonly minSamplesForPrediction: number;
  /** In-memory cache of per-agent state; loaded lazily on first touch. */
  private readonly cache = new Map<string, AgentClassifierState>();
  /** Agents whose in-memory state has been mutated since last train(). */
  private readonly dirty = new Set<string>();

  constructor(opts: RollingBaselineClassifierOptions) {
    this.stateStore = opts.stateStore;
    this.minSamplesForPrediction =
      opts.minSamplesForPrediction ?? DEFAULT_MIN_SAMPLES_FOR_PREDICTION;
  }

  async observe(vector: FeatureVector): Promise<void> {
    const state = await this.loadOrInit(vector.agent_id);
    for (const [featureName, observed] of Object.entries(vector.features)) {
      if (!Number.isFinite(observed)) continue;
      const welford = state.features[featureName] ?? {
        n: 0,
        mean: 0,
        m2: 0,
      };
      const nextN = welford.n + 1;
      const delta = observed - welford.mean;
      const nextMean = welford.mean + delta / nextN;
      const delta2 = observed - nextMean;
      const nextM2 = welford.m2 + delta * delta2;
      state.features[featureName] = { n: nextN, mean: nextMean, m2: nextM2 };
    }
    state.observation_count += 1;
    state.last_observed_at = vector.observed_at;
    this.dirty.add(vector.agent_id);
  }

  async predict(vector: FeatureVector): Promise<AnomalyPrediction> {
    const state = await this.loadOrInit(vector.agent_id);
    if (state.observation_count < this.minSamplesForPrediction) {
      return {
        anomaly_score: 0,
        explanation: [],
        feature_contributions: [],
        baseline_ready: false,
      };
    }
    const contributions: FeatureContribution[] = [];
    let sumSquaredZ = 0;
    for (const [featureName, observed] of Object.entries(vector.features)) {
      if (!Number.isFinite(observed)) continue;
      const welford = state.features[featureName];
      if (!welford || welford.n < 2) continue;
      const variance = welford.m2 / (welford.n - 1);
      const stddev = Math.max(Math.sqrt(variance), STDDEV_FLOOR);
      const z = (observed - welford.mean) / stddev;
      sumSquaredZ += z * z;
      contributions.push({
        feature_name: featureName,
        observed,
        baseline_mean: welford.mean,
        baseline_stddev: stddev,
        z_score: z,
      });
    }
    contributions.sort(
      (a, b) => Math.abs(b.z_score) - Math.abs(a.z_score),
    );
    const anomalyScore = Math.sqrt(sumSquaredZ);
    const explanation = contributions.map(
      (c) =>
        `${c.feature_name} ${c.observed.toFixed(2)} vs baseline ${c.baseline_mean.toFixed(2)}+/-${c.baseline_stddev.toFixed(2)} (z=${c.z_score.toFixed(2)})`,
    );
    return {
      anomaly_score: anomalyScore,
      explanation,
      feature_contributions: contributions,
      baseline_ready: true,
    };
  }

  async train(): Promise<TrainingResult> {
    const dirtyAgents = [...this.dirty];
    for (const agentId of dirtyAgents) {
      const state = this.cache.get(agentId);
      if (!state) continue;
      await this.stateStore.saveState(this.classifierId, agentId, state);
      this.dirty.delete(agentId);
    }
    let sampleCount = 0;
    for (const state of this.cache.values()) {
      sampleCount += state.observation_count;
    }
    return {
      trained_at: new Date().toISOString(),
      sample_count: sampleCount,
      agent_count: this.cache.size,
    };
  }

  /** Test helper: read the in-memory state for an agent. */
  getAgentState(agentId: string): AgentClassifierState | undefined {
    return this.cache.get(agentId);
  }

  private async loadOrInit(agentId: string): Promise<AgentClassifierState> {
    const cached = this.cache.get(agentId);
    if (cached) return cached;
    const persisted = await this.stateStore.loadState<AgentClassifierState>(
      this.classifierId,
      agentId,
    );
    const state: AgentClassifierState = persisted ?? {
      observation_count: 0,
      last_observed_at: null,
      features: {},
    };
    this.cache.set(agentId, state);
    return state;
  }
}
