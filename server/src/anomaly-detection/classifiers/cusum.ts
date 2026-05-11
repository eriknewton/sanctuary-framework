/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-2 CUSUM (Cumulative Sum) classifier.
 *
 * Detects per-agent MEAN SHIFTS over time. Where the rolling-baseline
 * classifier (Chi-1) fires on a single sample crossing a sigma
 * threshold, CUSUM fires when a sequence of small deviations
 * accumulates past a decision threshold. Best at catching slow,
 * persistent drifts that single-sample tests miss.
 *
 * Per-feature state: Welford running mean + variance (for sigma
 * estimate) plus positive-CUSUM and negative-CUSUM accumulators.
 *  - C+ tracks upward drift: max(0, C+_prev + (x - mu) - k*sigma)
 *  - C- tracks downward drift: max(0, C-_prev - (x - mu) - k*sigma)
 *  - Alert fires when max(C+, C-) crosses h*sigma.
 *  - max(0, ...) is the standard CUSUM reset-on-sign-change: a sample
 *    that pulls C+ below 0 resets it to 0; the same for C-. The two
 *    are independent.
 *
 * Predict-then-observe discipline (inherited from Chi-1):
 *  - predict() returns the hypothetical score if the sample were
 *    absorbed; it does NOT mutate state.
 *  - observe() commits the Welford and CUSUM updates. The base class
 *    AnomalyDetector.evaluate() loop calls observe() only when the
 *    sample is below the severity threshold (in-baseline) or during
 *    warmup. Drift samples skip observe(), so C+/C- and Welford
 *    stay anchored at the pre-drift baseline until the operator
 *    decides whether the new pattern is intended (Chi-3 ships the
 *    operator-visible decision UI).
 *
 * Sovereignty: state persisted encrypted at rest via ClassifierStateStore.
 * No outbound surface. Per-fortress; never aggregated centrally.
 */

import type {
  AnomalyClassifier,
  AnomalyContext,
  AnomalyPrediction,
  FeatureContribution,
  FeatureVector,
  TrainingResult,
} from "../types.js";
import { ClassifierStateStore } from "../classifier-state-store.js";

export const CUSUM_CLASSIFIER_ID = "cusum" as const;

/** Welford samples required before predict() returns baseline_ready=true. */
export const DEFAULT_CUSUM_MIN_SAMPLES_FOR_PREDICTION = 7;

/** Default sensitivity slack, in sigma units. Standard CUSUM choice. */
export const DEFAULT_CUSUM_K = 0.5;

/** Default decision threshold, in sigma units. Standard CUSUM choice. */
export const DEFAULT_CUSUM_H = 5;

/** Minimum stddev floor; protects against divide-by-zero on stable features. */
const STDDEV_FLOOR = 0.5;

/**
 * Per-(agent, feature) state. Persisted; do NOT change shape without
 * a version bump in classifier-state-store.
 */
interface FeatureCusumState {
  /** Welford sample count. */
  n: number;
  /** Welford running mean. */
  mean: number;
  /** Welford sum of squared deviations from mean (M2). */
  m2: number;
  /** Positive-CUSUM accumulator. Always >= 0. */
  c_plus: number;
  /** Negative-CUSUM accumulator. Always >= 0 (magnitude). */
  c_minus: number;
}

interface AgentCusumState {
  observation_count: number;
  last_observed_at: string | null;
  features: Record<string, FeatureCusumState>;
}

export interface CusumClassifierOptions {
  stateStore: ClassifierStateStore;
  /** Welford samples before predictions fire. Default 7. */
  minSamplesForPrediction?: number;
  /** Sensitivity slack k, in sigma units. Default 0.5. */
  k?: number;
  /** Decision threshold h, in sigma units. Default 5. */
  h?: number;
}

/**
 * CUSUM classifier. One instance per detector binding; per-(agent,
 * feature) state held in cache and persisted via train().
 */
export class CusumClassifier implements AnomalyClassifier {
  readonly classifierId = CUSUM_CLASSIFIER_ID;
  readonly k: number;
  readonly h: number;
  private readonly stateStore: ClassifierStateStore;
  private readonly minSamplesForPrediction: number;
  private readonly cache = new Map<string, AgentCusumState>();
  private readonly dirty = new Set<string>();

  constructor(opts: CusumClassifierOptions) {
    this.stateStore = opts.stateStore;
    this.minSamplesForPrediction =
      opts.minSamplesForPrediction ?? DEFAULT_CUSUM_MIN_SAMPLES_FOR_PREDICTION;
    this.k = opts.k ?? DEFAULT_CUSUM_K;
    this.h = opts.h ?? DEFAULT_CUSUM_H;
  }

  async observe(vector: FeatureVector): Promise<void> {
    const state = await this.loadOrInit(vector.agent_id);
    for (const [name, observed] of Object.entries(vector.features)) {
      if (!Number.isFinite(observed)) continue;
      const feat = state.features[name] ?? {
        n: 0,
        mean: 0,
        m2: 0,
        c_plus: 0,
        c_minus: 0,
      };
      const nextN = feat.n + 1;
      const delta = observed - feat.mean;
      const nextMean = feat.mean + delta / nextN;
      const delta2 = observed - nextMean;
      const nextM2 = feat.m2 + delta * delta2;
      let nextCPlus = feat.c_plus;
      let nextCMinus = feat.c_minus;
      // CUSUM accumulators require a sigma estimate; need n>=2 for
      // sample variance. During the first observation per feature the
      // accumulators stay at zero (no drift signal possible yet).
      if (feat.n >= 2) {
        const variance = feat.m2 / (feat.n - 1);
        const stddev = Math.max(Math.sqrt(variance), STDDEV_FLOOR);
        const kScaled = this.k * stddev;
        const devFromOldMean = observed - feat.mean;
        nextCPlus = Math.max(0, feat.c_plus + devFromOldMean - kScaled);
        nextCMinus = Math.max(0, feat.c_minus - devFromOldMean - kScaled);
      }
      state.features[name] = {
        n: nextN,
        mean: nextMean,
        m2: nextM2,
        c_plus: nextCPlus,
        c_minus: nextCMinus,
      };
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
    let maxScore = 0;
    type FeatureScore = {
      feature_name: string;
      score: number;
      direction: "up" | "down" | "flat";
      hyp_c_plus: number;
      hyp_c_minus: number;
      h_scaled: number;
    };
    const featureScores: FeatureScore[] = [];
    for (const [name, observed] of Object.entries(vector.features)) {
      if (!Number.isFinite(observed)) continue;
      const feat = state.features[name];
      if (!feat || feat.n < 2) continue;
      const variance = feat.m2 / (feat.n - 1);
      const stddev = Math.max(Math.sqrt(variance), STDDEV_FLOOR);
      const kScaled = this.k * stddev;
      const hScaled = this.h * stddev;
      const dev = observed - feat.mean;
      const hypCPlus = Math.max(0, feat.c_plus + dev - kScaled);
      const hypCMinus = Math.max(0, feat.c_minus - dev - kScaled);
      const featureScore = Math.max(hypCPlus, hypCMinus) / hScaled;
      const direction: "up" | "down" | "flat" =
        hypCPlus > hypCMinus ? "up" : hypCMinus > hypCPlus ? "down" : "flat";
      featureScores.push({
        feature_name: name,
        score: featureScore,
        direction,
        hyp_c_plus: hypCPlus,
        hyp_c_minus: hypCMinus,
        h_scaled: hScaled,
      });
      maxScore = Math.max(maxScore, featureScore);
      const z = dev / stddev;
      contributions.push({
        feature_name: name,
        observed,
        baseline_mean: feat.mean,
        baseline_stddev: stddev,
        z_score: z,
      });
    }
    contributions.sort((a, b) => Math.abs(b.z_score) - Math.abs(a.z_score));
    featureScores.sort((a, b) => b.score - a.score);
    const explanation = featureScores.map(
      (s) =>
        `${s.feature_name} drift_${s.direction} c+=${s.hyp_c_plus.toFixed(2)} c-=${s.hyp_c_minus.toFixed(2)} vs h=${s.h_scaled.toFixed(2)} (cusum_score=${s.score.toFixed(2)})`,
    );
    return {
      anomaly_score: maxScore,
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
  getAgentState(agentId: string): AgentCusumState | undefined {
    return this.cache.get(agentId);
  }

  private async loadOrInit(agentId: string): Promise<AgentCusumState> {
    const cached = this.cache.get(agentId);
    if (cached) return cached;
    const persisted = await this.stateStore.loadState<AgentCusumState>(
      this.classifierId,
      agentId,
    );
    const state: AgentCusumState = persisted ?? {
      observation_count: 0,
      last_observed_at: null,
      features: {},
    };
    this.cache.set(agentId, state);
    return state;
  }
}

/**
 * Convenience factory: builds a CusumClassifier with a fresh
 * ClassifierStateStore bound to the given AnomalyContext. The
 * dispatcher's addClassifierToDetector consumes a factory of this
 * shape; Chi-3's CLI/UX will resolve "cusum" -> this factory.
 */
export function createCusumClassifier(
  context: AnomalyContext,
  opts?: Omit<CusumClassifierOptions, "stateStore">,
): CusumClassifier {
  const stateStore = new ClassifierStateStore({
    storage: context.storage,
    masterKey: context.masterKey,
    fortressId: context.fortressId,
    now: context.now,
  });
  return new CusumClassifier({ stateStore, ...opts });
}
