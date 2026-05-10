/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-2 PSI (Population Stability Index)
 * classifier.
 *
 * Detects per-agent DISTRIBUTION SHIFTS over time. Where CUSUM catches
 * mean drifts (location shifts) and rolling-baseline catches single
 * outliers (point anomalies), PSI catches shape changes in the
 * underlying distribution. A feature that historically followed a
 * unimodal, tight distribution and starts producing a bimodal-with-
 * heavy-tail pattern will trip PSI even when the running mean has
 * barely moved.
 *
 * Per-feature lifecycle:
 *  - Warmup: accumulate trainingSamples raw values. Once the count
 *    crosses the threshold, compute quantile bin boundaries from the
 *    training set, record training_proportions, lock both, and
 *    transition to operational.
 *  - Operational: accumulate a rolling current_window of recent
 *    in-baseline samples (cap at currentWindowMax; older samples
 *    drop). predict() computes hypothetical-current proportions
 *    (including the predict-time sample) and PSI against locked
 *    training_proportions.
 *
 * Industry-standard PSI thresholds (Sidey-Gibbons 1990s, mature in
 * banking model-monitoring): PSI < 0.1 stable, 0.1 <= PSI < 0.25
 * warn, PSI >= 0.25 alert. Mapped onto Chi-1's severity scale
 * (info >= 1, warn >= 3, alert >= 6) via piecewise-linear scaling so
 * that PSI=0.1 produces score=3 (warn) and PSI=0.25 produces score=6
 * (alert). PSI in [0, 0.1) produces score=0 (no finding).
 *
 * Predict-then-observe discipline (inherited from Chi-1):
 *  - predict() computes PSI assuming the sample joins current_window,
 *    but does NOT mutate state.
 *  - observe() commits the sample. The base class evaluate() loop
 *    calls observe() only when the sample is below severity threshold
 *    or during warmup. Drift samples skip observe(), so current_window
 *    stays anchored at the pre-drift distribution until the operator
 *    decides (Chi-3 UI).
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

export const PSI_CLASSIFIER_ID = "psi" as const;

/** Default training-set size before bin boundaries lock. */
export const DEFAULT_PSI_TRAINING_SAMPLES = 30;

/** Default minimum current-window size before PSI predictions fire. */
export const DEFAULT_PSI_CURRENT_WINDOW_MIN = 10;

/** Default maximum current-window size (ring-buffer cap). */
export const DEFAULT_PSI_CURRENT_WINDOW_MAX = 100;

/** Default quantile bin count. 10 is the industry standard. */
export const DEFAULT_PSI_BIN_COUNT = 10;

/**
 * Smoothing epsilon added to each proportion before the log ratio to
 * avoid ln(0) when a bin is empty. Same trick used in canonical PSI
 * implementations.
 */
const PSI_SMOOTHING_EPSILON = 1e-4;

/** Minimum stddev floor for the diagnostic z-score on contributions. */
const STDDEV_FLOOR = 0.5;

/** Threshold below which a feature emits no PSI signal. */
const PSI_NO_FINDING_THRESHOLD = 0.1;

/** Threshold at which PSI is mapped to severity=alert (score=6). */
const PSI_ALERT_THRESHOLD = 0.25;

interface FeaturePsiState {
  phase: "warmup" | "operational";
  /** Populated during warmup; cleared after bin boundaries lock. */
  training_samples: number[];
  /** Locked after warmup. Length binCount+1. */
  bin_boundaries: number[] | null;
  /** Locked after warmup. Length binCount. */
  training_proportions: number[] | null;
  /** Ring buffer of in-baseline post-warmup samples; capped at currentWindowMax. */
  current_window: number[];
}

interface AgentPsiState {
  observation_count: number;
  last_observed_at: string | null;
  features: Record<string, FeaturePsiState>;
}

export interface PsiClassifierOptions {
  stateStore: ClassifierStateStore;
  /** Training samples required before bin boundaries lock. Default 30. */
  trainingSamples?: number;
  /** Minimum current-window size before predictions fire. Default 10. */
  currentWindowMin?: number;
  /** Maximum current-window size (ring buffer cap). Default 100. */
  currentWindowMax?: number;
  /** Number of quantile bins. Default 10. */
  binCount?: number;
}

/**
 * PSI classifier. One instance per detector binding; per-(agent,
 * feature) state held in cache and persisted via train().
 */
export class PsiClassifier implements AnomalyClassifier {
  readonly classifierId = PSI_CLASSIFIER_ID;
  readonly binCount: number;
  private readonly stateStore: ClassifierStateStore;
  private readonly trainingSamples: number;
  private readonly currentWindowMin: number;
  private readonly currentWindowMax: number;
  private readonly cache = new Map<string, AgentPsiState>();
  private readonly dirty = new Set<string>();

  constructor(opts: PsiClassifierOptions) {
    this.stateStore = opts.stateStore;
    this.trainingSamples = opts.trainingSamples ?? DEFAULT_PSI_TRAINING_SAMPLES;
    this.currentWindowMin =
      opts.currentWindowMin ?? DEFAULT_PSI_CURRENT_WINDOW_MIN;
    this.currentWindowMax =
      opts.currentWindowMax ?? DEFAULT_PSI_CURRENT_WINDOW_MAX;
    this.binCount = opts.binCount ?? DEFAULT_PSI_BIN_COUNT;
  }

  async observe(vector: FeatureVector): Promise<void> {
    const state = await this.loadOrInit(vector.agent_id);
    for (const [name, observed] of Object.entries(vector.features)) {
      if (!Number.isFinite(observed)) continue;
      const feat = state.features[name] ?? this.emptyFeatureState();
      if (feat.phase === "warmup") {
        feat.training_samples.push(observed);
        if (feat.training_samples.length >= this.trainingSamples) {
          const boundaries = this.computeQuantileBoundaries(
            feat.training_samples,
          );
          const proportions = this.computeProportions(
            feat.training_samples,
            boundaries,
          );
          feat.bin_boundaries = boundaries;
          feat.training_proportions = proportions;
          feat.phase = "operational";
          feat.training_samples = [];
        }
      } else {
        feat.current_window.push(observed);
        if (feat.current_window.length > this.currentWindowMax) {
          feat.current_window.shift();
        }
      }
      state.features[name] = feat;
    }
    state.observation_count += 1;
    state.last_observed_at = vector.observed_at;
    this.dirty.add(vector.agent_id);
  }

  async predict(vector: FeatureVector): Promise<AnomalyPrediction> {
    const state = await this.loadOrInit(vector.agent_id);
    const observed = Object.entries(vector.features).filter(([, v]) =>
      Number.isFinite(v),
    );
    if (observed.length === 0) {
      return {
        anomaly_score: 0,
        explanation: [],
        feature_contributions: [],
        baseline_ready: false,
      };
    }
    // Baseline is ready when EVERY observed feature has cleared warmup
    // AND has enough current-window samples to make PSI meaningful.
    for (const [name] of observed) {
      const feat = state.features[name];
      if (!feat) {
        return {
          anomaly_score: 0,
          explanation: [],
          feature_contributions: [],
          baseline_ready: false,
        };
      }
      if (feat.phase !== "operational") {
        return {
          anomaly_score: 0,
          explanation: [],
          feature_contributions: [],
          baseline_ready: false,
        };
      }
      if (feat.current_window.length < this.currentWindowMin) {
        return {
          anomaly_score: 0,
          explanation: [],
          feature_contributions: [],
          baseline_ready: false,
        };
      }
    }
    type FeatPsi = {
      feature_name: string;
      psi: number;
      top_bucket_idx: number;
      current_pct: number;
      training_pct: number;
      direction: "shift_up" | "shift_down" | "flat";
    };
    const featurePsis: FeatPsi[] = [];
    const contributions: FeatureContribution[] = [];
    let maxScore = 0;
    for (const [name, value] of observed) {
      const feat = state.features[name]!;
      const boundaries = feat.bin_boundaries!;
      const trainingProps = feat.training_proportions!;
      const hypWindow = [...feat.current_window, value];
      while (hypWindow.length > this.currentWindowMax) {
        hypWindow.shift();
      }
      const currentProps = this.computeProportions(hypWindow, boundaries);
      const psi = this.computePsi(trainingProps, currentProps);
      const score = this.psiToScore(psi);
      let topBucketIdx = 0;
      let topAbs = -Infinity;
      for (let i = 0; i < this.binCount; i += 1) {
        const tp = (trainingProps[i] ?? 0) + PSI_SMOOTHING_EPSILON;
        const cp = (currentProps[i] ?? 0) + PSI_SMOOTHING_EPSILON;
        const contribution = (cp - tp) * Math.log(cp / tp);
        if (Math.abs(contribution) > Math.abs(topAbs)) {
          topAbs = contribution;
          topBucketIdx = i;
        }
      }
      const cpTop = currentProps[topBucketIdx] ?? 0;
      const tpTop = trainingProps[topBucketIdx] ?? 0;
      const direction: "shift_up" | "shift_down" | "flat" =
        cpTop > tpTop ? "shift_up" : cpTop < tpTop ? "shift_down" : "flat";
      featurePsis.push({
        feature_name: name,
        psi,
        top_bucket_idx: topBucketIdx,
        current_pct: cpTop,
        training_pct: tpTop,
        direction,
      });
      if (score > maxScore) maxScore = score;
      const trainingMean = this.estimateMean(boundaries, trainingProps);
      const trainingStddev = Math.max(
        this.estimateStddev(boundaries, trainingProps, trainingMean),
        STDDEV_FLOOR,
      );
      const z = (value - trainingMean) / trainingStddev;
      contributions.push({
        feature_name: name,
        observed: value,
        baseline_mean: trainingMean,
        baseline_stddev: trainingStddev,
        z_score: z,
      });
    }
    featurePsis.sort((a, b) => b.psi - a.psi);
    contributions.sort((a, b) => Math.abs(b.z_score) - Math.abs(a.z_score));
    const explanation = featurePsis.map(
      (f) =>
        `${f.feature_name} PSI=${f.psi.toFixed(3)} top_bucket=${f.top_bucket_idx} (${f.direction}: current ${(f.current_pct * 100).toFixed(1)}% vs training ${(f.training_pct * 100).toFixed(1)}%)`,
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
  getAgentState(agentId: string): AgentPsiState | undefined {
    return this.cache.get(agentId);
  }

  private async loadOrInit(agentId: string): Promise<AgentPsiState> {
    const cached = this.cache.get(agentId);
    if (cached) return cached;
    const persisted = await this.stateStore.loadState<AgentPsiState>(
      this.classifierId,
      agentId,
    );
    const state: AgentPsiState = persisted ?? {
      observation_count: 0,
      last_observed_at: null,
      features: {},
    };
    this.cache.set(agentId, state);
    return state;
  }

  private emptyFeatureState(): FeaturePsiState {
    return {
      phase: "warmup",
      training_samples: [],
      bin_boundaries: null,
      training_proportions: null,
      current_window: [],
    };
  }

  private computeQuantileBoundaries(samples: number[]): number[] {
    const sorted = [...samples].sort((a, b) => a - b);
    const boundaries: number[] = [];
    for (let i = 0; i <= this.binCount; i += 1) {
      const idx = Math.floor((i / this.binCount) * (sorted.length - 1));
      boundaries.push(sorted[Math.min(idx, sorted.length - 1)] ?? 0);
    }
    // Strictly monotone: degenerate (repeated) boundaries from
    // discrete-value training distributions get nudged upward by a
    // small epsilon so bucketize remains deterministic.
    for (let i = 1; i < boundaries.length; i += 1) {
      if (boundaries[i]! <= boundaries[i - 1]!) {
        boundaries[i] = boundaries[i - 1]! + 1e-9;
      }
    }
    return boundaries;
  }

  private computeProportions(samples: number[], boundaries: number[]): number[] {
    const counts = new Array<number>(this.binCount).fill(0);
    for (const s of samples) {
      const idx = this.bucketize(s, boundaries);
      counts[idx] = (counts[idx] ?? 0) + 1;
    }
    const total = samples.length || 1;
    return counts.map((c) => c / total);
  }

  private bucketize(value: number, boundaries: number[]): number {
    if (value <= boundaries[0]!) return 0;
    if (value >= boundaries[boundaries.length - 1]!) return this.binCount - 1;
    for (let i = 0; i < this.binCount; i += 1) {
      if (value >= boundaries[i]! && value < boundaries[i + 1]!) return i;
    }
    return this.binCount - 1;
  }

  private computePsi(
    trainingProportions: number[],
    currentProportions: number[],
  ): number {
    let psi = 0;
    for (let i = 0; i < this.binCount; i += 1) {
      const tp = (trainingProportions[i] ?? 0) + PSI_SMOOTHING_EPSILON;
      const cp = (currentProportions[i] ?? 0) + PSI_SMOOTHING_EPSILON;
      psi += (cp - tp) * Math.log(cp / tp);
    }
    return psi;
  }

  /**
   * Map PSI to the Chi-1 severity scale via piecewise-linear scaling.
   * Industry thresholds: stable < 0.1, warn 0.1..0.25, alert >= 0.25.
   * Severity ladder targets: warn -> 3, alert -> 6.
   */
  private psiToScore(psi: number): number {
    if (!Number.isFinite(psi)) return 0;
    if (psi < PSI_NO_FINDING_THRESHOLD) return 0;
    if (psi < PSI_ALERT_THRESHOLD) {
      // Linear: 0.1 -> 3, 0.25 -> 6.
      return 3 + (psi - PSI_NO_FINDING_THRESHOLD) * 20;
    }
    // Beyond 0.25: continue linearly so very-large PSI keeps growing.
    return 6 + (psi - PSI_ALERT_THRESHOLD) * 12;
  }

  private estimateMean(boundaries: number[], proportions: number[]): number {
    let mean = 0;
    for (let i = 0; i < this.binCount; i += 1) {
      const midpoint =
        ((boundaries[i] ?? 0) + (boundaries[i + 1] ?? 0)) / 2;
      mean += midpoint * (proportions[i] ?? 0);
    }
    return mean;
  }

  private estimateStddev(
    boundaries: number[],
    proportions: number[],
    mean: number,
  ): number {
    let variance = 0;
    for (let i = 0; i < this.binCount; i += 1) {
      const midpoint =
        ((boundaries[i] ?? 0) + (boundaries[i + 1] ?? 0)) / 2;
      const diff = midpoint - mean;
      variance += diff * diff * (proportions[i] ?? 0);
    }
    return Math.sqrt(variance);
  }
}

/**
 * Convenience factory: builds a PsiClassifier with a fresh
 * ClassifierStateStore bound to the given AnomalyContext. The
 * dispatcher's addClassifierToDetector consumes a factory of this
 * shape; Chi-3's CLI/UX will resolve "psi" -> this factory.
 */
export function createPsiClassifier(
  context: AnomalyContext,
  opts?: Omit<PsiClassifierOptions, "stateStore">,
): PsiClassifier {
  const stateStore = new ClassifierStateStore({
    storage: context.storage,
    masterKey: context.masterKey,
    fortressId: context.fortressId,
    now: context.now,
  });
  return new PsiClassifier({ stateStore, ...opts });
}
