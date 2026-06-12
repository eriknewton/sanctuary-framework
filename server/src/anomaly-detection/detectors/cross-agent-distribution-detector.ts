/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-6 Cross-Agent Distribution Detector.
 *
 * Composes the cross-agent-distribution feature extractor + a default
 * rolling-baseline classifier. Inherits the default
 * predict-then-observe `evaluate()` loop from `AnomalyDetector`
 * (Chi-1 invariant; Chi-2 preserved per-classifier).
 *
 * Where per-agent-activity baselines an agent against its OWN history,
 * this detector baselines each agent's deviation from its PEERS, so
 * fortress-wide shifts (release weeks, quiet weekends) cancel out and
 * the one agent breaking from the cohort stands out.
 *
 * Operator can attach Chi-2's CUSUM and PSI classifiers via
 * `addClassifier()` to catch mean-shift and distribution-shape
 * drifts in the same feature stream. Each classifier maintains
 * its own training set and absorbs/emits independently.
 *
 * One detector per fortress; primary classifier per detector is
 * rolling-baseline; additional classifiers are operator-attached.
 * Sovereignty invariant preserved: per-fortress training state,
 * encrypted at rest via Chi-1's `ClassifierStateStore`. Peer
 * comparison happens INSIDE one fortress only; no cross-fortress
 * aggregation is introduced.
 */

import { AnomalyDetector } from "../types.js";
import type {
  AnomalyClassifier,
  AnomalyContext,
  FeatureVector,
} from "../types.js";
import {
  RollingBaselineClassifier,
} from "../classifiers/rolling-baseline.js";
import { ClassifierStateStore } from "../classifier-state-store.js";
import {
  extractCrossAgentDistribution,
  CROSS_AGENT_DISTRIBUTION_EXTRACTOR_ID,
} from "../feature-extractors/cross-agent-distribution.js";

export const CROSS_AGENT_DISTRIBUTION_DETECTOR_ID =
  CROSS_AGENT_DISTRIBUTION_EXTRACTOR_ID;

export interface CrossAgentDistributionDetectorOptions {
  classifier?: AnomalyClassifier;
  /** Optional minimum samples override threaded into the default classifier. */
  minSamplesForPrediction?: number;
}

export class CrossAgentDistributionDetector extends AnomalyDetector {
  readonly detectorId = CROSS_AGENT_DISTRIBUTION_DETECTOR_ID;
  readonly description =
    "Cross-agent distribution detector: per-agent activity features re-expressed as z-scores against the peer cohort in the same 24h window, plus peer count. Catches one agent diverging from its peers even when fortress-wide drift masks it from self-history baselines.";
  readonly classifier: AnomalyClassifier;
  private readonly explicitClassifier: boolean;
  private readonly minSamplesForPrediction: number | undefined;

  constructor(opts?: CrossAgentDistributionDetectorOptions) {
    super();
    this.explicitClassifier = opts?.classifier !== undefined;
    if (opts?.classifier) {
      this.classifier = opts.classifier;
    } else {
      this.classifier = new PendingClassifier();
    }
    this.minSamplesForPrediction = opts?.minSamplesForPrediction;
  }

  override async subscribe(context: AnomalyContext): Promise<void> {
    await super.subscribe(context);
    if (this.explicitClassifier) return;
    const stateStore = new ClassifierStateStore({
      storage: context.storage,
      masterKey: context.masterKey,
      fortressId: context.fortressId,
      now: context.now,
    });
    const realClassifier = new RollingBaselineClassifier({
      stateStore,
      ...(this.minSamplesForPrediction !== undefined
        ? { minSamplesForPrediction: this.minSamplesForPrediction }
        : {}),
    });
    (this as { classifier: AnomalyClassifier }).classifier = realClassifier;
  }

  async featureExtract(context: AnomalyContext): Promise<FeatureVector[]> {
    return extractCrossAgentDistribution(context);
  }
}

class PendingClassifier implements AnomalyClassifier {
  readonly classifierId = "pending" as const;
  async observe(): Promise<void> {
    throw new Error(
      "anomaly-detector: classifier accessed before subscribe()",
    );
  }
  async predict(): Promise<never> {
    throw new Error(
      "anomaly-detector: classifier accessed before subscribe()",
    );
  }
  async train(): Promise<never> {
    throw new Error(
      "anomaly-detector: classifier accessed before subscribe()",
    );
  }
}
