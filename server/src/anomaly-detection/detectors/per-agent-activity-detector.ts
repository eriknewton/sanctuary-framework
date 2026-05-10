/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-1 Per-Agent Activity Detector.
 *
 * Composes the per-agent-activity feature extractor + the
 * rolling-baseline classifier. Inherits the default evaluate() loop
 * from AnomalyDetector: extract -> observe (training) -> predict
 * (drift) -> emit findings above 1 sigma.
 *
 * One detector per fortress; one classifier per detector; one
 * Welford state per (classifier, agent). The whole stack stays
 * inside the fortress; nothing aggregates centrally.
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
  extractPerAgentActivity,
  PER_AGENT_ACTIVITY_EXTRACTOR_ID,
} from "../feature-extractors/per-agent-activity.js";

export const PER_AGENT_ACTIVITY_DETECTOR_ID =
  PER_AGENT_ACTIVITY_EXTRACTOR_ID;

export interface PerAgentActivityDetectorOptions {
  classifier?: AnomalyClassifier;
  /** Optional minimum samples override threaded into the default classifier. */
  minSamplesForPrediction?: number;
}

/**
 * v1.3 Chi-1 detector. Subclasses may override featureExtract() to
 * pre-process or filter the extracted vectors; the default uses the
 * shared per-agent-activity extractor.
 */
export class PerAgentActivityDetector extends AnomalyDetector {
  readonly detectorId = PER_AGENT_ACTIVITY_DETECTOR_ID;
  readonly description =
    "Per-agent statistical drift detector: tool-call count, egress volume, credential-use rate, audit-event count, recent-receipt count over a 24h rolling window. Compared against a per-agent rolling baseline (Welford running mean + variance).";
  readonly classifier: AnomalyClassifier;
  private readonly explicitClassifier: boolean;
  private readonly minSamplesForPrediction: number | undefined;

  constructor(opts?: PerAgentActivityDetectorOptions) {
    super();
    this.explicitClassifier = opts?.classifier !== undefined;
    if (opts?.classifier) {
      this.classifier = opts.classifier;
    } else {
      // Defer construction until we have the context's storage + key.
      // Placeholder; replaced in subscribe(). The intermediate value
      // exists only to satisfy TypeScript's strict initialization.
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
    return extractPerAgentActivity(context);
  }
}

/**
 * Throws on every method. Used as a placeholder so the detector type
 * stays non-nullable until subscribe() wires the real classifier.
 */
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
