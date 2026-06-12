/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-7 Time-Of-Day Activity Detector.
 *
 * Composes the time-of-day-activity feature extractor + a default
 * rolling-baseline classifier. Inherits the default
 * predict-then-observe `evaluate()` loop from `AnomalyDetector`
 * (Chi-1 invariant; Chi-2 preserved per-classifier).
 *
 * Lands the "time-of-day-conditioned baselines" forward-list entry:
 * because every band is its own feature, the rolling baseline learns
 * a separate mean + variance per six-hour UTC band per agent. The
 * learned baseline is therefore conditioned on time-of-day without
 * any classifier change.
 *
 * Complements (does not replace) the Chi-1 per-agent-activity
 * detector: Chi-1 sees HOW MUCH an agent does; this detector sees
 * WHEN. An agent that moves its usual workload into the small hours
 * at constant volume is invisible to Chi-1 and fires here.
 *
 * Operator can attach Chi-2's CUSUM and PSI classifiers via
 * `addClassifier()` to catch mean-shift and distribution-shape
 * drifts in the same feature stream. Each classifier maintains
 * its own training set and absorbs/emits independently.
 *
 * One detector per fortress; primary classifier per detector is
 * rolling-baseline; additional classifiers are operator-attached.
 * Sovereignty invariant preserved: per-fortress training state,
 * encrypted at rest via Chi-1's `ClassifierStateStore`.
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
  extractTimeOfDayActivity,
  TIME_OF_DAY_ACTIVITY_EXTRACTOR_ID,
} from "../feature-extractors/time-of-day-activity.js";

export const TIME_OF_DAY_ACTIVITY_DETECTOR_ID =
  TIME_OF_DAY_ACTIVITY_EXTRACTOR_ID;

export interface TimeOfDayActivityDetectorOptions {
  classifier?: AnomalyClassifier;
  /** Optional minimum samples override threaded into the default classifier. */
  minSamplesForPrediction?: number;
}

export class TimeOfDayActivityDetector extends AnomalyDetector {
  readonly detectorId = TIME_OF_DAY_ACTIVITY_DETECTOR_ID;
  readonly description =
    "Time-of-day activity detector: per-agent audit-event counts and proportions across four fixed six-hour UTC bands plus active-band count over a 24h window. Catches off-hours activity shifts at constant volume that count-based baselines miss.";
  readonly classifier: AnomalyClassifier;
  private readonly explicitClassifier: boolean;
  private readonly minSamplesForPrediction: number | undefined;

  constructor(opts?: TimeOfDayActivityDetectorOptions) {
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
    return extractTimeOfDayActivity(context);
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
