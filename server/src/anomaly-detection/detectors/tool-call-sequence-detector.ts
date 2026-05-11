/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-4 Tool-Call Sequence Detector.
 *
 * Composes the tool-call-sequence feature extractor + a default
 * rolling-baseline classifier. Inherits the default
 * predict-then-observe `evaluate()` loop from `AnomalyDetector`
 * (Chi-1 invariant; Chi-2 preserved per-classifier).
 *
 * Operator can attach Chi-2's CUSUM and PSI classifiers via
 * `addClassifier()` to catch mean-shift and distribution-shape
 * drifts in the same feature stream. Each classifier maintains
 * its own training set and absorbs/emits independently.
 *
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
  extractToolCallSequence,
  TOOL_CALL_SEQUENCE_EXTRACTOR_ID,
} from "../feature-extractors/tool-call-sequence.js";

export const TOOL_CALL_SEQUENCE_DETECTOR_ID =
  TOOL_CALL_SEQUENCE_EXTRACTOR_ID;

export interface ToolCallSequenceDetectorOptions {
  classifier?: AnomalyClassifier;
  /** Optional minimum samples override threaded into the default classifier. */
  minSamplesForPrediction?: number;
}

export class ToolCallSequenceDetector extends AnomalyDetector {
  readonly detectorId = TOOL_CALL_SEQUENCE_DETECTOR_ID;
  readonly description =
    "Tool-call sequence detector: per-agent distinct-tools-used, max sequence length, 3-gram Shannon entropy, and 2-gram repeat-pattern score over a 5-minute sliding window. Catches unusual orderings and data-exfiltration-shaped repeat patterns.";
  readonly classifier: AnomalyClassifier;
  private readonly explicitClassifier: boolean;
  private readonly minSamplesForPrediction: number | undefined;

  constructor(opts?: ToolCallSequenceDetectorOptions) {
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
    return extractToolCallSequence(context);
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
