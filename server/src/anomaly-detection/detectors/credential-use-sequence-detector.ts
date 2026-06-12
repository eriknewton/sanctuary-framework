/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-6 Credential-Use Sequence Detector.
 *
 * Composes the credential-use-sequence feature extractor + a default
 * rolling-baseline classifier. Inherits the default
 * predict-then-observe `evaluate()` loop from `AnomalyDetector`
 * (Chi-1 invariant; Chi-2 preserved per-classifier).
 *
 * Complements (does not replace) the Phi-2 rule-based credential-usage
 * watcher: Phi-2 fires on known shapes (per-secret rate spike,
 * never-before-seen secret pair); this detector learns each agent's
 * normal credential-consumption SHAPE (breadth, repeat pattern, burst)
 * and surfaces statistical drift from it.
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
  extractCredentialUseSequence,
  CREDENTIAL_USE_SEQUENCE_EXTRACTOR_ID,
} from "../feature-extractors/credential-use-sequence.js";

export const CREDENTIAL_USE_SEQUENCE_DETECTOR_ID =
  CREDENTIAL_USE_SEQUENCE_EXTRACTOR_ID;

export interface CredentialUseSequenceDetectorOptions {
  classifier?: AnomalyClassifier;
  /** Optional minimum samples override threaded into the default classifier. */
  minSamplesForPrediction?: number;
}

export class CredentialUseSequenceDetector extends AnomalyDetector {
  readonly detectorId = CREDENTIAL_USE_SEQUENCE_DETECTOR_ID;
  readonly description =
    "Credential-use sequence detector: per-agent credential-event count, distinct credentials used, repeated credential-pair score, and max 5-minute burst over a 24h rolling window. Catches credential enumeration and burst-dump shapes that total counts miss.";
  readonly classifier: AnomalyClassifier;
  private readonly explicitClassifier: boolean;
  private readonly minSamplesForPrediction: number | undefined;

  constructor(opts?: CredentialUseSequenceDetectorOptions) {
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
    return extractCredentialUseSequence(context);
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
