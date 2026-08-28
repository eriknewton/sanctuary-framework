/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-3 Anomaly Detector Catalog.
 *
 * Operator-visible catalog of detector + classifier combinations that
 * can be subscribed via the Anomaly Detection dashboard view + CLI.
 * Mirrors the Phi-1 PHI1_BASELINE_CATALOG factory pattern: each entry
 * carries a stable id, an operator-facing description, and a factory
 * that produces a fresh detector instance for the per-fortress
 * AnomalyPipelineDispatcher.
 *
 * Chi-1 shipped one detector (per-agent activity) wired to the
 * rolling-baseline classifier. Chi-3 surfaces it through the catalog
 * so the operator can subscribe via the dashboard / CLI rather than
 * editing server boot code.
 *
 * Chi-2's CUSUM + PSI classifiers are LANDED and registered below
 * (same detector + alternative classifier). Chi-3's UX layer
 * surfaces the catalog as-is; new entries light up automatically
 * on the dashboard.
 */

import {
  PerAgentActivityDetector,
  PER_AGENT_ACTIVITY_DETECTOR_ID,
} from "./detectors/per-agent-activity-detector.js";
import {
  CrossAgentTimingDetector,
  CROSS_AGENT_TIMING_DETECTOR_ID,
} from "./detectors/cross-agent-timing-detector.js";
import {
  ToolCallSequenceDetector,
  TOOL_CALL_SEQUENCE_DETECTOR_ID,
} from "./detectors/tool-call-sequence-detector.js";
import {
  AuditEventClassDistributionDetector,
  AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
  AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID,
  DEFAULT_AUDIT_EVENT_CLASS_PSI_THRESHOLD,
  DEFAULT_BASELINE_SAMPLE_COUNT,
} from "./detectors/audit-event-class-distribution-detector.js";
import {
  CredentialUseSequenceDetector,
  CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
} from "./detectors/credential-use-sequence-detector.js";
import {
  CrossAgentDistributionDetector,
  CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
} from "./detectors/cross-agent-distribution-detector.js";
import {
  TimeOfDayActivityDetector,
  TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
} from "./detectors/time-of-day-activity-detector.js";
import {
  DEFAULT_MIN_SAMPLES_FOR_PREDICTION,
  ROLLING_BASELINE_CLASSIFIER_ID,
} from "./classifiers/rolling-baseline.js";
import { CUSUM_CLASSIFIER_ID, CusumClassifier } from "./classifiers/cusum.js";
import { PSI_CLASSIFIER_ID, PsiClassifier } from "./classifiers/psi.js";
import { ClassifierStateStore } from "./classifier-state-store.js";
import type { AnomalyClassifier, AnomalyContext, AnomalyDetector } from "./types.js";
import { ThresholdConfigStore } from "../auto-trigger/threshold-config-store.js";
import { anomalyRuleId } from "../auto-trigger/types.js";

/**
 * One detector + classifier combination. The detectorId + classifierId
 * tuple is the operator-visible key; the dashboard renders both and
 * the subscription state hangs off the tuple.
 */
export interface AnomalyCatalogEntry {
  /** Stable detector id (matches AnomalyDetector.detectorId). */
  detectorId: string;
  /** Stable classifier id (matches AnomalyClassifier.classifierId). */
  classifierId: string;
  /** Operator-facing description. */
  description: string;
  /** Factory producing a fresh detector instance on each subscribe. */
  factory: () => AnomalyDetector;
  /**
   * Factory for classifier-specific subscriptions when the detector is
   * already active under another classifier tuple. May return a
   * Promise: constructing a classifier can require reading the
   * operator's persisted `ThresholdOverrides` for this rule first (see
   * the CUSUM entry below), which is an async storage read.
   */
  classifierFactory?: (
    context: AnomalyContext,
  ) => AnomalyClassifier | Promise<AnomalyClassifier>;
}

/**
 * Read this rule's persisted `warn_sigma`/`alert_sigma` overrides (if
 * any) and validate them to finite positive numbers -- an absent,
 * malformed, or non-positive override is dropped so the caller falls
 * back to the classifier's own compiled-in default rather than ever
 * widening detection (IC-29: "an absent/partial override never widens
 * detection, fail toward the existing defaults, never toward
 * silence"). `ThresholdConfigStore.get()` itself already resolves a
 * corrupt/undecryptable record to `null`, so a storage or crypto
 * failure here also falls through to "no override" rather than
 * throwing.
 */
async function loadValidatedSigmaOverrides(
  context: AnomalyContext,
  detectorId: string,
  classifierId: string,
): Promise<{ warnSigma?: number; alertSigma?: number }> {
  const store = new ThresholdConfigStore({
    storage: context.storage,
    masterKey: context.masterKey,
    fortressId: context.fortressId,
    now: context.now,
  });
  const config = await store.get(anomalyRuleId(detectorId, classifierId));
  const overrides = config?.threshold_overrides;
  if (!overrides) return {};
  const warnSigma = positiveFiniteOrUndefined(overrides.warn_sigma);
  const alertSigma = positiveFiniteOrUndefined(overrides.alert_sigma);
  return {
    ...(warnSigma !== undefined ? { warnSigma } : {}),
    ...(alertSigma !== undefined ? { alertSigma } : {}),
  };
}

function positiveFiniteOrUndefined(n: number | undefined): number | undefined {
  return n !== undefined && Number.isFinite(n) && n > 0 ? n : undefined;
}

/**
 * v1.3 Chi-3 anomaly-detection catalog. Operator subscribes to
 * (detector_id, classifier_id) pairs; the dashboard view + CLI
 * surface this catalog as the available menu.
 *
 * Chi-2's CUSUM + PSI entries are registered below (LANDED — do not
 * re-scope "land Chi-2" from this comment; check the entries first).
 */
export const ANOMALY_CATALOG: AnomalyCatalogEntry[] = [
  {
    detectorId: PER_AGENT_ACTIVITY_DETECTOR_ID,
    classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
    description:
      "Per-agent statistical drift detector: tool-call count, egress volume, credential-use rate, audit-event count, recent-receipt count over a 24h rolling window. Welford running mean + variance baseline per agent.",
    factory: () => new PerAgentActivityDetector(),
  },
  {
    detectorId: PER_AGENT_ACTIVITY_DETECTOR_ID,
    classifierId: CUSUM_CLASSIFIER_ID,
    description:
      "Per-agent CUSUM drift detector over the same per-agent activity feature stream. Catches slow mean shifts that single-sample baselines may miss.",
    factory: () => new PerAgentActivityDetector(),
    // Mapping derivation (IC-29): CusumClassifierOptions exposes exactly
    // two sigma-unit knobs, `k` ("sensitivity slack, in sigma units")
    // and `h` ("decision threshold, in sigma units"), and the class doc
    // itself names h as the alert boundary verbatim -- "Alert fires
    // when max(C+, C-) crosses h*sigma" -- so `alert_sigma` maps to `h`
    // by a direct terminology match. `k` is the only remaining
    // sigma-unit knob, governing how much a sample must deviate before
    // it starts accumulating toward that alert boundary (the
    // "early-warning" slack), so `warn_sigma` maps to `k` by
    // elimination + unit match. This side (the catalog, not the CLI or
    // the classifier) owns the mapping; CusumClassifier still owns the
    // `?? DEFAULT_CUSUM_K` / `?? DEFAULT_CUSUM_H` fallback, so an
    // absent or invalid override reaches the constructor as `undefined`
    // and never overrides the default.
    classifierFactory: async (context) => {
      const { warnSigma, alertSigma } = await loadValidatedSigmaOverrides(
        context,
        PER_AGENT_ACTIVITY_DETECTOR_ID,
        CUSUM_CLASSIFIER_ID,
      );
      return new CusumClassifier({
        stateStore: new ClassifierStateStore({
          storage: context.storage,
          masterKey: context.masterKey,
          fortressId: context.fortressId,
          now: context.now,
        }),
        ...(warnSigma !== undefined ? { k: warnSigma } : {}),
        ...(alertSigma !== undefined ? { h: alertSigma } : {}),
      });
    },
  },
  {
    detectorId: PER_AGENT_ACTIVITY_DETECTOR_ID,
    classifierId: PSI_CLASSIFIER_ID,
    description:
      "Per-agent PSI distribution-shift detector over the same per-agent activity feature stream. Catches feature-shape drift independent of mean movement.",
    factory: () => new PerAgentActivityDetector(),
    classifierFactory: (context) =>
      new PsiClassifier({
        stateStore: new ClassifierStateStore({
          storage: context.storage,
          masterKey: context.masterKey,
          fortressId: context.fortressId,
          now: context.now,
        }),
      }),
  },
  {
    detectorId: CROSS_AGENT_TIMING_DETECTOR_ID,
    classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
    description:
      `Cross-agent timing detector: per-agent-pair co-fire rate, inter-event time distribution, and Pearson correlation strength. Operator tunable: minSamplesForPrediction default ${DEFAULT_MIN_SAMPLES_FOR_PREDICTION}.`,
    factory: () => new CrossAgentTimingDetector(),
  },
  {
    detectorId: TOOL_CALL_SEQUENCE_DETECTOR_ID,
    classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
    description:
      `Tool-call sequence detector: per-agent distinct-tools-used, max sequence length, 3-gram Shannon entropy, and 2-gram repeat-pattern score. Operator tunable: minSamplesForPrediction default ${DEFAULT_MIN_SAMPLES_FOR_PREDICTION}.`,
    factory: () => new ToolCallSequenceDetector(),
  },
  {
    detectorId: AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
    classifierId: AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID,
    description:
      `Audit-event class distribution detector: per-agent categorical PSI over audit operation mix, with top per-class drift attribution. Operator tunables: psiThreshold default ${DEFAULT_AUDIT_EVENT_CLASS_PSI_THRESHOLD}, baselineSampleCount default ${DEFAULT_BASELINE_SAMPLE_COUNT}.`,
    factory: () => new AuditEventClassDistributionDetector(),
  },
  {
    detectorId: CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
    classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
    description:
      `Credential-use sequence detector: per-agent credential-event count, distinct credentials used, repeated credential-pair score, and max 5-minute burst over a 24h rolling window. Operator tunable: minSamplesForPrediction default ${DEFAULT_MIN_SAMPLES_FOR_PREDICTION}.`,
    factory: () => new CredentialUseSequenceDetector(),
  },
  {
    detectorId: CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
    classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
    description:
      `Cross-agent distribution detector: per-agent activity features re-expressed as peer-relative z-scores plus peer count over a 24h window. Operator tunable: minSamplesForPrediction default ${DEFAULT_MIN_SAMPLES_FOR_PREDICTION}.`,
    factory: () => new CrossAgentDistributionDetector(),
  },
  {
    detectorId: TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
    classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
    description:
      `Time-of-day activity detector: per-agent audit-event counts and proportions across four fixed six-hour UTC bands plus active-band count over a 24h window. Operator tunable: minSamplesForPrediction default ${DEFAULT_MIN_SAMPLES_FOR_PREDICTION}.`,
    factory: () => new TimeOfDayActivityDetector(),
  },
];

/**
 * Build a stable string key for a (detector, classifier) tuple.
 * Used as the URL path segment for subscribe / unsubscribe routes
 * and as the in-memory dispatcher registration key.
 *
 * The dispatcher's `registerDetector` keys by `detector.detectorId`
 * alone; Chi-3 keeps things compatible by treating (detectorId,
 * classifierId) as the OPERATOR-VISIBLE key but registering each
 * tuple's factory output under its detectorId. A future
 * dispatcher-side composite-key extension lights up multiple
 * classifiers per detector; Chi-3 ships the URL surface ready for
 * that without forcing it.
 */
export function catalogKey(
  detectorId: string,
  classifierId: string,
): string {
  return `${detectorId}__${classifierId}`;
}

/** Find a catalog entry by detector + classifier id. */
export function findCatalogEntry(
  detectorId: string,
  classifierId: string,
): AnomalyCatalogEntry | undefined {
  return ANOMALY_CATALOG.find(
    (e) => e.detectorId === detectorId && e.classifierId === classifierId,
  );
}
