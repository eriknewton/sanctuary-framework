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
import { anomalyRuleId, type ThresholdOverrides } from "../auto-trigger/types.js";

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
 * The rule_id the CUSUM per-agent-activity entry's overrides are
 * persisted under -- the exact key `sanctuary auto-trigger rules
 * set-threshold` and the PATCH route write to. Exported as a single
 * source of truth so the CLI/route write-time guard (which must refuse
 * `warn_sigma` for this specific rule; see `loadCusumSigmaOverride`
 * below) and this read path never drift apart on what "this rule"
 * means.
 */
export const CUSUM_ANOMALY_RULE_ID = anomalyRuleId(
  PER_AGENT_ACTIVITY_DETECTOR_ID,
  CUSUM_CLASSIFIER_ID,
);

/**
 * Raised when this rule's persisted `threshold_overrides` cannot be
 * safely honored: a real store read failure, or a row shape that is
 * unsupported or internally invalid for the CUSUM classifier. The
 * catalog refuses the subscription in every such case rather than
 * silently substituting the classifier's compiled default, because a
 * silent substitution is indistinguishable, from the operator's side,
 * from the override being honored.
 */
export class AnomalyThresholdOverrideError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnomalyThresholdOverrideError";
  }
}

/**
 * Read + validate this rule's persisted override for `h` (see the
 * mapping note on the CUSUM catalog entry below for why only
 * `alert_sigma` has a home here). Three failure classes all refuse via
 * `AnomalyThresholdOverrideError` rather than falling back to the
 * compiled default, because a fallback here is indistinguishable from
 * the override being honored:
 *
 *  1. `ThresholdConfigStore.getResult` reports `"error"` -- the row
 *     exists but could not be read back as written.
 *  2. The row's `threshold_overrides` carries a `warn_sigma` key at
 *     all (any value) -- this classifier has no field that key can
 *     safely bind to.
 *  3. The row's `alert_sigma` key is present but not a finite positive
 *     number.
 *
 * `"absent"` (no row for this rule_id yet) and a row whose
 * `threshold_overrides` touches neither key both return `{}`, which is
 * the one shape that means "compiled defaults apply" -- never a
 * partially-applied row.
 */
async function loadCusumSigmaOverride(
  context: AnomalyContext,
): Promise<{ alertSigma?: number }> {
  const store = new ThresholdConfigStore({
    storage: context.storage,
    masterKey: context.masterKey,
    fortressId: context.fortressId,
    now: context.now,
  });
  const result = await store.getResult(CUSUM_ANOMALY_RULE_ID);
  if (result.status === "error") {
    throw new AnomalyThresholdOverrideError(
      `rule ${CUSUM_ANOMALY_RULE_ID}: threshold overrides could not be read (${describeError(result.error)}); refusing the subscription`,
    );
  }
  if (result.status === "absent") return {};
  const overrides = result.config.threshold_overrides;
  if (!overrides) return {};
  return validateCusumOverrideRow(overrides);
}

function validateCusumOverrideRow(
  overrides: ThresholdOverrides,
): { alertSigma?: number } {
  if (Object.prototype.hasOwnProperty.call(overrides, "warn_sigma")) {
    throw new AnomalyThresholdOverrideError(
      `rule ${CUSUM_ANOMALY_RULE_ID}: warn_sigma is set but the CUSUM classifier has no configurable warning boundary for this rule (only alert_sigma); refusing the subscription`,
    );
  }
  if (!Object.prototype.hasOwnProperty.call(overrides, "alert_sigma")) {
    return {};
  }
  const alertSigma = overrides.alert_sigma;
  if (
    typeof alertSigma !== "number" ||
    !Number.isFinite(alertSigma) ||
    alertSigma <= 0
  ) {
    throw new AnomalyThresholdOverrideError(
      `rule ${CUSUM_ANOMALY_RULE_ID}: alert_sigma is set but is not a finite positive number; refusing the subscription`,
    );
  }
  return { alertSigma };
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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
    // Mapping derivation (IC-29, revised in fix-round 2): only
    // `alert_sigma -> h` is wired. `h` ("decision threshold, in sigma
    // units") is a direct terminology match: the classifier's own class
    // doc names h the alert boundary verbatim -- "Alert fires when
    // max(C+, C-) crosses h*sigma".
    //
    // `warn_sigma` was previously mapped to `k` ("sensitivity slack, in
    // sigma units") "by elimination" -- that mapping was wrong and is
    // NOT restored. `k` is subtracted from every observation BEFORE
    // accumulation (cusum.ts observe(): `c_plus + devFromOldMean -
    // kScaled`); a `k` at or above the true drift magnitude prevents
    // the accumulator from ever growing, so a larger "warning" value
    // there would suppress detection rather than add an earlier
    // warning -- the opposite of what an operator setting a warning
    // knob would expect.
    //
    // The alternative -- wiring warn_sigma into `severityFromAnomalyScore`
    // (types.ts), the shared info/warn/alert cutover at score 3 -- was
    // also considered and rejected: that function is one fixed
    // classifier-agnostic scale shared by rolling-baseline, CUSUM, and
    // PSI, and CUSUM's own `anomaly_score` is already normalized to `h`
    // (1.0 == the alert crossing), not raw sigma units, so a "warn at
    // score >= 3" cutover means something different per classifier and
    // reinterpreting it per-rule is a materially larger, separate
    // architectural change, not a safe narrow mapping.
    //
    // CUSUM therefore has no configurable warning boundary today.
    // `loadCusumSigmaOverride` refuses (throws) rather than silently
    // drops a persisted `warn_sigma` for this rule, and the CLI /
    // PATCH-route write paths refuse `--warn-sigma`/`warn_sigma` for
    // this rule_id up front (see `CUSUM_ANOMALY_RULE_ID` importers).
    classifierFactory: async (context) => {
      const { alertSigma } = await loadCusumSigmaOverride(context);
      return new CusumClassifier({
        stateStore: new ClassifierStateStore({
          storage: context.storage,
          masterKey: context.masterKey,
          fortressId: context.fortressId,
          now: context.now,
        }),
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
