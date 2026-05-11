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
 * Chi-2's CUSUM + PSI classifiers will register additional catalog
 * entries (same detector + alternative classifier) once that PR
 * lands. Chi-3's UX layer surfaces the catalog as-is; new entries
 * light up automatically on the dashboard.
 */

import {
  PerAgentActivityDetector,
  PER_AGENT_ACTIVITY_DETECTOR_ID,
} from "./detectors/per-agent-activity-detector.js";
import { ROLLING_BASELINE_CLASSIFIER_ID } from "./classifiers/rolling-baseline.js";
import type { AnomalyDetector } from "./types.js";

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
}

/**
 * v1.3 Chi-3 anomaly-detection catalog. Operator subscribes to
 * (detector_id, classifier_id) pairs; the dashboard view + CLI
 * surface this catalog as the available menu.
 *
 * Chi-2 adds CUSUM + PSI entries here when those classifiers land:
 *
 *   {
 *     detectorId: PER_AGENT_ACTIVITY_DETECTOR_ID,
 *     classifierId: CUSUM_CLASSIFIER_ID,
 *     description: "...",
 *     factory: () => new PerAgentActivityDetector({ classifier: new CusumClassifier(...) }),
 *   },
 */
export const ANOMALY_CATALOG: AnomalyCatalogEntry[] = [
  {
    detectorId: PER_AGENT_ACTIVITY_DETECTOR_ID,
    classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
    description:
      "Per-agent statistical drift detector: tool-call count, egress volume, credential-use rate, audit-event count, recent-receipt count over a 24h rolling window. Welford running mean + variance baseline per agent.",
    factory: () => new PerAgentActivityDetector(),
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
