/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-6 Cross-Agent Distribution feature extractor.
 *
 * Detects an agent DIVERGING FROM ITS PEERS, which agent-vs-own-history
 * baselines cannot see. Example: a fortress runs five build agents
 * doing similar work. All five drift busier together during a release
 * week, so each agent's own rolling baseline absorbs the shift without
 * a finding. But one agent that goes quiet while its peers stay busy,
 * or starts hammering credentials while its peers do not, stands out
 * against the cohort even when its own history is too short or too
 * noisy to flag it. This is the "cross-agent distribution comparison"
 * extension point named in the features doc since Chi-5.
 *
 * Per-agent feature vector computed from the SAME per-agent activity
 * features Chi-1 extracts (24h rolling window), re-expressed relative
 * to the peer population observed in that window:
 *
 *  - `peer_z:<activity-feature>`: the agent's value for each Chi-1
 *    activity feature (`tool_call_count`, `egress_call_count`,
 *    `credential_use_count`, `audit_event_count`,
 *    `recent_receipt_count`), expressed as a z-score against the mean
 *    and stddev of all OTHER agents in the window. Stddev floor 0.5
 *    (same floor the rolling-baseline classifier uses) avoids
 *    divide-by-zero on uniform cohorts.
 *  - `peer_count`: how many peer agents the comparison was computed
 *    against. The classifier baselines this too, so cohort-size churn
 *    (agents joining or leaving the fortress) is itself visible drift.
 *
 * The rolling-baseline classifier then learns each agent's NORMAL
 * peer deviation. An orchestrator that legitimately runs 3 sigma
 * hotter than its workers settles at that level; the finding fires
 * when the agent's relationship to the cohort changes.
 *
 * Vectors are only emitted when at least one peer exists (two or more
 * agents observed in the window). Single-agent fortresses produce no
 * vectors: there is no peer distribution to compare against, and the
 * per-agent-activity detector already covers the self-history angle.
 *
 * Castle-walking: read-only. No outbound surface, no LLM call. Pure
 * statistical math over the existing audit log, reusing the Chi-1
 * extractor as the single source of activity-feature truth.
 */

import type {
  AnomalyContext,
  FeatureVector,
} from "../types.js";
import { extractPerAgentActivity } from "./per-agent-activity.js";

export const CROSS_AGENT_DISTRIBUTION_EXTRACTOR_ID =
  "cross-agent-distribution" as const;

/** Feature-name prefix for peer-relative z-scores. Detector-owned namespace. */
export const PEER_Z_PREFIX = "peer_z:" as const;
/** Peer-count feature name. */
export const PEER_COUNT_FEATURE = "peer_count" as const;
/** Stddev floor for the peer distribution; mirrors rolling-baseline. */
export const PEER_STDDEV_FLOOR = 0.5;
/** Window label persisted on each FeatureVector (inherited from Chi-1). */
export const CROSS_AGENT_DISTRIBUTION_WINDOW_LABEL = "24h_rolling" as const;

/**
 * Produce one FeatureVector per agent observed in the rolling 24h
 * window, expressed as peer-relative z-scores. Returns an empty array
 * when fewer than two agents are observable (no peer distribution).
 */
export async function extractCrossAgentDistribution(
  context: AnomalyContext,
): Promise<FeatureVector[]> {
  const activityVectors = await extractPerAgentActivity(context);
  if (activityVectors.length < 2) return [];

  const featureNames = collectFeatureNames(activityVectors);
  const vectors: FeatureVector[] = [];
  for (const vector of activityVectors) {
    const peers = activityVectors.filter(
      (candidate) => candidate.agent_id !== vector.agent_id,
    );
    const features: Record<string, number> = {};
    for (const featureName of featureNames) {
      const observed = vector.features[featureName] ?? 0;
      const peerValues = peers.map((peer) => peer.features[featureName] ?? 0);
      features[`${PEER_Z_PREFIX}${featureName}`] = peerZScore(
        observed,
        peerValues,
      );
    }
    features[PEER_COUNT_FEATURE] = peers.length;
    vectors.push({
      agent_id: vector.agent_id,
      observed_at: vector.observed_at,
      features,
      window_label: CROSS_AGENT_DISTRIBUTION_WINDOW_LABEL,
    });
  }
  return vectors;
}

/** Union of feature names across all activity vectors, sorted for stability. */
function collectFeatureNames(vectors: readonly FeatureVector[]): string[] {
  const names = new Set<string>();
  for (const vector of vectors) {
    for (const name of Object.keys(vector.features)) {
      names.add(name);
    }
  }
  return [...names].sort();
}

/**
 * z-score of `observed` against the peer population, with the
 * rolling-baseline stddev floor applied so a perfectly uniform cohort
 * still yields a finite, meaningful deviation.
 */
function peerZScore(observed: number, peerValues: number[]): number {
  if (peerValues.length === 0) return 0;
  const n = peerValues.length;
  let sum = 0;
  for (const value of peerValues) sum += value;
  const mean = sum / n;
  let sumSq = 0;
  for (const value of peerValues) {
    const d = value - mean;
    sumSq += d * d;
  }
  const stddev = Math.max(Math.sqrt(sumSq / n), PEER_STDDEV_FLOOR);
  return (observed - mean) / stddev;
}
