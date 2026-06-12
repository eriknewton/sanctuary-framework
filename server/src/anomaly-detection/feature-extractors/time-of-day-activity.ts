/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-7 Time-Of-Day Activity feature extractor.
 *
 * Lands the "time-of-day-conditioned baselines" entry from the
 * detector catalog's forward list (named there since Chi-6). Detects
 * an agent shifting WHEN it acts, which volume-based baselines cannot
 * see. Example: an agent does 12 tool calls spread across business
 * hours every day. One day it does the same 12 calls between 02:00
 * and 04:00. The Chi-1 per-agent-activity counts are identical -- the
 * total volume and operation mix did not change -- but the agent's
 * diurnal shape did, and "suddenly working at 3am" is one of the
 * classic compromised-credential / exfiltration-window signals.
 *
 * Per-agent feature vector over the trailing 24h window. The window
 * length deliberately equals one full day so every clock hour appears
 * exactly once: each band's count covers exactly its six hours, drawn
 * partly from the previous calendar day when the window straddles
 * midnight.
 *
 *  - `band_count:<band>`: audit events attributed to the agent whose
 *    UTC hour-of-day falls in the band. Four fixed six-hour bands:
 *    `night` [00,06), `morning` [06,12), `afternoon` [12,18),
 *    `evening` [18,24). Event inclusion mirrors Chi-1's
 *    `audit_event_count` (every audit entry attributed to the agent),
 *    so the two detectors agree on what "activity" means.
 *  - `band_proportion:<band>`: the band's share of the agent's total
 *    events in the window. Catches the mix shift even when total
 *    volume drifts with it.
 *  - `active_band_count`: number of bands with at least one event. A
 *    business-hours-only agent that starts spanning all four bands is
 *    drift even before any single band looks extreme.
 *
 * The rolling-baseline classifier learns a separate mean + variance
 * for every band feature per agent: the learned baseline IS
 * time-of-day-conditioned. Bands are fixed UTC intervals, not
 * operator-local time: the labels are arbitrary but DETERMINISTIC,
 * and drift detection only needs the conditioning to be stable, not
 * semantically aligned with the operator's clock. (An agent whose
 * "night" is UTC afternoon simply learns its baseline in the
 * `afternoon` bucket.)
 *
 * Agent attribution mirrors Chi-1: non-empty `identity_id`, else the
 * synthetic `system` bucket. Agents with zero events in the window
 * emit no vector (idle periods stay out of the baseline, same as
 * tool-call-sequence and credential-use-sequence).
 *
 * Castle-walking: read-only. No outbound surface, no LLM call. Pure
 * statistical math over the existing audit log; features are event
 * counts and proportions only -- no operation payloads, no key
 * material, no raw timestamps leave the extractor.
 */

import type {
  AnomalyContext,
  FeatureVector,
} from "../types.js";
import type { AuditEntry } from "../../l2-operational/audit-log.js";

export const TIME_OF_DAY_ACTIVITY_EXTRACTOR_ID =
  "time-of-day-activity" as const;

/** Window size in milliseconds. v1.3 fixed at 24h (one full day; every clock hour appears exactly once). */
export const TIME_OF_DAY_WINDOW_MS = 24 * 60 * 60 * 1000;
/** Band length in hours. Four fixed six-hour UTC bands. */
export const BAND_LENGTH_HOURS = 6;
/** Audit query limit. */
const QUERY_LIMIT = 10_000;
/** Identity-id bucket reused from per-agent-activity. */
export const SYSTEM_AGENT_BUCKET = "system" as const;
/** Window label persisted on each FeatureVector. */
export const TIME_OF_DAY_ACTIVITY_WINDOW_LABEL = "24h_rolling" as const;

/** Fixed UTC time-of-day bands, in clock order. Detector-owned vocabulary. */
export const TIME_OF_DAY_BANDS = [
  "night",
  "morning",
  "afternoon",
  "evening",
] as const;

export type TimeOfDayBand = (typeof TIME_OF_DAY_BANDS)[number];

/** Feature-name prefix for per-band event counts. Detector-owned namespace. */
export const BAND_COUNT_PREFIX = "band_count:" as const;
/** Feature-name prefix for per-band event proportions. Detector-owned namespace. */
export const BAND_PROPORTION_PREFIX = "band_proportion:" as const;
/** Count of bands with at least one event. */
export const ACTIVE_BAND_COUNT_FEATURE = "active_band_count" as const;

/** Map a UTC hour-of-day [0,24) to its band. Boundary hours belong to the later band: hour 6 is `morning`. */
export function bandForUtcHour(hour: number): TimeOfDayBand {
  const index = Math.floor(hour / BAND_LENGTH_HOURS);
  return TIME_OF_DAY_BANDS[Math.min(index, TIME_OF_DAY_BANDS.length - 1)]!;
}

function agentBucket(entry: AuditEntry): string {
  if (entry.identity_id && entry.identity_id.length > 0) {
    return entry.identity_id;
  }
  return SYSTEM_AGENT_BUCKET;
}

/**
 * Produce one FeatureVector per agent with at least one audit event in
 * the trailing 24h window. Returns an empty array when the audit log
 * is empty.
 */
export async function extractTimeOfDayActivity(
  context: AnomalyContext,
): Promise<FeatureVector[]> {
  const now = context.now();
  const sinceIso = new Date(
    now.getTime() - TIME_OF_DAY_WINDOW_MS,
  ).toISOString();
  const result = await context.auditLog.query({
    since: sinceIso,
    limit: QUERY_LIMIT,
  });

  const bandCounts = new Map<string, Map<TimeOfDayBand, number>>();
  for (const entry of result.entries) {
    const ts = Date.parse(entry.timestamp);
    if (!Number.isFinite(ts)) continue;
    const band = bandForUtcHour(new Date(ts).getUTCHours());
    const agentId = agentBucket(entry);
    let counts = bandCounts.get(agentId);
    if (!counts) {
      counts = new Map();
      bandCounts.set(agentId, counts);
    }
    counts.set(band, (counts.get(band) ?? 0) + 1);
  }

  const observedAt = now.toISOString();
  const vectors: FeatureVector[] = [];
  const agentIds = [...bandCounts.keys()].sort();
  for (const agentId of agentIds) {
    const counts = bandCounts.get(agentId)!;
    vectors.push({
      agent_id: agentId,
      observed_at: observedAt,
      features: computeBandFeatures(counts),
      window_label: TIME_OF_DAY_ACTIVITY_WINDOW_LABEL,
    });
  }
  return vectors;
}

function computeBandFeatures(
  counts: ReadonlyMap<TimeOfDayBand, number>,
): Record<string, number> {
  let total = 0;
  let activeBands = 0;
  for (const band of TIME_OF_DAY_BANDS) {
    const count = counts.get(band) ?? 0;
    total += count;
    if (count > 0) activeBands += 1;
  }
  const features: Record<string, number> = {};
  for (const band of TIME_OF_DAY_BANDS) {
    const count = counts.get(band) ?? 0;
    features[`${BAND_COUNT_PREFIX}${band}`] = count;
    features[`${BAND_PROPORTION_PREFIX}${band}`] =
      total > 0 ? count / total : 0;
  }
  features[ACTIVE_BAND_COUNT_FEATURE] = activeBands;
  return features;
}
