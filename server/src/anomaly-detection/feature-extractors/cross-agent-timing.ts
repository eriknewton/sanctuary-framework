/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-4 Cross-Agent Timing feature extractor.
 *
 * Detects unusual co-firing patterns BETWEEN pairs of agents that
 * the per-agent activity extractor cannot see. Example: Cline and
 * OpenClaw normally operate hours apart on different tasks. One day
 * they suddenly fire within seconds of each other repeatedly. The
 * per-agent baselines look normal individually; the CORRELATION is
 * the anomaly.
 *
 * Per-(unordered-agent-pair) feature vector with four numeric
 * features:
 *
 *  - `co_fire_rate_24h`: count of event pairs (one from each agent)
 *    falling within `CO_FIRE_WINDOW_MS` (60s) of each other, over
 *    the last 24h.
 *  - `inter_event_time_p50_ms`: median of times-between-events
 *    measured as A->B-next or B->A-next within the 24h window.
 *  - `inter_event_time_p99_ms`: 99th percentile of the same
 *    distribution. Captures the long-tail behavior independent of
 *    the median.
 *  - `correlation_strength`: Pearson correlation coefficient between
 *    the two agents' event-count time series, computed over fixed
 *    5-minute buckets across the window. Range -1..1; 0 means no
 *    correlation, 1 means perfect co-firing, -1 means perfect anti-
 *    correlation. The classifier observes the ABSOLUTE value as a
 *    "magnitude of co-fire signal" feature, since both extremes are
 *    operationally meaningful drift.
 *
 * Castle-walking: read-only. No outbound surface, no LLM call. Pure
 * statistical math over the existing audit log.
 */

import type {
  AnomalyContext,
  FeatureVector,
} from "../types.js";
import type { AuditEntry } from "../../operational/audit-log.js";

export const CROSS_AGENT_TIMING_EXTRACTOR_ID = "cross-agent-timing" as const;

/** Window size in milliseconds. v1.3 fixed at 24h. */
const WINDOW_MS = 24 * 60 * 60 * 1000;
/** Co-fire window in milliseconds. v1.3 fixed at 60s. */
export const CO_FIRE_WINDOW_MS = 60_000;
/** Bucket size for the Pearson-correlation time series. v1.3 fixed at 5min. */
export const CORRELATION_BUCKET_MS = 5 * 60 * 1000;
/** Audit query limit. */
const QUERY_LIMIT = 10_000;
/** Identity-id bucket reused from per-agent-activity. */
export const SYSTEM_AGENT_BUCKET = "system" as const;
/** Window label persisted on each FeatureVector. */
export const CROSS_AGENT_TIMING_WINDOW_LABEL = "24h_rolling" as const;

const FEATURE_NAMES = [
  "co_fire_rate_24h",
  "inter_event_time_p50_ms",
  "inter_event_time_p99_ms",
  "correlation_strength",
] as const;

export type CrossAgentTimingFeatureName = (typeof FEATURE_NAMES)[number];

interface AgentEventStream {
  /** Per-agent timestamps (ms epoch), sorted ascending. */
  timestamps: number[];
  /** Per-bucket event counts; index = floor(timestamp_ms / CORRELATION_BUCKET_MS). */
  buckets: Map<number, number>;
}

/** Pair key is the canonical lexicographic order of two agent ids. */
export function pairKey(a: string, b: string): string {
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

/** Inverse of pairKey. Exported for diagnostics + tests. */
export function pairFromKey(key: string): { agent_a: string; agent_b: string } {
  const idx = key.indexOf("|");
  return { agent_a: key.slice(0, idx), agent_b: key.slice(idx + 1) };
}

/**
 * Produce one FeatureVector per UNORDERED agent-pair observed in
 * the rolling 24h window. Returns an empty array when there is
 * nothing observable. Pair `agent_id` field on the FeatureVector
 * carries the canonical pair-key string.
 */
export async function extractCrossAgentTiming(
  context: AnomalyContext,
): Promise<FeatureVector[]> {
  const now = context.now();
  const sinceIso = new Date(now.getTime() - WINDOW_MS).toISOString();
  const result = await context.auditLog.query({
    since: sinceIso,
    limit: QUERY_LIMIT,
  });

  const streams = collectAgentStreams(result.entries);
  const observedAt = now.toISOString();
  const vectors: FeatureVector[] = [];

  const agentIds = [...streams.keys()].sort();
  for (let i = 0; i < agentIds.length; i += 1) {
    for (let j = i + 1; j < agentIds.length; j += 1) {
      const idA = agentIds[i]!;
      const idB = agentIds[j]!;
      const streamA = streams.get(idA)!;
      const streamB = streams.get(idB)!;
      const features = computePairFeatures(streamA, streamB);
      vectors.push({
        agent_id: pairKey(idA, idB),
        observed_at: observedAt,
        features,
        window_label: CROSS_AGENT_TIMING_WINDOW_LABEL,
      });
    }
  }
  return vectors;
}

function collectAgentStreams(
  entries: readonly AuditEntry[],
): Map<string, AgentEventStream> {
  const out = new Map<string, AgentEventStream>();
  for (const entry of entries) {
    const id =
      entry.identity_id && entry.identity_id.length > 0
        ? entry.identity_id
        : SYSTEM_AGENT_BUCKET;
    const ts = Date.parse(entry.timestamp);
    if (!Number.isFinite(ts)) continue;
    let stream = out.get(id);
    if (!stream) {
      stream = { timestamps: [], buckets: new Map() };
      out.set(id, stream);
    }
    stream.timestamps.push(ts);
    const bucket = Math.floor(ts / CORRELATION_BUCKET_MS);
    stream.buckets.set(bucket, (stream.buckets.get(bucket) ?? 0) + 1);
  }
  for (const stream of out.values()) {
    stream.timestamps.sort((a, b) => a - b);
  }
  return out;
}

function computePairFeatures(
  a: AgentEventStream,
  b: AgentEventStream,
): Record<string, number> {
  const co_fire_rate_24h = countCoFires(a.timestamps, b.timestamps);
  const interEventTimes = collectInterEventTimes(a.timestamps, b.timestamps);
  const inter_event_time_p50_ms = percentile(interEventTimes, 0.5);
  const inter_event_time_p99_ms = percentile(interEventTimes, 0.99);
  const correlation_strength = pearsonCorrelation(a.buckets, b.buckets);
  return {
    co_fire_rate_24h,
    inter_event_time_p50_ms,
    inter_event_time_p99_ms,
    correlation_strength,
  };
}

/**
 * Count event pairs (one from each stream) within CO_FIRE_WINDOW_MS.
 * Linear two-pointer sweep; both arrays must be sorted ascending.
 */
function countCoFires(a: number[], b: number[]): number {
  if (a.length === 0 || b.length === 0) return 0;
  let count = 0;
  for (const tsA of a) {
    const lo = tsA - CO_FIRE_WINDOW_MS;
    const hi = tsA + CO_FIRE_WINDOW_MS;
    for (const tsB of b) {
      if (tsB < lo) continue;
      if (tsB > hi) break;
      count += 1;
    }
  }
  return count;
}

/**
 * Collect inter-event times: for every event in A, distance to the
 * NEXT event in B (and vice versa). Returns absolute milliseconds.
 * Empty when either stream is empty.
 */
function collectInterEventTimes(a: number[], b: number[]): number[] {
  const out: number[] = [];
  const pushNext = (src: number[], other: number[]): void => {
    if (other.length === 0) return;
    let cursor = 0;
    for (const ts of src) {
      while (cursor < other.length && other[cursor]! < ts) cursor += 1;
      if (cursor < other.length) {
        out.push(other[cursor]! - ts);
      }
    }
  };
  pushNext(a, b);
  pushNext(b, a);
  return out;
}

function percentile(sortedSource: number[], p: number): number {
  if (sortedSource.length === 0) return 0;
  const sorted = [...sortedSource].sort((x, y) => x - y);
  const idx = Math.min(
    sorted.length - 1,
    Math.floor(p * sorted.length),
  );
  return sorted[idx]!;
}

/**
 * Pearson correlation coefficient over per-bucket event counts.
 * Returns 0 when either side has zero variance (constant). Range
 * -1..1; the classifier observes this as-is so both polarity and
 * magnitude can drift independently.
 */
function pearsonCorrelation(
  bucketsA: Map<number, number>,
  bucketsB: Map<number, number>,
): number {
  const allBuckets = new Set<number>([
    ...bucketsA.keys(),
    ...bucketsB.keys(),
  ]);
  if (allBuckets.size === 0) return 0;
  const xs: number[] = [];
  const ys: number[] = [];
  for (const bucket of allBuckets) {
    xs.push(bucketsA.get(bucket) ?? 0);
    ys.push(bucketsB.get(bucket) ?? 0);
  }
  const n = xs.length;
  let sumX = 0;
  let sumY = 0;
  for (let i = 0; i < n; i += 1) {
    sumX += xs[i]!;
    sumY += ys[i]!;
  }
  const meanX = sumX / n;
  const meanY = sumY / n;
  let sumXY = 0;
  let sumX2 = 0;
  let sumY2 = 0;
  for (let i = 0; i < n; i += 1) {
    const dx = xs[i]! - meanX;
    const dy = ys[i]! - meanY;
    sumXY += dx * dy;
    sumX2 += dx * dx;
    sumY2 += dy * dy;
  }
  const denom = Math.sqrt(sumX2 * sumY2);
  if (denom === 0) return 0;
  return sumXY / denom;
}

export { FEATURE_NAMES };
