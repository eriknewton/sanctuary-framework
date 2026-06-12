/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-6 Credential-Use Sequence feature extractor.
 *
 * Detects unusual SHAPES in an agent's credential consumption that the
 * per-agent activity count (`credential_use_count`) cannot see.
 * Example: an agent normally reads `db_token` a few times spread over
 * a day. One day it reads `db_token`, `aws_root`, `stripe_secret`,
 * `db_token`, `aws_root`, `stripe_secret` in a tight loop within five
 * minutes. The total count may sit inside the agent's normal band; the
 * breadth, the hammered repeat pattern, and the burst are the anomaly.
 *
 * This extractor was named in the detector catalog's forward list
 * ("credential-use sequence patterns") since Chi-4; Chi-6 lands it.
 *
 * Per-agent feature vector with four numeric features over the rolling
 * 24h window (credential use is sparse; a 5-minute window would rarely
 * hold two events):
 *
 *  - `credential_event_count`: total broker credential operations
 *    (`broker_secret_*`, `broker_token_*`) attributed to the agent in
 *    the window. Mirrors per-agent-activity's `credential_use_count`
 *    inclusion rule so the two detectors agree on what "credential
 *    use" means.
 *  - `distinct_credentials_used`: count of unique credential tokens in
 *    the agent's sequence. A sudden breadth expansion is the
 *    "compromised agent enumerates every secret it can reach" shape.
 *  - `repeat_pair_score`: sum of (count - 1) over every consecutive
 *    credential 2-gram, same formula as the tool-call-sequence
 *    extractor's `repeat_pattern_score`. Captures one credential pair
 *    being hammered in alternation.
 *  - `burst_max_5min`: maximum number of credential operations falling
 *    into any single fixed 5-minute bucket of the window. Captures the
 *    dump-everything-at-once burst even when the 24h total looks
 *    ordinary.
 *
 * Credential token attribution: the broker audit payloads (see
 * `l3-disclosure/broker/token-issuer.ts` and the Phi-2 credential-usage
 * watcher) carry the secret id in `details.secret`. When present, that
 * id is the sequence token; otherwise the extractor falls back to the
 * operation name so schema-less entries still contribute to count and
 * burst features deterministically.
 *
 * Agent attribution: broker entries record the wrapped agent in
 * `details.agent` (the audit `identity_id` is often the broker
 * dependency identity). The extractor prefers `details.agent`, falls
 * back to `identity_id`, then to the synthetic `system` bucket,
 * matching the Phi-2 watcher's grouping while staying compatible with
 * the anomaly family's bucket convention.
 *
 * Castle-walking: read-only. No outbound surface, no LLM call. Pure
 * statistical math over the existing audit log.
 */

import type {
  AnomalyContext,
  FeatureVector,
} from "../types.js";
import type { AuditEntry } from "../../l2-operational/audit-log.js";

export const CREDENTIAL_USE_SEQUENCE_EXTRACTOR_ID =
  "credential-use-sequence" as const;

/** Window size in milliseconds. v1.3 fixed at 24h. */
export const CREDENTIAL_SEQUENCE_WINDOW_MS = 24 * 60 * 60 * 1000;
/** Burst bucket size in milliseconds. v1.3 fixed at 5 minutes. */
export const BURST_BUCKET_MS = 5 * 60 * 1000;
/** Audit query limit. */
const QUERY_LIMIT = 10_000;
/** Identity-id bucket reused from per-agent-activity. */
export const SYSTEM_AGENT_BUCKET = "system" as const;
/** Window label persisted on each FeatureVector. */
export const CREDENTIAL_USE_SEQUENCE_WINDOW_LABEL = "24h_rolling" as const;

const FEATURE_NAMES = [
  "credential_event_count",
  "distinct_credentials_used",
  "repeat_pair_score",
  "burst_max_5min",
] as const;

export type CredentialUseSequenceFeatureName = (typeof FEATURE_NAMES)[number];

/** Broker audit-op prefixes that count as credential use (Chi-1 rule). */
const CREDENTIAL_OP_PREFIXES = ["broker_secret_", "broker_token_"] as const;

interface AgentCredentialSequence {
  /** Ordered credential tokens (secret id or operation fallback). */
  tokens: string[];
  /** Event timestamps (ms epoch) in audit-log order. */
  timestamps: number[];
}

function isCredentialEntry(entry: AuditEntry): boolean {
  return CREDENTIAL_OP_PREFIXES.some((prefix) =>
    entry.operation.startsWith(prefix),
  );
}

function credentialToken(entry: AuditEntry): string {
  const details = entry.details as Record<string, unknown> | undefined;
  const secret = details?.["secret"];
  if (typeof secret === "string" && secret.length > 0) return secret;
  return entry.operation;
}

function agentBucket(entry: AuditEntry): string {
  const details = entry.details as Record<string, unknown> | undefined;
  const agent = details?.["agent"];
  if (typeof agent === "string" && agent.length > 0) return agent;
  if (entry.identity_id && entry.identity_id.length > 0) {
    return entry.identity_id;
  }
  return SYSTEM_AGENT_BUCKET;
}

/**
 * Produce one FeatureVector per agent with at least one credential
 * operation in the rolling 24h window. Agents with zero credential
 * activity are skipped (no vector emitted; keeps idle periods out of
 * the baseline the same way tool-call-sequence skips idle agents).
 */
export async function extractCredentialUseSequence(
  context: AnomalyContext,
): Promise<FeatureVector[]> {
  const now = context.now();
  const sinceIso = new Date(
    now.getTime() - CREDENTIAL_SEQUENCE_WINDOW_MS,
  ).toISOString();
  const result = await context.auditLog.query({
    since: sinceIso,
    limit: QUERY_LIMIT,
  });

  const sequences = collectAgentSequences(result.entries);
  const observedAt = now.toISOString();
  const vectors: FeatureVector[] = [];
  const agentIds = [...sequences.keys()].sort();
  for (const agentId of agentIds) {
    const seq = sequences.get(agentId)!;
    if (seq.tokens.length === 0) continue;
    vectors.push({
      agent_id: agentId,
      observed_at: observedAt,
      features: computeCredentialFeatures(seq),
      window_label: CREDENTIAL_USE_SEQUENCE_WINDOW_LABEL,
    });
  }
  return vectors;
}

function collectAgentSequences(
  entries: readonly AuditEntry[],
): Map<string, AgentCredentialSequence> {
  const out = new Map<string, AgentCredentialSequence>();
  // entries arrive in audit-log order (chronological); preserve that
  // order per agent so 2-gram repeat patterns are well-defined.
  for (const entry of entries) {
    if (!isCredentialEntry(entry)) continue;
    const ts = Date.parse(entry.timestamp);
    if (!Number.isFinite(ts)) continue;
    const id = agentBucket(entry);
    let seq = out.get(id);
    if (!seq) {
      seq = { tokens: [], timestamps: [] };
      out.set(id, seq);
    }
    seq.tokens.push(credentialToken(entry));
    seq.timestamps.push(ts);
  }
  return out;
}

function computeCredentialFeatures(
  seq: AgentCredentialSequence,
): Record<string, number> {
  return {
    credential_event_count: seq.tokens.length,
    distinct_credentials_used: new Set(seq.tokens).size,
    repeat_pair_score: repeatPairScore(seq.tokens),
    burst_max_5min: burstMax(seq.timestamps),
  };
}

/**
 * Sum of (count - 1) across every consecutive credential 2-gram.
 * Same formula as tool-call-sequence's repeat_pattern_score: a
 * sequence [A, B, A, B, A] has (A,B) twice and (B,A) twice,
 * contributing (2-1) + (2-1) = 2.
 */
function repeatPairScore(tokens: string[]): number {
  if (tokens.length < 2) return 0;
  const histogram = new Map<string, number>();
  for (let i = 0; i < tokens.length - 1; i += 1) {
    const key = `${tokens[i]},${tokens[i + 1]}`;
    histogram.set(key, (histogram.get(key) ?? 0) + 1);
  }
  let score = 0;
  for (const count of histogram.values()) {
    if (count > 1) score += count - 1;
  }
  return score;
}

/**
 * Maximum credential-operation count in any fixed 5-minute bucket.
 * Bucket index = floor(timestamp_ms / BURST_BUCKET_MS), the same
 * fixed-bucket convention the cross-agent-timing extractor uses for
 * its correlation series.
 */
function burstMax(timestamps: number[]): number {
  if (timestamps.length === 0) return 0;
  const buckets = new Map<number, number>();
  let max = 0;
  for (const ts of timestamps) {
    const bucket = Math.floor(ts / BURST_BUCKET_MS);
    const next = (buckets.get(bucket) ?? 0) + 1;
    buckets.set(bucket, next);
    if (next > max) max = next;
  }
  return max;
}

export { FEATURE_NAMES };
