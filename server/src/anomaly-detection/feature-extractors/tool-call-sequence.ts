/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-4 Tool-Call Sequence feature extractor.
 *
 * Detects unusual ORDERINGS within an agent's task that the per-agent
 * activity counts cannot see. Example: an agent typically calls
 * `read_file` -> `compute` -> `write_file`. One day it calls
 * `read_file` -> `write_file` -> `read_file` -> `write_file` in a
 * pattern that resembles data exfiltration probing. The per-feature
 * counts look normal; the SEQUENCE is the anomaly.
 *
 * Per-agent feature vector with four numeric features over a sliding
 * `SEQUENCE_WINDOW_MS` (5 minutes ending at now):
 *
 *  - `distinct_tools_used`: count of unique tool names called in the
 *    window. Low for narrow-scope tasks, high for orchestrators or
 *    discovery flows.
 *  - `max_sequence_length`: longest run of consecutive tool calls
 *    (the entire window's call count, since the extractor reads the
 *    rolling window).
 *  - `ngram_3_histogram_entropy`: Shannon entropy of the 3-gram
 *    distribution of tool calls. Low entropy means a repeating
 *    predictable pattern (e.g. `read,compute,write` over and over);
 *    high entropy means highly varied / unusual orderings. The
 *    classifier baseline establishes the agent's normal entropy band;
 *    drift in either direction is anomalous.
 *  - `repeat_pattern_score`: how often the same 2-call pattern is
 *    repeated. Pattern `(X,Y)` is counted whenever `X` is followed
 *    immediately by `Y`; the score is the sum of (count - 1) over
 *    all patterns. Captures the data-exfiltration shape where one
 *    pair is hammered repeatedly.
 *
 * Tool-call attribution: we count every audit-log entry whose
 * `operation` matches the proxy-call shape `proxy_call:<tool>` (the
 * canonical outbound-call audit entry). This mirrors the per-agent-
 * activity extractor's tool-call attribution; per-agent grouping is
 * via `entry.identity_id`.
 *
 * Castle-walking: read-only. No outbound, no LLM call. Pure
 * statistical math over the existing audit log.
 */

import type {
  AnomalyContext,
  FeatureVector,
} from "../types.js";
import type { AuditEntry } from "../../operational/audit-log.js";

export const TOOL_CALL_SEQUENCE_EXTRACTOR_ID =
  "tool-call-sequence" as const;

/** Sliding window in milliseconds. v1.3 fixed at 5 minutes. */
export const SEQUENCE_WINDOW_MS = 5 * 60 * 1000;
/** Audit query limit. */
const QUERY_LIMIT = 5_000;
/** Identity-id bucket reused from per-agent-activity. */
export const SYSTEM_AGENT_BUCKET = "system" as const;
/** Window label persisted on each FeatureVector. */
export const TOOL_CALL_SEQUENCE_WINDOW_LABEL = "5min_sliding" as const;

const FEATURE_NAMES = [
  "distinct_tools_used",
  "max_sequence_length",
  "ngram_3_histogram_entropy",
  "repeat_pattern_score",
] as const;

export type ToolCallSequenceFeatureName = (typeof FEATURE_NAMES)[number];

const PROXY_CALL_PREFIX = "proxy_call:";

interface AgentSequence {
  /** Per-agent ordered tool-name sequence over the window. */
  tools: string[];
}

/**
 * Produce one FeatureVector per agent observed in the rolling 5-min
 * window. Returns an empty array when there is nothing observable.
 * Agents with fewer than 1 tool call in the window are skipped (no
 * vector emitted; skips noise during idle periods).
 */
export async function extractToolCallSequence(
  context: AnomalyContext,
): Promise<FeatureVector[]> {
  const now = context.now();
  const sinceIso = new Date(now.getTime() - SEQUENCE_WINDOW_MS).toISOString();
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
    if (seq.tools.length === 0) continue;
    vectors.push({
      agent_id: agentId,
      observed_at: observedAt,
      features: computeSequenceFeatures(seq.tools),
      window_label: TOOL_CALL_SEQUENCE_WINDOW_LABEL,
    });
  }
  return vectors;
}

function collectAgentSequences(
  entries: readonly AuditEntry[],
): Map<string, AgentSequence> {
  const out = new Map<string, AgentSequence>();
  // entries arrive in audit-log order (chronological); we preserve
  // that order per agent to compute n-grams + repeat patterns.
  for (const entry of entries) {
    if (!entry.operation.startsWith(PROXY_CALL_PREFIX)) continue;
    const tool = entry.operation.slice(PROXY_CALL_PREFIX.length);
    if (tool.length === 0) continue;
    const id =
      entry.identity_id && entry.identity_id.length > 0
        ? entry.identity_id
        : SYSTEM_AGENT_BUCKET;
    let seq = out.get(id);
    if (!seq) {
      seq = { tools: [] };
      out.set(id, seq);
    }
    seq.tools.push(tool);
  }
  return out;
}

function computeSequenceFeatures(tools: string[]): Record<string, number> {
  const distinct = new Set(tools).size;
  const maxLen = tools.length;
  const ngramEntropy = shannonEntropyOfNgrams(tools, 3);
  const repeatScore = repeatPatternScore(tools);
  return {
    distinct_tools_used: distinct,
    max_sequence_length: maxLen,
    ngram_3_histogram_entropy: ngramEntropy,
    repeat_pattern_score: repeatScore,
  };
}

/**
 * Shannon entropy (in bits) of the n-gram distribution. n-gram is
 * the comma-joined window over `tools` of size `n`. Returns 0 when
 * fewer than `n` tool calls (no n-gram defined).
 */
function shannonEntropyOfNgrams(tools: string[], n: number): number {
  if (tools.length < n) return 0;
  const histogram = new Map<string, number>();
  let total = 0;
  for (let i = 0; i <= tools.length - n; i += 1) {
    const key = tools.slice(i, i + n).join(",");
    histogram.set(key, (histogram.get(key) ?? 0) + 1);
    total += 1;
  }
  if (total === 0) return 0;
  let entropy = 0;
  for (const count of histogram.values()) {
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Sum of (count - 1) across every 2-gram pattern. A flat sequence
 * like [A, B, A, B, A] has (A,B) appearing twice and (B,A) appearing
 * twice, contributing (2-1) + (2-1) = 2. Captures the data-
 * exfiltration shape where one specific pair is hammered.
 */
function repeatPatternScore(tools: string[]): number {
  if (tools.length < 2) return 0;
  const histogram = new Map<string, number>();
  for (let i = 0; i < tools.length - 1; i += 1) {
    const key = `${tools[i]},${tools[i + 1]}`;
    histogram.set(key, (histogram.get(key) ?? 0) + 1);
  }
  let score = 0;
  for (const count of histogram.values()) {
    if (count > 1) score += count - 1;
  }
  return score;
}

export { FEATURE_NAMES };
