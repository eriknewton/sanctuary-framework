/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-1 Per-Agent Activity feature extractor.
 *
 * For each agent observed in the recent audit log, projects a numeric
 * FeatureVector summarising activity over the rolling 24h window.
 *
 * Agent discovery: collect distinct non-empty `identity_id` values
 * from the audit-log entries within the window. Audit entries that
 * carry `identity_id == "system"` (proxy router, dispatcher self-
 * emissions) are bucketed under the synthetic agent id `system`. v1.4
 * proxy-attribution work will refine this; for v1.3 the bucket is
 * stable and useful.
 *
 * Features extracted (all numeric, stable schema):
 *  - `tool_call_count`: any audit operation interpreted as a tool
 *    call. Conservative inclusion: count entries that the system
 *    itself classifies as L1, L2, L3, or L4 layer reads/writes (ie
 *    every audit entry with layer set; this is essentially all of
 *    them). Includes the proxy_call:* family.
 *  - `egress_call_count`: count of `proxy_call:*` entries (outbound
 *    proxy invocations).
 *  - `credential_use_count`: count of `broker_secret_*` and
 *    `broker_token_*` entries (Secret Broker activity).
 *  - `audit_event_count`: total entries attributed to this agent in
 *    the window. Mirrors `tool_call_count` at v1.3 but kept as a
 *    distinct feature so future extractors can specialize tool-call
 *    counting without breaking the schema.
 *  - `recent_receipt_count`: count of composition / reputation
 *    receipt operations (`composition_receipt_*`, `reputation_*`).
 *
 * Castle-walking: read-only. No outbound surface, no agent attack
 * surface introduced. The extractor only consumes the existing audit
 * log.
 */

import type {
  AnomalyContext,
  FeatureVector,
} from "../types.js";
import type { AuditEntry } from "../../l2-operational/audit-log.js";

export const PER_AGENT_ACTIVITY_EXTRACTOR_ID = "per-agent-activity" as const;

/** Window size in milliseconds. v1.3 fixed at 24h. */
const WINDOW_MS = 24 * 60 * 60 * 1000;
/** Audit query limit. */
const QUERY_LIMIT = 10_000;
/** Identity-id bucket for `identity_id == "system"` audit emissions. */
export const SYSTEM_AGENT_BUCKET = "system" as const;
/** Window label persisted on each FeatureVector. */
export const PER_AGENT_ACTIVITY_WINDOW_LABEL = "24h_rolling" as const;

const FEATURE_NAMES = [
  "tool_call_count",
  "egress_call_count",
  "credential_use_count",
  "audit_event_count",
  "recent_receipt_count",
] as const;

export type PerAgentActivityFeatureName = (typeof FEATURE_NAMES)[number];

interface AgentBucket {
  tool_call_count: number;
  egress_call_count: number;
  credential_use_count: number;
  audit_event_count: number;
  recent_receipt_count: number;
}

function emptyBucket(): AgentBucket {
  return {
    tool_call_count: 0,
    egress_call_count: 0,
    credential_use_count: 0,
    audit_event_count: 0,
    recent_receipt_count: 0,
  };
}

function bucketToFeatures(bucket: AgentBucket): Record<string, number> {
  return {
    tool_call_count: bucket.tool_call_count,
    egress_call_count: bucket.egress_call_count,
    credential_use_count: bucket.credential_use_count,
    audit_event_count: bucket.audit_event_count,
    recent_receipt_count: bucket.recent_receipt_count,
  };
}

function classifyEntry(entry: AuditEntry, bucket: AgentBucket): void {
  bucket.audit_event_count += 1;
  bucket.tool_call_count += 1;
  if (entry.operation.startsWith("proxy_call:")) {
    bucket.egress_call_count += 1;
  }
  if (
    entry.operation.startsWith("broker_secret_") ||
    entry.operation.startsWith("broker_token_")
  ) {
    bucket.credential_use_count += 1;
  }
  if (
    entry.operation.startsWith("composition_receipt_") ||
    entry.operation === "reputation_record" ||
    entry.operation === "reputation_query" ||
    entry.operation === "reputation_publish"
  ) {
    bucket.recent_receipt_count += 1;
  }
}

/**
 * Produce one FeatureVector per agent observed in the rolling 24h
 * window. Returns an empty array when the audit log is empty.
 */
export async function extractPerAgentActivity(
  context: AnomalyContext,
): Promise<FeatureVector[]> {
  const now = context.now();
  const sinceIso = new Date(now.getTime() - WINDOW_MS).toISOString();
  const result = await context.auditLog.query({
    since: sinceIso,
    limit: QUERY_LIMIT,
  });
  const buckets = new Map<string, AgentBucket>();
  for (const entry of result.entries) {
    const agentId =
      entry.identity_id && entry.identity_id.length > 0
        ? entry.identity_id
        : SYSTEM_AGENT_BUCKET;
    let bucket = buckets.get(agentId);
    if (!bucket) {
      bucket = emptyBucket();
      buckets.set(agentId, bucket);
    }
    classifyEntry(entry, bucket);
  }
  const observedAt = now.toISOString();
  const vectors: FeatureVector[] = [];
  for (const [agentId, bucket] of buckets.entries()) {
    vectors.push({
      agent_id: agentId,
      observed_at: observedAt,
      features: bucketToFeatures(bucket),
      window_label: PER_AGENT_ACTIVITY_WINDOW_LABEL,
    });
  }
  vectors.sort((a, b) => (a.agent_id < b.agent_id ? -1 : 1));
  return vectors;
}

/** Exported so tests + Chi-2+ extractors can reuse the schema. */
export { FEATURE_NAMES };
