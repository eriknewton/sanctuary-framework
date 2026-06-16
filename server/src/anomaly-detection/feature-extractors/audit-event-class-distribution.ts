/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-5 Audit-event class distribution extractor.
 *
 * Projects the audit-log operation mix for each agent into numeric
 * FeatureVector fields so it remains compatible with Chi-1's numeric-only
 * dispatcher, while also exposing the richer distribution payload the
 * Chi-5 detector uses for categorical PSI attribution.
 *
 * Castle-walking: read-only audit-log query, no outbound, no LLM, no new
 * filesystem surface.
 */

import type {
  AnomalyContext,
  FeatureVector,
} from "../types.js";
import type { AuditEntry } from "../../operational/audit-log.js";
import { SYSTEM_AGENT_BUCKET } from "./per-agent-activity.js";

export const AUDIT_EVENT_CLASS_DISTRIBUTION_EXTRACTOR_ID =
  "audit-event-class-distribution" as const;

export const DEFAULT_AUDIT_EVENT_CLASS_WINDOW_MS =
  24 * 60 * 60 * 1000;
export const AUDIT_EVENT_CLASS_WINDOW_LABEL = "24h_rolling" as const;
const QUERY_LIMIT = 50_000;

export interface AuditEventClassDistribution {
  agent_id: string;
  window_start: string;
  window_end: string;
  total_events: number;
  class_counts: Record<string, number>;
  class_proportions: Record<string, number>;
}

export interface AuditEventClassDistributionOptions {
  windowMs?: number;
  queryLimit?: number;
}

export async function extractAuditEventClassDistribution(
  context: AnomalyContext,
  opts?: AuditEventClassDistributionOptions,
): Promise<FeatureVector[]> {
  const distributions = await extractAuditEventClassDistributions(
    context,
    opts,
  );
  return distributions.map(distributionToFeatureVector);
}

export async function extractAuditEventClassDistributions(
  context: AnomalyContext,
  opts?: AuditEventClassDistributionOptions,
): Promise<AuditEventClassDistribution[]> {
  const now = context.now();
  const windowMs = opts?.windowMs ?? DEFAULT_AUDIT_EVENT_CLASS_WINDOW_MS;
  const windowStart = new Date(now.getTime() - windowMs);
  const result = await context.auditLog.query({
    since: windowStart.toISOString(),
    limit: opts?.queryLimit ?? QUERY_LIMIT,
  });
  return buildAuditEventClassDistributions(
    result.entries,
    windowStart.toISOString(),
    now.toISOString(),
  );
}

export function distributionToFeatureVector(
  distribution: AuditEventClassDistribution,
): FeatureVector {
  const features: Record<string, number> = {
    total_events: distribution.total_events,
  };
  for (const className of Object.keys(distribution.class_counts).sort()) {
    features[`class_count:${className}`] =
      distribution.class_counts[className] ?? 0;
    features[`class_proportion:${className}`] =
      distribution.class_proportions[className] ?? 0;
  }
  return {
    agent_id: distribution.agent_id,
    observed_at: distribution.window_end,
    features,
    window_label: AUDIT_EVENT_CLASS_WINDOW_LABEL,
  };
}

export function buildAuditEventClassDistributions(
  entries: AuditEntry[],
  windowStart: string,
  windowEnd: string,
): AuditEventClassDistribution[] {
  const countsByAgent = new Map<string, Map<string, number>>();
  for (const entry of entries) {
    const agentId =
      entry.identity_id && entry.identity_id.length > 0
        ? entry.identity_id
        : SYSTEM_AGENT_BUCKET;
    let counts = countsByAgent.get(agentId);
    if (!counts) {
      counts = new Map<string, number>();
      countsByAgent.set(agentId, counts);
    }
    counts.set(entry.operation, (counts.get(entry.operation) ?? 0) + 1);
  }

  const out: AuditEventClassDistribution[] = [];
  for (const [agentId, counts] of countsByAgent.entries()) {
    const class_counts: Record<string, number> = {};
    let total = 0;
    for (const [className, count] of [...counts.entries()].sort((a, b) =>
      a[0].localeCompare(b[0]),
    )) {
      class_counts[className] = count;
      total += count;
    }
    const class_proportions: Record<string, number> = {};
    for (const className of Object.keys(class_counts)) {
      class_proportions[className] =
        total > 0 ? (class_counts[className] ?? 0) / total : 0;
    }
    out.push({
      agent_id: agentId,
      window_start: windowStart,
      window_end: windowEnd,
      total_events: total,
      class_counts,
      class_proportions,
    });
  }
  out.sort((a, b) => a.agent_id.localeCompare(b.agent_id));
  return out;
}
