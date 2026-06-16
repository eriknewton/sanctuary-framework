/**
 * Sanctuary WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 — dashboard backend.
 *
 * Backs the operator-visible "Query Anonymity" view. Reads
 * `query_anonymity_headers_stripped` audit events from the L2 audit
 * log and aggregates them into the stats shape the dashboard renders:
 *
 *   GET /api/query-anonymity/stats
 *     Returns:
 *       {
 *         window: "24h",
 *         total_outbound_calls: number,
 *         total_headers_stripped: number,
 *         top_stripped_headers: { name: string; count: number }[],  // top-5
 *         per_reason: { reason: string; count: number }[],
 *       }
 *
 * Read-only. No POST surface in Rho-1 (the strip is structurally
 * default-on; nothing for the operator to toggle).
 *
 * The full SPA-side rendering of this view (sibling to Sentinels /
 * Inbox / Coordination tabs) is deferred to a follow-up build — the
 * route ships in Rho-1 so the dashboard can light up the view as
 * soon as the SPA gets a panel for it.
 */

import type { AuditLog, AuditEntry } from "../operational/audit-log.js";
import { QUERY_ANONYMITY_AUDIT_OPS } from "./header-strip.js";

export const QUERY_ANONYMITY_API_PREFIX = "/api/query-anonymity";

export interface QueryAnonymityStats {
  window: "24h";
  generated_at: string;
  total_outbound_calls: number;
  total_headers_stripped: number;
  top_stripped_headers: { name: string; count: number }[];
  per_reason: { reason: string; count: number }[];
}

export interface QueryAnonymityRouteContext {
  auditLog: AuditLog;
  now?: () => Date;
}

const TOP_HEADERS_CAP = 5;
const DAY_MS = 24 * 60 * 60 * 1000;
const QUERY_LIMIT = 10_000;

export async function computeQueryAnonymityStats(
  ctx: QueryAnonymityRouteContext,
): Promise<QueryAnonymityStats> {
  const now = (ctx.now ?? (() => new Date()))();
  const sinceIso = new Date(now.getTime() - DAY_MS).toISOString();
  const queryResult = await ctx.auditLog.query({
    since: sinceIso,
    layer: "l2",
    operation_type: QUERY_ANONYMITY_AUDIT_OPS.HEADERS_STRIPPED,
    limit: QUERY_LIMIT,
  });

  let totalCalls = 0;
  let totalStripped = 0;
  const perHeader = new Map<string, number>();
  const perReason = new Map<string, number>();

  for (const entry of queryResult.entries) {
    if (entry.operation !== QUERY_ANONYMITY_AUDIT_OPS.HEADERS_STRIPPED) continue;
    totalCalls += 1;
    const details = entry.details ?? {};
    const removed = (details as Record<string, unknown>)["removed"];
    if (!Array.isArray(removed)) continue;
    for (const r of removed) {
      if (!r || typeof r !== "object") continue;
      const item = r as Record<string, unknown>;
      const name = typeof item["name"] === "string" ? item["name"] : null;
      const reason = typeof item["reason"] === "string" ? item["reason"] : null;
      if (name === null) continue;
      totalStripped += 1;
      const lowerName = name.toLowerCase();
      perHeader.set(lowerName, (perHeader.get(lowerName) ?? 0) + 1);
      if (reason !== null) {
        perReason.set(reason, (perReason.get(reason) ?? 0) + 1);
      }
    }
  }

  const topHeaders = [...perHeader.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, TOP_HEADERS_CAP)
    .map(([name, count]) => ({ name, count }));
  const reasonSummary = [...perReason.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([reason, count]) => ({ reason, count }));

  return {
    window: "24h",
    generated_at: now.toISOString(),
    total_outbound_calls: totalCalls,
    total_headers_stripped: totalStripped,
    top_stripped_headers: topHeaders,
    per_reason: reasonSummary,
  };
}

/**
 * HTTP handler: stripped-down shape so this route slots into the
 * existing dashboard dispatcher without dragging in the full
 * IncomingMessage/ServerResponse type baggage at this layer.
 *
 * Returns the JSON-serialized stats body + a status code. The
 * dashboard dispatcher converts to an actual HTTP response.
 */
export async function handleQueryAnonymityStatsRequest(
  ctx: QueryAnonymityRouteContext,
): Promise<{ status: 200; body: QueryAnonymityStats }> {
  const stats = await computeQueryAnonymityStats(ctx);
  return { status: 200, body: stats };
}

/** Exported for the doc page that renders the strip-list table. */
export { QUERY_ANONYMITY_AUDIT_OPS } from "./header-strip.js";

/** Helper for AuditEntry shape consumers in tests. */
export type AnonymityAuditEntry = AuditEntry;
