/**
 * Psi-2 producer adapters for UnifiedInboxBridge.
 *
 * These helpers keep source modules decoupled from the bridge's internal
 * entry shape while making each operator-attention producer explicit.
 */

import type { AuditEntry, AuditLog } from "../l2-operational/audit-log.js";
import type { CastleWallAuditEvent } from "../castle-wall/audit/events.js";
import type {
  UnifiedInboxBridge,
  UnifiedInboxEntry,
} from "./unified-inbox-bridge.js";

export const PSI2_AUDIT_OPS = {
  CASTLE_WALL_BLOCKED_EGRESS: "castle_wall_blocked_egress",
  QUERY_ANONYMITY_DAILY_AGGREGATED: "query_anonymity_daily_aggregated",
} as const;

export function ingestCastleWallBlockedEgress(params: {
  bridge: UnifiedInboxBridge;
  event: CastleWallAuditEvent;
}): UnifiedInboxEntry | null {
  const { event } = params;
  if (event.event_type !== "egress_blocked") return null;
  const host = event.destination?.host ?? event.destination?.ip ?? "unknown";
  const reason =
    typeof event.details.reason === "string"
      ? event.details.reason
      : typeof event.details.block_reason_class === "string"
        ? event.details.block_reason_class
        : "other";
  const seq =
    typeof event.details.seq === "number" ? String(event.details.seq) : host;
  return params.bridge.ingestBlockedEgress({
    source_event_id: `${event.timestamp}:${seq}`,
    agent_id: event.agent?.id,
    destination_category: host,
    block_reason_class: reason,
    observed_at: event.timestamp,
  });
}

export async function emitCastleWallBlockedEgress(params: {
  bridge: UnifiedInboxBridge;
  auditLog?: AuditLog;
  identityId: string;
  event: CastleWallAuditEvent;
}): Promise<UnifiedInboxEntry | null> {
  const entry = ingestCastleWallBlockedEgress(params);
  if (entry && params.auditLog) {
    await params.auditLog.appendCritical({
      layer: "l1",
      operation: PSI2_AUDIT_OPS.CASTLE_WALL_BLOCKED_EGRESS,
      identity_id: params.identityId,
      result: "failure",
      details: {
        inbox_id: entry.inbox_id,
        agent_id: entry.agent_id,
        target_host: params.event.destination?.host ?? null,
        decision_reason: params.event.details.reason ?? params.event.details.block_reason_class ?? null,
        observed_at: params.event.timestamp,
        fortress_id: params.event.fortress_id,
      },
    });
  }
  return entry;
}

export async function aggregateRhoDailyPrivacyEvents(params: {
  auditLog: AuditLog;
  bridge: UnifiedInboxBridge;
  identityId: string;
  fortressId: string;
  now?: Date;
}): Promise<UnifiedInboxEntry | null> {
  const now = params.now ?? new Date();
  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const result = await params.auditLog.query({
    since,
    operation_type: "query_anonymity_headers_stripped",
    limit: 100_000,
  });
  const entries = result.entries.filter((entry) =>
    auditEntryMatchesFortress(entry, params.fortressId),
  );
  const totalQueries = entries.length;
  let totalHeadersStripped = 0;
  const headerCounts = new Map<string, number>();
  for (const entry of entries) {
    const count = numberDetail(entry, "stripped_count");
    totalHeadersStripped += count;
    for (const name of removedHeaderNames(entry)) {
      headerCounts.set(name, (headerCounts.get(name) ?? 0) + 1);
    }
  }
  if (totalHeadersStripped <= 0) return null;
  const topHeaders = [...headerCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([name]) => name);
  const day = now.toISOString().slice(0, 10);
  void params.auditLog.append("l2", PSI2_AUDIT_OPS.QUERY_ANONYMITY_DAILY_AGGREGATED, params.identityId, {
    fortress_id: params.fortressId,
    window_start: since,
    window_end: now.toISOString(),
    total_queries: totalQueries,
    total_headers_stripped: totalHeadersStripped,
    top_headers: topHeaders,
  });
  await params.auditLog.flush();
  return params.bridge.ingestPrivacyEvent({
    source_event_id: `${params.fortressId}:${day}:headers_stripped_summary`,
    count: totalHeadersStripped,
    privacy_event_kind: "headers_stripped_summary",
    observed_at: now.toISOString(),
  });
}

export function ingestBudgetThreshold(params: {
  bridge: UnifiedInboxBridge;
  agent_id: string;
  threshold_name: string;
  current_value: number;
  limit: number;
  observed_at: string;
  bucket?: "daily" | "monthly" | "per_agent" | "custom";
}): UnifiedInboxEntry | null {
  const used = params.limit > 0 ? params.current_value / params.limit : 1;
  return params.bridge.ingestBudgetWarning({
    source_event_id: `${params.agent_id}:${params.threshold_name}:${params.observed_at}`,
    bucket: params.bucket ?? "per_agent",
    bucket_id: params.threshold_name,
    used_fraction: used,
    agent_id: params.agent_id,
    observed_at: params.observed_at,
  });
}

export function ingestRecoveryPrompt(params: {
  bridge: UnifiedInboxBridge;
  recovery_class: "passphrase_reset" | "keychain_rebind" | "config_backup_restore" | "exit_drill" | "other";
  agent_id?: string;
  action_required: boolean;
  deadline?: string;
  observed_at: string;
  source_event_id?: string;
}): UnifiedInboxEntry | null {
  return params.bridge.ingestRecoveryPrompt({
    source_event_id:
      params.source_event_id ??
      `${params.recovery_class}:${params.agent_id ?? "fortress"}:${params.observed_at}`,
    recovery_class: params.recovery_class,
    observed_at: params.observed_at,
    agent_id: params.agent_id,
    action_required: params.action_required,
    deadline: params.deadline,
  });
}

export async function ingestWrappedAgentErrors(params: {
  auditLog: AuditLog;
  bridge: UnifiedInboxBridge;
  since?: string;
  now?: Date;
}): Promise<UnifiedInboxEntry[]> {
  const now = params.now ?? new Date();
  const since =
    params.since ?? new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const result = await params.auditLog.query({ since, limit: 100_000 });
  const errorEntries = result.entries.filter(isWrappedAgentError);
  const recentByAgentClass = new Map<string, number>();
  for (const entry of errorEntries) {
    const key = `${stringDetail(entry, "agent_id") ?? "unknown"}:${stringDetail(entry, "error_class") ?? entry.operation}`;
    recentByAgentClass.set(key, (recentByAgentClass.get(key) ?? 0) + 1);
  }
  const ingested: UnifiedInboxEntry[] = [];
  for (const entry of errorEntries) {
    const agentId = stringDetail(entry, "agent_id") ?? "unknown";
    const errorClass = stringDetail(entry, "error_class") ?? entry.operation;
    const key = `${agentId}:${errorClass}`;
    const fatal = booleanDetail(entry, "fatal") === true;
    const repeated = (recentByAgentClass.get(key) ?? 0) > 3;
    const out = params.bridge.ingestAgentError({
      source_event_id: `${entry.timestamp}:${agentId}:${errorClass}`,
      agent_id: agentId,
      harness_name: stringDetail(entry, "harness_name") ?? stringDetail(entry, "harness") ?? "unknown",
      error_message: stringDetail(entry, "error_message") ?? errorClass,
      error_class: errorClass,
      agent_still_active: !fatal,
      repeated_in_24h: repeated,
      observed_at: entry.timestamp,
    });
    if (out) ingested.push(out);
  }
  return ingested;
}

function auditEntryMatchesFortress(entry: AuditEntry, fortressId: string): boolean {
  return entry.details?.fortress_id === undefined || entry.details.fortress_id === fortressId;
}

function numberDetail(entry: AuditEntry, key: string): number {
  const value = entry.details?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function stringDetail(entry: AuditEntry, key: string): string | null {
  const value = entry.details?.[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function booleanDetail(entry: AuditEntry, key: string): boolean | null {
  const value = entry.details?.[key];
  return typeof value === "boolean" ? value : null;
}

function removedHeaderNames(entry: AuditEntry): string[] {
  const removed = entry.details?.removed;
  if (!Array.isArray(removed)) return [];
  const out: string[] = [];
  for (const item of removed) {
    if (
      item &&
      typeof item === "object" &&
      "name" in item &&
      typeof item.name === "string"
    ) {
      out.push(item.name.toLowerCase());
    }
  }
  return out;
}

function isWrappedAgentError(entry: AuditEntry): boolean {
  const severity = stringDetail(entry, "severity");
  const context = stringDetail(entry, "context") ?? stringDetail(entry, "source");
  return (
    (severity === "error" || booleanDetail(entry, "fatal") === true) &&
    (context === "wrapped_agent" || stringDetail(entry, "agent_id") !== null)
  );
}
