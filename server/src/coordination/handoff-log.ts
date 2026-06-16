/**
 * Sanctuary v1.3 WP-V1.3-3 Omega-1 Coordination Handoff Log.
 *
 * OPENS WP-V1.3-3 Coordination Handoff Visualization. Read-only
 * server-side data API: queries the existing audit log for the
 * handoff-shape event classes, normalizes them into a uniform
 * HandoffEntry, and exposes query + per-entry detail.
 *
 * Why this matters: operators running multiple wrapped agents need
 * to SEE what their agents are doing together. Handoffs between
 * agents are the most important state transitions: who passed work
 * to whom, what got transferred, what got withheld. Without
 * visibility, operators can't audit the multi-agent workflow OR
 * diagnose where work stalled.
 *
 * Audit event sources unioned by this module:
 *  - `v1.1_local_handoff` (Tau-3 in-process coordination): canonical
 *    explicit-pair signal. Details carry sender_agent_id +
 *    recipient_agent_id.
 *  - `cross_harness_approval_aggregated` (Upsilon-1 cross-harness
 *    aggregator): wrapped-agent -> operator handoff. Details carry
 *    source_harness; recipient is the synthetic `operator` node.
 *
 * NOT included at v1.3 Omega-1 (deviation, documented in PR body):
 *  - `composition_completed` events do not exist as audit-log
 *    operations in current source; composition events are mesh-only
 *    signed envelopes (`composition_receipt_*` / `composition_*` are
 *    in COMPOSITION_EVENT_TYPES but never flow through
 *    auditLog.append). When composition wires audit emissions, the
 *    union extends here. Same posture as Phi-3 cross-agent-chatter
 *    watcher.
 *
 * Castle-walking discipline:
 *  - No outbound surface. Reads server-local audit log only.
 *  - No LLM call (purely operator-eyes view; no inference).
 *  - No new operator attack surface (read-only against existing audit
 *    log; new audit events are operator-action observability only).
 *
 * Multi-fortress isolation: HandoffLog is scoped to ONE AuditLog
 * instance per fortress; the audit log itself enforces fortress
 * boundary at the encryption layer.
 */

import { createHash } from "node:crypto";

import type { AuditEntry, AuditLog } from "../operational/audit-log.js";

/** Audit operations the HandoffLog reads. */
export const HANDOFF_LOG_OBSERVED_OPS = {
  /** Tau-3 in-process coordination handoff. */
  LOCAL_HANDOFF: "v1.1_local_handoff",
  /** Upsilon-1 cross-harness approval (wrapped-agent -> operator). */
  CROSS_HARNESS_APPROVAL: "cross_harness_approval_aggregated",
} as const;

const OBSERVED_OP_LIST: readonly string[] = [
  HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
  HANDOFF_LOG_OBSERVED_OPS.CROSS_HARNESS_APPROVAL,
];

/**
 * Synthetic recipient when the audit entry models a wrapped-agent ->
 * operator handoff (Upsilon-1 cross-harness flow). Stable string so
 * the operator UI can recognize it.
 */
export const OPERATOR_PSEUDO_AGENT = "operator" as const;

/**
 * Stable per-fortress entry id. Derived deterministically from the
 * audit-event payload so the same audit entry always maps to the
 * same entry id across server restarts.
 */
function makeEntryId(auditEventId: string): string {
  return createHash("sha256")
    .update(auditEventId)
    .digest("hex")
    .slice(0, 32);
}

/** Operator-facing per-handoff record. */
export interface HandoffEntry {
  /** Stable per-fortress entry id (32 hex chars; SHA-256 of audit_event_id). */
  entry_id: string;
  /** Pointer back to the source audit-event. */
  audit_event_id: string;
  source_agent_id: string;
  /** `operator` for cross-harness flows; `unknown` when the entry shape lacks a recipient. */
  target_agent_id: string;
  /** ISO 8601 timestamp from the underlying audit entry. */
  observed_at: string;
  /** The original audit operation (`v1.1_local_handoff`, `cross_harness_approval_aggregated`). */
  event_class: string;
  /** Operator-friendly one-liner. */
  context_transfer_summary: string;
  /** Multi-step workflow grouping key (Omega-3); v1.3 Omega-1 returns null. */
  workflow_link: string | null;
}

export interface HandoffEntryDetail {
  entry: HandoffEntry;
  /** Source audit entry, decrypted under operator auth. */
  source_audit_entry: AuditEntry;
}

export interface HandoffLogQueryOptions {
  /** Filter to entries with observed_at >= ISO 8601. */
  since?: string;
  /** Filter to entries with observed_at <= ISO 8601. */
  until?: string;
  /** Filter to entries where the agent participates as sender or recipient. */
  agent_id?: string;
  /** Result cap. Default 50; max 500. */
  limit?: number;
}

export interface HandoffLogOptions {
  auditLog: AuditLog;
  fortressId: string;
}

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;
/** Per-tick audit-log query cap before normalization filters. */
const AUDIT_QUERY_LIMIT = 10_000;

export class HandoffLog {
  private readonly auditLog: AuditLog;
  private readonly fortressId: string;

  constructor(opts: HandoffLogOptions) {
    this.auditLog = opts.auditLog;
    this.fortressId = opts.fortressId;
  }

  /** Stable fortress id this HandoffLog reads. */
  getFortressId(): string {
    return this.fortressId;
  }

  /**
   * Query handoffs in chronological-newest-first order. Filters
   * applied after normalization so the per-event-class shape
   * differences (sender field name, recipient inference) are handled
   * once.
   */
  async query(opts: HandoffLogQueryOptions): Promise<HandoffEntry[]> {
    const limit = Math.min(opts.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
    const queryResult = await this.auditLog.query({
      ...(opts.since !== undefined ? { since: opts.since } : {}),
      layer: "l2",
      limit: AUDIT_QUERY_LIMIT,
    });
    const normalized: HandoffEntry[] = [];
    for (const entry of queryResult.entries) {
      if (!OBSERVED_OP_LIST.includes(entry.operation)) continue;
      const handoff = this.normalize(entry);
      if (!handoff) continue;
      if (opts.until && handoff.observed_at > opts.until) continue;
      if (opts.since && handoff.observed_at < opts.since) continue;
      if (opts.agent_id) {
        if (
          handoff.source_agent_id !== opts.agent_id &&
          handoff.target_agent_id !== opts.agent_id
        ) {
          continue;
        }
      }
      normalized.push(handoff);
    }
    normalized.sort((a, b) => (a.observed_at < b.observed_at ? 1 : -1));
    return normalized.slice(0, limit);
  }

  /**
   * Look up a single entry by id. Returns the normalized entry +
   * the source audit payload for operator-facing detail rendering.
   * Returns null when no audit entry maps to the given id.
   */
  async getEntry(entryId: string): Promise<HandoffEntryDetail | null> {
    const queryResult = await this.auditLog.query({
      layer: "l2",
      limit: AUDIT_QUERY_LIMIT,
    });
    for (const audit of queryResult.entries) {
      if (!OBSERVED_OP_LIST.includes(audit.operation)) continue;
      const handoff = this.normalize(audit);
      if (!handoff) continue;
      if (handoff.entry_id === entryId) {
        return { entry: handoff, source_audit_entry: audit };
      }
    }
    return null;
  }

  private normalize(audit: AuditEntry): HandoffEntry | null {
    const details = audit.details as Record<string, unknown> | undefined;
    if (audit.operation === HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF) {
      const sender = optString(details, "sender_agent_id");
      const recipient = optString(details, "recipient_agent_id");
      if (!sender || !recipient || sender === recipient) return null;
      const auditEventId = optString(details, "event_id") ?? auditEventIdFallback(audit);
      return {
        entry_id: makeEntryId(auditEventId),
        audit_event_id: auditEventId,
        source_agent_id: sender,
        target_agent_id: recipient,
        observed_at: audit.timestamp,
        event_class: audit.operation,
        context_transfer_summary: localHandoffSummary(details, sender, recipient),
        workflow_link: null,
      };
    }
    if (
      audit.operation === HANDOFF_LOG_OBSERVED_OPS.CROSS_HARNESS_APPROVAL
    ) {
      const sender =
        optString(details, "source_harness") ??
        optString(details, "source_agent_id");
      if (!sender) return null;
      const auditEventId = optString(details, "aggregator_id") ?? auditEventIdFallback(audit);
      return {
        entry_id: makeEntryId(auditEventId),
        audit_event_id: auditEventId,
        source_agent_id: sender,
        target_agent_id: OPERATOR_PSEUDO_AGENT,
        observed_at: audit.timestamp,
        event_class: audit.operation,
        context_transfer_summary: crossHarnessSummary(details, sender),
        workflow_link: null,
      };
    }
    return null;
  }
}

function optString(
  details: Record<string, unknown> | undefined,
  key: string,
): string | null {
  if (!details) return null;
  const value = details[key];
  if (typeof value !== "string" || value.length === 0) return null;
  return value;
}

/**
 * Stable fallback when the audit details payload doesn't carry an
 * explicit event_id. Uses timestamp + operation as the deterministic
 * key. Mirrors Upsilon-1's audit_log_entry_id derivation.
 */
function auditEventIdFallback(audit: AuditEntry): string {
  return `${audit.timestamp}:${audit.operation}`;
}

function localHandoffSummary(
  details: Record<string, unknown> | undefined,
  sender: string,
  recipient: string,
): string {
  const taskScope = optString(details, "task_scope");
  const reasonClass = optString(details, "reason_class");
  if (taskScope) {
    return `${sender} -> ${recipient} handoff: ${taskScope}`;
  }
  if (reasonClass) {
    return `${sender} -> ${recipient} handoff (${reasonClass})`;
  }
  return `${sender} -> ${recipient} handoff`;
}

function crossHarnessSummary(
  details: Record<string, unknown> | undefined,
  sender: string,
): string {
  const policyRule = optString(details, "policy_rule_id");
  if (policyRule) {
    return `${sender} -> operator approval (${policyRule})`;
  }
  return `${sender} -> operator approval`;
}

/** Audit operations the Coordination view itself emits. */
export const COORDINATION_VIEW_AUDIT_OPS = {
  /** v1.3 Omega-1: operator opened the chronological handoff list. */
  VIEW_OPENED: "operator_coordination_view_opened",
  /** v1.3 Omega-1: operator drilled into a single handoff for detail. */
  ENTRY_DRILLED: "operator_handoff_entry_drilled",
  /**
   * v1.3 Omega-3: operator opened the Workflows sibling-view (list of
   * multi-handoff workflows grouped by `workflow-grouper`). Mirrors
   * VIEW_OPENED's shape so the dashboard activity feed can group both
   * as "operator coordination surfaces."
   */
  WORKFLOW_VIEW_OPENED: "operator_workflow_view_opened",
  /**
   * v1.3 Omega-3: operator drilled into a single workflow for its
   * timeline + member-handoffs detail. Mirrors ENTRY_DRILLED's shape.
   */
  WORKFLOW_DRILLED: "operator_workflow_drilled",
  /**
   * v1.3 Omega-3: server-side state transition observed on a
   * workflow (e.g., in_progress -> stalled). Emitted by the route
   * layer after the state tracker diffs against its prior snapshot.
   * Distinct from the operator-action events above: this records what
   * the workflow itself is doing, not what the operator clicked.
   */
  WORKFLOW_STATE_CHANGED: "coordination_workflow_state_changed",
} as const;

export type CoordinationViewAuditOp =
  (typeof COORDINATION_VIEW_AUDIT_OPS)[keyof typeof COORDINATION_VIEW_AUDIT_OPS];
