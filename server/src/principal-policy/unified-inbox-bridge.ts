/**
 * Sanctuary WP-V1.3-4 Psi-1 Unified Approval Inbox Bridge.
 *
 * **Opens WP-V1.3-4.** Upsilon-1 shipped the ApprovalAggregator with
 * cross-harness approvals + sentinel findings flowing through the
 * aggregator's single stream. Psi-1 extends that bridge to cover the
 * FULL set of operator-attention surfaces: blocked egress, privacy
 * events, budget warnings, recovery prompts, agent errors. All flow
 * through one unified stream the operator already checks — no more
 * three views to know what needs attention.
 *
 * Architecture:
 *
 *   - The bridge is an in-memory aggregator scoped to one fortress.
 *     Multi-fortress isolation is enforced by per-fortress instances
 *     stamped with `fortress_id`.
 *
 *   - Source classes are ingested via typed `ingestX` methods. Each
 *     normalizes the source event into a stable `UnifiedInboxEntry`
 *     and dedupes by `(source_class, source_event_id)`.
 *
 *   - Audit emission fires three new ops:
 *       unified_inbox_entry_aggregated (every successful ingest)
 *       unified_inbox_entry_resolved   (operator marks an entry resolved)
 *       unified_inbox_entry_deduped    (duplicate ingest detected)
 *
 *   - Subscribers receive in-process notifications via `onEvent` for
 *     SSE streaming. v1.3 Psi-1 ships the subscription hook + the
 *     HTTP `/api/inbox/unified/stream` SSE route as a separate
 *     module; this module exposes the listener-side API only.
 *
 * Castle-walking discipline:
 *   - No new outbound surface. Ingest is from server-local audit log
 *     + Upsilon-1's existing in-memory aggregator + Phi-N's finding
 *     store. Dedup is in-memory. The bridge never opens a socket.
 *
 *   - Sentinel observability and Castle Layer 2 invariants preserved:
 *     each ingest is a passive observer of an event that has already
 *     fired through the existing pipeline.
 *
 * Wire-up to actual producers (gate, sentinel dispatcher, Castle Wall,
 * Rho-1 query-anonymity audit emitter, recovery service, etc.) is
 * additive and ships in subsequent Psi-N builds. Psi-1 establishes
 * the bridge surface + ingest contracts + audit contracts + HTTP
 * routes.
 */

import { randomUUID, createHash } from "node:crypto";

import type { AuditLog } from "../l2-operational/audit-log.js";

// ── Public types ─────────────────────────────────────────────────────

export type UnifiedInboxSourceClass =
  | "approval"
  | "sentinel_finding"
  | "blocked_egress"
  | "privacy_event"
  | "budget_warning"
  | "recovery_prompt"
  | "agent_error";

export type UnifiedInboxSeverity = "info" | "warn" | "alert" | "critical";

export interface UnifiedInboxEntry {
  /** Stable per-fortress inbox id (UUID v4). */
  inbox_id: string;
  /** Which producer class emitted this entry. */
  source_class: UnifiedInboxSourceClass;
  /**
   * Stable per-source identifier the bridge uses for deduplication.
   * Format conventions per class:
   *   approval         — aggregator entry's audit_log_entry_id
   *   sentinel_finding — finding_id
   *   blocked_egress   — `<audit-timestamp>:<decision_id>`
   *   privacy_event    — `<audit-timestamp>:<aggregation-window>`
   *   budget_warning   — `<bucket>:<threshold-iso>`
   *   recovery_prompt  — `<ceremony_id>:<recovery_class>`
   *   agent_error      — `<audit-timestamp>:<agent_id>:<error_class>`
   */
  source_event_id: string;
  /** Optional agent attribution for per-agent entries. */
  agent_id?: string;
  /** Severity tier — `critical` is rare; reserved for hard-cap / lockdown class. */
  severity: UnifiedInboxSeverity;
  /** Operator-friendly one-line summary. Bounded at 240 chars on persist. */
  summary: string;
  /** Operator drill-target URL; opens full source detail. */
  details_url: string;
  /** ISO 8601 timestamp of source event. */
  observed_at: string;
  /** ISO 8601 timestamp the operator (or auto-resolver) resolved it. */
  resolved_at?: string;
  /** Operator identity that resolved this entry, when applicable. */
  resolved_by?: string;
  /** Stable fortress id stamped at emit. Multi-fortress isolation pivot. */
  fortress_id: string;
}

/** Hard cap on summary text. */
export const UNIFIED_INBOX_SUMMARY_MAX_CHARS = 240;

/** Audit-op constants. Wire into AuditLog.append directly. */
export const UNIFIED_INBOX_AUDIT_OPS = {
  AGGREGATED: "unified_inbox_entry_aggregated",
  RESOLVED: "unified_inbox_entry_resolved",
  DEDUPED: "unified_inbox_entry_deduped",
} as const;

export type UnifiedInboxAuditOp =
  (typeof UNIFIED_INBOX_AUDIT_OPS)[keyof typeof UNIFIED_INBOX_AUDIT_OPS];

// ── Subscriber interface ─────────────────────────────────────────────

export interface UnifiedInboxIngestEvent {
  type: "ingested";
  entry: UnifiedInboxEntry;
}

export interface UnifiedInboxResolveEvent {
  type: "resolved";
  entry: UnifiedInboxEntry;
}

export type UnifiedInboxBridgeEvent =
  | UnifiedInboxIngestEvent
  | UnifiedInboxResolveEvent;

export type UnifiedInboxUnsubscribe = () => void;

// ── Ingest payload shapes ────────────────────────────────────────────

/**
 * Each ingest method takes a normalized input shape. Callers map their
 * domain events into these shapes; the bridge never touches the source
 * domain types directly so it stays decoupled from upstream churn.
 */

export interface ApprovalIngest {
  source_event_id: string;
  agent_id?: string;
  severity: UnifiedInboxSeverity;
  summary: string;
  observed_at: string;
  aggregator_id?: string;
}

export interface SentinelFindingIngest {
  finding_id: string;
  agent_id?: string;
  severity: UnifiedInboxSeverity;
  summary: string;
  observed_at: string;
  sentinel_id: string;
}

export interface BlockedEgressIngest {
  source_event_id: string;
  agent_id?: string;
  destination_category: string;
  block_reason_class: string;
  observed_at: string;
}

export interface PrivacyEventIngest {
  source_event_id: string;
  /**
   * Per-call privacy events (Rho-1's `query_anonymity_headers_stripped`)
   * are too noisy for the inbox. Callers MUST aggregate per
   * (agent_id, day) window before ingest; `count` is the aggregated
   * call count.
   */
  count: number;
  agent_id?: string;
  privacy_event_kind:
    | "headers_stripped_summary"
    | "filter_denied"
    | "filter_rehydrated"
    | "filter_other";
  observed_at: string;
}

export interface BudgetWarningIngest {
  source_event_id: string;
  bucket: "daily" | "monthly" | "per_agent" | "custom";
  used_fraction: number;
  bucket_id?: string;
  agent_id?: string;
  observed_at: string;
}

export interface RecoveryPromptIngest {
  source_event_id: string;
  recovery_class:
    | "passphrase_reset"
    | "keychain_rebind"
    | "config_backup_restore"
    | "exit_drill"
    | "other";
  observed_at: string;
}

export interface AgentErrorIngest {
  source_event_id: string;
  agent_id: string;
  error_class: string;
  agent_still_active: boolean;
  observed_at: string;
}

// ── Bridge implementation ────────────────────────────────────────────

export interface UnifiedInboxBridgeDeps {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
  /** Optional cap on retained entries (default 1000). */
  maxEntries?: number;
  /**
   * Optional details-URL base. Defaults to `/api/inbox/unified`; the
   * bridge appends `/{inbox_id}` per entry. Operators on a custom
   * dashboard root override this.
   */
  detailsUrlBase?: string;
}

const DEFAULT_MAX_ENTRIES = 1000;
const DEFAULT_DETAILS_URL_BASE = "/api/inbox/unified";

export class UnifiedInboxBridge {
  private readonly auditLog: AuditLog;
  private readonly identityId: string;
  private readonly fortressId: string;
  private readonly now: () => Date;
  private readonly maxEntries: number;
  private readonly detailsUrlBase: string;
  /** Insertion-ordered entries; map key is the dedup key. */
  private readonly entriesByKey = new Map<string, UnifiedInboxEntry>();
  /** inbox_id -> dedup key lookup for resolve / get-by-id paths. */
  private readonly keyByInboxId = new Map<string, string>();
  private readonly listeners = new Set<
    (event: UnifiedInboxBridgeEvent) => void
  >();

  constructor(deps: UnifiedInboxBridgeDeps) {
    this.auditLog = deps.auditLog;
    this.identityId = deps.identityId;
    this.fortressId = deps.fortressId;
    this.now = deps.now ?? (() => new Date());
    this.maxEntries = deps.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.detailsUrlBase = deps.detailsUrlBase ?? DEFAULT_DETAILS_URL_BASE;
  }

  onEvent(
    listener: (event: UnifiedInboxBridgeEvent) => void,
  ): UnifiedInboxUnsubscribe {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  // ── ingest methods ─────────────────────────────────────────────────

  ingestApproval(input: ApprovalIngest): UnifiedInboxEntry | null {
    return this.ingest({
      source_class: "approval",
      source_event_id: input.source_event_id,
      severity: input.severity,
      summary: input.summary,
      observed_at: input.observed_at,
      ...(input.agent_id !== undefined ? { agent_id: input.agent_id } : {}),
    });
  }

  ingestSentinelFinding(input: SentinelFindingIngest): UnifiedInboxEntry | null {
    return this.ingest({
      source_class: "sentinel_finding",
      source_event_id: input.finding_id,
      severity: input.severity,
      summary: input.summary,
      observed_at: input.observed_at,
      ...(input.agent_id !== undefined ? { agent_id: input.agent_id } : {}),
    });
  }

  ingestBlockedEgress(input: BlockedEgressIngest): UnifiedInboxEntry | null {
    const summary = truncateSummary(
      `Egress to ${input.destination_category} blocked: ${input.block_reason_class}${input.agent_id ? ` (agent ${input.agent_id})` : ""}`,
    );
    // Block-reason-class drives severity: hard policy denials are
    // `alert`; fail-closed is `critical` (operator must investigate
    // immediately).
    const severity: UnifiedInboxSeverity =
      input.block_reason_class === "privacy_fail_closed" ||
      input.block_reason_class === "lockdown_active"
        ? "critical"
        : "alert";
    return this.ingest({
      source_class: "blocked_egress",
      source_event_id: input.source_event_id,
      severity,
      summary,
      observed_at: input.observed_at,
      ...(input.agent_id !== undefined ? { agent_id: input.agent_id } : {}),
    });
  }

  ingestPrivacyEvent(input: PrivacyEventIngest): UnifiedInboxEntry | null {
    if (input.count <= 0) return null; // No-op for zero-aggregation windows.
    const summary = truncateSummary(
      input.privacy_event_kind === "headers_stripped_summary"
        ? `Privacy filter stripped ${input.count} fingerprintable header${input.count === 1 ? "" : "s"} from outbound calls in last 24h${input.agent_id ? ` (agent ${input.agent_id})` : ""}`
        : `Privacy filter ${input.privacy_event_kind}: ${input.count} event${input.count === 1 ? "" : "s"}`,
    );
    const severity: UnifiedInboxSeverity =
      input.privacy_event_kind === "filter_denied" ? "alert" : "info";
    return this.ingest({
      source_class: "privacy_event",
      source_event_id: input.source_event_id,
      severity,
      summary,
      observed_at: input.observed_at,
      ...(input.agent_id !== undefined ? { agent_id: input.agent_id } : {}),
    });
  }

  ingestBudgetWarning(input: BudgetWarningIngest): UnifiedInboxEntry | null {
    const pct = Math.round(input.used_fraction * 100);
    const severity: UnifiedInboxSeverity =
      input.used_fraction >= 1
        ? "critical"
        : input.used_fraction >= 0.8
          ? "alert"
          : "warn";
    const summary = truncateSummary(
      `Budget ${input.bucket}${input.bucket_id ? ` ${input.bucket_id}` : ""}: ${pct}% used${input.agent_id ? ` (agent ${input.agent_id})` : ""}`,
    );
    return this.ingest({
      source_class: "budget_warning",
      source_event_id: input.source_event_id,
      severity,
      summary,
      observed_at: input.observed_at,
      ...(input.agent_id !== undefined ? { agent_id: input.agent_id } : {}),
    });
  }

  ingestRecoveryPrompt(input: RecoveryPromptIngest): UnifiedInboxEntry | null {
    const summary = truncateSummary(
      `Recovery prompt: ${input.recovery_class.replace(/_/g, " ")}`,
    );
    return this.ingest({
      source_class: "recovery_prompt",
      source_event_id: input.source_event_id,
      severity: "alert",
      summary,
      observed_at: input.observed_at,
    });
  }

  ingestAgentError(input: AgentErrorIngest): UnifiedInboxEntry | null {
    const severity: UnifiedInboxSeverity = input.agent_still_active
      ? "warn"
      : "critical";
    const summary = truncateSummary(
      `Agent ${input.agent_id} reported error (${input.error_class})${input.agent_still_active ? "" : " — agent inactive"}`,
    );
    return this.ingest({
      source_class: "agent_error",
      source_event_id: input.source_event_id,
      severity,
      summary,
      observed_at: input.observed_at,
      agent_id: input.agent_id,
    });
  }

  // ── query API ──────────────────────────────────────────────────────

  list(opts?: {
    since?: string;
    sourceClass?: UnifiedInboxSourceClass;
    severity?: UnifiedInboxSeverity;
    includeResolved?: boolean;
    limit?: number;
  }): UnifiedInboxEntry[] {
    const since = opts?.since !== undefined ? Date.parse(opts.since) : null;
    const out: UnifiedInboxEntry[] = [];
    for (const entry of this.entriesByKey.values()) {
      if (opts?.sourceClass !== undefined && entry.source_class !== opts.sourceClass) continue;
      if (opts?.severity !== undefined && entry.severity !== opts.severity) continue;
      if (opts?.includeResolved !== true && entry.resolved_at !== undefined) continue;
      if (since !== null) {
        const observedMs = Date.parse(entry.observed_at);
        if (!Number.isFinite(observedMs) || observedMs < since) continue;
      }
      out.push(entry);
    }
    const limit = opts?.limit ?? out.length;
    return out.slice(0, limit);
  }

  get(inboxId: string): UnifiedInboxEntry | null {
    const key = this.keyByInboxId.get(inboxId);
    if (key === undefined) return null;
    return this.entriesByKey.get(key) ?? null;
  }

  /**
   * Mark an entry resolved. Idempotent; resolving twice fires only
   * one audit event (the first time).
   */
  resolve(inboxId: string, resolvedBy: string): UnifiedInboxEntry | null {
    const key = this.keyByInboxId.get(inboxId);
    if (key === undefined) return null;
    const entry = this.entriesByKey.get(key);
    if (entry === undefined) return null;
    if (entry.resolved_at !== undefined) return entry;
    const resolvedAt = this.now().toISOString();
    const updated: UnifiedInboxEntry = {
      ...entry,
      resolved_at: resolvedAt,
      resolved_by: resolvedBy,
    };
    this.entriesByKey.set(key, updated);
    this.auditLog.append(
      "l2",
      UNIFIED_INBOX_AUDIT_OPS.RESOLVED,
      this.identityId,
      {
        inbox_id: updated.inbox_id,
        source_class: updated.source_class,
        source_event_id: updated.source_event_id,
        resolved_by: resolvedBy,
        fortress_id: this.fortressId,
      },
    );
    this.emit({ type: "resolved", entry: updated });
    return updated;
  }

  // ── helpers / private ──────────────────────────────────────────────

  /**
   * Visible for tests. Returns the current dedup-key set for
   * structural assertions.
   */
  size(): number {
    return this.entriesByKey.size;
  }

  private ingest(input: {
    source_class: UnifiedInboxSourceClass;
    source_event_id: string;
    severity: UnifiedInboxSeverity;
    summary: string;
    observed_at: string;
    agent_id?: string;
  }): UnifiedInboxEntry | null {
    const dedupKey = `${input.source_class}|${input.source_event_id}`;
    const existing = this.entriesByKey.get(dedupKey);
    if (existing !== undefined) {
      this.auditLog.append(
        "l2",
        UNIFIED_INBOX_AUDIT_OPS.DEDUPED,
        this.identityId,
        {
          source_class: input.source_class,
          source_event_id: input.source_event_id,
          existing_inbox_id: existing.inbox_id,
          fortress_id: this.fortressId,
        },
      );
      return null;
    }

    // Evict the oldest entry when at cap. Map preserves insertion
    // order; the first key is the oldest.
    if (this.entriesByKey.size >= this.maxEntries) {
      const oldestKey = this.entriesByKey.keys().next().value as
        | string
        | undefined;
      if (oldestKey !== undefined) {
        const evicted = this.entriesByKey.get(oldestKey);
        this.entriesByKey.delete(oldestKey);
        if (evicted) this.keyByInboxId.delete(evicted.inbox_id);
      }
    }

    const inboxId = randomUUID();
    const entry: UnifiedInboxEntry = {
      inbox_id: inboxId,
      source_class: input.source_class,
      source_event_id: input.source_event_id,
      severity: input.severity,
      summary: truncateSummary(input.summary),
      details_url: `${this.detailsUrlBase}/${inboxId}`,
      observed_at: input.observed_at,
      fortress_id: this.fortressId,
      ...(input.agent_id !== undefined ? { agent_id: input.agent_id } : {}),
    };
    this.entriesByKey.set(dedupKey, entry);
    this.keyByInboxId.set(inboxId, dedupKey);
    this.auditLog.append(
      "l2",
      UNIFIED_INBOX_AUDIT_OPS.AGGREGATED,
      this.identityId,
      {
        inbox_id: entry.inbox_id,
        source_class: entry.source_class,
        source_event_id: entry.source_event_id,
        severity: entry.severity,
        fortress_id: this.fortressId,
        ...(entry.agent_id !== undefined ? { agent_id: entry.agent_id } : {}),
      },
    );
    this.emit({ type: "ingested", entry });
    return entry;
  }

  private emit(event: UnifiedInboxBridgeEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listener exceptions never fail the bridge.
      }
    }
  }
}

function truncateSummary(s: string): string {
  if (s.length <= UNIFIED_INBOX_SUMMARY_MAX_CHARS) return s;
  return s.slice(0, UNIFIED_INBOX_SUMMARY_MAX_CHARS - 3) + "...";
}

/**
 * Deterministic dedup-key helper, exported for downstream callers
 * that want to compute the source_event_id without coupling to
 * domain-specific hashing.
 */
export function unifiedInboxDedupKey(
  sourceClass: UnifiedInboxSourceClass,
  sourceEventId: string,
): string {
  return createHash("sha256")
    .update(`${sourceClass}|${sourceEventId}`)
    .digest("hex");
}
