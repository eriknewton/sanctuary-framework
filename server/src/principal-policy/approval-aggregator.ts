/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-1
 *
 * The aggregator is a passive subscriber to the existing ApprovalGate
 * lifecycle. On each `gate-request` event it normalizes the payload into a
 * stable `AggregatedApproval` record, dedupes against prior emissions of
 * the same `(source_harness, source_agent_id, audit_log_entry_id)` tuple,
 * persists the record under the reserved `_approval_aggregator` namespace,
 * and exposes a query + resolve API.
 *
 * Scope of Upsilon-1:
 *  - Aggregator module + storage + resolve API.
 *  - Wired into the gate via an additive callback. The gate's blocking
 *    deny/accept logic is unchanged; the aggregator never fails the gate
 *    (callback exceptions are swallowed and audit-logged).
 *  - HTTP route surface and three audit event names are owned by the
 *    sibling `approval-aggregator-routes.ts` module + the gate wire-up.
 *
 * Out of scope (carries to Upsilon-2..4):
 *  - Per-harness wrapped-agent approval-redirect mode.
 *  - Operator decisions through the aggregator's HTTP `approve`/`deny`
 *    routes flowing back to a blocked `channel.requestApproval()` call;
 *    Upsilon-1 records the decision on the aggregator entry only.
 *  - Provenance + replay UX.
 *  - Mobile companion preview hook.
 */

import { randomUUID, createHash } from "node:crypto";

import type { StorageBackend } from "../storage/interface.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

/** Reserved storage namespace for aggregator records. */
export const APPROVAL_AGGREGATOR_NAMESPACE = "_approval_aggregator";

/** HKDF info string for the aggregator's per-fortress encryption key. */
export const APPROVAL_AGGREGATOR_HKDF_INFO = "l2-approval-aggregator-v1";

/**
 * Audit-event operation names emitted by the aggregator. Additive to the
 * existing free-form `operation` field on `AuditEntry`. v1.3-new.
 */
export const APPROVAL_AGGREGATOR_AUDIT_OPS = {
  AGGREGATED: "cross_harness_approval_aggregated",
  RESOLVED: "cross_harness_approval_resolved",
  DEDUPED: "cross_harness_approval_deduped",
} as const;

/**
 * Coordinator-CTO defaults baked in. v1.3 Upsilon-1 ships with one set of
 * sane numbers; per-fortress overrides land in a later PR if real fleet
 * usage shows a need.
 */
const DEFAULT_PENDING_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_MAX_LIST_LIMIT = 200;
const DEFAULT_LIST_PAGE_SIZE = 50;

/**
 * Lifecycle status of an aggregated approval entry.
 *  - `pending`: ingest fired, gate is awaiting a channel decision.
 *  - `approved` / `denied`: gate's channel returned a decision OR the
 *    operator resolved through the HTTP surface.
 *  - `timeout`: the channel reported a timeout (decided_by ===
 *    'channel_failure' OR explicit timeout reason).
 *  - `expired`: pending past TTL on a `list()` poll without a resolution.
 */
export type AggregatedApprovalStatus =
  | "pending"
  | "approved"
  | "denied"
  | "timeout"
  | "expired";

/**
 * Normalized record the aggregator stores per approval. Field set is
 * additive-stable; new fields go behind `?` so existing dashboards keep
 * rendering unchanged. Raw request payloads are not stored on the record;
 * only a SHA-256 hash and the original payload pulled separately via
 * `getFullPayload()`.
 */
export interface AggregatedApproval {
  /** Stable per-fortress aggregator id (UUID v4). */
  aggregator_id: string;
  /** Harness the source approval came from (claude-code, cline, cursor, etc). */
  source_harness: string;
  /** Wrapped-agent identifier. Ed25519 pubkey hex or label. */
  source_agent_id: string;
  /**
   * Audit-log entry id this approval correlates to. Used as the
   * deduplication key alongside source_harness and source_agent_id.
   * Format: `<iso-timestamp>:<operation>` so two different requests on the
   * same operation in the same millisecond are still distinguishable.
   */
  audit_log_entry_id: string;
  /** Policy rule that fired (`tier1_<operation>`, `tier2_<anomaly>`, etc.). */
  policy_rule_id: string;
  /** Operator-friendly one-line summary, derived from gate context. */
  action_summary: string;
  /** SHA-256 hex of the canonicalized request payload. */
  request_payload_hash: string;
  /** Lifecycle status. */
  status: AggregatedApprovalStatus;
  /** ISO 8601 timestamp the aggregator first ingested the request. */
  created_at: string;
  /** ISO 8601 timestamp the status left `pending`. */
  resolved_at?: string;
  /** Operator identity that resolved the entry, if applicable. */
  resolved_by?: string;
  /** ISO 8601 deadline. Defaults to created_at + DEFAULT_PENDING_TTL_MS. */
  expires_at: string;
  /**
   * Optional cross-link to a v1.1 hub inbox item id. When set, the
   * dashboard renderer SHOULD suppress the duplicate hub card so the
   * operator sees one card per approval. Hub inbox surface is unchanged
   * (the cross-link signal lives on the aggregator side only).
   */
  hub_inbox_item_id?: string;
}

/**
 * Source-context resolver. Called once per ingest to map gate context to
 * the aggregator's harness + agent_id fields. Default impl reads the
 * fortress identity (single-agent fortresses) and returns `unknown` when
 * the gate context does not name an agent.
 */
export interface ApprovalSourceContext {
  source_harness: string;
  source_agent_id: string;
}

/**
 * Event the gate emits per approval lifecycle transition.
 */
export interface ApprovalGateEvent {
  /** `requested` on initial gate entry; `resolved` when channel returns. */
  phase: "requested" | "resolved";
  /** Operation name from the policy gate. */
  operation: string;
  /** Tier the gate decided on. */
  tier: 1 | 2;
  /** Human-readable reason from the gate (audit log only; not user-facing). */
  reason: string;
  /** Sanitized context map the gate captured. */
  context: Record<string, unknown>;
  /** ISO 8601 timestamp the gate entered `requestApproval()`. */
  request_timestamp: string;
  /**
   * On `resolved` only. Channel decision plus decided_by metadata. When
   * `decision === 'deny'` and `decided_by === 'channel_failure'`, the
   * aggregator records `status: 'timeout'` (Castle-walking discipline:
   * fail-closed at the gate flows through to the inbox).
   */
  resolution?: {
    decision: "approve" | "deny";
    decided_at: string;
    decided_by: string;
  };
  /**
   * Stable correlation id the gate emits BOTH on `requested` and on
   * `resolved`. The aggregator uses this to update the same entry on the
   * resolution event. Format: `<iso-ms-timestamp>:<operation>:<random4>`.
   */
  correlation_id: string;
}

/**
 * Listener subscription returned by `onEvent`. Call to unsubscribe.
 */
export type ApprovalAggregatorUnsubscribe = () => void;

/**
 * Event emitted to subscribers. Mirrors the lifecycle transitions the
 * aggregator records. SSE listeners surface these to the dashboard.
 */
export interface ApprovalAggregatorEmit {
  /**
   * `aggregated` on first ingest, `resolved` on a status leaving pending,
   * `deduped` when an ingest dropped because the same dedup key was seen.
   */
  type: "aggregated" | "resolved" | "deduped";
  entry: AggregatedApproval;
}

/**
 * Constructor dependencies. `pendingTtlMs` and `maxListLimit` default to
 * coordinator-CTO defaults; tests pass overrides for deterministic timing.
 */
export interface ApprovalAggregatorDeps {
  storage: StorageBackend;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  /** Operator identity id. Recorded on the audit entries. */
  identityId: string;
  /** Stable fortress id. Drives the source-context default values. */
  fortressId: string;
  /** Optional override for the pending TTL. */
  pendingTtlMs?: number;
  /** Optional override for the maximum list limit. */
  maxListLimit?: number;
  /** Optional clock override for deterministic tests. Defaults to `() => new Date()`. */
  now?: () => Date;
  /** Optional source-context resolver. Defaults to fortress identifiers. */
  resolveSourceContext?: (event: ApprovalGateEvent) => ApprovalSourceContext;
  /**
   * Optional cross-link resolver. Returns the v1.1 hub inbox item id that
   * shadows the same approval, when known. Default returns undefined and
   * the dashboard renders both surfaces. Upsilon-2 wires this through the
   * hub inbox store.
   */
  resolveHubInboxItemId?: (event: ApprovalGateEvent) => string | undefined;
}

/**
 * Aggregator state. The map is hydrated lazily from the encrypted
 * namespace on first read; subsequent reads are served from memory.
 */
export class ApprovalAggregator {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly auditLog: AuditLog;
  private readonly identityId: string;
  private readonly fortressId: string;
  private readonly pendingTtlMs: number;
  private readonly maxListLimit: number;
  private readonly now: () => Date;
  private readonly resolveSourceContext: (
    event: ApprovalGateEvent,
  ) => ApprovalSourceContext;
  private readonly resolveHubInboxItemId: (
    event: ApprovalGateEvent,
  ) => string | undefined;

  /** Cached entries by `aggregator_id`. */
  private readonly entries = new Map<string, AggregatedApproval>();
  /** Dedup index: `${harness}|${agent}|${audit_id}` -> aggregator_id. */
  private readonly dedupIndex = new Map<string, string>();
  /** Correlation index: gate `correlation_id` -> aggregator_id. */
  private readonly correlationIndex = new Map<string, string>();
  /** Original request payloads kept in-memory for `getFullPayload()`. */
  private readonly fullPayloads = new Map<string, unknown>();
  /** Has the aggregator hydrated persisted entries on this process? */
  private hydrated = false;
  /** Active SSE listeners. */
  private readonly listeners = new Set<(event: ApprovalAggregatorEmit) => void>();

  constructor(deps: ApprovalAggregatorDeps) {
    this.storage = deps.storage;
    this.encryptionKey = derivePurposeKey(
      deps.masterKey,
      APPROVAL_AGGREGATOR_HKDF_INFO,
    );
    this.auditLog = deps.auditLog;
    this.identityId = deps.identityId;
    this.fortressId = deps.fortressId;
    this.pendingTtlMs = deps.pendingTtlMs ?? DEFAULT_PENDING_TTL_MS;
    this.maxListLimit = deps.maxListLimit ?? DEFAULT_MAX_LIST_LIMIT;
    this.now = deps.now ?? (() => new Date());
    this.resolveSourceContext =
      deps.resolveSourceContext ??
      ((_event: ApprovalGateEvent): ApprovalSourceContext => ({
        source_harness: this.fortressId,
        source_agent_id: this.fortressId,
      }));
    this.resolveHubInboxItemId =
      deps.resolveHubInboxItemId ?? ((_event) => undefined);
  }

  /**
   * Subscribe an event listener. Returns an unsubscribe fn. SSE handlers
   * use this to forward aggregator emissions to the dashboard.
   */
  onEvent(
    listener: (event: ApprovalAggregatorEmit) => void,
  ): ApprovalAggregatorUnsubscribe {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Ingest a gate event. Returns the aggregator entry on first sight,
   * `null` when deduped. Resolution events update the existing record;
   * unmatched resolutions are dropped silently (caller's gate emitted a
   * resolved-without-requested pair, which the aggregator does not invent
   * a record for).
   */
  async ingest(event: ApprovalGateEvent): Promise<AggregatedApproval | null> {
    await this.hydrate();

    if (event.phase === "requested") {
      return this.ingestRequested(event);
    }
    if (event.phase === "resolved") {
      return this.ingestResolved(event);
    }
    return null;
  }

  /**
   * List pending or recently resolved entries. Pending entries past TTL
   * are lazily transitioned to `expired` and persisted before the list
   * snapshot is returned.
   */
  async list(opts?: {
    status?: AggregatedApprovalStatus;
    sinceTs?: string;
    limit?: number;
  }): Promise<AggregatedApproval[]> {
    await this.hydrate();
    await this.expireStale();

    const limit = Math.min(
      opts?.limit ?? DEFAULT_LIST_PAGE_SIZE,
      this.maxListLimit,
    );
    const sinceMs = opts?.sinceTs
      ? Date.parse(opts.sinceTs)
      : Number.NEGATIVE_INFINITY;

    const matching: AggregatedApproval[] = [];
    for (const entry of this.entries.values()) {
      if (opts?.status && entry.status !== opts.status) continue;
      if (Date.parse(entry.created_at) < sinceMs) continue;
      matching.push(entry);
    }
    matching.sort((a, b) => b.created_at.localeCompare(a.created_at));
    return matching.slice(0, limit);
  }

  /**
   * Return the original (unhashed) request payload for the entry. Returns
   * `null` when the entry is unknown or the payload was evicted (e.g. the
   * process restarted; payloads are in-memory only at v1.3 Upsilon-1).
   */
  async getFullPayload(aggregatorId: string): Promise<unknown> {
    await this.hydrate();
    if (!this.entries.has(aggregatorId)) return null;
    return this.fullPayloads.get(aggregatorId) ?? null;
  }

  /**
   * Resolve an entry. Used by both:
   *   1. The gate wire-up on channel-decision return.
   *   2. The HTTP `approve`/`deny` routes when an operator clicks.
   *
   * Idempotent: resolving an already-resolved entry is a no-op (the record
   * keeps its first decision and the audit log is not double-fired).
   * Unknown ids throw `Error("approval-aggregator: not_found")` so HTTP
   * routes return 404.
   */
  async resolve(
    aggregatorId: string,
    decision: "approved" | "denied",
    operatorId: string,
  ): Promise<AggregatedApproval> {
    await this.hydrate();
    const entry = this.entries.get(aggregatorId);
    if (!entry) {
      throw new Error("approval-aggregator: not_found");
    }
    if (entry.status !== "pending") {
      return entry;
    }
    entry.status = decision;
    entry.resolved_at = this.now().toISOString();
    entry.resolved_by = operatorId;
    await this.persist(entry);
    this.auditLog.append(
      "l2",
      APPROVAL_AGGREGATOR_AUDIT_OPS.RESOLVED,
      this.identityId,
      {
        aggregator_id: entry.aggregator_id,
        source_harness: entry.source_harness,
        source_agent_id: entry.source_agent_id,
        audit_log_entry_id: entry.audit_log_entry_id,
        policy_rule_id: entry.policy_rule_id,
        decision,
        decided_by: operatorId,
        decided_at: entry.resolved_at,
      },
    );
    this.emit({ type: "resolved", entry: { ...entry } });
    return entry;
  }

  // ── Internal: ingest paths ─────────────────────────────────────────────

  private async ingestRequested(
    event: ApprovalGateEvent,
  ): Promise<AggregatedApproval | null> {
    const ctx = this.resolveSourceContext(event);
    const auditId = this.auditEntryIdForEvent(event);
    const dedupKey = `${ctx.source_harness}|${ctx.source_agent_id}|${auditId}`;
    const existing = this.dedupIndex.get(dedupKey);
    if (existing) {
      const existingEntry = this.entries.get(existing);
      if (existingEntry) {
        // Same dedup tuple seen twice. Bind correlation id (so the
        // resolution event lands on the existing record) and emit a
        // dedupe audit + listener notification.
        this.correlationIndex.set(event.correlation_id, existing);
        this.auditLog.append(
          "l2",
          APPROVAL_AGGREGATOR_AUDIT_OPS.DEDUPED,
          this.identityId,
          {
            aggregator_id: existing,
            source_harness: ctx.source_harness,
            source_agent_id: ctx.source_agent_id,
            audit_log_entry_id: auditId,
            policy_rule_id: this.derivePolicyRuleId(event),
            correlation_id: event.correlation_id,
          },
        );
        this.emit({ type: "deduped", entry: { ...existingEntry } });
        return null;
      }
    }

    const id = randomUUID();
    const now = this.now();
    const expires = new Date(now.getTime() + this.pendingTtlMs);
    const hubInboxId = this.resolveHubInboxItemId(event);
    const entry: AggregatedApproval = {
      aggregator_id: id,
      source_harness: ctx.source_harness,
      source_agent_id: ctx.source_agent_id,
      audit_log_entry_id: auditId,
      policy_rule_id: this.derivePolicyRuleId(event),
      action_summary: this.deriveActionSummary(event),
      request_payload_hash: this.hashPayload(event.context),
      status: "pending",
      created_at: now.toISOString(),
      expires_at: expires.toISOString(),
      ...(hubInboxId !== undefined ? { hub_inbox_item_id: hubInboxId } : {}),
    };

    this.entries.set(id, entry);
    this.dedupIndex.set(dedupKey, id);
    this.correlationIndex.set(event.correlation_id, id);
    this.fullPayloads.set(id, event.context);

    await this.persist(entry);
    this.auditLog.append(
      "l2",
      APPROVAL_AGGREGATOR_AUDIT_OPS.AGGREGATED,
      this.identityId,
      {
        aggregator_id: id,
        source_harness: ctx.source_harness,
        source_agent_id: ctx.source_agent_id,
        audit_log_entry_id: auditId,
        policy_rule_id: entry.policy_rule_id,
        ...(hubInboxId !== undefined ? { hub_inbox_item_id: hubInboxId } : {}),
      },
    );
    this.emit({ type: "aggregated", entry: { ...entry } });
    return entry;
  }

  private async ingestResolved(
    event: ApprovalGateEvent,
  ): Promise<AggregatedApproval | null> {
    const id = this.correlationIndex.get(event.correlation_id);
    if (!id) return null;
    const entry = this.entries.get(id);
    if (!entry) return null;
    if (entry.status !== "pending") return entry;
    if (!event.resolution) return entry;

    const failClosed =
      event.resolution.decision === "deny" &&
      event.resolution.decided_by === "channel_failure";
    const status: AggregatedApprovalStatus = failClosed
      ? "timeout"
      : event.resolution.decision === "approve"
        ? "approved"
        : "denied";

    entry.status = status;
    entry.resolved_at = event.resolution.decided_at;
    entry.resolved_by = event.resolution.decided_by;
    await this.persist(entry);
    this.auditLog.append(
      "l2",
      APPROVAL_AGGREGATOR_AUDIT_OPS.RESOLVED,
      this.identityId,
      {
        aggregator_id: id,
        source_harness: entry.source_harness,
        source_agent_id: entry.source_agent_id,
        audit_log_entry_id: entry.audit_log_entry_id,
        policy_rule_id: entry.policy_rule_id,
        decision: status,
        decided_by: entry.resolved_by,
        decided_at: entry.resolved_at,
        fail_closed: failClosed,
      },
    );
    this.emit({ type: "resolved", entry: { ...entry } });
    return entry;
  }

  // ── Internal: helpers ──────────────────────────────────────────────────

  /**
   * Audit-log entry id for the dedup tuple. The audit log itself does not
   * surface a stable per-entry id (counter-prefixed keys are internal); the
   * aggregator uses the request timestamp + operation, which together pin
   * the audit entry the gate appended on the same call.
   */
  private auditEntryIdForEvent(event: ApprovalGateEvent): string {
    return `${event.request_timestamp}:${event.operation}`;
  }

  private derivePolicyRuleId(event: ApprovalGateEvent): string {
    return `tier${event.tier}:${event.operation}`;
  }

  private deriveActionSummary(event: ApprovalGateEvent): string {
    return `${event.operation} (tier ${event.tier})`;
  }

  /**
   * Canonical SHA-256 of the request context. Sorted-keys serialization so
   * identical payloads always hash the same, even when key insertion order
   * varies. Defends against payload-replay smuggling (the aggregator can
   * tell the same payload was seen twice without storing it cleartext).
   */
  private hashPayload(payload: unknown): string {
    const canonical = JSON.stringify(payload, Object.keys(payload as object).sort());
    return createHash("sha256").update(canonical).digest("hex");
  }

  private emit(event: ApprovalAggregatorEmit): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listener exceptions never fail the gate; the aggregator's
        // contract with the gate is "swallow listener errors" so a broken
        // dashboard never blocks a real approval flow. Cross-walking
        // discipline: cooperative MCP layer is additive, never load-bearing.
      }
    }
  }

  private async expireStale(): Promise<void> {
    const nowMs = this.now().getTime();
    for (const entry of this.entries.values()) {
      if (entry.status !== "pending") continue;
      if (Date.parse(entry.expires_at) > nowMs) continue;
      entry.status = "expired";
      entry.resolved_at = this.now().toISOString();
      entry.resolved_by = "system_ttl";
      await this.persist(entry);
      this.auditLog.append(
        "l2",
        APPROVAL_AGGREGATOR_AUDIT_OPS.RESOLVED,
        this.identityId,
        {
          aggregator_id: entry.aggregator_id,
          source_harness: entry.source_harness,
          source_agent_id: entry.source_agent_id,
          audit_log_entry_id: entry.audit_log_entry_id,
          policy_rule_id: entry.policy_rule_id,
          decision: "expired",
          decided_by: "system_ttl",
          decided_at: entry.resolved_at,
        },
      );
      this.emit({ type: "resolved", entry: { ...entry } });
    }
  }

  private async persist(entry: AggregatedApproval): Promise<void> {
    const serialized = stringToBytes(JSON.stringify(entry));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      APPROVAL_AGGREGATOR_NAMESPACE,
      entry.aggregator_id,
      stringToBytes(JSON.stringify(encrypted)),
    );
  }

  private async hydrate(): Promise<void> {
    if (this.hydrated) return;
    this.hydrated = true;
    try {
      const metas = await this.storage.list(APPROVAL_AGGREGATOR_NAMESPACE);
      for (const meta of metas) {
        const raw = await this.storage.read(
          APPROVAL_AGGREGATOR_NAMESPACE,
          meta.key,
        );
        if (!raw) continue;
        try {
          const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const entry: AggregatedApproval = JSON.parse(bytesToString(decrypted));
          this.entries.set(entry.aggregator_id, entry);
          const dedupKey = `${entry.source_harness}|${entry.source_agent_id}|${entry.audit_log_entry_id}`;
          this.dedupIndex.set(dedupKey, entry.aggregator_id);
        } catch {
          // Skip corrupted entries. Rotation cadence is a follow-up PR.
        }
      }
    } catch {
      // Storage not yet writable (cold start); next call hydrates.
      this.hydrated = false;
    }
  }
}
