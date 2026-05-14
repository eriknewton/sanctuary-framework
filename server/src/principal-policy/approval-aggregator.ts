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
import type { AuditEntry, AuditLog } from "../l2-operational/audit-log.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import type { AggregatorPayloadStore } from "./aggregator-store.js";

/** Reserved storage namespace for aggregator records. */
export const APPROVAL_AGGREGATOR_NAMESPACE = "_approval_aggregator";

/** HKDF info string for the aggregator's per-fortress encryption key. */
export const APPROVAL_AGGREGATOR_HKDF_INFO = "l2-approval-aggregator-v1";

/**
 * Audit-event operation names emitted by the aggregator. Additive to the
 * existing free-form `operation` field on `AuditEntry`. The first three
 * names ship with Upsilon-1; the remaining three (replay surface) ship
 * with Upsilon-3.
 */
export const APPROVAL_AGGREGATOR_AUDIT_OPS = {
  AGGREGATED: "cross_harness_approval_aggregated",
  RESOLVED: "cross_harness_approval_resolved",
  DEDUPED: "cross_harness_approval_deduped",
  PAYLOAD_DECRYPTED: "cross_harness_approval_payload_decrypted",
  AUDIT_TRAIL_VIEWED: "cross_harness_approval_audit_trail_viewed",
  REPLAYED: "cross_harness_approval_replayed",
} as const;

/**
 * Coordinator-CTO defaults baked in. v1.3 Upsilon-1 ships with one set of
 * sane numbers; per-fortress overrides land in a later PR if real fleet
 * usage shows a need.
 */
const DEFAULT_PENDING_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_MAX_LIST_LIMIT = 200;
const DEFAULT_LIST_PAGE_SIZE = 50;

function canonicalJson(value: unknown): string {
  if (value === undefined || typeof value === "function" || typeof value === "symbol") {
    return "null";
  }
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => {
      const item = record[key];
      return item !== undefined && typeof item !== "function" && typeof item !== "symbol";
    })
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

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
 * One step in the Castle Architecture enforcement chain that led to this
 * approval. Layers are: l1 (Castle Wall, OS-level egress), l2 (Sentinel +
 * cooperative MCP gate), l3 (selective disclosure), l4 (reputation).
 * v1.3 Upsilon-3 ships the schema; default resolver populates a single
 * `l2` entry. Future Castle Wall wiring will extend the chain when a
 * payload's egress was first observed by the kernel filter.
 */
export interface EnforcementLayerEvent {
  layer: "l1" | "l2" | "l3" | "l4";
  event: string;
  timestamp: string;
}

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
  /**
   * Castle Architecture enforcement-layer chain that led to this
   * approval. Populated by the optional `resolveEnforcementChain` deps
   * hook; default returns a single `l2` step (cooperative MCP gate
   * fired). Persisted with the entry so the operator-replay surface can
   * render the enforcement context after a server restart. v1.3
   * Upsilon-3.
   */
  enforcement_chain?: EnforcementLayerEvent[];
  /**
   * Aggregator revision number stamped at entry creation. Stable across
   * status transitions. Used by the v1.4 mobile companion sync API to
   * separate "added" from "changed" deltas (created_at_revision >
   * sinceRevision means added; otherwise it is a status change).
   * v1.3 Upsilon-4.
   */
  created_at_revision?: number;
  /**
   * Aggregator revision number stamped at the last mutation (creation,
   * resolution, expiration). Sync-API consumers compare against the
   * revision they last saw to compute the delta. Monotonically
   * increasing per fortress; gaps are normal (one bump per mutation).
   * v1.3 Upsilon-4.
   */
  last_modified_revision?: number;
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
   * `deduped` when an ingest dropped because the same dedup key was seen,
   * `removed` when an entry was pruned (v1.3 Upsilon-4).
   */
  type: "aggregated" | "resolved" | "deduped" | "removed";
  entry: AggregatedApproval;
}

/**
 * Sync-API delta returned by `getSync()`. v1.3 Upsilon-4. Mobile
 * companions poll this for cheap state-sync without re-fetching the
 * full inbox. The `revision` field on the response is the aggregator's
 * current revision; pass it back as `sinceRevision` on the next call.
 *
 * `added` carries entries created after `sinceRevision`. `changed`
 * carries entries that existed at `sinceRevision` but have transitioned
 * status (resolved, expired) since. `removed` carries the
 * aggregator_ids of entries pruned after `sinceRevision`.
 *
 * Tombstone caveat: removal tombstones live in-process memory. Server
 * restart clears them. Mobile clients reconnecting after the server
 * restarted MUST re-bootstrap from `list()` rather than rely on the
 * sync delta. The v1.4 mobile companion build wires the bootstrap-on-
 * reconnect flow; v1.3 documents the constraint.
 */
export interface ApprovalAggregatorSyncDelta {
  revision: number;
  added: AggregatedApproval[];
  changed: AggregatedApproval[];
  removed: string[];
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
  /**
   * Optional at-rest payload store. When provided, the aggregator
   * persists each request payload via `savePayload` on ingest, and
   * rehydrates payloads on `getFullPayload` if the in-memory map lost
   * them (e.g. after a server restart). Upsilon-3 surface; absent in
   * Upsilon-1 / Upsilon-2 deployments, where payloads remain in-memory
   * only.
   */
  payloadStore?: AggregatorPayloadStore;
  /**
   * Optional resolver for the Castle Architecture enforcement chain
   * leading to this approval. Default returns a single `l2` step
   * (cooperative MCP gate fired). When the Castle Wall (Layer 1) ships,
   * its kernel-filter observer can populate richer chains by passing a
   * resolver here.
   */
  resolveEnforcementChain?: (
    event: ApprovalGateEvent,
  ) => EnforcementLayerEvent[];
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
  private readonly payloadStore: AggregatorPayloadStore | null;
  private readonly resolveEnforcementChain: (
    event: ApprovalGateEvent,
  ) => EnforcementLayerEvent[];

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
  /**
   * Monotonic revision counter, bumped on every mutation (ingest of new
   * entry, resolve, expire, delete). Hydrated from max(last_modified_revision)
   * across persisted entries on first read; in-memory after that. v1.3
   * Upsilon-4.
   */
  private currentRevision = 0;
  /**
   * Removal tombstones: aggregator_id -> revision at removal. Used by the
   * sync API to surface "removed" entries to mobile consumers between
   * polls. In-memory only; server restart clears tombstones (mobile
   * bootstraps via `list()` on reconnect). v1.3 Upsilon-4.
   */
  private readonly removedTombstones = new Map<string, number>();

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
    this.payloadStore = deps.payloadStore ?? null;
    this.resolveEnforcementChain =
      deps.resolveEnforcementChain ??
      ((event: ApprovalGateEvent): EnforcementLayerEvent[] => [
        {
          layer: "l2",
          event: `approval_required:${event.operation}`,
          timestamp: event.request_timestamp,
        },
      ]);
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
   * Current aggregator revision. v1.3 Upsilon-4. Mobile companions
   * poll the lightweight `/revision` route to detect that something
   * changed before fetching a full sync delta.
   */
  async getRevision(): Promise<number> {
    await this.hydrate();
    return this.currentRevision;
  }

  /**
   * Compute a delta since `sinceRevision`. v1.3 Upsilon-4. Mobile
   * clients poll this for cheap state-sync. Behavior:
   *  - `added`: entries whose `created_at_revision > sinceRevision`.
   *  - `changed`: entries that existed at `sinceRevision` but had a
   *    status transition (resolve, expire) since.
   *  - `removed`: aggregator_ids deleted after `sinceRevision`.
   *  - `revision`: current aggregator revision; pass this back as
   *    `sinceRevision` on the next call.
   *
   * `limit` caps the total count returned across all three lists,
   * prioritized as added -> changed -> removed (newer-state first).
   * When more changes exist than fit, the next call with the returned
   * revision will pick up the rest because each entry's
   * last_modified_revision is unchanged by truncation.
   */
  async getSync(opts?: {
    sinceRevision?: number;
    limit?: number;
  }): Promise<ApprovalAggregatorSyncDelta> {
    await this.hydrate();
    await this.expireStale();
    const sinceRevision = opts?.sinceRevision ?? 0;
    const cap = Math.min(
      opts?.limit ?? DEFAULT_LIST_PAGE_SIZE,
      this.maxListLimit,
    );
    const added: AggregatedApproval[] = [];
    const changed: AggregatedApproval[] = [];
    for (const entry of this.entries.values()) {
      const lastMod = entry.last_modified_revision ?? 0;
      if (lastMod <= sinceRevision) continue;
      const createdRev = entry.created_at_revision ?? 0;
      if (createdRev > sinceRevision) {
        added.push(entry);
      } else {
        changed.push(entry);
      }
    }
    const removed: string[] = [];
    for (const [id, rev] of this.removedTombstones) {
      if (rev > sinceRevision) removed.push(id);
    }
    added.sort(
      (a, b) =>
        (a.last_modified_revision ?? 0) - (b.last_modified_revision ?? 0),
    );
    changed.sort(
      (a, b) =>
        (a.last_modified_revision ?? 0) - (b.last_modified_revision ?? 0),
    );
    let remaining = cap;
    const addedOut = added.slice(0, Math.max(0, remaining));
    remaining -= addedOut.length;
    const changedOut = changed.slice(0, Math.max(0, remaining));
    remaining -= changedOut.length;
    const removedOut = removed.slice(0, Math.max(0, remaining));
    return {
      revision: this.currentRevision,
      added: addedOut,
      changed: changedOut,
      removed: removedOut,
    };
  }

  /**
   * Delete an entry. Drops the in-memory record, the persisted bundle,
   * and the at-rest payload (if a payload store is wired). Records a
   * tombstone with the new revision so sync-API consumers see a
   * `removed` delta. Returns true when an entry was deleted, false on
   * unknown id. v1.3 Upsilon-4. Reserved for v1.4+ retention housekeeping;
   * Upsilon-4 ships the surface so mobile sync-API tests can exercise the
   * removal path.
   */
  async deleteEntry(aggregatorId: string): Promise<boolean> {
    await this.hydrate();
    const entry = this.entries.get(aggregatorId);
    if (!entry) return false;
    const dedupKey = `${entry.source_harness}|${entry.source_agent_id}|${entry.audit_log_entry_id}`;
    this.entries.delete(aggregatorId);
    this.dedupIndex.delete(dedupKey);
    this.fullPayloads.delete(aggregatorId);
    for (const [corr, id] of this.correlationIndex) {
      if (id === aggregatorId) this.correlationIndex.delete(corr);
    }
    try {
      await this.storage.delete(APPROVAL_AGGREGATOR_NAMESPACE, aggregatorId);
    } catch {
      // Storage delete failure is non-fatal: the entry is gone from the
      // in-memory map and the tombstone fires regardless.
    }
    if (this.payloadStore) {
      try {
        await this.payloadStore.deletePayload(aggregatorId);
      } catch {
        // Same non-fatal posture.
      }
    }
    const revision = this.nextRevision();
    this.removedTombstones.set(aggregatorId, revision);
    this.emit({ type: "removed", entry: { ...entry } });
    return true;
  }

  private nextRevision(): number {
    this.currentRevision += 1;
    return this.currentRevision;
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
   * `null` when the entry is unknown. When the in-memory payload map has
   * been evicted (e.g. after a server restart) and a `payloadStore` was
   * provided, the at-rest bundle is decrypted and the in-memory map is
   * refilled. Audit emission lives on the `*WithAudit` variant; this base
   * accessor is silent so internal callers can read without polluting the
   * audit trail.
   */
  async getFullPayload(aggregatorId: string): Promise<unknown> {
    await this.hydrate();
    if (!this.entries.has(aggregatorId)) return null;
    const cached = this.fullPayloads.get(aggregatorId);
    if (cached !== undefined) return cached;
    if (this.payloadStore) {
      try {
        const restored = await this.payloadStore.loadPayload(aggregatorId);
        if (restored !== null) {
          this.fullPayloads.set(aggregatorId, restored);
          return restored;
        }
      } catch {
        // Fall through to null on store failure.
      }
    }
    return null;
  }

  /**
   * Return the entry record for the given id, or null when unknown.
   * Idempotent. v1.3 Upsilon-3.
   */
  async getEntry(aggregatorId: string): Promise<AggregatedApproval | null> {
    await this.hydrate();
    return this.entries.get(aggregatorId) ?? null;
  }

  /**
   * Audited variant of `getFullPayload`. Emits the
   * `cross_harness_approval_payload_decrypted` audit event before
   * returning. Used by the operator-facing /payload replay route.
   * v1.3 Upsilon-3.
   */
  async getFullPayloadWithAudit(
    aggregatorId: string,
    operatorId: string,
  ): Promise<unknown> {
    const payload = await this.getFullPayload(aggregatorId);
    if (payload === null) return null;
    const entry = this.entries.get(aggregatorId);
    this.auditLog.append(
      "l2",
      APPROVAL_AGGREGATOR_AUDIT_OPS.PAYLOAD_DECRYPTED,
      operatorId,
      {
        aggregator_id: aggregatorId,
        ...(entry
          ? {
              source_harness: entry.source_harness,
              source_agent_id: entry.source_agent_id,
              entry_status: entry.status,
            }
          : {}),
      },
    );
    return payload;
  }

  /**
   * Return the audit-log entries that led to and surround this approval.
   * Best-effort matching: aggregator-side emissions (AGGREGATED, RESOLVED,
   * DEDUPED, replay events) all carry `details.aggregator_id` and link
   * directly. Gate-side emissions (`gate_*:operation`) do not carry the
   * aggregator id at v1.3, so they are matched via timestamp window
   * (entry.created_at to entry.resolved_at + 1s, or expires_at + 1s while
   * pending) and operation suffix. Emits AUDIT_TRAIL_VIEWED on call.
   * v1.3 Upsilon-3.
   */
  async getAuditTrail(
    aggregatorId: string,
    operatorId: string,
  ): Promise<AuditEntry[]> {
    await this.hydrate();
    const entry = this.entries.get(aggregatorId);
    if (!entry) {
      return [];
    }
    const sinceMs = Date.parse(entry.created_at) - 1000;
    const sinceIso = new Date(sinceMs).toISOString();
    const queried = await this.auditLog.query({ since: sinceIso, limit: 1000 });
    const operationPart = entry.policy_rule_id.includes(":")
      ? entry.policy_rule_id.slice(entry.policy_rule_id.indexOf(":") + 1)
      : entry.policy_rule_id;
    const lifetimeStart = sinceMs;
    const lifetimeEnd = entry.resolved_at
      ? Date.parse(entry.resolved_at) + 1000
      : Date.parse(entry.expires_at) + 1000;

    const matches: AuditEntry[] = [];
    for (const audit of queried.entries) {
      const detailsId =
        audit.details !== undefined
          ? (audit.details as Record<string, unknown>)["aggregator_id"]
          : undefined;
      if (detailsId === aggregatorId) {
        matches.push(audit);
        continue;
      }
      const auditMs = Date.parse(audit.timestamp);
      if (auditMs < lifetimeStart || auditMs > lifetimeEnd) continue;
      if (audit.operation.endsWith(`:${operationPart}`)) {
        matches.push(audit);
      }
    }
    matches.sort((a, b) =>
      a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0,
    );

    this.auditLog.append(
      "l2",
      APPROVAL_AGGREGATOR_AUDIT_OPS.AUDIT_TRAIL_VIEWED,
      operatorId,
      {
        aggregator_id: aggregatorId,
        entry_status: entry.status,
        match_count: matches.length,
      },
    );
    return matches;
  }

  /**
   * List historical (resolved) approvals. Excludes pending entries by
   * design: `list()` is the pending-inbox surface and `getHistory()` is
   * the resolved-replay surface. Emits REPLAYED on each call. v1.3
   * Upsilon-3.
   */
  async getHistory(
    opts: {
      status?: AggregatedApprovalStatus;
      sinceTs?: string;
      limit?: number;
    } | undefined,
    operatorId: string,
  ): Promise<AggregatedApproval[]> {
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
      if (entry.status === "pending") continue;
      if (opts?.status && entry.status !== opts.status) continue;
      const stamp = Date.parse(entry.resolved_at ?? entry.created_at);
      if (stamp < sinceMs) continue;
      matching.push(entry);
    }
    matching.sort((a, b) => {
      const aStamp = a.resolved_at ?? a.created_at;
      const bStamp = b.resolved_at ?? b.created_at;
      return bStamp.localeCompare(aStamp);
    });
    const sliced = matching.slice(0, limit);

    this.auditLog.append(
      "l2",
      APPROVAL_AGGREGATOR_AUDIT_OPS.REPLAYED,
      operatorId,
      {
        result_count: sliced.length,
        ...(opts?.status !== undefined ? { status_filter: opts.status } : {}),
        ...(opts?.sinceTs !== undefined ? { since: opts.sinceTs } : {}),
      },
    );
    return sliced;
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
    entry.last_modified_revision = this.nextRevision();
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
    const enforcementChain = this.resolveEnforcementChain(event);
    const revision = this.nextRevision();
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
      created_at_revision: revision,
      last_modified_revision: revision,
      ...(hubInboxId !== undefined ? { hub_inbox_item_id: hubInboxId } : {}),
      ...(enforcementChain.length > 0
        ? { enforcement_chain: enforcementChain }
        : {}),
    };

    this.entries.set(id, entry);
    this.dedupIndex.set(dedupKey, id);
    this.correlationIndex.set(event.correlation_id, id);
    this.fullPayloads.set(id, event.context);

    await this.persist(entry);
    if (this.payloadStore) {
      try {
        await this.payloadStore.savePayload(id, event.context);
      } catch {
        // At-rest persistence failure is non-fatal: in-memory map still
        // serves the payload for the current process. Replay-after-restart
        // simply degrades for this entry.
      }
    }
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
    entry.last_modified_revision = this.nextRevision();
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
   * Canonical SHA-256 of the request context. Recursive sorted-keys
   * serialization so nested payloads cannot collide through top-level-only
   * JSON.stringify replacer behavior.
   */
  private hashPayload(payload: unknown): string {
    const canonical = canonicalJson(payload);
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
      entry.last_modified_revision = this.nextRevision();
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
    const aad = stringToBytes(entry.aggregator_id);
    const encrypted = encrypt(serialized, this.encryptionKey, aad);
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
          let decrypted: Uint8Array;
          try {
            decrypted = decrypt(
              encrypted,
              this.encryptionKey,
              stringToBytes(meta.key),
            );
          } catch {
            decrypted = decrypt(encrypted, this.encryptionKey);
          }
          const entry: AggregatedApproval = JSON.parse(bytesToString(decrypted));
          if (entry.aggregator_id !== meta.key) continue;
          this.entries.set(entry.aggregator_id, entry);
          const dedupKey = `${entry.source_harness}|${entry.source_agent_id}|${entry.audit_log_entry_id}`;
          this.dedupIndex.set(dedupKey, entry.aggregator_id);
          // v1.3 Upsilon-4: re-anchor the revision counter to max persisted
          // last_modified_revision so post-restart bumps stay monotonic.
          // Tombstones are not persisted; mobile bootstraps on reconnect.
          const lastMod = entry.last_modified_revision ?? 0;
          if (lastMod > this.currentRevision) {
            this.currentRevision = lastMod;
          }
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
