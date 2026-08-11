/**
 * Per-node local state stores.
 *
 * The lifecycle orchestrator holds a small set of replicated tables on each
 * node: policy bundle (per-agent latest signed policy event), agent-locator
 * table (per-agent canonical-node pointer), and node-lifecycle event log
 * (recent join/leave/revoke events). These shapes are the answers a sync
 * request fetches.
 *
 * Spec §3.2, §5.1, §6.1.
 */

import type {
  LocatorUpdatePayload,
  NodeLifecyclePayload,
  PolicyUpdatePayload,
  SignedEvent,
} from "../types.js";
import { decodePolicyBlob } from "../../policy-engine/canonical-policy.js";

export const POLICY_BUNDLE_REJECTION_AUDIT_OP =
  "mesh_policy_bundle_rejected" as const;

export type PolicyBundleRejectionReason =
  | "policy_payload_malformed"
  | "policy_version_replay"
  | "policy_validity_missing"
  | "policy_validity_invalid"
  | "policy_not_yet_valid"
  | "policy_expired";

export type PolicyBundleUpsertResult =
  | "applied"
  | PolicyBundleRejectionReason;

export interface PolicyBundleAuditEvent {
  operation: typeof POLICY_BUNDLE_REJECTION_AUDIT_OP;
  emitted_at: string;
  event_id: string;
  agent_id: string;
  reason: PolicyBundleRejectionReason;
  incoming_policy_version: unknown;
  current_policy_version: number;
  valid_from?: string;
  valid_until?: string;
}

export interface PolicyBundleStoreOptions {
  now?: () => Date;
  onAuditEvent?: (event: PolicyBundleAuditEvent) => void;
}

/**
 * Per-agent policy bundle. Holds only the highest-version signed policy
 * event seen for each agent_id. Stale versions and invalid validity windows
 * are rejected explicitly and audited, never silently accepted.
 */
export class PolicyBundleStore {
  private byAgent = new Map<string, SignedEvent<PolicyUpdatePayload>>();
  private readonly auditEventsList: PolicyBundleAuditEvent[] = [];
  private readonly now: () => Date;
  private readonly onAuditEvent?: (event: PolicyBundleAuditEvent) => void;

  constructor(options: PolicyBundleStoreOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.onAuditEvent = options.onAuditEvent;
  }

  upsert(evt: SignedEvent<PolicyUpdatePayload>): PolicyBundleUpsertResult {
    const payloadResult = this.validatePolicyUpdateEvent(evt);
    if (payloadResult !== "applied") {
      return this.reject(evt, payloadResult, undefined);
    }

    const existing = this.byAgent.get(evt.payload.agent_id);
    if (
      existing &&
      existing.payload.policy_version >= evt.payload.policy_version
    ) {
      return this.reject(evt, "policy_version_replay", existing);
    }

    this.byAgent.set(evt.payload.agent_id, evt);
    return "applied";
  }

  get(agentId: string): SignedEvent<PolicyUpdatePayload> | undefined {
    return this.byAgent.get(agentId);
  }

  versionOf(agentId: string): number {
    return this.byAgent.get(agentId)?.payload.policy_version ?? 0;
  }

  /** Vector of agent_id → highest-pinned policy_version. */
  versionVector(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const [k, v] of this.byAgent) out[k] = v.payload.policy_version;
    return out;
  }

  /**
   * Delta query for sync replies - return every event whose policy_version
   * is strictly greater than the requester's per-agent baseline. Agents the
   * requester has never seen (no entry in baseline) are included whole.
   */
  delta(
    sincePolicyVersions: Record<string, number>
  ): SignedEvent<PolicyUpdatePayload>[] {
    const out: SignedEvent<PolicyUpdatePayload>[] = [];
    for (const [agentId, evt] of this.byAgent) {
      const baseline = sincePolicyVersions[agentId] ?? 0;
      if (evt.payload.policy_version > baseline) out.push(evt);
    }
    return out;
  }

  size(): number {
    return this.byAgent.size;
  }

  snapshot(): SignedEvent<PolicyUpdatePayload>[] {
    return [...this.byAgent.values()];
  }

  auditEvents(): readonly PolicyBundleAuditEvent[] {
    return this.auditEventsList;
  }

  private validatePolicyUpdateEvent(
    evt: SignedEvent<PolicyUpdatePayload>
  ): "applied" | Exclude<PolicyBundleRejectionReason, "policy_version_replay"> {
    const payload = evt.payload;
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      return "policy_payload_malformed";
    }
    const record = payload as unknown as Record<string, unknown>;
    if (
      typeof record.agent_id !== "string" ||
      record.agent_id.trim().length === 0 ||
      !isSafeNonNegativeInteger(record.policy_version) ||
      (record.parent_version !== undefined &&
        !isSafeNonNegativeInteger(record.parent_version)) ||
      typeof record.policy_blob !== "string"
    ) {
      return "policy_payload_malformed";
    }
    if (
      typeof record.valid_from !== "string" ||
      record.valid_from.length === 0 ||
      typeof record.valid_until !== "string" ||
      record.valid_until.length === 0
    ) {
      return "policy_validity_missing";
    }
    const validFromMs = Date.parse(record.valid_from);
    const validUntilMs = Date.parse(record.valid_until);
    if (
      !Number.isFinite(validFromMs) ||
      !Number.isFinite(validUntilMs) ||
      validFromMs >= validUntilMs
    ) {
      return "policy_validity_invalid";
    }
    const nowMs = this.now().getTime();
    // Residual: validity-window enforcement trusts the local wall clock; a
    // local clock rollback can extend acceptance until a trusted time source lands.
    if (nowMs < validFromMs) return "policy_not_yet_valid";
    if (nowMs >= validUntilMs) return "policy_expired";

    try {
      const compiled = decodePolicyBlob(record.policy_blob);
      if (
        compiled.agent_id !== record.agent_id ||
        compiled.policy_version !== record.policy_version ||
        compiled.parent_version !== record.parent_version ||
        compiled.fortress_id !== evt.fortress_id
      ) {
        return "policy_payload_malformed";
      }
    } catch {
      return "policy_payload_malformed";
    }
    return "applied";
  }

  private reject(
    evt: SignedEvent<PolicyUpdatePayload>,
    reason: PolicyBundleRejectionReason,
    existing: SignedEvent<PolicyUpdatePayload> | undefined
  ): PolicyBundleRejectionReason {
    const payload =
      evt.payload !== null &&
      typeof evt.payload === "object" &&
      !Array.isArray(evt.payload)
        ? (evt.payload as unknown as Record<string, unknown>)
        : {};
    const agentId =
      typeof payload.agent_id === "string" && payload.agent_id.trim().length > 0
        ? payload.agent_id
        : "<malformed>";
    const auditEvent: PolicyBundleAuditEvent = {
      operation: POLICY_BUNDLE_REJECTION_AUDIT_OP,
      emitted_at: this.now().toISOString(),
      event_id: evt.event_id,
      agent_id: agentId,
      reason,
      incoming_policy_version: payload.policy_version,
      current_policy_version: existing?.payload.policy_version ?? 0,
      ...(typeof payload.valid_from === "string"
        ? { valid_from: payload.valid_from }
        : {}),
      ...(typeof payload.valid_until === "string"
        ? { valid_until: payload.valid_until }
        : {}),
    };
    this.auditEventsList.push(auditEvent);
    this.onAuditEvent?.(auditEvent);
    return reason;
  }
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

export const LOCATOR_REJECTION_AUDIT_OP =
  "mesh_locator_update_rejected" as const;

/**
 * MESH-LOCATOR-01 (rule 7, semantic-provenance): the only reason a
 * locator_update is ever refused before the version/conflict logic runs.
 */
export type LocatorRejectionReason = "locator_host_mismatch";

export type LocatorUpsertResult =
  | "applied"
  | "older"
  | "conflict"
  | LocatorRejectionReason;

export interface LocatorRejectionAuditEvent {
  operation: typeof LOCATOR_REJECTION_AUDIT_OP;
  emitted_at: string;
  event_id: string;
  agent_id: string;
  reason: LocatorRejectionReason;
  emitter_node: string;
  emitter_principal: string;
  claimed_canonical_node: string;
  claimed_hosting_principal: string;
}

export interface LocatorTableStoreOptions {
  now?: () => Date;
  onAuditEvent?: (event: LocatorRejectionAuditEvent) => void;
}

/**
 * Upper bound on distinct agent_ids a single fortress's locator table will
 * hold (AGENTS.md rule 8: attacker-influenced state needs an explicit cap).
 * 4096 is a generous multiple of any realistic per-fortress agent
 * population while still bounding a self-hosting-but-malicious rostered
 * peer (MESH-LOCATOR-01's host-mismatch check only stops it from claiming
 * OTHER agents, not from fabricating an unbounded number of agent_ids it
 * "self-hosts") to a fixed memory ceiling rather than unbounded growth.
 */
export const MAX_LOCATOR_TABLE_ENTRIES = 4096;

/** Per-fortress agent-locator table (§6). */
export class LocatorTableStore {
  private byAgent = new Map<string, SignedEvent<LocatorUpdatePayload>>();
  private highestVersion = 0;
  private readonly now: () => Date;
  private readonly onAuditEvent?: (event: LocatorRejectionAuditEvent) => void;
  private readonly auditEventsList: LocatorRejectionAuditEvent[] = [];

  constructor(options: LocatorTableStoreOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.onAuditEvent = options.onAuditEvent;
  }

  upsert(evt: SignedEvent<LocatorUpdatePayload>): LocatorUpsertResult {
    // AUTHORITY BINDING (MESH-LOCATOR-01, rule 7): `canonical_node` and
    // `hosting_principal` are ATTACKER-CONTROLLED PAYLOAD fields — the
    // envelope signature verified upstream (mesh-node.ts's verifyOrThrow,
    // called BEFORE this method is ever reached) proves only that
    // `emitter_node`/`emitter_principal` genuinely signed this envelope, not
    // that the payload's claimed new host is truthful. Without this check
    // any rostered-but-untrusted peer could publish a validly-signed
    // locator_update redirecting ANY OTHER agent's canonical node to
    // itself (a state-transfer-key-bearing trust hijack). A locator entry
    // is accepted ONLY as a first-person self-report: the node claiming to
    // now host the agent must BE the node whose signature this envelope
    // carries, and the principal named as host must BE the principal that
    // (co-)signed it. This mirrors the sibling handlers that already get
    // this right — heartbeat keys `roster.recordHeartbeat` off the
    // envelope's own `emitter_node`, never a payload field (mesh-node.ts),
    // and node_revoke has its own `assertNodeRevokeAuthorized` gate.
    if (
      evt.emitter_node !== evt.payload.canonical_node ||
      evt.emitter_principal !== evt.payload.hosting_principal
    ) {
      return this.reject(evt, "locator_host_mismatch");
    }

    const existing = this.byAgent.get(evt.payload.agent_id);
    if (existing) {
      if (
        existing.payload.locator_version === evt.payload.locator_version &&
        existing.payload.canonical_node !== evt.payload.canonical_node
      ) {
        return "conflict";
      }
      if (
        existing.payload.locator_version >= evt.payload.locator_version
      ) {
        return "older";
      }
    } else if (this.byAgent.size >= MAX_LOCATOR_TABLE_ENTRIES) {
      // Bound (rule 8): a NEW agent_id would grow the map past its cap.
      // Evict the oldest entry (Map iteration order is insertion order) —
      // never an UPDATE to an existing agent_id, which never grows the
      // map and so never needs to evict anything. Losing the oldest
      // locator entry here is not a trust-bearing removal the way a
      // federation peer's trust state disappearing is (BoundedMap's
      // audited-eviction ceremony is for that class): a peer that still
      // legitimately hosts the evicted agent simply re-publishes on its
      // next heartbeat/sync cycle, so a plain FIFO drop (no audit write,
      // no BoundedMap) is the correct, minimal bound here.
      const oldestAgentId = this.byAgent.keys().next().value as string;
      this.byAgent.delete(oldestAgentId);
    }
    this.byAgent.set(evt.payload.agent_id, evt);
    if (evt.payload.locator_version > this.highestVersion) {
      this.highestVersion = evt.payload.locator_version;
    }
    return "applied";
  }

  get(agentId: string): SignedEvent<LocatorUpdatePayload> | undefined {
    return this.byAgent.get(agentId);
  }

  highest(): number {
    return this.highestVersion;
  }

  delta(
    sinceLocatorVersion: number
  ): SignedEvent<LocatorUpdatePayload>[] {
    return [...this.byAgent.values()].filter(
      (e) => e.payload.locator_version > sinceLocatorVersion
    );
  }

  size(): number {
    return this.byAgent.size;
  }

  snapshot(): SignedEvent<LocatorUpdatePayload>[] {
    return [...this.byAgent.values()];
  }

  auditEvents(): readonly LocatorRejectionAuditEvent[] {
    return this.auditEventsList;
  }

  private reject(
    evt: SignedEvent<LocatorUpdatePayload>,
    reason: LocatorRejectionReason
  ): LocatorRejectionReason {
    const auditEvent: LocatorRejectionAuditEvent = {
      operation: LOCATOR_REJECTION_AUDIT_OP,
      emitted_at: this.now().toISOString(),
      event_id: evt.event_id,
      agent_id: evt.payload.agent_id,
      reason,
      emitter_node: evt.emitter_node,
      emitter_principal: evt.emitter_principal,
      claimed_canonical_node: evt.payload.canonical_node,
      claimed_hosting_principal: evt.payload.hosting_principal,
    };
    this.auditEventsList.push(auditEvent);
    this.onAuditEvent?.(auditEvent);
    return reason;
  }
}

/**
 * Upper bound on retained lifecycle events (AGENTS.md rule 8). 4096 mirrors
 * MAX_LOCATOR_TABLE_ENTRIES's derivation: a generous multiple of realistic
 * per-fortress join/leave/revoke churn, while still bounding a rostered
 * peer that broadcasts (or replies to sync with) an unbounded stream of
 * distinct, validly-signed lifecycle events to a fixed memory ceiling.
 */
export const MAX_LIFECYCLE_LOG_ENTRIES = 4096;

/**
 * Recent node-lifecycle events log. Used by sync to ship missed
 * join/leave/revoke events to a rejoining node.
 */
export class NodeLifecycleEventLog {
  private events: SignedEvent<NodeLifecyclePayload>[] = [];
  /** Dedup index mirroring `events` 1:1 (AGENTS.md rule 8 / MESH-SYNC-DOS-01):
   * the SAME event can legitimately reach `append()` twice — once via the
   * broadcast router, once via a sync response replaying it — and a
   * malicious peer can replay the identical signed event repeatedly to
   * inflate the log. Keying on `event_id` (a per-emitter-unique ULID, part
   * of the verified envelope) makes `append()` itself idempotent, which is
   * the single shared chokepoint every caller (mesh-node.ts's direct
   * append AND sync.ts's applySyncResponse append of the SAME accepted
   * events) inherits for free, rather than each call site having to
   * remember to dedup on its own.
   */
  private readonly seenEventIds = new Set<string>();

  /**
   * Append `evt` unless its `event_id` was already recorded. Returns
   * whether the event was newly added, so a caller that needs accurate
   * "how many new events did this apply" telemetry (sync.ts's
   * ApplySyncResult) can tell a genuine new event apart from a replay.
   */
  append(evt: SignedEvent<NodeLifecyclePayload>): boolean {
    if (this.seenEventIds.has(evt.event_id)) {
      return false;
    }
    if (this.events.length >= MAX_LIFECYCLE_LOG_ENTRIES) {
      // Bound (rule 8): FIFO-evict the oldest retained event before
      // admitting a new one. Not a trust-bearing removal (see
      // LocatorTableStore's identical eviction note) — a rejoining node
      // whose `since_event_id` baseline predates the evicted window falls
      // back to `since()`'s "unknown baseline -> ship everything we still
      // have" path below, which is always a safe (if larger) resync, never
      // a correctness violation.
      const evicted = this.events.shift();
      if (evicted) this.seenEventIds.delete(evicted.event_id);
    }
    this.events.push(evt);
    this.seenEventIds.add(evt.event_id);
    return true;
  }

  /**
   * Return events emitted strictly after `since_event_id`. If `since_event_id`
   * is undefined, return the full log (first-join sync case).
   */
  since(
    sinceEventId: string | undefined
  ): SignedEvent<NodeLifecyclePayload>[] {
    if (!sinceEventId) return [...this.events];
    const idx = this.events.findIndex((e) => e.event_id === sinceEventId);
    if (idx === -1) return [...this.events];
    return this.events.slice(idx + 1);
  }

  size(): number {
    return this.events.length;
  }

  snapshot(): SignedEvent<NodeLifecyclePayload>[] {
    return [...this.events];
  }
}
