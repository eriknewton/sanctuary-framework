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
import {
  MAX_RETAINED_NON_REVOKE_EVENTS_PER_EMITTER,
  MAX_RETAINED_REVOKE_AUTHORIZATIONS_PER_TARGET,
  NODE_LIFECYCLE_LOG_MAX_EVENTS,
} from "./constants.js";

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

/** Per-fortress agent-locator table (§6). */
export class LocatorTableStore {
  private byAgent = new Map<string, SignedEvent<LocatorUpdatePayload>>();
  private highestVersion = 0;

  upsert(
    evt: SignedEvent<LocatorUpdatePayload>
  ): "applied" | "older" | "conflict" {
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
}

/**
 * Recent node-lifecycle events log. Used by sync to ship missed
 * join/leave/revoke events to a rejoining node.
 *
 * SYNC-APPEND-01 (C12-REPLAY §3.3): this log is fed from untrusted sync input,
 * so it is NOT an unbounded array. Four invariants hold here:
 *   - a cap with revoke-preserving eviction (rule 8);
 *   - a per-EMITTER quota on retained non-revoke events (rule 8's per-origin
 *     quota): one flooding in-roster emitter evicts within its OWN bucket
 *     first and can never push another emitter's events out of the log;
 *   - non-revoke events dedupe on `(emitter_node_id, event_id)` — emitter-scoped
 *     so no cross-emitter suppression, and (per the caller contract) only
 *     VERIFIED events reach `append`, so an unverified colliding id can never
 *     occupy a slot;
 *   - accepted revokes retain on the AUTHORIZATION key (never `event_id`, which
 *     is attacker-chosen inside the signed body): one authorization yields at
 *     most one retained revoke entry per target, bounding the revoke-retained
 *     set by (#targets * per-target quota) so a single harvested quorum cannot
 *     apply eviction pressure against other targets' legitimate revokes.
 *
 * The roster-state binding (drop a same-authorization replay only when the
 * target is currently revoked, refuse it when re-admitted) lives in the CALLER
 * (`MeshNode.admitRevoke`), which knows roster state; this class provides the
 * authorization-presence query and the append that registers it.
 */
export class NodeLifecycleEventLog {
  private events: SignedEvent<NodeLifecyclePayload>[] = [];
  /** `${emitter_node} ${event_id}` for every retained NON-revoke event. */
  private readonly nonRevokeKeys = new Set<string>();
  /** authorization key -> the retained revoke event (identity for eviction). */
  private readonly revokeByAuth = new Map<
    string,
    SignedEvent<NodeLifecyclePayload>
  >();
  /** target_node_id -> retained authorization keys in insertion order. */
  private readonly revokeAuthsByTarget = new Map<string, string[]>();
  /**
   * emitter_node -> that emitter's retained NON-revoke events in insertion
   * order. Backs the per-emitter quota (rule 8's per-origin quota): eviction
   * under quota pressure comes from the flooding emitter's own bucket, never
   * a neighbor's.
   */
  private readonly nonRevokeByEmitter = new Map<
    string,
    SignedEvent<NodeLifecyclePayload>[]
  >();

  /**
   * Append a VERIFIED non-revoke lifecycle event. Idempotent on
   * `(emitter_node, event_id)`: a re-served duplicate is a no-op, never a
   * second row. Revokes MUST go through `appendRevoke` instead.
   */
  append(evt: SignedEvent<NodeLifecyclePayload>): void {
    if (evt.event_type === "node_revoke") {
      throw new Error(
        "NodeLifecycleEventLog.append: node_revoke events must use appendRevoke (authorization-keyed retention)"
      );
    }
    const key = this.nonRevokeKey(evt);
    if (this.nonRevokeKeys.has(key)) return;
    // Per-emitter quota (rule 8's per-origin quota): a full bucket evicts the
    // FLOODING emitter's own oldest event, never another emitter's — one
    // in-roster emitter must not be able to erase its neighbors' history
    // through global oldest-first eviction pressure.
    const bucket = this.nonRevokeByEmitter.get(evt.emitter_node) ?? [];
    while (bucket.length >= MAX_RETAINED_NON_REVOKE_EVENTS_PER_EMITTER) {
      const oldest = bucket[0];
      const idx = this.events.indexOf(oldest);
      if (idx !== -1) this.events.splice(idx, 1);
      this.forgetIndexed(oldest); // also shifts it out of this bucket
    }
    this.nonRevokeKeys.add(key);
    bucket.push(evt);
    this.nonRevokeByEmitter.set(evt.emitter_node, bucket);
    this.events.push(evt);
    this.enforceCap();
  }

  /**
   * True iff an accepted revoke carrying this authorization key is already
   * retained. The caller uses this to distinguish a first admission (append)
   * from a same-authorization replay (drop-if-still-revoked / refuse-if-live).
   */
  hasRetainedRevokeAuthorization(authKey: string): boolean {
    return this.revokeByAuth.has(authKey);
  }

  /**
   * Append a VERIFIED, AUTHORIZED, first-seen revoke. Caller guarantees
   * `hasRetainedRevokeAuthorization(authKey)` was false (a duplicate is dropped
   * or refused by the caller, never re-appended here). Enforces the per-target
   * authorization quota by EVICTING THE OLDEST authorization for that target,
   * never blocking the newest.
   */
  appendRevoke(
    evt: SignedEvent<NodeLifecyclePayload>,
    params: { target_node_id: string; authorization_key: string }
  ): void {
    const { target_node_id: target, authorization_key: authKey } = params;
    if (this.revokeByAuth.has(authKey)) {
      // Defense in depth: the caller already checked, but never silently
      // append a second row for the same authorization.
      return;
    }
    const auths = this.revokeAuthsByTarget.get(target) ?? [];
    // Evict-oldest to honor the per-target quota. The newest authorization's
    // entry is the ordering witness a late joiner needs; blocking it would
    // leave a legitimate post-rejoin revoke unretained while older entries sit
    // before the rejoin in log order (the RG3-1 divergence through the quota).
    while (auths.length >= MAX_RETAINED_REVOKE_AUTHORIZATIONS_PER_TARGET) {
      const oldest = auths.shift();
      if (oldest === undefined) break;
      this.dropRetainedRevoke(oldest);
    }
    this.revokeByAuth.set(authKey, evt);
    auths.push(authKey);
    this.revokeAuthsByTarget.set(target, auths);
    this.events.push(evt);
    this.enforceCap();
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

  private nonRevokeKey(evt: SignedEvent<NodeLifecyclePayload>): string {
    return `${evt.emitter_node} ${evt.event_id}`;
  }

  /**
   * Enforce the global cap. Evict OLDEST NON-REVOKE first; a revoke is evicted
   * only when the log holds nothing but revokes (degrades to "learn via a peer
   * with a longer log", never to un-revoking — the roster is authoritative).
   */
  private enforceCap(): void {
    while (this.events.length > NODE_LIFECYCLE_LOG_MAX_EVENTS) {
      let evictIdx = this.events.findIndex(
        (e) => e.event_type !== "node_revoke"
      );
      if (evictIdx === -1) evictIdx = 0; // only revokes remain
      const [removed] = this.events.splice(evictIdx, 1);
      if (removed) this.forgetIndexed(removed);
    }
  }

  /** Remove a retained revoke from the events array and every index. */
  private dropRetainedRevoke(authKey: string): void {
    const evt = this.revokeByAuth.get(authKey);
    if (!evt) return;
    const idx = this.events.indexOf(evt);
    if (idx !== -1) this.events.splice(idx, 1);
    this.forgetIndexed(evt, authKey);
  }

  /** Drop index entries for an evicted event (revoke or non-revoke). */
  private forgetIndexed(
    evt: SignedEvent<NodeLifecyclePayload>,
    knownAuthKey?: string
  ): void {
    if (evt.event_type !== "node_revoke") {
      this.nonRevokeKeys.delete(this.nonRevokeKey(evt));
      const bucket = this.nonRevokeByEmitter.get(evt.emitter_node);
      if (bucket) {
        const i = bucket.indexOf(evt);
        if (i !== -1) bucket.splice(i, 1);
        if (bucket.length === 0) this.nonRevokeByEmitter.delete(evt.emitter_node);
      }
      return;
    }
    let authKey = knownAuthKey;
    if (authKey === undefined) {
      for (const [k, v] of this.revokeByAuth) {
        if (v === evt) {
          authKey = k;
          break;
        }
      }
    }
    if (authKey === undefined) return;
    this.revokeByAuth.delete(authKey);
    const payload = evt.payload as { node_id?: string };
    const target = payload.node_id;
    if (target !== undefined) {
      const auths = this.revokeAuthsByTarget.get(target);
      if (auths) {
        const i = auths.indexOf(authKey);
        if (i !== -1) auths.splice(i, 1);
        if (auths.length === 0) this.revokeAuthsByTarget.delete(target);
      }
    }
  }
}
