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
 */
export class NodeLifecycleEventLog {
  private events: SignedEvent<NodeLifecyclePayload>[] = [];

  append(evt: SignedEvent<NodeLifecyclePayload>): void {
    this.events.push(evt);
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
