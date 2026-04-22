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

/**
 * Per-agent policy bundle. Holds only the highest-version signed policy
 * event seen for each agent_id. Older versions are dropped on update.
 */
export class PolicyBundleStore {
  private byAgent = new Map<string, SignedEvent<PolicyUpdatePayload>>();

  upsert(evt: SignedEvent<PolicyUpdatePayload>): "applied" | "older" {
    const existing = this.byAgent.get(evt.payload.agent_id);
    if (
      existing &&
      existing.payload.policy_version >= evt.payload.policy_version
    ) {
      return "older";
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
   * Delta query for sync replies — return every event whose policy_version
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
