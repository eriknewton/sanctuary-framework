import { describe, expect, it } from "vitest";

import {
  LocatorTableStore,
  NodeLifecycleEventLog,
  PolicyBundleStore,
} from "../../src/mesh/lifecycle/local-state.js";
import type {
  LocatorUpdatePayload,
  NodeLifecyclePayload,
  PolicyUpdatePayload,
  SignedEvent,
} from "../../src/mesh/types.js";

describe("mesh lifecycle local replicated state", () => {
  it("keeps the highest policy version per agent and returns strict deltas", () => {
    const store = new PolicyBundleStore();
    const v1 = policyEvent("agent-a", 1);
    const v2 = policyEvent("agent-a", 2);
    const other = policyEvent("agent-b", 4);

    expect(store.upsert(v2)).toBe("applied");
    expect(store.upsert(v1)).toBe("policy_version_replay");
    expect(store.upsert(other)).toBe("applied");

    expect(store.get("agent-a")).toBe(v2);
    expect(store.versionOf("agent-a")).toBe(2);
    expect(store.versionOf("missing")).toBe(0);
    expect(store.versionVector()).toEqual({ "agent-a": 2, "agent-b": 4 });
    expect(store.delta({ "agent-a": 2, "agent-b": 3 })).toEqual([other]);
    expect(store.snapshot()).toEqual([v2, other]);
    expect(store.size()).toBe(2);
  });

  it("audits lower-version policy bundle replays without replacing the current bundle", () => {
    const auditEvents: unknown[] = [];
    const store = new PolicyBundleStore({
      onAuditEvent: (event) => auditEvents.push(event),
    });
    const v2 = policyEvent("agent-a", 2);
    const v1 = policyEvent("agent-a", 1);

    expect(store.upsert(v2)).toBe("applied");
    expect(store.upsert(v1)).toBe("policy_version_replay");

    expect(store.get("agent-a")).toBe(v2);
    expect(store.auditEvents()).toHaveLength(1);
    expect(auditEvents).toHaveLength(1);
    expect(store.auditEvents()[0]).toMatchObject({
      operation: "mesh_policy_bundle_rejected",
      agent_id: "agent-a",
      reason: "policy_version_replay",
      incoming_policy_version: 1,
      current_policy_version: 2,
    });
  });

  it("rejects policy bundles outside their signed validity window", () => {
    const store = new PolicyBundleStore({
      now: () => new Date("2026-06-09T12:00:00.000Z"),
    });
    const expired = policyEvent("agent-a", 2, {
      valid_from: "2026-06-01T00:00:00.000Z",
      valid_until: "2026-06-09T12:00:00.000Z",
    });
    const missingWindow = event("policy-missing-window", "policy_update", {
      agent_id: "agent-a",
      policy_version: 3,
      policy_blob: "policy-3",
    } as PolicyUpdatePayload);

    expect(store.upsert(expired)).toBe("policy_expired");
    expect(store.upsert(missingWindow)).toBe("policy_validity_missing");
    expect(store.get("agent-a")).toBeUndefined();
    expect(store.auditEvents().map((event) => event.reason)).toEqual([
      "policy_expired",
      "policy_validity_missing",
    ]);
  });

  it("detects locator conflicts at the same version and advances only newer versions", () => {
    const store = new LocatorTableStore();
    const v1 = locatorEvent("agent-a", 1, "node-a");
    const conflict = locatorEvent("agent-a", 1, "node-b");
    const same = locatorEvent("agent-a", 1, "node-a");
    const v3 = locatorEvent("agent-a", 3, "node-c");
    const other = locatorEvent("agent-b", 2, "node-b");

    expect(store.upsert(v1)).toBe("applied");
    expect(store.upsert(conflict)).toBe("conflict");
    expect(store.upsert(same)).toBe("older");
    expect(store.upsert(other)).toBe("applied");
    expect(store.upsert(v3)).toBe("applied");

    expect(store.get("agent-a")).toBe(v3);
    expect(store.highest()).toBe(3);
    expect(store.delta(1)).toEqual([v3, other]);
    expect(store.snapshot()).toEqual([v3, other]);
    expect(store.size()).toBe(2);
  });

  it("returns lifecycle events after a known id and the full log for unknown baselines", () => {
    const log = new NodeLifecycleEventLog();
    const first = lifecycleEvent("evt-1", { node_id: "node-a", reason: "graceful" });
    const second = lifecycleEvent("evt-2", { node_id: "node-b", reason: "operator_directed" });
    const third = lifecycleEvent("evt-3", { node_id: "node-c", reason: "graceful" });

    log.append(first);
    log.append(second);
    log.append(third);

    expect(log.since(undefined)).toEqual([first, second, third]);
    expect(log.since("evt-1")).toEqual([second, third]);
    expect(log.since("evt-3")).toEqual([]);
    expect(log.since("missing")).toEqual([first, second, third]);
    expect(log.snapshot()).toEqual([first, second, third]);
    expect(log.size()).toBe(3);
  });
});

function policyEvent(
  agentId: string,
  policyVersion: number,
  window: Pick<PolicyUpdatePayload, "valid_from" | "valid_until"> = {
    valid_from: "2026-06-01T00:00:00.000Z",
    valid_until: "2099-01-01T00:00:00.000Z",
  },
): SignedEvent<PolicyUpdatePayload> {
  return event(`policy-${agentId}-${policyVersion}`, "policy_update", {
    agent_id: agentId,
    policy_version: policyVersion,
    ...window,
    policy_blob: `policy-${policyVersion}`,
  });
}

function locatorEvent(
  agentId: string,
  locatorVersion: number,
  canonicalNode: string,
): SignedEvent<LocatorUpdatePayload> {
  return event(`locator-${agentId}-${locatorVersion}-${canonicalNode}`, "locator_update", {
    agent_id: agentId,
    canonical_node: canonicalNode,
    locator_version: locatorVersion,
    last_migration_at: "2026-06-09T12:00:00.000Z",
    hosting_principal: "principal-a",
  });
}

function lifecycleEvent(
  eventId: string,
  payload: Extract<NodeLifecyclePayload, { node_id: string }>,
): SignedEvent<NodeLifecyclePayload> {
  return event(eventId, "node_leave", payload);
}

function event<Payload>(
  eventId: string,
  eventType: string,
  payload: Payload,
): SignedEvent<Payload> {
  return {
    protocol_version: "0.1",
    event_type: eventType,
    event_id: eventId,
    emitter_node: "node-a",
    emitter_principal: "principal-a",
    fortress_id: "fortress-a",
    causal_parents: [],
    payload,
    payload_hash: `hash-${eventId}`,
    emitted_at: "2026-06-09T12:00:00.000Z",
    monotonic_seq: 1,
    extension_envelope: {},
    node_signature: `node-sig-${eventId}`,
    principal_signature: `principal-sig-${eventId}`,
  };
}
