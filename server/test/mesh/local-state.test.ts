import { describe, expect, it } from "vitest";

import {
  LocatorTableStore,
  MAX_LOCATOR_TABLE_ENTRIES,
  MAX_LIFECYCLE_LOG_ENTRIES,
  NodeLifecycleEventLog,
  PolicyBundleStore,
} from "../../src/mesh/lifecycle/local-state.js";
import { encodePolicyBlob } from "../../src/policy-engine/canonical-policy.js";
import type {
  LocatorUpdatePayload,
  NodeLifecyclePayload,
  PolicyUpdatePayload,
  SignedEvent,
} from "../../src/mesh/types.js";
import type { CompiledPolicy } from "../../src/policy-engine/types.js";

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

  it("rejects and audits malformed runtime policy_version values before comparison", () => {
    const auditEvents: unknown[] = [];
    const store = new PolicyBundleStore({
      onAuditEvent: (event) => auditEvents.push(event),
    });
    const valid = policyEvent("agent-a", 2);

    expect(store.upsert(valid)).toBe("applied");

    const malformedVersions: unknown[] = ["x", Number.NaN, -1, 1.5];
    for (const version of malformedVersions) {
      const malformed = event("policy-malformed", "policy_update", {
        agent_id: "agent-a",
        policy_version: version,
        valid_from: "2026-06-01T00:00:00.000Z",
        valid_until: "2099-01-01T00:00:00.000Z",
        policy_blob: "policy-malformed",
      } as unknown as PolicyUpdatePayload);
      expect(store.upsert(malformed)).toBe("policy_payload_malformed");
    }

    expect(store.get("agent-a")).toBe(valid);
    expect(store.auditEvents()).toHaveLength(4);
    expect(auditEvents).toHaveLength(4);
    expect(store.auditEvents().map((event) => event.reason)).toEqual([
      "policy_payload_malformed",
      "policy_payload_malformed",
      "policy_payload_malformed",
      "policy_payload_malformed",
    ]);
    expect(store.auditEvents().map((event) => event.incoming_policy_version)).toEqual(
      malformedVersions,
    );
  });

  it("rejects fresh policy headers whose compiled blob replays mismatched identity or version fields", () => {
    const store = new PolicyBundleStore();
    const current = policyEvent("agent-a", 1);

    expect(store.upsert(current)).toBe("applied");

    const mismatchedBlobCases = [
      event("policy-agent-mismatch", "policy_update", {
        agent_id: "agent-a",
        policy_version: 2,
        parent_version: 1,
        valid_from: "2026-06-01T00:00:00.000Z",
        valid_until: "2099-01-01T00:00:00.000Z",
        policy_blob: policyBlob("agent-b", 2, { parentVersion: 1 }),
      }),
      event("policy-version-mismatch", "policy_update", {
        agent_id: "agent-a",
        policy_version: 2,
        parent_version: 1,
        valid_from: "2026-06-01T00:00:00.000Z",
        valid_until: "2099-01-01T00:00:00.000Z",
        policy_blob: policyBlob("agent-a", 1),
      }),
      event("policy-parent-mismatch", "policy_update", {
        agent_id: "agent-a",
        policy_version: 2,
        parent_version: 1,
        valid_from: "2026-06-01T00:00:00.000Z",
        valid_until: "2099-01-01T00:00:00.000Z",
        policy_blob: policyBlob("agent-a", 2, { parentVersion: 0 }),
      }),
    ] satisfies SignedEvent<PolicyUpdatePayload>[];

    for (const mismatched of mismatchedBlobCases) {
      expect(store.upsert(mismatched)).toBe("policy_payload_malformed");
    }

    expect(store.get("agent-a")).toBe(current);
    expect(store.auditEvents().map((event) => event.reason)).toEqual([
      "policy_payload_malformed",
      "policy_payload_malformed",
      "policy_payload_malformed",
    ]);
  });

  it("detects locator conflicts at the same version and advances only newer versions", () => {
    // Every fixture below is a self-consistent claim (emitter_node ===
    // canonical_node, emitter_principal === hosting_principal) so this test
    // exercises version/conflict resolution ONLY -- see the
    // "MESH-LOCATOR-01" describe block below for the authority-binding
    // check itself.
    const store = new LocatorTableStore();
    const v1 = locatorEvent("agent-a", 1, "node-a", { selfHost: true });
    const conflict = locatorEvent("agent-a", 1, "node-b", { selfHost: true });
    const same = locatorEvent("agent-a", 1, "node-a", { selfHost: true });
    const v3 = locatorEvent("agent-a", 3, "node-c", { selfHost: true });
    const other = locatorEvent("agent-b", 2, "node-b", { selfHost: true });

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

  describe("MESH-LOCATOR-01 - authority binding", () => {
    it("refuses a locator_update whose emitter does not match its claimed host, and audits the refusal", () => {
      const auditEvents: unknown[] = [];
      const store = new LocatorTableStore({
        onAuditEvent: (event) => auditEvents.push(event),
      });
      // "node-mal" (the fixture's fixed emitter_node/emitter_principal,
      // see event()) claims "node-victim"/"principal-victim" now hosts
      // agent-a -- a third-party claim it has no signature-bound
      // relationship to.
      const hijack = locatorEvent("agent-a", 1, "node-victim", {
        hostingPrincipal: "principal-victim",
      });

      expect(store.upsert(hijack)).toBe("locator_host_mismatch");
      expect(store.get("agent-a")).toBeUndefined();
      expect(store.size()).toBe(0);
      expect(store.auditEvents()).toHaveLength(1);
      expect(auditEvents).toHaveLength(1);
      expect(store.auditEvents()[0]).toMatchObject({
        operation: "mesh_locator_update_rejected",
        agent_id: "agent-a",
        reason: "locator_host_mismatch",
        emitter_node: "node-a",
        emitter_principal: "principal-a",
        claimed_canonical_node: "node-victim",
        claimed_hosting_principal: "principal-victim",
      });
    });

    it("applies a legitimate self-hosted update from the same fixture", () => {
      const store = new LocatorTableStore();
      const selfHosted = locatorEvent("agent-a", 1, "node-a", { selfHost: true });

      expect(store.upsert(selfHosted)).toBe("applied");
      expect(store.get("agent-a")).toBe(selfHosted);
    });

    it("refuses a locator_update whose principal does not match its claimed host, even when the node does", () => {
      const store = new LocatorTableStore();
      const principalMismatch = locatorEvent("agent-a", 1, "node-a", {
        hostingPrincipal: "principal-not-mine",
      });

      expect(store.upsert(principalMismatch)).toBe("locator_host_mismatch");
      expect(store.get("agent-a")).toBeUndefined();
    });

    it("bounds distinct agent_ids at MAX_LOCATOR_TABLE_ENTRIES via FIFO eviction of self-hosted entries, never an update to an existing agent_id", () => {
      const store = new LocatorTableStore();
      for (let i = 0; i < MAX_LOCATOR_TABLE_ENTRIES; i++) {
        expect(
          store.upsert(locatorEvent(`agent-${i}`, 1, "node-a", { selfHost: true }))
        ).toBe("applied");
      }
      expect(store.size()).toBe(MAX_LOCATOR_TABLE_ENTRIES);
      expect(store.get("agent-0")).toBeDefined();

      // One more DISTINCT agent_id evicts the oldest (agent-0).
      expect(
        store.upsert(
          locatorEvent(`agent-${MAX_LOCATOR_TABLE_ENTRIES}`, 1, "node-a", {
            selfHost: true,
          })
        )
      ).toBe("applied");
      expect(store.size()).toBe(MAX_LOCATOR_TABLE_ENTRIES);
      expect(store.get("agent-0")).toBeUndefined();
      expect(store.get(`agent-${MAX_LOCATOR_TABLE_ENTRIES}`)).toBeDefined();

      // An UPDATE to an existing (still-retained) agent_id never evicts
      // anything -- the map does not grow, so it must not shrink either.
      expect(
        store.upsert(locatorEvent("agent-1", 2, "node-a", { selfHost: true }))
      ).toBe("applied");
      expect(store.size()).toBe(MAX_LOCATOR_TABLE_ENTRIES);
      expect(store.get(`agent-${MAX_LOCATOR_TABLE_ENTRIES}`)).toBeDefined();
    });
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

  describe("MESH-SYNC-DOS-01 - append() dedup + bound", () => {
    it("append() is idempotent by event_id: a replayed/duplicate event is not double-applied", () => {
      const log = new NodeLifecycleEventLog();
      const evt = lifecycleEvent("evt-1", { node_id: "node-a", reason: "graceful" });

      expect(log.append(evt)).toBe(true);
      // Same event_id delivered again (broadcast + sync replaying the same
      // accepted event, or a peer replaying the identical signed envelope)
      // -- must be a no-op, not a second entry.
      expect(log.append(evt)).toBe(false);
      expect(log.append({ ...evt })).toBe(false);

      expect(log.size()).toBe(1);
      expect(log.snapshot()).toEqual([evt]);
    });

    it("bounds retained events at MAX_LIFECYCLE_LOG_ENTRIES via FIFO eviction, and stays dedup-correct across eviction", () => {
      const log = new NodeLifecycleEventLog();
      for (let i = 0; i < MAX_LIFECYCLE_LOG_ENTRIES; i++) {
        expect(
          log.append(
            lifecycleEvent(`evt-${i}`, { node_id: `node-${i}`, reason: "graceful" })
          )
        ).toBe(true);
      }
      expect(log.size()).toBe(MAX_LIFECYCLE_LOG_ENTRIES);

      // One more DISTINCT event evicts the oldest (evt-0).
      const overflow = lifecycleEvent(`evt-${MAX_LIFECYCLE_LOG_ENTRIES}`, {
        node_id: "node-overflow",
        reason: "graceful",
      });
      expect(log.append(overflow)).toBe(true);
      expect(log.size()).toBe(MAX_LIFECYCLE_LOG_ENTRIES);
      expect(log.snapshot().some((e) => e.event_id === "evt-0")).toBe(false);

      // evt-0's id was evicted from the dedup index too, so a LATER event
      // that happens to reuse it is treated as genuinely new, never
      // silently dropped as if it were still the original entry.
      const reusedId = lifecycleEvent("evt-0", {
        node_id: "node-reused",
        reason: "operator_directed",
      });
      expect(log.append(reusedId)).toBe(true);
    });
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
    policy_blob: policyBlob(agentId, policyVersion),
  });
}

function policyBlob(
  agentId: string,
  policyVersion: number,
  opts: { parentVersion?: number; fortressId?: string } = {},
): string {
  return encodePolicyBlob({
    schema_version: "0.1",
    agent_id: agentId,
    fortress_id: opts.fortressId ?? "fortress-a",
    policy_version: policyVersion,
    ...(opts.parentVersion !== undefined
      ? { parent_version: opts.parentVersion }
      : {}),
    slots: {
      memory: { slot: "memory", mode: "deny", grants: [] },
      credentials: { slot: "credentials", mode: "deny", grants: [] },
      plans: { slot: "plans", mode: "deny", grants: [] },
      outputs: { slot: "outputs", mode: "deny", grants: [] },
    },
    capabilities: {
      concordia_commitment_classes: [],
      honeypot_skill_ids: [],
      is_sentinel: false,
    },
    auto_trigger_ladder: {
      honeypot_auto_freeze: false,
      threshold_rule_action: "operator_approved",
      ml_anomaly_action: "operator_approved",
    },
    source_english: "fixture",
    compiled_at: "2026-06-09T12:00:00.000Z",
  } satisfies CompiledPolicy);
}

/**
 * `selfHost: true` makes the event's emitter (node-a/principal-a, `event()`'s
 * fixed defaults) equal `canonicalNode`/`hostingPrincipal` -- a legitimate
 * self-report that passes MESH-LOCATOR-01's authority check. Omitting it (the
 * default) keeps the fixed emitter fields, which is deliberately AUTHORITY-
 * MISMATCHED whenever `canonicalNode`/`hostingPrincipal` differ from
 * "node-a"/"principal-a" -- most non-authority tests in this file pass
 * `selfHost: true` for that reason; the authority tests deliberately don't.
 */
function locatorEvent(
  agentId: string,
  locatorVersion: number,
  canonicalNode: string,
  opts: { selfHost?: boolean; hostingPrincipal?: string } = {},
): SignedEvent<LocatorUpdatePayload> {
  const hostingPrincipal = opts.hostingPrincipal ?? "principal-a";
  return event(
    `locator-${agentId}-${locatorVersion}-${canonicalNode}`,
    "locator_update",
    {
      agent_id: agentId,
      canonical_node: canonicalNode,
      locator_version: locatorVersion,
      last_migration_at: "2026-06-09T12:00:00.000Z",
      hosting_principal: hostingPrincipal,
    },
    opts.selfHost
      ? { emitter_node: canonicalNode, emitter_principal: hostingPrincipal }
      : undefined
  );
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
  emitterOverrides?: { emitter_node?: string; emitter_principal?: string },
): SignedEvent<Payload> {
  return {
    protocol_version: "0.1",
    event_type: eventType,
    event_id: eventId,
    emitter_node: emitterOverrides?.emitter_node ?? "node-a",
    emitter_principal: emitterOverrides?.emitter_principal ?? "principal-a",
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
