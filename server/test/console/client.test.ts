/**
 * MeshConsoleClient — unit tests for the thin federation-protocol adapter.
 *
 * Covers:
 *   - AC5 (three-layer attestation badges): deterministic class names per
 *     layer × state.
 *   - AC7 (reserved namespaces honored): outbound surface guards reject
 *     every reserved extension key, capability bit, and event-type prefix.
 *   - Navigation + MSP v1.x reservation (scope item 5).
 */

import { describe, expect, it } from "vitest";

import {
  MeshConsoleClient,
  badgeClassName,
  custodyProvenanceStub,
  globalBadge,
  isReservedMeshSurface,
  perActionBadge,
  perAgentBadge,
  rollupGlobal,
  sanityCheckReservations,
  MeshConsoleReservedSurfaceError,
  MeshConsoleUnknownEventTypeError,
  CONSOLE_SURFACES,
  RESERVED_V1X_SURFACES,
  FEDERATION_NODE_JOIN_OPERATION,
} from "../../src/console/index.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
  RESERVED_EVENT_TYPE_PREFIXES,
  RESERVED_EXTENSION_ENVELOPE_KEYS,
} from "../../src/mesh/constants.js";

describe("AttestationBadge three-layer surface (AC5)", () => {
  it("emits deterministic class names for every (layer, state) combination", () => {
    const layers = [
      "global",
      "per-agent",
      "per-action",
      "custody-provenance-stub",
    ] as const;
    const states = ["verified", "pending", "degraded", "failed", "unknown"] as const;
    for (const layer of layers) {
      for (const state of states) {
        const cls = badgeClassName(layer, state);
        expect(cls).toBe(`att-badge att-${layer}-${state}`);
      }
    }
  });

  it("global / per-agent / per-action factories produce the matching layer/state", () => {
    expect(globalBadge("verified").layer).toBe("global");
    expect(globalBadge("verified").state).toBe("verified");
    expect(perAgentBadge("pending").layer).toBe("per-agent");
    expect(perAgentBadge("pending").state).toBe("pending");
    expect(perActionBadge("failed").layer).toBe("per-action");
    expect(perActionBadge("failed").state).toBe("failed");
  });

  it("custody-provenance stub is reserved for v1.x and carries the v1.x affordance class", () => {
    const stub = custodyProvenanceStub();
    expect(stub.layer).toBe("custody-provenance-stub");
    expect(stub.class_name).toContain("att-v1x-reserved");
    expect(stub.label).toContain("v1.x");
  });

  it("rollupGlobal propagates failure > degraded > pending > verified > unknown", () => {
    expect(rollupGlobal([])).toBe("unknown");
    expect(rollupGlobal(["verified", "verified"])).toBe("verified");
    expect(rollupGlobal(["verified", "pending"])).toBe("pending");
    expect(rollupGlobal(["verified", "degraded", "pending"])).toBe("degraded");
    expect(rollupGlobal(["verified", "degraded", "failed"])).toBe("failed");
  });
});

describe("Reserved-namespace enforcement (AC7)", () => {
  it("rejects reserved extension-envelope keys", () => {
    for (const key of RESERVED_EXTENSION_ENVELOPE_KEYS) {
      const result = isReservedMeshSurface({ extension_keys: [key] });
      expect(result.reserved).toBe(true);
      expect(result.reason).toContain("reserved");
    }
  });

  it("rejects reserved event_type prefixes", () => {
    for (const prefix of RESERVED_EVENT_TYPE_PREFIXES) {
      const candidate = `${prefix}some_event`;
      const result = isReservedMeshSurface({ event_type: candidate });
      expect(result.reserved).toBe(true);
    }
  });

  it("rejects reserved capability bits (3-31)", () => {
    const reserved_bit_3 = 1 << 3;
    const result = isReservedMeshSurface({ capabilities: reserved_bit_3 });
    expect(result.reserved).toBe(true);
  });

  it("accepts v0.1-permitted capability mask", () => {
    const result = isReservedMeshSurface({
      capabilities: CAP_STANDARD_FORTRESS_NODE,
    });
    expect(result.reserved).toBe(false);
  });

  it("accepts a v0.1 event_type (audit_batch)", () => {
    expect(isReservedMeshSurface({ event_type: "audit_batch" }).reserved).toBe(false);
  });

  it("sanity-check asserts spec §10 tuples are non-empty", () => {
    expect(() => sanityCheckReservations()).not.toThrow();
  });
});

describe("MeshConsoleClient — navigation + federation-node-join Tier 1", () => {
  it("navigation lists all six active surfaces + reserved v1.x surfaces disabled", () => {
    const client = { listNavigation: MeshConsoleClient.prototype.listNavigation.bind({}) };
    const nav = client.listNavigation();
    for (const surface of CONSOLE_SURFACES) {
      const item = nav.find((n) => n.id === surface);
      expect(item).toBeTruthy();
      expect(item?.enabled).toBe(true);
    }
    for (const reserved of RESERVED_V1X_SURFACES) {
      const item = nav.find((n) => n.id === reserved);
      expect(item).toBeTruthy();
      expect(item?.enabled).toBe(false);
    }
  });

  it("exposes the Tier 1 operation name so the policy loader can register it", () => {
    expect(MeshConsoleClient.federationJoinOperation()).toBe(
      FEDERATION_NODE_JOIN_OPERATION
    );
    expect(FEDERATION_NODE_JOIN_OPERATION).toBe("federation_node_join");
  });
});

describe("MeshConsoleClient — error types", () => {
  it("MeshConsoleReservedSurfaceError names itself", () => {
    const err = new MeshConsoleReservedSurfaceError("bad", { foo: "bar" });
    expect(err.name).toBe("MeshConsoleReservedSurfaceError");
    expect(err.message).toContain("bad");
  });

  it("MeshConsoleUnknownEventTypeError carries the eventType", () => {
    const err = new MeshConsoleUnknownEventTypeError("not_real");
    expect(err.name).toBe("MeshConsoleUnknownEventTypeError");
    expect(err.eventType).toBe("not_real");
  });
});
