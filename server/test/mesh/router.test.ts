import { describe, expect, it, vi } from "vitest";
import { MeshRouter } from "../../src/mesh/router.js";
import type { SignedEvent } from "../../src/mesh/types.js";

function makeEvent(eventType: string, payload: unknown = {}): SignedEvent {
  return {
    protocol_version: "0.1",
    event_type: eventType,
    event_id: `evt-${eventType}`,
    emitter_node: "node-1",
    emitter_principal: "system",
    fortress_id: "fortress-1",
    causal_parents: [],
    payload,
    payload_hash: "payload-hash",
    emitted_at: "2026-06-09T00:00:00.000Z",
    monotonic_seq: 1,
    extension_envelope: {},
    node_signature: "node-signature",
  };
}

describe("mesh/router : registration", () => {
  it("rejects non-v0.1 event types at registration time", () => {
    const router = new MeshRouter();

    expect(() => router.register("cross_fortress_read_query", vi.fn())).toThrow(
      "MeshRouter.register: cross_fortress_read_query is not a v0.1 event type",
    );
    expect(() => router.register("not_in_protocol", vi.fn())).toThrow(
      "MeshRouter.register: not_in_protocol is not a v0.1 event type",
    );
    expect(router.stats()).toEqual({
      dispatched: 0,
      dropped_reserved: 0,
      dropped_unknown: 0,
    });
  });

  it("keeps the latest handler when a v0.1 event type is registered twice", () => {
    const router = new MeshRouter();
    const first = vi.fn();
    const second = vi.fn();

    router.register("heartbeat", first);
    router.register("heartbeat", second);

    expect(router.dispatch(makeEvent("heartbeat"))).toBe(true);
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledOnce();
    expect(router.stats()).toEqual({
      dispatched: 1,
      dropped_reserved: 0,
      dropped_unknown: 0,
    });
  });
});

describe("mesh/router : dispatch", () => {
  it("dispatches registered v0.1 events and returns true", () => {
    const router = new MeshRouter();
    const handler = vi.fn();
    const event = makeEvent("policy_update", { policy_version: 3 });

    router.register("policy_update", handler);

    expect(router.dispatch(event)).toBe(true);
    expect(handler).toHaveBeenCalledWith(event);
    expect(router.stats()).toEqual({
      dispatched: 1,
      dropped_reserved: 0,
      dropped_unknown: 0,
    });
  });

  it("drops reserved event type prefixes before handler lookup", () => {
    const router = new MeshRouter();
    const handler = vi.fn();
    router.register("heartbeat", handler);

    expect(router.dispatch(makeEvent("EXTENSION_future_event"))).toBe(false);
    expect(router.dispatch(makeEvent("cross_harness_approval_created"))).toBe(false);
    expect(handler).not.toHaveBeenCalled();
    expect(router.stats()).toEqual({
      dispatched: 0,
      dropped_reserved: 2,
      dropped_unknown: 0,
    });
  });

  it("drops unregistered non-reserved event types as unknown", () => {
    const router = new MeshRouter();

    expect(router.dispatch(makeEvent("future_unreserved_event"))).toBe(false);
    expect(router.stats()).toEqual({
      dispatched: 0,
      dropped_reserved: 0,
      dropped_unknown: 1,
    });
  });
});
