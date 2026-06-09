import { describe, expect, it } from "vitest";

import {
  InMemoryTransport,
  type MessageSerialized,
} from "../../src/mesh/in-memory-transport.js";
import type { SignedEvent } from "../../src/mesh/types.js";

describe("InMemoryTransport dispatch contract", () => {
  it("broadcasts synchronously in attach and subscription order without self-delivery", async () => {
    const hub = new InMemoryTransport();
    const sender = hub.attach("node-a");
    const firstPeer = hub.attach("node-b");
    const secondPeer = hub.attach("node-c");
    const calls: string[] = [];
    const deliveredEvents: SignedEvent[] = [];
    const wireBytes: string[] = [];

    sender.subscribe(() => calls.push("sender:self"));
    firstPeer.subscribe((evt, wire) => {
      calls.push("node-b:first");
      deliveredEvents.push(evt);
      wireBytes.push(wire);
      (evt.payload as Record<string, unknown>).mutated_by = "node-b:first";
    });
    firstPeer.subscribe((evt, wire) => {
      calls.push("node-b:second");
      deliveredEvents.push(evt);
      wireBytes.push(wire);
    });
    secondPeer.subscribe((evt, wire) => {
      calls.push("node-c:first");
      deliveredEvents.push(evt);
      wireBytes.push(wire);
    });

    await sender.broadcast(signedEvent("event-1", { value: "original" }));

    expect(calls).toEqual(["node-b:first", "node-b:second", "node-c:first"]);
    expect(wireBytes).toHaveLength(3);
    expect(new Set(wireBytes).size).toBe(1);
    expect(deliveredEvents[0]).not.toBe(deliveredEvents[1]);
    expect(deliveredEvents[0]).not.toBe(deliveredEvents[2]);
    expect(deliveredEvents[1].payload).toEqual({ value: "original" });
    expect(deliveredEvents[2].payload).toEqual({ value: "original" });
  });

  it("unicast delivers only to the addressed peer and rejects unknown targets", async () => {
    const hub = new InMemoryTransport();
    const sender = hub.attach("node-a");
    const target = hub.attach("node-b");
    const bystander = hub.attach("node-c");
    const delivered: Array<{ target: string; message: MessageSerialized }> = [];

    target.subscribeUnicast((toNodeId, message) => {
      delivered.push({ target: toNodeId, message });
    });
    bystander.subscribeUnicast((toNodeId, message) => {
      delivered.push({ target: toNodeId, message: `bystander:${message}` });
    });

    await sender.unicast("node-b", "payload-1");

    expect(delivered).toEqual([{ target: "node-b", message: "payload-1" }]);
    await expect(sender.unicast("node-missing", "payload-2")).rejects.toThrow(
      "unknown unicast target node-missing",
    );
  });

  it("unsubscribe removes a handler for subsequent broadcasts", async () => {
    const hub = new InMemoryTransport();
    const sender = hub.attach("node-a");
    const target = hub.attach("node-b");
    const calls: string[] = [];
    const unsubscribe = target.subscribe((evt) => {
      calls.push(evt.event_id);
    });

    await sender.broadcast(signedEvent("event-before-unsubscribe"));
    unsubscribe();
    await sender.broadcast(signedEvent("event-after-unsubscribe"));

    expect(calls).toEqual(["event-before-unsubscribe"]);
  });
});

function signedEvent(
  eventId: string,
  payload: Record<string, unknown> = {},
): SignedEvent {
  return {
    event_id: eventId,
    event_type: "policy_update",
    payload,
    emitted_at: "2026-06-09T12:00:00.000Z",
    emitter_node: "node-a",
    signature_scheme: "ed25519-v1",
    signature: "sig",
  } as unknown as SignedEvent;
}
