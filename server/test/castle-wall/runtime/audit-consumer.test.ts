/**
 * Castle Wall audit consumer tests.
 *
 * Verifies layer enforcement, event-type validation, ACK after persist,
 * and metric-batch passthrough.
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  ACCEPTED_EVENT_TYPES,
  AuditConsumer,
  validateEvent,
  type AuditSink,
} from "../../../src/castle-wall/runtime/audit-consumer.js";
import { buildAuditEvent } from "../../../src/castle-wall/audit/builder.js";
import { CASTLE_WALL_AUDIT_LAYER } from "../../../src/castle-wall/constants.js";
import type { CastleWallAuditEvent } from "../../../src/castle-wall/audit/events.js";

class RecordingSink implements AuditSink {
  entries: Array<{
    layer: "l1";
    operation: string;
    identityId: string;
    details?: Record<string, unknown>;
    result: "success" | "failure";
  }> = [];
  flushedCount = 0;
  append(
    layer: "l1",
    operation: string,
    identityId: string,
    details?: Record<string, unknown>,
    result: "success" | "failure" = "success"
  ): void {
    this.entries.push({ layer, operation, identityId, details, result });
  }
  async flush(): Promise<void> {
    this.flushedCount += 1;
  }
}

describe("castle-wall/runtime/audit-consumer : validateEvent", () => {
  it("accepts a well-formed l1 event", () => {
    const event = buildAuditEvent({
      timestamp: "2026-05-04T00:00:00Z",
      fortress_id: "f",
      event_type: "egress_blocked",
    });
    expect(validateEvent(event)).toBeNull();
  });

  it("rejects events with the wrong layer", () => {
    const event: CastleWallAuditEvent = {
      ...buildAuditEvent({
        timestamp: "2026-05-04T00:00:00Z",
        fortress_id: "f",
        event_type: "egress_blocked",
      }),
      // simulate a faulty daemon
      layer: "l2" as unknown as typeof CASTLE_WALL_AUDIT_LAYER,
    };
    expect(validateEvent(event)).toMatch(/unexpected layer/);
  });

  it("rejects events with unknown event_type", () => {
    const event = {
      ...buildAuditEvent({
        timestamp: "2026-05-04T00:00:00Z",
        fortress_id: "f",
        event_type: "egress_blocked",
      }),
      event_type: "rogue" as unknown as CastleWallAuditEvent["event_type"],
    } as CastleWallAuditEvent;
    expect(validateEvent(event)).toMatch(/unknown event_type/);
  });

  it("rejects events with empty fortress_id", () => {
    const event = buildAuditEvent({
      timestamp: "2026-05-04T00:00:00Z",
      fortress_id: "",
      event_type: "egress_blocked",
    });
    expect(validateEvent(event)).toMatch(/missing fortress_id/);
  });

  it("ACCEPTED_EVENT_TYPES set is non-empty and includes core types", () => {
    expect(ACCEPTED_EVENT_TYPES.has("egress_blocked")).toBe(true);
    expect(ACCEPTED_EVENT_TYPES.has("operator_decision")).toBe(true);
    expect(ACCEPTED_EVENT_TYPES.has("queue_saturated")).toBe(true);
  });
});

describe("castle-wall/runtime/audit-consumer : ingestCritical", () => {
  let sink: RecordingSink;
  let consumer: AuditConsumer;

  beforeEach(() => {
    sink = new RecordingSink();
    consumer = new AuditConsumer(sink);
  });

  it("appends + flushes + ACKs in order on a valid event", async () => {
    const event = buildAuditEvent({
      timestamp: "2026-05-04T00:00:00Z",
      fortress_id: "f",
      event_type: "egress_allowed",
      destination: { host: "example.com", ip: "1.2.3.4", port: 443, protocol: "tcp" },
      decision: "allow_once",
      rule_id: "r1",
    });
    let acked = false;
    await consumer.ingestCritical({
      event,
      ack: async () => {
        acked = true;
      },
    });
    expect(sink.entries.length).toBe(1);
    expect(sink.entries[0]!.operation).toBe("egress_allowed");
    expect(sink.flushedCount).toBe(1);
    expect(acked).toBe(true);
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
  });

  it("ACKs malformed events with a failure entry, not a re-delivery loop", async () => {
    const event = buildAuditEvent({
      timestamp: "2026-05-04T00:00:00Z",
      fortress_id: "f",
      event_type: "egress_allowed",
    });
    const tampered = {
      ...event,
      event_type: "rogue" as unknown as CastleWallAuditEvent["event_type"],
    } as CastleWallAuditEvent;
    let acked = false;
    await consumer.ingestCritical({
      event: tampered,
      ack: async () => {
        acked = true;
      },
    });
    expect(sink.entries.length).toBe(1);
    expect(sink.entries[0]!.operation).toBe("audit_event_rejected");
    expect(sink.entries[0]!.result).toBe("failure");
    expect(acked).toBe(true);
    expect(consumer.getStats().rejectedEvents).toBe(1);
  });

  it("flattens agent + destination + decision + rule_id into details", async () => {
    const event = buildAuditEvent({
      timestamp: "2026-05-04T00:00:00Z",
      fortress_id: "f",
      event_type: "egress_blocked",
      agent: { id: "a", template: "t" },
      destination: { host: "h", ip: "1", port: 1, protocol: "tcp" },
      decision: "deny_once",
      rule_id: "r",
    });
    await consumer.ingestCritical({ event, ack: async () => {} });
    const details = sink.entries[0]!.details!;
    expect(details.agent).toEqual({ id: "a", template: "t" });
    expect(details.destination).toEqual({
      host: "h",
      ip: "1",
      port: 1,
      protocol: "tcp",
    });
    expect(details.decision).toBe("deny_once");
    expect(details.rule_id).toBe("r");
  });
});

describe("castle-wall/runtime/audit-consumer : ingestMetricBatch", () => {
  it("appends one entry per batch with the right operation tag", () => {
    const sink = new RecordingSink();
    const consumer = new AuditConsumer(sink);
    consumer.ingestMetricBatch("f", {
      windowStart: "t1",
      windowEnd: "t2",
      byDestination: [
        {
          host: "h",
          port: 443,
          protocol: "tcp",
          agent_id: "a",
          allowed_count: 5,
          blocked_count: 1,
        },
      ],
    });
    expect(sink.entries.length).toBe(1);
    expect(sink.entries[0]!.operation).toBe("egress_metric_batch");
    expect(consumer.getStats().acceptedMetricBatches).toBe(1);
  });
});
