/**
 * Castle Wall audit consumer tests.
 *
 * Verifies layer enforcement, event-type validation, ACK after persist,
 * and metric-batch passthrough.
 */

import { createHash } from "node:crypto";
import { describe, it, expect, beforeEach } from "vitest";

import {
  ACCEPTED_EVENT_TYPES,
  AuditChainError,
  AuditConsumer,
  validateEvent,
  type AuditSink,
} from "../../../src/castle-wall/runtime/audit-consumer.js";
import {
  buildAuditEvent,
  canonicalizeAuditEvent,
} from "../../../src/castle-wall/audit/builder.js";
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

class FaultingCriticalSink extends RecordingSink {
  async append(
    layer: "l1",
    operation: string,
    identityId: string,
    details?: Record<string, unknown>,
    result: "success" | "failure" = "success"
  ): Promise<void> {
    if (operation === "egress_allowed") {
      throw new Error("audit disk unavailable");
    }
    super.append(layer, operation, identityId, details, result);
  }
}

function eventHash(event: CastleWallAuditEvent): string {
  return createHash("sha256").update(canonicalizeAuditEvent(event), "utf8").digest("hex");
}

function chainedEvent(seq: number, prior_sha256_hex: string | null): CastleWallAuditEvent {
  return buildAuditEvent({
    timestamp: `2026-05-04T00:00:0${seq}Z`,
    fortress_id: "f",
    event_type: "egress_allowed",
    details: { seq, prior_sha256_hex },
  });
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
    expect(ACCEPTED_EVENT_TYPES.has("provider_unbound")).toBe(true);
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
      details: { seq: 0, prior_sha256_hex: null },
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
    expect(consumer.getWalChainState().lastAckedSeq).toBe(0);
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
      details: { seq: 0, prior_sha256_hex: null },
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

  it("rejects events with missing WAL chain fields", async () => {
    const event = buildAuditEvent({
      timestamp: "2026-05-04T00:00:00Z",
      fortress_id: "f",
      event_type: "egress_allowed",
    });

    await expect(consumer.ingestCritical({ event, ack: async () => {} })).rejects.toThrow(
      AuditChainError
    );
    expect(sink.entries[0]!.operation).toBe("wal_chain_verification_failed");
    expect(sink.entries[0]!.details?.reason).toBe("chain_fields_missing");
    expect(consumer.getStats().rejectedEvents).toBe(1);
  });

  it("rejects sequence regression", async () => {
    const eventSeq5 = chainedEvent(5, null);
    await consumer.ingestCritical({ event: eventSeq5, ack: async () => {} });

    const eventSeq4 = chainedEvent(4, eventHash(eventSeq5));
    await expect(consumer.ingestCritical({ event: eventSeq4, ack: async () => {} })).rejects.toThrow(
      /seq_regression/
    );
    expect(sink.entries.at(-1)!.operation).toBe("wal_chain_verification_failed");
    expect(sink.entries.at(-1)!.details?.reason).toBe("seq_regression");
  });

  it("rejects chain break when prior hash does not match the accepted event", async () => {
    const eventSeq5 = chainedEvent(5, null);
    await consumer.ingestCritical({ event: eventSeq5, ack: async () => {} });

    const tampered = chainedEvent(6, "deadbeef");
    await expect(consumer.ingestCritical({ event: tampered, ack: async () => {} })).rejects.toThrow(
      /wal_chain_verification_failed/
    );
    expect(sink.entries.at(-1)!.operation).toBe("wal_chain_verification_failed");
    expect(sink.entries.at(-1)!.details?.reason).toBe("wal_chain_verification_failed");
  });

  it("accepts valid chain continuation", async () => {
    const eventSeq5 = chainedEvent(5, null);
    await consumer.ingestCritical({ event: eventSeq5, ack: async () => {} });
    const eventSeq6 = chainedEvent(6, eventHash(eventSeq5));
    await consumer.ingestCritical({ event: eventSeq6, ack: async () => {} });

    expect(sink.entries.length).toBe(2);
    expect(consumer.getWalChainState().lastAckedSeq).toBe(6);
    expect(consumer.getWalChainState().lastEventCanonicalHash).toBe(eventHash(eventSeq6));
  });

  it("does not ACK or advance chain when critical persistence fails (#104)", async () => {
    const faultingSink = new FaultingCriticalSink();
    const faultingConsumer = new AuditConsumer(faultingSink);
    const eventSeq5 = chainedEvent(5, null);
    let acked = false;

    await expect(
      faultingConsumer.ingestCritical({
        event: eventSeq5,
        ack: async () => {
          acked = true;
        },
      })
    ).rejects.toThrow("audit disk unavailable");

    expect(acked).toBe(false);
    expect(faultingConsumer.getWalChainState().lastAckedSeq).toBeNull();
    expect(faultingConsumer.getWalChainState().lastEventCanonicalHash).toBeNull();
    expect(faultingConsumer.getStats().acceptedCriticalEvents).toBe(0);
    expect(faultingConsumer.getStats().persistenceFailures).toBe(1);
    expect(faultingSink.entries).toHaveLength(1);
    expect(faultingSink.entries[0]!.operation).toBe("critical_event_persistence_failed");
    expect(faultingSink.entries[0]!.result).toBe("failure");
    expect(faultingSink.entries[0]!.details?.seq).toBe(5);
  });

  it("refuses to BOOTSTRAP-accept a later event after a prior event failed to persist (codex CRITICAL FIX 2)", async () => {
    // The data-loss vector: seq 1 fails to persist (no ack, anchor stays null),
    // then seq 2 arrives chaining off seq 1. If the consumer treated seq 2 as a
    // fresh bootstrap it would accept + ack it, letting the daemon truncate its
    // WAL THROUGH the unpersisted seq 1 (silent audit data loss). The consumer
    // MUST reject seq 2 and never ack past the failed seq.
    const faultingSink = new FaultingCriticalSink();
    const faultingConsumer = new AuditConsumer(faultingSink);

    const eventSeq1 = chainedEvent(1, null);
    await expect(
      faultingConsumer.ingestCritical({ event: eventSeq1, ack: async () => {} })
    ).rejects.toThrow("audit disk unavailable");
    // Anchor never advanced: no durable seq 1.
    expect(faultingConsumer.getWalChainState().lastAckedSeq).toBeNull();
    expect(faultingConsumer.getWalChainState().lastEventCanonicalHash).toBeNull();

    // seq 2 chains off the (unpersisted) seq 1 → non-null prior-hash in the
    // still-bootstrap state → MUST be refused, MUST NOT ack.
    const eventSeq2 = chainedEvent(2, eventHash(eventSeq1));
    let seq2Acked = false;
    await expect(
      faultingConsumer.ingestCritical({
        event: eventSeq2,
        ack: async () => {
          seq2Acked = true;
        },
      })
    ).rejects.toThrow(/wal_chain_bootstrap_after_unpersisted_event/);
    expect(seq2Acked).toBe(false);
    expect(faultingConsumer.getStats().acceptedCriticalEvents).toBe(0);
    expect(faultingConsumer.getWalChainState().lastAckedSeq).toBeNull();
    // The refusal was durably recorded for audit.
    expect(faultingSink.entries.at(-1)!.operation).toBe("wal_chain_verification_failed");
  });

  // ─── #92 ACK failure handling + duplicate replay ────────────────────────

  it("emits critical_event_ack_failed on ACK exception, does not throw (#92)", async () => {
    const eventSeq5 = chainedEvent(5, null);
    const ackError = new Error("ipc broken pipe");
    await consumer.ingestCritical({
      event: eventSeq5,
      ack: async () => {
        throw ackError;
      },
    });
    // Original event still appended + flushed (data is durable).
    expect(sink.entries.length).toBe(2);
    expect(sink.entries[0]!.operation).toBe("egress_allowed");
    // Diagnostic entry recorded.
    expect(sink.entries[1]!.operation).toBe("critical_event_ack_failed");
    expect(sink.entries[1]!.result).toBe("failure");
    expect(sink.entries[1]!.details?.seq).toBe(5);
    expect(sink.entries[1]!.details?.reason).toBe("ipc broken pipe");
    expect(sink.entries[1]!.details?.event_type).toBe("egress_allowed");
    // Stats reflect both the accepted event and the ACK failure.
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
    expect(consumer.getStats().ackFailures).toBe(1);
    // State updated even though ACK failed: flush completed before ACK.
    expect(consumer.getWalChainState().lastAckedSeq).toBe(5);
    expect(consumer.getWalChainState().lastEventCanonicalHash).toBe(
      eventHash(eventSeq5)
    );
  });

  it("drops duplicate critical event silently on daemon retry after ACK failure (#92)", async () => {
    const eventSeq5 = chainedEvent(5, null);
    // First delivery: ACK fails.
    await consumer.ingestCritical({
      event: eventSeq5,
      ack: async () => {
        throw new Error("first ack failed");
      },
    });
    const beforeReplayLength = sink.entries.length;
    // Daemon retries the SAME event (same seq, same canonical content).
    let secondAcked = false;
    await consumer.ingestCritical({
      event: eventSeq5,
      ack: async () => {
        secondAcked = true;
      },
    });
    // No second copy of `egress_allowed`. Instead, a duplicate-dropped marker.
    const replayEntries = sink.entries.slice(beforeReplayLength);
    const dupEntry = replayEntries.find(
      (e) => e.operation === "critical_event_duplicate_dropped"
    );
    expect(dupEntry).toBeDefined();
    expect(dupEntry!.details?.seq).toBe(5);
    expect(dupEntry!.details?.event_type).toBe("egress_allowed");
    // Original event was appended exactly once across both deliveries.
    const originals = sink.entries.filter(
      (e) => e.operation === "egress_allowed"
    );
    expect(originals).toHaveLength(1);
    // Stats: the duplicate counter incremented; acceptedCriticalEvents stays 1.
    expect(consumer.getStats().duplicatesDropped).toBe(1);
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
    // Daemon receives the second ACK, so it stops retrying.
    expect(secondAcked).toBe(true);
  });

  it("treats same-seq with different content as a genuine seq_regression (not a duplicate) (#92)", async () => {
    const eventSeq5 = chainedEvent(5, null);
    await consumer.ingestCritical({ event: eventSeq5, ack: async () => {} });
    // Different timestamp ⇒ different canonical hash, but same seq=5.
    const tampered = buildAuditEvent({
      timestamp: "2026-05-04T01:00:05Z", // different from chainedEvent's "...0:05Z"
      fortress_id: "f",
      event_type: "egress_allowed",
      details: { seq: 5, prior_sha256_hex: null },
    });
    await expect(
      consumer.ingestCritical({ event: tampered, ack: async () => {} })
    ).rejects.toThrow(/seq_regression/);
    // No `critical_event_duplicate_dropped` for this case: it's corruption.
    const dupEntries = sink.entries.filter(
      (e) => e.operation === "critical_event_duplicate_dropped"
    );
    expect(dupEntries).toHaveLength(0);
  });

  // ─── #924 interaction: uncanonicalizable events must SETTLE, never fault ──
  //
  // mesh `canonicalize()` (#924) now THROWS on an unsafe integer (>= 2^53) so
  // it can never silently diverge from the Swift Int64 canonicalizer. This
  // consumer calls that same `canonicalize()` on attacker-controllable
  // `event.details` (a `Record<string, unknown>` spread verbatim from the
  // daemon wire body) in fail-closed paths that must never themselves throw
  // BEFORE the event's ack. An event with an unsafe integer buried in
  // `details` is a forgery the consumer already models (full-sweep interaction
  // sweep, 2026-07-14): it must be recorded as a SETTLED rejection (ACKed,
  // cursor advances, wall stays ARMED), never an unsettled fault that wedges
  // NOT-ARMED and causes the daemon to redeliver the same poison event forever.

  const UNSAFE_INT = 2 ** 53 + 1;

  it("settles an uncanonicalizable event on the reject (validateEvent-failure) path: recorded rejected + ACKed, never throws (bug-inject: unsafe int + bogus event_type)", async () => {
    const event = buildAuditEvent({
      timestamp: "2026-05-04T00:00:00Z",
      fortress_id: "f",
      event_type: "egress_allowed",
      details: { seq: 0, prior_sha256_hex: null, poison: UNSAFE_INT },
    });
    const tampered = {
      ...event,
      event_type: "rogue" as unknown as CastleWallAuditEvent["event_type"],
    } as CastleWallAuditEvent;
    let acked = false;
    // Must not throw: a forged/malformed event settling must never propagate
    // an exception out of ingestCritical (that is what the drain loop reads
    // as an UNSETTLED FAULT and trips NOT-ARMED).
    await expect(
      consumer.ingestCritical({
        event: tampered,
        ack: async () => {
          acked = true;
        },
      })
    ).resolves.toBeUndefined();
    expect(acked).toBe(true);
    expect(sink.entries.length).toBe(1);
    expect(sink.entries[0]!.operation).toBe("audit_event_rejected");
    expect(sink.entries[0]!.result).toBe("failure");
    expect(consumer.getStats().rejectedEvents).toBe(1);
    // The wall must stay armed: nothing here is an accepted critical event.
    expect(consumer.getStats().acceptedCriticalEvents).toBe(0);
  });

  it("settles an uncanonicalizable event on the accept/chain path as a SETTLED rejection, never accepts it, never throws (bug-inject: unsafe int, otherwise-valid event)", async () => {
    const event = chainedEvent(5, null);
    const poisoned: CastleWallAuditEvent = {
      ...event,
      details: { ...event.details, poison: UNSAFE_INT },
    };
    let acked = false;
    await expect(
      consumer.ingestCritical({
        event: poisoned,
        ack: async () => {
          acked = true;
        },
      })
    ).resolves.toBeUndefined();
    expect(acked).toBe(true);
    // Never accepted/chained: fail-closed for an unrepresentable event.
    expect(consumer.getStats().acceptedCriticalEvents).toBe(0);
    expect(consumer.getStats().rejectedEvents).toBe(1);
    expect(consumer.getWalChainState().lastAckedSeq).toBeNull();
    expect(consumer.getWalChainState().lastEventCanonicalHash).toBeNull();
    // Recorded as a rejection, not silently dropped or accepted as evidence.
    const rejected = sink.entries.find((e) => e.operation === "audit_event_rejected");
    expect(rejected).toBeDefined();
    expect(rejected!.result).toBe("failure");
    // Audit-integrity fidelity (opus MEDIUM): the canonicalization_failed
    // rejection must record seq + event_type so an auditor can correlate WHICH
    // WAL position was suppressed, matching the sibling
    // `producer_signature_rejected` path. These are read WITHOUT canonicalize.
    expect(rejected!.details?.reason).toBe("canonicalization_failed");
    expect(rejected!.details?.seq).toBe(5);
    expect(rejected!.details?.event_type).toBe("egress_allowed");
  });

  it("does not wedge on redelivery of the same uncanonicalizable event (anti-DoS)", async () => {
    const event = chainedEvent(7, null);
    const poisoned: CastleWallAuditEvent = {
      ...event,
      details: { ...event.details, poison: UNSAFE_INT },
    };
    // First delivery.
    let firstAcked = false;
    await expect(
      consumer.ingestCritical({
        event: poisoned,
        ack: async () => {
          firstAcked = true;
        },
      })
    ).resolves.toBeUndefined();
    expect(firstAcked).toBe(true);
    // Daemon redelivers the identical poison event (it was never accepted, so
    // the daemon's WAL cursor did not truly need to advance past it from the
    // consumer's point of view, but a real daemon may still redeliver on a
    // retry/restart). The consumer must handle it the SAME way every time -
    // settled rejection, never a throw, never a wedge.
    let secondAcked = false;
    await expect(
      consumer.ingestCritical({
        event: poisoned,
        ack: async () => {
          secondAcked = true;
        },
      })
    ).resolves.toBeUndefined();
    expect(secondAcked).toBe(true);
    expect(consumer.getStats().acceptedCriticalEvents).toBe(0);
    expect(consumer.getStats().rejectedEvents).toBe(2);
  });

  it("a genuine event AFTER a settled uncanonicalizable rejection still chains and accepts normally (wall stays armed)", async () => {
    const poisonedSeq5 = {
      ...chainedEvent(5, null),
      details: { seq: 5, prior_sha256_hex: null, poison: UNSAFE_INT },
    } as CastleWallAuditEvent;
    await consumer.ingestCritical({ event: poisonedSeq5, ack: async () => {} });
    expect(consumer.getWalChainState().lastAckedSeq).toBeNull();

    // A genuine bootstrap event (still no accepted anchor) must still be
    // accepted normally - the poisoned event never became part of the chain.
    const genuine = chainedEvent(5, null);
    await consumer.ingestCritical({ event: genuine, ack: async () => {} });
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
    expect(consumer.getWalChainState().lastAckedSeq).toBe(5);
    expect(consumer.getWalChainState().lastEventCanonicalHash).toBe(eventHash(genuine));
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
