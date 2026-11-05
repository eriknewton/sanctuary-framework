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
    expect(consumer.getWalChainState().lastEventChainHash).toBe(eventHash(eventSeq6));
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
    expect(faultingConsumer.getWalChainState().lastEventChainHash).toBeNull();
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
    expect(faultingConsumer.getWalChainState().lastEventChainHash).toBeNull();

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
    expect(consumer.getWalChainState().lastEventChainHash).toBe(
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
    expect(consumer.getWalChainState().lastEventChainHash).toBeNull();
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
    expect(consumer.getWalChainState().lastEventChainHash).toBe(eventHash(genuine));
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

import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
const FLOW_NOW = Date.parse("2026-11-04T00:00:00Z");
const FLOW_UID = 501; // Ordinary fixture principal.
const FLOW_TOKEN = Buffer.from(new Uint32Array([0, FLOW_UID, FLOW_UID, FLOW_UID, FLOW_UID, 123, 1, 1]).buffer).toString("hex");
const flowKey = ed25519.utils.randomPrivateKey();
const flowPin = Buffer.from(ed25519.getPublicKey(flowKey)).toString("base64url");
const flowHash = (body: string) => createHash("sha256").update(body).digest("hex");
function liveEnvelope(seq: number, prior: string | null, ip = "192.0.2.1") {
  const timestamp = new Date(FLOW_NOW).toISOString();
  const body = canonicalize({ timestamp, layer: "l1", operation: "egress_blocked", identity_id: FLOW_TOKEN, result: "blocked",
    details: { agent_id: FLOW_TOKEN, dest_ip: ip, dest_port: 443, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
  return { event: buildAuditEvent({ timestamp, fortress_id: "fixture", event_type: "egress_blocked",
    agent: { id: FLOW_TOKEN, template: "fixture" }, destination: { host: null, ip, port: 443, protocol: "tcp" }, details: { seq, prior_sha256_hex: prior } }),
    ack: async () => {}, producerDelivery: "live" as "live" | "durable_wal",
    producerSubjectBinding: { kind: "macos_audit_token" as const, fortressId: "fixture" },
    producer: { eventCanonicalJson: body, capturedAtUnixMs: FLOW_NOW, seq, keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      signatureB64url: Buffer.from(ed25519.sign(producerSigningBytes(body, FLOW_NOW, seq), flowKey)).toString("base64url") } };
}
async function countedConsumer(sink: AuditSink) {
  const path = "../../../src/castle-wall/runtime/macos-flow-coalescing.js";
  const module = await import(path).catch(() => null) as typeof import("../../../src/castle-wall/runtime/macos-flow-coalescing.js") | null;
  expect(module, "counted-flow helper is available").not.toBeNull();
  const coalescer = new module!.FlowCoalescer("fixture-instance", () => FLOW_NOW);
  const consumer = new AuditConsumer(sink, undefined, { pinnedProducerKeyB64url: flowPin, now: () => FLOW_NOW, chainContinuity: "producer_subset", liveFlowCoalescer: coalescer });
  return { consumer, coalescer };
}

// Live admission witnesses use the same signature, chain and identity path as primary persistence.
it("0 head, 2 coalesced, 1 regressed", async () => {
  const sink = new RecordingSink(); const f = await countedConsumer(sink);
  const zero = liveEnvelope(0, null), one = liveEnvelope(1, flowHash(zero.producer.eventCanonicalJson));
  const two = liveEnvelope(2, flowHash(one.producer.eventCanonicalJson));
  await f.consumer.ingestCritical(zero); await f.consumer.ingestCritical(two);
  expect(f.consumer.getStats().coalescedCriticalEvents, "second same-key admission is counted").toBe(1);
  await expect(f.consumer.ingestCritical(one)).rejects.toThrow("seq_regression");
  expect(sink.entries.at(-1)?.details?.reason, "coalesced admissions advance the shared floor").toBe("seq_regression");
});
it("identical replay of a coalesced sequence is a duplicate", async () => {
  const sink = new RecordingSink(); const f = await countedConsumer(sink);
  const zero = liveEnvelope(0, null), two = liveEnvelope(2, flowHash(zero.producer.eventCanonicalJson));
  await f.consumer.ingestCritical(zero); await f.consumer.ingestCritical(two);
  expect(f.consumer.getWalChainState().lastEventChainHash, "coalesced commit installs H2 before replay").toBe(flowHash(two.producer.eventCanonicalJson));
  await f.consumer.ingestCritical(two);
  expect(f.consumer.getWalChainState().lastEventChainHash, "coalesced commit preserves the selected signed hash").toBe(flowHash(two.producer.eventCanonicalJson));
  expect(sink.entries.at(-1)?.operation, "identical counted replay takes the duplicate path").toBe("critical_event_duplicate_dropped");
  expect(f.consumer.getStats().coalescedCriticalEvents).toBe(1);
  await expect(f.consumer.ingestCritical(liveEnvelope(2, two.event.details.prior_sha256_hex as string, "192.0.2.2"))).rejects.toThrow("seq_regression");
});
it("failed-primary debt forces primary persistence", async () => {
  const sink = new RecordingSink(); const append = sink.append.bind(sink); let fail = false; let primaryAttempts = 0;
  sink.append = (...args) => { if (args[1] === "egress_blocked") { primaryAttempts++; if (fail) throw new Error("fixture primary failure"); } append(...args); };
  const f = await countedConsumer(sink);
  const zero = liveEnvelope(0, null), one = liveEnvelope(1, flowHash(zero.producer.eventCanonicalJson), "192.0.2.2");
  const two = liveEnvelope(2, flowHash(one.producer.eventCanonicalJson));
  await f.consumer.ingestCritical(zero); fail = true;
  await expect(f.consumer.ingestCritical(one)).rejects.toThrow("fixture primary failure");
  const outcome = await f.consumer.ingestCritical(two).then(() => null, error => error);
  expect(primaryAttempts, "owed primary routes an otherwise-countable subset frame to persistence").toBe(3);
  expect((f.consumer as unknown as { pendingUnpersistedSeq: number | null }).pendingUnpersistedSeq, "failed primary debt remains owed").toBe(2);
  expect(f.consumer.getStats().coalescedCriticalEvents).toBe(0);
  expect(outcome).toBeInstanceOf(Error);
});
it("durable WAL delivery passes through the coalescer", async () => {
  const sink = new RecordingSink(); const f = await countedConsumer(sink);
  const zero = liveEnvelope(0, null), one = liveEnvelope(1, flowHash(zero.producer.eventCanonicalJson));
  await f.consumer.ingestCritical(zero); one.producerDelivery = "durable_wal";
  let observed = 0; one.ack = async () => { observed = sink.entries.filter(entry => entry.operation === "egress_blocked").length; };
  await f.consumer.ingestCritical(one);
  expect(observed, "durable delivery persists before ACK despite a matching live window").toBe(2);
  expect(f.consumer.getStats().coalescedCriticalEvents).toBe(0);
});

import { describe as parityDescribe, it as parityIt, expect as parityExpect } from "vitest";
import { AuditConsumer as ParityBaseConsumer } from "../../../src/castle-wall/runtime/audit-consumer.js";
import { MacOSFlowEventConsumer as ParityFlowConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
parityDescribe("consumer admission with counted-window configuration", () => {
  let enabled = false;
  let trace: unknown[] = [];
  let instances: ParityBaseConsumer[] = [];
  let hooks: Array<() => unknown> = [];
  let helper: typeof import("../../../src/castle-wall/runtime/macos-flow-coalescing.js") | null = null;
  class AuditConsumer extends ParityBaseConsumer {
    constructor(...args: ConstructorParameters<typeof ParityBaseConsumer>) {
      const sink = args[0];
      const append = sink.append.bind(sink), flush = sink.flush.bind(sink);
      sink.append = (...call) => { trace.push(["append", JSON.stringify(call)]); return append(...call); };
      sink.flush = () => { trace.push(["flush"]); return flush(); };
      super(sink, args[1], { ...args[2], ...(enabled ? { liveFlowCoalescer: new helper!.FlowCoalescer("parity-instance", () => 0) } : {}) });
      instances.push(this);
    }
    override async ingestCritical(envelope: Parameters<ParityBaseConsumer["ingestCritical"]>[0]): Promise<void> {
      const ack = envelope.ack;
      try {
        await super.ingestCritical({ ...envelope, ack: async () => { trace.push(["ACK", envelope.event.details?.seq]); return ack(); } });
        trace.push(["fulfilled"]);
      } catch (error) { trace.push(["thrown", error instanceof Error ? [error.constructor.name, error.name, error.message] : String(error)]); throw error; }
    }
  }
  function describe(title: string, register: () => void) {
    const previous = hooks; hooks = [...hooks]; parityDescribe(title, register); hooks = previous;
  }
  function beforeEach(hook: () => unknown) { hooks.push(hook); }
  function variant(callback: (...args: any[]) => unknown) {
    const setup = [...hooks];
    return async (...args: any[]) => {
      const consumer = new ParityFlowConsumer({ fortressId: "parity", defaultApprovalTimeoutSeconds: 30,
        auditSink: { append() {}, async flush() {} }, approvalQueue: { async enqueue() {} },
        manifestProvider: { currentSnapshot() { throw new Error("unused"); } } });
      parityExpect(consumer.flushCoalescedFlowSummaries).toBeTypeOf("function");
      const path = "../../../src/castle-wall/runtime/macos-flow-coalescing.js";
      helper = await import(path).catch(() => null); parityExpect(helper).not.toBeNull();
      const results: unknown[] = [];
      for (const mode of [false, true]) {
        enabled = mode; trace = []; instances = [];
        for (const hook of setup) await hook();
        await callback(...args);
        results.push({ trace: structuredClone(trace), consumers: instances.map(item => ({ stats: item.getStats(), state: item.getWalChainState() })) });
      }
      parityExpect(results[1], "ordered evidence bytes, outcomes, ACKs and counter deltas match the control").toEqual(results[0]);
    };
  }
  const it = Object.assign((title: string, callback: (...args: any[]) => unknown) => parityIt(title + " with coalescer attached", variant(callback)), {
    each: (cases: readonly any[]) => (title: string, callback: (...args: any[]) => unknown) => parityIt.each(cases)(title + " with coalescer attached", variant(callback)),
  });
class RecordingSink implements AuditSink {
    entries: Array<{
        layer: "l1";
        operation: string;
        identityId: string;
        details?: Record<string, unknown>;
        result: "success" | "failure";
    }> = [];
    flushedCount = 0;
    append(layer: "l1", operation: string, identityId: string, details?: Record<string, unknown>, result: "success" | "failure" = "success"): void {
        this.entries.push({ layer, operation, identityId, details, result });
    }
    async flush(): Promise<void> {
        this.flushedCount += 1;
    }
}
class FaultingCriticalSink extends RecordingSink {
    async append(layer: "l1", operation: string, identityId: string, details?: Record<string, unknown>, result: "success" | "failure" = "success"): Promise<void> {
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
    it("appends and flushes and ACKs in order on a valid event", async () => {
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
    it("flattens agent and destination and decision and rule_id into details", async () => {
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
        await consumer.ingestCritical({ event, ack: async () => { } });
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
        await expect(consumer.ingestCritical({ event, ack: async () => { } })).rejects.toThrow(AuditChainError);
        expect(sink.entries[0]!.operation).toBe("wal_chain_verification_failed");
        expect(sink.entries[0]!.details?.reason).toBe("chain_fields_missing");
        expect(consumer.getStats().rejectedEvents).toBe(1);
    });
    it("rejects sequence regression", async () => {
        const eventSeq5 = chainedEvent(5, null);
        await consumer.ingestCritical({ event: eventSeq5, ack: async () => { } });
        const eventSeq4 = chainedEvent(4, eventHash(eventSeq5));
        await expect(consumer.ingestCritical({ event: eventSeq4, ack: async () => { } })).rejects.toThrow(/seq_regression/);
        expect(sink.entries.at(-1)!.operation).toBe("wal_chain_verification_failed");
        expect(sink.entries.at(-1)!.details?.reason).toBe("seq_regression");
    });
    it("rejects chain break when prior hash does not match the accepted event", async () => {
        const eventSeq5 = chainedEvent(5, null);
        await consumer.ingestCritical({ event: eventSeq5, ack: async () => { } });
        const tampered = chainedEvent(6, "deadbeef");
        await expect(consumer.ingestCritical({ event: tampered, ack: async () => { } })).rejects.toThrow(/wal_chain_verification_failed/);
        expect(sink.entries.at(-1)!.operation).toBe("wal_chain_verification_failed");
        expect(sink.entries.at(-1)!.details?.reason).toBe("wal_chain_verification_failed");
    });
    it("accepts valid chain continuation", async () => {
        const eventSeq5 = chainedEvent(5, null);
        await consumer.ingestCritical({ event: eventSeq5, ack: async () => { } });
        const eventSeq6 = chainedEvent(6, eventHash(eventSeq5));
        await consumer.ingestCritical({ event: eventSeq6, ack: async () => { } });
        expect(sink.entries.length).toBe(2);
        expect(consumer.getWalChainState().lastAckedSeq).toBe(6);
        expect(consumer.getWalChainState().lastEventChainHash).toBe(eventHash(eventSeq6));
    });
    it("does not ACK or advance chain when critical persistence fails", async () => {
        const faultingSink = new FaultingCriticalSink();
        const faultingConsumer = new AuditConsumer(faultingSink);
        const eventSeq5 = chainedEvent(5, null);
        let acked = false;
        await expect(faultingConsumer.ingestCritical({
            event: eventSeq5,
            ack: async () => {
                acked = true;
            },
        })).rejects.toThrow("audit disk unavailable");
        expect(acked).toBe(false);
        expect(faultingConsumer.getWalChainState().lastAckedSeq).toBeNull();
        expect(faultingConsumer.getWalChainState().lastEventChainHash).toBeNull();
        expect(faultingConsumer.getStats().acceptedCriticalEvents).toBe(0);
        expect(faultingConsumer.getStats().persistenceFailures).toBe(1);
        expect(faultingSink.entries).toHaveLength(1);
        expect(faultingSink.entries[0]!.operation).toBe("critical_event_persistence_failed");
        expect(faultingSink.entries[0]!.result).toBe("failure");
        expect(faultingSink.entries[0]!.details?.seq).toBe(5);
    });
    it("refuses to BOOTSTRAP-accept a later event after a prior event failed to persist", async () => {
        const faultingSink = new FaultingCriticalSink();
        const faultingConsumer = new AuditConsumer(faultingSink);
        const eventSeq1 = chainedEvent(1, null);
        await expect(faultingConsumer.ingestCritical({ event: eventSeq1, ack: async () => { } })).rejects.toThrow("audit disk unavailable");
        expect(faultingConsumer.getWalChainState().lastAckedSeq).toBeNull();
        expect(faultingConsumer.getWalChainState().lastEventChainHash).toBeNull();
        const eventSeq2 = chainedEvent(2, eventHash(eventSeq1));
        let seq2Acked = false;
        await expect(faultingConsumer.ingestCritical({
            event: eventSeq2,
            ack: async () => {
                seq2Acked = true;
            },
        })).rejects.toThrow(/wal_chain_bootstrap_after_unpersisted_event/);
        expect(seq2Acked).toBe(false);
        expect(faultingConsumer.getStats().acceptedCriticalEvents).toBe(0);
        expect(faultingConsumer.getWalChainState().lastAckedSeq).toBeNull();
        expect(faultingSink.entries.at(-1)!.operation).toBe("wal_chain_verification_failed");
    });
    it("emits critical_event_ack_failed on ACK exception, does not throw", async () => {
        const eventSeq5 = chainedEvent(5, null);
        const ackError = new Error("ipc broken pipe");
        await consumer.ingestCritical({
            event: eventSeq5,
            ack: async () => {
                throw ackError;
            },
        });
        expect(sink.entries.length).toBe(2);
        expect(sink.entries[0]!.operation).toBe("egress_allowed");
        expect(sink.entries[1]!.operation).toBe("critical_event_ack_failed");
        expect(sink.entries[1]!.result).toBe("failure");
        expect(sink.entries[1]!.details?.seq).toBe(5);
        expect(sink.entries[1]!.details?.reason).toBe("ipc broken pipe");
        expect(sink.entries[1]!.details?.event_type).toBe("egress_allowed");
        expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
        expect(consumer.getStats().ackFailures).toBe(1);
        expect(consumer.getWalChainState().lastAckedSeq).toBe(5);
        expect(consumer.getWalChainState().lastEventChainHash).toBe(eventHash(eventSeq5));
    });
    it("drops duplicate critical event silently on daemon retry after ACK failure", async () => {
        const eventSeq5 = chainedEvent(5, null);
        await consumer.ingestCritical({
            event: eventSeq5,
            ack: async () => {
                throw new Error("first ack failed");
            },
        });
        const beforeReplayLength = sink.entries.length;
        let secondAcked = false;
        await consumer.ingestCritical({
            event: eventSeq5,
            ack: async () => {
                secondAcked = true;
            },
        });
        const replayEntries = sink.entries.slice(beforeReplayLength);
        const dupEntry = replayEntries.find((e) => e.operation === "critical_event_duplicate_dropped");
        expect(dupEntry).toBeDefined();
        expect(dupEntry!.details?.seq).toBe(5);
        expect(dupEntry!.details?.event_type).toBe("egress_allowed");
        const originals = sink.entries.filter((e) => e.operation === "egress_allowed");
        expect(originals).toHaveLength(1);
        expect(consumer.getStats().duplicatesDropped).toBe(1);
        expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
        expect(secondAcked).toBe(true);
    });
    it("treats same-seq with different content as a genuine seq_regression", async () => {
        const eventSeq5 = chainedEvent(5, null);
        await consumer.ingestCritical({ event: eventSeq5, ack: async () => { } });
        const tampered = buildAuditEvent({
            timestamp: "2026-05-04T01:00:05Z",
            fortress_id: "f",
            event_type: "egress_allowed",
            details: { seq: 5, prior_sha256_hex: null },
        });
        await expect(consumer.ingestCritical({ event: tampered, ack: async () => { } })).rejects.toThrow(/seq_regression/);
        const dupEntries = sink.entries.filter((e) => e.operation === "critical_event_duplicate_dropped");
        expect(dupEntries).toHaveLength(0);
    });
    const UNSAFE_INT = 2 ** 53 + 1;
    it("settles an uncanonicalizable event on the reject path: recorded rejected and ACKed, never throws", async () => {
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
        await expect(consumer.ingestCritical({
            event: tampered,
            ack: async () => {
                acked = true;
            },
        })).resolves.toBeUndefined();
        expect(acked).toBe(true);
        expect(sink.entries.length).toBe(1);
        expect(sink.entries[0]!.operation).toBe("audit_event_rejected");
        expect(sink.entries[0]!.result).toBe("failure");
        expect(consumer.getStats().rejectedEvents).toBe(1);
        expect(consumer.getStats().acceptedCriticalEvents).toBe(0);
    });
    it("settles an uncanonicalizable event on the accept/chain path as a SETTLED rejection, never accepts it, never throws", async () => {
        const event = chainedEvent(5, null);
        const poisoned: CastleWallAuditEvent = {
            ...event,
            details: { ...event.details, poison: UNSAFE_INT },
        };
        let acked = false;
        await expect(consumer.ingestCritical({
            event: poisoned,
            ack: async () => {
                acked = true;
            },
        })).resolves.toBeUndefined();
        expect(acked).toBe(true);
        expect(consumer.getStats().acceptedCriticalEvents).toBe(0);
        expect(consumer.getStats().rejectedEvents).toBe(1);
        expect(consumer.getWalChainState().lastAckedSeq).toBeNull();
        expect(consumer.getWalChainState().lastEventChainHash).toBeNull();
        const rejected = sink.entries.find((e) => e.operation === "audit_event_rejected");
        expect(rejected).toBeDefined();
        expect(rejected!.result).toBe("failure");
        expect(rejected!.details?.reason).toBe("canonicalization_failed");
        expect(rejected!.details?.seq).toBe(5);
        expect(rejected!.details?.event_type).toBe("egress_allowed");
    });
    it("settles repeated uncanonicalizable delivery", async () => {
        const event = chainedEvent(7, null);
        const poisoned: CastleWallAuditEvent = {
            ...event,
            details: { ...event.details, poison: UNSAFE_INT },
        };
        let firstAcked = false;
        await expect(consumer.ingestCritical({
            event: poisoned,
            ack: async () => {
                firstAcked = true;
            },
        })).resolves.toBeUndefined();
        expect(firstAcked).toBe(true);
        let secondAcked = false;
        await expect(consumer.ingestCritical({
            event: poisoned,
            ack: async () => {
                secondAcked = true;
            },
        })).resolves.toBeUndefined();
        expect(secondAcked).toBe(true);
        expect(consumer.getStats().acceptedCriticalEvents).toBe(0);
        expect(consumer.getStats().rejectedEvents).toBe(2);
    });
    it("a genuine event AFTER a settled uncanonicalizable rejection still chains and accepts normally", async () => {
        const poisonedSeq5 = {
            ...chainedEvent(5, null),
            details: { seq: 5, prior_sha256_hex: null, poison: UNSAFE_INT },
        } as CastleWallAuditEvent;
        await consumer.ingestCritical({ event: poisonedSeq5, ack: async () => { } });
        expect(consumer.getWalChainState().lastAckedSeq).toBeNull();
        const genuine = chainedEvent(5, null);
        await consumer.ingestCritical({ event: genuine, ack: async () => { } });
        expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
        expect(consumer.getWalChainState().lastAckedSeq).toBe(5);
        expect(consumer.getWalChainState().lastEventChainHash).toBe(eventHash(genuine));
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
});

// These controls begin after the same signed head has settled in both consumers.
const windowCases = [
  ["ordered append flush and ACK", "accepted"],
  ["malformed event ACK", "malformed"],
  ["signed record fields", "accepted"],
  ["missing chain fields", "missing"],
  ["sequence regression", "regression"],
  ["prior hash continuity", "prior"],
  ["valid chain continuation", "accepted"],
  ["primary failure and owed persistence", "persistence"],
  ["ACK exception diagnostic", "ack"],
  ["duplicate after ACK exception", "duplicate"],
  ["changed content at the same sequence", "changed"],
  ["uncanonicalizable malformed event", "malformed-number"],
  ["uncanonicalizable admitted shape", "number"],
  ["uncanonicalizable repeated delivery", "repeat-number"],
  ["valid continuation after a settled rejection", "after-number"],
  ["metric batch persistence", "metric"],
] as const;
for (const [label, scenario] of windowCases) it(`established live window preserves ${label}`, async () => {
  const module = await import("../../../src/castle-wall/runtime/macos-flow-coalescing.js").catch(() => null);
  expect(module).not.toBeNull();
  const results = [];
  for (const enabled of [false, true]) {
    const trace: unknown[][] = []; let fail = false, invocation = 0;
    const counted = new Set<number>();
    const sink: AuditSink = { append(...args) {
      trace.push(["append", invocation, JSON.stringify(args)]);
      if (fail && args[1] === "egress_blocked") throw new Error("fixture primary unavailable");
    }, async flush() { trace.push(["flush", invocation]); } };
    const coalescer = new module!.FlowCoalescer("window-parity", () => FLOW_NOW);
    const consumer = new AuditConsumer(sink, undefined, { pinnedProducerKeyB64url: flowPin, now: () => FLOW_NOW,
      chainContinuity: "producer_subset", ...(enabled ? { liveFlowCoalescer: coalescer } : {}) });
    const head = liveEnvelope(0, null);
    await consumer.ingestCritical(head);
    expect(consumer.getWalChainState().lastAckedSeq, "setup head has settled before the trigger").toBe(0);
    if (enabled) expect(coalescer.snapshot().keys, "the signed live head opens the addressed window").toBe(1);
    trace.length = 0; const before = consumer.getStats();
    const deliver = async (envelope: ReturnType<typeof liveEnvelope>, ackFailure = false) => {
      invocation++;
      try {
        await consumer.ingestCritical({ ...envelope, ack: async () => {
          trace.push(["ACK", invocation, envelope.event.details.seq]);
          if (ackFailure) throw new Error("fixture ACK unavailable");
        } }, { classify(kind) { if (kind === "coalesced") counted.add(invocation); } });
        trace.push(["fulfilled", invocation]);
      } catch (error) {
        trace.push(["thrown", invocation, error instanceof Error ? [error.constructor.name, error.name, error.message] : String(error)]);
      }
    };
    const next = liveEnvelope(1, flowHash(head.producer.eventCanonicalJson));
    const poisoned = { ...next, event: { ...next.event, details: { ...next.event.details, value: Number.MAX_SAFE_INTEGER + 1 } } };
    switch (scenario) {
      case "malformed": case "malformed-number": {
        const malformed = scenario === "malformed" ? next : poisoned;
        await deliver({ ...malformed, event: { ...malformed.event, event_type: "unknown" as CastleWallAuditEvent["event_type"] } }); break;
      }
      case "missing": await deliver({ ...next, event: { ...next.event, details: {} } }); break;
      case "regression": case "changed": await deliver(liveEnvelope(0, null, "192.0.2.2")); break;
      case "prior": await deliver(liveEnvelope(1, "different-prior")); break;
      case "number": await deliver(poisoned); break;
      case "repeat-number": await deliver(poisoned); await deliver(poisoned); break;
      case "after-number": await deliver(poisoned); await deliver(next); break;
      case "ack": await deliver(next, true); break;
      case "duplicate": await deliver(next, true); await deliver(next); break;
      case "persistence": {
        fail = true;
        const failed = liveEnvelope(1, flowHash(head.producer.eventCanonicalJson), "192.0.2.2");
        await deliver(failed);
        await deliver(liveEnvelope(2, flowHash(failed.producer.eventCanonicalJson)));
        expect(trace.filter(call => call[0] === "append" && JSON.parse(String(call[2]))[1] === "egress_blocked"),
          "owed primary attempts persistence beside an established matching window").toHaveLength(2);
        expect((consumer as unknown as { pendingUnpersistedSeq: number }).pendingUnpersistedSeq).toBe(2);
        break;
      }
      case "metric": consumer.ingestMetricBatch("fixture", { windowStart: "start", windowEnd: "end", byDestination: [] }); break;
      default: await deliver(next);
    }
    const stats = consumer.getStats();
    const delta = Object.fromEntries(Object.entries(stats).map(([key, value]) => [key, value - before[key as keyof typeof before]]));
    const admissions = delta.acceptedCriticalEvents! + delta.coalescedCriticalEvents!;
    if (enabled && ["accepted", "ack", "duplicate", "after-number"].includes(scenario)) {
      expect(delta.coalescedCriticalEvents, "eligible same-key trigger is counted after the settled head").toBe(1);
    }
    results.push({ trace, counted, delta, admissions, state: consumer.getWalChainState() });
  }
  const [control, counted] = results;
  expect(counted!.trace, "trigger evidence bytes and ACK order preserve the admitted write omission").toEqual(control!.trace.filter(call =>
    !(counted!.counted.has(call[1] as number) && (call[0] === "append" || call[0] === "flush") &&
      // ACK diagnostics occur after ACK and remain ordinary evidence.
      (call[0] === "flush" ? control!.trace.indexOf(call) < control!.trace.findIndex(item => item[0] === "ACK" && item[1] === call[1]) : !String(call[2]).includes("critical_event_ack_failed")))));
  const counters = (result: typeof control) => {
    const { acceptedCriticalEvents, coalescedCriticalEvents, ...other } = result!.delta;
    return { ...other, admissions: result!.admissions };
  };
  expect(counters(counted)).toEqual(counters(control));
  expect(counted!.state).toEqual(control!.state);
});
