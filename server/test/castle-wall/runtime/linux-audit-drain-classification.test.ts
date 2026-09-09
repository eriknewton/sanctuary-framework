/**
 * Drain-cycle SETTLEMENT vs RECLAMATION, and retryable vs terminal routing.
 *
 * These are the two conflations the cycle used to carry, and both were invisible
 * in a green suite because each one produced a plausible-looking outcome:
 *
 *  1. SETTLEMENT was read off the ACK's WIRE SUCCESS. The consumer advances its
 *     own durable chain state BEFORE calling `ack()` (precisely because "the data
 *     is already durable"), so a failed ACK send left the loop's cursor behind
 *     the consumer's and the loop reported "event did not settle" for an event
 *     that had fully settled - tripping a permanent not-armed wall.
 *  2. EVERY daemon-side refusal was TERMINAL. An ordinary `systemctl stop` with
 *     an ACK in flight, and any 2-second control-lock contention window, wrote a
 *     durable `castle_wall_drain_failed` record blaming a transport/persistence
 *     fault for a link that was fine.
 *
 * The fakes here are deliberately minimal: `drainOnce` touches exactly three
 * methods, and a fuller harness would hide which one each assertion is about.
 */

import { describe, it, expect } from "vitest";

import {
  drainOnce,
  classifyDrainFault,
  type DrainCycleResult,
} from "../../../src/castle-wall/runtime/linux-audit-drain.js";
import { RuntimeDrainError } from "../../../src/castle-wall/runtime/errors.js";
import type { AuditConsumer, CriticalEventEnvelope } from "../../../src/castle-wall/runtime/audit-consumer.js";
import type { IpcClient } from "../../../src/castle-wall/runtime/ipc-client.js";
import type { AuditDrainEvent, AuditDrainResponse } from "../../../src/castle-wall/ipc/messages.js";

/** A minimally-valid drained event whose canonical body the loop can parse. */
function drainEvent(seq: number): AuditDrainEvent {
  return {
    seq,
    captured_at_unix_ms: Date.now(),
    prior_sha256_hex: null,
    event_canonical_json: JSON.stringify({
      layer: "l1",
      operation: "egress_approved",
      fortress_id: "fortress:test",
      identity_id: "fortress:test",
      timestamp: new Date().toISOString(),
      details: {},
    }),
    critical: true,
    producer_signature_b64url: null,
    producer_key_id: null,
  };
}

interface FakeClientScript {
  /** Response (or throw) per `drainRequest` call, in order. */
  drain: Array<AuditDrainResponse | Error>;
  /** Throw (or undefined for success) per `sendDrainAck` call, in order. */
  ack: Array<Error | undefined>;
}

function fakeClient(script: FakeClientScript): {
  client: IpcClient;
  ackedSeqs: number[];
  drainCalls: Array<number | null>;
} {
  const ackedSeqs: number[] = [];
  const drainCalls: Array<number | null> = [];
  let drainIndex = 0;
  let ackIndex = 0;
  const client = {
    drainRequest: async (afterSeq: number | null): Promise<AuditDrainResponse> => {
      drainCalls.push(afterSeq);
      const next = script.drain[Math.min(drainIndex, script.drain.length - 1)];
      drainIndex += 1;
      if (next instanceof Error) throw next;
      return next!;
    },
    sendDrainAck: async (seq: number): Promise<void> => {
      ackedSeqs.push(seq);
      const next = script.ack[Math.min(ackIndex, script.ack.length - 1)];
      ackIndex += 1;
      if (next instanceof Error) throw next;
    },
  } as unknown as IpcClient;
  return { client, ackedSeqs, drainCalls };
}

/**
 * A consumer that behaves like the real one on the settlement contract: it calls
 * `ack()` AFTER its own durable state has advanced, and it SWALLOWS an ack
 * failure rather than rethrowing (`tryAck`'s documented behavior, because the
 * data is already durable). That swallow is exactly why the loop must not infer
 * settlement from the ack's success.
 */
function settlingConsumer(): AuditConsumer {
  return {
    ingestCritical: async (envelope: CriticalEventEnvelope): Promise<void> => {
      try {
        await envelope.ack();
      } catch {
        // Swallowed, mirroring `AuditConsumer.tryAck`.
      }
    },
  } as unknown as AuditConsumer;
}

const emptyBatch = (afterSeq: number | null): AuditDrainResponse => ({
  type: "audit_drain_response",
  request_id: "r",
  events: [],
  next_after_seq: afterSeq,
  more_pending: false,
  wal_overflow_count: 0,
});

const batch = (events: AuditDrainEvent[]): AuditDrainResponse => ({
  type: "audit_drain_response",
  request_id: "r",
  events,
  next_after_seq: events[events.length - 1]?.seq ?? null,
  more_pending: false,
  wal_overflow_count: 0,
});

describe("linux-audit-drain: classification is answered in exactly one place", () => {
  it("softens only a daemon-CLASSIFIED response, never an unexpected throw", () => {
    expect(
      classifyDrainFault(new RuntimeDrainError("busy", "ack", "retryable"))
    ).toBe("retryable");
    expect(
      classifyDrainFault(new RuntimeDrainError("poisoned", "drain", "terminal"))
    ).toBe("terminal");
    expect(
      classifyDrainFault(new RuntimeDrainError("pre-v2", "drain", "unclassified"))
    ).toBe("unclassified");
    // A dropped socket / request timeout / anything unexpected keeps the
    // fail-closed armed-but-not-draining behavior the contract is written for.
    expect(classifyDrainFault(new Error("socket hung up"))).toBe("terminal");
    expect(classifyDrainFault("not even an error")).toBe("terminal");
  });
});

describe("linux-audit-drain: settlement is the consumer's ack call, not the wire", () => {
  /**
   * FAIL-BEFORE for conflation 1. With the old ordering the cursor advanced only
   * after `sendDrainAck` RESOLVED, so this scenario returned
   * `nextAfterSeq: null` and routed an UNSETTLED FAULT (terminal) for an event
   * the consumer had durably persisted.
   */
  it("advances the cursor for a settled event whose ACK send failed, and records the debt", async () => {
    const { client, ackedSeqs } = fakeClient({
      drain: [batch([drainEvent(11)])],
      ack: [new RuntimeDrainError("daemon is stopping", "ack", "retryable")],
    });
    const terminal: Error[] = [];
    const retryable: Error[] = [];
    const result: DrainCycleResult = await drainOnce(
      client,
      settlingConsumer(),
      null,
      256,
      undefined,
      (err) => terminal.push(err),
      { onRetryableFault: (err) => retryable.push(err) }
    );

    expect(ackedSeqs).toEqual([11]);
    expect(result.nextAfterSeq).toBe(11);
    expect(result.drained).toBe(1);
    expect(terminal).toHaveLength(0);
    expect(retryable).toHaveLength(1);
    expect(result.faultClass).toBe("retryable");
    // The reclamation debt is remembered so a later cycle re-acks it; without
    // this the daemon WAL keeps seq 11 forever (the loop resumes ABOVE it) and
    // grows to its cap, at which point the daemon fails closed on all egress.
    expect(result.pendingAckSeq).toBe(11);
  });

  it("re-sends the owed ACK at the top of the next cycle, BEFORE pulling more", async () => {
    const { client, ackedSeqs, drainCalls } = fakeClient({
      drain: [emptyBatch(11)],
      ack: [undefined],
    });
    const result = await drainOnce(client, settlingConsumer(), 11, 256, undefined, undefined, {
      pendingAckSeq: 11,
    });
    expect(ackedSeqs).toEqual([11]);
    expect(drainCalls).toEqual([11]);
    expect(result.pendingAckSeq).toBeNull();
    expect(result.faulted).toBe(false);
  });

  /**
   * ADVERSARIAL SCHEDULING (AGENTS rule 8/12): the debt must stay O(1). A cycle
   * that cannot settle its debt must NOT stack a second one on top by pulling a
   * new batch, or repeated failure waves would grow retained state without bound.
   */
  it("never stacks a second unconfirmed ACK on an unresolved one", async () => {
    const { client, drainCalls } = fakeClient({
      drain: [batch([drainEvent(20)])],
      ack: [new RuntimeDrainError("daemon is stopping", "ack", "retryable")],
    });
    let owed: number | null = 11;
    for (let cycle = 0; cycle < 5; cycle += 1) {
      const result = await drainOnce(client, settlingConsumer(), 11, 256, undefined, undefined, {
        pendingAckSeq: owed,
      });
      owed = result.pendingAckSeq;
      expect(typeof owed).toBe("number");
      expect(owed).toBe(11);
    }
    expect(drainCalls).toHaveLength(0);
  });
});

describe("linux-audit-drain: retryable and terminal go to DIFFERENT sinks", () => {
  it("routes a retryable drain refusal away from the not-armed fault sink", async () => {
    const { client } = fakeClient({
      drain: [new RuntimeDrainError("audit drain failed: daemon is stopping", "drain", "retryable")],
      ack: [undefined],
    });
    const terminal: Error[] = [];
    const retryable: Error[] = [];
    const result = await drainOnce(client, settlingConsumer(), null, 256, undefined, (e) => terminal.push(e), {
      onRetryableFault: (e) => retryable.push(e),
    });
    expect(terminal).toHaveLength(0);
    expect(retryable).toHaveLength(1);
    expect(result.faultClass).toBe("retryable");
    expect(result.faulted).toBe(true);
    expect(result.morePending).toBe(false);
  });

  it("routes a terminal drain failure to the not-armed fault sink", async () => {
    const { client } = fakeClient({
      drain: [new RuntimeDrainError("audit drain failed: WAL lock is poisoned", "drain", "terminal")],
      ack: [undefined],
    });
    const terminal: Error[] = [];
    const retryable: Error[] = [];
    const result = await drainOnce(client, settlingConsumer(), null, 256, undefined, (e) => terminal.push(e), {
      onRetryableFault: (e) => retryable.push(e),
    });
    expect(terminal).toHaveLength(1);
    expect(retryable).toHaveLength(0);
    expect(result.faultClass).toBe("terminal");
  });

  it("keeps an UNEXPECTED throw terminal, preserving the armed-but-not-draining guard", async () => {
    const { client } = fakeClient({
      drain: [new Error("transport dropped")],
      ack: [undefined],
    });
    const terminal: Error[] = [];
    const retryable: Error[] = [];
    await drainOnce(client, settlingConsumer(), null, 256, undefined, (e) => terminal.push(e), {
      onRetryableFault: (e) => retryable.push(e),
    });
    expect(terminal).toHaveLength(1);
    expect(retryable).toHaveLength(0);
  });

  /**
   * A CONSUMER-side persistence failure is terminal even though it is
   * "transient" in the everyday sense. It is the class the fail-closed contract
   * is written for: evidence arrived and could not be durably held, so the wall
   * cannot claim its evidence channel works.
   */
  it("keeps a consumer persistence failure terminal", async () => {
    const { client } = fakeClient({ drain: [batch([drainEvent(3)])], ack: [undefined] });
    const throwingConsumer = {
      ingestCritical: async (): Promise<void> => {
        throw new Error("audit disk unavailable");
      },
    } as unknown as AuditConsumer;
    const terminal: Error[] = [];
    const retryable: Error[] = [];
    const result = await drainOnce(client, throwingConsumer, null, 256, undefined, (e) => terminal.push(e), {
      onRetryableFault: (e) => retryable.push(e),
    });
    expect(terminal).toHaveLength(1);
    expect(retryable).toHaveLength(0);
    expect(result.faultClass).toBe("terminal");
    // The cursor did NOT advance past the unsettled event, so the daemon
    // re-delivers it: no data is lost in this direction either.
    expect(result.nextAfterSeq).toBeNull();
  });
});
