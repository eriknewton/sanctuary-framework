/**
 * Audit consumer: drains the daemon's WAL by accepting `audit_emit`
 * notifications, validating shape, and folding into Sanctuary's existing
 * encrypted audit log via `AuditLog.append()` + `flush()`.
 *
 * Per scope-lock §8 Option D + B3: critical events go through synchronous
 * append + flush + ACK; metric batches go through one-way notifications
 * with no per-event ACK.
 *
 * PR 2a ships the consumer logic against an `AuditSink` interface so unit
 * tests can run without standing up the full Sanctuary AuditLog. PR 4
 * wires the real `AuditLog.append` connection.
 */

import { createHash } from "node:crypto";

import { CASTLE_WALL_AUDIT_LAYER } from "../constants.js";
import { canonicalize } from "../../mesh/canonical-json.js";
import type {
  CastleWallAuditEvent,
  CastleWallEventType,
} from "../audit/events.js";

/** Shape the consumer pushes into; `AuditLog.append` matches structurally. */
export interface AuditSink {
  /**
   * Append one entry. The implementer is responsible for the actual
   * encrypted-log persistence; this consumer only validates shape and
   * preserves ordering.
   */
  append(
    layer: "l1",
    operation: string,
    identityId: string,
    details?: Record<string, unknown>,
    result?: "success" | "failure"
  ): void;
  /** Block until all in-flight `append` calls have settled. */
  flush(): Promise<void>;
}

/** A single critical-event ACK callback the consumer invokes after persistence. */
export type CriticalAckCallback = () => Promise<void>;

/** Diagnostic counters surfaced for the lifecycle layer to expose. */
export interface AuditConsumerStats {
  acceptedCriticalEvents: number;
  acceptedMetricBatches: number;
  rejectedEvents: number;
}

export class AuditChainError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "AuditChainError";
  }
}

/** A single critical event awaiting persistence + ACK. */
export interface CriticalEventEnvelope {
  event: CastleWallAuditEvent;
  ack: CriticalAckCallback;
}

/** Metric-batch entry shape, mirroring the IPC message. */
export interface MetricBatch {
  windowStart: string;
  windowEnd: string;
  byDestination: ReadonlyArray<{
    host: string | null;
    port: number;
    protocol: "tcp" | "udp";
    agent_id: string;
    allowed_count: number;
    blocked_count: number;
  }>;
}

/** Set of event types accepted in PR 2a. PR 5 may extend, never remove. */
export const ACCEPTED_EVENT_TYPES: ReadonlySet<CastleWallEventType> = Object.freeze(
  new Set<CastleWallEventType>([
    "egress_blocked",
    "egress_allowed",
    "operator_decision",
    "policy_loaded",
    "policy_validation_failed",
    "filter_started",
    "filter_stopped",
    "filter_crashed",
    "queue_saturated",
    "no_wall_engaged",
    "no_wall_expired",
    "wal_overflow",
    "external_firewall_clobber",
    "egress_metric_batch",
  ])
);

/**
 * Validate an inbound event. Rejects events with the wrong layer or with
 * unknown event_type. Returns null on success or a reason string on failure.
 */
export function validateEvent(event: CastleWallAuditEvent): string | null {
  if (event.layer !== CASTLE_WALL_AUDIT_LAYER) {
    return `unexpected layer: ${String(event.layer)}`;
  }
  if (typeof event.event_type !== "string") {
    return "missing event_type";
  }
  if (!ACCEPTED_EVENT_TYPES.has(event.event_type)) {
    return `unknown event_type: ${event.event_type}`;
  }
  if (typeof event.fortress_id !== "string" || event.fortress_id.length === 0) {
    return "missing fortress_id";
  }
  if (typeof event.timestamp !== "string" || event.timestamp.length === 0) {
    return "missing timestamp";
  }
  return null;
}

/** The stateful consumer the lifecycle layer instantiates. */
export class AuditConsumer {
  private stats: AuditConsumerStats = {
    acceptedCriticalEvents: 0,
    acceptedMetricBatches: 0,
    rejectedEvents: 0,
  };
  private lastAckedSeq: number | null = null;
  private lastEventCanonicalHash: string | null = null;

  constructor(private readonly sink: AuditSink) {}

  /** Persist a critical event then invoke the daemon-supplied ACK callback. */
  async ingestCritical(envelope: CriticalEventEnvelope): Promise<void> {
    const reason = validateEvent(envelope.event);
    if (reason) {
      this.stats.rejectedEvents += 1;
      this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "audit_event_rejected",
        envelope.event.fortress_id ?? "unknown",
        { reason, event_canonical: canonicalize(envelope.event) },
        "failure"
      );
      // ACK rejected events too; the daemon should not re-deliver malformed.
      await envelope.ack();
      return;
    }
    const chainFailure = this.validateWalChain(envelope.event);
    if (chainFailure) {
      await this.emitVerificationFailure(chainFailure, envelope.event);
      throw new AuditChainError(chainFailure);
    }
    this.sink.append(
      CASTLE_WALL_AUDIT_LAYER,
      envelope.event.event_type,
      envelope.event.fortress_id,
      buildDetailsForEvent(envelope.event),
      "success"
    );
    await this.sink.flush();
    await envelope.ack();
    this.lastAckedSeq = Number(envelope.event.details.seq);
    this.lastEventCanonicalHash = computeCanonicalHash(envelope.event);
    this.stats.acceptedCriticalEvents += 1;
  }

  /** Append one batch entry per scope-lock §8 metric-event shape. */
  ingestMetricBatch(fortressId: string, batch: MetricBatch): void {
    this.sink.append(
      CASTLE_WALL_AUDIT_LAYER,
      "egress_metric_batch",
      fortressId,
      {
        window_start: batch.windowStart,
        window_end: batch.windowEnd,
        by_destination: batch.byDestination,
      },
      "success"
    );
    this.stats.acceptedMetricBatches += 1;
  }

  getStats(): AuditConsumerStats {
    return { ...this.stats };
  }

  getWalChainState(): { lastAckedSeq: number | null; lastEventCanonicalHash: string | null } {
    return {
      lastAckedSeq: this.lastAckedSeq,
      lastEventCanonicalHash: this.lastEventCanonicalHash,
    };
  }

  private validateWalChain(event: CastleWallAuditEvent): string | null {
    const hasSeq = Object.prototype.hasOwnProperty.call(event.details, "seq");
    const hasPriorHash = Object.prototype.hasOwnProperty.call(
      event.details,
      "prior_sha256_hex"
    );
    const seq = event.details.seq;
    const priorHash = event.details.prior_sha256_hex;
    if (
      !hasSeq ||
      typeof seq !== "number" ||
      !Number.isSafeInteger(seq) ||
      !hasPriorHash ||
      !(typeof priorHash === "string" || priorHash === null)
    ) {
      return "chain_fields_missing";
    }
    if (this.lastAckedSeq !== null && seq <= this.lastAckedSeq) {
      return "seq_regression";
    }
    if (this.lastEventCanonicalHash !== null && priorHash !== this.lastEventCanonicalHash) {
      return "wal_chain_verification_failed";
    }
    return null;
  }

  private async emitVerificationFailure(
    reason: string,
    event: CastleWallAuditEvent
  ): Promise<void> {
    this.stats.rejectedEvents += 1;
    this.sink.append(
      CASTLE_WALL_AUDIT_LAYER,
      "wal_chain_verification_failed",
      event.fortress_id ?? "unknown",
      { reason, event_canonical: canonicalize(event) },
      "failure"
    );
    await this.sink.flush();
  }
}

/** Build the `details` payload from an event, omitting redundant top-level fields. */
function buildDetailsForEvent(event: CastleWallAuditEvent): Record<string, unknown> {
  const out: Record<string, unknown> = { ...event.details };
  if (event.agent !== null) out.agent = event.agent;
  if (event.destination !== null) out.destination = event.destination;
  if (event.decision !== null) out.decision = event.decision;
  if (event.rule_id !== null) out.rule_id = event.rule_id;
  return out;
}

function computeCanonicalHash(event: CastleWallAuditEvent): string {
  return createHash("sha256").update(canonicalize(event), "utf8").digest("hex");
}
