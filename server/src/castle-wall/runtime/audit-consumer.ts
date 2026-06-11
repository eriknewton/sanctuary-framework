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
import type { UnifiedInboxBridge } from "../../principal-policy/unified-inbox-bridge.js";
import { ingestCastleWallBlockedEgress } from "../../principal-policy/unified-inbox-producers.js";

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
  ): void | Promise<void>;
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
  /**
   * Count of duplicate critical events the consumer has dropped (post-ACK-
   * failure replays from the daemon) per finding #92. Audit log records
   * each drop as a `critical_event_duplicate_dropped` entry.
   */
  duplicatesDropped: number;
  /**
   * Count of ACK failures observed per finding #92. Audit log records each
   * as a `critical_event_ack_failed` entry; the daemon retries and the
   * duplicate path closes the loop.
   */
  ackFailures: number;
  /** Count of critical events withheld from ACK because persistence failed. */
  persistenceFailures: number;
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
    "provider_unbound",
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
    duplicatesDropped: 0,
    ackFailures: 0,
    persistenceFailures: 0,
  };
  private lastAckedSeq: number | null = null;
  private lastEventCanonicalHash: string | null = null;

  constructor(
    private readonly sink: AuditSink,
    private readonly inboxBridge?: UnifiedInboxBridge,
  ) {}

  /**
   * Persist a critical event then invoke the daemon-supplied ACK callback.
   *
   * Failure modes addressed by full-sweep #92:
   *
   *   - **ACK failure (transport).** The IPC channel back to the daemon may
   *     fail after data is durably persisted. We update consumer state
   *     BEFORE invoking `ack()` (the flushed event is already on disk; the
   *     consumer's view of the chain must reflect that). The ACK itself is
   *     wrapped in a try-catch. On failure, we emit a
   *     `critical_event_ack_failed` audit entry and continue without
   *     rethrowing. The daemon will retry with the same event; the retry
   *     path below handles it as a duplicate replay.
   *
   *   - **Duplicate replay.** Daemon retried after a prior ACK failure.
   *     `validateWalChain` distinguishes this from a genuine `seq_regression`
   *     by comparing the canonical hash of the incoming event against the
   *     last persisted hash at the same seq. On match, we drop the duplicate
   *     payload and emit a `critical_event_duplicate_dropped` diagnostic
   *     entry; the daemon receives a fresh ACK so it stops retrying. Audit
   *     log integrity is preserved (no silent duplicate entries).
   */
  async ingestCritical(envelope: CriticalEventEnvelope): Promise<void> {
    const reason = validateEvent(envelope.event);
    if (reason) {
      this.stats.rejectedEvents += 1;
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "audit_event_rejected",
        envelope.event.fortress_id ?? "unknown",
        { reason, event_canonical: canonicalize(envelope.event) },
        "failure"
      );
      await this.sink.flush();
      // ACK rejected events too; the daemon should not re-deliver malformed.
      await this.tryAck(envelope, "audit_event_rejected");
      return;
    }
    const chainOutcome = this.validateWalChain(envelope.event);
    if (chainOutcome.kind === "duplicate_replay") {
      // Daemon retried a critical event whose persistence completed but whose
      // ACK never landed. Drop the payload silently (no double-append) and
      // record the diagnostic entry so an auditor can see why the chain has a
      // marker without a duplicate event.
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "critical_event_duplicate_dropped",
        envelope.event.fortress_id,
        {
          seq: envelope.event.details.seq,
          event_type: envelope.event.event_type,
        },
        "success"
      );
      await this.sink.flush();
      this.stats.duplicatesDropped += 1;
      await this.tryAck(envelope, "critical_event_duplicate_dropped");
      return;
    }
    if (chainOutcome.kind === "error") {
      await this.emitVerificationFailure(chainOutcome.reason, envelope.event);
      throw new AuditChainError(chainOutcome.reason);
    }
    try {
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        envelope.event.event_type,
        envelope.event.fortress_id,
        buildDetailsForEvent(envelope.event),
        "success"
      );
      if (this.inboxBridge && envelope.event.event_type === "egress_blocked") {
        ingestCastleWallBlockedEgress({
          bridge: this.inboxBridge,
          event: envelope.event,
        });
        await this.sink.append(
          CASTLE_WALL_AUDIT_LAYER,
          "castle_wall_blocked_egress",
          envelope.event.fortress_id,
          {
            event_type: envelope.event.event_type,
            seq: envelope.event.details.seq,
          },
          "success",
        );
      }
      await this.sink.flush();
    } catch (err) {
      await this.emitPersistenceFailure(err, envelope.event);
      throw err;
    }
    // Update state BEFORE the ACK call. The event is now durably persisted;
    // a transport-layer ACK failure must NOT leave the consumer's chain view
    // out of sync with what is actually on disk.
    this.lastAckedSeq = Number(envelope.event.details.seq);
    this.lastEventCanonicalHash = computeCanonicalHash(envelope.event);
    this.stats.acceptedCriticalEvents += 1;
    await this.tryAck(envelope, envelope.event.event_type);
  }

  /**
   * Invoke the daemon-supplied ACK callback. On failure, emit a
   * `critical_event_ack_failed` audit entry and continue without rethrowing.
   * The data is already durable; the daemon will retry; the retry path
   * recognizes the duplicate. This is the structural close of finding #92.
   */
  private async tryAck(
    envelope: CriticalEventEnvelope,
    operationContext: string
  ): Promise<void> {
    try {
      await envelope.ack();
    } catch (err) {
      this.stats.ackFailures += 1;
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "critical_event_ack_failed",
        envelope.event.fortress_id ?? "unknown",
        {
          seq: envelope.event.details?.seq,
          event_type: envelope.event.event_type,
          ack_for: operationContext,
          reason: err instanceof Error ? err.message : String(err),
        },
        "failure"
      );
      await this.sink.flush();
    }
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

  /**
   * Classify an inbound critical event against the WAL chain.
   *
   * Returns:
   *   - `{ kind: "ok" }` for fresh, well-chained events.
   *   - `{ kind: "duplicate_replay" }` for daemon retries of an already-
   *     persisted event (same seq + same canonical hash). #92 path.
   *   - `{ kind: "error", reason }` for chain corruption: missing fields,
   *     genuine seq regression with different content, or prior-hash
   *     mismatch.
   */
  private validateWalChain(
    event: CastleWallAuditEvent
  ):
    | { kind: "ok" }
    | { kind: "duplicate_replay" }
    | { kind: "error"; reason: string } {
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
      return { kind: "error", reason: "chain_fields_missing" };
    }
    if (this.lastAckedSeq !== null && seq <= this.lastAckedSeq) {
      // Distinguish duplicate replay (same seq + same content) from a
      // genuine regression (same seq + different content). A daemon retry
      // after ACK failure produces the former; corruption or a rolled-back
      // daemon WAL produces the latter.
      if (
        seq === this.lastAckedSeq &&
        this.lastEventCanonicalHash !== null &&
        computeCanonicalHash(event) === this.lastEventCanonicalHash
      ) {
        return { kind: "duplicate_replay" };
      }
      return { kind: "error", reason: "seq_regression" };
    }
    if (this.lastEventCanonicalHash !== null && priorHash !== this.lastEventCanonicalHash) {
      return { kind: "error", reason: "wal_chain_verification_failed" };
    }
    return { kind: "ok" };
  }

  private async emitVerificationFailure(
    reason: string,
    event: CastleWallAuditEvent
  ): Promise<void> {
    this.stats.rejectedEvents += 1;
    await this.sink.append(
      CASTLE_WALL_AUDIT_LAYER,
      "wal_chain_verification_failed",
      event.fortress_id ?? "unknown",
      { reason, event_canonical: canonicalize(event) },
      "failure"
    );
    await this.sink.flush();
  }

  private async emitPersistenceFailure(
    err: unknown,
    event: CastleWallAuditEvent
  ): Promise<void> {
    this.stats.persistenceFailures += 1;
    try {
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "critical_event_persistence_failed",
        event.fortress_id ?? "unknown",
        {
          seq: event.details?.seq,
          event_type: event.event_type,
          reason: err instanceof Error ? err.message : String(err),
        },
        "failure"
      );
      await this.sink.flush();
    } catch {
      // The primary safety property is fail-closed: no ACK and no chain
      // advance. If the audit sink itself is unavailable, surface the
      // original persistence failure to the caller.
    }
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
