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

import {
  CASTLE_WALL_AUDIT_LAYER,
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED,
} from "../constants.js";
import { canonicalize } from "../../mesh/canonical-json.js";
import type {
  CastleWallAuditEvent,
  CastleWallEventType,
} from "../audit/events.js";
import {
  verifyProducerSignature,
  type ProducerSignatureInput,
} from "./producer-signature.js";
import type { UnifiedInboxBridge } from "../../principal-policy/unified-inbox-bridge.js";
import { ingestCastleWallBlockedEgress } from "../../principal-policy/unified-inbox-producers.js";

/**
 * The set of event types that constitute *enforcement evidence* — the ones a
 * forged entry could use to fake a "the wall is doing its job" green light.
 * When a pinned producer key is configured, these REQUIRE a valid producer
 * signature; non-enforcement control events (handshake outcomes, ack/dup
 * diagnostics, etc.) are not gated by it.
 */
export const ENFORCEMENT_EVIDENCE_EVENT_TYPES: ReadonlySet<CastleWallEventType> =
  Object.freeze(
    new Set<CastleWallEventType>([
      "egress_blocked",
      "egress_allowed",
      "operator_decision",
    ])
  );

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
  /**
   * Count of enforcement-evidence events rejected because their producer
   * signature was missing or did not verify against the pinned producer key
   * (Slice L1, the load-bearing fail-closed counter). Each rejection records a
   * `producer_signature_rejected` audit entry.
   */
  producerSignatureRejections: number;
  /**
   * Count of enforcement-evidence events whose producer signature verified
   * against the pinned producer key. Diagnostic; lets the lifecycle layer
   * surface that the signed path is live.
   */
  producerSignatureAccepted: number;
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
  /**
   * The producer signature material the daemon attached to this event (Slice
   * L1). Present when the event was drained from a signing daemon; absent for
   * legacy/macOS/unsigned paths. When the consumer is configured with a pinned
   * producer key and the event is enforcement evidence, this MUST be present
   * and verify, or the event is rejected (fail closed).
   */
  producer?: ProducerSignatureInput;
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
    producerSignatureRejections: 0,
    producerSignatureAccepted: 0,
  };
  private lastAckedSeq: number | null = null;
  private lastEventCanonicalHash: string | null = null;
  /**
   * The TOFU-pinned producer public key (base64url-no-pad, 32 raw bytes). When
   * set, enforcement-evidence events MUST carry a producer signature that
   * verifies against this key (fail closed). When null, the consumer accepts on
   * the legacy channel-authenticity basis and stamps the entry as
   * `channel_authenticated_unsigned` — honest about NOT being per-producer
   * authenticated.
   */
  private readonly pinnedProducerKeyB64url: string | null;
  /**
   * Max age (ms) of a signed enforcement event relative to `now()` before it is
   * rejected as stale. The signature binds `captured_at_unix_ms`, so a captured
   * past signed frame replayed after a process restart (when `lastAckedSeq`
   * resets to null) would otherwise re-arm the wall. The freshness window
   * closes that out-of-process replay. 0/undefined disables the check. Also
   * rejects events dated unreasonably far in the future (clock-skew / forged
   * timestamp). (codex L1 HIGH #3.)
   */
  private readonly producerSigMaxAgeMs: number;
  private readonly producerSigMaxSkewMs: number;
  private readonly now: () => number;

  constructor(
    private readonly sink: AuditSink,
    private readonly inboxBridge?: UnifiedInboxBridge,
    options?: {
      pinnedProducerKeyB64url?: string | null;
      /** Reject signed enforcement events older than this many ms. Default 5 min. */
      producerSigMaxAgeMs?: number;
      /** Reject signed enforcement events dated more than this far ahead. Default 1 min. */
      producerSigMaxSkewMs?: number;
      /** Clock injection for tests. */
      now?: () => number;
    },
  ) {
    this.pinnedProducerKeyB64url = options?.pinnedProducerKeyB64url ?? null;
    this.producerSigMaxAgeMs = options?.producerSigMaxAgeMs ?? 5 * 60 * 1000;
    this.producerSigMaxSkewMs = options?.producerSigMaxSkewMs ?? 60 * 1000;
    this.now = options?.now ?? Date.now;
  }

  /** Whether per-producer signature enforcement is active for this consumer. */
  isProducerSignatureEnforced(): boolean {
    return this.pinnedProducerKeyB64url !== null;
  }

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

    // Slice L1 producer-authenticity gate. When a pinned producer key is
    // configured and this event is enforcement evidence, the daemon's per-event
    // signature MUST verify against the pinned key before we accept the event
    // as evidence. This is the load-bearing fail-closed property: an in-process
    // forger can mint the `cw_source` marker but cannot mint a valid signature
    // over `seq ‖ timestamp ‖ canonical-bytes` against the daemon's key, and a
    // replayed past signature is bound to a different seq so it does not verify.
    const sigOutcome = this.evaluateProducerSignature(envelope);
    if (sigOutcome.kind === "rejected") {
      this.stats.producerSignatureRejections += 1;
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "producer_signature_rejected",
        envelope.event.fortress_id ?? "unknown",
        {
          reason: sigOutcome.reason,
          event_type: envelope.event.event_type,
          seq: envelope.event.details.seq,
        },
        "failure"
      );
      await this.sink.flush();
      // Fail closed: do NOT persist as enforcement evidence, do NOT advance the
      // chain. We DO ACK so the daemon stops re-delivering a packet we have
      // permanently refused; the refusal is durably recorded above for audit.
      await this.tryAck(envelope, "producer_signature_rejected");
      throw new AuditChainError(sigOutcome.reason);
    }
    if (sigOutcome.kind === "verified") {
      this.stats.producerSignatureAccepted += 1;
    }

    try {
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        envelope.event.event_type,
        envelope.event.fortress_id,
        buildDetailsForEvent(envelope.event, sigOutcome),
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
    void this.sink.append(
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

  /**
   * Decide whether an event's producer signature is acceptable, and with what
   * evidence basis. Returns one of:
   *
   *   - `verified` — a producer signature verified against the pinned key
   *     (per-producer authenticated; the forgery hole is closed for this entry).
   *   - `unsigned` — accepted on the legacy channel-authenticity basis, either
   *     because no pinned producer key is configured OR because the event is
   *     not enforcement evidence (control/diagnostic events are not gated).
   *   - `rejected` — enforcement evidence that, with a pinned producer key
   *     configured, lacked a valid signature. The caller fails closed.
   */
  private evaluateProducerSignature(
    envelope: CriticalEventEnvelope
  ): SignatureOutcome {
    const isEnforcementEvidence = ENFORCEMENT_EVIDENCE_EVENT_TYPES.has(
      envelope.event.event_type
    );
    // No pinned key, or a non-evidence event: accept on the channel basis.
    if (this.pinnedProducerKeyB64url === null || !isEnforcementEvidence) {
      return { kind: "unsigned" };
    }
    if (!envelope.producer) {
      return { kind: "rejected", reason: "producer_signature_absent" };
    }
    // Parse the signed WAL body. The signature (verified below) is over THIS
    // body; once verified, the body — not the attacker-controllable
    // `envelope.event` — is the authoritative source for the persisted
    // evidence. We bind only the one cross-shape invariant the persist path
    // needs: the signed `operation` must map to the `event_type` slot the entry
    // is filed under (so a verified "allow" body can't be filed as a "block").
    // Every OTHER evidence field (agent, destination, decision provenance, rule
    // id) is taken FROM the signed body in `buildDetailsForEvent`, which
    // structurally eliminates the staple/strip/fabricate attack class — there is
    // nothing to mismatch because we do not trust the event's fields for signed
    // evidence. (codex L1 findings R2–R5.)
    const parsed = parseSignedBody(envelope.producer.eventCanonicalJson);
    if (parsed.kind === "error") {
      return { kind: "rejected", reason: parsed.reason };
    }
    const mappedEventType = WAL_OPERATION_TO_EVENT_TYPE[parsed.operation];
    if (mappedEventType === undefined || mappedEventType !== envelope.event.event_type) {
      return {
        kind: "rejected",
        reason: "producer_signed_body_operation_event_type_mismatch",
      };
    }
    // expectedKeyId is left to the verifier's default (the v1 key id); a
    // mismatched key id fails closed there.
    const verdict = verifyProducerSignature(
      envelope.producer,
      this.pinnedProducerKeyB64url
    );
    if (!verdict.ok) {
      return { kind: "rejected", reason: verdict.reason };
    }
    // Defense in depth: the daemon signs over the seq/timestamp it serves, and
    // the consumer's chain already rejects seq regressions; require the signed
    // seq to match the event's own seq so a signature lifted from one event
    // cannot be stapled onto a different-seq event.
    const eventSeq = envelope.event.details.seq;
    if (typeof eventSeq === "number" && eventSeq !== envelope.producer.seq) {
      return { kind: "rejected", reason: "producer_signature_seq_mismatch" };
    }
    // Freshness gate (anti-replay across process restart). The signature is
    // authentic, but a captured PAST signed frame could be replayed after a
    // restart resets the in-memory seq watermark. Reject events whose bound
    // timestamp is too old or implausibly far in the future.
    if (this.producerSigMaxAgeMs > 0) {
      const ageMs = this.now() - envelope.producer.capturedAtUnixMs;
      if (ageMs > this.producerSigMaxAgeMs) {
        return { kind: "rejected", reason: "producer_signature_stale" };
      }
      if (ageMs < -this.producerSigMaxSkewMs) {
        return { kind: "rejected", reason: "producer_signature_future_dated" };
      }
    }
    return {
      kind: "verified",
      signatureB64url: envelope.producer.signatureB64url as string,
      keyId: envelope.producer.keyId as string,
      signedBody: parsed.body,
    };
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

/**
 * Outcome of the producer-signature evaluation for one event.
 *   - `verified`: a producer signature verified against the pinned key.
 *   - `unsigned`: accepted on the channel-authenticity basis (no pinned key,
 *     or a non-enforcement-evidence event).
 *   - `rejected`: enforcement evidence missing a valid signature; fail closed.
 */
type SignatureOutcome =
  | {
      kind: "verified";
      signatureB64url: string;
      keyId: string;
      /** The authenticated WAL body; the source of truth for persisted evidence. */
      signedBody: Record<string, unknown>;
    }
  | { kind: "unsigned" }
  | { kind: "rejected"; reason: string };

/**
 * Map from the daemon's WAL `operation` tag to the consumer's `event_type` for
 * the enforcement-evidence verdicts. Mirrors `operation_for_verdict` in the
 * daemon (`castle-wall-daemon/src/policy.rs`). Used to corroborate that a
 * signed WAL body describes the same enforcement outcome as the event we
 * persist, across the two distinct JSON shapes.
 */
const WAL_OPERATION_TO_EVENT_TYPE: Readonly<Record<string, CastleWallEventType>> =
  Object.freeze({
    egress_approved: "egress_allowed",
    egress_blocked: "egress_blocked",
    egress_pending: "operator_decision",
  });

/**
 * Corroborate that the signed WAL body describes the same enforcement event we
 * are about to persist. Returns `null` when bound, or a rejection reason.
 *
 * Parse + structurally validate the daemon's signed WAL `AuditEntry` body. On
 * success the caller verifies the signature over it and then treats this body
 * as the AUTHORITATIVE evidence (every persisted evidence field is taken from
 * here, not from the attacker-controllable `CastleWallAuditEvent`). That is why
 * there is no field-by-field "bind against the event" comparison: we don't
 * trust the event's fields for signed evidence, so there is nothing to staple
 * onto.
 */
function parseSignedBody(
  signedCanonicalJson: string
):
  | { kind: "ok"; body: Record<string, unknown>; operation: string }
  | { kind: "error"; reason: string } {
  let body: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(signedCanonicalJson);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { kind: "error", reason: "producer_signed_body_unparseable" };
    }
    body = parsed as Record<string, unknown>;
  } catch {
    return { kind: "error", reason: "producer_signed_body_unparseable" };
  }
  if (body.layer !== CASTLE_WALL_AUDIT_LAYER) {
    return { kind: "error", reason: "producer_signed_body_layer_mismatch" };
  }
  const operation = body.operation;
  if (typeof operation !== "string") {
    return { kind: "error", reason: "producer_signed_body_missing_operation" };
  }
  return { kind: "ok", body, operation };
}

/** Build the `details` payload from an event, omitting redundant top-level fields. */
function buildDetailsForEvent(
  event: CastleWallAuditEvent,
  signature: SignatureOutcome
): Record<string, unknown> {
  // For a PRODUCER-SIGNED entry the authoritative evidence is the SIGNED BODY,
  // not the attacker-controllable `CastleWallAuditEvent`. We persist the signed
  // body's own `details` (agent_id, dest_*, decision_provenance, rule_id_matched,
  // ...) plus the verified signature. The event's chain bookkeeping fields (seq,
  // prior_sha256_hex) are preserved from `event.details` because the WAL chain
  // validation upstream already authenticated them and they are not part of the
  // signed body. This structurally defeats stapling/stripping/fabrication: no
  // evidence field is sourced from the untrusted event. (codex L1 R2–R5.)
  if (signature.kind === "verified") {
    const signedDetails =
      signature.signedBody.details !== null &&
      typeof signature.signedBody.details === "object" &&
      !Array.isArray(signature.signedBody.details)
        ? (signature.signedBody.details as Record<string, unknown>)
        : {};
    const out: Record<string, unknown> = { ...signedDetails };
    // Preserve the chain bookkeeping the upstream WAL-chain check authenticated.
    if (Object.prototype.hasOwnProperty.call(event.details, "seq")) {
      out.seq = event.details.seq;
    }
    if (Object.prototype.hasOwnProperty.call(event.details, "prior_sha256_hex")) {
      out.prior_sha256_hex = event.details.prior_sha256_hex;
    }
    out[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] = signature.signatureB64url;
    out[CASTLE_WALL_PRODUCER_KID_DETAIL_KEY] = signature.keyId;
    out[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY] =
      CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED;
    out[CASTLE_WALL_AUDIT_PROVENANCE_KEY] = CASTLE_WALL_AUDIT_PROVENANCE_VALUE;
    return out;
  }
  // Unsigned / channel-authenticated basis: persist the event fields, but a
  // forged `cw_producer_sig`/`cw_producer_kid` in the event's details must NEVER
  // survive as if verified, and the basis is stamped honestly.
  const out: Record<string, unknown> = { ...event.details };
  if (event.agent !== null) out.agent = event.agent;
  if (event.destination !== null) out.destination = event.destination;
  if (event.decision !== null) out.decision = event.decision;
  if (event.rule_id !== null) out.rule_id = event.rule_id;
  delete out[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY];
  delete out[CASTLE_WALL_PRODUCER_KID_DETAIL_KEY];
  out[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY] =
    CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED;
  // Provenance LAST, so a forged `event.details.cw_source` cannot survive into
  // the stored entry. Consumers reasoning about "actual enforcement" require
  // this marker (see CASTLE_WALL_AUDIT_PROVENANCE_KEY).
  out[CASTLE_WALL_AUDIT_PROVENANCE_KEY] = CASTLE_WALL_AUDIT_PROVENANCE_VALUE;
  return out;
}

function computeCanonicalHash(event: CastleWallAuditEvent): string {
  return createHash("sha256").update(canonicalize(event), "utf8").digest("hex");
}
