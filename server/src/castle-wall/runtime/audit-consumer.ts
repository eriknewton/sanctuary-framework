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
  CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY,
  CASTLE_WALL_CHAIN_BASIS_EVENT_CANONICAL,
  CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
  CASTLE_WALL_CHAIN_PRIOR_UNCONSUMED_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED,
  CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY,
  CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
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
import { protectionSubjectFromMacOSAuditToken } from "../subject-binding.js";
import type { UnifiedInboxBridge } from "../../principal-policy/unified-inbox-bridge.js";
import { ingestCastleWallBlockedEgress } from "../../principal-policy/unified-inbox-producers.js";

/**
 * The set of event types that constitute *enforcement evidence* - the ones a
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

/**
 * The consumer's own last persisted chain position, read back from LOCAL
 * storage at startup. This is the only input the startup anchor restore
 * accepts: the migrated anchor is recomputed from data we already persisted and
 * already verified, with ZERO incoming-event trust (the #1096 gate refuted
 * every wire-driven recovery variant as attacker-steerable).
 */
export type PersistedChainAnchor =
  | {
      kind: "persisted";
      /** The `details.seq` of the last accepted chain-participating entry. */
      seq: number;
      /**
       * The verbatim producer-signed canonical body persisted with that entry
       * (`cw_producer_signed_canonical`), or null when the entry was accepted
       * on the channel-unsigned basis (that path deliberately strips the
       * signed body, so local recomputation is impossible).
       */
      signedCanonicalJson: string | null;
      /**
       * The rest of the persisted `ProducerSignatureInput`
       * (`cw_producer_sig` / `cw_producer_kid` / `cw_producer_captured_at_ms`).
       * The restore RE-VERIFIES the signature over these before adopting the
       * anchor, so a persisted row is never trusted because of where it sits
       * or what marker it carries — only because the pinned producer key
       * signed those exact bytes.
       */
      signatureB64url: string | null;
      keyId: string | null;
      capturedAtUnixMs: number | null;
      /**
       * The recorded chain basis (`cw_chain_basis`), or null for entries
       * written before the basis was recorded — which by construction means
       * the legacy `event_canonical` basis.
       */
      chainBasis: string | null;
      /** Identity to attribute restore/migration audit records to. */
      identityId: string;
    }
  | {
      /**
       * Local history exists but cannot anchor a chain (e.g. the audit log
       * reports integrity findings). The consumer latches the loud stuck state
       * rather than guessing.
       */
      kind: "unavailable";
      reason: string;
    };

/**
 * Async reader for the consumer's persisted chain position. Returns null when
 * no chain-participating entry has ever been persisted (fresh install →
 * genesis bootstrap). Wire it with {@link buildChainAnchorSourceFromAuditLog}.
 */
export type ChainAnchorSource = () => Promise<PersistedChainAnchor | null>;

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
  /**
   * Subject-binding context for producer-signed verdicts. For macOS extension
   * verdicts, the signed WAL body carries the raw audit token and the local
   * runtime supplies the fortress id. For drain-shaped events whose signed WAL
   * body already carries a canonical `identity_id`, the persist path uses that
   * signed identity directly. A verified signature without one of these bindings
   * is rejected before persistence so signed evidence can never inherit the
   * unsigned envelope identity.
   */
  producerSubjectBinding?:
    | {
        kind: "macos_audit_token";
        fortressId: string;
      }
    | {
        kind: "signed_identity_id";
      };
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
  /**
   * The chain anchor: for producer-signed entries this is
   * `sha256(utf8(cw_producer_signed_canonical))` — the exact bytes every
   * producer hashes into its own `prior_sha256_hex` (Rust `audit.rs`, macOS
   * flow + availability paths). Anchoring on a locally-reconstructed
   * `CastleWallAuditEvent` hash forked the chain on every deployment because
   * no producer ever hashed that shape (#1096 root cause).
   */
  private lastEventChainHash: string | null = null;
  /**
   * Startup anchor restore state. `restorePromise` memoizes an in-flight
   * restore so concurrent first ingests share one attempt; a FAILED attempt
   * clears it so a transient storage fault is retried (fail-closed in the
   * meantime: the thrown error keeps the event unsettled, so nothing is
   * accepted or ACKed on an unrestored chain).
   */
  private restoreSettled = false;
  private restorePromise: Promise<void> | null = null;
  /**
   * Latched when local history exists but cannot anchor the chain (last
   * accepted entry unsigned, malformed anchor record, or audit-log integrity
   * findings). While latched, every critical event is refused UNSETTLED (no
   * persist, no chain advance, no ACK — an ACK would let the daemon truncate
   * its WAL through evidence we never accepted). A stuck chain an operator
   * must clear is honest; any self-healing fallback here would have to trust
   * the wire, which is exactly what the #1096 gate refuted.
   */
  private chainMigrationUnavailableReason: string | null = null;
  /**
   * FIX 2 (codex CRITICAL - defense in depth against acking past an unpersisted
   * event). Set to the seq of an event that VALIDATED + chained cleanly but then
   * FAILED to persist durably (a transient disk/transport fault), so no ack was
   * sent and the chain anchor did not advance. While this is non-null the
   * consumer owes that seq: it must NOT bootstrap-accept any LATER event, because
   * doing so would advance + ack past the un-anchored event and let the daemon
   * truncate its WAL through the gap (silent audit data loss). Cleared the moment
   * any event persists successfully (including a retry of the same seq).
   *
   * This is distinct from a REFUSED forgery: a forgery is correctly never
   * persisted, but the consumer never OWED that seq (the daemon's own WAL chain
   * is intact), so a following genuine event legitimately continues - we do not
   * set this on a signature/chain rejection, only on a persistence failure.
   */
  private pendingUnpersistedSeq: number | null = null;
  /**
   * The TOFU-pinned producer public key (base64url-no-pad, 32 raw bytes). When
   * set, enforcement-evidence events MUST carry a producer signature that
   * verifies against this key (fail closed). When null, the consumer accepts on
   * the legacy channel-authenticity basis and stamps the entry as
   * `channel_authenticated_unsigned` - honest about NOT being per-producer
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
  private readonly chainAnchorSource: ChainAnchorSource | undefined;
  private readonly chainContinuity: "complete" | "producer_subset";

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
      /**
       * Reader for the consumer's own last persisted chain position. When set
       * (and a pinned producer key is configured), the first ingest restores
       * the anchor from LOCAL storage before any incoming event is considered
       * — closing both the old-basis upgrade fork and the restart bootstrap
       * replay hole. When absent, the consumer bootstraps from null exactly as
       * before (path-less tests / legacy callers).
       */
      chainAnchorSource?: ChainAnchorSource;
      /**
       * How much of the producer's chain this consumer receives.
       *
       * `complete` (default): the consumer sees EVERY producer chain event
       * (the Linux drain walks the daemon's full WAL). A prior-hash mismatch
       * is a hard fork — real damage, chain stops, no self-heal.
       *
       * `producer_subset`: the consumer receives only a SUBSET of the
       * producer's chain by construction (the macOS extension signs flow
       * decisions AND availability reports into one shared seq/prior chain,
       * but only flow decisions arrive here — availability reports go to the
       * enforcement-availability store on their own delivery path). Prior-hash
       * contiguity across a gap is therefore UNVERIFIABLE locally, not
       * evidence of damage: continuity is enforced as verified producer
       * signature + strictly monotonic seq (the anti-replay primitive), the
       * prior hash is still asserted whenever the events are adjacent, and a
       * non-adjacent accept records `cw_chain_prior_unconsumed` on the
       * persisted entry so the audit trail never claims a continuity check it
       * could not perform. This is NOT the refuted fork recovery: there is no
       * threshold, no window, no re-anchor to a wire-chosen head — an
       * unverified or seq-regressing frame is rejected identically in both
       * modes, and the macOS ACK is a no-op so acceptance destroys nothing.
       */
      chainContinuity?: "complete" | "producer_subset";
    },
  ) {
    this.pinnedProducerKeyB64url = options?.pinnedProducerKeyB64url ?? null;
    this.producerSigMaxAgeMs = options?.producerSigMaxAgeMs ?? 5 * 60 * 1000;
    this.producerSigMaxSkewMs = options?.producerSigMaxSkewMs ?? 60 * 1000;
    this.now = options?.now ?? Date.now;
    this.chainAnchorSource = options?.chainAnchorSource;
    this.chainContinuity = options?.chainContinuity ?? "complete";
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
    // The anchor must be restored from LOCAL storage before the first incoming
    // event is even looked at: an event examined against a null anchor is
    // bootstrap-accepted, which is precisely the wire-trust the restore exists
    // to remove. A restore failure throws (unsettled — no persist, no ACK) so
    // a transient storage fault fails closed and is retried.
    await this.ensureChainAnchorRestored();
    if (this.chainMigrationUnavailableReason !== null) {
      // Latched stuck state (see the field's invariant comment): refuse
      // UNSETTLED so the daemon's WAL retains the evidence for operator repair.
      throw new AuditChainError("chain_migration_unavailable");
    }
    const reason = validateEvent(envelope.event);
    if (reason) {
      this.stats.rejectedEvents += 1;
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "audit_event_rejected",
        envelope.event.fortress_id ?? "unknown",
        { reason, event_canonical: safeCanonicalizeForDiagnostic(envelope.event) },
        "failure"
      );
      await this.sink.flush();
      // ACK rejected events too; the daemon should not re-deliver malformed.
      await this.tryAck(envelope, "audit_event_rejected");
      return;
    }
    // Anti-DoS (interaction with mesh #924): mesh `canonicalize()` now THROWS
    // on an unsafe integer (>= 2^53) anywhere in the value, and `event.details`
    // is a `Record<string, unknown>` spread verbatim from the attacker-
    // controllable daemon wire body (linux-audit-drain.ts). An event that
    // cannot be canonicalized is MALFORMED - it must be a SETTLED rejection
    // (recorded + ACKed, cursor advances, wall stays ARMED), exactly like any
    // other malformed event above, and it must NEVER be accepted/chained.
    // Computing the hash HERE, before the WAL-chain check or the persist call
    // even look at the event, means neither the chain's duplicate-hash
    // comparison nor the post-persist `lastEventChainHash` update below can
    // ever throw: both reuse this already-proven-canonicalizable hash instead
    // of re-deriving it from an event that might not be. A forger that stapled
    // a bogus integer onto an otherwise-valid event must settle the same way a
    // forger who stapled a bogus `event_type` does - never as an unsettled
    // fault that would wedge the drain loop into NOT-ARMED (see
    // linux-audit-drain.ts's cursor-is-the-discriminator ack/fault split).
    let canonicalHash: string;
    try {
      canonicalHash = computeCanonicalHash(envelope.event);
    } catch (err) {
      this.stats.rejectedEvents += 1;
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "audit_event_rejected",
        envelope.event.fortress_id ?? "unknown",
        {
          reason: "canonicalization_failed",
          detail: err instanceof Error ? err.message : String(err),
          // Record seq + event_type so an auditor can correlate WHICH WAL
          // position was suppressed - matching the sibling
          // `producer_signature_rejected` path. Both are read WITHOUT
          // canonicalize (the unrepresentable value lives elsewhere in
          // `details`), so reading them here stays throw-safe.
          seq: envelope.event.details?.seq,
          event_type: envelope.event.event_type,
        },
        "failure"
      );
      await this.sink.flush();
      // Settle + ACK exactly like the shape-validation rejection above: a
      // refused forgery must never stop the drain loop.
      await this.tryAck(envelope, "audit_event_rejected");
      return;
    }
    // Producer verification runs BEFORE the chain decision because the chain
    // basis for a verified event is the SIGNED BODY's own hash — the exact
    // bytes the producer hashed into its `prior_sha256_hex` — never a locally
    // reconstructed CastleWallAuditEvent (which no producer hashes; anchoring
    // on it forked the chain on every deployment, #1096 root cause).
    const sigOutcome = this.evaluateProducerSignature(envelope);
    if (sigOutcome.kind === "rejected") {
      await this.emitProducerSignatureRejected(envelope, sigOutcome.reason);
      throw new AuditChainError(sigOutcome.reason);
    }
    if (sigOutcome.kind === "verified") {
      this.stats.producerSignatureAccepted += 1;
    }
    const chainBasis = chainBasisFor(canonicalHash, sigOutcome);
    const chainOutcome = this.validateWalChain(
      envelope.event,
      chainBasis.hash,
      sigOutcome.kind === "verified",
    );
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
      // A fork now means real damage (crash mid-write, force-clear, rolled-back
      // producer WAL): stop the chain LOUDLY and do not self-heal. There is
      // deliberately no automatic recovery here — every wire-driven re-anchor
      // variant was gate-refuted as attacker-steerable (#1096 Q3/Q4), and a
      // stuck chain an operator must clear is honest where a self-healing one
      // an attacker can steer is not.
      await this.emitVerificationFailure(chainOutcome.reason, envelope.event);
      throw new AuditChainError(chainOutcome.reason);
    }

    const identityOutcome = persistedIdentityForEvent(envelope, sigOutcome);
    if (identityOutcome.kind === "rejected") {
      await this.emitProducerSignatureRejected(envelope, identityOutcome.reason);
      throw new AuditChainError(identityOutcome.reason);
    }

    try {
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        envelope.event.event_type,
        identityOutcome.identityId,
        buildDetailsForEvent(
          envelope,
          sigOutcome,
          chainBasis.kind,
          chainOutcome.kind === "ok_gap",
        ),
        resultForSignatureOutcome(sigOutcome),
      );
      if (this.inboxBridge && envelope.event.event_type === "egress_blocked") {
        ingestCastleWallBlockedEgress({
          bridge: this.inboxBridge,
          event: envelope.event,
        });
        await this.sink.append(
          CASTLE_WALL_AUDIT_LAYER,
          "castle_wall_blocked_egress",
          identityOutcome.identityId,
          {
            event_type: envelope.event.event_type,
            seq: envelope.event.details.seq,
          },
          "success",
        );
      }
      await this.sink.flush();
    } catch (err) {
      // FIX 2: remember the seq we owe so a LATER event cannot bootstrap-ack
      // past it (no WAL truncation through an unpersisted event). The cursor /
      // chain anchor are deliberately NOT advanced and no ack is sent.
      const failedSeq = Number(envelope.event.details.seq);
      if (Number.isSafeInteger(failedSeq)) this.pendingUnpersistedSeq = failedSeq;
      await this.emitPersistenceFailure(err, envelope.event);
      throw err;
    }
    // Update state BEFORE the ACK call. The event is now durably persisted;
    // a transport-layer ACK failure must NOT leave the consumer's chain view
    // out of sync with what is actually on disk.
    this.lastAckedSeq = Number(envelope.event.details.seq);
    // Reuse the basis hash selected up front in `ingestCritical` (already
    // proven derivable there); do NOT re-derive it here, which would
    // reintroduce a throw site after the event is already durably persisted.
    this.lastEventChainHash = chainBasis.hash;
    // The owed seq (if any) is now durable - clear the FIX 2 guard.
    this.pendingUnpersistedSeq = null;
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

  getWalChainState(): {
    lastAckedSeq: number | null;
    lastEventChainHash: string | null;
  } {
    return {
      lastAckedSeq: this.lastAckedSeq,
      lastEventChainHash: this.lastEventChainHash,
    };
  }

  /**
   * Restore the chain anchor from the consumer's OWN persisted history, once,
   * before the first incoming event is examined. See
   * {@link restoreChainAnchorOnce} for the migration semantics.
   */
  private ensureChainAnchorRestored(): Promise<void> {
    if (this.restoreSettled) return Promise.resolve();
    if (this.restorePromise === null) {
      this.restorePromise = this.restoreChainAnchorOnce().then(
        () => {
          this.restoreSettled = true;
        },
        (err) => {
          // A transient reader fault must be retryable, not latched: clear the
          // memo so the NEXT ingest attempts the restore again. The rethrow
          // keeps the current event unsettled (fail closed).
          this.restorePromise = null;
          throw err;
        },
      );
    }
    return this.restorePromise;
  }

  /**
   * One-time LOCAL anchor restore + basis migration.
   *
   * On first boot after the basis fix, persisted history was chained under the
   * legacy `event_canonical` basis, so a null-anchor bootstrap would either
   * fork against the first live event (stuck chain) or blindly accept it (the
   * restart replay hole). The bridge recomputes the anchor from the last
   * accepted entry's OWN persisted signed canonical body: verification
   * recomputes the commitment from stored, already-verified bytes — an anchor
   * claimed by an incoming frame is never trusted (every wire-driven recovery
   * variant was gate-refuted as attacker-steerable, #1096 Q3/Q4).
   *
   * "Was this written under the old basis" is a STORED FACT
   * (`cw_chain_basis` on the persisted entry), never an inference from
   * in-memory state (the Q5 defect); after one migration the stored basis on
   * new entries is `producer_signed_body`, so the migration is one-time by
   * construction. The migration record is flushed BEFORE the migrated anchor
   * is used.
   */
  private async restoreChainAnchorOnce(): Promise<void> {
    if (this.chainAnchorSource === undefined) return;
    if (this.pinnedProducerKeyB64url === null) {
      // Channel-unsigned basis: no signature can bind an anchor, so a restored
      // anchor would add nothing a forged frame could not also produce. The
      // chain keeps its documented channel-authenticated bootstrap semantics.
      return;
    }
    const anchor = await this.chainAnchorSource();
    if (anchor === null) {
      // No chain-participating history: genuine genesis bootstrap.
      return;
    }
    if (anchor.kind === "unavailable") {
      await this.latchMigrationUnavailable("unknown", anchor.reason);
      return;
    }
    if (!Number.isSafeInteger(anchor.seq) || anchor.seq < 0) {
      // Our own anchor record is malformed: that is damage, not a fresh chain.
      await this.latchMigrationUnavailable(
        anchor.identityId,
        "persisted_anchor_seq_invalid",
      );
      return;
    }
    if (anchor.signedCanonicalJson === null) {
      // The last accepted entry was channel-unsigned: its signed body was
      // deliberately stripped at persist time, so local recomputation is
      // impossible. Do NOT fall back to trusting the wire — surface the stuck
      // state loudly and leave repair to the operator.
      await this.latchMigrationUnavailable(
        anchor.identityId,
        "last_accepted_entry_unsigned",
      );
      return;
    }
    // DEFENSE IN DEPTH (gate finding, PR #1103 round 1): never adopt an anchor
    // because of WHERE a row sits or WHICH marker it carries. Any writer that
    // can append to this log could otherwise plant a chain position the
    // restore reads back as its own history. Re-verify the pinned producer's
    // signature over the persisted bytes, and require the signed seq to match
    // the row's seq, so the adopted anchor is cryptographically bound to a
    // real producer event. Freshness is deliberately NOT applied here: a
    // durable anchor is legitimately old, and the anti-replay property comes
    // from the restored monotonic seq floor, never from a time window.
    if (
      anchor.signatureB64url === null ||
      anchor.keyId === null ||
      anchor.capturedAtUnixMs === null
    ) {
      await this.latchMigrationUnavailable(
        anchor.identityId,
        "persisted_anchor_signature_material_missing",
      );
      return;
    }
    const verdict = verifyProducerSignature(
      {
        eventCanonicalJson: anchor.signedCanonicalJson,
        capturedAtUnixMs: anchor.capturedAtUnixMs,
        seq: anchor.seq,
        signatureB64url: anchor.signatureB64url,
        keyId: anchor.keyId,
      },
      this.pinnedProducerKeyB64url,
    );
    if (!verdict.ok) {
      await this.latchMigrationUnavailable(
        anchor.identityId,
        `persisted_anchor_signature_invalid:${verdict.reason}`,
      );
      return;
    }
    const parsedAnchorBody = parseSignedBody(anchor.signedCanonicalJson);
    if (parsedAnchorBody.kind === "error") {
      await this.latchMigrationUnavailable(
        anchor.identityId,
        `persisted_anchor_body_unparseable:${parsedAnchorBody.reason}`,
      );
      return;
    }
    const signedAnchorDetails = signedDetailsFromBody(parsedAnchorBody.body);
    if (
      Object.prototype.hasOwnProperty.call(
        signedAnchorDetails,
        CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
      ) &&
      signedAnchorDetails[CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY] !== anchor.seq
    ) {
      // The row's seq must be the one inside the signed bytes; otherwise a
      // genuine signed body could be re-filed under a chosen seq floor.
      await this.latchMigrationUnavailable(
        anchor.identityId,
        "persisted_anchor_seq_not_signature_bound",
      );
      return;
    }
    const anchorHash = computeSignedBodyHash(anchor.signedCanonicalJson);
    if (anchor.chainBasis !== CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY) {
      // Old-basis (or pre-recording) history: this is the one-time migration.
      // Record it first-class and FLUSH before the anchor is adopted, so the
      // audit trail explains the basis change before any event chains on it.
      await this.sink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "chain_basis_migrated",
        anchor.identityId,
        {
          previous_basis:
            anchor.chainBasis ?? CASTLE_WALL_CHAIN_BASIS_EVENT_CANONICAL,
          new_basis: CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
          anchor_seq: anchor.seq,
          anchor_sha256_hex: anchorHash,
          anchor_source: "persisted_signed_canonical_body",
        },
        "success",
      );
      await this.sink.flush();
    }
    this.lastAckedSeq = anchor.seq;
    this.lastEventChainHash = anchorHash;
  }

  private async latchMigrationUnavailable(
    identityId: string,
    reason: string,
  ): Promise<void> {
    this.chainMigrationUnavailableReason = reason;
    // One durable record at latch time (not one per refused event — a
    // per-event append would flood the log for as long as the daemon retries).
    await this.sink.append(
      CASTLE_WALL_AUDIT_LAYER,
      "chain_migration_unavailable",
      identityId,
      { reason },
      "failure",
    );
    await this.sink.flush();
    // SAFETY: one greppable operator line for the stuck chain; the per-event
    // refusals surface only as unsettled faults on the drain/flow paths.
    console.error(
      `[castle-wall] audit chain anchor migration UNAVAILABLE (${reason}): the chain is stopped fail-closed until an operator repairs the anchor; incoming critical events are refused unsettled.`,
    );
  }

  /**
   * Classify an inbound critical event against the WAL chain.
   *
   * `chainHash` is the basis hash the caller already selected up front in
   * `ingestCritical` (before this method runs) - reusing it here means this
   * method never itself calls `canonicalize()`/`computeCanonicalHash()` and
   * so can never throw on an unrepresentable event. Producer-signed events
   * chain on `sha256(envelope.producer.eventCanonicalJson)` (the producers'
   * own basis); channel-unsigned events keep the legacy event-canonical hash.
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
    event: CastleWallAuditEvent,
    chainHash: string,
    signatureVerified: boolean,
  ):
    | { kind: "ok" }
    | { kind: "ok_gap" }
    | { kind: "duplicate_replay" }
    | { kind: "error"; reason: string } {
    // Defense in depth: `details` is typed `Record<string, unknown>` and the
    // drain path always builds it as an object, but a null/undefined here
    // would make the `hasOwnProperty.call` below throw. Treat a missing
    // `details` as "no chain fields" - the same settled rejection as any other
    // malformed event, never an unsettled fault.
    const details = event.details as Record<string, unknown> | null | undefined;
    if (details === null || details === undefined) {
      return { kind: "error", reason: "chain_fields_missing" };
    }
    const hasSeq = Object.prototype.hasOwnProperty.call(
      event.details,
      CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
    );
    const hasPriorHash = Object.prototype.hasOwnProperty.call(
      event.details,
      CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY,
    );
    const seq = event.details[CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY];
    const priorHash =
      event.details[CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY];
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
        this.lastEventChainHash !== null &&
        chainHash === this.lastEventChainHash
      ) {
        return { kind: "duplicate_replay" };
      }
      return { kind: "error", reason: "seq_regression" };
    }
    if (this.lastEventChainHash !== null && priorHash !== this.lastEventChainHash) {
      // Subset consumption (macOS flow): a prior referencing a producer event
      // we never received is the NORMAL shape whenever an availability report
      // interleaved in the shared producer chain — not evidence of damage.
      // Acceptance across the gap still requires a VERIFIED producer signature
      // (seq + prior live inside the signed bytes) and the strict seq
      // monotonicity already enforced above; an unsigned or replayed frame is
      // rejected identically in both modes. Complete-chain consumers treat the
      // same mismatch as a hard fork, because there a missing link IS damage.
      if (
        this.chainContinuity === "producer_subset" &&
        signatureVerified &&
        typeof priorHash === "string"
      ) {
        return { kind: "ok_gap" };
      }
      return { kind: "error", reason: "wal_chain_verification_failed" };
    }
    // FIX 2 (codex CRITICAL - never bootstrap-accept past an UNPERSISTED event).
    //
    // We are in the BOOTSTRAP state here (`lastEventChainHash === null`): no
    // verified on-disk chain anchor exists, so `priorHash` cannot be checked. A
    // genuine first event (genesis, or a from-null re-pull) is legitimately
    // accepted here. The dangerous case: a PRIOR event validated + chained but
    // then FAILED to persist (`pendingUnpersistedSeq` is set, anchor still null),
    // and now a LATER event (seq > the owed seq) arrives. Accepting it would
    // advance + ack past the un-anchored event, letting the daemon truncate its
    // WAL through the gap (silent audit data loss). So while a seq is owed, only a
    // RETRY of that same seq may proceed; any higher seq is refused. (A retry of
    // the SAME seq with different content is already caught as `seq_regression`
    // once that seq persists; here we only block skipping AHEAD.)
    if (
      this.pendingUnpersistedSeq !== null &&
      seq > this.pendingUnpersistedSeq
    ) {
      return {
        kind: "error",
        reason: "wal_chain_bootstrap_after_unpersisted_event",
      };
    }
    return { kind: "ok" };
  }

  /**
   * Decide whether an event's producer signature is acceptable, and with what
   * evidence basis. Returns one of:
   *
   *   - `verified` - a producer signature verified against the pinned key
   *     (per-producer authenticated; the forgery hole is closed for this entry).
   *   - `unsigned` - accepted on the legacy channel-authenticity basis, either
   *     because no pinned producer key is configured OR because the event is
   *     not enforcement evidence (control/diagnostic events are not gated).
   *   - `rejected` - enforcement evidence that, with a pinned producer key
   *     configured, lacked a valid signature. The caller fails closed.
   */
  private evaluateProducerSignature(
    envelope: CriticalEventEnvelope
  ): SignatureOutcome {
    const isEnforcementEvidence = ENFORCEMENT_EVIDENCE_EVENT_TYPES.has(
      envelope.event.event_type
    );
    // No pinned key: accept on the documented channel-authenticated basis.
    if (this.pinnedProducerKeyB64url === null) {
      return { kind: "unsigned" };
    }
    if (!envelope.producer) {
      if (!isEnforcementEvidence) {
        // Control/diagnostic events are not signature-gated; without a
        // producer block they keep the channel basis (and the legacy
        // event-canonical chain basis, since there is no signed body to hash).
        return { kind: "unsigned" };
      }
      return { kind: "rejected", reason: "producer_signature_absent" };
    }
    // A producer block IS present: with a pinned key it must verify — for ANY
    // event type. Verifying non-enforcement signed frames too is what lets
    // every producer-signed event chain on the signed-body basis, and it
    // fail-closes a stapled/broken signature instead of quietly downgrading
    // the entry to the unsigned basis (rule 5: never silently degrade).
    // Parse the signed WAL body. The signature (verified below) is over THIS
    // body; once verified, the body - not the attacker-controllable
    // `envelope.event` - is the authoritative source for the persisted
    // evidence. We bind only the one cross-shape invariant the persist path
    // needs: the signed `operation` must map to the `event_type` slot the entry
    // is filed under (so a verified "allow" body can't be filed as a "block").
    // Every OTHER evidence field (agent, destination, decision provenance, rule
    // id) is taken FROM the signed body in `buildDetailsForEvent`, which
    // structurally eliminates the staple/strip/fabricate attack class - there is
    // nothing to mismatch because we do not trust the event's fields for signed
    // evidence. (codex L1 findings R2–R5.)
    const parsed = parseSignedBody(envelope.producer.eventCanonicalJson);
    if (parsed.kind === "error") {
      return { kind: "rejected", reason: parsed.reason };
    }
    // STRICT binding: the signed `operation` must map to exactly the
    // `event_type` slot the entry is filed under. An unmapped operation is a
    // rejection, never a pass-through — accepting unknown signed operations
    // for any event type would let a captured signature over one body be
    // stapled onto a differently-typed event (#1096 regression, reverted).
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
    const eventSeq =
      envelope.event.details[CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY];
    if (typeof eventSeq === "number" && eventSeq !== envelope.producer.seq) {
      return { kind: "rejected", reason: "producer_signature_seq_mismatch" };
    }
    const signedDetails =
      parsed.body.details !== null &&
      typeof parsed.body.details === "object" &&
      !Array.isArray(parsed.body.details)
        ? (parsed.body.details as Record<string, unknown>)
        : {};
    if (
      Object.prototype.hasOwnProperty.call(
        signedDetails,
        CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
      ) &&
      signedDetails[CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY] !==
        envelope.producer.seq
    ) {
      return { kind: "rejected", reason: "producer_signed_body_seq_mismatch" };
    }
    if (
      Object.prototype.hasOwnProperty.call(
        signedDetails,
        CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY,
      ) &&
      signedDetails[CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY] !==
        envelope.event.details[CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY]
    ) {
      return {
        kind: "rejected",
        reason: "producer_signed_body_prior_hash_mismatch",
      };
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
      // The exact signed inputs, persisted so a read-side consumer can
      // reconstruct the signed message and RE-verify (Slice R). Stored
      // verbatim - never re-canonicalized - so the reader hashes identical
      // bytes to the daemon and this consumer.
      eventCanonicalJson: envelope.producer.eventCanonicalJson,
      capturedAtUnixMs: envelope.producer.capturedAtUnixMs,
    };
  }

  private async emitProducerSignatureRejected(
    envelope: CriticalEventEnvelope,
    reason: string,
  ): Promise<void> {
    this.stats.producerSignatureRejections += 1;
    await this.sink.append(
      CASTLE_WALL_AUDIT_LAYER,
      "producer_signature_rejected",
      envelope.event.fortress_id ?? "unknown",
      {
        reason,
        event_type: envelope.event.event_type,
        seq: envelope.event.details.seq,
      },
      "failure",
    );
    await this.sink.flush();
    // Fail closed: do NOT persist as enforcement evidence, do NOT advance the
    // chain. We DO ACK so the daemon stops re-delivering a packet we have
    // permanently refused; the refusal is durably recorded above for audit.
    await this.tryAck(envelope, "producer_signature_rejected");
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
      { reason, event_canonical: safeCanonicalizeForDiagnostic(event) },
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
      /**
       * The verbatim canonical-JSON string the daemon signed, persisted so a
       * read-side consumer can reconstruct the signed message and re-verify.
       */
      eventCanonicalJson: string;
      /** The capture timestamp the signature is bound to (re-verify input). */
      capturedAtUnixMs: number;
    }
  | { kind: "unsigned" }
  | { kind: "rejected"; reason: string };

/**
 * Map from the daemon's WAL `operation` tag to the consumer's `event_type` for
 * the enforcement-evidence verdicts. Used to corroborate that a signed WAL
 * body describes the same enforcement outcome as the event we persist, across
 * the two distinct JSON shapes.
 *
 * COVERAGE CONTRACT: this map must list EVERY operation any producer signs
 * into `ingestCritical` — must match `operation_for_verdict` in
 * `castle-wall-daemon/src/policy.rs` and the flow-decision operations in
 * `castle-wall-macos/Sources/CastleWallFilter/AuditProducerSigning.swift`.
 * The strict check in `evaluateProducerSignature` REJECTS any signed body
 * whose operation is absent here, so a producer that starts signing a new
 * operation without a row added in the same change is refused fail-closed
 * (loud in CI/drills), never accepted un-corroborated.
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
  envelope: CriticalEventEnvelope,
  signature: SignatureOutcome,
  chainBasis:
    | typeof CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY
    | typeof CASTLE_WALL_CHAIN_BASIS_EVENT_CANONICAL,
  chainPriorUnconsumed: boolean,
): Record<string, unknown> {
  const { event } = envelope;
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
    if (
      Object.prototype.hasOwnProperty.call(
        event.details,
        CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
      )
    ) {
      out[CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY] =
        event.details[CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY];
    }
    if (
      Object.prototype.hasOwnProperty.call(
        event.details,
        CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY,
      )
    ) {
      out[CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY] =
        event.details[CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY];
    }
    out[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] = signature.signatureB64url;
    out[CASTLE_WALL_PRODUCER_KID_DETAIL_KEY] = signature.keyId;
    // R-1: persist the EXACT signed inputs so a read-side consumer can
    // reconstruct the signed message and re-verify the signature against the
    // pinned key (the seq is already preserved as `out.seq` above). Stored
    // verbatim - the reader must hash identical bytes to what the daemon
    // signed, so re-canonicalizing here would break verification.
    out[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY] =
      signature.eventCanonicalJson;
    out[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY] =
      signature.capturedAtUnixMs;
    if (envelope.producerSubjectBinding?.kind === "macos_audit_token") {
      out[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY] =
        CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN;
    } else if (envelope.producerSubjectBinding?.kind === "signed_identity_id") {
      out[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY] =
        CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID;
    }
    out[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY] =
      CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED;
    // The chain basis is recorded as a STORED FACT so the startup anchor
    // restore can decide "was this written under the old basis" without
    // inferring from in-memory state (#1096 Q5 defect).
    out[CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY] = chainBasis;
    if (chainPriorUnconsumed) {
      // Honesty marker: prior-hash contiguity was not locally assertable for
      // this hop (subset consumption); see the constant's invariant comment.
      out[CASTLE_WALL_CHAIN_PRIOR_UNCONSUMED_DETAIL_KEY] = true;
    }
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
  // A forged event must NOT be able to plant re-verification inputs that a
  // read-side consumer might mistake for a verified signature.
  delete out[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY];
  delete out[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY];
  delete out[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY];
  out[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY] =
    CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED;
  out[CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY] = chainBasis;
  // Provenance LAST, so a forged `event.details.cw_source` cannot survive into
  // the stored entry. Consumers reasoning about "actual enforcement" require
  // this marker (see CASTLE_WALL_AUDIT_PROVENANCE_KEY).
  out[CASTLE_WALL_AUDIT_PROVENANCE_KEY] = CASTLE_WALL_AUDIT_PROVENANCE_VALUE;
  return out;
}

function resultForSignatureOutcome(
  signature: SignatureOutcome,
): "success" | "failure" {
  if (signature.kind !== "verified") return "success";
  const result = signature.signedBody.result;
  if (result === "failure" || result === "blocked") return "failure";
  return "success";
}

function signedDetailsFromBody(
  signedBody: Record<string, unknown>
): Record<string, unknown> {
  return signedBody.details !== null &&
    typeof signedBody.details === "object" &&
    !Array.isArray(signedBody.details)
    ? (signedBody.details as Record<string, unknown>)
    : {};
}

function persistedIdentityForEvent(
  envelope: CriticalEventEnvelope,
  signature: SignatureOutcome,
):
  | { kind: "ok"; identityId: string }
  | { kind: "rejected"; reason: string } {
  const subjectBinding = envelope.producerSubjectBinding;
  if (signature.kind !== "verified") {
    return { kind: "ok", identityId: envelope.event.fortress_id };
  }
  if (subjectBinding === undefined) {
    return {
      kind: "rejected",
      reason: "producer_signed_without_subject_binding",
    };
  }
  if (subjectBinding.kind === "macos_audit_token") {
    const signedDetails = signedDetailsFromBody(signature.signedBody);
    const agentId =
      typeof signedDetails.agent_id === "string"
        ? signedDetails.agent_id
        : null;
    if (agentId === null) {
      return {
        kind: "rejected",
        reason: "producer_signed_body_missing_agent_id",
      };
    }
    const subject = protectionSubjectFromMacOSAuditToken(
      subjectBinding.fortressId,
      agentId,
    );
    if (subject === null) {
      return {
        kind: "rejected",
        reason: "producer_signed_body_agent_subject_unresolvable",
      };
    }
    return { kind: "ok", identityId: subject };
  }
  if (subjectBinding.kind === "signed_identity_id") {
    const identityId =
      typeof signature.signedBody.identity_id === "string" &&
      signature.signedBody.identity_id.length > 0
        ? signature.signedBody.identity_id
        : null;
    if (identityId === null) {
      return {
        kind: "rejected",
        reason: "producer_signed_body_missing_identity_id",
      };
    }
    return { kind: "ok", identityId };
  }
  return {
    kind: "rejected",
    reason: "producer_signed_body_subject_binding_unknown",
  };
}

function computeCanonicalHash(event: CastleWallAuditEvent): string {
  return createHash("sha256").update(canonicalize(event), "utf8").digest("hex");
}

/**
 * The shared chain basis: `sha256(utf8(eventCanonicalJson))` over the VERBATIM
 * signed body string. Must byte-match what every producer hashes for its own
 * `prior_sha256_hex` — `sha256_hex(canonical)` in
 * `castle-wall-daemon/src/audit.rs` and `sha256Hex(Data(walCanonical.utf8))`
 * in `castle-wall-macos/.../AuditProducerSigning.swift`. Never re-canonicalize
 * here: re-encoding could drift the bytes and fork the chain.
 */
function computeSignedBodyHash(eventCanonicalJson: string): string {
  return createHash("sha256").update(eventCanonicalJson, "utf8").digest("hex");
}

/**
 * Select the chain basis for one event. A VERIFIED producer signature pins the
 * chain to the signed body's hash (signature-bound by construction: `seq` and
 * `prior_sha256_hex` live inside the signed bytes). Anything else keeps the
 * legacy consumer-local event hash on the channel-authenticated basis.
 */
function chainBasisFor(
  canonicalHash: string,
  signature: SignatureOutcome,
): {
  hash: string;
  kind:
    | typeof CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY
    | typeof CASTLE_WALL_CHAIN_BASIS_EVENT_CANONICAL;
} {
  if (signature.kind === "verified") {
    return {
      hash: computeSignedBodyHash(signature.eventCanonicalJson),
      kind: CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
    };
  }
  return { hash: canonicalHash, kind: CASTLE_WALL_CHAIN_BASIS_EVENT_CANONICAL };
}

/**
 * Canonicalize a value for a DIAGNOSTIC audit field only - e.g. the
 * `event_canonical` detail attached to a rejection entry - never for the WAL
 * hash chain. Mesh `canonicalize()` (#924) throws on values it cannot
 * represent exactly (an unsafe integer >= 2^53, non-finite numbers, ...); an
 * attacker-controllable event that trips that guard is exactly the kind of
 * malformed input a diagnostic field exists to describe, so a serialization
 * failure here must degrade to a clearly-labeled placeholder string instead
 * of propagating out of the caller. The caller is typically already IN a
 * fail-closed rejection path (e.g. the `audit_event_rejected` /
 * `wal_chain_verification_failed` recording), and that recording - and the
 * ACK that settles the event - must never itself be prevented by the very
 * malformation it is recording.
 */
function safeCanonicalizeForDiagnostic(value: unknown): string {
  try {
    return canonicalize(value);
  } catch (err) {
    return `<uncanonicalizable: ${err instanceof Error ? err.message : String(err)}>`;
  }
}

/**
 * Minimal read surface the anchor restore needs from the persisted audit log.
 * `AuditLog.query` matches structurally (same pattern as `AuditSink` /
 * `AuditLog.append`).
 */
export interface ChainAnchorAuditLogReader {
  query(options: { layer: "l1"; limit?: number }): Promise<{
    entries: Array<{
      operation: string;
      identity_id: string;
      details?: Record<string, unknown>;
    }>;
    total: number;
    integrity_findings: ReadonlyArray<unknown>;
  }>;
}

/**
 * Scan bound for the anchor lookup: effectively "the whole log". The last
 * chain-participating entry may sit arbitrarily deep behind non-chain entries
 * (metric batches, rejection diagnostics, lifecycle records), and a bounded
 * page that missed it would silently degrade the restore to a genesis
 * bootstrap — reopening the very wire-trust hole the restore closes (rule 5).
 * `query` slices from the tail in memory, so the large limit costs nothing
 * beyond the read it already does.
 */
const CHAIN_ANCHOR_SCAN_LIMIT = Number.MAX_SAFE_INTEGER;

/**
 * Build a {@link ChainAnchorSource} over the fortress's own persisted audit
 * log. Finds the most recent ACCEPTED chain-participating castle-wall entry
 * (consumer provenance marker + chain bookkeeping fields present) and returns
 * its persisted signed canonical body + recorded chain basis. Refuses to
 * anchor (kind `unavailable`) when the log itself reports integrity findings:
 * damaged local history must latch the loud stuck state, never silently seed
 * a fresh chain.
 */
export function buildChainAnchorSourceFromAuditLog(
  log: ChainAnchorAuditLogReader,
): ChainAnchorSource {
  return async () => {
    const result = await log.query({
      layer: CASTLE_WALL_AUDIT_LAYER,
      limit: CHAIN_ANCHOR_SCAN_LIMIT,
    });
    if (result.integrity_findings.length > 0) {
      return { kind: "unavailable", reason: "audit_log_integrity_findings" };
    }
    for (let i = result.entries.length - 1; i >= 0; i -= 1) {
      const entry = result.entries[i]!;
      const details = entry.details;
      if (details === undefined || details === null) continue;
      // Only entries this consumer accepted participate in the chain: the
      // provenance marker is stamped by the consumer at persist time, and the
      // operation must be an accepted critical event type (rejection and
      // diagnostic records use non-accepted operation names).
      if (
        details[CASTLE_WALL_AUDIT_PROVENANCE_KEY] !==
        CASTLE_WALL_AUDIT_PROVENANCE_VALUE
      ) {
        continue;
      }
      if (!ACCEPTED_EVENT_TYPES.has(entry.operation as CastleWallEventType)) {
        continue;
      }
      const seq = details[CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY];
      const hasPrior = Object.prototype.hasOwnProperty.call(
        details,
        CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY,
      );
      // Metric batches and other non-chain accepted entries carry no chain
      // bookkeeping; they cannot anchor the chain.
      if (typeof seq !== "number" || !hasPrior) continue;
      const signed = details[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY];
      const basis = details[CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY];
      const sig = details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY];
      const kid = details[CASTLE_WALL_PRODUCER_KID_DETAIL_KEY];
      const capturedAt = details[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY];
      // Everything here is a CANDIDATE only: the consumer re-verifies the
      // producer signature over these bytes before adopting any of it. This
      // scan deliberately makes no trust decision.
      return {
        kind: "persisted",
        seq,
        signedCanonicalJson: typeof signed === "string" ? signed : null,
        signatureB64url: typeof sig === "string" ? sig : null,
        keyId: typeof kid === "string" ? kid : null,
        capturedAtUnixMs: typeof capturedAt === "number" ? capturedAt : null,
        chainBasis: typeof basis === "string" ? basis : null,
        identityId: entry.identity_id,
      };
    }
    return null;
  };
}
