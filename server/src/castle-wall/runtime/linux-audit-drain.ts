/**
 * Linux audit-drain pull-loop (the missing "PR 2b" consumer feed).
 *
 * Slice L1/R/P built the producer-signing daemon + the re-verifying consumer,
 * but nothing in production ever pulled the daemon's signed events INTO the
 * consumer. This module is that feed: it issues `audit_drain_request` frames to
 * the enforcing Linux daemon (the hybrid PULL model - main drives the pace),
 * maps each returned `AuditDrainEvent` into a `CriticalEventEnvelope` with the
 * per-event producer-signature material attached, and runs it through the audit
 * consumer's fail-closed re-verification gate. A genuine daemon-signed event
 * re-verifies; an in-process forger that minted the `cw_source` marker but
 * cannot mint a valid producer signature is rejected.
 *
 * # Why the consumer - not this loop - decides the verdict
 *
 * This loop is deliberately "dumb": it does not inspect signatures, does not
 * decide enforcement basis, and does not gate green/non-green. It only
 * transports the daemon's bytes faithfully into `AuditConsumer.ingestCritical`,
 * which holds the single fail-closed producer-signature gate (Slice L1/R). The
 * gate's authority must live in exactly one place; a second, looser check here
 * would be a divergence risk. So the loop's whole job is byte-faithful
 * transport + correct envelope construction.
 *
 * # ACK discipline
 *
 * The daemon truncates its WAL only when main acks. We let the AUDIT CONSUMER
 * drive acking: each `CriticalEventEnvelope.ack` we hand it sends an
 * `audit_drain_ack(seq)` for that event. The consumer already enforces the
 * "state durable BEFORE ack" contract and calls `ack()` for every settled event
 * - accepted, rejected-and-recorded, or duplicate-dropped - and skips it only
 * when ingest throws for a TRANSIENT reason (persistence/transport), so the
 * daemon re-delivers exactly the events that were not durably handled. Reusing
 * the consumer's own ack path (rather than a parallel batch ack) keeps a single
 * settlement authority and inherits its correctness.
 *
 * # Two cursors, because they answer different questions
 *
 * SETTLEMENT and RECLAMATION are separate facts and used to be conflated. The
 * local cursor advanced only after `client.sendDrainAck` RESOLVED, so an ACK
 * that failed on the wire left the cursor behind while the consumer had already
 * advanced `lastAckedSeq` and flushed (`audit-consumer.ts` updates its chain
 * state BEFORE calling ack, precisely because "the data is already durable"). The
 * loop then reported the event as "did not settle (no ack)" - an UNSETTLED FAULT
 * that tripped a permanent not-armed wall - for an event that had fully settled.
 * Two cursors, each meaning one thing:
 *
 *   - `cursor`         what the CONSUMER has durably settled. Advanced the
 *                      instant the consumer calls `ack()`, before the wire send,
 *                      because that call IS the settlement proof. It decides
 *                      where the next drain request resumes.
 *   - `pendingAckSeq`  the highest settled seq the DAEMON has not confirmed
 *                      truncating. Re-sent at the top of every later cycle until
 *                      confirmed. Without this, advancing `cursor` past an
 *                      unconfirmed ACK would leave those entries in the daemon
 *                      WAL forever (the daemon never re-delivers below
 *                      `after_seq`), growing it to its cap, at which point the
 *                      daemon fails closed and denies all wrapped-agent egress.
 *                      Re-acking is safe because truncate-through-seq is
 *                      idempotent.
 *
 * No data is lost in either direction: the consumer never advances past an
 * unpersisted event, and the daemon never truncates through one the consumer did
 * not durably hold.
 */

import type {
  AuditDrainEvent,
  AuditDrainResponse,
} from "../ipc/messages.js";
import type { CastleWallAuditEvent } from "../audit/events.js";
import {
  CASTLE_WALL_AUDIT_LAYER,
  CASTLE_WALL_SCHEMA_VERSION_V1,
} from "../constants.js";
import { fortressIdFromProtectionSubject } from "../subject-binding.js";
// `WAL_OPERATION_TO_EVENT_TYPE` is IMPORTED, not re-declared. It used to be a
// hand-mirrored copy carrying a "MUST stay in sync with audit-consumer.ts"
// comment, which is the exact shape AGENTS rule 5 prohibits: the consumer
// REJECTS a producer-signed event whose mapped type does not equal the one this
// loop attached, so a divergence between the two tables does not surface as a
// mismatch warning - it surfaces as genuine enforcement evidence being discarded
// as forgery-shaped. One table makes that unrepresentable.
import { WAL_OPERATION_TO_EVENT_TYPE } from "./audit-consumer.js";
import type { AuditConsumer, CriticalEventEnvelope } from "./audit-consumer.js";
import type { IpcClient } from "./ipc-client.js";
import { RuntimeDrainError } from "./errors.js";

/**
 * How a drain-cycle failure must be handled.
 *
 * `unclassified` is kept distinct from `retryable` rather than folded into it
 * because they are different facts: `retryable` is the daemon saying "I am busy
 * or stopping", while `unclassified` is a pre-v2 daemon saying nothing at all.
 * Both get the caller's bounded retry budget, but only one of them is a
 * statement about the daemon's condition, and an operator reading the reason
 * string is entitled to know which.
 */
export type DrainFaultClass = "retryable" | "unclassified" | "terminal";

/**
 * The three-valued condition of the signed-evidence channel.
 *
 * Declared HERE, in the module that owns the drain loop, rather than in the
 * activation gate that latches it: `health/castle-wall-snapshot.ts` needs the
 * type, and importing it from the gate created a gate <-> snapshot import cycle
 * (the gate already imports the snapshot builder). One direction, one owner.
 *
 * `retrying` is neither health nor failure. Folding it into `faulted` is what let
 * an ordinary `systemctl stop` or a 2-second control-lock window write permanent
 * not-armed evidence; folding it into `healthy` would let a daemon that refuses
 * forever pass as a working wall.
 */
export type CastleWallDrainState = "healthy" | "retrying" | "faulted";

/**
 * Classify one drain-cycle failure.
 *
 * The ONE place the question is answered, so the loop, the activation gate, and
 * any later consumer cannot answer it differently. Everything that is not a
 * classified {@link RuntimeDrainError} stays TERMINAL: a dropped socket, a
 * request timeout, or an unexpected throw is not a daemon telling us it is busy,
 * and the fail-closed armed-but-not-draining contract is written for exactly
 * those. Only a daemon RESPONSE carrying (or lacking) a class can be softened.
 */
export function classifyDrainFault(err: unknown): DrainFaultClass {
  if (err instanceof RuntimeDrainError) {
    if (err.errorClass === "terminal") return "terminal";
    return err.errorClass === "retryable" ? "retryable" : "unclassified";
  }
  return "terminal";
}

/** Per-cycle inputs that carry over from the previous cycle. */
export interface DrainCycleOptions {
  /**
   * Highest seq the consumer durably settled whose daemon-side truncation is
   * still unconfirmed. Re-acked at the top of the cycle. Carry the value from
   * the previous cycle's result, or the daemon WAL keeps entries the consumer
   * already holds until it hits its cap and fails closed.
   */
  pendingAckSeq?: number | null;
  /**
   * Sink for a RETRYABLE or UNCLASSIFIED fault. Separate from `onDrainFault`
   * (terminal only) so a busy or stopping daemon cannot write permanent
   * not-armed evidence about a link that is fine.
   */
  onRetryableFault?: (err: Error) => void;
}

/** What one drain cycle observed. */
export interface DrainCycleResult {
  nextAfterSeq: number | null;
  morePending: boolean;
  drained: number;
  faulted: boolean;
  faultedSeq: number | null;
  /** Reclamation debt to carry into the next cycle; `null` when nothing is owed. */
  pendingAckSeq: number | null;
  /** Worst class seen this cycle, or `null` when the cycle was clean. */
  faultClass: DrainFaultClass | null;
}


/** Default batch cap per drain request. Matches a sane daemon snapshot ceiling. */
export const DEFAULT_AUDIT_DRAIN_MAX_EVENTS = 256;

/** Default ceiling for exponential backoff after repeated unsettled faults. */
export const DEFAULT_AUDIT_DRAIN_MAX_FAULT_BACKOFF_MS = 30_000;

/** Options for one drain cycle / the continuous loop. */
export interface LinuxAuditDrainOptions {
  /** Max events to request per drain frame. Defaults to 256. */
  maxEvents?: number;
  /** Poll interval (ms) between drain cycles when running continuously. Default 1000. */
  pollIntervalMs?: number;
  /**
   * Maximum backoff delay after repeated same-cursor unsettled drain faults.
   * Defaults to 30s. The first fault waits `pollIntervalMs`, then doubles up to
   * this cap.
   */
  maxFaultBackoffMs?: number;
  /**
   * Seq to resume the loop's cursor from (exclusive - the first cycle pulls
   * strictly above it). Defaults to null (drain from the start). The activation
   * gate sets this to the cursor its fail-closed initial-drain confirmation
   * probe reached, so the continuous loop neither re-pulls nor skips an event
   * the probe already drained.
   */
  initialCursor?: number | null;
  /**
   * Reclamation debt inherited from the activation gate's initial-drain probe:
   * a seq the consumer durably settled whose daemon-side truncation the probe
   * could not confirm. Without carrying it, those daemon WAL entries would never
   * be re-acked (the loop resumes ABOVE them) and the WAL would grow toward its
   * cap. Defaults to null.
   */
  initialPendingAckSeq?: number | null;
  /** Injected timer for tests; defaults to setTimeout. */
  setTimer?: (cb: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  /**
   * Optional sink for non-fatal loop DIAGNOSTICS that do NOT mean the drain
   * stopped making progress: a producer-signature refusal that the consumer
   * durably recorded + acked (the event SETTLED - a refused forgery, by design),
   * or any other settled-but-noteworthy condition. The loop CONTINUES after
   * these; in opt-in mode they MUST NOT trip the not-armed health signal, or a
   * forged event could DoS the wall into a false NOT-ARMED. (codex HIGH:
   * settled-refusal must not stop the loop like a transport failure.)
   */
  onError?: (err: Error) => void;
  /**
   * Optional sink for an UNSETTLED drain FAULT: a condition where the loop could
   * not advance past an event because it did NOT durably settle - a transient
   * persistence/transport failure that threw BEFORE the ack, a malformed drain
   * entry the consumer cannot even parse, or the `drainRequest` transport itself
   * throwing. These are the load-bearing failures: in opt-in producer-signed
   * mode the daemon's signed enforcement evidence is NOT reaching the consumer,
   * so the wall is armed-but-not-draining and must read NOT-ARMED. Distinct from
   * `onError` precisely so a SETTLED refusal (cursor advanced) never trips the
   * health machine while a real transport/persistence fault always does. (codex
   * HIGH FIX.)
   */
  onDrainFault?: (err: Error) => void;
  /**
   * Sink for a RETRYABLE or UNCLASSIFIED fault: the daemon answered and said it
   * was busy or stopping (or, pre-v2, said nothing about why).
   *
   * Deliberately NOT routed to `onDrainFault`. Every daemon-side refusal used to
   * land there, so an ordinary `systemctl stop` with an ACK in flight, or any
   * 2-second control-lock contention window, wrote a durable
   * `castle_wall_drain_failed` record and latched the wall permanently
   * not-armed - blaming a transport/persistence fault for a link that was fine
   * and a daemon that was merely busy. The consumer's data is unaffected in both
   * cases. The CALLER applies a bounded budget to these and escalates to
   * `onDrainFault` only when it is exhausted.
   */
  onRetryableFault?: (err: Error) => void;
  /**
   * Called after any cycle that completed with no fault AND no reclamation debt.
   * The caller uses it to reset its retryable-fault budget, so the budget counts
   * CONSECUTIVE failures rather than accumulating over the process lifetime.
   */
  onCycleHealthy?: () => void;
}

/**
 * Construct the `CriticalEventEnvelope` for one drained WAL entry. The
 * `event_canonical_json` is the AUTHORITATIVE signed body; we parse it to derive
 * the consumer-shaped event (event_type from `operation`, layer, timestamp,
 * fortress_id) and graft the chain metadata (`seq`, `prior_sha256_hex`) the
 * consumer's WAL-chain validator requires. The producer-signature material is
 * attached verbatim so the consumer's gate verifies over the same bytes the
 * daemon signed.
 *
 * Exported for the end-to-end tests, which assert the mapping is correct.
 */
export function buildCriticalEnvelopeFromDrainEvent(
  drained: AuditDrainEvent,
  ack: () => Promise<void>
):
  | { kind: "ok"; envelope: CriticalEventEnvelope }
  | { kind: "error"; reason: string } {
  let body: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(drained.event_canonical_json);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { kind: "error", reason: "drain_event_body_unparseable" };
    }
    body = parsed as Record<string, unknown>;
  } catch {
    return { kind: "error", reason: "drain_event_body_unparseable" };
  }

  const operation = typeof body.operation === "string" ? body.operation : undefined;
  if (operation === undefined) {
    return { kind: "error", reason: "drain_event_body_missing_operation" };
  }
  // Map enforcement operations to their event_type; carry any other operation
  // through as its own event_type (the consumer's ACCEPTED_EVENT_TYPES gate then
  // validates it). This keeps the loop from silently dropping non-evidence
  // control events the daemon may also drain.
  const eventType = WAL_OPERATION_TO_EVENT_TYPE[operation] ?? operation;

  const signedIdentityId =
    typeof body.identity_id === "string" ? body.identity_id : null;
  const fortressId =
    typeof body.fortress_id === "string" && body.fortress_id.length > 0
      ? body.fortress_id
      : fortressIdFromProtectionSubject(signedIdentityId) ?? "unknown";
  const timestamp =
    typeof body.timestamp === "string" ? body.timestamp : new Date(drained.captured_at_unix_ms).toISOString();

  const bodyDetails =
    body.details !== null && typeof body.details === "object" && !Array.isArray(body.details)
      ? (body.details as Record<string, unknown>)
      : {};

  // The wire entry repeats the chain metadata (`seq`, `prior_sha256_hex`) the
  // consumer's WAL-chain validator reads from `event.details`, so we graft it
  // onto the reconstructed event. The consumer cross-checks these copies
  // against the verified signed body before accepting the entry, and chains on
  // the signed body's own hash. Evidence fields still come from
  // `producer.eventCanonicalJson`, never from this consumer-shaped event - so
  // there is no staple/strip attack surface here.
  const details: Record<string, unknown> = {
    ...bodyDetails,
    seq: drained.seq,
    prior_sha256_hex: drained.prior_sha256_hex,
  };

  const event: CastleWallAuditEvent = {
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    layer: CASTLE_WALL_AUDIT_LAYER,
    timestamp,
    fortress_id: fortressId,
    event_type: eventType as CastleWallAuditEvent["event_type"],
    agent: null,
    destination: null,
    decision: null,
    rule_id: null,
    details,
  };

  const envelope: CriticalEventEnvelope = {
    event,
    ack,
    producerDelivery: "durable_wal",
    producer: {
      eventCanonicalJson: drained.event_canonical_json,
      capturedAtUnixMs: drained.captured_at_unix_ms,
      seq: drained.seq,
      signatureB64url: drained.producer_signature_b64url ?? null,
      keyId: drained.producer_key_id ?? null,
    },
    producerSubjectBinding: { kind: "signed_identity_id" },
  };
  return { kind: "ok", envelope };
}

/**
 * Run ONE drain cycle: pull a batch from `afterSeq`, feed each event through the
 * consumer's fail-closed gate (which acks via the per-event callback on durable
 * settlement). Returns the cursor for the next cycle and whether more entries
 * are pending.
 *
 * Settlement = ack. The consumer calls our per-event `ack()` only AFTER the
 * event is durably handled - accepted, rejected-and-recorded, or
 * duplicate-dropped. That callback sends `audit_drain_ack(seq)` and advances our
 * cursor. An event whose ingest throws for a TRANSIENT reason never reaches its
 * ack, so the cursor does not advance past it and the daemon re-delivers it.
 *
 * Both the consumer's expected throws (an `AuditChainError` for a refused
 * forgery is thrown AFTER the durable refusal + ack) and a TRANSIENT throw
 * (persistence/transport, before ack) surface here. The cursor only ever
 * advances via the ack callback, so it tells us which kind we hit: after each
 * event we compare `cursor` to the event's seq. If it advanced, the event
 * SETTLED (a refused forgery is recorded + acked, so later genuine events in the
 * batch keep flowing). If it did NOT advance, the event was NOT durably handled
 * (transient failure before ack) and we STOP the batch - never acking past an
 * unpersisted seq, which would let the daemon truncate its WAL through a lost
 * event (FIX 2). The daemon re-delivers from the last settled seq next cycle.
 *
 * # Settled refusal vs unsettled fault - the cursor IS the discriminator (codex HIGH)
 *
 * The cursor check is also the single arbiter of WHICH error channel a throw
 * goes to, so a forged event can never DoS the wall into a false NOT-ARMED:
 *   - cursor ADVANCED past the event ⇒ it SETTLED. If it threw, it was a
 *     producer-signature refusal that the consumer durably recorded + acked -
 *     a DIAGNOSTIC (`onError`), and the loop CONTINUES. A refused forgery is the
 *     gate working as designed, NOT a transport failure.
 *   - cursor did NOT advance ⇒ the event did NOT settle (a transient
 *     persistence/transport throw before ack, or a malformed entry the consumer
 *     cannot even parse). That is an UNSETTLED FAULT (`onDrainFault`): in opt-in
 *     mode the signed evidence is not reaching the consumer, so the wall is
 *     armed-but-not-draining and must read NOT-ARMED. We break the batch.
 * Routing strictly by the cursor (never by error TYPE) means no settled outcome
 * - however it is reported - can ever trip the health machine.
 */
export async function drainOnce(
  client: IpcClient,
  consumer: AuditConsumer,
  afterSeq: number | null,
  maxEvents: number,
  onError?: (err: Error) => void,
  onDrainFault?: (err: Error) => void,
  options: DrainCycleOptions = {}
): Promise<DrainCycleResult> {
  // Two distinct roles, kept apart on purpose (see the module header): `cursor`
  // is what the CONSUMER has durably settled and decides where we resume;
  // `pendingAckSeq` is what the DAEMON has not confirmed truncating.
  let cursor: number | null = afterSeq;
  let pendingAckSeq: number | null = options.pendingAckSeq ?? null;
  let drained = 0;
  let faulted = false;
  let faultedSeq: number | null = null;
  // The worst class seen this cycle. `null` while healthy.
  let faultClass: DrainFaultClass | null = null;

  /** Fold one failure into this cycle's worst-class summary and route it. */
  const noteFault = (err: Error, seq: number | null): void => {
    const cls = classifyDrainFault(err);
    faulted = true;
    if (faultedSeq === null) faultedSeq = seq;
    // `terminal` always wins; otherwise the first class seen stands.
    if (faultClass === null || cls === "terminal") faultClass = cls;
    if (cls === "terminal") onDrainFault?.(err);
    else options.onRetryableFault?.(err);
  };

  /**
   * Send one ACK and track the reclamation debt.
   *
   * Rethrows so the consumer's own `tryAck` still records
   * `critical_event_ack_failed`, but the fault is CLASSIFIED here first: a
   * stopping or busy daemon refusing a truncation is not a broken evidence
   * channel, and the events in question are already durable consumer-side.
   */
  const ack = async (seq: number): Promise<void> => {
    try {
      await client.sendDrainAck(seq);
      // Confirmed (or, on a pre-v2 peer, sent on the documented one-way basis
      // the owner ruling preserves, whose weaker guarantee is reported through
      // `drainAcksAreConfirmed()` rather than hidden). Debt cleared.
      if (pendingAckSeq !== null && pendingAckSeq <= seq) pendingAckSeq = null;
    } catch (err) {
      pendingAckSeq = pendingAckSeq === null ? seq : Math.max(pendingAckSeq, seq);
      noteFault(err instanceof Error ? err : new Error(String(err)), seq);
      throw err;
    }
  };

  const summary = (morePending: boolean): DrainCycleResult => ({
    nextAfterSeq: cursor,
    morePending,
    drained,
    faulted,
    faultedSeq,
    pendingAckSeq,
    faultClass,
  });

  // Settle any ACK the daemon has not confirmed BEFORE pulling more. Doing it
  // first bounds the debt at one seq: a cycle cannot stack a second unconfirmed
  // ACK on top of an unresolved one, so the retained state here is O(1) rather
  // than a list that grows with every failed reclamation (AGENTS rule 8).
  if (pendingAckSeq !== null) {
    try {
      await ack(pendingAckSeq);
    } catch {
      // Already classified and routed by `ack`. Do NOT pull a new batch on top
      // of an unresolved reclamation debt; the loop's capped backoff paces it.
      return summary(false);
    }
  }

  let response: AuditDrainResponse;
  try {
    response = await client.drainRequest(afterSeq, maxEvents);
  } catch (err) {
    // Routed here rather than thrown so a RETRYABLE daemon response (busy,
    // stopping) cannot reach the loop's catch-all, which treats anything it
    // catches as an unsettled fault.
    const error = err instanceof Error ? err : new Error(String(err));
    noteFault(error, null);
    return summary(false);
  }

  for (const drainedEvent of response.events) {
    // SETTLEMENT, not transport success, advances the cursor. The consumer
    // invokes this callback only after the event is durably persisted AND its
    // own chain state has advanced, so by the time we are called the event has
    // settled whether or not the wire send that follows succeeds. Advancing
    // after the send is what made a failed ACK look like an unpersisted event.
    const built = buildCriticalEnvelopeFromDrainEvent(drainedEvent, async () => {
      cursor = drainedEvent.seq;
      drained += 1;
      await ack(drainedEvent.seq);
    });
    if (built.kind === "error") {
      // A malformed drain entry never settles (the cursor cannot advance past a
      // body we cannot even parse). That is an UNSETTLED FAULT: the daemon's
      // signed bytes are not arriving intact, so in opt-in mode the wall is
      // armed-but-not-draining. Route it to `onDrainFault` (trips NOT-ARMED) and
      // STOP iterating so the cursor does not advance past the gap (the daemon
      // re-delivers from `cursor`).
      // TERMINAL: bytes that will not parse do not become parseable on a retry.
      noteFault(
        new RuntimeDrainError(
          `audit_drain: ${built.reason} at seq ${drainedEvent.seq}`,
          "drain",
          "terminal"
        ),
        drainedEvent.seq
      );
      break;
    }
    let ingestError: Error | undefined;
    try {
      await consumer.ingestCritical(built.envelope);
    } catch (err) {
      // The consumer throws `AuditChainError` for a refused forgery / chain
      // error - but only AFTER durably recording it AND calling our ack (so the
      // cursor already advanced past it inside the callback above). A TRANSIENT
      // throw (persistence/transport) happens BEFORE ack, so the cursor stays
      // put and the daemon re-delivers. We do NOT classify by error type here;
      // the cursor check below decides whether this was a settled refusal
      // (diagnostic) or an unsettled fault (NOT-ARMED).
      ingestError = err instanceof Error ? err : new Error(String(err));
    }
    // FIX 2 (codex CRITICAL - drain must never ack past an UNPERSISTED event) +
    // settled-refusal-vs-fault split (codex HIGH).
    //
    // The ack callback advances `cursor` to `drainedEvent.seq` ONLY when the
    // consumer durably settled this event (accepted, rejected-and-recorded, or
    // duplicate-dropped). The cursor is therefore the single discriminator for
    // SETTLEMENT. It no longer conflates settlement with RECLAMATION: a failed
    // ACK wire send leaves `pendingAckSeq` owed and is classified by `ack`,
    // while the cursor - which the consumer's own durable state already
    // advanced - stays advanced.
    if (cursor === drainedEvent.seq) {
      // SETTLED. If it threw, it was a producer-signature refusal recorded +
      // acked - a diagnostic, NOT a transport failure. Report it via `onError`;
      // the loop CONTINUES so later genuine events in the batch keep flowing.
      // A refused forgery must never stop the loop (else a forger could DoS the
      // wall into a false NOT-ARMED).
      if (ingestError) onError?.(ingestError);
    } else {
      // NOT SETTLED. A TRANSIENT persistence/transport failure threw before ack
      // (cursor stayed put). Continuing would feed seq N+1 to the consumer,
      // which - with `lastEventChainHash` still null because seq N never
      // persisted - would accept N+1 as a fresh bootstrap and ack
      // `audit_drain_ack(N+1)`, truncating the daemon WAL THROUGH the lost seq N
      // (silent audit data loss). We STOP the batch; the cursor stays at the last
      // durably settled seq and the daemon re-delivers from there.
      //
      // TERMINAL: this is a CONSUMER-side persistence/integrity failure, which
      // is the class the fail-closed contract is written for. It is not the
      // daemon-busy case that `error_class` reclassifies.
      noteFault(
        new RuntimeDrainError(
          ingestError?.message ??
            `audit_drain: event seq ${drainedEvent.seq} did not settle (no ack)`,
          "drain",
          "terminal"
        ),
        drainedEvent.seq
      );
      break;
    }
  }

  // `morePending` is suppressed after ANY fault (including a retryable one): the
  // loop's backoff is what paces a retry, and chasing more batches through a
  // daemon that just told us it is busy is the amplification this bounds.
  return summary(!faulted && cursor !== afterSeq ? response.more_pending : false);
}

/**
 * Continuously drain in a poll loop until stopped. Each cycle pulls all
 * currently-pending batches (following `more_pending`) then sleeps
 * `pollIntervalMs` before the next cycle. The loop NEVER throws out of itself (a
 * wedged daemon link degrades observably, it does not crash the host). Settled
 * diagnostics (a durably-recorded producer-signature refusal) are reported via
 * `onError` and the loop continues; an UNSETTLED FAULT (transport/persistence
 * failure, malformed entry, or a `drainRequest` that itself throws) is reported
 * via `onDrainFault` - the load-bearing NOT-ARMED signal in opt-in mode. Returns
 * a handle whose `stop()` halts the loop after the in-flight cycle settles.
 */
export interface LinuxAuditDrainHandle {
  /** Stop the loop after the current cycle settles. */
  stop(): Promise<void>;
  /** The last seq the loop has acked (for tests/observability). */
  lastAckedSeq(): number | null;
}

export function startLinuxAuditDrainLoop(
  client: IpcClient,
  consumer: AuditConsumer,
  options: LinuxAuditDrainOptions = {}
): LinuxAuditDrainHandle {
  const maxEvents = options.maxEvents ?? DEFAULT_AUDIT_DRAIN_MAX_EVENTS;
  const pollIntervalMs = options.pollIntervalMs ?? 1000;
  const maxFaultBackoffMs = positiveIntegerOption(
    options.maxFaultBackoffMs,
    DEFAULT_AUDIT_DRAIN_MAX_FAULT_BACKOFF_MS
  );
  const setTimer = options.setTimer ?? ((cb, ms) => setTimeout(cb, ms));
  const clearTimer = options.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));

  let stopped = false;
  let cursor: number | null = options.initialCursor ?? null;
  let lastAcked: number | null = null;
  // Reclamation debt carried BETWEEN cycles. Bounded at one seq by construction:
  // `drainOnce` settles it before pulling a new batch and returns without
  // pulling if it cannot, so this can never accumulate a list (AGENTS rule 8).
  let pendingAckSeq: number | null = options.initialPendingAckSeq ?? null;
  let consecutiveFaultCursor: number | null = null;
  let consecutiveFaultsAtCursor = 0;
  let timer: unknown = null;
  let inflight: Promise<void> = Promise.resolve();

  const cycle = async (): Promise<void> => {
    if (stopped) return;
    let faultedThisCycle = false;
    try {
      // Drain all currently-pending batches before sleeping.
      let morePending = true;
      while (morePending && !stopped) {
        const result = await drainOnce(
          client,
          consumer,
          cursor,
          maxEvents,
          options.onError,
          options.onDrainFault,
          { pendingAckSeq, onRetryableFault: options.onRetryableFault }
        );
        cursor = result.nextAfterSeq;
        pendingAckSeq = result.pendingAckSeq;
        if (result.drained > 0) lastAcked = cursor;
        if (result.faulted) faultedThisCycle = true;
        morePending = result.morePending;
      }
    } catch (err) {
      // `drainOnce` routes daemon-classified failures itself, so anything
      // reaching here is an UNEXPECTED throw. Treated as TERMINAL, which is the
      // pre-existing fail-closed behavior for a dropped link: the signed
      // enforcement evidence is not reaching the consumer, so in opt-in mode the
      // wall is armed-but-not-draining. We never throw out of the loop; the
      // health machine (opt-in mode) decides whether to tear the activation
      // down. Without an `onDrainFault` handler the loop simply retries on the
      // next tick (the channel-basis floor behavior).
      const fault = err instanceof Error ? err : new Error(String(err));
      if (options.onDrainFault) options.onDrainFault(fault);
      else options.onError?.(fault);
      faultedThisCycle = true;
    }
    if (!faultedThisCycle && pendingAckSeq === null) {
      // A clean cycle with nothing owed. The caller resets its retryable budget
      // here, which is what makes that budget count CONSECUTIVE failures rather
      // than every failure the process has ever seen.
      options.onCycleHealthy?.();
    }
    if (faultedThisCycle) {
      if (consecutiveFaultCursor === cursor) {
        consecutiveFaultsAtCursor += 1;
      } else {
        consecutiveFaultCursor = cursor;
        consecutiveFaultsAtCursor = 1;
      }
      // DELIBERATELY NO ACK-AND-DROP HERE. Bounding the RATE of re-delivery
      // (the no-progress guard above plus the capped backoff below) is what
      // removes the unbounded-allocation path. ACKing a never-persisted event
      // to "make progress" would advance the daemon cursor past evidence the
      // consumer never accepted, which either loses that evidence silently or
      // leaves the next event's prior_sha256_hex chaining from a head the
      // consumer never anchored - manufacturing the very chain fork the shared
      // -basis fix exists to remove. A durable, inspectable quarantine (persist
      // the faulted event + its signature metadata BEFORE any ack, and carry a
      // verified continuity anchor across it) is the only sound way to skip a
      // stuck event; that is deliberately out of scope here and tracked as its
      // own build. Until then a persistently faulting cursor retries slowly and
      // loudly forever, which is bounded and honest.
    } else {
      consecutiveFaultCursor = cursor;
      consecutiveFaultsAtCursor = 0;
    }
    if (!stopped) {
      const delayMs = faultedThisCycle
        ? faultBackoffDelayMs(
            pollIntervalMs,
            maxFaultBackoffMs,
            consecutiveFaultsAtCursor
          )
        : pollIntervalMs;
      timer = setTimer(() => {
        inflight = cycle();
      }, delayMs);
    }
  };

  inflight = cycle();

  return {
    stop: async () => {
      stopped = true;
      if (timer !== null) clearTimer(timer);
      // Let the in-flight cycle settle so we don't ack/persist mid-write.
      await inflight.catch(() => {});
    },
    lastAckedSeq: () => lastAcked,
  };
}

function positiveIntegerOption(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value < 1) return fallback;
  return Math.floor(value);
}

function faultBackoffDelayMs(
  pollIntervalMs: number,
  maxFaultBackoffMs: number,
  consecutiveFaultsAtCursor: number
): number {
  const exponent = Math.max(0, consecutiveFaultsAtCursor - 1);
  const delay = pollIntervalMs * 2 ** exponent;
  return Math.min(delay, maxFaultBackoffMs);
}
