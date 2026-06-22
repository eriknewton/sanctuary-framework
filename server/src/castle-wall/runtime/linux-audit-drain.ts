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
import type { AuditConsumer, CriticalEventEnvelope } from "./audit-consumer.js";
import type { IpcClient } from "./ipc-client.js";

/**
 * Map a daemon WAL `operation` tag to the consumer's `event_type`. MUST stay in
 * sync with `WAL_OPERATION_TO_EVENT_TYPE` in `audit-consumer.ts` (which the
 * consumer uses to cross-check the signed body against the persisted slot). Only
 * the enforcement-evidence operations are mapped here; any other operation maps
 * to its own string and is carried through unchanged (control/diagnostic events
 * are not producer-gated by the consumer).
 */
const WAL_OPERATION_TO_EVENT_TYPE: Readonly<Record<string, string>> = Object.freeze({
  egress_approved: "egress_allowed",
  egress_blocked: "egress_blocked",
  egress_pending: "operator_decision",
});

/** Default batch cap per drain request. Matches a sane daemon snapshot ceiling. */
export const DEFAULT_AUDIT_DRAIN_MAX_EVENTS = 256;

/** Options for one drain cycle / the continuous loop. */
export interface LinuxAuditDrainOptions {
  /** Max events to request per drain frame. Defaults to 256. */
  maxEvents?: number;
  /** Poll interval (ms) between drain cycles when running continuously. Default 1000. */
  pollIntervalMs?: number;
  /**
   * Seq to resume the loop's cursor from (exclusive - the first cycle pulls
   * strictly above it). Defaults to null (drain from the start). The activation
   * gate sets this to the cursor its fail-closed initial-drain confirmation
   * probe reached, so the continuous loop neither re-pulls nor skips an event
   * the probe already drained.
   */
  initialCursor?: number | null;
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

  const fortressId =
    typeof body.fortress_id === "string" && body.fortress_id.length > 0
      ? body.fortress_id
      : typeof body.identity_id === "string"
        ? body.identity_id
        : "unknown";
  const timestamp =
    typeof body.timestamp === "string" ? body.timestamp : new Date(drained.captured_at_unix_ms).toISOString();

  const bodyDetails =
    body.details !== null && typeof body.details === "object" && !Array.isArray(body.details)
      ? (body.details as Record<string, unknown>)
      : {};

  // The chain metadata (`seq`, `prior_sha256_hex`) lives on the WIRE entry, not
  // inside the signed body - the consumer's WAL-chain validator reads it from
  // `event.details`, so we graft it on. The signed body remains the
  // authoritative source for evidence fields (the consumer re-parses
  // `producer.eventCanonicalJson` and uses THAT, not these details, for signed
  // evidence - so there is no staple/strip attack surface here).
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
    producer: {
      eventCanonicalJson: drained.event_canonical_json,
      capturedAtUnixMs: drained.captured_at_unix_ms,
      seq: drained.seq,
      signatureB64url: drained.producer_signature_b64url ?? null,
      keyId: drained.producer_key_id ?? null,
    },
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
  onDrainFault?: (err: Error) => void
): Promise<{ nextAfterSeq: number | null; morePending: boolean; drained: number }> {
  const response: AuditDrainResponse = await client.drainRequest(afterSeq, maxEvents);
  let cursor: number | null = afterSeq;
  let drained = 0;

  for (const drainedEvent of response.events) {
    // The per-event ack IS the drain ack: the consumer invokes it on durable
    // settlement, which truncates the daemon WAL through this seq and advances
    // our cursor. Building the cursor advance INSIDE the ack means the cursor
    // can never run ahead of what the consumer durably settled.
    const built = buildCriticalEnvelopeFromDrainEvent(drainedEvent, async () => {
      await client.sendDrainAck(drainedEvent.seq);
      cursor = drainedEvent.seq;
      drained += 1;
    });
    if (built.kind === "error") {
      // A malformed drain entry never settles (the cursor cannot advance past a
      // body we cannot even parse). That is an UNSETTLED FAULT: the daemon's
      // signed bytes are not arriving intact, so in opt-in mode the wall is
      // armed-but-not-draining. Route it to `onDrainFault` (trips NOT-ARMED) and
      // STOP iterating so the cursor does not advance past the gap (the daemon
      // re-delivers from `cursor`).
      onDrainFault?.(
        new Error(`audit_drain: ${built.reason} at seq ${drainedEvent.seq}`)
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
    // duplicate-dropped). The cursor is therefore the single discriminator:
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
      // which - with `lastEventCanonicalHash` still null because seq N never
      // persisted - would accept N+1 as a fresh bootstrap and ack
      // `audit_drain_ack(N+1)`, truncating the daemon WAL THROUGH the lost seq N
      // (silent audit data loss). This is an UNSETTLED FAULT → `onDrainFault`
      // (trips NOT-ARMED in opt-in mode). We STOP the batch; the cursor stays at
      // the last durably settled seq and the daemon re-delivers from there.
      onDrainFault?.(
        ingestError ??
          new Error(
            `audit_drain: event seq ${drainedEvent.seq} did not settle (no ack)`
          )
      );
      break;
    }
  }

  return {
    nextAfterSeq: cursor,
    morePending: response.more_pending,
    drained,
  };
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
  const setTimer = options.setTimer ?? ((cb, ms) => setTimeout(cb, ms));
  const clearTimer = options.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));

  let stopped = false;
  let cursor: number | null = options.initialCursor ?? null;
  let lastAcked: number | null = null;
  let timer: unknown = null;
  let inflight: Promise<void> = Promise.resolve();

  const cycle = async (): Promise<void> => {
    if (stopped) return;
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
          options.onDrainFault
        );
        cursor = result.nextAfterSeq;
        if (result.drained > 0) lastAcked = cursor;
        morePending = result.morePending;
      }
    } catch (err) {
      // A `drainRequest` itself threw - the daemon link dropped. The signed
      // enforcement evidence is not reaching the consumer, so in opt-in mode the
      // wall is armed-but-not-draining: this is an UNSETTLED transport FAULT
      // (`onDrainFault` → NOT-ARMED), NOT a settled diagnostic. We never throw
      // out of the loop; the health machine (opt-in mode) decides whether to
      // tear the activation down. Without an `onDrainFault` handler the loop
      // simply retries on the next tick (the channel-basis floor behavior).
      const fault = err instanceof Error ? err : new Error(String(err));
      if (options.onDrainFault) options.onDrainFault(fault);
      else options.onError?.(fault);
    }
    if (!stopped) {
      timer = setTimer(() => {
        inflight = cycle();
      }, pollIntervalMs);
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
