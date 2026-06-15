/**
 * Linux audit-drain pull-loop (the missing "PR 2b" consumer feed).
 *
 * Slice L1/R/P built the producer-signing daemon + the re-verifying consumer,
 * but nothing in production ever pulled the daemon's signed events INTO the
 * consumer. This module is that feed: it issues `audit_drain_request` frames to
 * the enforcing Linux daemon (the hybrid PULL model — main drives the pace),
 * maps each returned `AuditDrainEvent` into a `CriticalEventEnvelope` with the
 * per-event producer-signature material attached, and runs it through the audit
 * consumer's fail-closed re-verification gate. A genuine daemon-signed event
 * re-verifies; an in-process forger that minted the `cw_source` marker but
 * cannot mint a valid producer signature is rejected.
 *
 * # Why the consumer — not this loop — decides the verdict
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
 * — accepted, rejected-and-recorded, or duplicate-dropped — and skips it only
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
  /** Injected timer for tests; defaults to setTimeout. */
  setTimer?: (cb: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  /**
   * Optional sink for non-fatal loop diagnostics (transient drain errors). The
   * loop never throws on a transient error — it logs and retries — so a wedged
   * daemon link degrades observably rather than crashing the host process.
   */
  onError?: (err: Error) => void;
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
  // inside the signed body — the consumer's WAL-chain validator reads it from
  // `event.details`, so we graft it on. The signed body remains the
  // authoritative source for evidence fields (the consumer re-parses
  // `producer.eventCanonicalJson` and uses THAT, not these details, for signed
  // evidence — so there is no staple/strip attack surface here).
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
 * event is durably handled — accepted, rejected-and-recorded, or
 * duplicate-dropped. That callback sends `audit_drain_ack(seq)` and advances our
 * cursor. An event whose ingest throws for a TRANSIENT reason never reaches its
 * ack, so the cursor does not advance past it and the daemon re-delivers it.
 *
 * Both the consumer's expected throws (an `AuditChainError` for a refused
 * forgery is thrown AFTER the durable refusal + ack) and a TRANSIENT throw
 * (persistence/transport, before ack) surface here; we report them and keep
 * iterating the batch (a forgery in the middle of a batch must not block later
 * genuine events from being pulled — each event is independently
 * seq-acked/cursored). The cursor only ever advances via the ack callback, so a
 * transient (un-acked) failure correctly leaves that seq pending.
 */
export async function drainOnce(
  client: IpcClient,
  consumer: AuditConsumer,
  afterSeq: number | null,
  maxEvents: number,
  onError?: (err: Error) => void
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
      // A malformed drain entry is not the consumer's concern; surface it and
      // STOP iterating so the cursor does not advance past the gap (the daemon
      // re-delivers from `cursor`).
      onError?.(new Error(`audit_drain: ${built.reason} at seq ${drainedEvent.seq}`));
      break;
    }
    try {
      await consumer.ingestCritical(built.envelope);
    } catch (err) {
      // The consumer throws `AuditChainError` for a refused forgery / chain
      // error — but only AFTER durably recording it AND calling our ack (so the
      // cursor already advanced past it inside the callback above). A TRANSIENT
      // throw (persistence/transport) happens BEFORE ack, so the cursor stays
      // put and the daemon re-delivers. Either way we just report and continue:
      // the ack callback is the single source of cursor truth.
      onError?.(err instanceof Error ? err : new Error(String(err)));
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
 * `pollIntervalMs` before the next cycle. Transient errors are reported via
 * `onError` and the loop continues (a wedged daemon link degrades observably,
 * it does not crash the host). Returns a handle whose `stop()` halts the loop
 * after the in-flight cycle settles.
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
  let cursor: number | null = null;
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
          options.onError
        );
        cursor = result.nextAfterSeq;
        if (result.drained > 0) lastAcked = cursor;
        morePending = result.morePending;
      }
    } catch (err) {
      // A drain-request transport failure (link dropped) is transient: report
      // and retry on the next tick. Never throw out of the loop.
      options.onError?.(err instanceof Error ? err : new Error(String(err)));
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
