/**
 * Streaming consumer that drives the enforcement exporter off the verified audit
 * chain with a DURABLE CURSOR and BOUNDED RETRY.
 *
 * It ties three already-safe pieces together WITHOUT weakening any of them:
 *   - `AuditLog.streamVerifiedChain` (the tamper-evident, strict-verified source),
 *   - the CLOSED `mapAuditEntryToEnforcementEvent` mapping (metadata only; raw
 *     `details` are never spread), and
 *   - the already-armed `EnforcementExporter` (safe-by-default sink; the outbound
 *     HTTP push is Tier-1-gated + pinned + fail-loud).
 *
 * DURABLE CURSOR (resume, no re-send storm, no gap): a run forwards only entries
 * whose chain sequence is STRICTLY ABOVE the persisted cursor. The cursor is
 * advanced (and persisted) ONLY AFTER a batch is confirmed delivered by the
 * fail-loud sink, so a crash can only leave it BEHIND the delivered frontier
 * (the fail-safe direction: re-scan + re-deliver, never skip). See `./cursor.ts`.
 *
 * BOUNDED RETRY, STILL FAIL CLOSED: a transient sink failure is retried up to a
 * bounded budget with backoff. The retried payload is the SAME already-mapped
 * metadata batch (never re-derived, never a different / less-secure sink: the
 * sink was fixed at `enable()` time and this module never falls back). After the
 * budget is exhausted the streamer records a distinct `_retry_exhausted` op and
 * RE-THROWS, leaving the cursor un-advanced so the batch is re-attempted next
 * run. It never silently drops a batch and never reports success on failure.
 *
 * TAMPER-EVIDENCE IS PRESERVED (the safety is in the await, not a pre-gate): the
 * consumer buffers mapped events DURING `streamVerifiedChain`'s decrypt loop but
 * DELIVERS them only AFTER the await resolves clean. In strict mode the await
 * throws `AuditIntegrityError` on a chain that does not verify, so a tampered
 * chain makes this method reject before a single event is delivered. On a
 * torn-read retry the consumer's `reset()` discards the partial buffer so exactly
 * one accepted verified pass is delivered.
 */

import type { AuditEntry } from "../../operational/audit-log.js";
import { mapAuditEntryToEnforcementEvent } from "./map.js";
import type { EnforcementEvent } from "./schema.js";
import type { EnforcementExporter, ExportAudit } from "./exporter.js";
import { EXPORT_CURSOR_START, type ExportCursorStore } from "./cursor.js";
import {
  ENFORCEMENT_EXPORT_CURSOR_ADVANCED,
  ENFORCEMENT_EXPORT_CURSOR_RESET,
  ENFORCEMENT_EXPORT_RETRY_EXHAUSTED,
} from "./audit-ops.js";

/**
 * The narrow slice of `AuditLog` the streamer reads: one verified-chain pass. Each
 * item carries the `entry_hash` (the tamper-evident chain link) so the streamer can
 * BIND the cursor to the chain identity — a wipe+recreate that regrows a different
 * chain carries a different hash at the same sequence, which the streamer detects.
 */
export interface VerifiedChainSource {
  streamVerifiedChain(consumer: {
    onEntry: (item: { sequence: number; entry_hash: string; entry: AuditEntry }) => void;
    reset?: () => void;
  }): Promise<void>;
}

/** A mapped event paired with the chain sequence + entry hash it was read from. */
interface SequencedEvent {
  sequence: number;
  /** The chain `entry_hash` at `sequence` — persisted as the cursor's identity anchor. */
  entryHash: string;
  event: EnforcementEvent;
}

/** The result of one verified-chain scan: buffered forwardable events + chain-head facts. */
interface ChainScan {
  /** Mapped, forwardable events STRICTLY above the scan's cursor, in chain order. */
  buffered: SequencedEvent[];
  /** Highest sequence SEEN this pass (the verified chain head), or null on an empty chain. */
  actualChainHead: number | null;
  /** The `entry_hash` at `actualChainHead` (null iff the chain is empty). */
  headHash: string | null;
  /** The `entry_hash` at the scan's cursor sequence, or null if that sequence is not present. */
  hashAtCursor: string | null;
}

/**
 * Reasons the streamer DISCARDS a valid-MAC-but-stale cursor after seeing the
 * chain. These are distinct from the store-level reasons (in `./cursor.ts`)
 * because they need the verified chain head, which only the streamer knows.
 */
type StreamerCursorResetReason =
  /** The cursor sits ABOVE the verified chain head — an overshoot tamper signal
   * (the exact `999999999` case), or a chain that shrank under a stale cursor. */
  | "cursor_above_chain_head"
  /** The cursor's sequence is not present in the surviving chain (FIFO-pruned, or
   * a different chain) → its identity binding cannot be re-verified here. */
  | "cursor_sequence_absent"
  /** The surviving entry at the cursor's sequence carries a DIFFERENT hash → a
   * wipe+recreate regrew a different chain; the old position is meaningless. */
  | "cursor_chain_identity_mismatch";

/** Options controlling batch size + the bounded retry budget. */
export interface EnforcementExportStreamerOptions {
  /** Max events per delivered batch. Default 500. Must be a positive integer. */
  batchSize?: number;
  /**
   * Max RE-tries after the first attempt on a transient sink failure (so a value
   * of 3 makes up to 4 total attempts). Default 3. `0` disables retry (still
   * fails closed). Must be a non-negative integer.
   */
  maxRetries?: number;
  /** Base backoff between retries in ms (multiplied by the attempt number). Default 200. */
  retryBackoffMs?: number;
  /** Injected sleep so tests are hermetic (no real timers). Defaults to a real delay. */
  sleep?: (ms: number) => Promise<void>;
}

export interface EnforcementExportStreamerDeps extends EnforcementExportStreamerOptions {
  /** An ALREADY-ENABLED exporter (its sink is fixed; this module never re-arms it). */
  exporter: EnforcementExporter;
  /** The durable resume point. */
  cursor: ExportCursorStore;
  /** Local audit append for the cursor-advance / cursor-reset / retry-exhausted ops. */
  audit: ExportAudit;
  /**
   * LOUD sink for a cursor RESET, in ADDITION to the audit record: a reset means a
   * full re-send (or a formerly-blind console), so it is announced on stderr too.
   * Defaults to `process.stderr`; injected so tests stay hermetic.
   */
  warn?: (message: string) => void;
}

/** Outcome of a single `runOnce()`. */
export interface StreamRunOutcome {
  /** Cursor at the start of the run (the resume point read from disk). */
  fromCursor: number;
  /** Cursor at the end of the run (the new persisted resume point). */
  toCursor: number;
  /** Number of enforcement events delivered this run. */
  delivered: number;
  /** Number of batches delivered this run. */
  batches: number;
}

const DEFAULT_BATCH_SIZE = 500;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BACKOFF_MS = 200;

function realSleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Drives one pass of the verified chain into the armed exporter, advancing a
 * durable cursor. Construct once per run (or reuse: `runOnce` re-reads the cursor
 * each call, so it is safe to call repeatedly, e.g. from a poll loop).
 */
export class EnforcementExportStreamer {
  private readonly batchSize: number;
  private readonly maxRetries: number;
  private readonly retryBackoffMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly warn: (message: string) => void;

  constructor(private readonly deps: EnforcementExportStreamerDeps) {
    const batchSize = deps.batchSize ?? DEFAULT_BATCH_SIZE;
    if (!Number.isInteger(batchSize) || batchSize < 1) {
      throw new Error("batchSize must be a positive integer");
    }
    const maxRetries = deps.maxRetries ?? DEFAULT_MAX_RETRIES;
    if (!Number.isInteger(maxRetries) || maxRetries < 0) {
      throw new Error("maxRetries must be a non-negative integer");
    }
    this.batchSize = batchSize;
    this.maxRetries = maxRetries;
    this.retryBackoffMs = deps.retryBackoffMs ?? DEFAULT_RETRY_BACKOFF_MS;
    this.sleep = deps.sleep ?? realSleep;
    this.warn = deps.warn ?? ((message) => void process.stderr.write(`${message}\n`));
  }

  /**
   * Read the cursor, stream the verified chain forwarding only entries above it,
   * deliver in bounded batches with retry, and durably advance the cursor as each
   * batch lands. Rejects (fail closed) if a batch exhausts its retry budget.
   *
   * CURSOR AUTHENTICATION + HEAD-CLAMP + IDENTITY BINDING (fail LOUD, never a
   * silent zero-forward): the persisted cursor is master-key-MAC'd (`./cursor.ts`).
   * A read that DISCARDED the cursor (unreadable/corrupt/unauthenticated/tampered)
   * is announced loudly and falls back to the start sentinel (re-scan). AFTER the
   * verified pass, a valid-MAC-but-stale cursor is caught too: one ABOVE the chain
   * head (the `999999999` overshoot), or bound to a different chain identity (an
   * audit-store wipe+recreate), triggers a LOUD reset + a re-scan from the start so
   * the new low sequences are never silently skipped. Every reset re-sends already
   * delivered events (the collector dedupes); it NEVER skips.
   */
  async runOnce(source: VerifiedChainSource): Promise<StreamRunOutcome> {
    const read = await this.deps.cursor.read();
    let fromCursor = read.state.sequence;
    const boundHash = read.state.entryHash;

    // A store-level DISCARD (bad MAC, legacy/unauthenticated, corrupt, unreadable)
    // already reset `state` to the start sentinel; make the reset LOUD, then scan
    // from the start below (fromCursor is already the sentinel).
    if (read.reset) {
      await this.recordCursorReset(read.reset.reason, read.reset.detail, read.state.sequence);
    }

    // ── First verified pass with the authenticated cursor. ──────────────────
    let scan = await this.scanChain(source, fromCursor);

    // ── Head-clamp + chain-identity binding (catch a valid-MAC-but-stale cursor).
    // Only meaningful for a real (non-start) cursor against a non-empty chain.
    if (fromCursor !== EXPORT_CURSOR_START && scan.actualChainHead !== null) {
      let reason: StreamerCursorResetReason | null = null;
      let detail = "";
      if (fromCursor > scan.actualChainHead) {
        reason = "cursor_above_chain_head";
        detail = `cursor ${fromCursor} is above the verified chain head ${scan.actualChainHead}`;
      } else if (boundHash !== null && scan.hashAtCursor === null) {
        reason = "cursor_sequence_absent";
        detail = `cursor sequence ${fromCursor} is not present in the surviving chain (pruned, or a different chain)`;
      } else if (boundHash !== null && scan.hashAtCursor !== boundHash) {
        reason = "cursor_chain_identity_mismatch";
        detail = `entry hash at cursor sequence ${fromCursor} does not match the bound chain identity`;
      }
      if (reason !== null) {
        await this.recordCursorReset(reason, detail, fromCursor);
        // Re-scan from the start: the buffered set was filtered against a stale
        // cursor and would skip the surviving chain's prefix. Re-sending from the
        // start is the fail-safe (at-least-once) direction. The identity binding is
        // dropped with the reset (nothing below reads `boundHash` again).
        fromCursor = EXPORT_CURSOR_START;
        scan = await this.scanChain(source, fromCursor);
      }
    }

    // `highWaterScanned` is the highest sequence SEEN (including dropped/
    // non-forwarded entries) so a long tail of un-forwardable entries is not
    // re-scanned every run once a clean pass completes.
    const highWaterScanned =
      scan.actualChainHead === null ? fromCursor : Math.max(fromCursor, scan.actualChainHead);

    // ── Deliver AFTER the verified pass resolved clean ──────────────────────
    let delivered = 0;
    let batches = 0;
    let toCursor = fromCursor;

    for (let i = 0; i < scan.buffered.length; i += this.batchSize) {
      const slice = scan.buffered.slice(i, i + this.batchSize);
      const events = slice.map((s) => s.event);
      const last = slice[slice.length - 1]!;

      await this.deliverWithRetry(events);

      // The batch is confirmed delivered by the fail-loud sink. Advance + persist
      // the cursor to this batch's high sequence (bound to that entry's hash)
      // BEFORE moving on, so a crash mid-run resumes after the last DELIVERED
      // batch (no re-send storm) and never past an undelivered one (no gap).
      toCursor = last.sequence;
      await this.deps.cursor.write({ sequence: toCursor, entryHash: last.entryHash });
      await this.deps.audit(
        ENFORCEMENT_EXPORT_CURSOR_ADVANCED,
        { from: fromCursor, to: toCursor, batch_events: events.length, reason: "batch_delivered" },
        "success",
      );
      delivered += events.length;
      batches += 1;
    }

    // A clean pass with everything delivered advances the cursor past any
    // un-forwardable tail so it is not re-scanned next run. Only ever moves the
    // cursor FORWARD, and only after every batch landed. The identity anchor is
    // the chain HEAD's hash (the sequence we advance to).
    if (highWaterScanned > toCursor && scan.headHash !== null) {
      toCursor = highWaterScanned;
      await this.deps.cursor.write({ sequence: toCursor, entryHash: scan.headHash });
      await this.deps.audit(
        ENFORCEMENT_EXPORT_CURSOR_ADVANCED,
        { from: fromCursor, to: toCursor, batch_events: 0, reason: "scan_complete" },
        "success",
      );
    }

    return { fromCursor, toCursor, delivered, batches };
  }

  /**
   * One verified-chain pass, buffering the mapped forwardable events STRICTLY
   * above `fromCursor` and capturing the chain-head facts the head-clamp +
   * identity checks need. `reset()` discards a torn-read partial pass.
   */
  private async scanChain(
    source: VerifiedChainSource,
    fromCursor: number,
  ): Promise<ChainScan> {
    let buffered: SequencedEvent[] = [];
    let actualChainHead: number | null = null;
    let headHash: string | null = null;
    let hashAtCursor: string | null = null;
    await source.streamVerifiedChain({
      onEntry: (item) => {
        if (actualChainHead === null || item.sequence > actualChainHead) {
          actualChainHead = item.sequence;
          headHash = item.entry_hash;
        }
        if (item.sequence === fromCursor) hashAtCursor = item.entry_hash;
        if (item.sequence <= fromCursor) return;
        const event = mapAuditEntryToEnforcementEvent(item.entry);
        if (event !== null) buffered.push({ sequence: item.sequence, entryHash: item.entry_hash, event });
      },
      reset: () => {
        buffered = [];
        actualChainHead = null;
        headHash = null;
        hashAtCursor = null;
      },
    });
    return { buffered, actualChainHead, headHash, hashAtCursor };
  }

  /**
   * Announce a cursor RESET on BOTH channels: a durable `_cursor_reset` audit
   * record (best-effort, never throws) AND stderr. A reset means the off-box
   * console is about to receive a full re-send (or was blind); it must never be
   * silent. The reason/detail carry no secrets.
   */
  private async recordCursorReset(
    reason: string,
    detail: string,
    discardedFrom: number,
  ): Promise<void> {
    this.warn(
      `sanctuary cortex-export: export cursor RESET to start (${reason}): ${detail}. ` +
        "Re-scanning the verified chain from the beginning; already-delivered events may " +
        "be re-sent (the collector dedupes on event identity). This is never a skip.",
    );
    await this.deps.audit(
      ENFORCEMENT_EXPORT_CURSOR_RESET,
      { reason, detail, discarded_from: discardedFrom },
      "failure",
    );
  }

  /**
   * Deliver one already-mapped batch through the armed exporter, retrying a
   * transient failure up to the bounded budget. The retried payload is the SAME
   * `events` array (metadata only) delivered through the SAME sink; there is no
   * re-mapping and no fallback to a different lane. After the budget is exhausted
   * this records a distinct `_retry_exhausted` op and RE-THROWS (fail closed).
   */
  private async deliverWithRetry(events: readonly EnforcementEvent[]): Promise<void> {
    let attempt = 0;
    for (;;) {
      let outcomeReason: string | null;
      try {
        const outcome = await this.deps.exporter.exportEvents(events);
        if (outcome.status === "refused") {
          // The exporter refused WITHOUT throwing (e.g. it is not enabled). That
          // is a configuration fault, not a transient blip: fail closed
          // immediately (no retry) rather than spin the loop against a dead sink.
          outcomeReason = outcome.reason;
        } else {
          return;
        }
      } catch (err) {
        // A THROW from the sink is a transient delivery failure: retry within the
        // bounded budget, then fail closed.
        if (attempt >= this.maxRetries) {
          const reason = err instanceof Error ? err.message : "delivery failed";
          await this.recordRetryExhausted(events.length, attempt, reason);
          throw err;
        }
        attempt += 1;
        await this.sleep(this.retryBackoffMs * attempt);
        continue;
      }
      // Reached only on a non-throwing refusal: terminal, not retried.
      await this.recordRetryExhausted(events.length, attempt, outcomeReason ?? "refused");
      throw new Error(`enforcement export refused: ${outcomeReason ?? "refused"}`);
    }
  }

  private async recordRetryExhausted(
    batchEvents: number,
    attempts: number,
    reason: string,
  ): Promise<void> {
    await this.deps.audit(
      ENFORCEMENT_EXPORT_RETRY_EXHAUSTED,
      { batch_events: batchEvents, attempts: attempts + 1, reason },
      "failure",
    );
  }
}

export { EXPORT_CURSOR_START };
