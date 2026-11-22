/**
 * Denial ledger: the operator-side record of why a tool call was refused.
 *
 * Every refusal leaves the MCP router as one fixed result, so the cause of a
 * refusal is never visible to the agent. The router hands the cause to this
 * ledger instead, and the ledger records it in the audit log: one
 * `denial_cause` row per tool per window, and one `denial_cause_summary` row
 * when a window that saw more than one refusal closes.
 *
 * The ledger's own state and I/O are bounded whatever the caller does and
 * whatever the audit log does: a fixed number of open windows, fixed-size
 * counters per window, and a global cap on appends that have not settled.
 * Nothing here is awaited by the router, and nothing here throws into it, so a
 * ledger append never delays the refusing call's own response. Its appends go
 * through the audit log's one append queue, which later calls share with it
 * exactly as they share it with every gate and tool append.
 */
import { randomBytes } from "node:crypto";
import {
  AuditChainStateUnknownError,
  AuditLockContentionError,
  AuditPersistenceError,
  AuditWriterAuthorityError,
  type AuditLog,
} from "../operational/audit-log.js";

/**
 * The closed list of refusal causes. Must match the literals the router passes
 * at every recordDenial call site in router.ts, which
 * test/agent-native/denial-ledger.test.ts checks structurally. A value outside
 * this list is recorded as `other`.
 */
export const DENIAL_CAUSES = [
  "pre_gate_argument_refused",
  "export_capacity",
  "pre_gate_record_fault",
  "gate_fault",
  "gate_denied",
  "integrity_read_fault",
  "write_integrity_stop",
  "handler_error",
  "post_allow_refusal",
  "proxy_upstream_error",
  // This cause must match argumentStageCause in tool-outcome.ts.
  "session_not_bound",
  "origin_unresolved",
  "other",
] as const;

export type DenialCause = (typeof DENIAL_CAUSES)[number];

const DENIAL_CAUSE_SET: ReadonlySet<string> = new Set(DENIAL_CAUSES);

export function closedDenialCause(cause: string): DenialCause {
  return DENIAL_CAUSE_SET.has(cause) ? (cause as DenialCause) : "other";
}

/** The same minute the baseline's rate windows use. */
export const DENIAL_WINDOW_MS = 60_000;
/**
 * Open windows tracked at once: the same figure as
 * OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS in principal-policy/gate.ts (bookkeeping
 * bounded independently of how many names are presented). One more overflow
 * window takes every key that arrives while all of these are open, so at most
 * DENIAL_LEDGER_MAX_KEYS + 1 windows are live.
 */
export const DENIAL_LEDGER_MAX_KEYS = 256;
/** One first row and one summary for every live window (256 keyed + 1 overflow). */
export const DENIAL_LEDGER_MAX_PENDING_APPENDS = 2 * (DENIAL_LEDGER_MAX_KEYS + 1);
/** Well above one local append, short enough not to stall a stop. */
export const LEDGER_CLOSE_DEADLINE_MS = 5_000;
/**
 * Enough for a one-line error; 257 first rows stay under 64 KiB of message
 * text (257 * 200 = 51,400 bytes). Counted in stored bytes (see
 * storedStringBytes), never in characters.
 */
export const DENIAL_FIRST_ROW_MESSAGE_MAX_BYTES = 200;
/** Linked refs kept per window, so a window's record stays fixed-size. */
export const DENIAL_WINDOW_MAX_LINKED_REFS = 8;
/**
 * Stored-byte width of every identifier-like row field (tool, error name,
 * linked ref, the agent id inside origin): the MCP tool-name length limit of
 * 128, which every tool name, error class name, verdict key and audit ref in
 * this tree is well inside. A longer value is truncated.
 */
export const DENIAL_ROW_IDENTIFIER_MAX_BYTES = 128;
// The router's caller principal is `agent:<id>` (router.ts); the id gets the identifier width.
const ORIGIN_PREFIX = "agent:";
/** Stored-byte width of origin: the `agent:` prefix plus one identifier. */
export const DENIAL_ROW_ORIGIN_MAX_BYTES = ORIGIN_PREFIX.length + DENIAL_ROW_IDENTIFIER_MAX_BYTES;
// Window counters are clamped here, so a summary's counters have a fixed widest form.
const DENIAL_COUNTER_MAX = Number.MAX_SAFE_INTEGER;
/**
 * The handler-reported facts a first row carries. Must match the keys
 * refusedResultFacts reads in tool-outcome.ts; any other key is dropped so the
 * row's key set stays fixed.
 */
const DENIAL_FACT_KEYS = ["committed", "audited"] as const;
// 8 random bytes = 16 hex characters, the width of the router's tool_error refs.
const DENIAL_REF_BYTES = 8;
// The overflow window's key; registered tool names never contain a space.
const OVERFLOW_KEY = "overflow window";
const OVERFLOW_TOOL = "overflow";

/** What the router knows about one refusal; operator-side only. */
export interface DenialRecordInput {
  /** The registered tool name. */
  readonly tool: string;
  /** The router's server-set caller principal (`agent:<id>` or `agent:unknown`). */
  readonly origin: string;
  /** An audit id this refusal relates to (an approval audit id, a tool_error ref). */
  readonly linked_ref?: string;
  /** The first error's name, or the top-level verdict key of a refused body. */
  readonly error_name?: string;
  /** The first error's message, or the top-level verdict value of a refused body. */
  readonly error_message?: string;
  /** Boolean facts a handler reported about effects it already committed. */
  readonly facts?: Readonly<Record<string, boolean>>;
}

/** The router's view of the ledger: record and forget, never awaited. */
export interface DenialRecorder {
  record(cause: DenialCause, input: DenialRecordInput): void;
}

/**
 * A ledger with no audit sink, for router fixtures built without an audit log:
 * it counts refusals per cause and starts no I/O.
 */
export class CountingDenialRecorder implements DenialRecorder {
  private readonly counts = new Map<DenialCause, number>();

  record(cause: DenialCause, _input: DenialRecordInput): void {
    const closed = closedDenialCause(cause);
    this.counts.set(closed, (this.counts.get(closed) ?? 0) + 1);
  }

  count(cause: DenialCause): number {
    return this.counts.get(cause) ?? 0;
  }
}

/** How a window's first row ended; `pending` until its append settles. */
export const FIRST_ROW_STATES = ["pending", "written", "failed", "unconfirmed", "skipped_budget"] as const;
export type FirstRowState = (typeof FIRST_ROW_STATES)[number];
/** How a window's summary ended; `none` when the window closed with one refusal. */
export type SummaryState = "none" | "pending" | "written" | "failed" | "skipped_budget";

/**
 * One window's own record. A detached append holds this record, never the map
 * entry, so a late settle updates only its own generation and releases only
 * the slots it reserved.
 */
export interface DenialGeneration {
  readonly generation_id: number;
  readonly key: string;
  readonly denial_ref: string;
  first_row: FirstRowState;
  summary: SummaryState;
  slots_held: number;
}

interface DenialWindow {
  readonly generation: DenialGeneration;
  readonly tool: string;
  readonly window_started_at: number;
  attempted: number;
  readonly causes: Map<DenialCause, number>;
  readonly linked_refs: string[];
}

export interface DenialLedgerSnapshot {
  readonly open_keyed_windows: number;
  readonly overflow_open: boolean;
  readonly pending_appends: number;
  readonly ledger_budget_exhausted: number;
  readonly ledger_append_failures: number;
  /** Refusals recorded after close; counted only. */
  readonly recorded_after_close: number;
  readonly windows: ReadonlyArray<{ readonly key: string; readonly attempted: number; readonly generation: Readonly<DenialGeneration> }>;
}

export interface DenialLedgerOptions {
  /** Operator stderr line sink; defaults to process.stderr. */
  readonly warn?: (line: string) => void;
}

/**
 * Bytes a string field occupies in the row the audit log stores before
 * encryption: its JSON form (escapes included, quotes excluded) in UTF-8. Must
 * match the JSON.stringify of the normalized entry in
 * operational/audit-log.ts's persistChainedEntry.
 */
function storedStringBytes(value: string): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8") - 2;
}

/** Bytes a whole details object occupies in the stored row. */
function storedObjectBytes(value: Record<string, unknown>): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

/**
 * The longest prefix of `value` whose stored form fits `maxBytes`, cut only
 * between whole code points, so a multi-byte character is never split.
 */
export function truncateStoredString(value: string, maxBytes: number): string {
  if (storedStringBytes(value) <= maxBytes) return value;
  let kept = "";
  let used = 0;
  for (const codePoint of value) {
    const cost = storedStringBytes(codePoint);
    if (used + cost > maxBytes) break;
    kept += codePoint;
    used += cost;
  }
  return kept;
}

function longest(values: readonly string[]): string {
  return values.reduce((widest, value) => (storedStringBytes(value) > storedStringBytes(widest) ? value : widest), "");
}

// Every ISO timestamp from year 0 to 9999 has this one width.
const WIDEST_TIMESTAMP = new Date(0).toISOString();
const WIDEST_DENIAL_REF = `denial:${"f".repeat(DENIAL_REF_BYTES * 2)}`;

/**
 * Stored size of every `denial_cause` row's details: the row with every field
 * at its widest (each identifier at DENIAL_ROW_IDENTIFIER_MAX_BYTES, origin at
 * DENIAL_ROW_ORIGIN_MAX_BYTES, the message at
 * DENIAL_FIRST_ROW_MESSAGE_MAX_BYTES, the longest closed cause, every optional
 * field present and both facts at their wider value) and an empty pad. Each
 * real row is padded up to it, so a row's size says nothing about its cause.
 */
export const DENIAL_CAUSE_ROW_DETAILS_BYTES = storedObjectBytes({
  denial_ref: WIDEST_DENIAL_REF,
  tool: "x".repeat(DENIAL_ROW_IDENTIFIER_MAX_BYTES),
  cause: longest(DENIAL_CAUSES),
  origin: "x".repeat(DENIAL_ROW_ORIGIN_MAX_BYTES),
  window_started_at: WIDEST_TIMESTAMP,
  linked_ref: "x".repeat(DENIAL_ROW_IDENTIFIER_MAX_BYTES),
  error_name: "x".repeat(DENIAL_ROW_IDENTIFIER_MAX_BYTES),
  error_message: "x".repeat(DENIAL_FIRST_ROW_MESSAGE_MAX_BYTES),
  ...Object.fromEntries(DENIAL_FACT_KEYS.map((key) => [key, false])),
  pad: "",
});

/**
 * Stored size of every `denial_cause_summary` row's details: the widest tool,
 * both timestamps, every counter at DENIAL_COUNTER_MAX (one per closed cause),
 * DENIAL_WINDOW_MAX_LINKED_REFS refs at the identifier width, the longest
 * first-row state and an empty pad.
 */
export const DENIAL_SUMMARY_ROW_DETAILS_BYTES = storedObjectBytes({
  denial_ref: WIDEST_DENIAL_REF,
  tool: "x".repeat(DENIAL_ROW_IDENTIFIER_MAX_BYTES),
  window_started_at: WIDEST_TIMESTAMP,
  window_closed_at: WIDEST_TIMESTAMP,
  attempted: DENIAL_COUNTER_MAX,
  causes: Object.fromEntries(DENIAL_CAUSES.map((cause) => [cause, DENIAL_COUNTER_MAX])),
  linked_refs: Array.from({ length: DENIAL_WINDOW_MAX_LINKED_REFS }, () => "x".repeat(DENIAL_ROW_IDENTIFIER_MAX_BYTES)),
  first_row: longest(FIRST_ROW_STATES),
  pad: "",
});

/**
 * Append a pad that brings the details to exactly `rowBytes`. Every field was
 * already bounded to its width, so the shortfall is never negative for
 * timestamps in years 0 to 9999; it is clamped at zero regardless.
 */
function padTo(details: Record<string, unknown>, rowBytes: number): Record<string, unknown> {
  const shortfall = rowBytes - storedObjectBytes({ ...details, pad: "" });
  return { ...details, pad: " ".repeat(Math.max(0, shortfall)) };
}

function clampCounter(value: number): number {
  return Math.min(value, DENIAL_COUNTER_MAX);
}

/**
 * Whether a failed append is known to have been refused before any byte was
 * written. Must match the before-write contracts documented on these classes
 * in operational/audit-log.ts; any other failure may have written bytes.
 */
function refusedBeforeWrite(error: unknown): boolean {
  if (error instanceof AuditChainStateUnknownError) return true;
  if (error instanceof AuditWriterAuthorityError) return true;
  if (error instanceof AuditLockContentionError) return true;
  if (error instanceof AuditPersistenceError) {
    return error.classification === "storage_full"
      || error.classification === "disk_failure"
      || error.classification === "permission_denied";
  }
  return false;
}

export class DenialLedger implements DenialRecorder {
  private readonly windows = new Map<string, DenialWindow>();
  private overflow: DenialWindow | undefined;
  private readonly pending = new Set<Promise<void>>();
  private nextGeneration = 1;
  private pendingSlots = 0;
  private budgetExhausted = 0;
  private appendFailures = 0;
  private recordedAfterClose = 0;
  private closed = false;
  private readonly warn: (line: string) => void;

  constructor(
    private readonly auditLog: AuditLog,
    private readonly clock: () => number,
    options: DenialLedgerOptions = {},
  ) {
    this.warn = options.warn ?? ((line) => { process.stderr.write(`${line}\n`); });
  }

  /**
   * Count one refusal. Never throws and never awaits: a ledger fault must not
   * change what the router returns, and a ledger append never delays the
   * refusing call's own response (later calls share the audit log's append
   * queue with it, as they do with every other append).
   */
  record(cause: DenialCause, input: DenialRecordInput): void {
    try {
      if (this.closed) {
        // After close a refusal is only counted: no window opens and no append
        // starts, so nothing the ledger holds outlives cleanup.
        this.recordedAfterClose += 1;
        return;
      }
      const now = this.clock();
      this.closeExpired(now);
      const closedCause = closedDenialCause(cause);
      let window = this.windows.get(input.tool);
      if (window === undefined) {
        if (this.windows.size < DENIAL_LEDGER_MAX_KEYS) {
          window = this.open(input.tool, input.tool, now);
          this.windows.set(input.tool, window);
          this.startFirstRow(window, closedCause, input);
        } else if (this.overflow === undefined) {
          window = this.open(OVERFLOW_KEY, input.tool, now);
          this.overflow = window;
          this.startFirstRow(window, closedCause, input);
        } else {
          window = this.overflow;
        }
      }
      window.attempted += 1;
      window.causes.set(closedCause, (window.causes.get(closedCause) ?? 0) + 1);
      if (input.linked_ref !== undefined && window.linked_refs.length < DENIAL_WINDOW_MAX_LINKED_REFS) {
        window.linked_refs.push(truncateStoredString(input.linked_ref, DENIAL_ROW_IDENTIFIER_MAX_BYTES));
      }
    } catch {
      // Ledger bookkeeping is operator evidence; it never reaches the refusal.
    }
  }

  /**
   * Close every open window (summaries only within the remaining budget), wait
   * at most LEDGER_CLOSE_DEADLINE_MS for pending appends, and report how many
   * did not settle. Does not cancel the audit log's appends.
   */
  async close(): Promise<void> {
    if (!this.closed) {
      this.closeExpired(Number.POSITIVE_INFINITY);
      this.closed = true;
    }
    if (this.pending.size > 0) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<void>((resolve) => {
        timer = setTimeout(resolve, LEDGER_CLOSE_DEADLINE_MS);
        timer.unref?.();
      });
      try {
        await Promise.race([Promise.allSettled([...this.pending]).then(() => undefined), deadline]);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    }
    if (this.pending.size > 0) {
      this.warn(`[Sanctuary] denial ledger closed with ${this.pending.size} audit appends unsettled`);
    }
  }

  snapshot(): DenialLedgerSnapshot {
    const live = [...this.windows.values(), ...(this.overflow ? [this.overflow] : [])];
    return {
      open_keyed_windows: this.windows.size,
      overflow_open: this.overflow !== undefined,
      pending_appends: this.pendingSlots,
      ledger_budget_exhausted: this.budgetExhausted,
      ledger_append_failures: this.appendFailures,
      recorded_after_close: this.recordedAfterClose,
      windows: live.map((window) => ({ key: window.generation.key, attempted: window.attempted, generation: window.generation })),
    };
  }

  private open(key: string, tool: string, now: number): DenialWindow {
    return {
      generation: {
        generation_id: this.nextGeneration++,
        key,
        denial_ref: `denial:${randomBytes(DENIAL_REF_BYTES).toString("hex")}`,
        first_row: "pending",
        summary: "none",
        slots_held: 0,
      },
      tool,
      window_started_at: now,
      attempted: 0,
      causes: new Map(),
      linked_refs: [],
    };
  }

  /**
   * Close every window whose minute has passed. The map is insertion-ordered by
   * window start, so the walk stops at the first unexpired window and each
   * window is closed once (amortized constant per record).
   */
  private closeExpired(now: number): void {
    for (const [key, window] of this.windows) {
      if (now - window.window_started_at < DENIAL_WINDOW_MS) break;
      this.closeWindow(window, now);
      this.windows.delete(key);
    }
    if (this.overflow !== undefined && now - this.overflow.window_started_at >= DENIAL_WINDOW_MS) {
      this.closeWindow(this.overflow, now);
      this.overflow = undefined;
    }
  }

  private closeWindow(window: DenialWindow, now: number): void {
    if (window.attempted <= 1) return;
    const generation = window.generation;
    if (!this.reserveSlot(generation)) {
      generation.summary = "skipped_budget";
      return;
    }
    generation.summary = "pending";
    const closedAt = Number.isFinite(now) ? now : this.clock();
    // Every summary row is padded to DENIAL_SUMMARY_ROW_DETAILS_BYTES, so its
    // stored size is the same whatever the window saw.
    const details = padTo({
      denial_ref: generation.denial_ref,
      tool: truncateStoredString(window.generation.key === OVERFLOW_KEY ? OVERFLOW_TOOL : window.tool, DENIAL_ROW_IDENTIFIER_MAX_BYTES),
      window_started_at: new Date(window.window_started_at).toISOString(),
      window_closed_at: new Date(closedAt).toISOString(),
      attempted: clampCounter(window.attempted),
      causes: Object.fromEntries([...window.causes].map(([cause, count]) => [cause, clampCounter(count)])),
      linked_refs: [...window.linked_refs],
      first_row: generation.first_row,
    }, DENIAL_SUMMARY_ROW_DETAILS_BYTES);
    this.detach(generation, () => this.auditLog.appendCritical({
      layer: "l2",
      operation: "denial_cause_summary",
      identity_id: "system",
      result: "failure",
      details,
    }), (outcome) => {
      generation.summary = outcome === "written" ? "written" : "failed";
      if (outcome !== "written") {
        this.appendFailures += 1;
        this.warn(`[Sanctuary] denial ledger summary append failed for ${generation.denial_ref}`);
      }
    });
  }

  private startFirstRow(window: DenialWindow, cause: DenialCause, input: DenialRecordInput): void {
    const generation = window.generation;
    if (this.closed || !this.reserveSlot(generation)) {
      generation.first_row = "skipped_budget";
      return;
    }
    const bounded = (value: string | undefined, maxBytes: number) =>
      value === undefined ? undefined : truncateStoredString(value, maxBytes);
    const linkedRef = bounded(input.linked_ref, DENIAL_ROW_IDENTIFIER_MAX_BYTES);
    const errorName = bounded(input.error_name, DENIAL_ROW_IDENTIFIER_MAX_BYTES);
    const message = bounded(input.error_message, DENIAL_FIRST_ROW_MESSAGE_MAX_BYTES);
    const facts = Object.fromEntries(DENIAL_FACT_KEYS
      .filter((key) => typeof input.facts?.[key] === "boolean")
      .map((key) => [key, input.facts![key]]));
    // Every first row is padded to DENIAL_CAUSE_ROW_DETAILS_BYTES, so its stored
    // size is the same whatever the cause, tool or message.
    const details = padTo({
      denial_ref: generation.denial_ref,
      tool: truncateStoredString(input.tool, DENIAL_ROW_IDENTIFIER_MAX_BYTES),
      cause,
      origin: truncateStoredString(input.origin, DENIAL_ROW_ORIGIN_MAX_BYTES),
      window_started_at: new Date(window.window_started_at).toISOString(),
      ...(linkedRef !== undefined ? { linked_ref: linkedRef } : {}),
      ...(errorName !== undefined ? { error_name: errorName } : {}),
      ...(message !== undefined ? { error_message: message } : {}),
      ...facts,
    }, DENIAL_CAUSE_ROW_DETAILS_BYTES);
    this.detach(generation, () => this.auditLog.appendCritical({
      layer: "l2",
      operation: "denial_cause",
      identity_id: "system",
      result: "failure",
      details,
    }), (outcome) => {
      generation.first_row = outcome;
      if (outcome !== "written") {
        // One line per window: a first row is attempted once and never retried inside its window.
        this.warn(`[Sanctuary] denial ledger first row ${outcome} for ${generation.denial_ref}`);
      }
    });
  }

  /** Reserve one global slot synchronously, before the append is enqueued. */
  private reserveSlot(generation: DenialGeneration): boolean {
    if (this.pendingSlots >= DENIAL_LEDGER_MAX_PENDING_APPENDS) {
      this.budgetExhausted += 1;
      return false;
    }
    this.pendingSlots += 1;
    generation.slots_held += 1;
    return true;
  }

  /**
   * Observe one detached append. Its slot is released only when the append
   * settles, never because its window expired or its entry was deleted.
   */
  private detach(
    generation: DenialGeneration,
    append: () => Promise<void>,
    settle: (outcome: "written" | "failed" | "unconfirmed") => void,
  ): void {
    let started: Promise<void>;
    try {
      started = append();
    } catch (error) {
      // A synchronous throw settles like a rejection; the slot is still released below.
      started = Promise.reject(error);
    }
    const observed = started.then(
      () => settle("written"),
      (error: unknown) => settle(refusedBeforeWrite(error) ? "failed" : "unconfirmed"),
    ).catch(() => {
      // A settle callback fault is still observed here.
    }).finally(() => {
      this.pendingSlots -= 1;
      generation.slots_held -= 1;
      this.pending.delete(observed);
    });
    this.pending.add(observed);
  }
}
