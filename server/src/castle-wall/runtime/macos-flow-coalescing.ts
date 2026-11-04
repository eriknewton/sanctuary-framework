/** Fixed-size informational windows for admitted macOS live-flow observations. */
import { parseIsoInstantWithOffset } from "../../core/time.js";

// 256 bounds destination diversity in one consumer, including owed records.
export const FLOW_COALESCE_MAX_KEYS = 256;
// Two slots own one immutable reservation and one mutable accumulator.
export const FLOW_COALESCE_MAX_RECORDS_PER_KEY = 2;
// 512 bytes covers the encoded subject/destination/verdict tuple and separators.
export const FLOW_COALESCE_MAX_KEY_BYTES = 512;
// 1024 bytes bounds a complete encoded record, including maximum-width counters.
export const FLOW_COALESCE_MAX_RECORD_BYTES = 1024;
// Arrivals address one key; only flush and snapshot operations traverse the table.
export const FLOW_COALESCE_MAX_KEY_VISITS_PER_FRAME = 1;
export const FLOW_COALESCE_MAX_SUMMARIES_PER_FLUSH = FLOW_COALESCE_MAX_KEYS;
// Must match CASTLE_WALL_AUDIT_OPERATIONS in cli/castle-wall.ts.
export const FLOW_COALESCE_SUMMARY_OPERATION = "castle_wall_flow_decisions_coalesced";

/** Metadata already admitted by its consumer; timestamps are local receipt observations. */
export interface FlowCoalescingMetadata {
  subject: string;
  destination: { ip: string; port: number; protocol: "tcp" | "udp"; host: string | null };
  decision: "allow" | "drop";
  seq?: number;
}

/**
 * Informational summary; host represents the first counted arrival and is excluded from the key.
 * Coalescing remembers admission only for the lifetime of this consumer. A persisted informational summary does not restore its coalesced sequences. After restart, a previously coalesced sequence above the restored primary position can be accepted again while fresh; subsequent delivery is subject to the ordinary duplicate and regression rules. Repeated restarts can repeat this effect until freshness expires. Unpersisted summary evidence can cover open, pending, and in-flight windows, including merged windows of unrestricted age during a continuing outage. Successfully persisted primary records remain durable; failed or unsettled heads have no durability guarantee.
 */
export interface FlowCoalescedSummary extends FlowCoalescingMetadata {
  consumer_instance_id: string;
  summary_seq: number;
  coalesced_count: number;
  first_recorded_at: string;
  last_recorded_at: string;
  window_ms: number;
  head_persisted: boolean;
  windows_merged: number;
  seq_min?: number;
  seq_max?: number;
}
interface Window {
  open: boolean;
  headPersisted: boolean;
  segmentCounted: boolean;
  mutable: FlowCoalescedSummary | null;
  reserved: Readonly<FlowCoalescedSummary> | null;
  appended: boolean;
}
/** Admission classification with an invocation-owned head completion callback. */
export type FlowClassification = { kind: "coalesced" } | { kind: "head"; settled(persisted: boolean): void };
const bytes = (value: unknown) => Buffer.byteLength(JSON.stringify(value), "utf8");
const ceiling = Number.MAX_SAFE_INTEGER;

/** Bound metadata before retaining any encoded tuple or record. Missing fields use primary persistence. */
export function flowCoalescingMetadata(subject: unknown, fields: Record<string, unknown>): FlowCoalescingMetadata | null {
  const { dest_ip: ip, dest_port: port, dest_protocol: protocol, decision, dest_host: host, seq } = fields;
  if (typeof subject !== "string" || typeof ip !== "string" ||
      typeof port !== "number" || !Number.isSafeInteger(port) || port < 0 || port > 65535 || // TCP/UDP ports have sixteen bits.
      (protocol !== "tcp" && protocol !== "udp") || (decision !== "allow" && decision !== "drop") ||
      (host !== undefined && host !== null && typeof host !== "string")) return null;
  // UTF-16 length is a cheap lower bound; the exact UTF-8/JSON budget is checked before retention.
  if (subject.length > FLOW_COALESCE_MAX_KEY_BYTES || ip.length > FLOW_COALESCE_MAX_KEY_BYTES ||
      (typeof host === "string" && host.length > FLOW_COALESCE_MAX_RECORD_BYTES)) return null;
  return { subject, destination: { ip, port, protocol, host: typeof host === "string" ? host : null }, decision,
    ...(typeof seq === "number" && Number.isSafeInteger(seq) ? { seq } : {}) };
}

/** Own admitted counts in two slots per key; persistence is supplied by the flow consumer. */
export class FlowCoalescer {
  private readonly windows = new Map<string, Window>();
  private sequence = 0;
  private confirmed = 0;
  private counted = 0;
  private written = 0;
  private failures = 0;
  private overflow = 0;
  private visits = 0;
  private lowerBound = false;
  constructor(readonly instanceId: string, private readonly now: () => number) {}

  /** Classify only after admission; forced primary delivery never consumes an existing window. */
  classify(metadata: FlowCoalescingMetadata | null, forcePrimary = false): FlowClassification {
    const passthrough: FlowClassification = { kind: "head", settled() {} };
    if (!metadata || forcePrimary || this.counted === ceiling || this.sequence === ceiling) return passthrough;
    const { subject, destination, decision, seq } = metadata;
    // Public helper callers receive the same pre-encoding bound as the consumer adapter.
    if (subject.length > FLOW_COALESCE_MAX_KEY_BYTES || destination.ip.length > FLOW_COALESCE_MAX_KEY_BYTES ||
        (destination.host?.length ?? 0) > FLOW_COALESCE_MAX_RECORD_BYTES) return passthrough;
    const key = JSON.stringify([subject, destination.ip, destination.port, destination.protocol, decision]);
    if (Buffer.byteLength(key, "utf8") > FLOW_COALESCE_MAX_KEY_BYTES) return passthrough;
    const time = new Date(this.now()).toISOString();
    const record: FlowCoalescedSummary = { subject, destination: { ...destination }, decision,
      consumer_instance_id: this.instanceId, summary_seq: 0, coalesced_count: 1,
      first_recorded_at: time, last_recorded_at: time, window_ms: 0, head_persisted: false, windows_merged: 1,
      ...(seq !== undefined ? { seq_min: seq, seq_max: seq } : {}) };
    // Reserve room for every numeric field at its widest supported value before retaining metadata.
    if (bytes({ ...record, summary_seq: ceiling, coalesced_count: ceiling, window_ms: ceiling,
      windows_merged: ceiling, ...(seq !== undefined ? { seq_min: -ceiling, seq_max: -ceiling } : {}) }) > FLOW_COALESCE_MAX_RECORD_BYTES) return passthrough;
    this.visits = this.increment(this.visits);
    let window = this.windows.get(key);
    if (!window) {
      if (this.windows.size >= FLOW_COALESCE_MAX_KEYS) { this.overflow = this.increment(this.overflow); return passthrough; }
      window = { open: false, headPersisted: false, segmentCounted: false, mutable: null, reserved: null, appended: false };
      this.windows.set(key, window);
    }
    if (!window.open) {
      window.open = true; window.headPersisted = false; window.segmentCounted = false;
      const owned = window;
      return { kind: "head", settled: (persisted) => {
        owned.headPersisted = persisted;
        // FIFO admission leaves a failed head with no counted arrivals in its window; older evidence remains owned.
        if (!persisted) {
          owned.open = false;
          if (!owned.mutable && !owned.reserved) this.windows.delete(key);
        }
      } };
    }
    const old = window.mutable;
    if (old && (old.coalesced_count === ceiling || (!window.segmentCounted && old.windows_merged === ceiling))) return passthrough;
    // A long-lived pending interval must remain an exact safe integer when windows merge.
    // Shared strict parsing keeps receipt-window arithmetic independent of the host time zone.
    const first = old ? parseIsoInstantWithOffset(old.first_recorded_at) : 0;
    const last = parseIsoInstantWithOffset(time);
    if (first === undefined || last === undefined) return passthrough;
    const interval = old ? Math.max(0, last - first) : 0;
    if (!Number.isSafeInteger(interval)) return passthrough;
    if (old) {
      old.coalesced_count++;
      old.last_recorded_at = time;
      old.window_ms = interval;
      old.head_persisted &&= window.headPersisted;
      if (!window.segmentCounted) old.windows_merged++;
      if (seq !== undefined) { old.seq_min = Math.min(old.seq_min ?? seq, seq); old.seq_max = Math.max(old.seq_max ?? seq, seq); }
    } else {
      record.head_persisted = window.headPersisted;
      window.mutable = record;
    }
    window.segmentCounted = true;
    this.counted++;
    return { kind: "coalesced" };
  }

  /** Close every logical window, retaining all owed counts and evicting empty windows. */
  closeWindows(): void {
    for (const [key, window] of this.windows) {
      window.open = false;
      if (!window.mutable && !window.reserved) this.windows.delete(key);
    }
  }

  /** Reserve each key once per flush; retry identifiers and payloads remain immutable. */
  *reservations(): Generator<{ record: Readonly<FlowCoalescedSummary>; appended: boolean; markAppended(): void; confirm(): void }> {
    for (const key of [...this.windows.keys()]) {
      const window = this.windows.get(key);
      if (!window) continue;
      if (!window.reserved && window.mutable && this.sequence < ceiling) {
        window.mutable.summary_seq = ++this.sequence;
        window.reserved = Object.freeze({ ...window.mutable, destination: Object.freeze({ ...window.mutable.destination }) });
        window.mutable = null;
        window.appended = false;
      }
      if (!window.reserved) continue;
      const reservation = window.reserved;
      yield { record: reservation, appended: window.appended,
        markAppended() { window.appended = true; },
        confirm: () => {
          if (window.reserved !== reservation) return;
          this.confirmed += reservation.coalesced_count;
          this.written = this.increment(this.written);
          window.reserved = null; window.appended = false;
          if (!window.open && !window.mutable) this.windows.delete(key);
        } };
    }
  }
  /** Record failed write attempts without converting represented observations to loss. */
  noteWriteFailure(): void { this.failures = this.increment(this.failures); }
  private increment(value: number): number { if (value === ceiling) { this.lowerBound = true; return value; } return value + 1; }
  /** Synchronous accounting includes mutable and reserved counts exactly once. */
  snapshot() {
    let pending = 0, pendingKeys = 0, retainedBytes = 0, records = 0, maxRecordsPerKey = 0;
    for (const [key, window] of this.windows) {
      const count = (window.mutable?.coalesced_count ?? 0) + (window.reserved?.coalesced_count ?? 0);
      pending += count; if (count > 0) pendingKeys++;
      const perKey = Number(window.mutable !== null) + Number(window.reserved !== null);
      records += perKey; maxRecordsPerKey = Math.max(maxRecordsPerKey, perKey);
      retainedBytes += Buffer.byteLength(key, "utf8") + (window.mutable ? bytes(window.mutable) : 0) + (window.reserved ? bytes(window.reserved) : 0);
    }
    return { keys: this.windows.size, pending_keys: pendingKeys, records, max_records_per_key: maxRecordsPerKey,
      retained_bytes: retainedBytes, key_visits: this.visits, keys_overflowed: this.overflow,
      coalesced: this.counted, coalesced_total: this.counted, coalesced_evidence_pending: pending, coalesced_evidence_confirmed: this.confirmed,
      coalescedSummariesWritten: this.written, summary_write_failures: this.failures, counters_lower_bound: this.lowerBound };
  }
}

interface AdmissionWaiter { run(): Promise<void>; resolve(): void; reject(error: unknown): void; shutdown(): void }
/** FIFO admission whose waiting closures remain charged at the listener until settlement. */
export class FlowAdmission {
  private readonly waiting = new Set<AdmissionWaiter>();
  private active: Promise<void> | null = null;
  private closed = false;
  /** Own the complete admission and persistence outcome; no payload is copied into this gate. */
  enter(run: () => Promise<void>, shutdown: () => void): Promise<void> {
    if (this.closed) { shutdown(); return Promise.resolve(); }
    return new Promise<void>((resolve, reject) => {
      const waiter = { run, shutdown, resolve, reject };
      if (this.active) this.waiting.add(waiter); else this.start(waiter);
    });
  }
  private start(waiter: AdmissionWaiter): void {
    const active = Promise.resolve().then(waiter.run);
    this.active = active;
    void active.then(waiter.resolve, waiter.reject).finally(() => {
      this.active = null;
      const next = this.waiting.values().next().value;
      if (next) { this.waiting.delete(next); this.start(next); }
    });
  }
  /** Close queued admission synchronously; admitted work keeps its ownership through settlement. */
  close(): void {
    this.closed = true;
    for (const waiter of this.waiting) { waiter.shutdown(); waiter.resolve(); }
    this.waiting.clear();
  }
  /** Stop may await the active owner under its own deadline. */
  async drain(): Promise<void> { await this.active?.catch(() => undefined); }
  /** Diagnostic counts never release an admission or listener charge. */
  snapshot() { return { closed: this.closed, unadmitted: this.waiting.size, active: Number(this.active !== null) }; }
}
