/**
 * The operator log: an append-only, hash-chained, authenticated-encrypted row
 * store under `_local_oplog`. Only operator surfaces read it; agent discovery
 * skips the namespace and every agent tool refuses it.
 *
 * Records: `row/<12-digit seq>`, `head`, `anchor` (the rotation-anchor shape
 * of the shared audit log), `prune` (a bounded prune intent) and
 * `prune-blocked` (the one blocked-base marker).
 */
import { createHash } from "node:crypto";
import { canonicalLocalJson } from "./canonical.js";
import {
  KIB,
  LOCAL_OPLOG_NAMESPACE,
  LocalStoreError,
  MIB,
  asPlainRecord,
  assertLocalStoreBackend,
  copyStoreKey,
  isLowerHex,
  isNonNegativeSafeInteger,
  isRequestId,
  readRecord,
  requireExactFields,
  sealRecord,
  toLocalStoreError,
  withLocalStoreLock,
  type LocalStoreBackend,
  type LocalStoreLockOptions,
  type RecordBounds,
} from "./store-record.js";

// A year or more of jobs for a few seats at the per-seat job rate.
export const OPLOG_MAX_ROWS = 50_000;
// OPLOG_MAX_ROWS rows averaging under 640 encrypted bytes (32,000,000), rounded up.
export const OPLOG_MAX_BYTES = 32 * MIB;
// The largest body (a refusal with cause and ids) is under 1 KiB; 4 KiB covers
// the canonical row envelope, base64 expansion and the encryption envelope.
export const OPLOG_ROW_MAX_BYTES = 4 * KIB;
// An append adds one row, so 64 deletions drain a backlog while bounding one append's work.
export const OPLOG_PRUNE_MAX_PER_APPEND = 64;

// Row keys carry the sequence as 12 zero-padded decimal digits after this prefix.
export const OPLOG_SEQ_DIGITS = 12;
const OPLOG_ROW_KEY_PREFIX = "row/";
const OPLOG_MAX_SEQ = 10 ** OPLOG_SEQ_DIGITS - 1;
// SHA-256 is 256 bits: 64 hex digits.
const HASH_HEX_LENGTH = 256 / 4;
export const OPLOG_GENESIS_PREV_HASH = "0".repeat(HASH_HEX_LENGTH);

const HEAD_KEY = "head";
const ANCHOR_KEY = "anchor";
const PRUNE_INTENT_KEY = "prune";
const PRUNE_BLOCKED_KEY = "prune-blocked";
const APPEND_LOCK = "append.lock";

// Every record in this namespace (rows and the four control records) is
// bounded by the row cap, measured on the sealed bytes as stored.
const RECORD_BOUNDS: RecordBounds = {
  plaintextMaxBytes: OPLOG_ROW_MAX_BYTES,
  sealedMaxBytes: OPLOG_ROW_MAX_BYTES,
};

/** The one closed list of row kinds; 1b adds job kinds here. */
export const OPLOG_KINDS = [
  "genesis",
  "worker_spawned",
  "worker_died",
  "result_pending",
  "result_committed",
  "result_indeterminate",
  "result_expired",
  "result_evicted",
  "result_deleted",
  "operator_export",
  "operator_render",
  "prune_blocked",
  "job_dropped",
] as const;
export type OplogKind = (typeof OPLOG_KINDS)[number];

export const WORKER_EXIT_CAUSES = ["exit", "signal", "fault"] as const;

/**
 * Why accepted work never reached a job: the worker was not ready or its
 * channel was backlogged, or the worker's queue or the seat's share was full.
 * Must match the drop producers in tool.ts and job-queue.ts.
 */
export const JOB_DROP_CAUSES = ["worker_unavailable", "queue_full", "seat_full"] as const;
export type JobDropCause = (typeof JOB_DROP_CAUSES)[number];

/** Closed body per kind: ids and counters only, never key material or record text. */
export interface OplogBodies {
  genesis: Record<string, never>;
  worker_spawned: { pid: number };
  worker_died: { pid: number; cause: (typeof WORKER_EXIT_CAUSES)[number] };
  result_pending: { request_id: string };
  result_committed: { request_id: string };
  result_indeterminate: { request_id: string };
  result_expired: { request_id: string };
  result_evicted: { request_id: string };
  result_deleted: { request_id: string };
  operator_export: { request_id: string };
  operator_render: { request_id: string };
  prune_blocked: { base_seq: number };
  job_dropped: { request_id: string; cause: JobDropCause };
}
export type OplogAppendKind = Exclude<OplogKind, "genesis">;

export type OplogRow = {
  [K in OplogKind]: { seq: number; prev_hash: string; at: number; kind: K; body: OplogBodies[K] };
}[OplogKind];

export interface OplogHead {
  seq: number;
  row_hash: string;
  base_seq: number;
  total_bytes: number;
}
export interface OplogAnchor {
  base_seq: number;
  base_prev_hash: string;
}
interface PruneIntent {
  from_seq: number;
  to_seq: number;
  base_prev_hash: string;
  removed_bytes: number;
}
interface PruneBlockedMarker {
  base_seq: number;
  event_seq: number;
}

/** Named append states, in order; the hook exists for fault injection. */
export type OplogAppendState = "state_LOCKED" | "state_ROW_WRITTEN" | "state_ROW_VERIFIED" | "state_HEAD_ADVANCED";

export type OplogVerification =
  | { ok: true; base_seq: number; head_seq: number }
  | { ok: false; seq: number; reason: "missing" | "unreadable" | "link" | "head" | "anchor" };

export interface OplogStatus {
  base_seq: number;
  head_seq: number;
  rows: number;
  total_bytes: number;
  over_cap: boolean;
  prune_blocked: boolean;
}

export interface OplogOptions extends LocalStoreLockOptions {
  now?: () => number;
  /** Smaller retention caps for tests; each must not exceed its production constant. */
  caps?: { maxRows?: number; maxBytes?: number; prunePerAppend?: number };
  onAppendState?: (state: OplogAppendState, seq: number) => void | Promise<void>;
}

export function oplogRowKey(seq: number): string {
  if (!isSeq(seq)) throw new LocalStoreError("capacity");
  return `${OPLOG_ROW_KEY_PREFIX}${String(seq).padStart(OPLOG_SEQ_DIGITS, "0")}`;
}

function isSeq(value: unknown): value is number {
  return isNonNegativeSafeInteger(value) && value <= OPLOG_MAX_SEQ;
}

function rowHash(row: OplogRow): string {
  return createHash("sha256").update(canonicalLocalJson(row)).digest("hex");
}

export function validateOplogBody<K extends OplogKind>(kind: K, input: unknown): OplogBodies[K] {
  const body = asPlainRecord(input);
  switch (kind) {
    case "genesis":
      requireExactFields(body, []);
      break;
    case "worker_spawned":
      requireExactFields(body, ["pid"]);
      if (!isNonNegativeSafeInteger(body.pid) || body.pid === 0) throw new LocalStoreError("invalid_record");
      break;
    case "worker_died":
      requireExactFields(body, ["pid", "cause"]);
      if (
        !isNonNegativeSafeInteger(body.pid) ||
        body.pid === 0 ||
        !WORKER_EXIT_CAUSES.some((cause) => cause === body.cause)
      ) {
        throw new LocalStoreError("invalid_record");
      }
      break;
    case "prune_blocked":
      requireExactFields(body, ["base_seq"]);
      if (!isSeq(body.base_seq)) throw new LocalStoreError("invalid_record");
      break;
    case "job_dropped":
      requireExactFields(body, ["request_id", "cause"]);
      if (!isRequestId(body.request_id) || !JOB_DROP_CAUSES.some((cause) => cause === body.cause)) {
        throw new LocalStoreError("invalid_record");
      }
      break;
    default:
      if (!OPLOG_KINDS.includes(kind)) throw new LocalStoreError("invalid_record");
      requireExactFields(body, ["request_id"]);
      if (!isRequestId(body.request_id)) throw new LocalStoreError("invalid_record");
  }
  // Closed schemas: no free-form body field exists that could carry record text or key bytes.
  return { ...body } as OplogBodies[K];
}

export function validateOplogRow(input: unknown): OplogRow {
  const row = asPlainRecord(input);
  requireExactFields(row, ["seq", "prev_hash", "at", "kind", "body"]);
  if (
    !isSeq(row.seq) ||
    !isLowerHex(row.prev_hash, HASH_HEX_LENGTH) ||
    !isNonNegativeSafeInteger(row.at) ||
    !OPLOG_KINDS.some((kind) => kind === row.kind)
  ) {
    throw new LocalStoreError("invalid_record");
  }
  const kind = row.kind as OplogKind;
  // Only sequence zero is genesis, and genesis links to the all-zero hash.
  if ((row.seq === 0) !== (kind === "genesis")) throw new LocalStoreError("invalid_record");
  if (kind === "genesis" && row.prev_hash !== OPLOG_GENESIS_PREV_HASH) throw new LocalStoreError("invalid_record");
  return { seq: row.seq, prev_hash: row.prev_hash, at: row.at, kind, body: validateOplogBody(kind, row.body) } as OplogRow;
}

function validateHead(input: unknown): OplogHead {
  const head = asPlainRecord(input);
  requireExactFields(head, ["seq", "row_hash", "base_seq", "total_bytes"]);
  if (
    !isSeq(head.seq) ||
    !isSeq(head.base_seq) ||
    head.base_seq > head.seq ||
    !isLowerHex(head.row_hash, HASH_HEX_LENGTH) ||
    !isNonNegativeSafeInteger(head.total_bytes)
  ) {
    throw new LocalStoreError("invalid_record");
  }
  return { seq: head.seq, row_hash: head.row_hash, base_seq: head.base_seq, total_bytes: head.total_bytes };
}

function validateAnchor(input: unknown): OplogAnchor {
  const anchor = asPlainRecord(input);
  requireExactFields(anchor, ["base_seq", "base_prev_hash"]);
  if (!isSeq(anchor.base_seq) || !isLowerHex(anchor.base_prev_hash, HASH_HEX_LENGTH)) {
    throw new LocalStoreError("invalid_record");
  }
  return { base_seq: anchor.base_seq, base_prev_hash: anchor.base_prev_hash };
}

function validateIntent(input: unknown): PruneIntent {
  const intent = asPlainRecord(input);
  requireExactFields(intent, ["from_seq", "to_seq", "base_prev_hash", "removed_bytes"]);
  if (
    !isSeq(intent.from_seq) ||
    !isSeq(intent.to_seq) ||
    intent.to_seq <= intent.from_seq ||
    intent.to_seq - intent.from_seq > OPLOG_PRUNE_MAX_PER_APPEND ||
    !isLowerHex(intent.base_prev_hash, HASH_HEX_LENGTH) ||
    !isNonNegativeSafeInteger(intent.removed_bytes)
  ) {
    throw new LocalStoreError("invalid_record");
  }
  return {
    from_seq: intent.from_seq,
    to_seq: intent.to_seq,
    base_prev_hash: intent.base_prev_hash,
    removed_bytes: intent.removed_bytes,
  };
}

function validateBlockedMarker(input: unknown): PruneBlockedMarker {
  const marker = asPlainRecord(input);
  requireExactFields(marker, ["base_seq", "event_seq"]);
  if (!isSeq(marker.base_seq) || !isSeq(marker.event_seq)) throw new LocalStoreError("invalid_record");
  return { base_seq: marker.base_seq, event_seq: marker.event_seq };
}

/** Operator log over a lock-capable strict backend; one instance per opened store. */
export class LocalOplog {
  private readonly key: Uint8Array;
  private readonly now: () => number;
  private readonly maxRows: number;
  private readonly maxBytes: number;
  private readonly prunePerAppend: number;
  private closed = false;

  constructor(
    private readonly storage: LocalStoreBackend,
    key: Uint8Array,
    private readonly options: OplogOptions = {},
  ) {
    assertLocalStoreBackend(storage);
    this.key = copyStoreKey(key);
    this.now = options.now ?? Date.now;
    this.maxRows = boundedCap(options.caps?.maxRows, OPLOG_MAX_ROWS);
    this.maxBytes = boundedCap(options.caps?.maxBytes, OPLOG_MAX_BYTES);
    this.prunePerAppend = boundedCap(options.caps?.prunePerAppend, OPLOG_PRUNE_MAX_PER_APPEND);
  }

  /** Zero the key; every later call refuses. */
  close(): void {
    this.closed = true;
    this.key.fill(0);
  }

  /** Create genesis, anchor and head when absent; otherwise check the head authenticates and names the last row, and the anchor authenticates. */
  async ensure(): Promise<"created" | "verified"> {
    return this.locked(async () => {
      const existing = await this.readControl(HEAD_KEY);
      if (existing !== null) {
        const head = validateHead(existing);
        const last = await this.readRow(head.seq);
        if (last === null || rowHash(last.row) !== head.row_hash) throw new LocalStoreError("invalid_record");
        // Every later append prunes from the anchor, so a head without an authenticating anchor refuses at boot.
        const anchor = await this.readControl(ANCHOR_KEY);
        if (anchor === null) throw new LocalStoreError("invalid_record");
        validateAnchor(anchor);
        return "verified";
      }
      // A store with rows or an anchor but no head is damaged, never re-initialized over.
      if ((await this.readControl(ANCHOR_KEY)) !== null) throw new LocalStoreError("invalid_record");
      // Only an interrupted first boot leaves a record without a head, and that record is genesis. Any
      // other row (a successor, or the suffix a prune left after removing genesis) or a prune record
      // means the head was lost, whatever row/0 holds. The listing is boot-only and bounded by the row cap.
      this.assertOpen();
      const allowed = oplogRowKey(0);
      let stored: Array<{ key: string }>;
      try {
        stored = await this.storage.list(LOCAL_OPLOG_NAMESPACE);
      } catch (error) {
        throw toLocalStoreError(error);
      }
      const damaged = stored.some(({ key }) => (key.startsWith(OPLOG_ROW_KEY_PREFIX) && key !== allowed) || key === PRUNE_INTENT_KEY || key === PRUNE_BLOCKED_KEY);
      if (damaged) throw new LocalStoreError("invalid_record");
      let genesis = await this.readRow(0);
      if (genesis === null) {
        const row = validateOplogRow({ seq: 0, prev_hash: OPLOG_GENESIS_PREV_HASH, at: this.clock(), kind: "genesis", body: {} });
        genesis = { row, bytes: await this.publishRow(row) };
      }
      await this.writeControl(ANCHOR_KEY, { base_seq: 0, base_prev_hash: OPLOG_GENESIS_PREV_HASH } satisfies OplogAnchor);
      await this.writeControl(HEAD_KEY, {
        seq: 0,
        row_hash: rowHash(genesis.row),
        base_seq: 0,
        total_bytes: genesis.bytes,
      } satisfies OplogHead);
      return "created";
    });
  }

  /** Append one row: state_LOCKED, state_ROW_WRITTEN, state_ROW_VERIFIED, state_HEAD_ADVANCED; then bounded pruning. */
  async append<K extends OplogAppendKind>(kind: K, body: OplogBodies[K]): Promise<OplogRow> {
    const checked = validateOplogBody(kind, body);
    return this.locked(async () => {
      const head = await this.requireHead();
      await this.options.onAppendState?.("state_LOCKED", head.seq);
      const recoveredDeletes = await this.finishPrune(head);
      await this.rollForward(head);
      await this.finishBlockedEvent(head);
      const row = await this.appendRow(head, kind, checked);
      await this.prune(head, this.prunePerAppend - recoveredDeletes);
      return row;
    });
  }

  /** Walk base to head: every row authenticates, links to its predecessor, and the head names the last one. */
  async verifyChain(): Promise<OplogVerification> {
    return this.locked(async () => {
      const head = await this.requireHead();
      const anchorValue = await this.readControl(ANCHOR_KEY);
      if (anchorValue === null) return { ok: false, seq: head.base_seq, reason: "anchor" };
      const anchor = validateAnchor(anchorValue);
      let base = head.base_seq;
      let expectedBytes = head.total_bytes;
      const intentValue = await this.readControl(PRUNE_INTENT_KEY);
      if (intentValue !== null) {
        const intent = validateIntent(intentValue);
        // state_PRUNE_INTENDED: the intent is durable but neither the anchor nor the head has moved, so
        // every row from the old base is still present. Otherwise (state_PRUNE_ANCHORED) the anchor names
        // to_seq and the rows before it are leaving.
        const intended = head.base_seq === intent.from_seq && anchor.base_seq === intent.from_seq;
        if (!intended) {
          if (head.base_seq === intent.from_seq) expectedBytes -= intent.removed_bytes;
          base = intent.to_seq;
        }
      }
      if (anchor.base_seq !== base) return { ok: false, seq: base, reason: "anchor" };
      let previous = anchor.base_prev_hash;
      let bytes = 0;
      for (let seq = base; seq <= head.seq; seq += 1) {
        let found: { row: OplogRow; bytes: number } | null;
        try {
          found = await this.readRow(seq);
        } catch {
          return { ok: false, seq, reason: "unreadable" };
        }
        if (found === null) return { ok: false, seq, reason: "missing" };
        if (found.row.prev_hash !== previous) return { ok: false, seq, reason: "link" };
        previous = rowHash(found.row);
        bytes += found.bytes;
      }
      if (previous !== head.row_hash || bytes !== expectedBytes) return { ok: false, seq: head.seq, reason: "head" };
      return { ok: true, base_seq: base, head_seq: head.seq };
    });
  }

  /** Read at most `limit` retained rows from `fromSeq`; one page is at most OPLOG_MAX_ROWS rows. */
  async readRows(fromSeq: number, limit: number): Promise<OplogRow[]> {
    if (!isSeq(fromSeq) || !Number.isSafeInteger(limit) || limit <= 0 || limit > OPLOG_MAX_ROWS) {
      throw new LocalStoreError("capacity");
    }
    return this.locked(async () => {
      const head = await this.requireHead();
      const rows: OplogRow[] = [];
      for (let seq = Math.max(fromSeq, head.base_seq); seq <= head.seq && rows.length < limit; seq += 1) {
        const found = await this.readRow(seq);
        if (found === null) throw new LocalStoreError("invalid_record");
        rows.push(found.row);
      }
      return rows;
    });
  }

  async status(): Promise<OplogStatus> {
    return this.locked(async () => {
      const head = await this.requireHead();
      const rows = head.seq - head.base_seq + 1;
      return {
        base_seq: head.base_seq,
        head_seq: head.seq,
        rows,
        total_bytes: head.total_bytes,
        over_cap: rows > this.maxRows || head.total_bytes > this.maxBytes,
        prune_blocked: (await this.readControl(PRUNE_BLOCKED_KEY)) !== null,
      };
    });
  }

  // ── Internals (all run under the append lock) ─────────────────────

  private locked<T>(operation: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new LocalStoreError("closed"));
    // Lock order: the results lock, then this append lock. Nothing in this
    // section takes the results lock, so the two cannot deadlock.
    return withLocalStoreLock(this.storage, LOCAL_OPLOG_NAMESPACE, APPEND_LOCK, operation, this.options);
  }

  private clock(): number {
    const now = this.now();
    if (!isNonNegativeSafeInteger(now)) throw new LocalStoreError("invalid_record");
    return now;
  }

  /**
   * A closed log's key is zeroed, so a call already in flight when close ran must not read or write:
   * a record sealed under the zeroed key would make the log unreadable at the next boot.
   */
  private assertOpen(): void {
    if (this.closed) throw new LocalStoreError("closed");
  }

  private async readControl(key: string): Promise<unknown | null> {
    this.assertOpen();
    const found = await readRecord(this.storage, LOCAL_OPLOG_NAMESPACE, key, this.key, RECORD_BOUNDS);
    return found === null ? null : found.value;
  }

  private async writeControl(key: string, value: unknown): Promise<void> {
    this.assertOpen();
    const sealed = sealRecord(value, this.key, key, RECORD_BOUNDS);
    try {
      await this.storage.writeStrict(LOCAL_OPLOG_NAMESPACE, key, sealed);
    } catch (error) {
      throw toLocalStoreError(error);
    }
  }

  private async deleteKey(key: string): Promise<void> {
    this.assertOpen();
    try {
      await this.storage.delete(LOCAL_OPLOG_NAMESPACE, key);
    } catch (error) {
      throw toLocalStoreError(error);
    }
  }

  private async requireHead(): Promise<OplogHead> {
    const value = await this.readControl(HEAD_KEY);
    // No head means no store: appends never create one implicitly.
    if (value === null) throw new LocalStoreError("not_found");
    return validateHead(value);
  }

  private async readRow(seq: number): Promise<{ row: OplogRow; bytes: number } | null> {
    this.assertOpen();
    const found = await readRecord(this.storage, LOCAL_OPLOG_NAMESPACE, oplogRowKey(seq), this.key, RECORD_BOUNDS);
    if (found === null) return null;
    const row = validateOplogRow(found.value);
    if (row.seq !== seq) throw new LocalStoreError("invalid_record");
    return { row, bytes: found.sealed.length };
  }

  /** Exclusive publish then byte-exact read-back; returns the sealed size. */
  private async publishRow(row: OplogRow): Promise<number> {
    const key = oplogRowKey(row.seq);
    this.assertOpen();
    const sealed = sealRecord(row, this.key, key, RECORD_BOUNDS);
    let created: boolean;
    try {
      created = await this.storage.writeIfAbsentStrict(LOCAL_OPLOG_NAMESPACE, key, sealed);
    } catch (error) {
      throw toLocalStoreError(error);
    }
    // An occupied slot means another writer got here first; never overwrite a row.
    if (!created) throw new LocalStoreError("conflict");
    await this.options.onAppendState?.("state_ROW_WRITTEN", row.seq);
    let stored: Uint8Array | null;
    try {
      stored = await this.storage.readBounded(LOCAL_OPLOG_NAMESPACE, key, RECORD_BOUNDS.sealedMaxBytes);
    } catch (error) {
      throw toLocalStoreError(error);
    }
    // The head advances only past a row whose stored bytes equal what was sealed.
    if (stored === null || !bytesEqual(stored, sealed)) throw new LocalStoreError("io");
    await this.options.onAppendState?.("state_ROW_VERIFIED", row.seq);
    return sealed.length;
  }

  private async appendRow<K extends OplogAppendKind>(head: OplogHead, kind: K, body: OplogBodies[K]): Promise<OplogRow> {
    if (head.seq >= OPLOG_MAX_SEQ) throw new LocalStoreError("capacity");
    const row = validateOplogRow({ seq: head.seq + 1, prev_hash: head.row_hash, at: this.clock(), kind, body });
    const bytes = await this.publishRow(row);
    head.seq = row.seq;
    head.row_hash = rowHash(row);
    head.total_bytes += bytes;
    await this.writeControl(HEAD_KEY, head);
    await this.options.onAppendState?.("state_HEAD_ADVANCED", row.seq);
    return row;
  }

  /** An append interrupted after its row write left a verified-linkable row one past the head. */
  private async rollForward(head: OplogHead): Promise<void> {
    if (head.seq >= OPLOG_MAX_SEQ) return;
    const orphan = await this.readRow(head.seq + 1);
    if (orphan === null) return;
    // Only a row that names the current head's hash may extend it; anything else is a fork.
    if (orphan.row.prev_hash !== head.row_hash) throw new LocalStoreError("invalid_record");
    head.seq = orphan.row.seq;
    head.row_hash = rowHash(orphan.row);
    head.total_bytes += orphan.bytes;
    await this.writeControl(HEAD_KEY, head);
  }

  /** Complete an interrupted prune: anchor, deletes, head, then drop the intent. */
  private async finishPrune(head: OplogHead): Promise<number> {
    const value = await this.readControl(PRUNE_INTENT_KEY);
    if (value === null) return 0;
    const intent = validateIntent(value);
    const advanced = head.base_seq === intent.to_seq;
    if ((!advanced && head.base_seq !== intent.from_seq) || intent.to_seq > head.seq) {
      throw new LocalStoreError("invalid_record");
    }
    // The anchor is durable before any row leaves, so a verifier always has a starting link.
    await this.writeControl(ANCHOR_KEY, { base_seq: intent.to_seq, base_prev_hash: intent.base_prev_hash } satisfies OplogAnchor);
    for (let seq = intent.from_seq; seq < intent.to_seq; seq += 1) await this.deleteKey(oplogRowKey(seq));
    if (!advanced) {
      head.base_seq = intent.to_seq;
      head.total_bytes -= intent.removed_bytes;
      await this.writeControl(HEAD_KEY, head);
    }
    await this.deleteKey(PRUNE_INTENT_KEY);
    return intent.to_seq - intent.from_seq;
  }

  /** Publish a reserved prune_blocked row that an interrupted append left unwritten. */
  private async finishBlockedEvent(head: OplogHead): Promise<void> {
    const value = await this.readControl(PRUNE_BLOCKED_KEY);
    if (value === null) return;
    const marker = validateBlockedMarker(value);
    if (marker.event_seq <= head.seq) return;
    if (marker.event_seq !== head.seq + 1) throw new LocalStoreError("invalid_record");
    await this.appendRow(head, "prune_blocked", { base_seq: marker.base_seq });
  }

  /**
   * Retention: oldest rows first, at most `budget` deletions, never the head
   * row. Slice 2 adds the disclosure-witness floor to the eligibility test in
   * this loop.
   */
  private async prune(head: OplogHead, budget: number): Promise<void> {
    const anchorValue = await this.readControl(ANCHOR_KEY);
    if (anchorValue === null) throw new LocalStoreError("invalid_record");
    const anchor = validateAnchor(anchorValue);
    if (anchor.base_seq !== head.base_seq) throw new LocalStoreError("invalid_record");
    let next = head.base_seq;
    let previous = anchor.base_prev_hash;
    let removed = 0;
    let blockedAt: number | undefined;
    while (
      next - head.base_seq < budget &&
      next < head.seq &&
      (head.seq - next + 1 > this.maxRows || head.total_bytes - removed > this.maxBytes)
    ) {
      let oldest: { row: OplogRow; bytes: number } | null;
      try {
        oldest = await this.readRow(next);
      } catch {
        oldest = null;
      }
      // A row that does not open or link stops the prune before its delete, so
      // retention can never erase the evidence that the chain was damaged.
      if (oldest === null || oldest.row.prev_hash !== previous) {
        blockedAt = next;
        break;
      }
      removed += oldest.bytes;
      previous = rowHash(oldest.row);
      next += 1;
    }
    if (next > head.base_seq) {
      await this.writeControl(PRUNE_INTENT_KEY, {
        from_seq: head.base_seq,
        to_seq: next,
        base_prev_hash: previous,
        removed_bytes: removed,
      } satisfies PruneIntent);
      await this.finishPrune(head);
    }
    const markerValue = await this.readControl(PRUNE_BLOCKED_KEY);
    const marker = markerValue === null ? null : validateBlockedMarker(markerValue);
    if (blockedAt !== undefined) {
      if (marker?.base_seq === blockedAt) return;
      // Reserve the event before publishing it, so one blocked base yields one row even across a crash.
      await this.writeControl(PRUNE_BLOCKED_KEY, { base_seq: blockedAt, event_seq: head.seq + 1 } satisfies PruneBlockedMarker);
      await this.appendRow(head, "prune_blocked", { base_seq: blockedAt });
    } else if (marker !== null && marker.base_seq < head.base_seq) {
      await this.deleteKey(PRUNE_BLOCKED_KEY);
    }
  }
}

function boundedCap(value: number | undefined, production: number): number {
  if (value === undefined) return production;
  if (!Number.isSafeInteger(value) || value <= 0 || value > production) throw new LocalStoreError("capacity");
  return value;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) if (left[index] !== right[index]) return false;
  return true;
}
