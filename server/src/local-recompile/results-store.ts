/**
 * The results store: bounded, authenticated-encrypted result objects under
 * `_local_results`, enumerated only through one bounded index record so no
 * operation lists the namespace. Each mutation logs its operator-log row
 * inside the results lock before its effect.
 *
 * Records: `obj/<request_id>` and `index`.
 *
 * Crash consistency, under a crash at any single write:
 * - Reachability: every stored object has an index entry. A new entry is
 *   published before its object, an object is deleted before its entry, and an
 *   object being replaced keeps its entry in every intermediate index.
 * - Size: an entry's byte count is never below its object's stored size. A
 *   replacement that grows the object raises the entry's count first.
 * - State: the object decides. Housekeeping rewrites an entry that a crash
 *   left behind its object, and drops an entry whose object is gone.
 */
import {
  DAY_MS,
  HOUR_MS,
  KIB,
  LOCAL_RESULTS_NAMESPACE,
  LocalStoreError,
  MIB,
  MINUTE_MS,
  SEAT_ID_HEX_LENGTH,
  asPlainRecord,
  assertLocalStoreBackend,
  canonicalBytes,
  copyStoreKey,
  isLowerHex,
  isNonNegativeSafeInteger,
  isRequestId,
  readRecord,
  requireExactFields,
  sealRecord,
  sealedRecordMaxBytes,
  toLocalStoreError,
  withLocalStoreLock,
  type LocalStoreBackend,
  type LocalStoreLockOptions,
  type RecordBounds,
} from "./store-record.js";
import type { LocalOplog, OplogAppendKind } from "./oplog.js";

// Per fortress, pending and indeterminate objects included.
export const RESULTS_MAX_OBJECTS = 200;
// An 8 KiB combined summary plus eight 2 KiB chunk summaries (8 + 16 = 24 KiB)
// plus room for the job's text frames.
export const RESULT_BODY_MAX_BYTES = 32 * KIB;
// RESULT_BODY_MAX_BYTES plus 4 KiB for the banner, instruction and citations.
export const RESULT_OBJECT_MAX_BYTES = RESULT_BODY_MAX_BYTES + 4 * KIB;
// RESULTS_MAX_OBJECTS x RESULT_OBJECT_MAX_BYTES is about 7 MiB, under 8 MiB.
export const RESULTS_MAX_TOTAL_BYTES = 8 * MIB;
// Design default retention for a committed result.
export const RESULT_TTL_MS = 30 * DAY_MS;
// After the job deadline a still-pending object is marked indeterminate.
export const PENDING_GRACE_MS = 10 * MINUTE_MS;
// An indeterminate object is kept one day after it became indeterminate.
export const INDETERMINATE_TTL_MS = 24 * HOUR_MS;
// One-minute granularity is a tenth of the PENDING_GRACE_MS window.
export const HOUSEKEEPING_INTERVAL_MS = MINUTE_MS;

/** Result kinds, one closed list; 1b's job fills it in. */
export const LOCAL_RESULT_KINDS = ["summarize"] as const;
export type LocalResultKind = (typeof LOCAL_RESULT_KINDS)[number];
export const LOCAL_RESULT_STATES = ["pending", "committed", "indeterminate"] as const;
export type LocalResultState = (typeof LOCAL_RESULT_STATES)[number];

/** A result body: named text fields, each a string or a list of strings. */
export type LocalResultBody = Record<string, string | string[]>;

export interface LocalResultObject {
  request_id: string;
  seat: string;
  kind: LocalResultKind;
  state: LocalResultState;
  created_at: number;
  deadline: number;
  /** When the next sweep transition applies: indeterminate for pending, deletion otherwise. */
  expires_at: number;
  state_changed_at: number;
  body: LocalResultBody | null;
}

interface IndexEntry {
  request_id: string;
  state: LocalResultState;
  bytes: number;
  created_at: number;
  state_changed_at: number;
  expires_at: number;
}

const INDEX_KEY = "index";
const RESULTS_LOCK = "results.lock";
// Field names (about 70 bytes), a 32-digit id, the longest state (13), a byte
// count and three millisecond timestamps (13 digits each) and JSON punctuation
// come to under 200 bytes; 256 per entry.
const INDEX_ENTRY_MAX_BYTES = 256;
const OBJECT_BOUNDS: RecordBounds = {
  plaintextMaxBytes: RESULT_OBJECT_MAX_BYTES,
  sealedMaxBytes: sealedRecordMaxBytes(RESULT_OBJECT_MAX_BYTES),
};
const INDEX_PLAINTEXT_MAX_BYTES = RESULTS_MAX_OBJECTS * INDEX_ENTRY_MAX_BYTES;
const INDEX_BOUNDS: RecordBounds = {
  plaintextMaxBytes: INDEX_PLAINTEXT_MAX_BYTES,
  sealedMaxBytes: sealedRecordMaxBytes(INDEX_PLAINTEXT_MAX_BYTES),
};

export interface PutPendingInput {
  request_id: string;
  seat: string;
  kind: LocalResultKind;
  deadline: number;
}

export interface ResultsStoreOptions extends LocalStoreLockOptions {
  now?: () => number;
  /** Smaller caps for tests; each must not exceed its production constant. */
  caps?: { maxObjects?: number; maxTotalBytes?: number };
}

export interface SweepSummary {
  expired: number;
  indeterminate: number;
  repaired: number;
}

export function objectKey(requestId: string): string {
  if (!isRequestId(requestId)) throw new LocalStoreError("invalid_record");
  return `obj/${requestId}`;
}

/** Results store; `oplog` must be opened over the same storage. */
export class LocalResultsStore {
  private readonly key: Uint8Array;
  private readonly now: () => number;
  private readonly maxObjects: number;
  private readonly maxTotalBytes: number;
  private closed = false;

  constructor(
    private readonly storage: LocalStoreBackend,
    key: Uint8Array,
    private readonly oplog: LocalOplog,
    private readonly options: ResultsStoreOptions = {},
  ) {
    assertLocalStoreBackend(storage);
    this.key = copyStoreKey(key);
    this.now = options.now ?? Date.now;
    this.maxObjects = boundedCap(options.caps?.maxObjects, RESULTS_MAX_OBJECTS);
    this.maxTotalBytes = boundedCap(options.caps?.maxTotalBytes, RESULTS_MAX_TOTAL_BYTES);
  }

  close(): void {
    this.closed = true;
    this.key.fill(0);
  }

  /** Create an empty index when absent; otherwise check it authenticates and parses. */
  async ensure(): Promise<"created" | "verified"> {
    return this.locked(async () => {
      if ((await this.readIndexOrNull()) !== null) return "verified";
      await this.writeIndex([]);
      return "created";
    });
  }

  /** Reserve a pending object, evicting oldest uncommitted then oldest committed objects to make room. */
  async putPending(input: PutPendingInput): Promise<LocalResultObject> {
    const now = this.clock();
    const object = validateObject({
      request_id: input.request_id,
      seat: input.seat,
      kind: input.kind,
      state: "pending",
      created_at: now,
      deadline: input.deadline,
      expires_at: input.deadline + PENDING_GRACE_MS,
      state_changed_at: now,
      body: null,
    });
    const bytes = objectBytes(object);
    return this.locked(async () => {
      const entries = await this.readIndex();
      if (entries.some((entry) => entry.request_id === object.request_id)) throw new LocalStoreError("exists");
      const kept = await this.evictFor(entries, bytes, 1);
      await this.log("result_pending", object.request_id);
      // The index entry is published before the object, so every stored object is reachable from the index.
      kept.push(indexEntry(object, bytes));
      await this.writeIndex(kept);
      await this.writeObject(object, true);
      return object;
    });
  }

  /** Commit a pending object with its body; an indeterminate, committed or overdue object refuses. */
  async markCommitted(requestId: string, body: LocalResultBody): Promise<LocalResultObject> {
    const checkedBody = validateBody(body);
    return this.locked(async () => {
      const entries = await this.readIndex();
      const current = await this.requireObject(entries, requestId);
      // A completion that arrives after the object left pending is discarded, never resurrected.
      if (current.state !== "pending") throw new LocalStoreError("conflict");
      const now = this.clock();
      // Past its deadline plus grace a pending object is indeterminate by rule, whether or not a sweep has run yet.
      if (now >= current.expires_at) throw new LocalStoreError("conflict");
      const next = validateObject({
        ...current,
        state: "committed",
        state_changed_at: now,
        expires_at: now + RESULT_TTL_MS,
        body: checkedBody,
      });
      const bytes = objectBytes(next);
      // The committing entry stays in every index evictFor publishes, so its object is never unreachable.
      const kept = await this.evictFor(entries, bytes, 0, requestId);
      await this.log("result_committed", requestId);
      await this.replaceObject(kept, next, bytes);
      return next;
    });
  }

  async markIndeterminate(requestId: string): Promise<LocalResultObject> {
    return this.locked(async () => {
      const entries = await this.readIndex();
      const current = await this.requireObject(entries, requestId);
      if (current.state !== "pending") throw new LocalStoreError("conflict");
      const now = this.clock();
      await this.toIndeterminateEntries(entries, current, now);
      return indeterminateOf(current, now);
    });
  }

  /** Delete one object; the operator-log row is written before the delete. */
  async delete(requestId: string): Promise<boolean> {
    return this.locked(async () => {
      const entries = await this.readIndex();
      if (!entries.some((entry) => entry.request_id === requestId)) return false;
      await this.log("result_deleted", requestId);
      await this.deleteObject(requestId);
      await this.writeIndex(entries.filter((entry) => entry.request_id !== requestId));
      return true;
    });
  }

  /** One object; uncommitted objects are visible only when asked for. */
  async get(requestId: string, options: { includeUncommitted?: boolean } = {}): Promise<LocalResultObject | null> {
    if (!isRequestId(requestId)) throw new LocalStoreError("invalid_record");
    return this.locked(async () => {
      const entries = await this.readIndex();
      if (!entries.some((entry) => entry.request_id === requestId)) return null;
      const object = await this.readObject(requestId);
      if (object === null) return null;
      return visible(object, options.includeUncommitted === true) ? object : null;
    });
  }

  /** Every visible object, in index order; at most RESULTS_MAX_OBJECTS reads. */
  async list(options: { includeUncommitted?: boolean } = {}): Promise<LocalResultObject[]> {
    return this.locked(async () => {
      const objects: LocalResultObject[] = [];
      for (const entry of await this.readIndex()) {
        if (!visible(entry, options.includeUncommitted === true)) continue;
        const object = await this.readObject(entry.request_id);
        if (object !== null && visible(object, options.includeUncommitted === true)) objects.push(object);
      }
      return objects;
    });
  }

  /**
   * Housekeeping, bounded by the index (at most RESULTS_MAX_OBJECTS entries):
   * committed past expiry and indeterminate past their TTL are deleted, pending
   * past deadline plus grace become indeterminate. The object, not the index
   * copy, decides, and an index entry whose object is gone is dropped.
   */
  async sweep(now: number = this.clock()): Promise<SweepSummary> {
    if (!isNonNegativeSafeInteger(now)) throw new LocalStoreError("invalid_record");
    return this.locked(async () => {
      const summary: SweepSummary = { expired: 0, indeterminate: 0, repaired: 0 };
      let entries = await this.readIndex();
      for (const entry of [...entries]) {
        const object = await this.readObject(entry.request_id);
        if (object === null) {
          entries = entries.filter((candidate) => candidate.request_id !== entry.request_id);
          await this.writeIndex(entries);
          summary.repaired += 1;
          continue;
        }
        // An entry a crash left behind its object (a raised size, or the old state) is rewritten from the object.
        const actual = indexEntry(object, objectBytes(object));
        if (!sameEntry(entry, actual)) {
          entries = entries.map((candidate) => (candidate.request_id === actual.request_id ? actual : candidate));
          await this.writeIndex(entries);
          summary.repaired += 1;
        }
        if (now < object.expires_at) continue;
        if (object.state === "pending") {
          entries = await this.toIndeterminateEntries(entries, object, now);
          summary.indeterminate += 1;
        } else {
          await this.log("result_expired", object.request_id);
          await this.deleteObject(object.request_id);
          entries = entries.filter((candidate) => candidate.request_id !== object.request_id);
          await this.writeIndex(entries);
          summary.expired += 1;
        }
      }
      return summary;
    });
  }

  // ── Internals (all run under the results lock) ─────────────────────

  private locked<T>(operation: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new LocalStoreError("closed"));
    // Lock order: this results lock first, then the operator-log append lock
    // inside it (LocalOplog.append). The log never takes this lock.
    return withLocalStoreLock(this.storage, LOCAL_RESULTS_NAMESPACE, RESULTS_LOCK, operation, this.options);
  }

  private clock(): number {
    const now = this.now();
    if (!isNonNegativeSafeInteger(now)) throw new LocalStoreError("invalid_record");
    return now;
  }

  private async log(kind: OplogAppendKind & `result_${string}`, requestId: string): Promise<void> {
    await this.oplog.append(kind, { request_id: requestId });
  }

  private async toIndeterminateEntries(entries: IndexEntry[], object: LocalResultObject, now: number): Promise<IndexEntry[]> {
    const next = indeterminateOf(object, now);
    await this.log("result_indeterminate", object.request_id);
    return this.replaceObject(entries, next, objectBytes(next));
  }

  /**
   * Replace one stored object in place: raise its entry's size first when the
   * object grows, then write the object, then publish the exact entry. A crash
   * at any of the three writes leaves an index that still reaches the object
   * and never undercounts it; sweep reconciles the entry from the object.
   */
  private async replaceObject(entries: IndexEntry[], next: LocalResultObject, bytes: number): Promise<IndexEntry[]> {
    const id = next.request_id;
    const current = entries.find((entry) => entry.request_id === id);
    if (current === undefined) throw new LocalStoreError("not_found");
    if (bytes > current.bytes) {
      await this.writeIndex(entries.map((entry) => (entry.request_id === id ? { ...entry, bytes } : entry)));
    }
    await this.writeObject(next, false);
    const updated = entries.map((entry) => (entry.request_id === id ? indexEntry(next, bytes) : entry));
    await this.writeIndex(updated);
    return updated;
  }

  /**
   * Make room for one more object of `bytes` (adding `slots` entries). When
   * `replacing` names an entry, that object is being rewritten at `bytes`: it
   * keeps its slot, is never a victim, and its old size does not count.
   * Eviction order: pending and indeterminate oldest first, then committed
   * oldest first; each eviction is logged before its delete.
   */
  private async evictFor(entries: IndexEntry[], bytes: number, slots: number, replacing?: string): Promise<IndexEntry[]> {
    if (bytes > this.maxTotalBytes) throw new LocalStoreError("capacity");
    const order = entries.filter((entry) => entry.request_id !== replacing).sort((left, right) => {
      const rank = Number(left.state === "committed") - Number(right.state === "committed");
      return rank !== 0 ? rank : left.created_at - right.created_at;
    });
    const kept = [...entries];
    let total = kept.reduce((sum, entry) => sum + (entry.request_id === replacing ? 0 : entry.bytes), 0);
    for (const victim of order) {
      if (kept.length + slots <= this.maxObjects && total + bytes <= this.maxTotalBytes) break;
      await this.log("result_evicted", victim.request_id);
      await this.deleteObject(victim.request_id);
      kept.splice(kept.findIndex((entry) => entry.request_id === victim.request_id), 1);
      total -= victim.bytes;
      // The shrunken index is published at once, so a crash cannot strand a deleted entry's bytes.
      await this.writeIndex(kept);
    }
    if (kept.length + slots > this.maxObjects || total + bytes > this.maxTotalBytes) {
      throw new LocalStoreError("capacity");
    }
    return kept;
  }

  private async requireObject(entries: IndexEntry[], requestId: string): Promise<LocalResultObject> {
    if (!entries.some((entry) => entry.request_id === requestId)) throw new LocalStoreError("not_found");
    const object = await this.readObject(requestId);
    if (object === null) throw new LocalStoreError("not_found");
    return object;
  }

  /**
   * A closed store's key is zeroed, so a call already in flight when close ran must not read or write:
   * a record sealed under the zeroed key would make the store unreadable at the next boot.
   */
  private assertOpen(): void {
    if (this.closed) throw new LocalStoreError("closed");
  }

  private async readIndexOrNull(): Promise<IndexEntry[] | null> {
    this.assertOpen();
    const found = await readRecord(this.storage, LOCAL_RESULTS_NAMESPACE, INDEX_KEY, this.key, INDEX_BOUNDS);
    return found === null ? null : validateIndex(found.value, this.maxObjects);
  }

  private async readIndex(): Promise<IndexEntry[]> {
    const entries = await this.readIndexOrNull();
    // A missing index is a store that was never created or was damaged; it is never silently reset.
    if (entries === null) throw new LocalStoreError("not_found");
    return entries;
  }

  private async writeIndex(entries: IndexEntry[]): Promise<void> {
    this.assertOpen();
    const sealed = sealRecord({ entries }, this.key, INDEX_KEY, INDEX_BOUNDS);
    try {
      await this.storage.writeStrict(LOCAL_RESULTS_NAMESPACE, INDEX_KEY, sealed);
    } catch (error) {
      throw toLocalStoreError(error);
    }
  }

  private async readObject(requestId: string): Promise<LocalResultObject | null> {
    this.assertOpen();
    const key = objectKey(requestId);
    const found = await readRecord(this.storage, LOCAL_RESULTS_NAMESPACE, key, this.key, OBJECT_BOUNDS);
    if (found === null) return null;
    const object = validateObject(found.value);
    if (object.request_id !== requestId) throw new LocalStoreError("invalid_record");
    return object;
  }

  private async writeObject(object: LocalResultObject, exclusive: boolean): Promise<void> {
    const key = objectKey(object.request_id);
    this.assertOpen();
    const sealed = sealRecord(object, this.key, key, OBJECT_BOUNDS);
    try {
      if (exclusive) {
        if (!(await this.storage.writeIfAbsentStrict(LOCAL_RESULTS_NAMESPACE, key, sealed))) {
          throw new LocalStoreError("exists");
        }
      } else {
        await this.storage.writeStrict(LOCAL_RESULTS_NAMESPACE, key, sealed);
      }
    } catch (error) {
      throw toLocalStoreError(error);
    }
  }

  private async deleteObject(requestId: string): Promise<void> {
    this.assertOpen();
    try {
      await this.storage.delete(LOCAL_RESULTS_NAMESPACE, objectKey(requestId));
    } catch (error) {
      throw toLocalStoreError(error);
    }
  }
}

function visible(item: { state: LocalResultState }, includeUncommitted: boolean): boolean {
  return includeUncommitted || item.state === "committed";
}

function indeterminateOf(object: LocalResultObject, now: number): LocalResultObject {
  return { ...object, state: "indeterminate", state_changed_at: now, expires_at: now + INDETERMINATE_TTL_MS };
}

function sameEntry(left: IndexEntry, right: IndexEntry): boolean {
  return (
    left.request_id === right.request_id &&
    left.state === right.state &&
    left.bytes === right.bytes &&
    left.created_at === right.created_at &&
    left.state_changed_at === right.state_changed_at &&
    left.expires_at === right.expires_at
  );
}

function indexEntry(object: LocalResultObject, bytes: number): IndexEntry {
  return {
    request_id: object.request_id,
    state: object.state,
    bytes,
    created_at: object.created_at,
    state_changed_at: object.state_changed_at,
    expires_at: object.expires_at,
  };
}

/** Canonical plaintext size; RESULT_OBJECT_MAX_BYTES and the total cap are measured on it. */
function objectBytes(object: LocalResultObject): number {
  return canonicalBytes(object, RESULT_OBJECT_MAX_BYTES).length;
}

function boundedCap(value: number | undefined, production: number): number {
  if (value === undefined) return production;
  if (!Number.isSafeInteger(value) || value <= 0 || value > production) throw new LocalStoreError("capacity");
  return value;
}

/** Flat body only: the walk is bounded by the byte cap before canonical serialization. */
export function validateBody(input: unknown): LocalResultBody {
  const body = asPlainRecord(input);
  if (Object.getPrototypeOf(body) !== Object.prototype && Object.getPrototypeOf(body) !== null) {
    throw new LocalStoreError("invalid_record");
  }
  const copy: LocalResultBody = {};
  // A running lower bound on the canonical size stops an oversized body before it is serialized.
  let lowerBound = 2;
  for (const name of Object.keys(body)) {
    // Assigning this name into the copy would run the prototype setter instead of storing a field, so the
    // stored body would differ from the one submitted; the name is refused rather than dropped.
    if (name === "__proto__") throw new LocalStoreError("invalid_record");
    const value = body[name];
    lowerBound += name.length + 3;
    if (typeof value === "string") {
      lowerBound += value.length;
      copy[name] = value;
    } else if (Array.isArray(value)) {
      const items: string[] = [];
      for (const item of value) {
        if (typeof item !== "string") throw new LocalStoreError("invalid_record");
        lowerBound += item.length + 3;
        if (lowerBound > RESULT_BODY_MAX_BYTES) throw new LocalStoreError("capacity");
        items.push(item);
      }
      copy[name] = items;
    } else {
      throw new LocalStoreError("invalid_record");
    }
    if (lowerBound > RESULT_BODY_MAX_BYTES) throw new LocalStoreError("capacity");
  }
  canonicalBytes(copy, RESULT_BODY_MAX_BYTES);
  return copy;
}

function validateObject(input: unknown): LocalResultObject {
  const object = asPlainRecord(input);
  requireExactFields(object, [
    "request_id",
    "seat",
    "kind",
    "state",
    "created_at",
    "deadline",
    "expires_at",
    "state_changed_at",
    "body",
  ]);
  if (
    !isRequestId(object.request_id) ||
    !isLowerHex(object.seat, SEAT_ID_HEX_LENGTH) ||
    !LOCAL_RESULT_KINDS.some((kind) => kind === object.kind) ||
    !LOCAL_RESULT_STATES.some((state) => state === object.state) ||
    !isNonNegativeSafeInteger(object.created_at) ||
    !isNonNegativeSafeInteger(object.deadline) ||
    !isNonNegativeSafeInteger(object.expires_at) ||
    !isNonNegativeSafeInteger(object.state_changed_at) ||
    object.deadline < object.created_at
  ) {
    throw new LocalStoreError("invalid_record");
  }
  // Only a committed object carries a body.
  const committed = object.state === "committed";
  if (committed !== (object.body !== null)) throw new LocalStoreError("invalid_record");
  return {
    request_id: object.request_id,
    seat: object.seat,
    kind: object.kind as LocalResultKind,
    state: object.state as LocalResultState,
    created_at: object.created_at,
    deadline: object.deadline,
    expires_at: object.expires_at,
    state_changed_at: object.state_changed_at,
    body: committed ? validateBody(object.body) : null,
  };
}

function validateIndex(input: unknown, maxObjects: number): IndexEntry[] {
  const index = asPlainRecord(input);
  requireExactFields(index, ["entries"]);
  if (!Array.isArray(index.entries) || index.entries.length > maxObjects) throw new LocalStoreError("invalid_record");
  const seen = new Set<string>();
  return index.entries.map((value: unknown) => {
    const entry = asPlainRecord(value);
    requireExactFields(entry, ["request_id", "state", "bytes", "created_at", "state_changed_at", "expires_at"]);
    if (
      !isRequestId(entry.request_id) ||
      seen.has(entry.request_id) ||
      !LOCAL_RESULT_STATES.some((state) => state === entry.state) ||
      !isNonNegativeSafeInteger(entry.bytes) ||
      entry.bytes > RESULT_OBJECT_MAX_BYTES ||
      !isNonNegativeSafeInteger(entry.created_at) ||
      !isNonNegativeSafeInteger(entry.state_changed_at) ||
      !isNonNegativeSafeInteger(entry.expires_at)
    ) {
      throw new LocalStoreError("invalid_record");
    }
    seen.add(entry.request_id);
    return {
      request_id: entry.request_id,
      state: entry.state as LocalResultState,
      bytes: entry.bytes,
      created_at: entry.created_at,
      state_changed_at: entry.state_changed_at,
      expires_at: entry.expires_at,
    };
  });
}
