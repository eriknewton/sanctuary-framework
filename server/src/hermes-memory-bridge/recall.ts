import { HUB_APPROVAL_PASSAGE_MAX_UNITS } from "../contracts/v1.1/hub-events.js";
import type { MemoryPassage } from "../sdw/adapters/memory-backend.js";
import { MAX_RESULT_FRAME_BYTES, MEMORY_CORPUS_SCAN_CAP } from "./constants.js";

export const RECALL_MAX_QUERY_UNITS = 4096; // Four Ki UTF-16 units bound query normalization work.
export const RECALL_MAX_TERMS = 6; // At most six distinct matching terms per passage.
export const RECALL_TERM_MAX_POINTS = 32; // Thirty-two code points bound each distinct matching term.
export const RECALL_MAX_PASSAGES = 3; // Three excerpts are the recall context policy limit.
// Must match HUB_APPROVAL_PASSAGE_MAX_UNITS in server/src/contracts/v1.1/hub-events.ts.
export const RECALL_PASSAGE_MAX_UNITS = HUB_APPROVAL_PASSAGE_MAX_UNITS;
export const RECALL_CREATED_AT_UNITS = 24; // YYYY-MM-DDTHH:mm:ss.sssZ has exactly 24 UTF-16 units.
export const RECALL_DATE_UNITS = "YYYY-MM-DD".length;
export const RECALL_LINE_OVERHEAD_UNITS = "- (saved ".length + RECALL_DATE_UNITS + ") ".length + "\n".length;
export const RECALL_CONTEXT_MAX_UNITS = RECALL_MAX_PASSAGES * (RECALL_PASSAGE_MAX_UNITS + RECALL_LINE_OVERHEAD_UNITS);
export const RECALL_MAX_CANDIDATES_SCANNED = MEMORY_CORPUS_SCAN_CAP;
// Bridge saves fit this byte cap; only imported passages can exceed this many UTF-16 units.
export const RECALL_MAX_PASSAGE_SCAN_UNITS = MAX_RESULT_FRAME_BYTES;
export const RECALL_MAX_SCANNED_UNITS_PER_CALL = 32 * RECALL_MAX_PASSAGE_SCAN_UNITS; // Thirty-two maximum passage scans per call.
export const RECALL_MAX_RETAINED_CANDIDATES = RECALL_MAX_PASSAGES;
// Five is the number of verification failures among the top-ranked candidates that can be absorbed before the
// answer may differ from verifying every passage; bridge saves are always signed by the bridge, so failures come
// only from tamper or owner imports. Eight entries bound the unverified candidates one recall holds and verifies.
export const RECALL_VERIFY_CANDIDATES = RECALL_MAX_PASSAGES + 5;
// Twenty-five milliseconds is about twice box 1's estimated full per-passage verification cost of 12.3 ms, rounded
// up; the scan stops this long before the wall so the candidates it ranked can still be verified inside it.
export const RECALL_VERIFY_RESERVE_MS = RECALL_VERIFY_CANDIDATES * 25;
// Four equals Node's default thread-pool size (UV_THREADPOOL_SIZE unset), the pool every asynchronous file read
// runs on. It is a bounded observation, not a proof: on box 1 (11-18, 2000 passages) windows of 2 to 16 measured
// within session drift of each other, and the smaller window bounds the reads and retained state one call holds.
export const RECALL_READ_AHEAD_PASSAGES = 4;
// Two: a read-ahead slot issues its document and provenance reads together, then one status, provenance or chunk
// read at a time, so at most two of its reads are ever in flight at once.
export const RECALL_READS_PER_SLOT = 2;
// The passage text one call's read-ahead retains, at most: each slot drops its text once its passage passes
// RECALL_MAX_PASSAGE_SCAN_UNITS, so it holds at most that many units, and at most RECALL_READ_AHEAD_PASSAGES slots
// exist. The read path enforces no maximum on one stored chunk, so this bounds retained text, not the one chunk
// record each slot decodes transiently, which can be any size the store holds (as for the one-at-a-time loop).
// Must match the release in readRecallSlot in sdw/adapters/sdw-memory-backend.ts.
export const RECALL_READ_AHEAD_RETAINED_TEXT_UNITS = RECALL_READ_AHEAD_PASSAGES * RECALL_MAX_PASSAGE_SCAN_UNITS;
// Must match SHIM_CONNECT_HELLO_TIMEOUT_MS in hermes-memory-client/protocol.ts.
export const RECALL_PREFETCH_BUDGET_MS = 5000; // Five seconds is the local prefetch window.
export const RECALL_REPLY_RESERVE_MS = 1000; // One second is reserved for audit and response delivery.
export const RECALL_WALL_BUDGET_MS = RECALL_PREFETCH_BUDGET_MS - RECALL_REPLY_RESERVE_MS;
export const RECALL_STOPWORDS = Object.freeze("about again also and any are but can did does for from had has have how into its just know not our please remember should tell that the their them then there these they this those was were what when where which who whom why will with would you your".split(" "));
const stopwords = new Set(RECALL_STOPWORDS);

/** Cut a UTF-16 budget without splitting a supplementary code point. */
export function recallPrefix(text: string, units: number): string {
  let end = Math.min(text.length, units);
  if (end > 0 && end < text.length && /[\uD800-\uDBFF]/u.test(text[end - 1]!) && /[\uDC00-\uDFFF]/u.test(text[end]!)) end--;
  return text.slice(0, end);
}

/** Extract bounded, first-seen terms for literal substring matching. */
export function recallTerms(query: string): { terms: readonly string[]; truncated: boolean } {
  const prefix = recallPrefix(query, RECALL_MAX_QUERY_UNITS);
  let truncated = prefix.length < query.length;
  const terms: string[] = [];
  for (const token of prefix.toLowerCase().normalize("NFC").split(/[^\p{L}\p{N}]+/u)) {
    const points = Array.from(token);
    if (points.length < 3 || stopwords.has(token)) continue; // Three code points is the minimum useful matching token.
    const term = points.slice(0, RECALL_TERM_MAX_POINTS).join("");
    if (points.length > RECALL_TERM_MAX_POINTS) truncated = true;
    if (terms.includes(term)) continue;
    if (terms.length === RECALL_MAX_TERMS) { truncated = true; break; }
    terms.push(term);
  }
  return { terms, truncated };
}

export interface HermesRecallCandidate {
  readonly passage_id: string;
  readonly created_at: string;
  readonly instant: number;
  readonly excerpt: string;
  readonly distinct: number;
  readonly occurrences: number;
}
export interface HermesRecallResult {
  readonly outcome: "recalled";
  readonly context: string;
  readonly passages: readonly { readonly passage_id: string; readonly created_at: string }[];
  readonly truncated: boolean;
}
export interface HermesRecallLimits {
  readonly candidates: number;
  readonly passageUnits: number;
  readonly scannedUnits: number;
  readonly retained: number;
  readonly wallMs: number;
  readonly verifyCandidates: number;
  readonly verifyReserveMs: number;
  /** Passages read ahead of the ordered commit; 1 keeps the one-passage-at-a-time order of reads. */
  readonly readAhead: number;
}
const limits: HermesRecallLimits = Object.freeze({ candidates: RECALL_MAX_CANDIDATES_SCANNED,
  passageUnits: RECALL_MAX_PASSAGE_SCAN_UNITS, scannedUnits: RECALL_MAX_SCANNED_UNITS_PER_CALL,
  retained: RECALL_MAX_RETAINED_CANDIDATES, wallMs: RECALL_WALL_BUDGET_MS,
  verifyCandidates: RECALL_VERIFY_CANDIDATES, verifyReserveMs: RECALL_VERIFY_RESERVE_MS,
  readAhead: RECALL_READ_AHEAD_PASSAGES });

/** One call owns all counters and retained excerpts; overrides can only tighten production bounds. */
export class HermesRecallBudget {
  readonly limits: HermesRecallLimits;
  readonly terms: readonly string[];
  truncated: boolean;
  candidatesScanned = 0;
  unitsScanned = 0;
  maximumRetained = 0;
  maximumHeld = 0;
  private readonly startedAt: number;
  private readonly best: HermesRecallCandidate[] = [];
  constructor(query: string, readonly nowMs: () => number, readonly signal: AbortSignal, tighten: Partial<HermesRecallLimits> = {}) {
    this.limits = Object.freeze({ ...limits, ...tighten });
    for (const key of Object.keys(limits) as (keyof HermesRecallLimits)[]) {
      const value = this.limits[key];
      if (!Number.isSafeInteger(value) || value < 1 || value > limits[key]) throw new RangeError("Recall limits may only tighten");
    }
    const extracted = recallTerms(query);
    this.terms = extracted.terms;
    this.truncated = extracted.truncated;
    this.startedAt = nowMs();
  }
  active(): boolean {
    if (this.signal.aborted || this.nowMs() - this.startedAt >= this.limits.wallMs || this.unitsScanned >= this.limits.scannedUnits) {
      this.truncated = true;
      return false;
    }
    return true;
  }
  /** The scan phase ends the verification reserve before the wall, so ranked candidates are still verified inside it. */
  scanning(): boolean {
    if (!this.active()) return false;
    // The reserve is carved out of the wall, never added to it: verification spends only time the wall already allows.
    if (this.nowMs() - this.startedAt >= this.limits.wallMs - this.limits.verifyReserveMs) {
      this.truncated = true;
      return false;
    }
    return true;
  }
  /**
   * The scan's stop conditions (abort, the wall minus the verification reserve, the scanned-unit cap) as a pure
   * question. It changes no state: scanning() sets truncated as a side effect, so the read-ahead, which runs ahead
   * of the commit and must leave every budget decision to the commit in listing order, asks only this.
   */
  scanOpen(): boolean {
    return !this.signal.aborted && this.nowMs() - this.startedAt < this.limits.wallMs - this.limits.verifyReserveMs &&
      this.unitsScanned < this.limits.scannedUnits;
  }
  /** The verification phase stops only for abort and the wall; the scan caps bound scanning, not verifying ranked candidates. */
  verifying(): boolean {
    if (this.signal.aborted || this.nowMs() - this.startedAt >= this.limits.wallMs) {
      this.truncated = true;
      return false;
    }
    return true;
  }
  candidate(): boolean {
    if (!this.scanning()) return false;
    if (this.candidatesScanned === this.limits.candidates) { this.truncated = true; return false; }
    this.candidatesScanned++;
    return true;
  }
  scan(units: number): boolean {
    const remaining = this.limits.scannedUnits - this.unitsScanned;
    this.unitsScanned += Math.min(units, remaining);
    if (units > remaining) { this.truncated = true; return false; }
    return true;
  }
  get retainedCount(): number {
    return this.best.length;
  }
  retain(passage: Pick<MemoryPassage, "passage_id" | "created_at" | "text">): void {
    const candidate = this.score(passage);
    if (candidate !== null) this.admit(candidate);
  }
  /** Score without retaining: a score carries no credibility and only orders candidates for verification. */
  score(passage: Pick<MemoryPassage, "passage_id" | "created_at" | "text">): HermesRecallCandidate | null {
    const projected = recallTimestamp(passage.created_at);
    if (projected === null) return null;
    const text = passage.text.toLowerCase().normalize("NFC");
    let distinct = 0;
    let occurrences = 0;
    for (const term of this.terms) {
      let count = 0;
      for (let index = text.indexOf(term); index >= 0; index = text.indexOf(term, index + term.length)) count++;
      if (count > 0) distinct++;
      occurrences += count;
    }
    if (distinct === 0) return null;
    return { passage_id: passage.passage_id, created_at: projected.created_at, instant: projected.instant,
      excerpt: recallPrefix(passage.text, RECALL_PASSAGE_MAX_UNITS), distinct, occurrences };
  }
  /** Retain a candidate whose passage has already passed verification. */
  admit(candidate: HermesRecallCandidate): void {
    const index = this.best.findIndex(other => compareRecallCandidates(candidate, other) < 0);
    const position = index < 0 ? this.best.length : index;
    if (position >= this.limits.retained) return;
    if (this.best.length === this.limits.retained) this.best.pop();
    this.best.splice(position, 0, candidate);
    this.maximumRetained = Math.max(this.maximumRetained, this.best.length);
  }
  result(): HermesRecallResult {
    return { outcome: "recalled", context: this.best.map(p => `- (saved ${p.created_at.slice(0, RECALL_DATE_UNITS)}) ${p.excerpt}\n`).join(""),
      passages: this.best.map(p => ({ passage_id: p.passage_id, created_at: p.created_at })), truncated: this.truncated };
  }
}

/** The best unverified candidates of one recall, each with the record its verification must bind to. */
export class HermesRecallCandidateHeap<T> {
  private readonly entries: { readonly candidate: HermesRecallCandidate; readonly bound: T }[] = [];
  /** Set once a scored candidate was dropped for capacity; the answer may then miss a passage verify-everything returns. */
  overflowed = false;
  constructor(private readonly budget: HermesRecallBudget) {}
  get size(): number {
    return this.entries.length;
  }
  offer(candidate: HermesRecallCandidate, bound: T): void {
    const index = this.entries.findIndex(other => compareRecallCandidates(candidate, other.candidate) < 0);
    const position = index < 0 ? this.entries.length : index;
    // Bounded state from untrusted input: at most verifyCandidates entries, each one excerpt prefix and one record,
    // whatever the corpus size or scan order, so the verification work per call is bounded by the same number.
    if (position >= this.budget.limits.verifyCandidates) { this.overflowed = true; return; }
    if (this.entries.length === this.budget.limits.verifyCandidates) { this.entries.pop(); this.overflowed = true; }
    this.entries.splice(position, 0, { candidate, bound });
    this.budget.maximumHeld = Math.max(this.budget.maximumHeld, this.entries.length);
  }
  /** Remove and return the best remaining candidate, in compareRecallCandidates order. */
  take(): { readonly candidate: HermesRecallCandidate; readonly bound: T } | undefined {
    return this.entries.shift();
  }
}

/** Canonical timestamps bind both context dates and metadata to the same finite instant. */
export function recallTimestamp(stored: string): { created_at: string; instant: number } | null {
  const instant = new Date(stored).getTime();
  if (!Number.isFinite(instant)) return null;
  // The output bound is derived from this projection, not stored metadata, because the write gate does not bound it.
  const created_at = new Date(instant).toISOString();
  if (created_at.length !== RECALL_CREATED_AT_UNITS) return null;
  return { created_at, instant };
}
export function compareRecallCandidates(a: HermesRecallCandidate, b: HermesRecallCandidate): number {
  return b.distinct - a.distinct || b.occurrences - a.occurrences || b.instant - a.instant || a.passage_id.localeCompare(b.passage_id);
}
