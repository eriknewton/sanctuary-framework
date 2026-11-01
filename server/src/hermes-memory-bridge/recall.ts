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
}
const limits: HermesRecallLimits = Object.freeze({ candidates: RECALL_MAX_CANDIDATES_SCANNED,
  passageUnits: RECALL_MAX_PASSAGE_SCAN_UNITS, scannedUnits: RECALL_MAX_SCANNED_UNITS_PER_CALL,
  retained: RECALL_MAX_RETAINED_CANDIDATES, wallMs: RECALL_WALL_BUDGET_MS });

/** One call owns all counters and retained excerpts; overrides can only tighten production bounds. */
export class HermesRecallBudget {
  readonly limits: HermesRecallLimits;
  readonly terms: readonly string[];
  truncated: boolean;
  candidatesScanned = 0;
  unitsScanned = 0;
  maximumRetained = 0;
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
  candidate(): boolean {
    if (!this.active()) return false;
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
  retain(passage: Pick<MemoryPassage, "passage_id" | "created_at" | "text">): void {
    const projected = recallTimestamp(passage.created_at);
    if (projected === null) return;
    const text = passage.text.toLowerCase().normalize("NFC");
    let distinct = 0;
    let occurrences = 0;
    for (const term of this.terms) {
      let count = 0;
      for (let index = text.indexOf(term); index >= 0; index = text.indexOf(term, index + term.length)) count++;
      if (count > 0) distinct++;
      occurrences += count;
    }
    if (distinct === 0) return;
    const candidate = { passage_id: passage.passage_id, created_at: projected.created_at, instant: projected.instant,
      excerpt: recallPrefix(passage.text, RECALL_PASSAGE_MAX_UNITS), distinct, occurrences };
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
