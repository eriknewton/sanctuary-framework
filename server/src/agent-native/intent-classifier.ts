import { COOPERATIVE_TOOL_NAMES, type CooperativeToolName } from "./tool-names.js";
import {
  EVALUATE_NOUNS,
  EVALUATE_RELATED_TOOLS,
  EVALUATE_ROUTES,
  type EvaluateQuestion,
  type EvaluateRoute,
  type EvaluateRouteToolName,
} from "./capabilities-catalog.js";

export interface IntentClassification {
  safety_class: "ordinary" | "sensitive" | "gated";
  /** Evaluate routes carry their question alongside ordinary guidance. */
  intent_class?: "evaluate";
  evaluate_question?: EvaluateQuestion;
  tool: CooperativeToolName | EvaluateRouteToolName | null;
  example: Record<string, unknown> | null;
  why_sanctuary: string;
  guidance?: string;
  related_tools?: typeof EVALUATE_RELATED_TOOLS;
  remediation_class?: "request_review" | "try_lower_scope" | "wait";
  probe_key?: string;
}

// About 150 English words, more than ten times the longest catalog or test phrasing.
export const HELP_INTENT_MAX_CHARS = 1024;
// Four classifier caps, or 2^12 code points; must match help inputSchema in cooperative-surface.ts.
export const HELP_INTENT_SCHEMA_MAX_CHARS = 4 * HELP_INTENT_MAX_CHARS;
// Prefix and suffix together scan one classifier cap.
export const HELP_BAND_SCAN_CHARS = HELP_INTENT_MAX_CHARS / 2;
// Well above an ordinary intent's leetspeak copy plus one copy per encoded token.
export const HELP_MAX_VARIANTS = 32;
// One decode chain may use a quarter of the variant slots, leaving room for other tokens and generators.
export const HELP_MAX_DECODE_PASSES = HELP_MAX_VARIANTS / 4;
// Thirty-two variants of one scan unit bound retained decoded UTF-8 text.
export const HELP_MAX_VARIANT_BYTES = HELP_MAX_VARIANTS * HELP_BAND_SCAN_CHARS;
// Four bytes, the shortest needle, require eight base64 characters.
const BASE64_MIN_CHARS = 8;
export const HELP_NEEDLES = [
  "delete", "forget", "erase", "wipe", "purge", "remove", "remove permanently", "removepermanently",
  "destroy", "shred", "drop", "export", "import", "identity bundle", "identitybundle",
  "private key", "privatekey", "secret key", "secretkey", "sign", "signature", "approval",
  "policy", "webhook", "callback", "http://", "https://", "other agent", "otheragent",
  "prior session", "priorsession", "widen",
] as const;
export const HELP_BENIGN_WORDS = [
  "important", "importance", "importantly", "design", "designs", "designed", "designing", "designer",
  "redesign", "assign", "assigns", "assigned", "assigning", "assignment", "assignments",
  "signal", "signals", "dropdown", "backdrop",
] as const;
export const HELP_MASK = "-";
const CLAUSE_SPLITTER = /\b(?:then|and|also)\b|[,;]+/;
const splitClauses = (text: string): string[] => text.split(CLAUSE_SPLITTER).map(s => s.trim()).filter(Boolean);

function benignSpans(text: string): Array<{ start: number; end: number }> {
  const pattern = new RegExp(`(^|[^a-z0-9])(${HELP_BENIGN_WORDS.join("|")})(?=$|[^a-z0-9])`, "g");
  return Array.from(text.matchAll(pattern), match => ({
    start: match.index + match[1].length,
    end: match.index + match[0].length,
  }));
}
function mask(text: string): string {
  const spans = benignSpans(text);
  let result = "";
  let offset = 0;
  for (const span of spans) {
    result += text.slice(offset, span.start) + HELP_MASK;
    offset = span.end;
  }
  return result + text.slice(offset);
}

function normalizeHelpVariant(text: string): { normalized: string; fold: string; unreadable: boolean } {
  // Every scan uses compatibility normalization, accent removal, then case folding so copies share one alphabet.
  const normalized = text.normalize("NFKC").normalize("NFD").replace(/\p{M}/gu, "").replace(/[\u2018\u2019\u02bc]/g, "'");
  const fold = normalized.toLowerCase();
  // Letters outside the scanner's ASCII class must not disappear during compaction.
  const unreadable = /[^a-z]/u.test(fold.replace(/[^\p{L}]/gu, ""));
  return { normalized, fold, unreadable };
}

/** Return bounded folded decodings and their retained work counts for intent screening. */
export function buildHelpVariants(normalized: string): { variants: string[]; bytes: number; budgetHit: boolean; unreadable: boolean } {
  const original = normalizeHelpVariant(normalized);
  const { fold } = original;
  let unreadable = original.unreadable;
  const masked = mask(fold);
  const variants = new Set<string>();
  let bytes = 0;
  let budgetHit = false;
  const add = (value: string): boolean => {
    const variant = normalizeHelpVariant(value);
    const folded = variant.fold;
    unreadable ||= variant.unreadable;
    if (folded === fold || folded === masked || variants.has(folded)) return true;
    const size = Buffer.byteLength(folded, "utf8");
    // Both budgets apply before retention, keeping every scanned copy within bounded work.
    if (variants.size >= HELP_MAX_VARIANTS || bytes + size > HELP_MAX_VARIANT_BYTES) {
      budgetHit = true;
      return false;
    }
    variants.add(folded);
    bytes += size;
    if (variants.size === HELP_MAX_VARIANTS || bytes === HELP_MAX_VARIANT_BYTES) {
      budgetHit = true;
      return false;
    }
    return true;
  };
  const decodePercent = (text: string): boolean => {
    let current = text;
    for (let pass = 0; pass < HELP_MAX_DECODE_PASSES; pass += 1) {
      let decoded: string;
      try { decoded = decodeURIComponent(current); }
      catch { return true; /* Previously retained text remains available to the screen. */ }
      if (decoded === current) return true;
      if (!add(decoded)) return false;
      // Normalize each retained output before another pass so compatibility percent signs share the same fixed point.
      current = normalizeHelpVariant(decoded).normalized;
    }
    try {
      // A chain still changing at the pass bound cannot authorize runnable guidance.
      if (decodeURIComponent(current) !== current) {
        budgetHit = true;
        return false;
      }
    } catch { /* The last retained text has no further valid percent decoding. */ }
    return true;
  };
  if (!decodePercent(normalized)) return { variants: [...variants], bytes, budgetHit, unreadable };
  for (const token of normalized.split(/[^a-z0-9%+/=_-]+/i)) {
    if (token.includes("%")) {
      if (!decodePercent(token)) break;
    }
    if (token.length >= BASE64_MIN_CHARS && /^[a-z0-9+/=_-]+$/i.test(token)) {
      try {
        // Only valid UTF-8 bytes represent a text variant; the original token is always screened.
        const decoded = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(token, "base64"));
        if (!add(decoded)) break;
      } catch { /* Non-text bytes leave only the original token to screen. */ }
    }
  }
  if (!budgetHit) add(normalized.replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a").replace(/@/g, "a"));
  return { variants: [...variants], bytes, budgetHit, unreadable };
}

function scanCopies(fold: string): string | undefined {
  const masked = mask(fold);
  const spans = benignSpans(fold);
  // Each offset names its benign occurrence, so checking a hit takes constant work.
  const benignOccurrence = new Int32Array(fold.length).fill(-1);
  spans.forEach((span, index) => benignOccurrence.fill(index, span.start, span.end));
  const scan = (source: string, removeJoiners: boolean, ignoreBenign: boolean): string | undefined => {
    const direct: string[] = [];
    const compact: string[] = [];
    const directOffsets: number[] = [];
    const compactOffsets: number[] = [];
    for (let i = 0; i < source.length; i += 1) {
      const char = source[i];
      // Copies B and C remove complete joiner code points while keeping UTF-16 offsets for benign-span checks.
      const point = String.fromCodePoint(source.codePointAt(i)!);
      if (removeJoiners && /[\p{Pd}_.]/u.test(point)) {
        // The loop advances one code unit; skip any remaining unit of this code point as well.
        i += point.length - 1;
        continue;
      }
      direct.push(char);
      directOffsets.push(i);
      if (/[a-z0-9:/._-]/.test(char)) {
        compact.push(char);
        compactOffsets.push(i);
      }
    }
    const copies = [{ text: direct.join(""), offsets: directOffsets }, { text: compact.join(""), offsets: compactOffsets }];
    for (const needle of HELP_NEEDLES) {
      for (const { text, offsets } of copies) {
        let index = text.indexOf(needle);
        while (index !== -1) {
          const start = offsets[index];
          const end = offsets[index + needle.length - 1] + 1;
          // Only a hit wholly contained in one benign occurrence is eligible for this ignore.
          if (!ignoreBenign || (benignOccurrence[start] < 0 || benignOccurrence[start] !== benignOccurrence[end - 1])) return needle;
          index = text.indexOf(needle, index + 1);
        }
      }
    }
    return undefined;
  };
  return scan(masked, false, false) ?? scan(masked, true, false) ?? scan(fold, true, true);
}
function screen(text: string): { needle?: string; budgetHit: boolean; fold: string; unreadable?: boolean } {
  const { normalized, fold } = normalizeHelpVariant(text);
  const { variants, budgetHit, unreadable } = buildHelpVariants(normalized);
  // No scan copy may erase an unreadable letter from the original or any decoded text.
  if (unreadable) return { budgetHit, fold, unreadable };
  const clauses = splitClauses(fold);
  const texts = [...(clauses.length > 1 ? clauses : []), fold, ...variants];
  // A needle found in any scanned copy wins, so benign words and encodings preserve the same review boundary.
  for (const value of texts) {
    const needle = scanCopies(value);
    if (needle) return { needle, budgetHit, fold };
  }
  return { budgetHit, fold };
}
function sensitive(probe_key: string): IntentClassification {
  return { safety_class: "sensitive", tool: null, example: null,
    why_sanctuary: "The request is ambiguous, so runnable guidance is suppressed.",
    remediation_class: "try_lower_scope", probe_key };
}
function gated(probe_key: string): IntentClassification {
  // The first eight needles name the cooperative forget operation.
  return { safety_class: "gated", tool: HELP_NEEDLES.slice(0, 8).some(needle => needle === probe_key) ? COOPERATIVE_TOOL_NAMES.forget : null,
    example: { args: "<operator-approved placeholders only>" },
    why_sanctuary: "This request may need operator review before execution.",
    remediation_class: "request_review", probe_key };
}


export const HELP_WRITE_CUES = [
  "remember", "memorize", "memorise", "store", "save", "persist", "stash", "note down", "note that",
  "jot", "jot down", "write down", "write this down", "write that down", "write it down",
  "keep in mind", "keep track of", "keep a note", "keep a record", "keep note of",
] as const;
export const HELP_STRONG_READ_CUES = ["recall", "lookup", "look up", "retrieve", "fetch", "read back"] as const;
export const HELP_WEAK_READ_CUES = ["read", "get"] as const;
export const HELP_STORED_REFERENCES = ["saved", "stored", "remembered", "memorized", "recorded", "persisted", "noted", "kept"] as const;
// Evaluate noun yielding must match EVALUATE_NOUNS and EVALUATE_ROUTES in capabilities-catalog.ts.
export const MEMORY_VERBS = {
  remember: HELP_WRITE_CUES,
  recall: HELP_STRONG_READ_CUES,
  weakRead: HELP_WEAK_READ_CUES,
} as const;
// Two intervening tokens keep local negation attached to its cue.
const NEGATION_REACH = 2;
// Twenty-four characters cover the longest marker (might), a pronoun and their spaces.
const PURPOSE_LOOKBACK_CHARS = 24;
// A note four words away is still the object of the verb.
const WRITE_OBJECT_WORDS = 4;
// The memory destination stays within a short, punctuation-free phrase.
const WRITE_DESTINATION_CHARS = 60;
interface Cue { start: number; end: number; kind: "write" | "strong" | "weak"; clause: number; negated: boolean }
function collectCues(fold: string): Cue[] {
  const cues: Cue[] = [];
  let clauseStart = 0;
  let clauseIndex = 0;
  for (const rawClause of fold.split(CLAUSE_SPLITTER)) {
    const start = fold.indexOf(rawClause, clauseStart);
    // Joiners between letters carry the same local negation boundary as whitespace, with source offsets preserved.
    const clause = rawClause.replace(/(?<=[a-z])[\p{Pd}_./]+(?=[a-z])/gu, joiners => " ".repeat(joiners.length));
    const tokens = Array.from(clause.matchAll(/\S+/g));
    const add = (pattern: RegExp, kind: Cue["kind"]) => {
      for (const match of clause.matchAll(pattern)) {
        const tokenIndex = tokens.findIndex(token => token.index <= match.index && token.index + token[0].length > match.index);
        const earlier = tokens.slice(Math.max(0, tokenIndex - NEGATION_REACH - 1), tokenIndex);
        const negated = earlier.some(token => /^(?:not|never|don't|cannot)$/.test(token[0]) || token[0].endsWith("n't"));
        cues.push({ start: start + match.index, end: start + match.index + match[0].length, kind, clause: clauseIndex, negated });
      }
    };
    add(new RegExp(`\\b(?:${[...MEMORY_VERBS.remember].sort((a, b) => b.length - a.length).join("|")})\\b`, "g"), "write");
    add(/\bwrite\s+(?:a|an|the|this|that|my)\s+(?:note|memo|reminder)\b/g, "write");
    for (const verb of clause.matchAll(/\b(?:make|take|leave|add)\b/g)) {
      const following = tokens.filter(token => token.index >= verb.index + verb[0].length).slice(0, WRITE_OBJECT_WORDS);
      const object = following.find(token => /^(?:note|notes|message|memo|reminder)\b/.test(token[0]));
      if (object) {
        const before = tokens.filter(token => token.index < verb.index).slice(-NEGATION_REACH - 1);
        const negated = before.some(token => /^(?:not|never|don't|cannot)$/.test(token[0]) || token[0].endsWith("n't"));
        cues.push({ start: start + verb.index, end: start + object.index + object[0].length, kind: "write", clause: clauseIndex, negated });
      }
    }
    add(new RegExp(`\\b(?:put|add|commit)\\b[^,;.]{0,${WRITE_DESTINATION_CHARS}}\\b(?:to memory|in memory|into memory)\\b`, "g"), "write");
    add(new RegExp(`\\b(?:${MEMORY_VERBS.recall.join("|")})\\b`, "g"), "strong");
    add(new RegExp(`\\b(?:${MEMORY_VERBS.weakRead.join("|")})\\b`, "g"), "weak");
    clauseStart = start + clause.length;
    clauseIndex += 1;
  }
  // The earliest cue decides; a longer cue at the same offset keeps its full meaning.
  return cues.sort((a, b) => a.start - b.start || b.end - a.end).filter((cue, index, all) =>
    index === 0 || cue.start !== all[index - 1].start);
}
function memoryAnswer(kind: "write" | "read", fold: string): IntentClassification {
  // A timezone token authorizes the concrete timezone example; other memory guidance stays a fill-in template.
  const tokens = fold.match(/[a-z0-9]+/g) ?? [];
  const timezone = tokens.some((token, index) => token === "timezone" || token === "tz" ||
    (token === "time" && tokens[index + 1] === "zone"));
  return kind === "write" ? {
    safety_class: "ordinary", tool: COOPERATIVE_TOOL_NAMES.remember,
    example: timezone ? { key: "user_tz", value: "America/Los_Angeles" } : { key: "<key>", value: "<value>" },
    why_sanctuary: "State is encrypted, identity-bound, and audited.",
  } : {
    safety_class: "ordinary", tool: COOPERATIVE_TOOL_NAMES.recall,
    example: { key: timezone ? "user_tz" : "<key>" },
    why_sanctuary: "Recall preserves verification status in the response.",
  };
}
function evaluateAnswer(route: EvaluateRoute): IntentClassification {
  return { safety_class: "ordinary", intent_class: "evaluate", evaluate_question: route.question,
    tool: route.tool, example: route.example, why_sanctuary: route.why_sanctuary,
    guidance: route.guidance, related_tools: EVALUATE_RELATED_TOOLS };
}
function state_MULTI_CLAUSE_AMBIGUOUS(fold: string, cues: Cue[]): boolean {
  const clauses = fold.split(CLAUSE_SPLITTER);
  return clauses.filter(clause => clause.trim()).length > 1 && clauses.some((clause, index) =>
    clause.trim() && !cues.some(cue => cue.clause === index));
}
function state_QUESTION_GUARD(fold: string, cues: Cue[], allCues: Cue[]): IntentClassification | undefined {
  const storedClauses = new Set<number>();
  let otherQuestion = false;
  let clauseStart = 0;
  for (const [index, clause] of fold.split(CLAUSE_SPLITTER).entries()) {
    const start = fold.indexOf(clause, clauseStart);
    clauseStart = start + clause.length;
    // Question syntax uses every write cue; local negation only controls the resulting guidance.
    const writes = allCues.filter(cue => cue.clause === index && cue.kind === "write");
    if (!writes.length || !/^(?:what|which|where|did|does|do\s+(?:you|we)|have\s+(?:you|we|i))\b/.test(clause.trim())) continue;
    if (writes.every(cue => /\bto\s+$/.test(fold.slice(start, cue.start)))) continue;
    const storedQuestion = writes.every(cue => {
      const before = fold.slice(start, cue.start);
      const after = fold.slice(cue.end, clauseStart);
      return /\b(?:did|have|has|had)\s+(?:i|you|we|they|it)\s+$/.test(before) ||
        (fold.slice(cue.start, cue.end) === "remember" && /^\s*do\s+(?:you|we)\s+$/.test(before) && /^\s+(?:my|our|what|which|where|when|whether|if|how)\b/.test(after));
    });
    if (storedQuestion) storedClauses.add(index);
    else otherQuestion = true;
  }
  // A stored-data question in any clause excludes write guidance; only its own live cues permit recall.
  if (storedClauses.size) {
    if (cues.some(cue => !storedClauses.has(cue.clause))) return sensitive("conflict");
    const readNegated = allCues.some(cue => cue.negated && cue.kind !== "write" && storedClauses.has(cue.clause));
    return readNegated ? sensitive("ambiguous") : memoryAnswer("read", fold);
  }
  if (otherQuestion) return sensitive("conflict");
}
function state_MAIN_VERB(fold: string, cues: Cue[]): IntentClassification | undefined {
  const writes = cues.filter(cue => cue.kind === "write");
  const remaining = cues.filter(cue => {
    if (cue.kind === "write" || !writes.length) return true;
    const before = fold.slice(Math.max(0, cue.start - PURPOSE_LOOKBACK_CHARS), cue.start);
    const lastPunctuation = Math.max(fold.lastIndexOf(",", cue.start), fold.lastIndexOf(";", cue.start), fold.lastIndexOf(".", cue.start));
    const context = fold.slice(lastPunctuation + 1, cue.start);
    const precedingWords = before.trimEnd().split(/\s+/);
    const markers = ["to", "can", "could", "will", "may", "might"];
    const lastWord = precedingWords.at(-1) ?? "";
    const purposeMarker = markers.includes(lastWord) ||
      (markers.includes(precedingWords.at(-2) ?? "") && /^\w+$/.test(lastWord));
    const purposeContext = /\b(?:so|in order|for)\b/.test(context) || writes.some(write => write.clause === cue.clause && write.start < cue.start);
    return !(purposeMarker && purposeContext);
  });
  if (remaining.some(cue => cue.kind === "write") && remaining.some(cue => cue.kind !== "write")) return sensitive("conflict");
  const first = remaining[0];
  if (first) return memoryAnswer(first.kind === "write" ? "write" : "read", fold);
}
export function classifyIntent(intent: string): IntentClassification {
  const points = Array.from(intent);
  if (points.length > HELP_INTENT_MAX_CHARS) {
    const prefix = screen(points.slice(0, HELP_BAND_SCAN_CHARS).join(""));
    const suffix = screen(points.slice(-HELP_BAND_SCAN_CHARS).join(""));
    if (prefix.unreadable || suffix.unreadable) return sensitive("unreadable");
    if (prefix.needle ?? suffix.needle) return gated((prefix.needle ?? suffix.needle)!);
    return state_OVERSIZE();
  }
  const scanned = screen(intent);
  if (scanned.unreadable) return sensitive("unreadable");
  if (scanned.needle) return state_GATED(scanned.needle);
  if (scanned.budgetHit) return state_VARIANT_BUDGET();
  const fold = scanned.fold;
  const allCues = collectCues(fold);
  // A negated cue class remains unavailable throughout routing and both fallbacks in its clause.
  const cues = allCues.filter(cue => !cue.negated && !allCues.some(other =>
    other.negated && other.clause === cue.clause && (other.kind === "write") === (cue.kind === "write")));
  const question = state_QUESTION_GUARD(fold, cues, allCues);
  if (question) return question;
  if (state_MULTI_CLAUSE_AMBIGUOUS(fold, allCues)) return sensitive("multi_intent");
  const writes = cues.filter(cue => cue.kind === "write");
  const route = EVALUATE_ROUTES.find(candidate => candidate.matches.test(fold));
  const state_EVALUATE_NOUN = route && EVALUATE_NOUNS.test(fold) && !writes.length && !cues.some(cue => cue.kind === "strong");
  if (state_EVALUATE_NOUN) return evaluateAnswer(route);
  const main = state_MAIN_VERB(fold, cues);
  if (main) return main;
  const state_EVALUATE_FALLBACK = route && !writes.length;
  if (state_EVALUATE_FALLBACK) return evaluateAnswer(route);
  const state_STORED_REFERENCE = new RegExp(`\\b(?:${HELP_STORED_REFERENCES.join("|")})\\b`).test(fold) && !writes.length && !allCues.some(cue => cue.negated && cue.kind !== "write");
  if (state_STORED_REFERENCE) return memoryAnswer("read", fold);
  return state_AMBIGUOUS();
}
function state_OVERSIZE(): IntentClassification { return sensitive("oversize"); }
function state_VARIANT_BUDGET(): IntentClassification { return sensitive("variant_budget"); }
function state_GATED(needle: string): IntentClassification { return gated(needle); }
function state_AMBIGUOUS(): IntentClassification { return sensitive("ambiguous"); }
