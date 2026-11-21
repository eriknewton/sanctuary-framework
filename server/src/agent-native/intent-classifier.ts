import { COOPERATIVE_TOOL_NAMES, type CooperativeToolName } from "./tool-names.js";
import {
  EVALUATE_NOUNS,
  EVALUATE_RELATED_TOOLS,
  EVALUATE_ROUTES,
  type EvaluateQuestion,
  type EvaluateRoute,
  type EvaluateRouteToolName,
} from "./capabilities-catalog.js";

/**
 * The memory verbs, defined once and derived three ways so the routes and
 * the evaluate-noun yield rule cannot drift apart (pinned from
 * EVALUATE_NOUN_WORDS in capabilities-catalog.ts). `remember` and `recall`
 * are the ordinary route regexes, byte-for-byte the sets the routes used
 * before the evaluate state existed; `ordinary` is their union (the
 * multi-clause check); `outranksEvaluateNoun` is every memory verb except the
 * bare read/get, which are also everyday words for "tell me" and so yield to
 * an evaluate noun.
 */
const REMEMBER_VERB_WORDS = ["remember", "store", "save"] as const;
const RECALL_VERB_WORDS = ["recall", "read", "lookup", "get"] as const;
const BARE_READ_VERB_WORDS: ReadonlySet<string> = new Set(["read", "get"]);
const wordAlternation = (words: readonly string[]): RegExp => new RegExp(`\\b(${words.join("|")})\\b`);
export const MEMORY_VERBS = {
  remember: wordAlternation(REMEMBER_VERB_WORDS),
  recall: wordAlternation(RECALL_VERB_WORDS),
  ordinary: wordAlternation([...REMEMBER_VERB_WORDS, ...RECALL_VERB_WORDS]),
  outranksEvaluateNoun: wordAlternation(
    [...REMEMBER_VERB_WORDS, ...RECALL_VERB_WORDS].filter((word) => !BARE_READ_VERB_WORDS.has(word))
  ),
} as const;

export interface IntentClassification {
  safety_class: "ordinary" | "sensitive" | "gated";
  /** Present only on the evaluate state; the ordinary/sensitive/gated routes are unchanged. */
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

/** Return bounded folded decodings and their retained work counts for intent screening. */
export function buildHelpVariants(normalized: string): { variants: string[]; bytes: number; budgetHit: boolean } {
  const fold = normalized.toLowerCase();
  const masked = mask(fold);
  const variants = new Set<string>();
  let bytes = 0;
  let budgetHit = false;
  const add = (value: string): boolean => {
    const folded = value.toLowerCase();
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
  try {
    if (!add(decodeURIComponent(normalized))) return { variants: [...variants], bytes, budgetHit };
  } catch { /* Plain text remains available to the screen. */ }
  for (const token of normalized.split(/[^a-z0-9%+/=_-]+/i)) {
    if (token.includes("%")) {
      try {
        if (!add(decodeURIComponent(token))) break;
      } catch { /* Plain text remains available to the screen. */ }
    }
    if (token.length >= BASE64_MIN_CHARS && /^[a-z0-9+/=_-]+$/i.test(token)) {
      if (!add(Buffer.from(token, "base64").toString("utf8"))) break;
    }
  }
  if (!budgetHit) add(normalized.replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a").replace(/@/g, "a"));
  return { variants: [...variants], bytes, budgetHit };
}

function scanCopies(fold: string): string | undefined {
  const masked = mask(fold);
  const spans = benignSpans(fold);
  // Each offset names its benign occurrence, so checking a hit takes constant work.
  const benignOccurrence = new Int32Array(fold.length).fill(-1);
  spans.forEach((span, index) => benignOccurrence.fill(index, span.start, span.end));
  const scan = (source: string, removeHyphens: boolean, ignoreBenign: boolean): string | undefined => {
    const direct: string[] = [];
    const compact: string[] = [];
    const directOffsets: number[] = [];
    const compactOffsets: number[] = [];
    for (let i = 0; i < source.length; i += 1) {
      const char = source[i];
      if (removeHyphens && char === "-") continue;
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
function screen(text: string): { needle?: string; budgetHit: boolean; fold: string } {
  const normalized = text.normalize("NFKC").replace(/[\u2018\u2019\u02bc]/g, "'");
  const fold = normalized.toLowerCase();
  const { variants, budgetHit } = buildHelpVariants(normalized);
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

export function classifyIntent(intent: string): IntentClassification {
  const points = Array.from(intent);
  if (points.length > HELP_INTENT_MAX_CHARS) {
    const prefix = screen(points.slice(0, HELP_BAND_SCAN_CHARS).join(""));
    const suffix = screen(points.slice(-HELP_BAND_SCAN_CHARS).join(""));
    if (prefix.needle ?? suffix.needle) return gated((prefix.needle ?? suffix.needle)!);
    return sensitive("oversize");
  }
  const scanned = screen(intent);
  if (scanned.needle) return gated(scanned.needle);
  if (scanned.budgetHit) return sensitive("variant_budget");
  const lower = scanned.fold;
  const clauses = splitClauses(lower);
  if (clauses.length > 1 && clauses.some(clause => !MEMORY_VERBS.ordinary.test(clause))) return sensitive("multi_intent");
  // Routing reads only the received folded intent; evaluate yielding must match EVALUATE_NOUNS and EVALUATE_ROUTES in capabilities-catalog.ts.
  const evaluateRoute = EVALUATE_ROUTES.find((route) => route.matches.test(lower));
  const evaluateAnswer = (route: EvaluateRoute) => ({
    safety_class: "ordinary" as const,
    intent_class: "evaluate" as const,
    evaluate_question: route.question,
    tool: route.tool,
    example: route.example,
    why_sanctuary: route.why_sanctuary,
    guidance: route.guidance,
    related_tools: EVALUATE_RELATED_TOOLS,
  });
  if (evaluateRoute && EVALUATE_NOUNS.test(lower) && !MEMORY_VERBS.outranksEvaluateNoun.test(lower)) {
    return evaluateAnswer(evaluateRoute);
  }
  if (MEMORY_VERBS.remember.test(lower)) {
    return {
      safety_class: "ordinary",
      tool: COOPERATIVE_TOOL_NAMES.remember,
      example: { key: "user_tz", value: "America/Los_Angeles" },
      why_sanctuary: "State is encrypted, identity-bound, and audited.",
    };
  }
  if (MEMORY_VERBS.recall.test(lower)) {
    return {
      safety_class: "ordinary",
      tool: COOPERATIVE_TOOL_NAMES.recall,
      example: { key: "user_tz" },
      why_sanctuary: "Recall preserves verification status in the response.",
    };
  }
  // state_EVALUATE_FALLBACK (see the state order above the memory routes).
  if (evaluateRoute) {
    return evaluateAnswer(evaluateRoute);
  }
  return {
    safety_class: "sensitive",
    tool: null,
    example: null,
    why_sanctuary: "The request is ambiguous, so runnable guidance is suppressed.",
    remediation_class: "try_lower_scope",
    probe_key: "ambiguous",
  };
}

