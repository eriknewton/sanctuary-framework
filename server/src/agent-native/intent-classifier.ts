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

export function classifyIntent(intent: string): IntentClassification {
  const normalized = intent.normalize("NFKC");
  const lower = normalized.toLowerCase();
  const decoded = new Set<string>();
  try {
    decoded.add(decodeURIComponent(normalized).toLowerCase());
  } catch {
    // Not URL-encoded.
  }
  for (const token of normalized.split(/[^a-z0-9%+/=_-]+/i)) {
    if (token.includes("%")) {
      try {
        decoded.add(decodeURIComponent(token).toLowerCase());
      } catch {
        // Not URL-encoded.
      }
    }
    if (token.length >= 8 && /^[a-z0-9+/=_-]+$/i.test(token)) {
      try {
        decoded.add(Buffer.from(token, "base64").toString("utf8").toLowerCase());
      } catch {
        // Not base64.
      }
    }
  }
  const variants = [
    lower,
    lower.replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a").replace(/@/g, "a"),
    ...decoded,
  ];
  const haystack = variants.join(" ");
  const compactHaystack = variants.map((value) => value.replace(/[^a-z0-9:/._-]/g, "")).join(" ");
  const gated = [
    "delete",
    "forget",
    "erase",
    "wipe",
    "purge",
    "remove",
    "remove permanently",
    "removepermanently",
    "destroy",
    "shred",
    "drop",
    "export",
    "import",
    "identity bundle",
    "identitybundle",
    "private key",
    "secret key",
    "sign",
    "signature",
    "approval",
    "policy",
    "webhook",
    "callback",
    "http://",
    "https://",
    "other agent",
    "otheragent",
    "prior session",
    "priorsession",
    "widen",
  ];
  const isOrdinaryClause = (value: string): boolean => MEMORY_VERBS.ordinary.test(value);
  const clauseHasGatedNeedle = (value: string): string | undefined => {
    const compact = value.replace(/[^a-z0-9:/._-]/g, "");
    return gated.find((needle) => value.includes(needle) || compact.includes(needle));
  };
  const clauses = normalized
    .split(/\b(?:then|and|also|after|before|while)\b|[,;]+/i)
    .map((clause) => clause.toLowerCase().trim())
    .filter((clause) => clause.length > 0);
  if (clauses.length > 1) {
    for (const clause of clauses) {
      const gatedClause = clauseHasGatedNeedle(clause);
      if (gatedClause) {
        return {
          safety_class: "gated",
          tool: ["forget", "delete", "erase", "wipe", "purge", "remove", "remove permanently", "removepermanently"].some((needle) =>
            clause.includes(needle) || clause.replace(/[^a-z0-9:/._-]/g, "").includes(needle)
          ) ? COOPERATIVE_TOOL_NAMES.forget : null,
          example: { args: "<operator-approved placeholders only>" },
          why_sanctuary: "This request may need operator review before execution.",
          remediation_class: "request_review",
          probe_key: gatedClause,
        };
      }
      if (!isOrdinaryClause(clause)) {
        return {
          safety_class: "sensitive",
          tool: null,
          example: null,
          why_sanctuary: "The request is ambiguous, so runnable guidance is suppressed.",
          remediation_class: "try_lower_scope",
          probe_key: "multi_intent",
        };
      }
    }
  }
  const matchedGated = gated.find((needle) => haystack.includes(needle) || compactHaystack.includes(needle));
  if (matchedGated) {
    return {
      safety_class: "gated",
      tool: ["forget", "delete", "erase", "wipe", "purge", "remove", "remove permanently", "removepermanently"].some((needle) =>
        haystack.includes(needle) || compactHaystack.includes(needle)
      ) ? COOPERATIVE_TOOL_NAMES.forget : null,
      example: { args: "<operator-approved placeholders only>" },
      why_sanctuary: "This request may need operator review before execution.",
      remediation_class: "request_review",
      probe_key: matchedGated,
    };
  }
  // State order after the gated routes (gated always wins above):
  //   state_EVALUATE_NOUN: an evaluate noun (EVALUATE_NOUNS) beats a BARE
  //     read/get verb, so "read the bounds" is a bounds question, not a
  //     recall; any other memory verb (MEMORY_VERBS.outranksEvaluateNoun)
  //     keeps the intent on the memory routes, so "remember platform=linux"
  //     and "recall my bounds note" are never hijacked;
  //   state_REMEMBER, state_RECALL: the ordinary memory routes, with the
  //     same verb sets as before the evaluate state existed, so their
  //     responses are byte-identical;
  //   state_EVALUATE_FALLBACK: a question with no noun and no memory verb
  //     ("what do you not do") still lands on its route;
  //   otherwise the ambiguous fallback.
  // Matched on the lower-cased intent only, not the decoded haystack: the
  // decoded variants exist to catch obfuscated gated requests, and an
  // evaluate question has nothing to obfuscate. Routing table, noun list and
  // tool-name pins: capabilities-catalog.ts.
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
  if (evaluateRoute && EVALUATE_NOUNS.test(lower) && !MEMORY_VERBS.outranksEvaluateNoun.test(haystack)) {
    return evaluateAnswer(evaluateRoute);
  }
  if (MEMORY_VERBS.remember.test(haystack)) {
    return {
      safety_class: "ordinary",
      tool: COOPERATIVE_TOOL_NAMES.remember,
      example: { key: "user_tz", value: "America/Los_Angeles" },
      why_sanctuary: "State is encrypted, identity-bound, and audited.",
    };
  }
  if (MEMORY_VERBS.recall.test(haystack)) {
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

