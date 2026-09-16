/**
 * Sanctuary MCP Server, Operator Chat, Concierge Dynamic Context Router
 *
 * WP-V1.3-9 Tau-3 (criterion (c) of the v1.3 scope-lock revision). Builds
 * on Tau-1 (PR #164, concierge memory store) and Tau-2 (PR #166, multi-turn
 * coherence read-fold path). At each operator turn the concierge fetches
 * live data relevant to the operator's query and folds it into context
 * between the static Sanctuary reference and the prior-turns fold.
 *
 * Tau-4 (PR #_, criterion (d)) layers an operator-query grammar on top:
 * the caller (`operator-chat-service`) parses the query into a
 * `ParsedQuery` via `concierge-query-grammar`, threads the result into
 * `classifyQuery` + `foldContext`, and the matches carry the parsed
 * grammar through to fetchers as `FetcherHints` (time range + agent
 * names + event types). Existing fetcher implementations that do not
 * read the second argument continue to work unchanged.
 *
 * The module is intentionally pure: keyword classification + a small
 * amount of hint extraction + a fold orchestrator that calls caller-
 * provided fetchers. The wiring layer assembles the concrete fetchers
 * (templates registry, agent registry, audit log, sentinel store, etc.)
 * so this module stays test-isolatable and composable.
 *
 * Castle-walking discipline:
 * - No new outbound surface; the optional auxiliary classifier is invoked
 *   through the substrate selector by the caller (the service threads the
 *   classifier callback through, this module never owns the channel).
 * - Encryption boundaries hold for the underlying data sources; this
 *   module receives plain strings already produced inside the fortress.
 * - Failure-mode handling is fail-soft: a fetcher failure omits its
 *   category from the fold and surfaces an audit event through the
 *   caller's onFetcherFailure hook. The user-facing concierge query is
 *   never broken by a context-assembly failure.
 *
 * Out of scope here (Tau-5):
 * - Agent-context awareness (proactive folding without an explicit
 *   query). The router still routes off explicit query content only.
 */

import type { ParsedQuery } from "./concierge-query-grammar.js";

const APPROX_CHARS_PER_TOKEN = 4;

/**
 * Default token budget for the rendered dynamic-context section. The
 * static reference block + prior-turns fold + per-provider sections (recent
 * activity / wrapped agents / open inbox) sit alongside this section in the
 * final concierge prompt; the budget is per-section, not total.
 */
export const DEFAULT_DYNAMIC_CONTEXT_TOKEN_BUDGET = 2000;

/** Section header injected into the prompt when at least one category folds. */
export const DYNAMIC_CONTEXT_SECTION_HEADER = "## Live fortress context";

/**
 * Closed enum of categories the router may classify a query into. Adding
 * a category requires updating: this enum, the keyword table, the
 * fetcher interface, every wiring fetcher, and the test surface.
 */
export type ContextCategory =
  | "templates"
  | "agent_state"
  | "agent_activity"
  | "audit_log"
  | "sentinel_findings"
  | "anomaly_alerts"
  | "recent_receipts"
  | "verascore_deltas";

export const CONTEXT_CATEGORIES: readonly ContextCategory[] = [
  "templates",
  "agent_state",
  "agent_activity",
  "audit_log",
  "sentinel_findings",
  "anomaly_alerts",
  "recent_receipts",
  "verascore_deltas",
] as const;

/**
 * One category match produced by `classifyQuery`. `matched_keywords`
 * surfaces the exact phrases that hit so audit consumers and operators
 * can verify why a category fired.
 *
 * `agent_name_hint` carries a single-name extraction for back-compat
 * with Tau-3 fetcher signatures. When `query_grammar` is present and
 * resolved an agent name, `agent_name_hint` mirrors `query_grammar.agent_names[0]`.
 *
 * `query_grammar` (Tau-4) carries the full parsed query when the caller
 * supplied one. Fetchers receive the structured hints derived from it
 * via `FetcherHints`; matches expose the raw parse for consumers that
 * want the full residual or ambiguity flags.
 */
export interface CategoryMatch {
  category: ContextCategory;
  /** 0..1, higher means stronger lexical signal. */
  confidence: number;
  matched_keywords: string[];
  /** Best-effort agent-name extraction; null when no clean hint surfaces. */
  agent_name_hint: string | null;
  /** Tau-4 parsed-query attachment. Optional; absent when the caller did not parse. */
  query_grammar?: ParsedQuery | null;
}

/**
 * Structured hints passed to fetchers as the optional second argument
 * (Tau-4). Derived from `ParsedQuery` by the router; fetchers are free
 * to read or ignore individual fields. Tau-3 fetchers that take no
 * second argument continue to work because the slot is optional.
 */
export interface FetcherHints {
  /** Time range derived from the operator's query, when one resolved. */
  time_range?: { start: Date; end: Date; relative_label?: string };
  /**
   * All agent names the parser matched against the registry, in the
   * order they surfaced. Distinct from the `agentNameHint` first arg
   * (which carries only the first match for back-compat).
   */
  agent_names?: readonly string[];
  /**
   * Event-type names the parser matched against the canonical audit-
   * event-class enumeration. Already filtered to the closed set.
   */
  event_types?: readonly string[];
}

/**
 * Caller-supplied data sources. Each fetcher returns plain text the
 * router stitches into the rendered section. Returning the empty string
 * (or whitespace only) is treated as "nothing to fold for this category"
 * and the category drops out of the final categoriesIncluded list.
 *
 * Tau-4 extends every fetcher with an optional `hints?: FetcherHints`
 * argument carrying the parsed-query attachments (time range, agent
 * names, event types). Fetchers that ignore the argument continue to
 * compile; fetchers that consume it can scope queries against the
 * audit log, activity feed, etc., to the operator's stated window.
 */
export interface ContextFetchers {
  templates: (hints?: FetcherHints) => Promise<string>;
  agent_state: (
    agentNameHint: string | null,
    hints?: FetcherHints,
  ) => Promise<string>;
  agent_activity: (
    agentNameHint: string | null,
    hints?: FetcherHints,
  ) => Promise<string>;
  audit_log: (hints?: FetcherHints) => Promise<string>;
  sentinel_findings: (hints?: FetcherHints) => Promise<string>;
  anomaly_alerts: (hints?: FetcherHints) => Promise<string>;
  recent_receipts: (hints?: FetcherHints) => Promise<string>;
  verascore_deltas: (hints?: FetcherHints) => Promise<string>;
}

/**
 * Auxiliary classifier the caller may supply for the LLM-assist fallback
 * path. Invoked only when keyword classification returns zero matches
 * AND the query is non-trivial (>= 8 chars, not a clear greeting).
 */
export type LlmAssistClassifier = (
  query: string,
  categories: readonly ContextCategory[],
) => Promise<ContextCategory | "none">;

export interface FoldContextOptions {
  /** Token budget for the rendered section; defaults to DEFAULT_DYNAMIC_CONTEXT_TOKEN_BUDGET. */
  maxTokens?: number;
  /** When set, invoked on zero keyword matches to ask an LLM. */
  llmAssistClassify?: LlmAssistClassifier;
  /** Audit hook for fetcher failures; receives the category + error. */
  onFetcherFailure?: (category: ContextCategory, error: unknown) => void;
  /**
   * Tau-4: pre-parsed operator query. When present, every match attaches
   * the parse, the agent_name_hint is overridden by the parser's first
   * `agent_names` entry when non-empty, and fetchers receive the
   * structured `FetcherHints` derived from the parse.
   */
  parsed?: ParsedQuery | null;
}

export interface FoldContextResult {
  /** Rendered section, or empty string when nothing folded. */
  section: string;
  /** Categories whose data made it into the final rendered section. */
  categoriesIncluded: ContextCategory[];
}

interface CategoryKeywordSpec {
  category: ContextCategory;
  /** Word-boundary regex patterns; case-insensitive. */
  patterns: { source: string; phrase: string }[];
}

/**
 * Build a word-boundary regex from a phrase. Multi-word phrases use
 * `\s+` between words. Wrap with `\b` so "log" does not match "login"
 * and "score" does not match "scoreboard".
 */
function phrasePattern(phrase: string): { source: string; phrase: string } {
  const escaped = phrase
    .toLowerCase()
    .split(/\s+/)
    .map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("\\s+");
  return { source: `\\b${escaped}\\b`, phrase };
}

/**
 * Keyword route table. Phrases are matched case-insensitive with word
 * boundaries. Multi-word phrases ("channel templates") count as one
 * match. Each category's confidence scales with the number of matched
 * keywords.
 */
const CATEGORY_KEYWORDS: CategoryKeywordSpec[] = [
  {
    category: "templates",
    patterns: [
      "templates",
      "template",
      "channel templates",
      "channel template",
      "list templates",
      "available templates",
      "what templates",
    ].map(phrasePattern),
  },
  {
    category: "agent_state",
    patterns: [
      "state",
      "status",
      "agent state",
      "agent status",
      "status of agent",
      "status of agents",
      "state of",
      "doing",
    ].map(phrasePattern),
  },
  {
    category: "agent_activity",
    patterns: [
      "activity",
      "agent activity",
      "what did",
      "recent activity",
    ].map(phrasePattern),
  },
  {
    category: "audit_log",
    patterns: [
      "audit log",
      "audit",
      "log entry",
      "log entries",
      "what happened",
      "show me events",
      "event class",
    ].map(phrasePattern),
  },
  {
    category: "sentinel_findings",
    patterns: [
      "sentinel",
      "sentinels",
      "warning",
      "warnings",
      "alert",
      "alerts",
      "whats wrong",
      "what's wrong",
      "findings",
    ].map(phrasePattern),
  },
  {
    category: "anomaly_alerts",
    patterns: [
      "anomaly",
      "anomalies",
      "spike",
      "unusual",
      "outlier",
    ].map(phrasePattern),
  },
  {
    category: "recent_receipts",
    patterns: [
      "receipt",
      "receipts",
      "concordia",
      "commitment",
      "commitments",
      "chain",
      "chains",
    ].map(phrasePattern),
  },
  {
    category: "verascore_deltas",
    patterns: [
      "verascore",
      "vera score",
      "trust score",
      "reputation",
    ].map(phrasePattern),
  },
];

/**
 * Best-effort agent-name hint extractor. Looks for `agent <name>`,
 * quoted names, or capitalized identifiers near the verb. Tau-3 keeps
 * this intentionally narrow; the full operator-query grammar lands in
 * Tau-4. Returns null when no clean hint surfaces.
 */
function extractAgentNameHint(query: string): string | null {
  const agentPattern = /\bagent\s+["']?([A-Za-z][\w-]{0,40})["']?/i;
  const m = query.match(agentPattern);
  if (m && m[1]) return m[1];
  const quoted = query.match(/["']([A-Za-z][\w-]{0,40})["']/);
  if (quoted && quoted[1]) return quoted[1];
  return null;
}

/**
 * Heuristic for whether a query is "trivial" (not worth invoking the
 * auxiliary LLM classifier on). Keeps short greetings and one-word
 * pings out of the LLM-assist path. Coordinator-CTO bake: 8 chars min,
 * known-greeting bypass, no LLM for empty / whitespace.
 */
const TRIVIAL_GREETINGS = new Set([
  "hi",
  "hello",
  "hey",
  "yo",
  "ok",
  "thanks",
  "thx",
  "thank you",
]);
function isTrivialQuery(query: string): boolean {
  const norm = query.trim().toLowerCase();
  if (norm.length === 0) return true;
  if (norm.length < 8) return true;
  return TRIVIAL_GREETINGS.has(norm);
}

/**
 * Classify the operator's query against the 8-category route table.
 * Returns 0..N matches ordered by descending confidence, then by
 * categories' enum order to stabilize ranking.
 *
 * Tau-4: when `parsedGrammar` is supplied, every match attaches the
 * parse, and `agent_name_hint` for `agent_state` / `agent_activity`
 * prefers the parser's first registered agent name (falling back to
 * the local single-name extractor when the parser found nothing).
 */
export function classifyQuery(
  query: string,
  parsedGrammar?: ParsedQuery | null,
): CategoryMatch[] {
  const normalized = query.toLowerCase();
  const matches: CategoryMatch[] = [];
  const grammarAgent =
    parsedGrammar && parsedGrammar.agent_names.length > 0
      ? parsedGrammar.agent_names[0] ?? null
      : null;

  for (const spec of CATEGORY_KEYWORDS) {
    const matchedPhrases: string[] = [];
    for (const pattern of spec.patterns) {
      if (matchedPhrases.includes(pattern.phrase)) continue;
      const re = new RegExp(pattern.source, "i");
      if (re.test(normalized)) {
        matchedPhrases.push(pattern.phrase);
      }
    }
    if (matchedPhrases.length === 0) continue;

    const confidence = Math.min(1.0, 0.4 + 0.3 * matchedPhrases.length);

    const wantsAgentHint =
      spec.category === "agent_state" || spec.category === "agent_activity";
    const agent_name_hint = wantsAgentHint
      ? grammarAgent ?? extractAgentNameHint(query)
      : null;

    matches.push({
      category: spec.category,
      confidence,
      matched_keywords: matchedPhrases,
      agent_name_hint,
      ...(parsedGrammar !== undefined ? { query_grammar: parsedGrammar } : {}),
    });
  }

  matches.sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    return (
      CONTEXT_CATEGORIES.indexOf(a.category) -
      CONTEXT_CATEGORIES.indexOf(b.category)
    );
  });

  return matches;
}

/**
 * Build a `FetcherHints` object from a parsed query. Returns `undefined`
 * (not an empty object) when the parse contributed no resolvable fields,
 * so fetchers see a missing arg rather than a hints object full of
 * absent fields.
 */
export function fetcherHintsFromGrammar(
  parsed: ParsedQuery | null | undefined,
): FetcherHints | undefined {
  if (!parsed) return undefined;
  const hasTime = parsed.time_range !== null;
  const hasAgents = parsed.agent_names.length > 0;
  const hasEvents = parsed.event_types.length > 0;
  if (!hasTime && !hasAgents && !hasEvents) return undefined;

  const hints: FetcherHints = {};
  if (parsed.time_range) {
    const range = parsed.time_range;
    hints.time_range = {
      start: range.start,
      end: range.end,
      ...(range.relative_label !== undefined
        ? { relative_label: range.relative_label }
        : {}),
    };
  }
  if (hasAgents) hints.agent_names = parsed.agent_names;
  if (hasEvents) hints.event_types = parsed.event_types;
  return hints;
}

function approxTokenLen(text: string): number {
  return Math.ceil(text.length / APPROX_CHARS_PER_TOKEN);
}

const CATEGORY_LABELS: Record<ContextCategory, string> = {
  templates: "Templates",
  agent_state: "Agent state",
  agent_activity: "Agent activity",
  audit_log: "Audit log",
  sentinel_findings: "Sentinel findings",
  anomaly_alerts: "Anomaly alerts",
  recent_receipts: "Recent receipts",
  verascore_deltas: "Verascore deltas",
};

interface FetchAttempt {
  category: ContextCategory;
  text: string;
}

async function runFetcher(
  match: CategoryMatch,
  fetchers: ContextFetchers,
  hints: FetcherHints | undefined,
): Promise<string> {
  switch (match.category) {
    case "templates":
      return fetchers.templates(hints);
    case "agent_state":
      return fetchers.agent_state(match.agent_name_hint, hints);
    case "agent_activity":
      return fetchers.agent_activity(match.agent_name_hint, hints);
    case "audit_log":
      return fetchers.audit_log(hints);
    case "sentinel_findings":
      return fetchers.sentinel_findings(hints);
    case "anomaly_alerts":
      return fetchers.anomaly_alerts(hints);
    case "recent_receipts":
      return fetchers.recent_receipts(hints);
    case "verascore_deltas":
      return fetchers.verascore_deltas(hints);
  }
}

function trivialMatch(
  category: ContextCategory,
  parsedGrammar?: ParsedQuery | null,
): CategoryMatch {
  return {
    category,
    confidence: 0.5,
    matched_keywords: ["llm-assist"],
    agent_name_hint:
      parsedGrammar && parsedGrammar.agent_names.length > 0
        ? parsedGrammar.agent_names[0] ?? null
        : null,
    ...(parsedGrammar !== undefined ? { query_grammar: parsedGrammar } : {}),
  };
}

/**
 * Build the dynamic-context section. Pure modulo the I/O the caller
 * provides through the fetchers + optional classifier hooks.
 *
 * Algorithm:
 * 1. Run keyword classification.
 * 2. If zero matches and the query is non-trivial and an auxiliary
 *    classifier is provided, invoke it. Treat its non-"none" result as
 *    a single-category match with confidence 0.5.
 * 3. For each match (descending confidence), invoke the fetcher. On
 *    error, call onFetcherFailure and skip the category.
 * 4. Render the surviving fetched sections into one block, dropping
 *    lower-confidence categories first when the rendered block exceeds
 *    the token budget. Always retain the highest-confidence category
 *    that produced any text (even if it alone exceeds the budget; in
 *    that case the section is included raw, the caller decides whether
 *    to truncate further upstream).
 */
export async function foldContext(
  query: string,
  fetchers: ContextFetchers,
  opts?: FoldContextOptions,
): Promise<FoldContextResult> {
  const budget = opts?.maxTokens ?? DEFAULT_DYNAMIC_CONTEXT_TOKEN_BUDGET;
  const parsed = opts?.parsed ?? null;
  const hints = fetcherHintsFromGrammar(parsed);

  let matches = classifyQuery(query, parsed);

  if (matches.length === 0 && !isTrivialQuery(query) && opts?.llmAssistClassify) {
    try {
      const picked = await opts.llmAssistClassify(query, CONTEXT_CATEGORIES);
      if (picked !== "none" && CONTEXT_CATEGORIES.includes(picked)) {
        matches = [trivialMatch(picked, parsed)];
      }
    } catch {
      // LLM-assist failure is non-fatal; fall through with no matches.
    }
  }

  if (matches.length === 0) {
    return { section: "", categoriesIncluded: [] };
  }

  const attempts: FetchAttempt[] = [];
  for (const match of matches) {
    try {
      const text = await runFetcher(match, fetchers, hints);
      const trimmed = text.trim();
      if (trimmed.length > 0) {
        attempts.push({ category: match.category, text: trimmed });
      }
    } catch (err) {
      opts?.onFetcherFailure?.(match.category, err);
    }
  }

  if (attempts.length === 0) {
    return { section: "", categoriesIncluded: [] };
  }

  const headerTokens = approxTokenLen(`${DYNAMIC_CONTEXT_SECTION_HEADER}\n`);
  const sepTokens = approxTokenLen("\n\n");
  let runningTokens = headerTokens;
  const kept: FetchAttempt[] = [];

  for (const attempt of attempts) {
    const block = `### ${CATEGORY_LABELS[attempt.category]}\n${attempt.text}`;
    const tokens = approxTokenLen(block) + (kept.length > 0 ? sepTokens : 0);
    if (kept.length === 0) {
      kept.push(attempt);
      runningTokens += tokens;
      continue;
    }
    if (runningTokens + tokens > budget) break;
    kept.push(attempt);
    runningTokens += tokens;
  }

  const blocks = kept.map(
    (k) => `### ${CATEGORY_LABELS[k.category]}\n${k.text}`,
  );
  const section = `${DYNAMIC_CONTEXT_SECTION_HEADER}\n${blocks.join("\n\n")}`;
  return {
    section,
    categoriesIncluded: kept.map((k) => k.category),
  };
}

/**
 * Test-only export of the trivial-query helper so the LLM-assist
 * gating tests do not have to duplicate the rule.
 */
export const __testing = { isTrivialQuery, extractAgentNameHint };
