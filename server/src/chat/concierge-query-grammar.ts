/**
 * Sanctuary MCP Server, Operator Chat, Concierge Query Grammar
 *
 * WP-V1.3-9 Tau-4 (criterion (d) of the v1.3 scope-lock revision). Builds
 * on Tau-3 (PR #171, dynamic context router). The grammar layer parses
 * operator queries into structured parameters: time ranges, agent names,
 * event types, and a free-form intent residual. Tau-3 fetchers receive
 * the parsed hints alongside the query so the substrate sees the most
 * relevant data slice.
 *
 * The module is pure: rule-based extraction, no I/O, no clock side
 * effects beyond the optional `now` parameter for deterministic tests.
 * The optional LLM-assist fallback is invoked by the caller when the
 * rule-based parser produces low confidence.
 *
 * Castle-walking discipline:
 * - No new outbound surface; the LLM-assist fallback routes through the
 *   substrate selector at the same `concierge` surface Tau-3 already
 *   uses.
 * - Encryption boundaries hold: this module receives plain strings
 *   already produced inside the fortress.
 * - Failure-mode handling is fail-soft: low-confidence parses surface a
 *   structured fallback menu so the operator sees what the concierge
 *   can answer, never a silent drop.
 *
 * Privacy invariant:
 * The runtime `ParsedQuery` carries `intent_phrase` (free-form residual
 * pulled from the operator's query) for the router's own consumption.
 * The audit emission MUST NOT include `intent_phrase`; consumers serialize
 * via `auditSafeSummary()` which strips it. See `OperatorConciergeChatPayload`
 * safe-metadata invariant in `contracts/v1.2/operator-chat-events.ts`.
 *
 * Out of scope here (Tau-5 + later):
 * - Agent-context awareness (proactive parsing without an explicit
 *   query). Tau-4 parses off explicit query content only.
 * - Voice input or natural-language-as-API surface (defer to v1.5+).
 * - Cross-fortress concierge query (defer to v1.4 cross-tenant scope).
 * - Window markers like "around the time of <event>" that require an
 *   audit-log lookup to resolve. Tau-4 ships static patterns only.
 */

import {
  COMPOSITION_EVENT_TYPES,
  type CompositionEventType,
} from "../composition/constants.js";
import { OPERATOR_CHAT_OPS } from "./operator-chat-audit-events.js";

// ── Public types ─────────────────────────────────────────────────────────

/**
 * A resolved time range. `relative_label` carries the original token
 * ("yesterday", "past hour", etc.) when the range was derived from a
 * relative pattern, so consumers can render operator-readable copy.
 */
export interface ParsedTimeRange {
  start: Date;
  end: Date;
  relative_label?: string;
}

/**
 * Stable structured-failure flags surfaced when the parser cannot
 * resolve a token confidently. The strings are enum-like (no free text)
 * so the audit emission stays safe-metadata-only and the dashboard can
 * group by cause.
 */
export type AmbiguityFlag =
  | "unknown_time_token"
  | "unknown_agent_token"
  | "unknown_event_token"
  | "ambiguous_time_range"
  | "no_signal_extracted";

/**
 * Runtime parsed-query shape. Used by the router to thread parameters
 * into context fetchers, and by the structured-fallback menu builder.
 *
 * `intent_phrase` is the residual after time/agent/event tokens are
 * stripped, useful for router-level intent routing. It carries operator
 * query content and MUST NOT be serialized into the audit log.
 */
export interface ParsedQuery {
  time_range: ParsedTimeRange | null;
  agent_names: string[];
  event_types: string[];
  intent_phrase: string;
  ambiguity_flags: AmbiguityFlag[];
  /** 0..1; 1.0 = every component resolved cleanly. */
  parse_confidence: number;
}

/**
 * Audit-safe projection of `ParsedQuery`. Drops `intent_phrase` (carries
 * raw query content) and serializes Dates as ISO strings. This is the
 * shape that lands in `OperatorConciergeChatPayload.parsed_grammar`.
 */
export interface ParsedQueryAuditSummary {
  time_range:
    | { start_iso: string; end_iso: string; relative_label?: string }
    | null;
  agent_names: string[];
  event_types: string[];
  ambiguity_flags: AmbiguityFlag[];
  parse_confidence: number;
}

/**
 * Read-only registry view consumed by `parseQuery` for agent-name
 * extraction. The grammar matches operator query tokens against the
 * `agent_id` field of each record (case-insensitive, prefix-or-exact).
 *
 * Wired from `HubAgentRegistrySource.list()` at the service layer; tests
 * can hand a literal array. Both shapes are accepted so callers do not
 * have to wrap a hub registry in an adapter just to feed the parser.
 */
export type AgentRegistryView =
  | readonly { agent_id: string }[]
  | { list: () => readonly { agent_id: string }[] };

/**
 * Optional LLM-assist completion. Invoked by `parseQueryWithLlmAssist`
 * when the rule-based parse confidence is below `LLM_ASSIST_THRESHOLD`.
 * The classifier sees the query plus the partial parse and may return
 * `null` (no completion) or a partial-shape patch the caller merges.
 *
 * The runtime caller (operator-chat-service) MUST route this through
 * the substrate selector at the `concierge` surface so no new outbound
 * channel opens. See Castle-walking discipline at the top of the file.
 */
export type LlmAssistGrammarCompletion = (
  query: string,
  partial: ParsedQuery,
) => Promise<Partial<{
  time_range: ParsedTimeRange;
  agent_names: string[];
  event_types: string[];
}> | null>;

export interface ParseQueryOptions {
  registry?: AgentRegistryView;
  /**
   * Closed-set audit event-class enum. Defaults to
   * `CANONICAL_AUDIT_EVENT_CLASSES`. Callers may pass a narrower set
   * (e.g., the hub events list) when the surface only consults a subset.
   */
  eventClassEnum?: readonly string[];
  /**
   * Deterministic clock for tests. Defaults to `new Date()` per-call.
   * The parser captures `now` once, so multi-token resolution is
   * internally consistent.
   */
  now?: Date;
}

// ── Canonical audit-event-class enumeration ──────────────────────────────

/**
 * Canonical audit-event-class enumeration the grammar matches against.
 *
 * Source-of-truth pulls:
 * - `composition/constants.ts` `COMPOSITION_EVENT_TYPES` (composition_*).
 * - `chat/operator-chat-audit-events.ts` `OPERATOR_CHAT_OPS` (operator_concierge_*).
 *
 * Hand-curated additions: the high-traffic operator-relevant event
 * classes from the broader audit surface (`policy_change`, the Tier 1
 * lifecycle ops, `cross_harness_approval_*`, exit-bundle ops). The full
 * audit surface has ~55 distinct operation strings; the grammar only
 * surfaces the ones an operator is likely to ask about by name.
 *
 * Adding an entry here requires no Tau-4 migration; the grammar treats
 * the enum as data. Callers can always pass a custom `eventClassEnum`.
 */
export const CANONICAL_AUDIT_EVENT_CLASSES = [
  // Lifecycle / policy
  "policy_change",
  "approval_request",
  "audit_truncate",
  "lockdown",
  "unwrap",

  // Exit bundle (Tier 1)
  "exit_bundle_export",
  "exit_bundle_import_activate",
  "exit_bundle_rekey",

  // Cross-harness approval aggregator
  "cross_harness_approval_aggregated",
  "cross_harness_approval_resolved",
  "cross_harness_approval_deduped",
  "cross_harness_approval_payload_decrypted",
  "cross_harness_approval_audit_trail_viewed",
  "cross_harness_approval_replayed",

  // Composition (full set from constants.ts)
  ...COMPOSITION_EVENT_TYPES,

  // Operator chat / concierge (full set from OPERATOR_CHAT_OPS)
  OPERATOR_CHAT_OPS.CONCIERGE_CHAT,
  OPERATOR_CHAT_OPS.AGENT_INSPECT_PANEL_OPENED,
  OPERATOR_CHAT_OPS.CONCIERGE_HISTORY_READ,
  OPERATOR_CHAT_OPS.CONCIERGE_THREAD_DELETED,
  OPERATOR_CHAT_OPS.CONCIERGE_MEMORY_READ_FAILED,
  OPERATOR_CHAT_OPS.CONCIERGE_CONTEXT_FETCHER_FAILED,

  // Bridge / commitment
  "bridge_commit",
  "bridge_verify",
  "bridge_attest",
  "proof_commitment",
  "proof_reveal",

  // Reputation
  "reputation_export",
  "reputation_import",
  "reputation_publish",
  "reputation_record",
  "reputation_query",
] as const;

export type CanonicalAuditEventClass =
  | (typeof CANONICAL_AUDIT_EVENT_CLASSES)[number]
  | CompositionEventType;

/**
 * Synonym map: operator-friendly phrasing on the left, canonical event
 * names on the right. Multi-word phrases match case-insensitive with
 * word boundaries. One synonym may resolve to multiple canonical names
 * (e.g., "approvals" surfaces both the Tier 1 request and the cross-
 * harness aggregator events).
 */
const EVENT_SYNONYMS: { phrase: string; canonical: readonly string[] }[] = [
  { phrase: "approvals", canonical: ["approval_request", "cross_harness_approval_aggregated", "cross_harness_approval_resolved"] },
  { phrase: "approval", canonical: ["approval_request"] },
  { phrase: "policy changes", canonical: ["policy_change"] },
  { phrase: "policy change", canonical: ["policy_change"] },
  { phrase: "policy edits", canonical: ["policy_change"] },
  { phrase: "lockdowns", canonical: ["lockdown"] },
  { phrase: "exit bundles", canonical: ["exit_bundle_export", "exit_bundle_import_activate"] },
  { phrase: "exit bundle", canonical: ["exit_bundle_export"] },
  { phrase: "audit truncations", canonical: ["audit_truncate"] },
  { phrase: "audit truncation", canonical: ["audit_truncate"] },
  { phrase: "compositions", canonical: ["composition_receipt_packed", "composition_receipt_verified"] },
  { phrase: "receipts", canonical: ["composition_receipt_packed", "composition_receipt_verified"] },
  { phrase: "receipt verifications", canonical: ["composition_receipt_verified"] },
  { phrase: "concierge chats", canonical: [OPERATOR_CHAT_OPS.CONCIERGE_CHAT] },
  { phrase: "cross harness approvals", canonical: ["cross_harness_approval_aggregated", "cross_harness_approval_resolved"] },
];

// ── Time-range parsing ───────────────────────────────────────────────────

const MS_PER_HOUR = 60 * 60 * 1000;
const MS_PER_DAY = 24 * MS_PER_HOUR;

const NUMBER_WORDS: Record<string, number> = {
  a: 1,
  an: 1,
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
  twelve: 12,
  twentyfour: 24,
};

interface TimeMatch {
  range: ParsedTimeRange;
  /** The literal substring matched, used to strip the residual phrase. */
  matchedSubstring: string;
}

/**
 * Resolve a relative or absolute time-range token. Returns null when no
 * pattern matched. Stable order: from/to ranges, since-X ranges, then
 * single-token relatives, then ISO dates.
 */
function resolveTimeRange(query: string, now: Date): TimeMatch | null {
  const normalized = query.trim();
  const lower = normalized.toLowerCase();

  // (1) "from X to Y" / "between X and Y"
  const fromTo = lower.match(
    /\b(?:from|between)\s+(.+?)\s+(?:to|and|-|until)\s+([\w:.\-+t /]+)/i,
  );
  if (fromTo) {
    const aSlice = fromTo[1];
    const bSlice = fromTo[2];
    if (aSlice !== undefined && bSlice !== undefined) {
      const a = parseInstant(aSlice, now);
      const b = parseInstant(bSlice, now);
      if (a && b) {
        const start = a.getTime() <= b.getTime() ? a : b;
        const end = a.getTime() <= b.getTime() ? b : a;
        return {
          range: { start, end },
          matchedSubstring: fromTo[0],
        };
      }
    }
  }

  // (2) "since X"
  const sinceMatch = lower.match(/\bsince\s+([\w:.\-+t /]+)/i);
  if (sinceMatch) {
    const slice = sinceMatch[1];
    if (slice !== undefined) {
      const start = parseInstant(slice, now);
      if (start) {
        return {
          range: { start, end: now },
          matchedSubstring: sinceMatch[0],
        };
      }
    }
  }

  // (3) "yesterday"
  if (/\byesterday\b/.test(lower)) {
    const startOfToday = startOfDay(now);
    const start = new Date(startOfToday.getTime() - MS_PER_DAY);
    const end = new Date(startOfToday.getTime() - 1);
    return {
      range: { start, end, relative_label: "yesterday" },
      matchedSubstring: "yesterday",
    };
  }

  // (4) "today"
  if (/\btoday\b/.test(lower)) {
    return {
      range: {
        start: startOfDay(now),
        end: now,
        relative_label: "today",
      },
      matchedSubstring: "today",
    };
  }

  // (5a) "last 24h" / "last Nh" compact form. Checked BEFORE the
  // general "past/last N hours" pattern so the compact relative_label
  // (e.g., "last 24h") is preserved instead of being normalized to
  // "past 24 hours".
  const compactHours = lower.match(/\blast\s+(\d+)\s*h\b/i);
  if (compactHours) {
    const tok = compactHours[1];
    if (tok !== undefined) {
      const n = Number.parseInt(tok, 10);
      if (Number.isFinite(n) && n > 0) {
        const start = new Date(now.getTime() - n * MS_PER_HOUR);
        return {
          range: { start, end: now, relative_label: `last ${n}h` },
          matchedSubstring: compactHours[0],
        };
      }
    }
  }

  // (5b) "past/last N hours" or "past/last hour"
  const hoursMatch = lower.match(
    /\b(?:past|last)\s+([\w]+|\d+)\s*(?:hr\b|hrs\b|hour|hours)/i,
  );
  if (hoursMatch) {
    const tok = hoursMatch[1];
    if (tok !== undefined) {
      const n = parseCount(tok);
      if (n !== null && n > 0) {
        const start = new Date(now.getTime() - n * MS_PER_HOUR);
        return {
          range: { start, end: now, relative_label: `past ${n} hour${n === 1 ? "" : "s"}` },
          matchedSubstring: hoursMatch[0],
        };
      }
    }
  }
  if (/\b(?:past|last)\s+hour\b/.test(lower)) {
    const start = new Date(now.getTime() - MS_PER_HOUR);
    return {
      range: { start, end: now, relative_label: "past hour" },
      matchedSubstring: lower.match(/\b(?:past|last)\s+hour\b/i)![0],
    };
  }

  // (6) "past/last N days" or "past/last day"
  const daysMatch = lower.match(
    /\b(?:past|last)\s+([\w]+|\d+)\s*(?:d\b|day|days)/i,
  );
  if (daysMatch) {
    const tok = daysMatch[1];
    if (tok !== undefined) {
      const n = parseCount(tok);
      if (n !== null && n > 0) {
        const start = new Date(now.getTime() - n * MS_PER_DAY);
        return {
          range: { start, end: now, relative_label: `past ${n} day${n === 1 ? "" : "s"}` },
          matchedSubstring: daysMatch[0],
        };
      }
    }
  }
  if (/\b(?:past|last)\s+day\b/.test(lower)) {
    const start = new Date(now.getTime() - MS_PER_DAY);
    return {
      range: { start, end: now, relative_label: "past day" },
      matchedSubstring: lower.match(/\b(?:past|last)\s+day\b/i)![0],
    };
  }

  // (7) "this week"
  if (/\bthis\s+week\b/.test(lower)) {
    const start = startOfWeek(now);
    return {
      range: { start, end: now, relative_label: "this week" },
      matchedSubstring: lower.match(/\bthis\s+week\b/i)![0],
    };
  }

  // (8) "past/last week"
  if (/\b(?:past|last)\s+week\b/.test(lower)) {
    const start = new Date(now.getTime() - 7 * MS_PER_DAY);
    return {
      range: { start, end: now, relative_label: "past week" },
      matchedSubstring: lower.match(/\b(?:past|last)\s+week\b/i)![0],
    };
  }

  // (9) ISO date / datetime as a standalone token
  // Matches YYYY-MM-DD, YYYY-MM-DDTHH:MM, YYYY-MM-DD HH:MM
  const isoMatch = normalized.match(
    /\b(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?)\b/,
  );
  if (isoMatch) {
    const tok = isoMatch[1];
    if (tok !== undefined) {
      const parsed = parseInstant(tok, now);
      if (parsed) {
        const isDateOnly = /^\d{4}-\d{2}-\d{2}$/.test(tok);
        if (isDateOnly) {
          return {
            range: {
              start: parsed,
              end: new Date(parsed.getTime() + MS_PER_DAY - 1),
            },
            matchedSubstring: tok,
          };
        }
        // Datetime: ±30min window.
        return {
          range: {
            start: new Date(parsed.getTime() - 30 * 60 * 1000),
            end: new Date(parsed.getTime() + 30 * 60 * 1000),
          },
          matchedSubstring: tok,
        };
      }
    }
  }

  return null;
}

/**
 * Best-effort instant parser. Accepts ISO strings the JS Date constructor
 * recognizes plus a few relative tokens. Returns null on miss.
 */
function parseInstant(token: string, now: Date): Date | null {
  const trimmed = token.trim().replace(/[,.!?;]+$/g, "");
  if (!trimmed) return null;
  const lower = trimmed.toLowerCase();

  if (lower === "now") return now;
  if (lower === "today") return startOfDay(now);
  if (lower === "yesterday") {
    return new Date(startOfDay(now).getTime() - MS_PER_DAY);
  }

  // ISO date or datetime via Date constructor.
  const isoLike = trimmed.replace(" ", "T");
  const parsed = new Date(isoLike);
  if (!Number.isNaN(parsed.getTime())) return parsed;

  return null;
}

function parseCount(token: string): number | null {
  const lower = token.toLowerCase();
  if (/^\d+$/.test(lower)) {
    const n = Number.parseInt(lower, 10);
    return Number.isFinite(n) ? n : null;
  }
  return NUMBER_WORDS[lower] ?? null;
}

function startOfDay(d: Date): Date {
  const out = new Date(d);
  out.setHours(0, 0, 0, 0);
  return out;
}

/**
 * Start of the operator's current week, defined as the most recent
 * Monday at 00:00 local. Sanctuary domain uses Monday as week-start
 * across audit-log digests so this aligns with the dashboard view.
 */
function startOfWeek(d: Date): Date {
  const out = startOfDay(d);
  const dayOfWeek = out.getDay(); // 0=Sun, 1=Mon, ..., 6=Sat
  const offsetToMonday = (dayOfWeek + 6) % 7;
  out.setDate(out.getDate() - offsetToMonday);
  return out;
}

// ── Agent-name extraction ────────────────────────────────────────────────

function listFromRegistry(
  registry: AgentRegistryView | undefined,
): readonly { agent_id: string }[] {
  if (!registry) return [];
  if (Array.isArray(registry)) return registry;
  if (typeof (registry as { list?: unknown }).list === "function") {
    return (registry as { list: () => readonly { agent_id: string }[] }).list();
  }
  return [];
}

/**
 * Tokenize the query into word-boundary segments and slide a registry
 * matcher across them. Returns the deduplicated, original-cased
 * registry agent_ids that surfaced.
 *
 * Match rule: case-insensitive prefix match against `agent_id`, requires
 * the query token to be at least 3 chars (so "a" / "ai" do not match
 * "AgentX"). Whole-word match preferred when both prefix and exact are
 * present.
 *
 * Multi-token names: registry agent_ids may contain hyphens or
 * underscores ("data-miner", "leak_timeline"). The matcher walks the
 * normalized agent_id without separators to allow operator queries like
 * "data miner" to land on "data-miner".
 */
function extractAgentNames(
  query: string,
  registry: AgentRegistryView | undefined,
): { matched: string[]; flagged: boolean } {
  const records = listFromRegistry(registry);
  if (records.length === 0) return { matched: [], flagged: false };

  const lowerQuery = query.toLowerCase();
  const compactQuery = lowerQuery.replace(/[\s_-]+/g, "");
  const matched: string[] = [];
  const seen = new Set<string>();

  for (const rec of records) {
    const id = rec.agent_id;
    if (!id || seen.has(id)) continue;
    const idLower = id.toLowerCase();
    if (idLower.length < 3) continue;
    const idCompact = idLower.replace(/[\s_-]+/g, "");

    const wordRe = new RegExp(
      `\\b${idLower.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`,
      "i",
    );
    if (wordRe.test(query)) {
      matched.push(id);
      seen.add(id);
      continue;
    }
    if (idCompact.length >= 4 && compactQuery.includes(idCompact)) {
      matched.push(id);
      seen.add(id);
    }
  }

  // Flag when the operator typed `agent <NAME>` but no registry hit
  // surfaced (an unknown agent name was mentioned).
  const agentMention = lowerQuery.match(/\bagent\s+([a-z0-9_-]{3,40})/i);
  const flagged =
    matched.length === 0 &&
    agentMention !== null &&
    agentMention[1] !== undefined &&
    !records.some((r) => r.agent_id.toLowerCase() === agentMention[1]?.toLowerCase());

  return { matched, flagged };
}

// ── Event-type extraction ────────────────────────────────────────────────

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractEventTypes(
  query: string,
  enumValues: readonly string[],
): { matched: string[]; flagged: boolean } {
  const lower = query.toLowerCase();
  const matched: string[] = [];
  const seen = new Set<string>();

  // (1) Direct match against the enum values themselves (operators
  // sometimes paste exact event-class names like "policy_change").
  for (const ev of enumValues) {
    if (seen.has(ev)) continue;
    const re = new RegExp(`\\b${escapeRegex(ev)}\\b`, "i");
    if (re.test(query)) {
      matched.push(ev);
      seen.add(ev);
    }
  }

  // (2) Synonyms map.
  for (const syn of EVENT_SYNONYMS) {
    const re = new RegExp(
      `\\b${syn.phrase.split(/\s+/).map(escapeRegex).join("\\s+")}\\b`,
      "i",
    );
    if (re.test(query)) {
      for (const c of syn.canonical) {
        if (seen.has(c)) continue;
        if (!enumValues.includes(c)) continue;
        matched.push(c);
        seen.add(c);
      }
    }
  }

  // (3) Glob-style `composition_*`, `cross_harness_approval_*`
  const globMatches = lower.match(/\b([a-z_]+)_\*/g) ?? [];
  for (const glob of globMatches) {
    const prefix = glob.slice(0, -2);
    for (const ev of enumValues) {
      if (seen.has(ev)) continue;
      if (ev.startsWith(prefix)) {
        matched.push(ev);
        seen.add(ev);
      }
    }
  }

  // Operator typed "the X events" / "show me Y events" but nothing
  // surfaced. Flag for ambiguity surface.
  const eventNounMention =
    /\b(?:event|events|class|classes)\b/i.test(query) && matched.length === 0;
  return { matched, flagged: eventNounMention };
}

// ── Intent residual + confidence ─────────────────────────────────────────

/**
 * Strip resolved tokens from the original query and collapse whitespace
 * to produce the free-form intent residual. The router uses this for
 * downstream intent routing (e.g., inferring whether the operator wants
 * a digest vs. a list vs. a count). Audit emission MUST drop this field.
 */
function deriveIntentPhrase(query: string, stripTokens: string[]): string {
  let out = query;
  for (const tok of stripTokens) {
    if (!tok) continue;
    const re = new RegExp(escapeRegex(tok), "gi");
    out = out.replace(re, " ");
  }
  return out.replace(/\s+/g, " ").trim();
}

/**
 * Confidence is the fraction of present-and-resolved dimensions over
 * present dimensions. A query that mentions no time / agent / event is
 * trivially "0/0" and we return 1.0 only when the intent residual is
 * non-empty (the caller can still decide to invoke LLM-assist on
 * intent-only queries via `parse_confidence < threshold` plus other
 * cues; the router treats intent-only as routable to the keyword
 * classifier).
 */
function computeConfidence(parsed: {
  hasTimeMention: boolean;
  timeResolved: boolean;
  hasAgentMention: boolean;
  agentResolved: boolean;
  hasEventMention: boolean;
  eventResolved: boolean;
  intentEmpty: boolean;
  ambiguityCount: number;
}): number {
  const dims: { present: boolean; resolved: boolean }[] = [
    { present: parsed.hasTimeMention, resolved: parsed.timeResolved },
    { present: parsed.hasAgentMention, resolved: parsed.agentResolved },
    { present: parsed.hasEventMention, resolved: parsed.eventResolved },
  ];
  const present = dims.filter((d) => d.present);
  let base: number;
  if (present.length === 0) {
    // No time/agent/event signal surfaced. Confidence is low; the
    // caller should consider invoking LLM-assist. Distinct from the
    // empty-string case where confidence is 0.
    base = parsed.intentEmpty ? 0.0 : 0.3;
  } else {
    const resolved = present.filter((d) => d.resolved).length;
    base = resolved / present.length;
  }
  // Ambiguity flags pull confidence down 0.15 per flag, clamp to [0, 1].
  const adjusted = base - 0.15 * parsed.ambiguityCount;
  if (adjusted < 0) return 0;
  if (adjusted > 1) return 1;
  return adjusted;
}

const TIME_MENTION_PROBE =
  /\b(yesterday|today|now|past|last|this\s+week|this\s+month|since|from|between|\d{4}-\d{2}-\d{2})\b/i;
const AGENT_MENTION_PROBE = /\bagent[s]?\b/i;
const EVENT_MENTION_PROBE = /\b(event|events|class|classes|approvals?|policy)\b/i;

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Parse an operator query into a structured `ParsedQuery`. Pure: no
 * I/O, no implicit clock side effects beyond the optional `now` opt.
 *
 * The parser is rule-based and best-effort. When no signal extracts and
 * the query is non-empty, the result still carries a meaningful
 * `intent_phrase` (the original query, normalized) so the router's
 * keyword classifier still has something to work with.
 *
 * Callers that want LLM-assist completion should call
 * `parseQueryWithLlmAssist` instead, or check `isLowConfidence(parsed)`
 * and merge a completion patch themselves.
 */
export function parseQuery(
  query: string,
  opts?: ParseQueryOptions,
): ParsedQuery {
  const now = opts?.now ?? new Date();
  const enumValues = opts?.eventClassEnum ?? CANONICAL_AUDIT_EVENT_CLASSES;
  const original = query ?? "";
  const trimmed = original.trim();

  if (trimmed.length === 0) {
    return {
      time_range: null,
      agent_names: [],
      event_types: [],
      intent_phrase: "",
      ambiguity_flags: ["no_signal_extracted"],
      parse_confidence: 0,
    };
  }

  const ambiguity_flags = new Set<AmbiguityFlag>();

  // Time
  const timeMatch = resolveTimeRange(trimmed, now);
  const hasTimeMention = TIME_MENTION_PROBE.test(trimmed);
  if (hasTimeMention && !timeMatch) {
    ambiguity_flags.add("unknown_time_token");
  }

  // Agent names
  const agentResult = extractAgentNames(trimmed, opts?.registry);
  if (agentResult.flagged) {
    ambiguity_flags.add("unknown_agent_token");
  }
  const hasAgentMention = AGENT_MENTION_PROBE.test(trimmed);

  // Event types
  const eventResult = extractEventTypes(trimmed, enumValues);
  const hasEventMention = EVENT_MENTION_PROBE.test(trimmed);
  if (eventResult.flagged) {
    ambiguity_flags.add("unknown_event_token");
  }

  // Intent residual (strip resolved tokens + the time match span).
  const stripTokens: string[] = [];
  if (timeMatch) stripTokens.push(timeMatch.matchedSubstring);
  for (const name of agentResult.matched) stripTokens.push(name);
  for (const ev of eventResult.matched) {
    if (trimmed.toLowerCase().includes(ev.toLowerCase())) {
      stripTokens.push(ev);
    }
  }
  const intent_phrase = deriveIntentPhrase(trimmed, stripTokens);

  const parse_confidence = computeConfidence({
    hasTimeMention,
    timeResolved: timeMatch !== null,
    hasAgentMention,
    agentResolved: agentResult.matched.length > 0,
    hasEventMention,
    eventResolved: eventResult.matched.length > 0,
    intentEmpty: intent_phrase.length === 0,
    ambiguityCount: ambiguity_flags.size,
  });

  if (
    timeMatch === null &&
    agentResult.matched.length === 0 &&
    eventResult.matched.length === 0 &&
    intent_phrase.length === 0
  ) {
    ambiguity_flags.add("no_signal_extracted");
  }

  return {
    time_range: timeMatch ? timeMatch.range : null,
    agent_names: agentResult.matched,
    event_types: eventResult.matched,
    intent_phrase,
    ambiguity_flags: Array.from(ambiguity_flags),
    parse_confidence,
  };
}

/**
 * Confidence threshold below which the LLM-assist fallback should fire.
 * Coordinator-CTO bake at Tau-4 ship: 0.5 splits clearly-resolved queries
 * from "could not resolve" queries without burning the substrate on
 * every short query.
 */
export const LLM_ASSIST_THRESHOLD = 0.5;

export function isLowConfidence(parsed: ParsedQuery): boolean {
  return parsed.parse_confidence < LLM_ASSIST_THRESHOLD;
}

/**
 * Run the rule-based parse, and when `isLowConfidence(parsed)` AND the
 * caller supplied `llmAssist`, ask the classifier for a completion.
 * The completion patch is merged conservatively: only fields the rule-
 * based parser left empty are filled, never overwritten.
 *
 * On classifier failure / null return / non-shape result, the rule-
 * based parse is returned unchanged (fail-soft per Castle-walking).
 */
export async function parseQueryWithLlmAssist(
  query: string,
  llmAssist: LlmAssistGrammarCompletion | undefined,
  opts?: ParseQueryOptions,
): Promise<ParsedQuery> {
  const parsed = parseQuery(query, opts);
  if (!llmAssist || !isLowConfidence(parsed)) return parsed;

  let completion: Awaited<ReturnType<LlmAssistGrammarCompletion>>;
  try {
    completion = await llmAssist(query, parsed);
  } catch {
    return parsed;
  }
  if (!completion || typeof completion !== "object") return parsed;

  const merged: ParsedQuery = { ...parsed };
  if (parsed.time_range === null && completion.time_range) {
    merged.time_range = completion.time_range;
  }
  if (parsed.agent_names.length === 0 && Array.isArray(completion.agent_names)) {
    merged.agent_names = completion.agent_names.filter(
      (s) => typeof s === "string" && s.length > 0,
    );
  }
  if (parsed.event_types.length === 0 && Array.isArray(completion.event_types)) {
    const allowed = new Set(opts?.eventClassEnum ?? CANONICAL_AUDIT_EVENT_CLASSES);
    merged.event_types = completion.event_types.filter(
      (s) => typeof s === "string" && allowed.has(s),
    );
  }
  // Recompute confidence reflecting the merged state.
  merged.parse_confidence = Math.max(
    parsed.parse_confidence,
    computeConfidence({
      hasTimeMention: TIME_MENTION_PROBE.test(query),
      timeResolved: merged.time_range !== null,
      hasAgentMention: AGENT_MENTION_PROBE.test(query),
      agentResolved: merged.agent_names.length > 0,
      hasEventMention: EVENT_MENTION_PROBE.test(query),
      eventResolved: merged.event_types.length > 0,
      intentEmpty: merged.intent_phrase.length === 0,
      ambiguityCount: merged.ambiguity_flags.length,
    }),
  );
  return merged;
}

/**
 * Project a runtime `ParsedQuery` into the audit-safe summary. Drops
 * `intent_phrase` (carries operator query content) and serializes Date
 * objects as ISO strings. The output is what
 * `OperatorConciergeChatPayload.parsed_grammar` carries.
 */
export function auditSafeSummary(parsed: ParsedQuery): ParsedQueryAuditSummary {
  return {
    time_range: parsed.time_range
      ? {
          start_iso: parsed.time_range.start.toISOString(),
          end_iso: parsed.time_range.end.toISOString(),
          ...(parsed.time_range.relative_label !== undefined
            ? { relative_label: parsed.time_range.relative_label }
            : {}),
        }
      : null,
    agent_names: [...parsed.agent_names],
    event_types: [...parsed.event_types],
    ambiguity_flags: [...parsed.ambiguity_flags],
    parse_confidence: parsed.parse_confidence,
  };
}

/**
 * Operator-friendly fallback menu surfaced when the parser cannot
 * resolve enough to route. The menu lists what the concierge can answer
 * categorically, with one example per category, so the operator can
 * rephrase. The returned text is plain markdown (no em-dashes per the
 * Sanctuary public-facing copy rule) and safe to render directly.
 */
export function structuredFallbackMenu(parsed: ParsedQuery): string {
  const lines: string[] = [];
  lines.push("I am not sure I understood that. Here is what I can answer:");
  lines.push("");
  lines.push("- Templates: list the channel templates you have available.");
  lines.push("- Agent state: show what your wrapped agents are doing right now.");
  lines.push(
    "- Agent activity: show recent activity for an agent. Try: \"what did agent X do yesterday\".",
  );
  lines.push(
    "- Audit log: show recent audit entries. Try: \"show me policy changes from this week\".",
  );
  lines.push(
    "- Sentinel findings: list current warnings or anomaly alerts.",
  );
  lines.push(
    "- Receipts: list recent Concordia commitments or composition receipts.",
  );
  lines.push(
    "- Verascore: show recent reputation deltas or trust score changes.",
  );

  if (parsed.ambiguity_flags.includes("unknown_time_token")) {
    lines.push("");
    lines.push(
      "Tip: time ranges I understand include yesterday, today, past hour, last 24h, this week, since 2026-05-01, and from 2026-05-01 to 2026-05-08.",
    );
  }
  if (parsed.ambiguity_flags.includes("unknown_agent_token")) {
    lines.push("");
    lines.push(
      "Tip: agent names match against the registered agents on this fortress. Try the agent's full id.",
    );
  }
  if (parsed.ambiguity_flags.includes("unknown_event_token")) {
    lines.push("");
    lines.push(
      "Tip: event classes I understand include policy changes, approvals, exit bundles, audit truncations, compositions, receipts, and concierge chats.",
    );
  }
  return lines.join("\n");
}
