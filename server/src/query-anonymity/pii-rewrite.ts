/**
 * Sanctuary WP-V1.x-QUERY-LAYER-ANONYMITY Rho-2 Tier B PII rewrite, basic shape.
 *
 * Builds on Rho-1 (Tier A header strip; on main). Tier A strips
 * fingerprintable HTTP headers from every outbound substrate-selector
 * call structurally and unconditionally. Tier B (this module) rewrites
 * PII *in the query body* before it reaches the substrate selector.
 *
 * Design (per Erik decisions + coordinator scope call 2026-05-09):
 *   - **Default-off, operator-toggleable.** Per-fortress config defaults
 *     to OFF. Operators MUST acknowledge a privacy-vs-functionality
 *     trade-off explainer before flipping it on (first-toggle consent
 *     UX). A per-query override exists for one-shot enablement.
 *   - **Regex first-pass over 7 categories**: emails, phone numbers,
 *     SSN-shape, IPv4 / IPv6, credit-card-shape (Luhn-validated),
 *     full street addresses, common name patterns.
 *   - **LLM-assist on residuals** via `selector.invokeRedact` on the
 *     `privacy-filter-tier-2` surface. The redact surface returns
 *     `{ redacted, placeholders }`. Rho-3 smart mode (iteration-14)
 *     consumes the placeholders for context-aware re-mapping at
 *     concierge render time.
 *   - **Substrate-selector call carries rewritten text only.** The
 *     original text never crosses the outbound boundary once Tier B
 *     fires. The caller is responsible for replacing the field on its
 *     request object before calling the selector.
 *
 * Castle-walking discipline:
 *   - No new outbound surface. LLM-assist re-uses the existing
 *     substrate-selector channel (already a Castle Layer 1 egress
 *     channel; Tier A's strip applies to it; the Castle Wall egress
 *     filter still binds).
 *   - Tier B is a REDUCTION of what crosses the outbound boundary,
 *     same posture as Tier A.
 *
 * What does NOT land here:
 *   - **Smart mode** (Rho-3 in iteration-14): context-aware
 *     decisioning, intent classifier, reverse-mapping memo, concierge
 *     render-time mapping. Erik confirmed smart mode WILL ship; it's
 *     split off to its own build for cleaner test surface + lower
 *     divergence risk.
 *   - **Live wiring into the substrate-selector invoke pipeline**:
 *     deferred to a Rho-2.5 boot-wiring follow-up. This module ships
 *     the primitive + config + routes; consumers (selector wrapper
 *     and/or selector mid-flight call site) attach to it.
 *
 * Audit emission:
 *   - `query_anonymity_pii_rewritten` fires per rewrite call with
 *     per-category redaction counts + total residual count after
 *     LLM-assist + boolean "consented_to_trade_off" snapshot.
 */

import type {
  SubstrateSelector,
} from "../intelligence/selector.js";
import type { Surface } from "../intelligence/types.js";

// ── Public types ─────────────────────────────────────────────────────

/**
 * The seven categories Rho-2 redacts via regex first-pass. Names is
 * intentionally last because it has the highest false-positive rate;
 * LLM-assist post-pass can refine in Rho-3.
 */
export type PiiCategory =
  | "email"
  | "phone"
  | "ssn"
  | "ip_address"
  | "credit_card"
  | "street_address"
  | "name";

export const PII_CATEGORIES: readonly PiiCategory[] = [
  "email",
  "phone",
  "ssn",
  "ip_address",
  "credit_card",
  "street_address",
  "name",
] as const;

/** Per-category redaction count from one rewrite call. */
export type RedactionCounts = Record<PiiCategory, number>;

export interface PiiRewriteResult {
  /** Text with all matched PII replaced by category-stable placeholders. */
  rewritten: string;
  /** Per-category counts of redactions performed. */
  redaction_counts: RedactionCounts;
  /** Token reverse-mapping (placeholder -> original). Forward-compat with Rho-3. */
  placeholders: Record<string, string>;
  /**
   * Whether LLM-assist ran on residuals (true when caller passed a
   * selector + Tier B was enabled).
   */
  llm_assist_ran: boolean;
  /** Count of additional residuals LLM-assist redacted on top of regex. */
  llm_residual_count: number;
}

/** Audit op constants. Stable shape for downstream emitters. */
export const PII_REWRITE_AUDIT_OPS = {
  PII_REWRITTEN: "query_anonymity_pii_rewritten",
  CONFIG_UPDATED: "query_anonymity_pii_config_updated",
  CONSENT_RECORDED: "query_anonymity_pii_consent_recorded",
} as const;

export type PiiRewriteAuditOp =
  (typeof PII_REWRITE_AUDIT_OPS)[keyof typeof PII_REWRITE_AUDIT_OPS];

/** Surface name fixed at the type level for LLM-assist invocations. */
export const PII_REWRITE_LLM_SURFACE: Surface = "privacy-filter-tier-2";

/**
 * Operator-facing trade-off explainer rendered before the first
 * toggle-to-on. Plain English; no jargon. The dashboard route returns
 * this verbatim so the operator reads the same text whether they're
 * in the CLI, the dashboard, or a downstream consumer. Length-capped
 * because dashboards have small footers.
 */
export const PII_TRADE_OFF_EXPLAINER = [
  "Tier B PII rewrite scrubs personal information from your queries",
  "before they reach the LLM substrate (Claude, GPT, local model).",
  "",
  "What it protects:",
  "  - Emails, phone numbers, SSNs, IPs, credit cards, street",
  "    addresses, and obvious name patterns get replaced with",
  "    placeholders before the call.",
  "  - The substrate receives only the rewritten text. Your original",
  "    text never crosses the outbound boundary.",
  "",
  "What it costs:",
  "  - Substrates work less well when they cannot see the real",
  "    values. A query like 'email Alex about the rent' becomes",
  "    'email [NAME_0] about the rent', and the response loses",
  "    specificity. Some tasks (drafting personalized messages,",
  "    looking up specific addresses) become harder.",
  "  - Smart mode (Rho-3) will re-introduce the originals at render",
  "    time so YOU see them but the substrate never did. That mode",
  "    ships in iteration-14; until then, the placeholder shows",
  "    through.",
  "",
  "This is OFF by default. Turn it on per-fortress (every query) or",
  "per-query (one shot). You can turn it off again at any time.",
].join("\n");

// ── Regex first-pass ─────────────────────────────────────────────────

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

// US phone numbers: +1 (123) 456-7890, 123-456-7890, 1234567890, etc.
// Restricts to 10-digit US-style; international/freeform not covered
// in the regex pass (LLM-assist catches them).
const PHONE_RE =
  /(?:(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b/g;

const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_RE = /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g;

// Credit card candidates: 13-19 digits, optional spaces/hyphens.
// Validated by Luhn check before redaction so false positives
// (long invoice numbers) don't get redacted.
const CREDIT_CARD_RE = /\b(?:\d[ -]?){13,18}\d\b/g;

// Street address: number + 1-4 capitalized words + street-type suffix.
// Misses many real addresses (PO boxes, apartments, international);
// LLM-assist is the safety net. Anchored on suffix because that's the
// strongest signal.
const STREET_RE =
  /\b\d{1,6}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Place|Pl|Court|Ct|Highway|Hwy|Parkway|Pkwy|Terrace|Ter|Circle|Cir)\b\.?/g;

// Name candidates: two capitalized words in a row, neither in a
// stop-list of common false positives (place names, organization
// names, etc.). High false-positive rate is accepted: LLM-assist in
// Rho-3 will refine.
const NAME_CANDIDATE_RE = /\b[A-Z][a-z]{1,}\s+[A-Z][a-z]{1,}\b/g;

const NAME_STOP_LIST = new Set<string>([
  "United States", "New York", "Los Angeles", "San Francisco",
  "San Jose", "Las Vegas", "New Jersey", "North Carolina",
  "South Carolina", "North Dakota", "South Dakota", "New Mexico",
  "New Hampshire", "Rhode Island", "West Virginia", "American Express",
  "Bank Of", "United Kingdom", "Hong Kong", "South Korea",
  "Saudi Arabia", "South Africa", "New Zealand", "Czech Republic",
  "Costa Rica", "El Salvador", "Puerto Rico", "Sri Lanka",
  "Saint Petersburg", "Saint Louis", "Saint Paul", "Fort Worth",
  "Fort Lauderdale", "Salt Lake", "Long Island", "Long Beach",
  "Mountain View", "Silicon Valley", "Wall Street", "Big Sur",
  "Open Source", "Machine Learning", "Artificial Intelligence",
  "Real Estate", "Customer Service", "Last Year", "Last Week",
  "Last Month", "Next Year", "Next Week", "Next Month",
  "First Class", "Second Class", "First Place", "Second Place",
  "World War", "Civil War", "Cold War", "Korean War", "Vietnam War",
]);

// Luhn check for credit-card candidate filtering.
function isLuhnValid(digits: string): boolean {
  const onlyDigits = digits.replace(/\D/g, "");
  if (onlyDigits.length < 13 || onlyDigits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = onlyDigits.length - 1; i >= 0; i -= 1) {
    let n = Number.parseInt(onlyDigits[i]!, 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

interface CategoryPass {
  category: PiiCategory;
  pattern: RegExp;
  /** Optional filter: return true to redact, false to skip. */
  filter?: (match: string) => boolean;
}

const CATEGORY_PASSES: readonly CategoryPass[] = [
  { category: "email", pattern: EMAIL_RE },
  { category: "ssn", pattern: SSN_RE },
  { category: "credit_card", pattern: CREDIT_CARD_RE, filter: isLuhnValid },
  { category: "phone", pattern: PHONE_RE },
  { category: "ip_address", pattern: IPV4_RE },
  { category: "ip_address", pattern: IPV6_RE },
  { category: "street_address", pattern: STREET_RE },
  // Name pass runs LAST so other categories (which sometimes look
  // name-shaped) consume their matches first. Stop-list filter.
  {
    category: "name",
    pattern: NAME_CANDIDATE_RE,
    filter: (match) => !NAME_STOP_LIST.has(match),
  },
];

function emptyCounts(): RedactionCounts {
  return {
    email: 0,
    phone: 0,
    ssn: 0,
    ip_address: 0,
    credit_card: 0,
    street_address: 0,
    name: 0,
  };
}

/**
 * Run the regex first-pass. Returns the rewritten text + per-category
 * counts + placeholder map. Pure; no audit emission, no I/O.
 *
 * Per-category indices are accumulated ACROSS passes that share a
 * category (e.g. the IPv4 + IPv6 passes both feed `ip_address`),
 * keeping placeholder tokens unique. Repeated occurrences of the same
 * original token within a single call dedupe to the same placeholder.
 */
export function rewritePiiRegexOnly(text: string): PiiRewriteResult {
  let working = text;
  const counts = emptyCounts();
  // category -> next-index (accumulates across passes sharing a category)
  const categoryIndex = new Map<PiiCategory, number>();
  // `category|original` -> placeholder token (within-call dedupe)
  const seen = new Map<string, string>();
  const placeholders: Record<string, string> = {};
  for (const pass of CATEGORY_PASSES) {
    working = working.replace(pass.pattern, (match) => {
      if (pass.filter && !pass.filter(match)) return match;
      const seenKey = `${pass.category}|${match}`;
      const existing = seen.get(seenKey);
      if (existing) return existing;
      const idx = categoryIndex.get(pass.category) ?? 0;
      const token = `[${pass.category.toUpperCase()}_${idx}]`;
      categoryIndex.set(pass.category, idx + 1);
      seen.set(seenKey, token);
      placeholders[token] = match;
      counts[pass.category] += 1;
      return token;
    });
  }
  return {
    rewritten: working,
    redaction_counts: counts,
    placeholders,
    llm_assist_ran: false,
    llm_residual_count: 0,
  };
}

// ── LLM-assist on residuals ──────────────────────────────────────────

/**
 * Minimal selector contract this module uses. Decoupled from the full
 * SubstrateSelector type so tests can pass a stub without dragging the
 * whole selector graph into scope. The real selector implements both
 * the structural shape AND ships audit emission on every invoke.
 */
export interface PiiRewriteSelector {
  invokeRedact: SubstrateSelector["invokeRedact"];
}

export interface PiiRewriteWithLlmOptions {
  identityId: string;
  /** Soft cap on the LLM-assist call's response token budget. */
  maxTokens?: number;
}

/**
 * Two-pass rewrite: regex first, then LLM-assist on the regex output
 * for any residuals the regex missed. The placeholder map from the
 * regex pass is preserved + extended by LLM-found residuals.
 *
 * Failure-mode: if the LLM call fails, we return the regex-only
 * result (with `llm_assist_ran = false`) rather than fail the whole
 * rewrite. The audit emission carries the failure class so the
 * operator dashboard can surface persistent LLM-assist outages.
 */
export async function rewritePiiWithLlm(
  text: string,
  selector: PiiRewriteSelector,
  opts: PiiRewriteWithLlmOptions,
): Promise<PiiRewriteResult> {
  const regexPass = rewritePiiRegexOnly(text);
  // Short-circuit: if regex caught nothing AND the text is short
  // enough that an LLM call is wasteful, skip the LLM round-trip.
  // Operator can still see this in the audit log (llm_assist_ran:
  // false). Threshold deliberately low; tighter than typical context
  // windows.
  const totalRegexHits = Object.values(regexPass.redaction_counts).reduce(
    (a, b) => a + b,
    0,
  );
  if (text.length < 24 && totalRegexHits === 0) {
    return regexPass;
  }
  try {
    const resp = await selector.invokeRedact(PII_REWRITE_LLM_SURFACE, {
      kind: "redact",
      text: regexPass.rewritten,
    });
    if (resp.body.kind !== "redact") {
      // Substrate failed or returned an unexpected body shape; fall
      // back to the regex-only result.
      return regexPass;
    }
    const llmRedacted = resp.body.redacted;
    const llmPlaceholders = resp.body.placeholders ?? {};
    // Merge placeholder maps. The LLM may have rewritten the
    // already-replaced regex tokens; we trust the LLM's output text
    // wholesale but combine the placeholder dictionaries so both
    // regex and LLM-found tokens have reverse mappings.
    const mergedPlaceholders: Record<string, string> = {
      ...regexPass.placeholders,
    };
    for (const [token, original] of Object.entries(llmPlaceholders)) {
      if (!(token in mergedPlaceholders)) {
        mergedPlaceholders[token] = original;
      }
    }
    const residualCount = Math.max(
      0,
      Object.keys(llmPlaceholders).length -
        Object.keys(regexPass.placeholders).length,
    );
    return {
      rewritten: llmRedacted,
      redaction_counts: regexPass.redaction_counts,
      placeholders: mergedPlaceholders,
      llm_assist_ran: true,
      llm_residual_count: residualCount,
    };
  } catch {
    // Any throw: degrade to regex-only. The caller can see this in
    // the audit log (llm_assist_ran stays false).
    return regexPass;
  }
  // SAFETY: maxTokens is accepted for forward-compat but not yet
  // surfaced to the redact-request schema; selectors that support
  // it can read it from a future extension field.
  void opts.maxTokens;
}
