/**
 * Sanctuary MCP Server — Privacy Filter Tier 2 Redactor
 *
 * Pre-egress redactor wired into the SubstrateSelector. Used by the
 * frontier-with-filter substrate (and any other surface that asks for
 * Tier 2 redaction) to produce redacted text + audit-emit a
 * `pii_redaction_event` payload before any outbound API call.
 *
 * v1.2 scope (per spawn prompt section 2.3):
 *   - Tier 1 regex (15 patterns + encrypted placeholder vault) ALWAYS
 *     runs. The shipped privacy-filter.ts module already implements
 *     this; the Tier 2 redactor wraps that path and emits the audit
 *     event through the selector.
 *   - When the operator binds the `privacy-filter-tier-2` surface to a
 *     non-disabled substrate, v1.3+ adds a small-LLM PII classifier on
 *     top of Tier 1 regex. v1.2 ships the wiring + emission path; the
 *     LLM-classifier augmentation is documented as a deviation from
 *     spawn-prompt scope and flagged for v1.3 (operator-LLM redaction
 *     produces unstructured output that needs a span-extraction layer
 *     to merge with the regex spans, which is a meaningful body of
 *     additional work; v1.2 ships safely without it).
 *   - Surfaces that route through Tier 2 ALWAYS see at least Tier 1
 *     regex behavior. Disabled-Tier-2 = Tier 1 + transparency UI
 *     surfaces "Tier 2 unavailable; only regex PII detection active".
 *
 * Composition partners named: Microsoft Presidio (already shipped as
 * the regex-pattern source per privacy-filter.ts), Ollama (substrate
 * runtime when v1.3+ wires the small-LLM classifier).
 *
 * Recursion-avoidance:
 * The redactor closes over the SubstrateSelector for audit emission
 * only; it does NOT invoke any substrate (which would risk infinite
 * recursion through the frontier substrate's own pre-egress hook). The
 * v1.3 small-LLM classifier path will use a separate selector method
 * gated to non-frontier substrates so the recursion can never form.
 */

import {
  PrivacyPlaceholderVault,
  detectSensitiveSpans,
} from "../operational/privacy-filter.js";
import type { FrontierRedactor } from "./substrates/frontier.js";
import type { SubstrateSelector } from "./selector.js";
import type { Surface, SubstrateChoice } from "./types.js";

export interface Tier2RedactorConfig {
  /** Selector that receives the audit emission for each redaction call. */
  selector: SubstrateSelector;
  /** Vault for stable placeholder issuance across calls. */
  vault: PrivacyPlaceholderVault;
  /**
   * Surface this redactor is REDACTING FOR. Audit events stamp this so
   * the operator can see "concierge -> redactor produced N matches".
   * Different surfaces using the same redactor are typically a
   * misconfiguration; the bootstrap code constructs one redactor per
   * surface that needs Tier 2.
   */
  surface: Surface;
  /**
   * Substrate the redaction is being performed for (always the surface's
   * downstream substrate, e.g. "frontier-with-filter" or "venice"). Used
   * for audit emission only.
   */
  substrate: SubstrateChoice;
  /**
   * Vault scope for placeholder reuse. Defaults to the surface name so
   * placeholders are stable per-surface but distinct across surfaces.
   */
  scope?: string;
}

/**
 * Build a FrontierRedactor that runs Tier 1 regex + emits a Tier 2
 * audit event. The redactor signature matches the FrontierRedactor type
 * exactly so the substrate selector can install this as a drop-in for
 * the IDENTITY_REDACTOR default at construction time.
 */
export function buildPrivacyTier2Redactor(cfg: Tier2RedactorConfig): FrontierRedactor {
  const scope = cfg.scope ?? cfg.surface;
  return async (text: string) => {
    if (!text) {
      cfg.selector.emitRedactionEvent({
        surface: cfg.surface,
        substrate: cfg.substrate,
        matchCount: 0,
        filterTier: 2,
      });
      return { redacted: "", matchCount: 0 };
    }

    const spans = detectSensitiveSpans(text);
    if (spans.length === 0) {
      cfg.selector.emitRedactionEvent({
        surface: cfg.surface,
        substrate: cfg.substrate,
        matchCount: 0,
        filterTier: 2,
      });
      return { redacted: text, matchCount: 0 };
    }

    // Sort by start; clip overlapping spans to keep replacement deterministic.
    const sorted = [...spans].sort((a, b) => a.start - b.start);
    const pieces: string[] = [];
    let cursor = 0;
    let matchCount = 0;
    for (const span of sorted) {
      if (span.start < cursor) continue; // skip overlapping later span
      const placeholder = await cfg.vault.placeholderFor(span.class, span.text, scope);
      pieces.push(text.slice(cursor, span.start));
      pieces.push(placeholder);
      cursor = span.end;
      matchCount += 1;
    }
    pieces.push(text.slice(cursor));
    const redacted = pieces.join("");

    cfg.selector.emitRedactionEvent({
      surface: cfg.surface,
      substrate: cfg.substrate,
      matchCount,
      filterTier: 2,
    });

    return { redacted, matchCount };
  };
}
