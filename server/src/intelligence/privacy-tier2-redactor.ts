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
import type { PiiConfigStore } from "../query-anonymity/pii-config-store.js";
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

/**
 * Config for the consent-gated Tier B redactor installed on the
 * production substrate selector at boot.
 */
export interface ConsentGatedTier2RedactorConfig extends Tier2RedactorConfig {
  /**
   * Live per-fortress Tier B config store. Read at EVERY call so the
   * operator's toggle takes effect immediately without re-installing the
   * redactor. Tier 2 scrubbing fires ONLY when the operator opted in
   * (`enabled` or `smart_mode_enabled`) AND recorded consent
   * (`consented_to_trade_off`); otherwise the redactor is a passthrough
   * that audit-emits `filter_tier: 1` so the transparency UI shows the
   * Tier B step did not run.
   */
  configStore: PiiConfigStore;
}

/**
 * Build the redactor the entry point installs on the production
 * `SubstrateSelector` via `installRedactor`. Unlike the bare
 * `buildPrivacyTier2Redactor`, this variant is opt-in + consent-gated:
 * it reads the live `PiiConfigStore` on every call and only performs the
 * Tier 2 scrub when the operator has both enabled Tier B and consented to
 * the trade-off. When Tier B is off or unconsented, it returns the input
 * unchanged and emits a `filter_tier: 1` redaction event (zero matches),
 * exactly matching the prior `IDENTITY_REDACTOR` behavior so a toggled-off
 * operator sees no behavior change.
 *
 * Honesty (never-overclaim rule): the gate is read from real persisted
 * state at call time, so a query is scrubbed iff the operator genuinely
 * opted in with consent. `effectiveTierBEnabled()` in the route layer
 * derives the same truth from the same config plus the
 * redactor-installed signal, so the operator-facing surface never claims
 * active scrubbing the path does not perform.
 */
export function buildConsentGatedTier2Redactor(
  cfg: ConsentGatedTier2RedactorConfig,
): FrontierRedactor {
  const tier2 = buildPrivacyTier2Redactor(cfg);
  return async (text: string) => {
    let active = false;
    try {
      const config = await cfg.configStore.get();
      active = Boolean(
        config &&
          (config.enabled || config.smart_mode_enabled) &&
          config.consented_to_trade_off,
      );
    } catch {
      // Fail closed toward NO claimed protection: a store read error must
      // never silently behave as if Tier B is active. Passthrough (the
      // substrate still receives the text) with a filter_tier:1 event so
      // the transparency UI reflects that Tier 2 did not run.
      active = false;
    }
    if (!active) {
      cfg.selector.emitRedactionEvent({
        surface: cfg.surface,
        substrate: cfg.substrate,
        matchCount: 0,
        filterTier: 1,
      });
      return { redacted: text, matchCount: 0 };
    }
    return tier2(text);
  };
}
