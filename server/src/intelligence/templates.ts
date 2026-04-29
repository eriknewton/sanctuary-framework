/**
 * Sanctuary MCP Server — Intelligence Substrate Badge Template Registry
 *
 * Mirrors the v1.1 hub display-template-id pattern (`HubInboxItemHeader`):
 * backends emit stable keys + typed args; the dashboard owns the actual
 * render strings. This makes it structurally impossible for substrate
 * tradeoff text to leak operator data or smuggle free-form prose.
 *
 * Each substrate has one labelKey (badge title) and one tradeoffKey
 * (operator-readable tradeoff body). The transparency UI registry resolves
 * them. v1.2 ships English; v1.3+ may localize.
 *
 * Dead-claims discipline (CLAUDE.md):
 *   - Local: claims "data stays on machine" (defensible per-operator)
 *   - Venice: claims "contractual privacy via relay" (NOT cryptographic)
 *   - Frontier-with-filter: explicitly names the leakage with required caveat
 *   - Hybrid: defers honesty to per-surface badges
 *   - Disabled: surface refuses LLM calls; explains why
 */

import { hashToString } from "../core/hashing.js";
import { sha256 } from "@noble/hashes/sha256";
import { stringToBytes } from "../core/encoding.js";
import type { LocalModelPick, SubstrateChoice } from "./types.js";

/** Stable badge label key per substrate. */
export const BADGE_LABEL_KEYS: Record<SubstrateChoice, string> = {
  local: "intelligence.badge.local.label",
  venice: "intelligence.badge.venice.label",
  "frontier-with-filter": "intelligence.badge.frontier.label",
  hybrid: "intelligence.badge.hybrid.label",
  disabled: "intelligence.badge.disabled.label",
};

/** Stable tradeoff body key per substrate. */
export const BADGE_TRADEOFF_KEYS: Record<SubstrateChoice, string> = {
  local: "intelligence.badge.local.tradeoff",
  venice: "intelligence.badge.venice.tradeoff",
  "frontier-with-filter": "intelligence.badge.frontier.tradeoff",
  hybrid: "intelligence.badge.hybrid.tradeoff",
  disabled: "intelligence.badge.disabled.tradeoff",
};

/**
 * Operator-readable display strings for each badge labelKey + tradeoffKey.
 *
 * The dashboard SPA owns the canonical render path (template registry under
 * `dashboard/v1_1/templates.ts`). This map is the BACKEND fallback used by:
 *   - the `/api/hub/intelligence/status` route when the consumer is not the
 *     v1.1 SPA
 *   - operator-CLI surfaces (`sanctuary intelligence status`)
 *   - tests
 *
 * No-em-dash discipline applies: tradeoff body uses periods, commas, colons,
 * semicolons. Composition partners named per CLAUDE.md (Ollama, Venice.ai,
 * Anthropic, OpenAI, Google).
 */
export const BACKEND_FALLBACK_STRINGS: Record<string, string> = {
  "intelligence.badge.local.label": "Local model",
  "intelligence.badge.local.tradeoff":
    "Your queries never leave your machine. Capability is moderate; complex reasoning may underperform a frontier model. Hardware required: 8GB RAM Apple Silicon M1+ or equivalent.",
  "intelligence.badge.venice.label": "Venice.ai",
  "intelligence.badge.venice.tradeoff":
    "Queries reach Venice's relay during inference. Venice's contract states no retention or training on user data. Trust is contractual, not cryptographic. Capability higher than local.",
  "intelligence.badge.frontier.label": "Frontier with PII filter",
  "intelligence.badge.frontier.tradeoff":
    "Queries reach the frontier provider after PII redaction. Highest capability. The frontier provider may log queries per their ToS. Redaction can fail on subtle PII (paraphrased addresses, contextual identifiers); expect imperfect privacy. The Privacy Filter event log shows what was redacted.",
  "intelligence.badge.hybrid.label": "Hybrid (per surface)",
  "intelligence.badge.hybrid.tradeoff":
    "Each surface routes to its own substrate per your configuration. Tradeoffs apply per surface; see each row.",
  "intelligence.badge.disabled.label": "Disabled",
  "intelligence.badge.disabled.tradeoff":
    "This surface does not invoke an LLM. Privacy filter falls back to Tier 1 regex; concierge, sentinel scoring, and gate explanation surfaces become unavailable until you pick a substrate.",
};

/**
 * Operator-readable model labels for the local substrate.
 */
export const LOCAL_MODEL_LABELS: Record<LocalModelPick, string> = {
  "gemma-2-2b": "Gemma 2 2B (via Ollama)",
  "phi-4-mini": "Phi-4 Mini (via Ollama)",
  "llama-3.1-8b": "Llama 3.1 8B (via Ollama)",
};

/**
 * Resolve a backend-side display string. The dashboard SPA's own template
 * registry owns the canonical UI render; this is the fallback for non-SPA
 * consumers and tests.
 */
export function resolveBackendString(key: string): string {
  return BACKEND_FALLBACK_STRINGS[key] ?? key;
}

/**
 * Hash the tradeoff text the operator saw at choice time. Used for the
 * `intelligence_substrate_chosen` audit event so the auditor can prove WHICH
 * tradeoff text the operator agreed to (without storing the prose itself,
 * which would bloat the audit log and introduce localization drift).
 */
export function tradeoffTextHash(substrate: SubstrateChoice): string {
  const text = resolveBackendString(BADGE_TRADEOFF_KEYS[substrate]);
  return hashToString(sha256(stringToBytes(text)));
}
