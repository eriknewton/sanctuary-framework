/**
 * Sanctuary MCP Server — Intelligence Substrate Default Config
 *
 * Per Erik ratification 2026-04-29 (position paper §5):
 *   - concierge:                       local + Gemma 2 2B
 *   - direct-agent-gate-advisor:       local + Gemma 2 2B (mirrors concierge)
 *   - sentinel-scoring:                local + Phi-4 Mini (rules + escalation)
 *   - gate-explanation:                disabled (templates v1.2; v1.3+ adds LLM)
 *   - privacy-filter-tier-2:           local + Phi-4 Mini (NER + classifier)
 *   - template-suggestion:             local + Gemma 2 2B
 *
 * Below-baseline hardware: selector recommends operator override to Venice or
 * frontier-with-filter at first-use. Defaults still ship as "local" so the
 * config surface stays consistent; the hardware-capability report flags the
 * mismatch in the transparency UI.
 */

import type {
  FallbackBehavior,
  LocalModelPick,
  SubstrateChoice,
  SubstrateConfig,
  Surface,
} from "./types.js";

export const DEFAULT_PER_SURFACE: Record<Surface, SubstrateChoice> = {
  concierge: "local",
  "direct-agent-gate-advisor": "local",
  "sentinel-scoring": "local",
  // Templates v1.2 means no LLM call; selector returns a "disabled" handle and
  // surfaces emit template-rendered prose. v1.3+ flips this to "local" once
  // the English-authored gate path lands.
  "gate-explanation": "disabled",
  "privacy-filter-tier-2": "local",
  "template-suggestion": "local",
};

export const DEFAULT_LOCAL_MODEL_PICKS: Partial<Record<Surface, LocalModelPick>> = {
  concierge: "gemma-2-2b",
  "direct-agent-gate-advisor": "gemma-2-2b",
  "sentinel-scoring": "phi-4-mini",
  "privacy-filter-tier-2": "phi-4-mini",
  "template-suggestion": "gemma-2-2b",
};

/**
 * Per-surface fallback behavior defaults. Per position paper §5:
 *   - concierge:               degrade-silent
 *   - sentinel-scoring:        conservative-deny
 *   - privacy-filter-tier-2:   degrade-silent (Tier 1 regex always works)
 *   - others:                  conservative-deny
 */
export const DEFAULT_FALLBACK: Record<Surface, FallbackBehavior> = {
  concierge: "degrade-silent",
  "direct-agent-gate-advisor": "conservative-deny",
  "sentinel-scoring": "conservative-deny",
  "gate-explanation": "degrade-silent",
  "privacy-filter-tier-2": "degrade-silent",
  "template-suggestion": "degrade-silent",
};

export const DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434";

/**
 * Default value for the picker's "Apply to all surfaces" toggle. ON by
 * default per Finding SS: the operator-friendly path is bulk apply;
 * per-surface granularity is opt-in.
 */
export const DEFAULT_APPLY_TO_ALL_SURFACES = true;

export function buildDefaultConfig(): SubstrateConfig {
  return {
    version: 1,
    perSurface: { ...DEFAULT_PER_SURFACE },
    localModelPicks: { ...DEFAULT_LOCAL_MODEL_PICKS },
    ollamaEndpoint: DEFAULT_OLLAMA_ENDPOINT,
    frontierConfig: {},
    fallback: { ...DEFAULT_FALLBACK },
    applyToAllSurfaces: DEFAULT_APPLY_TO_ALL_SURFACES,
    updatedAt: new Date().toISOString(),
  };
}
