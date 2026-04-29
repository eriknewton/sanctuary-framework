/**
 * Sanctuary MCP Server — Hybrid Substrate (Per-Surface Router)
 *
 * Per position paper section 5: hybrid substrate is per-surface routing.
 * Operator pre-binds each surface to a concrete substrate; the router
 * looks up the binding and delegates to the chosen substrate's handle.
 *
 * v1.2 ships per-surface routing only. Per-query sensitivity-classifier
 * routing is deferred to v1.3+ (a sensitivity classifier flags
 * "contains PII?" -> local-only, "needs frontier reasoning?" -> Venice or
 * frontier; the operator overrides per-query). The v1.3 commit replaces
 * the static per-surface lookup here with a classifier-driven choice.
 *
 * Why a separate file:
 * The SubstrateSelector dispatch path already handles `choice === "hybrid"`
 * by reading config.hybridRules.perSurface[surface] and recursing. Keeping
 * the router shape as its own module makes the v1.3 swap surgical: replace
 * `resolveHybridChoice` with a classifier-driven function and the selector
 * stays unchanged.
 */

import type {
  HybridRoutingRules,
  SubstrateChoice,
  Surface,
} from "../../types.js";

export type HybridResolvedChoice = Exclude<SubstrateChoice, "hybrid">;

/**
 * Resolve a surface to a concrete substrate via the operator's hybrid
 * routing rules. Returns null when the operator has not configured a
 * rule for the surface; the selector treats null as "fall back to
 * disabled" so consumers see a stable disabled handle rather than a
 * silent re-route.
 *
 * v1.2 lookup: pure per-surface map. The operator-facing picker modal
 * is the only entry point for setting these rules; per-query overrides
 * are not exposed.
 */
export function resolveHybridChoice(
  rules: HybridRoutingRules | undefined,
  surface: Surface,
): HybridResolvedChoice | null {
  if (!rules) return null;
  return rules.perSurface[surface] ?? null;
}

/**
 * Build a per-surface hybrid rules record from a partial operator-supplied
 * map. Surfaces the operator did not specify default to `disabled` so the
 * dashboard transparency UI surfaces the unconfigured row visibly rather
 * than silently routing through some implicit default.
 *
 * The picker modal calls this when the operator clicks "Save" on the
 * hybrid configuration tab; the selector receives the canonical full
 * record and persists it.
 */
export function buildHybridRules(
  partial: Partial<Record<Surface, HybridResolvedChoice>>,
): HybridRoutingRules {
  const surfaces: Surface[] = [
    "concierge",
    "direct-agent-gate-advisor",
    "sentinel-scoring",
    "gate-explanation",
    "privacy-filter-tier-2",
    "template-suggestion",
  ];
  const filled = {} as Record<Surface, HybridResolvedChoice>;
  for (const surface of surfaces) {
    filled[surface] = partial[surface] ?? "disabled";
  }
  return { perSurface: filled };
}

/**
 * Validate that a HybridRoutingRules record is complete (every surface
 * has a binding) and contains no recursive `hybrid` rules. Used by the
 * picker modal before save and by the selector at config-load time so a
 * v1.3+ schema bump that reintroduces hybrid recursion is caught early.
 */
export function validateHybridRules(rules: HybridRoutingRules): { ok: true } | { ok: false; reason: string } {
  const surfaces: Surface[] = [
    "concierge",
    "direct-agent-gate-advisor",
    "sentinel-scoring",
    "gate-explanation",
    "privacy-filter-tier-2",
    "template-suggestion",
  ];
  for (const surface of surfaces) {
    const choice = rules.perSurface[surface];
    if (!choice) {
      return { ok: false, reason: `surface ${surface} has no rule` };
    }
    // The HybridResolvedChoice type already excludes "hybrid" at the type
    // level; this runtime check defends against record values constructed
    // outside TypeScript (e.g. corrupt persisted state).
    if ((choice as string) === "hybrid") {
      return { ok: false, reason: `surface ${surface} routes to hybrid (recursion not supported at v1.2)` };
    }
  }
  return { ok: true };
}
