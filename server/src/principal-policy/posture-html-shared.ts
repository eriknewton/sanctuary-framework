/**
 * Shared client-side HTML fragments for the posture surfaces.
 *
 * The posture Home page (`posture-home-html.ts`) and the per-agent drill-down
 * (`posture-agent-html.ts`) are each self-contained HTML strings with an inline
 * `<script>`. A few honesty-critical client functions MUST be byte-identical
 * across both surfaces so the "never fake green" contract cannot silently drift
 * on one copy. This module is the single source of truth for those fragments:
 * both renderers interpolate the exported constants instead of hand-copying the
 * function body.
 *
 * The exported values are RAW JavaScript SOURCE strings (not executed here),
 * interpolated verbatim into each page's inline script. Keep them dependency
 * free and side-effect free.
 */

/**
 * The agent Standing pill: the most-screenshotted honesty surface (#634).
 *
 * GREEN ("enforcement active") is earned ONLY by CONFIRMED live enforcement for
 * the agent (`enforcement_active === "active"`). A policy-protected agent whose
 * enforcement we cannot observe is amber "protection requested", never green. A
 * no-longer-protected agent (mid-unwrap, or observed not enforcing) is red. Both
 * the Home grid and the drill-down Standing section render this exact function,
 * so neither surface can weaken the color model independently. A test pins the
 * two interpolations byte-identical (#641).
 */
export const AGENT_PILL_FN_SOURCE = `function agentPill(row) {
    if (row.enforcement_active === "active")
      return '<span class="pill green">enforcement active</span>';
    if (row.policy_protected && row.enforcement_active !== "active")
      return '<span class="pill amber">protection requested</span>';
    return '<span class="pill red">not enforcing</span>';
  }`;
