/**
 * Shared client-side HTML/CSS fragments for the posture surfaces.
 *
 * The posture Home page (`posture-home-html.ts`), the per-agent drill-down
 * (`posture-agent-html.ts`), and the Evidence view (`posture-evidence-html.ts`)
 * are each self-contained HTML strings with an inline `<style>` and, for two of
 * them, an inline `<script>`. A few honesty-critical client functions and the
 * shared design-token block MUST be byte-identical across surfaces so neither
 * the "never fake green" contract nor the visual language can silently drift on
 * one copy. This module is the single source of truth for those fragments: all
 * three renderers interpolate the exported constants instead of hand-copying
 * the function body or the token block.
 *
 * The exported JS-source values are RAW JavaScript SOURCE strings (not executed
 * here), interpolated verbatim into each page's inline script. The exported CSS
 * value is a RAW CSS string interpolated verbatim into each page's inline
 * `<style>` tag. Keep them dependency free and side-effect free.
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

/**
 * The shared `:root` CSS custom-property block for the three posture pages
 * (Home, per-agent drill-down, Evidence view). Pure refactor: before this
 * change each of `posture-home-html.ts`, `posture-agent-html.ts`, and
 * `posture-evidence-html.ts` hand-copied an identical `:root { ... }` block
 * inline in its `<style>` tag. Copy-pasted design tokens drift silently the
 * first time someone tweaks a color on one page and forgets the other two;
 * this constant is now the single source all three interpolate, so a future
 * token change can no longer land on only one of the three surfaces.
 *
 * This is a byte-for-byte extraction of the block that already shipped on
 * all three pages: no color, spacing, or property changed. A test
 * (`posture-html-shared.test.ts`) pins the rendered `:root` block on all three
 * pages equal to a captured baseline of the pre-refactor output, so this
 * extraction cannot silently change what ships.
 */
export const POSTURE_ROOT_TOKENS_CSS = `:root {
    --bg: #0e1116; --panel: #161b22; --panel-2: #1c2330; --border: #2a313c;
    --text: #e6edf3; --muted: #9aa6b2; --green: #2ea043; --amber: #d29922;
    --red: #f85149; --accent: #58a6ff;
  }`;
