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

import { PAPER_INK_ROOT_TOKENS_CSS } from "../dashboard/design-tokens.js";

export { PAPER_INK_ROOT_TOKENS_CSS, THEME_BOOTSTRAP_SCRIPT } from "../dashboard/design-tokens.js";

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
 * The shared design-token block for the three posture pages (Home, per-agent
 * drill-down, Evidence view). This is now the canonical "paper/ink" token
 * block - the SAME `PAPER_INK_ROOT_TOKENS_CSS` the v1.1 dashboard and the Fleet
 * Switcher interpolate - so all four web surfaces speak one visual language.
 *
 * Before this change the three posture pages carried a generic GitHub-dark
 * palette (`--bg: #0e1116; --green: #2ea043; --accent: #58a6ff; ...`) that read
 * as a developer default and diverged from the v1.1 board's warm paper/ink
 * system. Porting them onto the shared block is the S1 "one token system" work:
 * the pages' component CSS now references the paper/ink token names
 * (`--paper`, `--surface`, `--rule`, `--ink`, `--ink-3`, `--sage`, `--ochre`,
 * `--rust`, `--indigo`) directly, and the standalone pages carry a small theme
 * bootstrap (`THEME_BOOTSTRAP_SCRIPT`) so they follow the dashboard's light/dark
 * choice instead of rendering a single fixed theme.
 *
 * A test (`posture-html-shared.test.ts`) pins the rendered `:root` block on all
 * three pages equal to the shared constant, so a future token change can no
 * longer land on only one of the surfaces.
 */
export const POSTURE_ROOT_TOKENS_CSS = PAPER_INK_ROOT_TOKENS_CSS;

/**
 * The shared status-pill CSS for the posture surfaces. Before this change each
 * of the three pages hand-copied a nearly identical `.pill` rule set inline;
 * this constant is the single source all three interpolate.
 *
 * Two additions the design audit called for, on top of the paper/ink recolor:
 *
 *   - **Color + shape redundancy.** Every status pill carries a leading glyph
 *     (filled circle = good, triangle = attention, hexagon = fault, open circle
 *     = neutral, dashed ring = unknown), so state is legible without color for
 *     colorblind and projector viewing. The glyph is injected by CSS `::before`,
 *     so the honesty mappers' emitted markup (`<span class="pill green">...`) is
 *     byte-unchanged - the pinned mapper sources cannot drift from this.
 *
 *   - **The slate "unknown / not monitored" treatment.** A full-weight neutral
 *     gray with a dashed ring - never a whisper, never mistaken for green.
 *     "Green must mean checked-and-passed, never no-data." Available here for
 *     surfaces that render an unknown status (wired incrementally); adding the
 *     treatment does not itself change any mapper's color model.
 *
 * Glyphs are written as CSS unicode escapes so this source stays ASCII-clean.
 */
export const STATUS_PILL_CSS = `.pill {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    white-space: nowrap;
  }
  .pill::before { font-size: 9px; line-height: 1; }
  .pill.green { background: var(--sage-bg); color: var(--sage); }
  .pill.green::before { content: "\\25CF"; }
  .pill.amber { background: var(--ochre-bg); color: var(--ochre); }
  .pill.amber::before { content: "\\25B2"; }
  .pill.red { background: var(--rust-bg); color: var(--rust); }
  .pill.red::before { content: "\\2B22"; }
  .pill.neutral { background: var(--surface-2); color: var(--ink-3); }
  .pill.neutral::before { content: "\\25CB"; }
  .pill.unknown { background: var(--slate-bg); color: var(--slate); border: 1px dashed var(--slate); }
  .pill.unknown::before { content: "\\25CC"; }`;
