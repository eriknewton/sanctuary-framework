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
 * The shared relative-time formatter for freshness stamps ("checked 14s ago").
 *
 * S3 evidence spine: every posture claim on screen should say how recently it
 * was checked, and a freshness stamp is only trustworthy if it means the same
 * thing on every surface. Four near-identical `Ns/m/h/d ago` ladders already
 * existed in this codebase with divergent null/NaN handling; this constant is
 * the single source the posture pages interpolate so the wording of "how fresh"
 * cannot drift per surface.
 *
 * Honesty contract, and the reason this is NOT a copy of the v1.1 client's
 * `relTimeFromIso`: an absent or unparseable timestamp returns the EMPTY string,
 * never the raw input and never a fabricated age. Call sites are responsible for
 * rendering an explicit "no evidence yet" when they get "" back, so a missing
 * check can never be mistaken for a recent one. `Math.max(0, ...)` clamps a
 * future-dated timestamp (clock skew) to "0s ago" rather than a negative age.
 */
export const REL_TIME_FN_SOURCE = `function relTime(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    var sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
    if (sec < 60) return sec + "s ago";
    var min = Math.floor(sec / 60);
    if (min < 60) return min + "m ago";
    var hr = Math.floor(min / 60);
    if (hr < 24) return hr + "h ago";
    return Math.floor(hr / 24) + "d ago";
  }`;

/**
 * The shared design-token block for the three posture pages (Home, per-agent
 * drill-down, Evidence view). This is a re-export of the canonical "paper/ink"
 * token block, `PAPER_INK_ROOT_TOKENS_CSS` in
 * `server/src/dashboard/design-tokens.ts`.
 *
 * SCOPE, precisely: the surfaces that interpolate that constant are the v1.1
 * board (`dashboard/v1_1/html.ts`), the mobile view (`dashboard/mobile.ts`),
 * the login page and the Fleet Switcher (both in
 * `principal-policy/dashboard-html.ts`), and these three posture pages. That
 * is NOT every page this server serves: `generateDashboardHTML` (the approval
 * board, same file as the login page) still declares its own legacy
 * GitHub-dark `:root`, and one name, `--surface`, exists in both systems at
 * different values. The note above that block is the authoritative warning;
 * do not read this comment as a claim that the token system is universal.
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

/**
 * The shared evidence-spine CSS: the denominator, freshness stamp, and
 * evidence-link treatments that hang off a posture tile or panel row.
 *
 * S3 makes three things visible on every claim the pages already have data for:
 * a denominator ("2 of 3"), a freshness stamp ("checked 14s ago"), and a link
 * to the evidence behind the number. The denominator renders in a lighter,
 * smaller sans face beside the value so the big number still reads first;
 * the freshness stamp is mono (it is a measurement, not prose); the evidence
 * link uses the informational indigo, never a status hue, so it can never be
 * mistaken for a state signal.
 *
 * `--slate` is deliberate for `.stat-fresh.none`: an absent freshness stamp is
 * the unknown treatment, not a warning and never a pass.
 */
export const EVIDENCE_SPINE_CSS = `.stat-of {
    font-size: 11px; font-weight: 400; color: var(--ink-3); margin-left: 4px;
    font-variant-numeric: tabular-nums;
  }
  .stat-foot {
    margin-top: auto; padding-top: 6px; display: flex; align-items: baseline;
    justify-content: space-between; gap: 8px; flex-wrap: wrap;
  }
  .stat-fresh { font-family: var(--mono, monospace); font-size: 10px; color: var(--ink-4, var(--ink-3)); white-space: nowrap; }
  .stat-fresh.none { color: var(--slate); }
  .stat-ev { font-size: 10.5px; color: var(--indigo); text-decoration: none; white-space: nowrap; }
  .stat-ev:hover { text-decoration: underline; }`;
