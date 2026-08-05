/**
 * Canonical "paper/ink" design tokens - the single source of truth for the
 * web console's visual language.
 *
 * Before this module, the paper/ink `:root` token block lived inline in the
 * v1.1 dashboard shell (`dashboard/v1_1/html.ts`), while the posture surfaces
 * (`principal-policy/posture-*-html.ts`) and the Fleet Switcher page
 * (`principal-policy/dashboard-html.ts`) each carried their OWN token block -
 * the posture pages in a generic GitHub-dark palette, the Fleet Switcher in a
 * hand-copied light-only "scoped mirror" with no dark theme. Three visual
 * languages across four surfaces. This constant promotes the v1.1 block to the
 * one shared source every web surface interpolates, so the palette, the warm
 * dark theme, and the type/spacing scale can no longer drift per surface.
 *
 * The block is a byte-faithful extraction of the tokens that already shipped on
 * the v1.1 board, with two additive tokens the audit called out:
 *   - `--accent`: a real accent token (aliased to `--indigo`). Fixes the v1.1
 *     `var(--accent, #58a6ff)` leak, where an undefined accent fell back to a
 *     GitHub blue that did not belong to the paper/ink system.
 *   - `--slate` / `--slate-bg`: a true neutral gray for the "unknown /
 *     not monitored" first-class status treatment (see `STATUS_PILL_CSS` in
 *     `posture-html-shared.ts`). Green must mean "checked and passed," never
 *     "no data"; unknown gets its own full-weight gray, not a whisper.
 *
 * On top of that physical ladder sits a SEMANTIC alias layer (the
 * `--color-*` names at the end of the `:root` block). It encodes the paragraph
 * above in token names instead of prose: `unknown` has its own name and its own
 * hue, so a surface with no result never has to borrow the pass color. The
 * aliases are additive and change no rendered value; the rationale and the
 * per-element `var()` mechanics are at the enforcement site itself.
 *
 * Consumed as a RAW CSS string interpolated verbatim into each page's inline
 * `<style>` tag. Keep it dependency free and side-effect free.
 *
 * IN-REPO CONSUMERS (all interpolate this constant and declare no `:root` of
 * their own): `dashboard/v1_1/html.ts`, `dashboard/mobile.ts`,
 * `principal-policy/posture-html-shared.ts` (re-exported as
 * `POSTURE_ROOT_TOKENS_CSS`), and `principal-policy/dashboard-html.ts` in
 * `generateLoginHTML` and `generateFleetSwitcherHTML`.
 *
 * ONE SURFACE IS STILL OUTSIDE THIS SYSTEM: `generateDashboardHTML` in
 * `principal-policy/dashboard-html.ts` carries its own GitHub-dark `:root`
 * (`--bg`, `--green`, `--red`, `--blue`, ...) with no paper/ink token in it.
 * That is the legacy approval-channel board; porting it is a visual change and
 * is deliberately NOT part of this token work. Do not read the pin above as
 * covering it.
 *
 * OUT-OF-BUILD MIRRORS. Two files outside this module's import graph hand-copy
 * a SUBSET of these values and must match them:
 *   - `server/docs/design-refs/sprint-piece-2/tokens.css` (static design
 *     reference; no build step reads this constant)
 *   - `menubar/src/styles/popover.css` (separate Tauri/menubar build)
 * Both carry a "must match `PAPER_INK_ROOT_TOKENS_CSS` in this file" pin. Both
 * are value-faithful subsets as of 2026-08-04 (verified token by token, zero
 * value drift); neither mirrors the semantic `--color-*` layer, and neither
 * mirrors `--slate`/`--slate-bg`, because neither surface renders an unknown
 * status today. Changing a value here means changing it in both mirrors in the
 * SAME PR. Nothing enforces this mechanically: a drifted mirror compiles,
 * renders, and looks almost right, which is exactly how it goes unnoticed.
 */
export const PAPER_INK_ROOT_TOKENS_CSS = `:root {
  --paper: #f7f5f0;
  --paper-2: #efece5;
  --paper-3: #e6e3da;
  --ink: #1a1a17;
  --ink-2: #39362f;
  --ink-3: #6a6659;
  --ink-4: #9a9585;
  --rule: #d8d4c8;
  --rule-2: #c4bfb0;
  --surface: #fdfcf8;
  --surface-2: #f1eee6;
  --sage: oklch(62% 0.07 145);
  --sage-bg: oklch(94% 0.02 145);
  --ochre: oklch(68% 0.09 75);
  --ochre-bg: oklch(94% 0.03 75);
  --rust: oklch(55% 0.11 35);
  --rust-bg: oklch(94% 0.03 35);
  --indigo: oklch(50% 0.10 260);
  --indigo-bg: oklch(94% 0.03 260);
  --slate: oklch(50% 0.015 260);
  --slate-bg: oklch(92% 0.005 260);
  --accent: var(--indigo);
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  --serif: "Iowan Old Style", "Charter", "Georgia", serif;
  --rad: 6px;
  --rad-lg: 10px;
  --shadow: 0 1px 2px rgba(0,0,0,0.04), 0 0 0 1px rgba(0,0,0,0.02);
  /* Type scale. Names are size-relative, not semantic, so refactors do
     not need to invent new names. Existing rules used these literal px
     values; tokens make future polish a one-line change. */
  --text-xs: 11px;
  --text-sm: 12px;
  --text-base: 13px;
  --text-md: 14px;
  --text-lg: 16px;
  --text-xl: 22px;
  --text-display: 36px;
  /* Spacing scale (4px multiples). Layout-specific magic numbers
     (220px sidebar, 360px fortress rail, concierge-card heights) stay
     as literals because the token system is for component padding /
     margin / gap, not grid track sizing. */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 24px;
  --space-6: 32px;
  /* Semantic alias layer. Everything above is PHYSICAL: the name says what the
     value looks like (--sage, --ink-3, --surface-2). Everything below is
     SEMANTIC: the name says what the value MEANS. Component CSS should reach
     for the semantic name so the status vocabulary this system enforces is
     legible in the stylesheet rather than only in the prose above.

     Why the alias layer exists rather than a comment: the status set has five
     members and "unknown" is one of them, with its own hue and its own name.
     Green must mean "checked and passed," never "no data." A surface with no
     result has --color-status-unknown to reach for, so it never has to borrow
     the pass color for want of a token. The wired mapping of these five onto
     .pill classes is STATUS_PILL_CSS in
     principal-policy/posture-html-shared.ts.

     Aliases are strictly ADDITIVE: each resolves to a physical token declared
     above, so introducing them changes no rendered value on any surface.
     var() substitution is computed per element, and the dark palette
     redeclares the physical tokens on this same element (html), so an alias
     declared once here tracks the theme with no dark-block counterpart. Same
     mechanism as --accent: var(--indigo) above; that is why the dark block
     below repeats no alias.

     This comment lives inside a TypeScript template literal: no backticks and
     no dollar-brace here, or the CSS string terminates mid-block. */
  --color-status-pass: var(--sage);
  --color-status-pass-bg: var(--sage-bg);
  --color-status-attention: var(--ochre);
  --color-status-attention-bg: var(--ochre-bg);
  --color-status-fault: var(--rust);
  --color-status-fault-bg: var(--rust-bg);
  --color-status-neutral: var(--ink-3);
  --color-status-neutral-bg: var(--surface-2);
  --color-status-unknown: var(--slate);
  --color-status-unknown-bg: var(--slate-bg);
  /* Informational, never a status hue: an evidence link must not be readable
     as a state signal (see EVIDENCE_SPINE_CSS in posture-html-shared.ts). */
  --color-info: var(--indigo);
  --color-info-bg: var(--indigo-bg);
  --color-text-primary: var(--ink);
  --color-text-secondary: var(--ink-2);
  --color-text-muted: var(--ink-3);
  --color-text-faint: var(--ink-4);
  /* Surfaces are named by role, not by elevation. The physical ladder inverts
     between themes (in light, --surface is lighter than --surface-2; in dark it
     is darker), so "raised"/"sunken" would be true in one theme and false in
     the other. */
  --color-surface-page: var(--paper);
  --color-surface-card: var(--surface);
  --color-surface-subtle: var(--surface-2);
  --color-border: var(--rule);
  --color-border-strong: var(--rule-2);
}
[data-theme="dark"] {
  --paper: #121210;
  --paper-2: #171714;
  --paper-3: #1e1e1b;
  --ink: #ecebe5;
  --ink-2: #c7c5bd;
  --ink-3: #8d8a80;
  --ink-4: #5e5c55;
  --rule: #2a2a26;
  --rule-2: #36352f;
  --surface: #1a1a17;
  --surface-2: #1f1e1a;
  --sage: oklch(72% 0.08 145);
  --sage-bg: oklch(22% 0.03 145);
  --ochre: oklch(78% 0.09 75);
  --ochre-bg: oklch(22% 0.04 75);
  --rust: oklch(70% 0.11 35);
  --rust-bg: oklch(22% 0.04 35);
  --indigo: oklch(72% 0.09 260);
  --indigo-bg: oklch(22% 0.03 260);
  --slate: oklch(72% 0.01 260);
  --slate-bg: oklch(23% 0.005 260);
}`;

/**
 * Theme bootstrap for the STANDALONE web pages (posture Home / per-agent /
 * Evidence, and the Fleet Switcher) that do not embed the v1.1 client module.
 *
 * The paper/ink token block defaults to the light `:root` palette and applies
 * the warm dark palette under `[data-theme="dark"]`. The v1.1 dashboard sets
 * that attribute from its own client (an explicit toggle written to
 * `sessionStorage["sanctuary-v11-theme"]`, falling back to the OS preference).
 * These standalone pages have no client module, so without this bootstrap they
 * would render light-only and visibly diverge from a dark dashboard. This tiny
 * head script reuses the SAME storage key so an explicit dashboard choice
 * carries across (same origin), and otherwise follows the OS preference. It is
 * read-only and side-effect free beyond setting the attribute; it never writes
 * the key (only the dashboard's toggle does), so it cannot fight the toggle.
 *
 * Interpolated verbatim into a `<script>` tag in each page's `<head>` so the
 * attribute is set before first paint (no flash of the wrong theme).
 */
export const THEME_BOOTSTRAP_SCRIPT = `(function () {
  try {
    var choice = sessionStorage.getItem("sanctuary-v11-theme");
    if (choice === "dark" || choice === "light") {
      if (choice === "dark") document.documentElement.setAttribute("data-theme", "dark");
      return;
    }
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      document.documentElement.setAttribute("data-theme", "dark");
    }
  } catch (e) { /* storage blocked: fall through to light default */ }
})();`;
