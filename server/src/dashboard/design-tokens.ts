/**
 * Canonical design tokens for the Sanctuary web console: the single source of
 * truth for the console's visual language.
 *
 * Before this module, the token block lived inline in the v1.1 dashboard shell
 * (`dashboard/v1_1/html.ts`), while the posture surfaces
 * (`principal-policy/posture-*-html.ts`) and the Fleet Switcher page
 * (`principal-policy/dashboard-html.ts`) each carried their OWN token block -
 * the posture pages in a generic GitHub-dark palette, the Fleet Switcher in a
 * hand-copied light-only "scoped mirror" with no dark theme. Three visual
 * languages across four surfaces. This constant is the one shared source every
 * console surface interpolates, so the palette, the dark theme, and the
 * type/spacing scale can no longer drift per surface. (It does not reach the
 * legacy approval board; see the collision note below.)
 *
 * VALUES (2026-10-12). The values are the ratified console design system: a
 * cool navy-and-white palette with a green/amber/red/gray/violet status set, a
 * reserved five-step severity ramp, an egress chart pair, and three bundled
 * faces (Manrope for interface text, Space Grotesk for headings and big
 * numerals, Roboto Mono for machine-produced values; see `design-fonts.ts`).
 * The swap changed VALUES only. Every token NAME that shipped before still
 * exists with the same meaning, with three deliberate exceptions a reader must
 * know about:
 *   - `--serif` is now the DISPLAY stack (`var(--display)`, Space Grotesk).
 *     There is no serif face in the console. Every current reader sets a
 *     heading, a name, or a numeral, never running text; prose belongs on
 *     `--sans`. Retire the name once no template reads it.
 *   - `--shadow` is `none`. The console is flat: separation comes from a
 *     `--rule` border, and every surface that read the shadow already draws one.
 *   - `--text-display` is 26px (the tile-value size), down from 36px.
 * Physical names are now partly misnomers (`--sage` is a green, `--ochre` an
 * amber, `--rust` a red, `--indigo` a blue, `--paper` the page ground). They
 * survive because the semantic layer and every template reach them by name;
 * renaming them is a separate mechanical change.
 *
 * The physical ladder also carries:
 *   - `--accent`: the one accent (aliased to `--indigo`), plus `--accent-ink`,
 *     `--accent-hover`, the two accent tints, and `--focus`.
 *   - `--slate` / `--slate-bg`: a true neutral gray for the "unknown /
 *     not monitored" first-class status treatment (see `STATUS_PILL_CSS` in
 *     `posture-html-shared.ts`). Green must mean "checked and passed," never
 *     "no data"; unknown gets its own full-weight gray, not a whisper.
 *   - `--locked` / `--locked-bg`: the fifth status hue (locked down, paused).
 *   - a `-line` chip border per status hue.
 *   - `--ink-line`: the neutral chip border, a SERVER-ONLY name. The design
 *     sets the neutral border as a per-theme hex directly on
 *     `--color-status-neutral-line`; the server names that value `--ink-line`
 *     so the semantic alias resolves to a physical token like every other
 *     alias (the plain-`var()` rule at the alias layer). The light and dark
 *     values are the design's two neutral-line values; one extra name here
 *     that the design's file does not declare.
 *   - `--sev-*`: the severity ramp, reserved for severity marks.
 *   - `--chart-allowed` / `--chart-blocked`: the egress chart pair.
 *
 * On top of that physical ladder sits a SEMANTIC alias layer (the
 * `--color-*` names at the end of the `:root` block). It encodes the paragraph
 * above in token names instead of prose: `unknown` has its own name and its own
 * hue, so a surface with no result never has to borrow the pass color. Every
 * alias is a plain `var()` of a physical token; the rationale and the
 * per-element `var()` mechanics are at the enforcement site itself.
 *
 * NOT DECLARED HERE: the design system's component alias block (`--bg`,
 * `--text`, `--border`, `--radius-*`, `--font-*`, `--space-tight` and the
 * rest), which maps the design's preview names onto these server names. The
 * legacy approval board and the pre-v1.1 dashboard (`dashboard/html.ts`) each
 * define their own `--bg` and `--border`; the alias block would repaint them
 * the moment any page carried both. It lands only after those boards are
 * retired or renamed.
 *
 * Consumed as a RAW CSS string interpolated verbatim into each page's inline
 * `<style>` tag. Keep it dependency free and side-effect free.
 *
 * IN-REPO CONSUMERS (each interpolates this constant and declares no `:root` of
 * its own; each also interpolates `CONSOLE_FONT_FACE_CSS` from
 * `design-fonts.ts` so the named faces resolve): `dashboard/v1_1/html.ts`,
 * `dashboard/mobile.ts`, `principal-policy/posture-html-shared.ts`
 * (re-exported as `POSTURE_ROOT_TOKENS_CSS`), and
 * `principal-policy/dashboard-html.ts` in `generateLoginHTML` and
 * `generateFleetSwitcherHTML`. That list is exhaustive: this constant is NOT
 * the source for every page the server serves.
 *
 * ONE SURFACE IS STILL OUTSIDE THIS SYSTEM: `generateDashboardHTML` in
 * `principal-policy/dashboard-html.ts` carries its own GitHub-dark `:root`
 * (`--bg`, `--green`, `--red`, `--blue`, ...). That is the legacy
 * approval-channel board; porting it is a visual change and is deliberately NOT
 * part of this token work. Do not read the pin above as covering it.
 *
 * ONE TOKEN NAME COLLIDES ACROSS THE TWO SYSTEMS: `--surface`. The legacy board
 * defines it as `#161b22`; this constant defines it as `#ffffff` (light) and
 * `#121825` (dark). Every other legacy name (`--bg`, `--border`,
 * `--text-primary`, `--green`, ...) is absent here, so `--surface` is the one
 * place a partial merge of the two blocks silently recolors cards instead of
 * failing loudly. The same warning is pinned at the legacy block itself; the
 * two must keep agreeing.
 *
 * OUT-OF-BUILD MIRRORS. Two files outside this module's import graph hand-copy
 * a SUBSET of these values and must match them:
 *   - `server/docs/design-refs/sprint-piece-2/tokens.css` (static design
 *     reference; no build step reads this constant)
 *   - `menubar/src/styles/popover.css` (separate Tauri/menubar build)
 * Both carry a "must match `PAPER_INK_ROOT_TOKENS_CSS` in this file" pin. Both
 * were re-copied to the 2026-10-12 values in the same change as this block;
 * neither mirrors the semantic `--color-*` layer, the status `-line`, locked,
 * severity, or chart tokens, because neither surface renders them today.
 * Neither bundles the faces, so both fall back to the system stacks named
 * after them. Changing a value here means changing it in both mirrors in the
 * SAME PR.
 *
 * `test/structure/design-token-mirror-reconciliation.test.ts` is the gate for
 * all of the above: it reparses both mirrors and fails on any token they share
 * with this constant at a different value. Without it a drifted mirror
 * compiles, renders, and looks almost right, which is exactly how it goes
 * unnoticed.
 */
export const PAPER_INK_ROOT_TOKENS_CSS = `:root {
  /* Physical ladder, light theme. Values are the ratified 2026-10-12 console
     design system; the contrast figures quoted below are WCAG ratios measured
     on --surface unless another fill is named. */
  --paper: #f4f6fa;
  --paper-2: #eef1f7;
  --paper-3: #e6eaf2;
  --ink: #0f172a;
  --ink-2: #4b5566;
  /* Tertiary text: table headers, section labels, hints, evidence ages,
     timestamps, footers, message meta, input placeholders. Stepped so 11px
     text clears 4.5:1 on every fill it sits on, the active rail fill
     included. */
  --ink-3: #5e6879;
  /* Disabled labels, plus non-text marks (a dot, bar or ring for an off,
     pending or empty state) whose meaning a word or title beside them
     carries. Below the 4.5:1 text floor on purpose: WCAG exempts disabled
     controls, and a mark that only repeats its word conveys nothing alone.
     Never text a person must read: ages, timestamps, footers, meta lines,
     section labels and placeholders use --ink-3, and the unknown status uses
     --slate. */
  --ink-4: #a3abba;
  --rule: #d9dee9;
  /* Control borders. Below the 3:1 non-text floor for a control boundary
     today; raising it recolors every control and is an open design item. */
  --rule-2: #c5ccdc;
  --surface: #ffffff;
  --surface-2: #eef1f7;
  /* Status hues. Each pair is the chip text color and its tint; the chip text
     clears 4.5:1 on its own tint. A status is never told by color alone: every
     chip also carries a fixed glyph shape and an uppercase word. */
  --sage: #037949;
  --sage-bg: #e1efe9;
  --sage-line: #9ac9b6;
  --ochre: #8b6508;
  --ochre-bg: #f1ede1;
  --ochre-line: #d1c19c;
  --rust: #c72647;
  --rust-bg: #f8e5e9;
  --rust-line: #e9a8b5;
  --indigo: #2f63e8;
  --indigo-bg: #eaeffd;
  /* Unknown has its own gray and is never green: "no answer arrived" must not
     borrow the pass hue, because a green with no evidence behind it reads as
     protection that was never checked. Full weight, never dimmed, never
     hidden, never counted as protected; told apart from the neutral gray by
     its dotted ring (the neutral pill's ring is solid), its dashed border,
     its tint and its word. */
  --slate: #60697d;
  --slate-bg: #e9eaed;
  --slate-line: #b7bcc5;
  /* The fifth status: locked down or paused. */
  --locked: #7c4dd9;
  --locked-bg: #efeafa;
  --locked-line: #cbb8f0;
  /* Border of a neutral chip, in the -line pattern after the --ink-3 text the
     neutral status draws from. Server-only name for the design's neutral
     border value (see the header). No consumer draws it yet; it is declared
     for the shell restyle, like the other -line borders. */
  --ink-line: #bcc2cf;
  /* The one accent: links, focus, selection, the primary button fill, the
     active rail marker. Never a status. */
  --accent-ink: #ffffff;
  --accent-hover: #1f4fc9;
  /* Active rail item fill (accent at 14% over surface, flattened); row hover
     (accent at 5%). The selected-row fill is --indigo-bg (accent at 10%). */
  --accent-tint-strong: #e2e9fc;
  --accent-tint-faint: #f5f7fe;
  /* Severity ramp, levels 1 to 5. RESERVED for severity marks (the 4px bar and
     glyph beside a finding): never a status, never a chart series, never a
     button. The ramp is validated as an ordered scale against the status hues,
     so borrowing one of these as a state color would put two meanings on one
     hue. Every bar clears the 3:1 mark floor on --paper, --surface,
     --surface-2, the selected-row fill and the hover fill; no mark sits on the
     active rail fill. The word beside the bar carries the level; in light the
     word is --ink-2 for every level, because reds, oranges and ambers darkened
     to text contrast converge into browns. */
  --sev-critical: #d93a55;
  --sev-high: #974b14;
  --sev-medium: #ab8300;
  --sev-low: #137ce4;
  --sev-info: #7d8798;
  --sev-critical-text: var(--ink-2);
  --sev-high-text: var(--ink-2);
  --sev-medium-text: var(--ink-2);
  --sev-low-text: var(--ink-2);
  --sev-info-text: var(--ink-2);
  /* Egress chart pair, teal allowed and red blocked, validated as a
     categorical pair. The chart sits on --surface only: light allowed is
     under the 3:1 mark floor on --surface-2 and --paper. */
  --chart-allowed: #0a9fa5;
  --chart-blocked: #9e1c38;
  /* End color of the one permitted gradient, the product mark (accent to this
     at 135deg). Nowhere else. */
  --mark-teal: #2fd4c8;
  --accent: var(--indigo);
  /* Keyboard focus ring: 2px solid, 2px offset. */
  --focus: var(--accent);
  /* Faces. Each stack names the bundled face first (CONSOLE_FONT_FACE_CSS in
     design-fonts.ts) and the previous system stack after it, so a page that
     does not load the faces, or a face that fails to decode, still renders in
     the system stack. Mono is for anything a machine produced: identifiers,
     hashes, destinations, ages, counts. */
  --mono: "Roboto Mono", ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: "Manrope", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  /* Headings and big numerals only; never running text. */
  --display: "Space Grotesk", "Manrope", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  /* Legacy name for the heading face. There is no serif in the console; every
     reader sets a heading, a name, or a numeral. Point prose at --sans. */
  --serif: var(--display);
  --rad: 6px;
  --rad-lg: 10px;
  /* The console is flat: borders, not shadows. A surface that needs
     separation draws a 1px --rule border. */
  --shadow: none;
  /* Type scale. Names are size-relative, not semantic, so refactors do
     not need to invent new names. Existing rules used these literal px
     values; tokens make future polish a one-line change. */
  --text-xs: 11px;
  --text-sm: 12px;
  /* 12.5px: the one size between the 12px and 13px steps. Table cells, drawer
     paragraphs, key-value lists, and mono values inside a cell. */
  --text-cell: 12.5px;
  --text-base: 13px;
  --text-md: 14px;
  --text-lg: 16px;
  --text-xl: 22px;
  /* Tile values and the big counts, always beside a denominator. */
  --text-display: 26px;
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

     Why the layer is worth its lines: the status set has six members (pass,
     attention, fault, neutral, unknown, locked), and "unknown" is one of
     them, with its own hue and its own name. Green must mean "checked and
     passed," never "no data." A surface with no result has
     --color-status-unknown to reach for, so it never has to borrow the pass
     color for want of a token. Five members are wired to .pill classes in
     STATUS_PILL_CSS in principal-policy/posture-html-shared.ts (green, amber,
     red, neutral, unknown). Locked is declared here for the shell restyle and
     has no consumer yet: the v1.1 .pill.tone-locked, .posture-seal.tone-locked
     and .ambient-seal.tone-locked rules all still paint the fault red until
     that slice.

     Every alias resolves to a physical token declared above, never to a
     literal. var() substitution is computed per element, and the dark palette
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
  --color-status-neutral-line: var(--ink-line);
  --color-status-unknown: var(--slate);
  --color-status-unknown-bg: var(--slate-bg);
  --color-status-locked: var(--locked);
  --color-status-locked-bg: var(--locked-bg);
  /* Informational, never a status hue: an evidence link must not be readable
     as a state signal (see EVIDENCE_SPINE_CSS in posture-html-shared.ts). */
  --color-info: var(--indigo);
  --color-info-bg: var(--indigo-bg);
  --color-text-primary: var(--ink);
  --color-text-secondary: var(--ink-2);
  --color-text-muted: var(--ink-3);
  --color-text-faint: var(--ink-4);
  /* Surfaces are named by role, not by elevation. The physical ladder does not
     keep one elevation order across themes, so "raised"/"sunken" would be true
     in one theme and false in the other. */
  --color-surface-page: var(--paper);
  --color-surface-card: var(--surface);
  --color-surface-subtle: var(--surface-2);
  --color-border: var(--rule);
  --color-border-strong: var(--rule-2);
}
[data-theme="dark"] {
  --paper: #0b0f17;
  --paper-2: #0f141e;
  --paper-3: #121825;
  --ink: #e8ecf4;
  --ink-2: #a3adc2;
  --ink-3: #8791a5;
  --ink-4: #4e5870;
  --rule: #243049;
  --rule-2: #2f3c57;
  --surface: #121825;
  --surface-2: #182032;
  --sage: #2fd08a;
  --sage-bg: #152e31;
  --sage-line: #1e624d;
  --ochre: #f2c14e;
  --ochre-bg: #2d2c2a;
  --ochre-line: #6c5c35;
  --rust: #ff5c7a;
  --rust-bg: #2e202f;
  --rust-line: #713347;
  --indigo: #5b8cff;
  --indigo-bg: #19243b;
  --slate: #8a94a8;
  --slate-bg: #232937;
  --slate-line: #485060;
  --locked: #b48cff;
  --locked-bg: #25263f;
  --locked-line: #53467c;
  --ink-line: #414c64;
  --accent-ink: #0b0f17;
  --accent-hover: #86abff;
  --accent-tint-strong: #1c2844;
  --accent-tint-faint: #161e30;
  /* Dark severity words wear the hue for Critical, High and Low (each clears
     4.5:1 on --surface). Medium's lemon bar would outshine Critical and High
     as a word, and Info's gray is a mark-only value, so both words stay
     --ink-2. */
  --sev-critical: #ff4d6d;
  --sev-high: #e58212;
  --sev-medium: #fffd4b;
  --sev-low: #8ac3fc;
  --sev-info: #6a768c;
  --sev-critical-text: var(--sev-critical);
  --sev-high-text: var(--sev-high);
  --sev-medium-text: var(--ink-2);
  --sev-low-text: var(--sev-low);
  --sev-info-text: var(--ink-2);
  --chart-allowed: #0a989c;
  --chart-blocked: #e3526c;
  --mark-teal: #2fd4c8;
}`;

/**
 * Theme bootstrap for the console's web pages: the STANDALONE pages (posture
 * Home / per-agent / Evidence, and the Fleet Switcher) that do not embed the
 * v1.1 client module, and the v1.1 shell's own head, so its first paint
 * already wears the right theme.
 *
 * The paper/ink token block declares the light palette on `:root` and the
 * dark palette under `[data-theme="dark"]`. The ratified console is DARK BY
 * DEFAULT (2026-10-13): with no explicit choice the page is dark, whatever the
 * OS reports; an explicit "light" choice, written by the dashboard's theme
 * toggle to `sessionStorage["sanctuary-v11-theme"]`, still wins. The same key
 * is read here so a dashboard choice carries across pages (same origin). The
 * prefers-color-scheme preference no longer selects light. Storage that
 * throws is the same as no choice: dark.
 *
 * Must match the theme fallback in `dashboard/v1_1/client.ts` (the
 * `THEME_KEY` block near its end): both read the same key and both resolve
 * "no explicit choice" to dark.
 *
 * Read-only and side-effect free beyond setting the attribute; it never
 * writes the key (only the dashboard's toggle does), so it cannot fight the
 * toggle. Interpolated verbatim into a `<script>` tag in each page's `<head>`
 * so the attribute is set before first paint (no flash of the wrong theme).
 */
export const THEME_BOOTSTRAP_SCRIPT = `(function () {
  try {
    if (sessionStorage.getItem("sanctuary-v11-theme") === "light") return;
  } catch (e) { /* storage blocked: no explicit choice, so the dark default */ }
  document.documentElement.setAttribute("data-theme", "dark");
})();`;
