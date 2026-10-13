/**
 * Design-token mirror reconciliation guard.
 *
 * This file carried a `fail-before-exempt` marker when it was first pushed,
 * claiming there was no pre-fix state in which it failed. That was WRONG, and
 * an adversarial review caught it. Measured against pre-fix source it fails:
 *
 *   - 4 of 12 against a full `origin/main` archive: both "carries the
 *     must-match pin" assertions (the pins did not exist yet) plus the two
 *     alias assertions (the `--color-*` layer did not exist yet).
 *   - 2 of 12 under CI's actual method, which reverts only `server/src` and
 *     leaves the mirror CSS in place: the two alias assertions.
 *
 * So the exemption was both false and unnecessary, and it is gone. Only the
 * value-drift half of this file describes an invariant that already held; the
 * pin and alias halves are genuinely new. A false exemption is the same class
 * of defect as the stale pin comment this PR exists to fix, which is the reason
 * it is written down here instead of quietly deleted.
 *
 * `PAPER_INK_ROOT_TOKENS_CSS` (server/src/dashboard/design-tokens.ts) is the
 * canonical palette for the paper/ink surfaces. It is not the palette of every
 * page the server serves: the legacy approval board (`generateDashboardHTML`)
 * still runs on its own GitHub-dark `:root`, and this test does not cover it.
 * Two files copy a SUBSET of the canonical values by hand and cannot import the
 * constant:
 *
 *   - server/docs/design-refs/sprint-piece-2/tokens.css: a static design
 *     reference; no build step reads TypeScript.
 *   - menubar/src/styles/popover.css: a separate Tauri build with no import
 *     path into server/src.
 *
 * Both carry a "must match `PAPER_INK_ROOT_TOKENS_CSS`" pin comment. A comment
 * is not a gate: a drifted mirror still parses, still renders, and looks almost
 * right, so the divergence surfaces months later as "the menubar and the console
 * are subtly different colors." This test is the gate the comments describe,
 * modeled on hkdf-registry-reconciliation.test.ts (mechanical scan is the
 * authority, the prose is the index).
 *
 * The contract is SUBSET-with-identical-values, not equality. A mirror is free
 * to omit a token it has no use for; it is NOT free to declare a token the
 * canonical block also declares and give it a different value. Omissions are
 * reported for visibility; only value drift and unexplained mirror-only tokens
 * fail.
 *
 * If this test fails, the fix is to reconcile the value in the SAME PR that
 * changed it, never to relax the assertion.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { PAPER_INK_ROOT_TOKENS_CSS } from "../../src/dashboard/design-tokens.js";

const HERE = fileURLToPath(import.meta.url);
// test/structure/<this file> -> server/ -> repo root. `menubar/` and
// `server/docs/` both hang off the repo root, so the mirrors are resolved from
// there rather than from server/.
const SERVER_DIR = join(HERE, "..", "..", "..");
const REPO_ROOT = join(SERVER_DIR, "..");

type Block = "light" | "dark";
type TokenMap = Record<Block, Record<string, string>>;

/**
 * Parse the `:root` and `[data-theme="dark"]` custom-property blocks out of a
 * CSS string. Comments are stripped first so a token name mentioned inside a
 * pin comment cannot be mistaken for a declaration.
 */
function parseTokens(css: string): TokenMap {
  const stripped = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const out: TokenMap = { light: {}, dark: {} };
  const blockRe = /(:root|\[data-theme="dark"\])\s*\{([^}]*)\}/g;
  let match: RegExpExecArray | null;
  while ((match = blockRe.exec(stripped)) !== null) {
    const block: Block = match[1] === ":root" ? "light" : "dark";
    for (const line of match[2].split("\n")) {
      const decl = line.match(/^\s*(--[\w-]+)\s*:\s*(.+?);\s*$/);
      if (decl) out[block][decl[1]] = decl[2];
    }
  }
  return out;
}

const CANONICAL = parseTokens(PAPER_INK_ROOT_TOKENS_CSS);

/**
 * Tokens a mirror may declare that the canonical block does not. Each entry is
 * a decision, not a backlog item: adding one means the mirror owns a value the
 * product surfaces have no counterpart for. Keep this list near-empty.
 */
const MIRROR_ONLY_ALLOWED: Record<string, Record<string, string>> = {
  "server/docs/design-refs/sprint-piece-2/tokens.css": {
    "--space-7": "the design reference lays out a 48px step the shipped surfaces never use",
  },
  "menubar/src/styles/popover.css": {},
};

const MIRRORS = [
  "server/docs/design-refs/sprint-piece-2/tokens.css",
  "menubar/src/styles/popover.css",
] as const;

describe("design-token mirrors reconcile with the canonical paper/ink constant", () => {
  it("the canonical constant parses into both a light and a dark block", () => {
    // Guards the parser itself: if this regressed to zero tokens, every
    // subset assertion below would vacuously pass.
    expect(Object.keys(CANONICAL.light).length).toBeGreaterThan(30);
    expect(Object.keys(CANONICAL.dark).length).toBeGreaterThan(15);
    // The ratified 2026-10-12 console page grounds. Must match --paper in
    // PAPER_INK_ROOT_TOKENS_CSS (server/src/dashboard/design-tokens.ts).
    expect(CANONICAL.light["--paper"]).toBe("#f4f6fa");
    expect(CANONICAL.dark["--paper"]).toBe("#0b0f17");
  });

  for (const relPath of MIRRORS) {
    describe(relPath, () => {
      const css = readFileSync(join(REPO_ROOT, relPath), "utf8");
      const mirror = parseTokens(css);
      const allowed = MIRROR_ONLY_ALLOWED[relPath];

      it("carries the must-match pin naming the canonical constant", () => {
        // The pin and this test are the two halves of the same contract; a
        // mirror that loses its pin becomes invisible to the next reader.
        expect(css).toContain("PAPER_INK_ROOT_TOKENS_CSS");
        expect(css).toContain("server/src/dashboard/design-tokens.ts");
      });

      it("declares no token whose value differs from the canonical block", () => {
        const drift: string[] = [];
        for (const block of ["light", "dark"] as const) {
          for (const [name, value] of Object.entries(mirror[block])) {
            if (!(name in CANONICAL[block])) continue;
            if (CANONICAL[block][name] !== value) {
              drift.push(
                `${block} ${name}: canonical=${CANONICAL[block][name]} mirror=${value}`,
              );
            }
          }
        }
        expect(drift).toEqual([]);
      });

      it("declares no unexplained mirror-only token", () => {
        const unexplained: string[] = [];
        for (const block of ["light", "dark"] as const) {
          for (const name of Object.keys(mirror[block])) {
            if (name in CANONICAL[block]) continue;
            if (name in allowed) continue;
            unexplained.push(`${block} ${name}`);
          }
        }
        expect(unexplained).toEqual([]);
      });

      it("mirrors a non-trivial share of the palette in both themes", () => {
        // A mirror that silently emptied out would pass the drift check with
        // nothing to compare, so pin that it still mirrors something real.
        const shared = (block: Block) =>
          Object.keys(mirror[block]).filter((n) => n in CANONICAL[block]).length;
        expect(shared("light")).toBeGreaterThanOrEqual(25);
        expect(shared("dark")).toBeGreaterThanOrEqual(15);
      });
    });
  }
});

describe("semantic alias layer", () => {
  const ALIAS_PREFIX = "--color-";

  it("every semantic alias resolves to a physical token declared in the same block", () => {
    // An alias pointing at a token that does not exist renders as an invalid
    // value and silently falls back to the inherited or initial value, which
    // for a status color means the state stops being distinguishable.
    const dangling: string[] = [];
    for (const [name, value] of Object.entries(CANONICAL.light)) {
      if (!name.startsWith(ALIAS_PREFIX)) continue;
      const target = value.match(/^var\((--[\w-]+)\)$/);
      expect(target, `${name} must be a plain var() alias, got: ${value}`).not.toBeNull();
      const physical = target![1];
      if (!(physical in CANONICAL.light)) dangling.push(`${name} -> ${physical}`);
    }
    expect(dangling).toEqual([]);
  });

  it("the status vocabulary names unknown as a first-class member with its own hue", () => {
    // The module's stated invariant: green must mean "checked and passed,"
    // never "no data." That only holds if a no-data surface has its own token
    // to reach for, and if that token is not an alias of the pass color.
    expect(CANONICAL.light["--color-status-pass"]).toBe("var(--sage)");
    expect(CANONICAL.light["--color-status-unknown"]).toBe("var(--slate)");
    expect(CANONICAL.light["--color-status-unknown"]).not.toBe(
      CANONICAL.light["--color-status-pass"],
    );
    expect(CANONICAL.light["--color-status-unknown-bg"]).not.toBe(
      CANONICAL.light["--color-status-pass-bg"],
    );
    // --slate resolves to a real neutral in BOTH themes; an unknown pill that
    // vanished in dark mode would read as "nothing to report."
    expect(CANONICAL.light["--slate"]).toBeDefined();
    expect(CANONICAL.dark["--slate"]).toBeDefined();
    expect(CANONICAL.dark["--slate"]).not.toBe(CANONICAL.light["--slate"]);
  });

  /**
   * Follow a token's var() chain within one theme to the literal it renders.
   * The dark map is the light block overlaid by the dark block, because the
   * dark block redeclares only physical tokens on the same element and every
   * alias reaches the dark value through that override.
   */
  const themeMap = (block: Block): Record<string, string> =>
    block === "light" ? CANONICAL.light : { ...CANONICAL.light, ...CANONICAL.dark };
  function resolveLiteral(map: Record<string, string>, name: string): string {
    const seen = new Set<string>();
    let current = name;
    for (;;) {
      expect(seen.has(current), `var() cycle through ${current}`).toBe(false);
      seen.add(current);
      const value = map[current];
      expect(value, `${current} is not declared`).toBeDefined();
      const next = value.match(/^var\((--[\w-]+)\)$/);
      if (!next) return value.toLowerCase();
      current = next[1];
    }
  }

  it("the reserved severity ramp and the chart pair are never a status alias", () => {
    // The --sev-* ramp is validated as an ordered scale and the --chart-* pair
    // as a categorical pair, each against the status hues. A status alias that
    // borrowed one would put two meanings on one hue, and the validation that
    // kept them distinguishable would no longer describe what renders. The
    // comparison is on RESOLVED literals per theme, so an alias routed through
    // an intermediate token, or a physical token that copies a ramp literal,
    // fails the same way a direct var(--sev-*) does. The -text tokens are word
    // colors, not ramp hues (light ones are --ink-2), so they are not reserved.
    const RESERVED = /^--(sev|chart)-(?!.*-text$)/;
    for (const block of ["light", "dark"] as const) {
      const map = themeMap(block);
      const reserved = new Set(
        Object.keys(map)
          .filter((n) => RESERVED.test(n))
          .map((n) => resolveLiteral(map, n)),
      );
      // 7 = the five severity levels plus the two chart tokens; fewer means the
      // reserved set was not read at all and the borrow check below is vacuous.
      expect(reserved.size).toBeGreaterThanOrEqual(7);
      const borrowed: string[] = [];
      for (const name of Object.keys(CANONICAL.light)) {
        if (!name.startsWith(ALIAS_PREFIX)) continue;
        const literal = resolveLiteral(map, name);
        if (reserved.has(literal)) borrowed.push(`${block} ${name} -> ${literal}`);
      }
      expect(borrowed).toEqual([]);
    }
  });

  it("the locked status has a hue of its own in both themes", () => {
    // Locked, like unknown, must be told apart from every other status by
    // its hue in BOTH themes; a dark --locked that copied the pass green
    // would make a locked-down agent read as checked and passed in dark mode.
    // The other status hues are read off the alias layer itself, so a status
    // added later joins the comparison without editing this test.
    expect(CANONICAL.light["--color-status-locked"]).toBe("var(--locked)");
    // The dark block must declare --locked itself: the theme map falls back to
    // the light value for an undeclared name, so without this line a deleted
    // dark --locked would ship the light violet in dark mode and the collision
    // check below would still pass (round-2 closure finding, PR #1596).
    expect(CANONICAL.dark["--locked"]).toBeDefined();
    const STATUS_HUE = /^--color-status-[a-z]+$/;
    for (const block of ["light", "dark"] as const) {
      const map = themeMap(block);
      const locked = resolveLiteral(map, "--color-status-locked");
      const others = Object.keys(CANONICAL.light).filter(
        (n) => STATUS_HUE.test(n) && n !== "--color-status-locked",
      );
      // 5 = the other status members (pass, attention, fault, neutral, unknown);
      // fewer means the alias layer was not read and the collision check is vacuous.
      expect(others.length).toBeGreaterThanOrEqual(5);
      const collisions = others
        .filter((n) => resolveLiteral(map, n) === locked)
        .map((n) => `${block} ${n} = ${locked}`);
      expect(collisions).toEqual([]);
    }
  });

  it("the design system's component alias block is not declared in the canonical block", () => {
    // The ratified design ships a second alias layer for its component
    // previews. The legacy approval board and the pre-v1.1 dashboard define
    // --bg and --border themselves, so declaring that layer here would repaint
    // them on any page that carries both blocks. It lands only after those
    // boards are retired or renamed.
    //
    // The full set, not a sample: a sampled denylist passes when the one name
    // declared is a name it skipped. Must match the COMPONENT ALIAS BLOCK in
    // the ratified design system's tokens.css (the 2026-10-12 design handoff,
    // which lives outside this repo), all 52 names in its order.
    const DESIGN_ONLY_ALIASES = [
      "--bg",
      "--text",
      "--text-2",
      "--text-3",
      "--text-4",
      "--border",
      "--border-2",
      "--accent-tint",
      "--good",
      "--good-bg",
      "--good-line",
      "--warn",
      "--warn-bg",
      "--warn-line",
      "--bad",
      "--bad-bg",
      "--bad-line",
      "--unknown",
      "--unknown-bg",
      "--unknown-line",
      "--neutral",
      "--neutral-bg",
      "--neutral-line",
      "--font-display",
      "--font-sans",
      "--font-mono",
      "--radius-xs",
      "--radius-sm",
      "--radius-md",
      "--radius-control",
      "--radius-lg",
      "--radius-xl",
      "--radius-pill",
      "--space-hair",
      "--space-tight",
      "--space-page",
      "--stroke-hairline",
      "--stroke-marker",
      "--stroke-focus",
      "--shadow-none",
      "--shadow-marker-accent",
      "--size-topbar",
      "--size-rail",
      "--size-control",
      "--size-button",
      "--size-button-sm",
      "--size-chip",
      "--size-filter",
      "--size-drawer",
      "--size-icon",
      "--size-icon-sm",
      "--size-glyph",
    ];
    // 52 = the count of declarations in that block; a short list here is the
    // sampling defect this test exists to prevent.
    expect(new Set(DESIGN_ONLY_ALIASES).size).toBe(52);
    const declared = DESIGN_ONLY_ALIASES.filter(
      (name) => name in CANONICAL.light || name in CANONICAL.dark,
    );
    expect(declared).toEqual([]);
  });

  it("aliases are declared once and are never redeclared in the dark block", () => {
    // var() substitution is computed per element and the dark block redeclares
    // the physical tokens on that same element, so a single declaration tracks
    // the theme. A dark-block copy would be dead weight that can drift.
    const inDark = Object.keys(CANONICAL.dark).filter((n) => n.startsWith(ALIAS_PREFIX));
    expect(inDark).toEqual([]);
    const inLight = Object.keys(CANONICAL.light).filter((n) => n.startsWith(ALIAS_PREFIX));
    expect(inLight.length).toBeGreaterThanOrEqual(20);
  });
});
