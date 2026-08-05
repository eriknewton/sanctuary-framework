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
    expect(CANONICAL.light["--paper"]).toBe("#f7f5f0");
    expect(CANONICAL.dark["--paper"]).toBe("#121210");
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
