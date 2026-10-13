/**
 * The login page is on the shared token system, with no hand-copied mirror.
 *
 * `generateLoginHTML` used to carry its own 22-token light-only `:root` block,
 * hand-copied from the v1.1 board, under a pin comment that had gone stale in
 * both halves: it named a canonical source that no longer holds tokens, and it
 * called the shared tokens module "a logged follow-up" while the same file
 * already imported `PAPER_INK_ROOT_TOKENS_CSS`. That is the exact failure mode
 * the pin convention exists to prevent, so the copy is gone and the page
 * interpolates the canonical constant.
 *
 * These pin the two halves of that change:
 *
 *   1. The page emits the canonical block VERBATIM, and emits no second
 *      paper/ink token block beside it. A future editor who re-copies a subset
 *      "just for this page" fails here rather than shipping a palette that
 *      drifts on the login screen alone.
 *   2. The semantic `--color-*` alias layer reaches the page, so the status
 *      vocabulary is available wherever the tokens are.
 *
 * Plus one characterization assertion that guards the PR's visual-identity
 * claim from a later well-meaning edit: the login page deliberately does NOT
 * emit `THEME_BOOTSTRAP_SCRIPT`. Nothing sets `data-theme`, so the shared dark
 * block cannot match and the page still renders light-only, exactly as it did
 * before it moved onto the shared constant. Adding the bootstrap is a real
 * visual change and needs its own decision; if someone adds it, this test says
 * so out loud instead of letting the login screen quietly go dark.
 */

import { describe, expect, it } from "vitest";

import { generateLoginHTML } from "../../src/principal-policy/dashboard-html.js";
import {
  PAPER_INK_ROOT_TOKENS_CSS,
  THEME_BOOTSTRAP_SCRIPT,
} from "../../src/dashboard/design-tokens.js";

const LOGIN_HTML = generateLoginHTML({ serverVersion: "9.9.9-test" });

/** Count `:root {` custom-property blocks, ignoring CSS comments. */
function countRootBlocks(html: string): number {
  const stripped = html.replace(/\/\*[\s\S]*?\*\//g, "");
  return (stripped.match(/:root\s*\{/g) ?? []).length;
}

describe("login page design tokens - one shared source, no scoped mirror", () => {
  it("interpolates the canonical paper/ink constant verbatim", () => {
    expect(LOGIN_HTML).toContain(PAPER_INK_ROOT_TOKENS_CSS);
  });

  it("emits exactly one :root block, so no hand-copied mirror rides alongside", () => {
    expect(countRootBlocks(LOGIN_HTML)).toBe(1);
  });

  it("carries the shared dark palette block that the old scoped mirror lacked", () => {
    expect(LOGIN_HTML).toContain('[data-theme="dark"]');
  });

  it("carries the semantic alias layer", () => {
    expect(LOGIN_HTML).toContain("--color-status-unknown: var(--slate);");
    expect(LOGIN_HTML).toContain("--color-status-pass: var(--sage);");
    expect(LOGIN_HTML).toContain("--color-text-muted: var(--ink-3);");
  });

  it("still renders light-only: no theme bootstrap, so data-theme is never set", () => {
    // The dark block above is inert on this page BECAUSE of this. If the
    // bootstrap is ever added here the page starts following the OS/dashboard
    // theme, which is a deliberate product change, not a refactor.
    expect(LOGIN_HTML).not.toContain(THEME_BOOTSTRAP_SCRIPT);
    expect(LOGIN_HTML).not.toContain('setAttribute("data-theme"');
  });

  it("declares every token the retired scoped mirror declared, at the ratified console values", () => {
    // The 22 names the deleted copy declared are the names the page's CSS
    // rules are written against, so each must still resolve on this page. The
    // VALUES were re-based on 2026-10-12, when the console palette and faces
    // changed by design (must match PAPER_INK_ROOT_TOKENS_CSS in
    // server/src/dashboard/design-tokens.ts); an unreviewed drift from these
    // still repaints the login screen and fails here.
    //
    // The three font stacks matter as much as the colors here and are easy to
    // omit from a list like this because they are not hex values. The page
    // makes seven var(--mono) / var(--sans) / var(--serif) references, so a
    // changed stack restyles every label, input, and title on the screen while
    // every color assertion still passes.
    const RETIRED_MIRROR: Record<string, string> = {
      "--paper": "#f4f6fa",
      "--paper-2": "#eef1f7",
      "--ink": "#0f172a",
      "--ink-2": "#4b5566",
      "--ink-3": "#5e6879",
      "--ink-4": "#a3abba",
      "--rule": "#d9dee9",
      "--surface": "#ffffff",
      "--surface-2": "#eef1f7",
      "--rust": "#c72647",
      "--rust-bg": "#f8e5e9",
      "--mono":
        '"Roboto Mono", ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
      "--sans":
        '"Manrope", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
      "--serif": "var(--display)",
      "--rad": "6px",
      "--rad-lg": "10px",
      "--shadow": "none",
      "--text-xs": "11px",
      "--text-sm": "12px",
      "--text-md": "14px",
      "--text-base": "13px",
      "--text-lg": "16px",
    };
    // Pins the list against the count in the comment above, so a future edit
    // cannot quietly drop a token and leave the "all 22" claim standing.
    expect(Object.keys(RETIRED_MIRROR)).toHaveLength(22);
    for (const [name, value] of Object.entries(RETIRED_MIRROR)) {
      expect(LOGIN_HTML, `${name} must still resolve to ${value}`).toContain(
        `${name}: ${value};`,
      );
    }
  });
});
