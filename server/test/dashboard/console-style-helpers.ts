/**
 * Shared readers for the console style tests: the server token values per
 * theme, WCAG contrast between two of them, and a flat list of the rules in a
 * page's inline style. Not a test file; the dashboard style tests import it so
 * every ratio they assert is computed from the frozen token values, never
 * copied by hand.
 */

import { PAPER_INK_ROOT_TOKENS_CSS } from "../../src/dashboard/design-tokens.js";

export type Theme = "light" | "dark";
export type TokenMap = Record<string, string>;

/** The `[data-theme="dark"]` selector that opens the dark block. Must match
 *  the dark block's selector in design-tokens.ts. */
const DARK_BLOCK_SELECTOR = '[data-theme="dark"]';

function readBlock(block: string, into: TokenMap): void {
  for (const m of block.matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)) into[m[1]!] = m[2]!.trim();
}

function resolve(map: TokenMap, value: string, depth = 0): string {
  const alias = value.match(/^var\(--([a-z0-9-]+)\)$/);
  if (!alias || depth > 8) return value.toLowerCase();
  return resolve(map, map[alias[1]!] ?? value, depth + 1);
}

/** Every token's resolved value in each theme. The dark block overrides the
 *  light block; a name the dark block does not redeclare keeps its light
 *  value, as the cascade does. */
export function themeTokens(): Record<Theme, TokenMap> {
  const at = PAPER_INK_ROOT_TOKENS_CSS.indexOf(DARK_BLOCK_SELECTOR);
  if (at < 0) throw new Error("the token block has no dark theme block");
  const lightRaw: TokenMap = {};
  readBlock(PAPER_INK_ROOT_TOKENS_CSS.slice(0, at), lightRaw);
  const darkRaw: TokenMap = { ...lightRaw };
  readBlock(PAPER_INK_ROOT_TOKENS_CSS.slice(at), darkRaw);
  const out = { light: {} as TokenMap, dark: {} as TokenMap };
  for (const [theme, raw] of [["light", lightRaw], ["dark", darkRaw]] as const) {
    for (const k of Object.keys(raw)) out[theme][k] = resolve(raw, raw[k]!);
  }
  return out;
}

/** WCAG 2.x relative luminance of a six-digit hex color. 0.03928, 12.92,
 *  0.055, 1.055 and 2.4 are the sRGB transfer constants, and 0.2126, 0.7152,
 *  0.0722 the Rec. 709 channel weights, all from the WCAG definition. */
function luminance(hex: string): number {
  if (!/^#[0-9a-f]{6}$/i.test(hex)) throw new Error(`not a six-digit hex color: ${hex}`);
  const [r, g, b] = [1, 3, 5].map((i) => {
    const v = parseInt(hex.slice(i, i + 2), 16) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}

/** WCAG contrast ratio; 0.05 is the WCAG flare term. */
export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

/** WCAG 1.4.11 non-text contrast floor for control boundaries and marks. */
export const NON_TEXT_FLOOR = 3;

/** The fills a control or a mark sits on anywhere in the console: the
 *  surfaces, the paper steps, and the tints a selected or hovered row wears. */
export const CONSOLE_FILLS = [
  "surface",
  "surface-2",
  "paper",
  "paper-2",
  "paper-3",
  "accent-tint-strong",
  "accent-tint-faint",
  "indigo-bg",
] as const;

/** The lowest ratio a token reaches against every console fill in a theme. */
export function minRatio(tokens: TokenMap, token: string): { ratio: number; fill: string } {
  let worst = { ratio: Infinity, fill: "" };
  for (const fill of CONSOLE_FILLS) {
    const r = contrast(tokens[token]!, tokens[fill]!);
    if (r < worst.ratio) worst = { ratio: r, fill };
  }
  return worst;
}

export interface CssRule {
  /** The enclosing at-rule prelude (for example `@media (max-width: 1000px)`), or null at top level. */
  media: string | null;
  selector: string;
  decls: Array<[string, string]>;
}

/** A flat list of style rules, comments removed, each tagged with the
 *  at-rule it sits in. Handles one level of nesting, which is all the
 *  console styles use. */
export function cssRules(css: string): CssRule[] {
  const src = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const out: CssRule[] = [];
  let i = 0;
  const stack: string[] = [];
  let buf = "";
  while (i < src.length) {
    const c = src[i]!;
    if (c === "{") {
      const prelude = buf.trim().replace(/\s+/g, " ");
      buf = "";
      if (prelude.startsWith("@")) {
        stack.push(prelude);
        i++;
        continue;
      }
      const end = src.indexOf("}", i);
      const body = src.slice(i + 1, end);
      const decls: Array<[string, string]> = [];
      for (const d of body.split(";")) {
        const at = d.indexOf(":");
        if (at < 0) continue;
        decls.push([d.slice(0, at).trim().toLowerCase(), d.slice(at + 1).trim().replace(/\s+/g, " ")]);
      }
      out.push({ media: stack.length ? stack[stack.length - 1]! : null, selector: prelude, decls });
      i = end + 1;
      continue;
    }
    if (c === "}") {
      stack.pop();
      buf = "";
      i++;
      continue;
    }
    buf += c;
    i++;
  }
  return out;
}

/** The inline style of a rendered page (every `<style>` tag, joined). */
export function inlineStyle(html: string): string {
  return [...html.matchAll(/<style>([\s\S]*?)<\/style>/g)].map((m) => m[1]!).join("\n");
}

/** The token a declaration paints with, from its `var(--name)`, or null for
 *  `0`, `none`, `transparent` or a color that is not a token. */
export function tokenOf(value: string): string | null {
  const m = value.match(/var\(--([a-z0-9-]+)\)/);
  return m ? m[1]! : null;
}

/** Font names a console page must never name: the system stacks and the
 *  CDN faces the pages carried before they read the bundled faces. */
export const FOREIGN_FONT_NAMES = [
  "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "Helvetica",
  "Arial", "SF Mono", "Menlo", "Consolas", "JetBrains Mono", "Inter",
  "monospace", "sans-serif",
];

/** What a page that reads the console design system must not carry in its
 *  own CSS (its inline style minus the shared font-face and token blocks):
 *  a color literal (a palette of its own), a foreign font name, a remote
 *  font, a gradient, an animation, or a :root of its own. Returns the
 *  problems found, empty when the page is clean. */
export function ownStyleProblems(html: string, shared: { fonts: string; tokens: string }): string[] {
  const style = inlineStyle(html);
  const problems: string[] = [];
  if (!style.includes(shared.fonts)) problems.push("does not interpolate CONSOLE_FONT_FACE_CSS");
  if (!style.includes(shared.tokens)) problems.push("does not interpolate PAPER_INK_ROOT_TOKENS_CSS");
  const own = style.split(shared.fonts).join("").split(shared.tokens).join("").replace(/\/\*[\s\S]*?\*\//g, "");
  for (const m of own.matchAll(/#[0-9a-fA-F]{3,8}\b|\b(?:rgb|rgba|hsl|hsla)\(/g)) problems.push(`color literal ${m[0]}`);
  for (const name of FOREIGN_FONT_NAMES) {
    if (new RegExp(`(^|[\\s,:"'])${name.replace(/[-]/g, "\\-")}([\\s,;"']|$)`, "m").test(own)) problems.push(`names font ${name}`);
  }
  if (/@import|url\(\s*["']?https?:/i.test(own) || /fonts\.googleapis|fonts\.gstatic/i.test(html)) problems.push("loads a remote font or stylesheet");
  if (/gradient\(/i.test(own)) problems.push("paints a gradient");
  if (/@keyframes|animation\s*:/i.test(own)) problems.push("animates");
  if (/(^|[\s}]):root\s*\{/.test(own)) problems.push("declares its own :root");
  return problems;
}
