import { describe, expect, it } from "vitest";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";
import { renderPostureAgentHTML } from "../../src/principal-policy/posture-agent-html.js";
import { renderPostureEvidenceHTML } from "../../src/principal-policy/posture-evidence-html.js";
import { POSTURE_ROOT_TOKENS_CSS } from "../../src/principal-policy/posture-html-shared.js";
import { PAPER_INK_ROOT_TOKENS_CSS } from "../../src/dashboard/design-tokens.js";
import { CONSOLE_FONT_FACE_CSS } from "../../src/dashboard/design-fonts.js";
import {
  NON_TEXT_FLOOR,
  contrast,
  cssRules,
  inlineStyle,
  ownStyleProblems,
  themeTokens,
} from "../dashboard/console-style-helpers.js";

/**
 * Extract the first `:root { ... }` custom-property block from a rendered
 * HTML string. Brace-balanced so it is robust to the surrounding `<style>`
 * content.
 */
function extractRootBlock(html: string): string {
  const start = html.indexOf(":root");
  if (start === -1) throw new Error(":root block not found");
  const open = html.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < html.length; i++) {
    const ch = html[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return html.slice(start, i + 1);
    }
  }
  throw new Error("unbalanced braces for :root block");
}

/**
 * Single-source guard: the three posture surfaces (`posture-home-html.ts`,
 * `posture-agent-html.ts`, `posture-evidence-html.ts`) must all interpolate the
 * SAME design-token block, so the palette / theme / scale can never drift on one
 * copy.
 *
 * S1 (UI restyle, 2026-07-18) deliberately re-based this pin. The posture pages
 * previously carried a generic GitHub-dark `:root` block; they now share the
 * canonical "paper/ink" tokens (`PAPER_INK_ROOT_TOKENS_CSS`) — the exact block
 * the v1.1 board and the Fleet Switcher interpolate. The pinning MECHANISM is
 * unchanged (all three render byte-identical blocks); only the baseline moved,
 * from a hand-copied hex baseline to the shared constant itself so it cannot
 * rot. A guard below also asserts the old GitHub-dark palette is fully gone.
 *
 * The first `:root { ... }` block a page emits is the paper/ink primitives
 * block; the warm dark palette rides a separate `[data-theme="dark"]` block, so
 * `extractRootBlock` (first `:root`) returns the primitives to compare.
 */
const SHARED_ROOT_BLOCK = extractRootBlock(PAPER_INK_ROOT_TOKENS_CSS);

describe("posture :root design-token block - one shared source, zero cross-surface drift", () => {
  it("the shared posture token constant IS the canonical paper/ink block", () => {
    expect(POSTURE_ROOT_TOKENS_CSS).toBe(PAPER_INK_ROOT_TOKENS_CSS);
  });

  it("posture Home renders the shared paper/ink :root block", () => {
    const block = extractRootBlock(renderPostureHomeHTML());
    expect(block).toBe(SHARED_ROOT_BLOCK);
  });

  it("posture per-agent drill-down renders the shared paper/ink :root block", () => {
    const block = extractRootBlock(renderPostureAgentHTML());
    expect(block).toBe(SHARED_ROOT_BLOCK);
  });

  it("posture Evidence view renders the shared paper/ink :root block", () => {
    const block = extractRootBlock(renderPostureEvidenceHTML());
    expect(block).toBe(SHARED_ROOT_BLOCK);
  });

  it("all three surfaces render byte-identical :root blocks to each other", () => {
    const home = extractRootBlock(renderPostureHomeHTML());
    const agent = extractRootBlock(renderPostureAgentHTML());
    const evidence = extractRootBlock(renderPostureEvidenceHTML());
    expect(agent).toBe(home);
    expect(evidence).toBe(home);
  });

  it("the retired GitHub-dark palette is fully gone from every posture surface", () => {
    for (const html of [
      renderPostureHomeHTML(),
      renderPostureAgentHTML(),
      renderPostureEvidenceHTML(),
    ]) {
      // Old primitives + link blue that leaked the wrong design system.
      expect(html).not.toContain("#0e1116");
      expect(html).not.toContain("#58a6ff");
      expect(html).not.toContain("#2ea043");
      // The canonical palette is present (the ratified 2026-10-12 page
      // ground; must match --paper in server/src/dashboard/design-tokens.ts).
      expect(html).toContain("--paper: #f4f6fa;");
    }
  });

  it("all three posture surfaces load the bundled faces and carry no local palette, foreign font, or remote resource", () => {
    for (const html of [
      renderPostureHomeHTML(),
      renderPostureAgentHTML(),
      renderPostureEvidenceHTML(),
    ]) {
      expect(ownStyleProblems(html, {
        fonts: CONSOLE_FONT_FACE_CSS,
        tokens: PAPER_INK_ROOT_TOKENS_CSS,
      })).toEqual([]);
    }
  });

  it("all three posture surfaces boot dark by default while preserving a stored light choice", () => {
    for (const html of [
      renderPostureHomeHTML(),
      renderPostureAgentHTML(),
      renderPostureEvidenceHTML(),
    ]) {
      expect(html).toContain('sessionStorage.getItem("sanctuary-v11-theme") === "light"');
      expect(html).toContain('setAttribute("data-theme", "dark")');
    }
  });

  it("all three posture surfaces render no em dash and no L-numbered layer labels", () => {
    for (const html of [
      renderPostureHomeHTML(),
      renderPostureAgentHTML(),
      renderPostureEvidenceHTML(),
    ]) {
      expect(html).not.toContain("\u2014");
      expect(html).not.toContain("&mdash;");
      const text = html
        .replace(/<script\b[\s\S]*?<\/script\b[^>]*>/gi, " ")
        .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ");
      expect(text).not.toMatch(/\bL[1-4]\b/i);
    }
  });

  it("the shared status pills give every state a shape, and Unknown does not wear the pass shape", () => {
    const html = renderPostureHomeHTML();
    expect(html).toContain(".pill.green::before { content: \"\\25CF\"; }");
    expect(html).toContain(".pill.amber::before { content: \"\\25B2\"; }");
    expect(html).toContain(".pill.red::before { content: \"\\25A0\"; }");
    expect(html).toContain(".pill.neutral::before { content: \"\\2013\"; }");
    expect(html).toContain(".pill.unknown::before { content: \"\\25CB\"; }");
    const unknownRule = html.match(/\.pill\.unknown::before \{[^}]+}/)?.[0] ?? "";
    expect(unknownRule).not.toContain("\\25CF");
  });

  it("the posture control edge token clears the 3:1 non-text floor in both themes", () => {
    const homeRules = cssRules(inlineStyle(renderPostureHomeHTML()));
    const evidenceRules = cssRules(inlineStyle(renderPostureEvidenceHTML()));
    const decl = (rules: ReturnType<typeof cssRules>, selector: string, property: string) =>
      rules.find((rule) => rule.selector === selector)?.decls.find(([key]) => key === property)?.[1];
    expect(decl(homeRules, ".fleet-link", "border")).toContain("var(--ink-3)");
    expect(decl(homeRules, ".approval-actions button", "border")).toContain("var(--ink-3)");
    expect(decl(homeRules, "button.guided", "border")).toContain("var(--ink-3)");
    expect(decl(homeRules, ".story-toggle input", "accent-color")).toBe("var(--indigo)");
    expect(decl(homeRules, "html", "color-scheme")).toBe("light");
    expect(decl(homeRules, 'html[data-theme="dark"]', "color-scheme")).toBe("dark");
    expect(decl(evidenceRules, ".filter-group input, .filter-group select", "border")).toContain("var(--ink-3)");
    expect(renderPostureHomeHTML()).toContain(".pill.unknown { background: var(--slate-bg); color: var(--slate); border: 1px dashed var(--slate); }");

    const tokens = themeTokens();
    for (const theme of ["light", "dark"] as const) {
      for (const fill of ["surface", "surface-2", "paper"] as const) {
        expect(contrast(tokens[theme]["ink-3"]!, tokens[theme][fill]!), `${theme} ${fill}`).toBeGreaterThanOrEqual(NON_TEXT_FLOOR);
      }
      expect(contrast(tokens[theme]["slate"]!, tokens[theme]["slate-bg"]!), `${theme} unknown edge`).toBeGreaterThanOrEqual(NON_TEXT_FLOOR);
      expect(contrast(tokens[theme]["sage"]!, tokens[theme]["surface-2"]!), `${theme} approve edge`).toBeGreaterThanOrEqual(NON_TEXT_FLOOR);
      expect(contrast(tokens[theme]["rust"]!, tokens[theme]["surface-2"]!), `${theme} deny edge`).toBeGreaterThanOrEqual(NON_TEXT_FLOOR);
      expect(contrast(tokens[theme]["indigo"]!, tokens[theme]["surface"]!), `${theme} Apply fill`).toBeGreaterThanOrEqual(NON_TEXT_FLOOR);
    }
  });

  it("evidence page layer rows render Health Score names while preserving raw tokens as titles", () => {
    const html = renderPostureEvidenceHTML();
    const start = html.indexOf("function esc(s)");
    const end = html.indexOf("function buildQueryParams()");
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const entriesPanel = { innerHTML: "" };
    const document = {
      getElementById: (id: string) => id === "entries-panel" ? entriesPanel : null,
    };
    const ops = ["identity", "gate", "proof", "reputation"];
    const entries = ["l1", "l2", "l3", "l4"].map((layer, i) => ({
      timestamp: new Date(Date.UTC(2026, 9, 14, 12, i)).toISOString(),
      layer,
      operation: ops[i],
      result: "success",
      identity_id: `id-${i}`,
      details: {},
    }));
    const source = `${html.slice(start, end)}
renderEntries({ entries, total: entries.length });
return entriesPanel.innerHTML;`;
    // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
    const rendered = new Function("document", "entries", "entriesPanel", "window", source)(document, entries, entriesPanel, {}) as string;

    expect(rendered).toContain('title="l1">Cognitive</span>');
    expect(rendered).toContain('title="l2">Operational</span>');
    expect(rendered).toContain('title="l3">Selective Disclosure</span>');
    expect(rendered).toContain('title="l4">Verifiable Reputation</span>');
    expect(rendered.replace(/<[^>]+>/g, " ")).not.toMatch(/\bL[1-4]\b/i);
  });
});
