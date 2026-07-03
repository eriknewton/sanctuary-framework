import { describe, expect, it } from "vitest";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";
import { renderPostureAgentHTML } from "../../src/principal-policy/posture-agent-html.js";
import { renderPostureEvidenceHTML } from "../../src/principal-policy/posture-evidence-html.js";
import { POSTURE_ROOT_TOKENS_CSS } from "../../src/principal-policy/posture-html-shared.js";

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
 * Pure refactor guard (#B5): before this change, `posture-home-html.ts`,
 * `posture-agent-html.ts`, and `posture-evidence-html.ts` each hand-copied an
 * identical `:root { ... }` design-token block inline in their `<style>` tag.
 * This test captures the EXACT block all three pages shipped before the
 * extraction (the baseline below is a byte-for-byte copy of the pre-refactor
 * source) and pins that the shared `POSTURE_ROOT_TOKENS_CSS` constant, and
 * every page that now interpolates it, still renders that identical block.
 *
 * This is a refactor-only guarantee: the test proves the rendered token names
 * and values did not move when the three pages switched from a hand-copied
 * block to a single shared source. It makes no claim about the tokens
 * themselves being correct or complete, only that they did not drift.
 */
const PRE_REFACTOR_ROOT_BLOCK_BASELINE = `:root {
    --bg: #0e1116; --panel: #161b22; --panel-2: #1c2330; --border: #2a313c;
    --text: #e6edf3; --muted: #9aa6b2; --green: #2ea043; --amber: #d29922;
    --red: #f85149; --accent: #58a6ff;
  }`;

describe("posture :root design-token block - zero drift across the shared extraction (#B5)", () => {
  it("the shared token constant matches the captured pre-refactor baseline", () => {
    expect(POSTURE_ROOT_TOKENS_CSS).toBe(PRE_REFACTOR_ROOT_BLOCK_BASELINE);
  });

  it("posture Home renders the unchanged :root block", () => {
    const block = extractRootBlock(renderPostureHomeHTML());
    expect(block).toBe(PRE_REFACTOR_ROOT_BLOCK_BASELINE);
  });

  it("posture per-agent drill-down renders the unchanged :root block", () => {
    const block = extractRootBlock(renderPostureAgentHTML());
    expect(block).toBe(PRE_REFACTOR_ROOT_BLOCK_BASELINE);
  });

  it("posture Evidence view renders the unchanged :root block", () => {
    const block = extractRootBlock(renderPostureEvidenceHTML());
    expect(block).toBe(PRE_REFACTOR_ROOT_BLOCK_BASELINE);
  });

  it("all three surfaces render byte-identical :root blocks to each other", () => {
    const home = extractRootBlock(renderPostureHomeHTML());
    const agent = extractRootBlock(renderPostureAgentHTML());
    const evidence = extractRootBlock(renderPostureEvidenceHTML());
    expect(agent).toBe(home);
    expect(evidence).toBe(home);
  });
});
