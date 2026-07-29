import { describe, expect, it } from "vitest";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";
import { renderPostureAgentHTML } from "../../src/principal-policy/posture-agent-html.js";
import { renderPostureEvidenceHTML } from "../../src/principal-policy/posture-evidence-html.js";
import { POSTURE_ROOT_TOKENS_CSS } from "../../src/principal-policy/posture-html-shared.js";
import { PAPER_INK_ROOT_TOKENS_CSS } from "../../src/dashboard/design-tokens.js";

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
      // The paper/ink palette is present.
      expect(html).toContain("--paper: #f7f5f0;");
    }
  });
});
