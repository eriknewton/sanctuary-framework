import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { IMMUNE_MODEL_LOAD_SURFACES } from "../../src/intelligence/model-manifest-v2.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = join(here, "..", "..", "src");

describe("Q5E structural chokepoints", () => {
  it("pins the reviewed closed immune-surface set", () => {
    expect(IMMUNE_MODEL_LOAD_SURFACES).toEqual([
      "sentinel-scoring",
      "privacy-filter-tier-2",
    ]);
  });

  it("permits local substrate construction only inside the gated-handle method", async () => {
    const selector = await readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
    expect(selector.match(/LocalSubstrate\.fromPick\(/g)).toHaveLength(1);
    const gatedStart = selector.indexOf("private gatedLocalHandle(");
    const nextMethod = selector.indexOf("private integrityRefusalHandle(", gatedStart);
    expect(gatedStart).toBeGreaterThan(0);
    expect(nextMethod).toBeGreaterThan(gatedStart);
    expect(selector.slice(gatedStart, nextMethod)).toContain("LocalSubstrate.fromPick(");
    const invokeStart = selector.indexOf("private async invoke(");
    const invokeEnd = selector.indexOf("private recordRecentFailure(", invokeStart);
    expect(selector.slice(invokeStart, invokeEnd)).toContain(
      "const handle = await this.getOrIssueHandle(surface, choice)",
    );
    expect(selector).not.toContain("const handle = this.buildHandle(surface, choice)");
  });

  it("keeps raw Ollama generation inside the local adapter reached by that handle", async () => {
    const selector = await readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
    const local = await readFile(
      join(srcRoot, "intelligence", "substrates", "local.ts"),
      "utf8",
    );
    expect(selector).not.toMatch(/\.generate\(/);
    expect(local.match(/this\.client\.generate\(/g)).toHaveLength(3);
    expect(selector).toContain(
      "closes the selector-to-first-invoke gap, but not a malicious-runtime",
    );
  });
});
