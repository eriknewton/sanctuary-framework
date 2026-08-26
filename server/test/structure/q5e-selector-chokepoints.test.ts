import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { IMMUNE_MODEL_LOAD_SURFACES } from "../../src/intelligence/model-manifest-v2.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = join(here, "..", "..", "src");

async function productionSourceFiles(dir = srcRoot): Promise<string[]> {
  const files: string[] = [];
  for (const name of await readdir(dir)) {
    const path = join(dir, name);
    if ((await stat(path)).isDirectory()) files.push(...await productionSourceFiles(path));
    else if (/\.(?:ts|tsx|js|mjs|cjs)$/.test(path)) files.push(path);
  }
  return files;
}

function relativeSourcePath(path: string): string {
  return relative(srcRoot, path).replaceAll("\\", "/");
}

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

  it("freezes the repo-wide Ollama construction and raw generation inventory", async () => {
    const inventory = await Promise.all((await productionSourceFiles()).map(async (path) => ({
      path: relativeSourcePath(path),
      source: await readFile(path, "utf8"),
    })));
    expect(inventory
      .filter(({ source }) => source.includes("new OllamaClient("))
      .map(({ path }) => path)
      .sort()).toEqual([
        "intelligence/selector.ts",
        "wrap/local-intelligence.ts",
      ]);
    expect(inventory
      .filter(({ source }) => source.includes("/api/generate"))
      .map(({ path }) => path)
      .sort()).toEqual(["intelligence/substrates/local.ts"]);
  });

  it("makes immune integrity refusals terminal before the remote fallback chain", async () => {
    const selector = await readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
    const fallbackStart = selector.indexOf("private async tryNextSubstrate(");
    const fallbackEnd = selector.indexOf("private async getOrIssueHandle(", fallbackStart);
    const fallback = selector.slice(fallbackStart, fallbackEnd);
    expect(fallback).toContain('primary === "local"');
    expect(fallback).toContain("IMMUNE_SURFACE_SET.has(surface)");
    expect(fallback).toContain("this.integrityFailures.has(surface)");
    expect(fallback.indexOf("IMMUNE_SURFACE_SET.has(surface)")).toBeLessThan(
      fallback.indexOf("FALLBACK_CHAIN.slice"),
    );
  });
});
