/**
 * `audit-chain repair-plan` must run OFFLINE, against the fortress directory,
 * with no MCP server involved.
 *
 * WHY THIS IS A STRUCTURAL TEST AND NOT A BEHAVIORAL ONE. The requirement
 * exists because a fortress with hard audit-chain integrity findings is exactly
 * the fortress whose server does not start, so the diagnostic for that
 * situation cannot depend on the server. A behavioral test that merely omits
 * starting a server proves nothing: it would keep passing the day someone adds
 * an import that requires one. So this crawls the verb's transitive relative
 * import graph and fails if the server factory is reachable at all.
 *
 * Same crawl shape as `test/coordination/no-concordia-dependency.test.ts`.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { stripCodeComments } from "./public-surface";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = normalize(join(HERE, "..", "..", "src"));
const ENTRY = normalize(join(SRC_ROOT, "cli", "audit-chain-repair-plan.ts"));

/**
 * The module that builds the MCP server. Reaching it would mean the verb's
 * module graph pulls in the very startup path that cannot run on a broken
 * chain. `src/cli.ts` is excluded from the graph by construction: it imports
 * this verb lazily, not the other way round.
 */
const SERVER_FACTORY_FILE = normalize(join(SRC_ROOT, "index.ts"));
const SERVER_FACTORY_SYMBOL = "createSanctuaryServer";

function resolveImport(fromFile: string, spec: string): string | null {
  if (!spec.startsWith(".") && !isAbsolute(spec)) return null;
  const base = spec.startsWith(".") ? join(dirname(fromFile), spec) : spec;
  const candidates = [
    base,
    base.replace(/\.js$/, ".ts"),
    base + ".ts",
    join(base, "index.ts"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate) && statSync(candidate).isFile()) {
      return normalize(candidate);
    }
  }
  return null;
}

function extractImports(source: string): string[] {
  const specs: string[] = [];
  for (const match of source.matchAll(
    /import\s+(?:[\s\S]+?)\s+from\s+["']([^"']+)["']/g
  )) {
    specs.push(match[1]!);
  }
  for (const match of source.matchAll(
    /export\s+(?:[\s\S]+?)\s+from\s+["']([^"']+)["']/g
  )) {
    specs.push(match[1]!);
  }
  // Dynamic `await import("...")` counts: it is still a dependency of the
  // running verb, just a deferred one.
  for (const match of source.matchAll(/import\s*\(\s*["']([^"']+)["']\s*\)/g)) {
    specs.push(match[1]!);
  }
  return specs;
}

function crawl(entry: string): { visited: Set<string>; path: Map<string, string> } {
  const visited = new Set<string>();
  const path = new Map<string, string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.shift()!;
    if (visited.has(file)) continue;
    visited.add(file);
    const source = readFileSync(file, "utf8");
    for (const spec of extractImports(source)) {
      const resolved = resolveImport(file, spec);
      if (!resolved || visited.has(resolved)) continue;
      path.set(resolved, file);
      queue.push(resolved);
    }
  }
  return { visited, path };
}

describe("audit-chain repair-plan runs offline", () => {
  const { visited, path } = crawl(ENTRY);

  it("crawls a non-trivial graph (a parser that matched nothing would pass vacuously)", () => {
    expect(visited.size).toBeGreaterThan(10);
    expect(visited.has(ENTRY)).toBe(true);
  });

  it("never reaches the MCP server factory module", () => {
    if (!visited.has(SERVER_FACTORY_FILE)) {
      expect(visited.has(SERVER_FACTORY_FILE)).toBe(false);
      return;
    }
    // Render the chain so the failure names the import that broke the property
    // rather than just asserting false.
    const chain: string[] = [];
    let cursor: string | undefined = SERVER_FACTORY_FILE;
    while (cursor) {
      chain.unshift(relative(SRC_ROOT, cursor));
      cursor = path.get(cursor);
    }
    expect(chain.join(" -> ")).toBe("");
  });

  it("never references the server factory symbol anywhere in its graph", () => {
    // Comment-stripped via the shared helper: this verb's own header EXPLAINS
    // why it must not require the server, and a raw substring scan would read
    // that explanation as the violation it warns about.
    const offenders = [...visited].filter((file) =>
      stripCodeComments(readFileSync(file, "utf8"), relative(SRC_ROOT, file)).includes(
        SERVER_FACTORY_SYMBOL
      )
    );
    expect(offenders.map((f) => relative(SRC_ROOT, f))).toEqual([]);
  });
});
