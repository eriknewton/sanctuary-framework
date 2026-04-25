/**
 * Structural assertion: the coordination workstream MUST NOT import from
 * Concordia or Verascore. The concept overlaps with Concordia negotiation
 * receipts but the v1.1 internal handoff path is local-only and crypto-
 * independent of the Concordia sidecar.
 *
 * Implemented as a static import-graph crawl. We start at
 * `server/src/coordination/index.ts`, follow every relative import, and
 * fail the test if any visited file:
 *
 *   - imports from `concordia/` (Python sidecar source path)
 *   - imports from `../bridge/` (Sanctuary's Concordia bridge module)
 *   - imports from `../composition/` (Verascore + Concordia composition layer)
 *
 * This is the same pattern the policy-engine uses to keep network/LLM out
 * of gate paths.
 */

import { describe, expect, it } from "vitest";
import { dirname, isAbsolute, join, normalize, relative } from "node:path";
import { readFileSync, existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SRC_ROOT = join(__dirname, "../../src");
const ENTRY = join(SRC_ROOT, "coordination/index.ts");

const FORBIDDEN_PATH_FRAGMENTS = [
  "/concordia/",
  "/sidecars/concordia/",
  "/bridge/",
  "/composition/",
];
const FORBIDDEN_BARE_PACKAGES = [
  "concordia",
  "concordia-protocol",
  "@concordia/",
  "verascore",
];

function resolveImport(fromFile: string, spec: string): string | null {
  if (!spec.startsWith(".") && !isAbsolute(spec)) return null;
  const base = spec.startsWith(".") ? join(dirname(fromFile), spec) : spec;
  const candidates = [
    base,
    base.replace(/\.js$/, ".ts"),
    base.replace(/\.js$/, ".tsx"),
    base + ".ts",
    base + ".tsx",
    join(base, "index.ts"),
  ];
  for (const c of candidates) {
    if (existsSync(c) && statSync(c).isFile()) return normalize(c);
  }
  return null;
}

function extractImports(source: string): string[] {
  const out: string[] = [];
  const reImport = /import\s+(?:[\s\S]+?)\s+from\s+["']([^"']+)["']/g;
  const reExport = /export\s+(?:[\s\S]+?)\s+from\s+["']([^"']+)["']/g;
  for (const m of source.matchAll(reImport)) out.push(m[1]!);
  for (const m of source.matchAll(reExport)) out.push(m[1]!);
  return out;
}

describe("coordination — no Concordia or Verascore dependency", () => {
  it("the entire coordination import graph is free of Concordia/Verascore/bridge/composition references", () => {
    const visited = new Set<string>();
    const queue: string[] = [normalize(ENTRY)];
    const violations: Array<{ file: string; specifier: string }> = [];

    while (queue.length > 0) {
      const file = queue.shift()!;
      if (visited.has(file)) continue;
      visited.add(file);
      const source = readFileSync(file, "utf8");
      for (const spec of extractImports(source)) {
        // Bare-package check.
        for (const pkg of FORBIDDEN_BARE_PACKAGES) {
          if (spec === pkg || spec.startsWith(`${pkg}/`)) {
            violations.push({ file: relative(SRC_ROOT, file), specifier: spec });
          }
        }
        // Path-fragment check (against the resolved absolute path).
        const resolved = resolveImport(file, spec);
        if (resolved) {
          const norm = resolved.replace(/\\/g, "/");
          for (const frag of FORBIDDEN_PATH_FRAGMENTS) {
            if (norm.includes(frag)) {
              violations.push({
                file: relative(SRC_ROOT, file),
                specifier: spec,
              });
            }
          }
          if (!visited.has(resolved)) queue.push(resolved);
        }
      }
    }

    expect(violations).toEqual([]);
  });
});
