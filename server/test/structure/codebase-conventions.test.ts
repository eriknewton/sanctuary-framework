/**
 * Codebase-conventions structural gate (durability "teeth").
 *
 * The 2026-06-14 professionalization pass made `server/src` legible: a
 * 54-module map (`server/src/README.md`) and a barrel convention (a thin
 * re-export `index.ts` per module). Those conventions had NO enforcement, so
 * the next PR that adds a module without a map row, or skips its barrel, would
 * silently un-do the work. This gate is the structural layer (mirrors the
 * retired-vocabulary gate): it fails CI when the tree drifts from the map or
 * the barrel convention.
 *
 * Two checks:
 *   1. MODULE-MAP FRESHNESS — the module names in the map's MODULE INDEX TABLE
 *      exactly equal the directories under `server/src`. Add/remove/rename a
 *      module without updating its row -> red.
 *   2. BARREL COVERAGE — every module dir has an `index.ts` barrel EXCEPT the
 *      documented exceptions. A new barrel-less module -> red; an exception
 *      that GAINS a barrel (e.g. a layer dir after the rename) -> red until it
 *      is removed from the allowlist (keeps the allowlist honest).
 *
 * Parser note (from the 2026-06-14 adversarial review): the README contains
 * FIVE markdown tables. The freshness parser MUST anchor to the
 * `## MODULE INDEX TABLE` heading and read only that one table, or a generic
 * table scan picks up the vocabulary / root-surface / runtime-asset /
 * out-of-scope tables (76 rows, not 54) and reds every PR.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// server/test/structure/<file> -> repo root is four levels up (same anchor the
// retired-vocabulary gate uses).
const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");
const MAP_PATH = join(SERVER_SRC, "README.md");

/**
 * Module dirs WITHOUT an `index.ts` barrel that are INTENTIONAL (documented in
 * the map's "Barrel convention" section). Keep this list in lockstep with the
 * map. The four `l*` layer dirs graduate off this list when the pending layer
 * rename adds their barrels — at which point this gate reminds you to remove
 * them here, in that same PR.
 */
const ALLOWED_BARRELLESS = [
  "cli", // command-handler surface, not a re-exportable module
  "compliance", // nests its code under eu_ai_act/
  "contracts", // per-version barrels only; a top-level one would merge frozen wire versions
  "l1-cognitive",
  "l2-operational",
  "l3-disclosure",
  "l4-reputation",
  "v1", // versioned HTTP route surface, not a re-exportable module
].sort();

/** Immediate subdirectories of server/src (the 54 module dirs). */
function moduleDirs(): string[] {
  return readdirSync(SERVER_SRC, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

/**
 * Extract the module names from the map's MODULE INDEX TABLE only.
 *
 * Anchors on the `## MODULE INDEX TABLE` heading, reads pipe-rows until the
 * next `##` heading, drops the header row and the `|---|` separator, and takes
 * column 1 (the module name). Throws if the anchor or separator is missing so
 * a structurally-changed README fails loudly rather than silently matching 0.
 */
function mapModules(): string[] {
  const lines = readFileSync(MAP_PATH, "utf-8").split("\n");
  const start = lines.findIndex((l) => /^##\s+MODULE INDEX TABLE\b/.test(l));
  if (start < 0) {
    throw new Error(
      "server/src/README.md: '## MODULE INDEX TABLE' heading not found — the map's structure changed; update this gate's anchor.",
    );
  }
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^##\s/.test(lines[i]!)) {
      end = i;
      break;
    }
  }
  const rows = lines
    .slice(start + 1, end)
    .map((l) => l.trim())
    .filter((l) => l.startsWith("|"));
  const sepIdx = rows.findIndex((r) => /^\|[\s:|-]*-[\s:|-]*\|?$/.test(r));
  if (sepIdx < 0) {
    throw new Error(
      "server/src/README.md: MODULE INDEX TABLE separator row not found — update this gate.",
    );
  }
  return rows
    .slice(sepIdx + 1)
    .map((r) => r.split("|")[1]!.trim().replace(/`/g, ""))
    .filter((name) => name.length > 0)
    .sort();
}

describe("codebase-conventions gate", () => {
  it("module map (server/src/README.md) lists exactly the dirs under server/src", () => {
    const onDisk = moduleDirs();
    const inMap = mapModules();

    const missingFromMap = onDisk.filter((d) => !inMap.includes(d));
    const missingFromTree = inMap.filter((m) => !onDisk.includes(m));

    expect(
      { missingFromMap, missingFromTree },
      "Module map is out of sync with server/src.\n" +
        (missingFromMap.length
          ? `  dirs on disk with NO map row (add a row in this PR): ${missingFromMap.join(", ")}\n`
          : "") +
        (missingFromTree.length
          ? `  map rows with NO dir (a rename/removal not reflected in the map): ${missingFromTree.join(", ")}\n`
          : "") +
        "The map's value is that it never drifts from the tree — update it in the same PR that changes a module.",
    ).toEqual({ missingFromMap: [], missingFromTree: [] });
  });

  it("every module dir has an index.ts barrel except the documented exceptions", () => {
    const unbarreled = moduleDirs()
      .filter((d) => !existsSync(join(SERVER_SRC, d, "index.ts")))
      .sort();

    const newlyUnbarreled = unbarreled.filter(
      (d) => !ALLOWED_BARRELLESS.includes(d),
    );
    const nowBarreled = ALLOWED_BARRELLESS.filter(
      (d) => !unbarreled.includes(d),
    );

    expect(
      { newlyUnbarreled, nowBarreled },
      "Barrel convention drift.\n" +
        (newlyUnbarreled.length
          ? `  module(s) missing an index.ts barrel (add one, or document the exception in ALLOWED_BARRELLESS + the map): ${newlyUnbarreled.join(", ")}\n`
          : "") +
        (nowBarreled.length
          ? `  exception(s) that now HAVE a barrel (remove from ALLOWED_BARRELLESS here + update the map's "Barrel convention" count): ${nowBarreled.join(", ")}\n`
          : ""),
    ).toEqual({ newlyUnbarreled: [], nowBarreled: [] });
  });
});
