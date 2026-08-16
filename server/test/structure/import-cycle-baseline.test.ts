/**
 * Import-cycle baseline guard (Phase-0 rename safety net).
 *
 * The zero-dependency cycle detector (scripts/check-import-cycles.ts) reports
 * the current set of import cycles in server/src. The reorg's god-file splits +
 * barrel introductions are a classic way to add an import cycle by accident (a
 * cycle can compile yet break import-time tool-registration order — scoping §8
 * risk 1, the index.ts split risk). A committed baseline
 * (test/fixtures/import-cycle-baseline.txt) freezes the cycles that exist today;
 * this test fails if a change INTRODUCES a new cycle, while tolerating the
 * pre-existing ones until they are paid down deliberately.
 *
 * It runs the detector's ACTUAL logic in-process by importing the shared
 * library (scripts/check-import-cycles.lib.ts) that the CLI runner also
 * consumes — one parser, one resolver, one SCC pass (AGENTS.md rule 5), so
 * this guard cannot drift from the tool that generates the committed baseline.
 * (It previously carried an inline copy of that logic because importing the
 * pre-split script would have run its main().) The baseline is regenerated
 * with `npm run check-import-cycles:baseline`.
 *
 * SET-BASED, not count-based (the codex-backstop finding on #569): comparing
 * only the cycle COUNT is a hole — a reorg can introduce a brand-new cycle while
 * an old one disappears in the same diff, leaving the count unchanged so a
 * count<=baseline check passes. This guard instead compares the SCC MEMBER SETS:
 * it fails if any cycle whose exact member set is NOT in the committed baseline
 * appears, regardless of whether the total count went up, down, or stayed flat.
 * The baseline file already lists each cycle's member files, so no baseline
 * format change is needed; the parse below reads those member blocks.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  allTsFiles,
  buildGraph,
  stronglyConnectedComponents,
} from "../../scripts/check-import-cycles.lib.js";

const HERE = fileURLToPath(import.meta.url);
const SERVER_DIR = resolve(HERE, "..", "..", "..");
const SERVER_SRC = join(SERVER_DIR, "src");
const BASELINE_PATH = join(
  SERVER_DIR,
  "test",
  "fixtures",
  "import-cycle-baseline.txt",
);

/**
 * Canonical signature for one cycle: its member files (src-relative, POSIX
 * separators) sorted and joined. Two runs that find the same set of files in a
 * cycle produce the same signature regardless of discovery order.
 */
function sccSignature(memberRelPaths: string[]): string {
  return [...memberRelPaths].sort().join(" | ");
}

/**
 * Compute the SCC member-set signature for every strongly-connected component
 * of size > 1 (Tarjan, iterative). Returns the SET of signatures — the unit of
 * comparison for the guard, so a swap (new cycle in, old cycle out, same count)
 * is caught.
 */
function computeSccSignatures(files: string[]): Set<string> {
  // One shared graph build + Tarjan pass, imported from the detector's own
  // library — the unit this guard compares against the committed baseline is
  // exactly what `npm run check-import-cycles:baseline` writes.
  const graph = buildGraph(files, SERVER_SRC);
  const signatures = new Set<string>();
  for (const comp of stronglyConnectedComponents(graph)) {
    if (comp.length > 1) {
      const members = comp.map((i) =>
        relative(SERVER_SRC, graph.nodes[i]!).split("\\").join("/"),
      );
      signatures.add(sccSignature(members));
    }
  }
  return signatures;
}

/**
 * Parse the committed baseline file's "Cycle N (M files):" blocks into the same
 * member-set signature form produced by computeSccSignatures. Each block is a
 * header line followed by indented member file paths until a blank line.
 */
function baselineSignatures(): Set<string> {
  const text = readFileSync(BASELINE_PATH, "utf-8");
  const lines = text.split("\n");
  const signatures = new Set<string>();
  let current: string[] | null = null;
  const flush = (): void => {
    if (current && current.length > 0) {
      signatures.add(sccSignature(current));
    }
    current = null;
  };
  const headerRe = /^Cycle\s+\d+\s+\(\d+\s+files?\):/;
  for (const raw of lines) {
    if (headerRe.test(raw.trim())) {
      flush();
      current = [];
      continue;
    }
    if (current !== null) {
      const member = raw.trim();
      if (member === "") {
        flush();
      } else {
        current.push(member.split("\\").join("/"));
      }
    }
  }
  flush();
  if (signatures.size === 0) {
    throw new Error(
      "could not parse any cycle member sets from the baseline file; expected " +
        "'Cycle N (M files):' blocks followed by indented member paths",
    );
  }
  return signatures;
}

describe("import-cycle baseline guard", () => {
  const files = allTsFiles(SERVER_SRC);

  it("sanity: the scanner found the source tree", () => {
    expect(files.length).toBeGreaterThan(400);
  });

  it("the baseline file parses into the expected member sets", () => {
    // Guards the parser itself: the committed baseline currently lists 9
    // cycles, so a parse that silently yields an empty/short set (and would
    // make the guard below vacuous) is caught here.
    const baseline = baselineSignatures();
    const headerCount = (
      readFileSync(BASELINE_PATH, "utf-8").match(/^Cycle\s+\d+\s+\(/gm) ?? []
    ).length;
    expect(baseline.size).toBe(headerCount);
    expect(baseline.size).toBeGreaterThanOrEqual(1);
  });

  it("introduces no NEW import cycle (by member set) beyond the committed baseline", () => {
    const baseline = baselineSignatures();
    const current = computeSccSignatures(files);

    // The defect this catches: a swap that keeps the COUNT flat. We compare the
    // exact member sets, so a brand-new cycle reds even if an old one vanished
    // in the same diff.
    const introduced = [...current].filter((sig) => !baseline.has(sig)).sort();
    expect(
      introduced,
      "A NEW import cycle (member set not in the committed baseline) appeared " +
        "(scoping §8 risk 1) — even if the total cycle count did not rise (a " +
        "swap can mask it). Inspect with `npm run check-import-cycles`, break " +
        "the new cycle, or — if it is intentional and reviewed — regenerate the " +
        "baseline with `npm run check-import-cycles:baseline` in this PR. " +
        "New cycle(s):\n  " + introduced.join("\n  "),
    ).toEqual([]);
  });
});
