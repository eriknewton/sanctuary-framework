#!/usr/bin/env node
/**
 * Zero-dependency import-cycle detector over server/src, CLI entry point.
 *
 * This is a BASELINE / REPORTING tool, not a failing gate. The reorg splits
 * god-files and adds index.ts barrels; barrels are a classic way to introduce
 * import cycles by accident. Running this before and after each phase lets the
 * reorg avoid INTRODUCING new cycles. It always exits 0 and just reports.
 *
 * Usage:
 *   npx tsx scripts/check-import-cycles.ts
 *   npx tsx scripts/check-import-cycles.ts --list-edges
 *
 * Exit code is always 0.
 *
 * Parser, resolver, and graph logic live in `check-import-cycles.lib.ts` (also
 * consumed by `test/structure/pqc-slice1-additive.test.ts`'s frozen-serializer
 * boundary guard). This file is the thin runner so importing the library from
 * a test does not also run this CLI's report-and-exit `main()`, mirroring
 * `check-no-raw-console.ts` / `check-no-raw-console.lib.ts`.
 */

import { relative, resolve } from "node:path";
import {
  allTsFiles,
  buildGraph,
  stronglyConnectedComponents,
} from "./check-import-cycles.lib.js";

// ---- Path anchors ---------------------------------------------------------
// scripts/ -> server/ -> server/src.

const SCRIPT_DIR = import.meta.dirname ?? resolve(".");
const SERVER_DIR = resolve(SCRIPT_DIR, "..");
const SERVER_SRC = resolve(SERVER_DIR, "src");

// ---- Arg parsing ----------------------------------------------------------

function parseArgs(argv: string[]): { listEdges: boolean } {
  let listEdges = false;
  for (const a of argv) {
    if (a === "--list-edges") listEdges = true;
  }
  return { listEdges };
}

// ---- Report ---------------------------------------------------------------

function out(line = ""): void {
  // SAFETY: developer reporting tool; stdout is the contract for the report.
  process.stdout.write(line + "\n");
}

function main(): void {
  const { listEdges } = parseArgs(process.argv.slice(2));
  const files = allTsFiles(SERVER_SRC);
  const graph = buildGraph(files, SERVER_SRC);
  const sccs = stronglyConnectedComponents(graph);
  const cycles = sccs.filter((c) => c.length > 1);

  // Stable ordering: by smallest member path, ascending.
  const rel = (i: number): string => relative(SERVER_SRC, graph.nodes[i]!);
  cycles.sort((a, b) => {
    const am = a.map(rel).sort()[0]!;
    const bm = b.map(rel).sort()[0]!;
    return am.localeCompare(bm);
  });

  out("============================================================");
  out("  Sanctuary import-cycle baseline (server/src)");
  out("============================================================");
  out(`  files scanned ......... ${files.length}`);
  out(`  intra-src edges ....... ${graph.edgeCount}`);
  out(`  self-imports .......... ${graph.selfImports.length}`);
  out(`  cycles (SCC size > 1) . ${cycles.length}`);
  out("");

  if (graph.selfImports.length > 0) {
    out("-- Self-imports (file imports itself) ----------------------");
    for (const f of graph.selfImports) out(`  ${relative(SERVER_SRC, f)}`);
    out("");
  }

  if (cycles.length === 0) {
    out("No multi-file import cycles found in server/src.");
  } else {
    out("-- Cycles --------------------------------------------------");
    out("(each cycle is a set of files mutually reachable via imports)");
    out("");
    cycles.forEach((comp, ci) => {
      const members = comp.map(rel).sort();
      out(`Cycle ${ci + 1}  (${members.length} files):`);
      for (const m of members) out(`    ${m}`);
      out("");
    });
  }

  if (listEdges) {
    out("-- All intra-src edges -------------------------------------");
    graph.adj.forEach((tos, from) => {
      for (const to of tos) {
        out(`  ${rel(from)}  ->  ${rel(to)}`);
      }
    });
    out("");
  }

  // Reporting tool: never fail the build.
  process.exitCode = 0;
}

main();
