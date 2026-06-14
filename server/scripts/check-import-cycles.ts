#!/usr/bin/env node
/**
 * Zero-dependency import-cycle detector over server/src.
 *
 * Scans every .ts file under server/src for static `import ... from "..."`,
 * `export ... from "..."`, and dynamic `import("...")` specifiers that resolve
 * to a relative path WITHIN server/src, builds the file-level import graph,
 * and reports every cycle (strongly-connected component of size > 1, plus
 * single-file self-imports).
 *
 * This is a BASELINE / REPORTING tool, not a failing gate. The reorg splits
 * god-files and adds index.ts barrels; barrels are a classic way to introduce
 * import cycles by accident. Running this before and after each phase lets the
 * reorg avoid INTRODUCING new cycles. It always exits 0 and just reports.
 *
 * Dependency-free: a regex import scanner over Node built-ins. No new npm
 * package; the already-present `typescript` compiler API is deliberately not
 * used so the tool stays cheap and obvious.
 *
 * Module resolution mirrors the repo's `moduleResolution: bundler` setup:
 *   - only relative specifiers ("./x", "../y") are followed;
 *   - bare/package specifiers (no leading ".") are ignored as externals;
 *   - a ".js" suffix on a relative specifier maps to the ".ts" source
 *     (the repo writes ESM imports with explicit .js specifiers);
 *   - extensionless and directory specifiers resolve via .ts then /index.ts.
 *
 * Usage:
 *   npx vite-node scripts/check-import-cycles.ts
 *   npx vite-node scripts/check-import-cycles.ts --list-edges
 *
 * Exit code is always 0.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

// ---- Path anchors ---------------------------------------------------------
// scripts/ -> server/ -> server/src.

const SCRIPT_DIR = import.meta.dirname ?? resolve(".");
const SERVER_DIR = resolve(SCRIPT_DIR, "..");
const SERVER_SRC = join(SERVER_DIR, "src");

// ---- Arg parsing ----------------------------------------------------------

function parseArgs(argv: string[]): { listEdges: boolean } {
  let listEdges = false;
  for (const a of argv) {
    if (a === "--list-edges") listEdges = true;
  }
  return { listEdges };
}

// ---- File discovery -------------------------------------------------------

function allTsFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
    }
  };
  walk(dir);
  out.sort();
  return out;
}

// ---- Import-specifier extraction ------------------------------------------

/**
 * Strip line comments, block comments, and string-literal CONTENTS from a
 * source so the specifier regexes do not match import-like text inside a
 * comment or an unrelated string. Quote characters are preserved so the
 * specifier regexes (which look for a quoted string after `from`/`import(`)
 * still see the delimiters; only the inner text that is NOT part of an
 * import/export specifier is blanked.
 *
 * Rather than fully blank string contents (which would erase the specifier
 * we want to read), this only removes comments. The specifier regexes below
 * anchor on `from` / `import(` / `export ... from`, which effectively never
 * appear inside ordinary string payloads in this codebase, so comment removal
 * is the load-bearing scrub.
 */
function stripComments(source: string): string {
  let out = "";
  let i = 0;
  let state: "code" | "line" | "block" | "dq" | "sq" | "tpl" = "code";
  while (i < source.length) {
    const c = source[i]!;
    const next = source[i + 1];
    if (state === "code") {
      if (c === "/" && next === "/") {
        state = "line";
        i += 2;
        continue;
      }
      if (c === "/" && next === "*") {
        state = "block";
        i += 2;
        continue;
      }
      if (c === '"') {
        state = "dq";
        out += c;
        i += 1;
        continue;
      }
      if (c === "'") {
        state = "sq";
        out += c;
        i += 1;
        continue;
      }
      if (c === "`") {
        state = "tpl";
        out += c;
        i += 1;
        continue;
      }
      out += c;
      i += 1;
      continue;
    }
    if (state === "line") {
      if (c === "\n") {
        state = "code";
        out += c;
      }
      i += 1;
      continue;
    }
    if (state === "block") {
      if (c === "*" && next === "/") {
        state = "code";
        i += 2;
        continue;
      }
      if (c === "\n") out += c;
      i += 1;
      continue;
    }
    // string states: keep the delimiters and contents (import specifiers live
    // here), but handle escapes so an escaped quote does not end the string.
    if (state === "dq" || state === "sq" || state === "tpl") {
      out += c;
      if (c === "\\" && i + 1 < source.length) {
        out += source[i + 1];
        i += 2;
        continue;
      }
      if (state === "dq" && c === '"') state = "code";
      else if (state === "sq" && c === "'") state = "code";
      else if (state === "tpl" && c === "`") state = "code";
      i += 1;
      continue;
    }
  }
  return out;
}

// import ... from "x";  /  export ... from "x";  /  export * from "x";
const FROM_RE = /\b(?:import|export)\b[^;]*?\bfrom\s*["'`]([^"'`]+)["'`]/g;
// side-effect import:  import "x";
const BARE_IMPORT_RE = /\bimport\s*["'`]([^"'`]+)["'`]/g;
// dynamic import("x")
const DYNAMIC_RE = /\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g;

function extractSpecifiers(source: string): string[] {
  const scrubbed = stripComments(source);
  const specs = new Set<string>();
  for (const re of [FROM_RE, BARE_IMPORT_RE, DYNAMIC_RE]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(scrubbed)) !== null) {
      specs.add(m[1]!);
    }
  }
  return [...specs];
}

// ---- Module resolution ----------------------------------------------------

/**
 * Resolve a relative specifier from an importing file to an on-disk .ts file
 * under server/src. Returns the absolute resolved path, or null if the
 * specifier is external (bare) or resolves outside server/src / to a non-.ts
 * target.
 */
function resolveSpecifier(fromFile: string, spec: string): string | null {
  if (!spec.startsWith(".")) return null; // external / package import
  const fromDir = dirname(fromFile);
  // The repo writes ESM imports with explicit `.js`; map back to `.ts`.
  const base = resolve(fromDir, spec);

  const candidates: string[] = [];
  if (/\.js$/.test(spec)) {
    candidates.push(base.replace(/\.js$/, ".ts"));
    candidates.push(base.replace(/\.js$/, ".tsx"));
  } else if (/\.ts$/.test(spec)) {
    candidates.push(base);
  } else {
    candidates.push(base + ".ts");
    candidates.push(base + ".tsx");
    candidates.push(join(base, "index.ts"));
    candidates.push(join(base, "index.tsx"));
  }
  // Also allow a bare directory specifier ending in .js that pointed at an
  // index (rare, but handle "./foo/index.js" already covered, and "./foo.js"
  // that is actually a directory barrel).
  if (/\.js$/.test(spec)) {
    candidates.push(join(base.replace(/\.js$/, ""), "index.ts"));
  }

  for (const cand of candidates) {
    if (existsSync(cand) && statSync(cand).isFile()) {
      // Only follow edges that stay inside server/src.
      const rel = relative(SERVER_SRC, cand);
      if (!rel.startsWith("..")) return cand;
      return null;
    }
  }
  return null;
}

// ---- Graph build ----------------------------------------------------------

interface Graph {
  nodes: string[]; // absolute file paths
  index: Map<string, number>;
  adj: number[][]; // adjacency list of node indices
  edgeCount: number;
  selfImports: string[];
}

function buildGraph(files: string[]): Graph {
  const index = new Map<string, number>();
  files.forEach((f, i) => index.set(f, i));
  const adj: number[][] = files.map(() => []);
  const seenEdge = new Set<string>();
  const selfImports: string[] = [];
  let edgeCount = 0;

  for (const file of files) {
    const from = index.get(file)!;
    const source = readFileSync(file, "utf-8");
    for (const spec of extractSpecifiers(source)) {
      const target = resolveSpecifier(file, spec);
      if (target === null) continue;
      const to = index.get(target);
      if (to === undefined) continue; // resolved outside the scanned set
      if (to === from) {
        if (!selfImports.includes(file)) selfImports.push(file);
        continue;
      }
      const key = `${from}->${to}`;
      if (seenEdge.has(key)) continue;
      seenEdge.add(key);
      adj[from]!.push(to);
      edgeCount++;
    }
  }

  return { nodes: files, index, adj, edgeCount, selfImports };
}

// ---- Cycle detection (Tarjan SCC) -----------------------------------------

/**
 * Tarjan's strongly-connected-components. Any SCC with more than one node is
 * a cycle (a set of files mutually reachable through imports). Iterative to
 * avoid blowing the call stack on a large graph.
 */
function stronglyConnectedComponents(graph: Graph): number[][] {
  const n = graph.nodes.length;
  const indexOf = new Int32Array(n).fill(-1);
  const lowlink = new Int32Array(n).fill(-1);
  const onStack = new Uint8Array(n);
  const stack: number[] = [];
  const sccs: number[][] = [];
  let counter = 0;

  // Iterative DFS frame: node + position in its adjacency list.
  for (let start = 0; start < n; start++) {
    if (indexOf[start] !== -1) continue;
    const callStack: Array<{ node: number; pos: number }> = [
      { node: start, pos: 0 },
    ];
    indexOf[start] = lowlink[start] = counter++;
    stack.push(start);
    onStack[start] = 1;

    while (callStack.length > 0) {
      const frame = callStack[callStack.length - 1]!;
      const { node } = frame;
      const neighbors = graph.adj[node]!;
      if (frame.pos < neighbors.length) {
        const w = neighbors[frame.pos]!;
        frame.pos++;
        if (indexOf[w] === -1) {
          indexOf[w] = lowlink[w] = counter++;
          stack.push(w);
          onStack[w] = 1;
          callStack.push({ node: w, pos: 0 });
        } else if (onStack[w] === 1) {
          lowlink[node] = Math.min(lowlink[node]!, indexOf[w]!);
        }
      } else {
        // Done with this node; propagate lowlink to parent and close SCC root.
        if (lowlink[node] === indexOf[node]) {
          const comp: number[] = [];
          for (;;) {
            const w = stack.pop()!;
            onStack[w] = 0;
            comp.push(w);
            if (w === node) break;
          }
          sccs.push(comp);
        }
        callStack.pop();
        const parent = callStack[callStack.length - 1];
        if (parent) {
          lowlink[parent.node] = Math.min(
            lowlink[parent.node]!,
            lowlink[node]!,
          );
        }
      }
    }
  }
  return sccs;
}

// ---- Report ---------------------------------------------------------------

function out(line = ""): void {
  // SAFETY: developer reporting tool; stdout is the contract for the report.
  process.stdout.write(line + "\n");
}

function main(): void {
  const { listEdges } = parseArgs(process.argv.slice(2));
  const files = allTsFiles(SERVER_SRC);
  const graph = buildGraph(files);
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
