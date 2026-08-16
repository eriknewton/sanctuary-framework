/**
 * Import-graph library for server/src: specifier extraction, module
 * resolution, cycle detection, and transitive-reachability queries.
 *
 * This is the ONE parser for "what does file X import, and does that chain
 * reach file Y" (AGENTS.md rule 5 — cross-file parsers are shared, not
 * hand-copied per consumer; a mirrored regex drifts from the original the
 * first time either one is edited). `check-import-cycles.ts` (the CLI/CI
 * reporting entry point) and `test/structure/pqc-slice1-additive.test.ts`
 * (the legacy-frozen-serializer boundary guard) both import from here rather
 * than growing their own copy.
 *
 * Split into `.lib.ts` (logic, side-effect-free) + a thin `.ts` runner
 * mirrors `check-no-raw-console.lib.ts` / `check-no-raw-console.ts`: importing
 * the library from a test must not also run a CLI `main()` or call
 * `process.exit`.
 *
 * Dependency-free: a regex import scanner over Node built-ins, deliberately
 * not the `typescript` compiler API, so the tool stays cheap and obvious (see
 * the module doc-comment history in `check-import-cycles.ts` before this
 * split).
 *
 * Module resolution mirrors the repo's `moduleResolution: bundler` setup:
 *   - only relative specifiers ("./x", "../y") are followed;
 *   - bare/package specifiers (no leading ".") are ignored as externals;
 *   - a ".js" suffix on a relative specifier maps to the ".ts" source
 *     (the repo writes ESM imports with explicit .js specifiers);
 *   - extensionless and directory specifiers resolve via .ts then /index.ts.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

// ---- File discovery -------------------------------------------------------

export function allTsFiles(dir: string): string[] {
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
export function stripComments(source: string): string {
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
// Same clause, but also captures whether it is a FULLY type-only clause
// (`import type {...} from "x"` / `export type {...} from "x"`) — group 2 is
// present only when `type` immediately follows the `import`/`export`
// keyword. Kept separate from FROM_RE (rather than adding a group to it) so
// existing `m[1]` callers of FROM_RE are undisturbed.
const FROM_TYPE_AWARE_RE =
  /\b(?:import|export)\b(\s+type\b)?[^;]*?\bfrom\s*["'`]([^"'`]+)["'`]/g;
// side-effect import:  import "x";
const BARE_IMPORT_RE = /\bimport\s*["'`]([^"'`]+)["'`]/g;
// dynamic import("x")
const DYNAMIC_RE = /\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g;

export function extractSpecifiers(source: string): string[] {
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

/**
 * Like `extractSpecifiers`, but omits specifiers reached only through a
 * FULLY type-only clause (`import type {...} from "x"` /
 * `export type {...} from "x"`). TypeScript elides a wholly type-only clause
 * at compile time, so it creates zero runtime coupling; a consumer asking
 * "does file A depend on file B at runtime" (as opposed to "is there any
 * lexical edge between them", which is what the cycle detector's
 * `extractSpecifiers`/`buildGraph` care about) must not treat that clause as
 * an edge, or it flags a dependency that can never execute. A MIXED clause
 * (`import { type A, b } from "x"`) still counts: at least one binding (`b`)
 * is a value, so the module is genuinely evaluated at runtime, even though
 * this regex scanner cannot (and does not need to) separate which half of
 * the named-import list is which.
 */
export function extractValueSpecifiers(source: string): string[] {
  const scrubbed = stripComments(source);
  const specs = new Set<string>();
  FROM_TYPE_AWARE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FROM_TYPE_AWARE_RE.exec(scrubbed)) !== null) {
    const isFullyTypeOnlyClause = m[1] !== undefined;
    if (isFullyTypeOnlyClause) continue;
    specs.add(m[2]!);
  }
  for (const re of [BARE_IMPORT_RE, DYNAMIC_RE]) {
    re.lastIndex = 0;
    while ((m = re.exec(scrubbed)) !== null) {
      specs.add(m[1]!);
    }
  }
  return [...specs];
}

// ---- Module resolution ----------------------------------------------------

/**
 * Resolve a relative specifier from an importing file to an on-disk .ts file
 * under `srcRoot`. Returns the absolute resolved path, or null if the
 * specifier is external (bare) or resolves outside `srcRoot` / to a non-.ts
 * target.
 */
export function resolveSpecifier(
  fromFile: string,
  spec: string,
  srcRoot: string,
): string | null {
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
      // Only follow edges that stay inside srcRoot.
      const rel = relative(srcRoot, cand);
      if (!rel.startsWith("..")) return cand;
      return null;
    }
  }
  return null;
}

// ---- Graph build ------------------------------------------------------

export interface ImportGraph {
  nodes: string[]; // absolute file paths
  index: Map<string, number>;
  adj: number[][]; // adjacency list of node indices
  edgeCount: number;
  selfImports: string[];
}

export function buildGraph(files: string[], srcRoot: string): ImportGraph {
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
      const target = resolveSpecifier(file, spec, srcRoot);
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
export function stronglyConnectedComponents(graph: ImportGraph): number[][] {
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

// ---- Transitive reachability -----------------------------------------

/**
 * Does `fromFile` import `toFile` AT RUNTIME, directly or through any chain
 * of intermediate `srcRoot`-local files? BFS over the same specifier
 * extraction/resolution used by the cycle detector, so a boundary guard (e.g.
 * "this frozen file never reaches the suite registry") tracks real module
 * edges instead of a whole-file substring, which both false-positives on a
 * comment that merely mentions the target's name and false-negatives on an
 * indirect/re-exported import path.
 *
 * Deliberately uses `extractValueSpecifiers`, not `extractSpecifiers`: a
 * fully type-only `import type` chain (two of which chain `mesh/trust-root.ts`
 * -> `mesh/types.ts` -> `core/crypto-suite-registry.ts` on main today) is
 * erased by the compiler and creates no runtime dependency, and this
 * function's callers care about runtime coupling specifically ("does this
 * frozen serializer end up DEPENDING ON the new suite abstraction when it
 * runs", not "is there any lexical mention of it anywhere in the type
 * graph"). Treating a type-only edge as a hit here would make the guard fail
 * on a chain that can never execute, trading one false signal (the substring
 * check's false-negative) for another (a type-only false-positive).
 *
 * `visited` guards against the graph's existing cycles sending this into a
 * loop; each file is read and parsed at most once per call.
 */
export function transitivelyImports(
  fromFile: string,
  toFile: string,
  srcRoot: string,
): boolean {
  const visited = new Set<string>([fromFile]);
  const queue: string[] = [fromFile];
  let qi = 0;
  while (qi < queue.length) {
    const current = queue[qi]!;
    qi += 1;
    if (!existsSync(current)) continue;
    const source = readFileSync(current, "utf-8");
    for (const spec of extractValueSpecifiers(source)) {
      const target = resolveSpecifier(current, spec, srcRoot);
      if (target === null) continue;
      if (target === toFile) return true;
      if (visited.has(target)) continue;
      visited.add(target);
      queue.push(target);
    }
  }
  return false;
}
