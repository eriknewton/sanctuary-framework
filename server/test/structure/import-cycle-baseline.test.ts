/**
 * Import-cycle baseline guard (Phase-0 rename safety net).
 *
 * The zero-dependency cycle detector (scripts/check-import-cycles.ts) reports
 * the current set of import cycles in server/src. The reorg's god-file splits +
 * barrel introductions are a classic way to add an import cycle by accident (a
 * cycle can compile yet break import-time tool-registration order — scoping §8
 * risk 1, the index.ts split risk). A committed baseline
 * (test/fixtures/import-cycle-baseline.txt) freezes the count that exists today;
 * this test fails if a change INTRODUCES a new cycle, while tolerating the
 * pre-existing ones until they are paid down deliberately.
 *
 * It re-runs the detector's logic in-process (importing the script would run its
 * main()), so the gate stays zero-dependency and in lockstep with the committed
 * baseline file. The baseline is regenerated with `npm run check-import-cycles:baseline`.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(import.meta.url);
const SERVER_DIR = resolve(HERE, "..", "..", "..");
const SERVER_SRC = join(SERVER_DIR, "src");
const BASELINE_PATH = join(
  SERVER_DIR,
  "test",
  "fixtures",
  "import-cycle-baseline.txt",
);

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

const FROM_RE = /\b(?:import|export)\b[^;]*?\bfrom\s*["'`]([^"'`]+)["'`]/g;
const BARE_IMPORT_RE = /\bimport\s*["'`]([^"'`]+)["'`]/g;
const DYNAMIC_RE = /\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g;

function extractSpecifiers(source: string): string[] {
  const specs = new Set<string>();
  for (const re of [FROM_RE, BARE_IMPORT_RE, DYNAMIC_RE]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) specs.add(m[1]!);
  }
  return [...specs];
}

function resolveSpecifier(fromFile: string, spec: string): string | null {
  if (!spec.startsWith(".")) return null;
  const base = resolve(dirname(fromFile), spec);
  const candidates: string[] = [];
  if (/\.js$/.test(spec)) {
    candidates.push(base.replace(/\.js$/, ".ts"));
    candidates.push(join(base.replace(/\.js$/, ""), "index.ts"));
  } else if (/\.ts$/.test(spec)) {
    candidates.push(base);
  } else {
    candidates.push(base + ".ts", join(base, "index.ts"));
  }
  for (const cand of candidates) {
    if (existsSync(cand) && statSync(cand).isFile()) {
      const rel = relative(SERVER_SRC, cand);
      return rel.startsWith("..") ? null : cand;
    }
  }
  return null;
}

/** Count strongly-connected components of size > 1 (Tarjan, iterative). */
function countCycles(files: string[]): number {
  const index = new Map<string, number>();
  files.forEach((f, i) => index.set(f, i));
  const adj: number[][] = files.map(() => []);
  for (const file of files) {
    const from = index.get(file)!;
    for (const spec of extractSpecifiers(readFileSync(file, "utf-8"))) {
      const target = resolveSpecifier(file, spec);
      if (target === null) continue;
      const to = index.get(target);
      if (to === undefined || to === from) continue;
      if (!adj[from]!.includes(to)) adj[from]!.push(to);
    }
  }
  const n = files.length;
  const idx = new Int32Array(n).fill(-1);
  const low = new Int32Array(n).fill(-1);
  const onStack = new Uint8Array(n);
  const stack: number[] = [];
  let counter = 0;
  let cycles = 0;
  for (let start = 0; start < n; start++) {
    if (idx[start] !== -1) continue;
    const call: Array<{ node: number; pos: number }> = [{ node: start, pos: 0 }];
    idx[start] = low[start] = counter++;
    stack.push(start);
    onStack[start] = 1;
    while (call.length > 0) {
      const frame = call[call.length - 1]!;
      const neighbors = adj[frame.node]!;
      if (frame.pos < neighbors.length) {
        const w = neighbors[frame.pos]!;
        frame.pos++;
        if (idx[w] === -1) {
          idx[w] = low[w] = counter++;
          stack.push(w);
          onStack[w] = 1;
          call.push({ node: w, pos: 0 });
        } else if (onStack[w] === 1) {
          low[frame.node] = Math.min(low[frame.node]!, idx[w]!);
        }
      } else {
        if (low[frame.node] === idx[frame.node]) {
          const comp: number[] = [];
          for (;;) {
            const w = stack.pop()!;
            onStack[w] = 0;
            comp.push(w);
            if (w === frame.node) break;
          }
          if (comp.length > 1) cycles++;
        }
        call.pop();
        const parent = call[call.length - 1];
        if (parent) {
          low[parent.node] = Math.min(low[parent.node]!, low[frame.node]!);
        }
      }
    }
  }
  return cycles;
}

function baselineCount(): number {
  const text = readFileSync(BASELINE_PATH, "utf-8");
  const m = text.match(/cycles \(SCC size > 1\)\s*\.*\s*(\d+)/);
  if (!m) throw new Error("could not parse cycle count from baseline file");
  return Number.parseInt(m[1]!, 10);
}

describe("import-cycle baseline guard", () => {
  const files = allTsFiles(SERVER_SRC);

  it("sanity: the scanner found the source tree", () => {
    expect(files.length).toBeGreaterThan(400);
  });

  it("introduces no NEW import cycle beyond the committed baseline", () => {
    const baseline = baselineCount();
    const current = countCycles(files);
    expect(
      current,
      `Import cycle count rose from the committed baseline (${baseline}) to ` +
        `${current}. A reorg/split likely introduced a new cycle (scoping §8 ` +
        "risk 1). Inspect with `npm run check-import-cycles`, break the cycle, " +
        "or — if the increase is intentional and reviewed — regenerate the " +
        "baseline with `npm run check-import-cycles:baseline` in this PR.",
    ).toBeLessThanOrEqual(baseline);
  });
});
