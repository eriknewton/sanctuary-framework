#!/usr/bin/env node
/**
 * Professionalization reorg evidence refresher.
 *
 * Recomputes the Section-1 evidence of the professionalization plan against
 * the CURRENT tree so each reorg phase can attach fresh numbers instead of
 * citing a stale snapshot. The reorg moves files; these counts drift every
 * phase, so the plan's "before/after" claims must be regenerated, not copied.
 *
 * Computes and prints a scannable report:
 *   - module directories under server/src (immediate subdirs)
 *   - loose .ts files at server/src root
 *   - total line count across server/src/**\/*.ts
 *   - test files under server/test
 *   - barrel coverage: how many module dirs contain an index.ts (X of N)
 *   - top ~20 largest .ts files under server/src by line count (god-files)
 *   - per-layer importer counts for cognitive .. reputation
 *   - the repo-root .test-baseline value (REPO root, not server/)
 *
 * Dependency-free: Node built-ins plus child_process shell-outs to
 * git/find/grep, matching the existing scripts in this directory.
 *
 * Usage:
 *   npx tsx scripts/refresh-reorg-evidence.ts
 *   npx tsx scripts/refresh-reorg-evidence.ts --top 30
 *
 * This is a reporting tool. It always exits 0; it never fails a build.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";

// ---- Path anchors ---------------------------------------------------------
// scripts/ -> server/ -> repo root. Mirrors check-no-raw-console.ts, which
// resolves the repo root as two levels above the script directory.

const SCRIPT_DIR = import.meta.dirname ?? resolve(".");
const SERVER_DIR = resolve(SCRIPT_DIR, "..");
const REPO_ROOT = resolve(SERVER_DIR, "..");
const SERVER_SRC = join(SERVER_DIR, "src");
const SERVER_TEST = join(SERVER_DIR, "test");
const TEST_BASELINE_PATH = join(REPO_ROOT, ".test-baseline");

const LAYER_DIRS = [
  "cognitive",
  "operational",
  "disclosure",
  "reputation",
] as const;

// ---- Arg parsing ----------------------------------------------------------

function parseArgs(argv: string[]): { top: number } {
  let top = 20;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--top") {
      const n = Number.parseInt(argv[++i] ?? "", 10);
      if (Number.isFinite(n) && n > 0) top = n;
    }
  }
  return { top };
}

// ---- File discovery -------------------------------------------------------

/** Immediate subdirectories of a directory (non-recursive). */
function immediateSubdirs(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

/** Loose .ts files at the immediate level of a directory (non-recursive). */
function looseTsFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".ts"))
    .map((e) => e.name)
    .sort();
}

/** Every .ts file under a directory tree (recursive). */
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

/** Line count for a single file. Counts newline-separated lines. */
function lineCount(file: string): number {
  const text = readFileSync(file, "utf-8");
  if (text.length === 0) return 0;
  // Count lines the way `wc -l` would when a trailing newline exists, but
  // also count a final unterminated line so partial files are not undercounted.
  let lines = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\n") lines++;
  }
  if (text[text.length - 1] !== "\n") lines++;
  return lines;
}

// ---- Layer importer counting ----------------------------------------------

/**
 * Count files under server/src and server/test that reference a path string
 * (e.g. "cognitive"). Shells out to grep, which the repo already does in
 * other scripts. Returns the count of distinct matching files.
 */
function layerImporterCount(needle: string): number {
  const roots = [SERVER_SRC, SERVER_TEST].filter((d) => existsSync(d));
  if (roots.length === 0) return 0;
  try {
    const out = execFileSync(
      "grep",
      ["-rlF", "--include=*.ts", needle, ...roots],
      { encoding: "utf-8" },
    );
    return out.split("\n").filter((l) => l.trim().length > 0).length;
  } catch (err) {
    // grep exits 1 when there are zero matches; that is not an error here.
    const code = (err as { status?: number }).status;
    if (code === 1) return 0;
    throw err;
  }
}

// ---- .test-baseline -------------------------------------------------------

function readTestBaseline(): string {
  if (!existsSync(TEST_BASELINE_PATH)) return "(missing)";
  return readFileSync(TEST_BASELINE_PATH, "utf-8").trim();
}

// ---- Git context (best-effort) --------------------------------------------

function gitContext(): { branch: string; commit: string } {
  const safe = (args: string[]): string => {
    try {
      return execFileSync("git", args, {
        cwd: REPO_ROOT,
        encoding: "utf-8",
      }).trim();
    } catch {
      return "(unknown)";
    }
  };
  return {
    branch: safe(["rev-parse", "--abbrev-ref", "HEAD"]),
    commit: safe(["rev-parse", "--short", "HEAD"]),
  };
}

// ---- Report assembly ------------------------------------------------------

interface SizedFile {
  rel: string;
  lines: number;
}

function out(line = ""): void {
  // SAFETY: developer reporting tool; stdout is the contract for the report.
  process.stdout.write(line + "\n");
}

function main(): void {
  const { top } = parseArgs(process.argv.slice(2));

  const moduleDirs = immediateSubdirs(SERVER_SRC);
  const loose = looseTsFiles(SERVER_SRC);
  const srcFiles = allTsFiles(SERVER_SRC);

  const sized: SizedFile[] = srcFiles.map((f) => ({
    rel: relative(SERVER_DIR, f),
    lines: lineCount(f),
  }));
  const totalLines = sized.reduce((acc, f) => acc + f.lines, 0);

  const testFiles = allTsFiles(SERVER_TEST).filter((f) =>
    /\.(test|spec)\.ts$/.test(basename(f)),
  );

  const barreled = moduleDirs.filter((name) =>
    existsSync(join(SERVER_SRC, name, "index.ts")),
  );

  const godFiles = [...sized].sort((a, b) => b.lines - a.lines).slice(0, top);

  const layerCounts = LAYER_DIRS.map((layer) => ({
    layer,
    count: layerImporterCount(layer),
  }));

  const baseline = readTestBaseline();
  const git = gitContext();

  // ---- Human-readable report ----
  out("============================================================");
  out("  Sanctuary professionalization reorg - evidence refresh");
  out("============================================================");
  out(`  repo root : ${REPO_ROOT}`);
  out(`  branch    : ${git.branch} @ ${git.commit}`);
  out("");

  out("-- Tree shape ----------------------------------------------");
  out(`  module directories under server/src ... ${moduleDirs.length}`);
  out(`  loose .ts files at server/src root .... ${loose.length}`);
  out(`  total .ts files under server/src ...... ${srcFiles.length}`);
  out(`  total lines across server/src/**/*.ts . ${totalLines}`);
  out(`  test files under server/test .......... ${testFiles.length}`);
  out(
    `  barrel coverage (dirs with index.ts) .. ${barreled.length} of ${moduleDirs.length}`,
  );
  out(`  repo-root .test-baseline .............. ${baseline}`);
  out("");

  out("-- Loose .ts files at server/src root ----------------------");
  for (const name of loose) out(`  ${name}`);
  out("");

  out("-- Module dirs WITHOUT an index.ts barrel ------------------");
  const unbarreled = moduleDirs.filter(
    (name) => !existsSync(join(SERVER_SRC, name, "index.ts")),
  );
  if (unbarreled.length === 0) {
    out("  (none - every module dir has a barrel)");
  } else {
    for (const name of unbarreled) out(`  ${name}`);
  }
  out("");

  out(`-- Top ${top} largest .ts files under server/src (god-files) -`);
  const widest = Math.max(...godFiles.map((f) => f.lines), 0).toString().length;
  godFiles.forEach((f, i) => {
    const rank = String(i + 1).padStart(2, " ");
    const lines = String(f.lines).padStart(widest, " ");
    out(`  ${rank}. ${lines}  ${f.rel}`);
  });
  out("");

  out("-- Per-layer importer counts (files under src + test) ------");
  for (const { layer, count } of layerCounts) {
    out(`  ${layer.padEnd(16, " ")} ${count}`);
  }
  out("");

  // ---- Markdown table block (timestamp-free, paste-ready) ----
  out("============================================================");
  out("  Markdown (timestamp-free; paste into the plan's Section 1)");
  out("============================================================");
  out("");
  out("| Metric | Value |");
  out("|--------|-------|");
  out(`| Module directories under \`server/src\` | ${moduleDirs.length} |`);
  out(`| Loose \`.ts\` files at \`server/src\` root | ${loose.length} |`);
  out(`| Total \`.ts\` files under \`server/src\` | ${srcFiles.length} |`);
  out(`| Total lines across \`server/src/**/*.ts\` | ${totalLines} |`);
  out(`| Test files under \`server/test\` | ${testFiles.length} |`);
  out(
    `| Barrel coverage (dirs with \`index.ts\`) | ${barreled.length} of ${moduleDirs.length} |`,
  );
  out(`| Repo-root \`.test-baseline\` | ${baseline} |`);
  out("");
  out("| Layer | Importer files (src + test) |");
  out("|-------|------------------------------|");
  for (const { layer, count } of layerCounts) {
    out(`| \`${layer}\` | ${count} |`);
  }
  out("");
  out(`Top ${top} largest \`.ts\` files under \`server/src\`:`);
  out("");
  out("| # | Lines | File |");
  out("|---|-------|------|");
  godFiles.forEach((f, i) => {
    out(`| ${i + 1} | ${f.lines} | \`${f.rel}\` |`);
  });
  out("");
}

main();
