/**
 * Regenerate `em-dash-baseline.txt` from the SAME public-surface resolver and
 * the SAME comment-strip the em-dash guard uses, so the baseline can never
 * drift from the guard's scope/counting. This is the only sanctioned way to
 * rewrite the baseline.
 *
 * Run from the `server/` directory:
 *   npx tsx test/structure/gen-em-dash-baseline.ts
 *
 * It writes the per-file counts (count\tpath, sorted by path) for every
 * in-scope file with >=1 em-dash, preserving the header comment block. Use it
 * ONLY to (a) seed the baseline when scope changes, or (b) lock in reductions
 * after a dedicated prose-cleanup PR. It NEVER rewrites prose; it only records
 * the current state so the guard becomes fail-on-new.
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  REPO_ROOT,
  publicFacingRelPaths,
  firstPartySourceFiles,
  isFirstPartySourceCode,
  stripCodeComments,
} from "./public-surface";

const HERE = join(fileURLToPath(import.meta.url), "..");
const BASELINE_PATH = join(HERE, "em-dash-baseline.txt");
const EM_DASH = "—";

function emDashCount(rel: string): number {
  const abs = join(REPO_ROOT, rel);
  if (!existsSync(abs)) return 0;
  let txt = readFileSync(abs, "utf8");
  if (isFirstPartySourceCode(rel)) txt = stripCodeComments(txt, rel);
  let n = 0;
  let idx = txt.indexOf(EM_DASH);
  while (idx !== -1) {
    n++;
    idx = txt.indexOf(EM_DASH, idx + 1);
  }
  return n;
}

const HEADER = `# Em-dash ratchet baseline (DoE review C-1, the no-em-dash rule).
#
# The no-em-dash rule (CLAUDE.md, 2026-04-21): ZERO em-dashes (—, U+2014) in
# public-facing artifacts. This file pins the CURRENT per-file em-dash count
# across the guard's scope so the guard is a FAIL-ON-NEW ratchet:
#
#   - Adding an em-dash to ANY in-scope file (count exceeds its baseline, or a
#     file not listed here gains one) -> the em-dash guard reds.
#   - REMOVING em-dashes is always allowed; when a file drops to 0 the guard
#     tells you to delete its row here so the ratchet tightens permanently.
#
# SCOPE (mirrors public-surface.ts, used by em-dash.test.ts): public root docs
# (README*, CHANGELOG*, ROADMAP.md, SANCTUARY_ARCHITECTURE.md,
# sanctuary_framework.md), the public text subtrees (docs/, announcements/,
# examples/, quickstart/, rfcs/), package metadata + the plugin manifest, and
# every tracked server/src TS file scanned CODE-ONLY (comments/JSDoc stripped —
# the rule exempts code comments).
#
# TODO (no-em-dash debt): drive these counts to 0 in dedicated prose-cleanup
# PRs (NOT mixed with code changes), then delete this file and flip the guard to
# a hard "zero em-dashes anywhere in scope" assertion. Each row removed is debt
# retired.
#
# DO NOT hand-edit to raise a count. Regenerate ONLY via
#   npx tsx test/structure/gen-em-dash-baseline.ts
# (from server/) after a legitimate scope change or a prose-cleanup reduction.
#
# Format: one row per file with at least one em-dash, "<count>\\t<repo-relative-path>",
# sorted by path. Lines starting with '#' and blank lines are ignored.
#`;

function main(): void {
  const rels = [...new Set([...publicFacingRelPaths(), ...firstPartySourceFiles()])].sort();
  const rows: string[] = [];
  for (const rel of rels) {
    const c = emDashCount(rel);
    if (c > 0) rows.push(`${c}\t${rel}`);
  }
  const body = `${HEADER}\n${rows.join("\n")}\n`;
  writeFileSync(BASELINE_PATH, body, "utf8");
  process.stdout.write(
    `em-dash-baseline.txt regenerated: ${rows.length} file(s) with em-dashes ` +
      `across ${rels.length} in-scope file(s).\n`,
  );
}

main();
