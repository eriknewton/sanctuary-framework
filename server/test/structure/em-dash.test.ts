/**
 * EM-DASH guard (DoE review C-1, the no-em-dash rule) — FAIL-ON-NEW ratchet.
 *
 * THE RULE (CLAUDE.md, 2026-04-21): zero em-dashes (—, U+2014) in public-facing
 * artifacts. There is a large body of PRE-EXISTING em-dashes across the
 * public-facing surface (mostly internal-style audit/compliance/sprint reports
 * under docs/, plus example bundles and RFCs). The build directive is explicit:
 * do NOT rewrite public prose to clear them here.
 *
 * So this guard is a RATCHET, not a hard zero-assertion. It reads the committed
 * per-file baseline (`em-dash-baseline.txt`) and fails only when the situation
 * gets WORSE:
 *   - an in-scope file's current em-dash count EXCEEDS its baseline count, or
 *   - a file with NO baseline row gains an em-dash.
 * Reducing counts is always allowed; when a baselined file drops to 0 the guard
 * reds with a "tighten the baseline" message so the row gets removed and the
 * win is locked in. The baseline file's header TODO tracks the path to zero.
 *
 * SCOPE: the shared public-facing surface (see `public-surface.ts`) — public
 * root docs, the public text subtrees (docs/, announcements/, examples/,
 * quickstart/, rfcs/, the product components, server/public, templates, ...),
 * package metadata + the plugin manifest — PLUS every tracked server/src TS
 * file scanned CODE-ONLY (comments and JSDoc stripped). The no-em-dash rule
 * targets public-facing prose and user-visible strings; em-dashes inside
 * internal code comments are explicitly permitted (this matches
 * test/cli/no-em-dash-in-cli.test.ts). The doc surface is scanned whole; only
 * the code surface is comment-stripped (via the shared `stripCodeComments`, a
 * TypeScript PARSER-backed strip — not a regex or a hand-rolled scanner — so
 * em-dashes inside string/template/regex literals that contain comment tokens
 * are NOT lost). The scope + strip are shared with the
 * baseline generator (gen-em-dash-baseline.ts), so they cannot drift.
 *
 * CODE SCOPE: the em-dash code scan now covers ALL first-party JS/TS source
 * (firstPartySourceFiles — server/src plus menubar/, quickstart/, scripts/, the
 * server config/scripts, etc.), matching the no-CIMC guard. These render
 * user-visible UI/CLI strings, so they are in scope for the typography rule.
 * DELIBERATE BOUNDARY: Swift/Rust source is NOT in the em-dash ratchet (the
 * no-CIMC guard does scan .rs/.swift, because a CIMC attribution there is a hard
 * rule break, but em-dashes are a JS/TS-doc/UI typography concern and a
 * .rs/.swift ratchet would add noise for little value). Binary artifacts
 * (e.g. examples/.../bundle.pdf, docs/images/**) are also out: substring-scanning
 * binary content for em-dashes/CIMC is unreliable; their .md companions ARE scanned.
 *
 * TRUST BOUNDARY (accepted, documented): like every ratchet baseline in this
 * repo (`.test-baseline`, import-cycle-baseline.txt), the committed
 * `em-dash-baseline.txt` is author-maintained. A PR could in principle add a
 * new em-dash AND raise its baseline row in the same diff and stay green. That
 * is caught by REVIEW (a baseline raise is a visible, called-out diff with a
 * "DO NOT raise" banner), not by this test — mechanically forbidding a same-PR
 * raise would couple the test to git history. This matches how the repo's other
 * ratchets are governed; it is a deliberate boundary, not an oversight.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  REPO_ROOT,
  publicFacingRelPaths,
  firstPartySourceFiles,
  isFirstPartySourceCode,
  stripCodeComments,
} from "./public-surface";

const BASELINE_PATH = join(
  fileURLToPath(import.meta.url),
  "..",
  "em-dash-baseline.txt",
);

const EM_DASH = "—"; // —

/**
 * The in-scope set (repo-relative, sorted): the shared doc/text/metadata
 * surface PLUS every tracked server/src TS file.
 */
function inScopeRelPaths(): string[] {
  const set = new Set<string>([
    ...publicFacingRelPaths(),
    ...firstPartySourceFiles(),
  ]);
  return [...set].sort();
}

/**
 * Count em-dashes in a repo-relative file. server/src TS files are
 * comment-stripped first (code-only); everything else is counted whole.
 */
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

/**
 * Parse the baseline file into a path -> count map. FAILS on a duplicate path
 * row: a Map silently overwrites, so without an explicit seen-set a stale +
 * fresh row for the same file would let a regression through. We surface the
 * duplicate as an error string the test asserts on rather than papering over it.
 */
function parseBaseline(): { map: Map<string, number>; duplicates: string[] } {
  const map = new Map<string, number>();
  const duplicates: string[] = [];
  const raw = readFileSync(BASELINE_PATH, "utf8").split("\n");
  for (const line of raw) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const tab = t.indexOf("\t");
    const [countStr, path] =
      tab >= 0
        ? [t.slice(0, tab), t.slice(tab + 1)]
        : t.split(/\s+/, 2); // tolerate space-separated rows
    const count = Number.parseInt(countStr!, 10);
    if (!Number.isFinite(count) || !path) continue;
    const key = path.trim();
    if (map.has(key)) duplicates.push(key);
    map.set(key, count);
  }
  return { map, duplicates };
}

describe("em-dash guard (no NEW em-dashes in public-facing artifacts)", () => {
  it("no in-scope file exceeds its committed em-dash baseline", () => {
    const { map: baseline, duplicates } = parseBaseline();
    // a duplicate baseline row would let a regression through (Map overwrite)
    expect(
      duplicates,
      "Duplicate path row(s) in em-dash-baseline.txt — a later row silently " +
        "overwrites an earlier one and can mask a regression. Collapse to one " +
        "row per path:\n  " + duplicates.join("\n  "),
    ).toEqual([]);
    // sanity: baseline parsed and resolved scope is real
    expect(baseline.size).toBeGreaterThan(0);
    const scope = inScopeRelPaths();
    expect(scope.length).toBeGreaterThan(50);

    const regressions: string[] = [];
    const tightenable: string[] = [];

    // (a) regression: an in-scope file's current count EXCEEDS its baseline
    //     (0 if the file has no row). Adding a new em-dash reds.
    for (const rel of scope) {
      const current = emDashCount(rel);
      const allowed = baseline.get(rel) ?? 0;
      if (current > allowed) {
        regressions.push(
          `${rel}: ${current} em-dash(es) now, baseline allows ${allowed} ` +
            `(+${current - allowed} NEW)`,
        );
      }
    }

    // (b) TRUE RATCHET: any baselined file whose current count is BELOW its
    //     baseline row (a partial OR full reduction) must tighten the row to the
    //     new count — otherwise the slack (e.g. baseline 10, now 8) silently
    //     permits a later +2 regression. Tighten-to-N (delete the row at 0).
    for (const [rel, allowed] of baseline) {
      const current = emDashCount(rel);
      if (current < allowed) {
        tightenable.push(
          current === 0
            ? `${rel}: now 0 — DELETE its row (was ${allowed})`
            : `${rel}: now ${current} — lower its row to ${current} (was ${allowed})`,
        );
      }
    }

    expect(
      { regressions, tightenable },
      "Em-dash ratchet violated (CLAUDE.md no-em-dash rule, 2026-04-21).\n" +
        (regressions.length
          ? "NEW em-dashes added to public-facing prose — remove them (use a " +
            "comma, parenthesis, or colon). DO NOT raise the baseline to make " +
            "this pass:\n  " +
            regressions.join("\n  ") +
            "\n"
          : "") +
        (tightenable.length
          ? "These files dropped BELOW their baseline — tighten " +
            "server/test/structure/em-dash-baseline.txt to lock in the win " +
            "(run: npx tsx test/structure/gen-em-dash-baseline.ts from server/), " +
            "so the reduction cannot be silently re-spent:\n  " +
            tightenable.join("\n  ") +
            "\n"
          : ""),
    ).toEqual({ regressions: [], tightenable: [] });
  });

  it("the baseline file lists no path that is out of scope or duplicated", () => {
    const { map: baseline, duplicates } = parseBaseline();
    expect(
      duplicates,
      "Duplicate path row(s) in em-dash-baseline.txt:\n  " +
        duplicates.join("\n  "),
    ).toEqual([]);
    const scope = new Set(inScopeRelPaths());
    const outOfScope = [...baseline.keys()].filter((p) => !scope.has(p));
    expect(
      outOfScope,
      "Baseline lists path(s) not in the guard's scope (a file moved/renamed, " +
        "or the scope changed). Remove or fix these rows in em-dash-baseline.txt:\n  " +
        outOfScope.join("\n  "),
    ).toEqual([]);
  });
});
