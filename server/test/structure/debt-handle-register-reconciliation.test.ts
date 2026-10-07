/**
 * DEBT-handle shape + uniqueness guard (AGENTS.md rule 9, the mechanical half
 * named as feasible-and-unbuilt: "rule 9's `DEBT`-comment-to-register
 * reconciliation").
 *
 * THE PROBLEM THIS CLOSES: a `DEBT` source comment is not tracked risk until
 * it is reconciled into the private `Open_Defects_Register`. Reconciliation
 * needs a stable, unique token per debt so a coordinator-side script can map
 * source to register rows. Before this guard, most `DEBT` markers carried no
 * identifier at all, and the identifier `DEBT-1` was reused as a purely
 * file-local name across unrelated files, so grep-based reconciliation was
 * defeated: the same three characters could not tell you which debt you were
 * looking at.
 *
 * WHAT COUNTS AS A MARKER: any whole-word occurrence of `DEBT` in a `.ts`
 * file under `server/src` or `server/test`, or a `.rs` file under
 * `castle-wall-daemon/src` or `castle-wall-daemon/tests` (excluding
 * `__fixtures__` directories). These four are the ONLY roots walked — a
 * `DEBT` mention in a `.md` file (this repo's `README.md`s, docs, or
 * `AGENTS.md` itself) is deliberately out of scope and is never scanned; a
 * prose reference in Markdown is not a source-level debt marker and mixing
 * the two would make this guard responsible for content it does not own.
 * The ONE additional exclusion is this test file's own path: its docstring
 * necessarily uses the bare word `DEBT` many times to describe the pattern
 * itself, which is prose ABOUT the marker, not a marker.
 *
 * This is deliberately the same literal token the private register's own
 * reconciliation script keys on (`scripts/reconcile-debt-handles.sh`) — a
 * bare `DEBT`, `DEBT-1`, or anything else that is not the exact
 * `DEBT(<HANDLE>)` shape fails this guard. There is no separate notion of
 * "declaration" vs "backreference" marker: every appearance of the word is
 * required to carry its handle inline, so a reader (human or the
 * reconciliation script) never has to chase a bare mention back to the
 * nearest labeled one.
 *
 * THE SHAPE: `DEBT(<HANDLE>)` where `<HANDLE>` matches `^[A-Z][A-Z0-9-]{2,40}$`
 * — an uppercase, hyphen-delimited slug, never a bare small number like the
 * retired `DEBT-1`. Two different debts must never share a handle, and this
 * guard enforces that as EXACT global uniqueness: every `DEBT(<HANDLE>)` in
 * the scanned tree is required to be the only occurrence of that handle. A
 * second mention of the same underlying debt elsewhere in the tree cites the
 * handle in prose (e.g. "tracked as FOO-BAR-BAZ") without repeating the bare
 * `DEBT` token, which keeps this guard's uniqueness check simple and total
 * rather than requiring it to judge whether two mentions describe the same
 * debt or two different ones.
 *
 * SCOPE DISCIPLINE (do not weaken): this guard checks TOKEN SHAPE AND
 * UNIQUENESS ONLY. It never reads, imports, or references
 * `Open_Defects_Register` or any other file in the private coordinator repo
 * — that cross-repo boundary is exactly why this half is public-CI-checkable
 * at all.
 *
 * Resolving a handle against the register is a separate, coordinator-side
 * reconciliation step, run outside this repository's CI, never this test's.
 *
 * FAIL-BEFORE PROOF (recorded by hand, not re-derived here): against main at
 * `d059897f`, the same whole-word `DEBT` scan over `server/src`,
 * `server/test`, `castle-wall-daemon/src`, and `castle-wall-daemon/tests`
 * found 49 occurrences (42 under the `src` roots, 7 under `server/test` —
 * `castle-wall-daemon/tests` carried none), ZERO of which matched the
 * `DEBT(<HANDLE>)` shape — every one was either a bare `DEBT:`, a
 * `DEBT-1`-style numeric pseudo-id (reused across `server/src/config.ts`,
 * `server/src/core/config-baseline.ts`, `server/src/core/anti-rollback.ts`,
 * and their two matching test files for the SAME debt, which is exactly the
 * collision this guard exists to prevent), or a mid-sentence prose mention.
 * This test fails that state and passes only once every occurrence is a
 * uniquely-handled `DEBT(<HANDLE>)` token.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(import.meta.url);
const SERVER_DIR = join(HERE, "..", "..", "..");
const REPO_ROOT = join(SERVER_DIR, "..");

// These four roots are the WHOLE scope, and the AGENTS.md rule-9 sentence
// names them exactly this way — keep the two in sync. A `.md` file is never
// scanned at any root: this guard is a source-level marker check, not a docs
// linter, and README/AGENTS prose that discusses `DEBT` in the abstract is
// not itself a marker needing a handle.
const SCAN_ROOTS: ReadonlyArray<{ readonly dir: string; readonly exts: readonly string[] }> = [
  { dir: join(SERVER_DIR, "src"), exts: [".ts"] },
  { dir: join(SERVER_DIR, "test"), exts: [".ts"] },
  { dir: join(REPO_ROOT, "castle-wall-daemon", "src"), exts: [".rs"] },
  { dir: join(REPO_ROOT, "castle-wall-daemon", "tests"), exts: [".rs"] },
];

// This file's own path, relative to REPO_ROOT, filled in once files are
// resolved below. Excluded from the scan because its docstring above uses
// the bare word `DEBT` many times to describe the pattern itself -- prose
// ABOUT the marker, not a marker. This is the ONLY file-level exclusion;
// every other file under the four roots above is in scope.
const SELF_REL_PATH = relative(REPO_ROOT, HERE);

// Directory name fragments never scanned: test fixtures and generated output
// carry no live DEBT markers of interest, and including them would make this
// guard responsible for tree content it does not own. "test" itself is not
// excluded -- server/test is a scan root -- only nested fixture/build dirs.
const EXCLUDED_DIR_NAMES = new Set(["__fixtures__", "node_modules", "dist", "target"]);

interface ScannedFile {
  readonly absPath: string;
  readonly relPath: string;
}

function walk(dir: string, exts: readonly string[], out: ScannedFile[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    // A configured root that does not exist on this checkout scans as empty
    // rather than failing the guard; castle-wall-daemon/src is a sibling repo
    // area that may not always be present in every worktree shape.
    return;
  }
  for (const entry of entries) {
    if (EXCLUDED_DIR_NAMES.has(entry)) continue;
    const abs = join(dir, entry);
    const st = statSync(abs);
    if (st.isDirectory()) {
      walk(abs, exts, out);
    } else if (exts.some((ext) => entry.endsWith(ext))) {
      const relPath = relative(REPO_ROOT, abs);
      if (relPath === SELF_REL_PATH) continue;
      out.push({ absPath: abs, relPath });
    }
  }
}

function scanFiles(): ScannedFile[] {
  const out: ScannedFile[] = [];
  for (const { dir, exts } of SCAN_ROOTS) {
    walk(dir, exts, out);
  }
  return out;
}

// The marker token itself: a whole-word `DEBT`, never matching inside
// `DEBTOR`/`DEBTS` (the trailing `\b` already prevents that). Conformance is
// judged by what immediately follows: `(<HANDLE>)` in the exact shape below,
// or anything else (nothing, `:`, `-1`, a space) is non-conforming.
const DEBT_WORD = /\bDEBT\b/g;
const HANDLE_SHAPE = /^[A-Z][A-Z0-9-]{2,40}$/;
// Matches a conforming marker starting at a DEBT_WORD match position.
const CONFORMING_AT_POINT = /^DEBT\(([A-Z0-9-]+)\)/;

interface MarkerHit {
  readonly relPath: string;
  readonly line: number;
  readonly excerpt: string;
  readonly conforming: boolean;
  readonly handle?: string;
}

function findMarkers(file: ScannedFile): MarkerHit[] {
  const source = readFileSync(file.absPath, "utf8");
  const lines = source.split("\n");
  const hits: MarkerHit[] = [];
  lines.forEach((lineText, idx) => {
    DEBT_WORD.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = DEBT_WORD.exec(lineText)) !== null) {
      const tail = lineText.slice(match.index);
      const conformingMatch = CONFORMING_AT_POINT.exec(tail);
      if (conformingMatch) {
        const handle = conformingMatch[1];
        hits.push({
          relPath: file.relPath,
          line: idx + 1,
          excerpt: lineText.trim(),
          conforming: HANDLE_SHAPE.test(handle),
          handle,
        });
      } else {
        hits.push({
          relPath: file.relPath,
          line: idx + 1,
          excerpt: lineText.trim(),
          conforming: false,
        });
      }
    }
  });
  return hits;
}

describe("E9: DEBT marker handles are shaped and unique (rule 9 mechanical half)", () => {
  const files = scanFiles();
  const allHits = files.flatMap(findMarkers);

  it("scanned at least one DEBT marker, so this guard is exercising real content", () => {
    expect(allHits.length).toBeGreaterThan(0);
  });

  it("every DEBT marker has the exact DEBT(<HANDLE>) shape", () => {
    const nonConforming = allHits.filter((hit) => !hit.conforming);
    if (nonConforming.length > 0) {
      const detail = nonConforming
        .map((hit) => `  ${hit.relPath}:${hit.line}: ${hit.excerpt}`)
        .join("\n");
      throw new Error(
        `${nonConforming.length} DEBT marker(s) do not match DEBT(<HANDLE>) ` +
          `where <HANDLE> matches ^[A-Z][A-Z0-9-]{2,40}$:\n${detail}\n\n` +
          `Fix: wrap the bare marker as DEBT(<MODULE-SLUG>) with a unique, ` +
          `descriptive handle, changing nothing else on the line. See this ` +
          `file's header comment for the convention.`,
      );
    }
  });

  it("every DEBT(<HANDLE>) handle is unique across the tree", () => {
    const conforming = allHits.filter((hit): hit is MarkerHit & { handle: string } =>
      hit.conforming && hit.handle !== undefined,
    );
    const seen = new Map<string, MarkerHit>();
    const duplicates: string[] = [];
    for (const hit of conforming) {
      const prior = seen.get(hit.handle);
      if (prior) {
        duplicates.push(
          `  ${hit.handle}: ${prior.relPath}:${prior.line} and ${hit.relPath}:${hit.line}`,
        );
      } else {
        seen.set(hit.handle, hit);
      }
    }
    if (duplicates.length > 0) {
      throw new Error(
        `DEBT handle(s) reused across distinct marker sites (this is exactly ` +
          `the DEBT-1 collision the guard exists to prevent):\n${duplicates.join("\n")}\n\n` +
          `Fix: give each distinct debt its own handle. A second mention of the ` +
          `SAME debt should cite the handle in prose without repeating the bare ` +
          `DEBT(...) token.`,
      );
    }
  });

  it("scans only within this repository (no cross-repo register read)", () => {
    // Rule 9's public/private split requires this half to stay a pure
    // token-shape check with no cross-repo read. This does not prove the
    // absence of a register import (that guarantee lives in review, per this
    // file's header comment); it does pin that every scanned path resolves
    // inside REPO_ROOT, so a future edit widening SCAN_ROOTS cannot silently
    // reach outside this checkout.
    for (const file of files) {
      expect(file.absPath.startsWith(REPO_ROOT)).toBe(true);
    }
  });
});
