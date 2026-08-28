/**
 * IC-30: unify fortress flag parsing on the strict parser.
 *
 * `server/src/cli/argv.ts` exports two divergent ways to read a flag's
 * value: `flagValue`/`flagValues` (permissive: an empty `--fortress=`, a
 * duplicate `--fortress a --fortress b`, or a dropped value that swallows
 * the NEXT flag as its own value all pass silently) and `consumeFlagValue`
 * (strict: all three refuse). Before this fix, roughly half of the
 * fortress-scoped CLI verbs used each parser for `--fortress`, so which
 * fortress an operator's command touched could depend on which file
 * happened to implement that verb. See
 * `Review/Sanctuary/IC30_Parser_Unification_Spawn_Prompt_2026-08-28.md`.
 *
 * This is the tripwire that keeps the class closed: a FULL-SET scan of the
 * `server/src/cli` tree (every `.ts` source file, not a sampled list), not
 * an assertion pinned to today's known files. A file added later that
 * parses `--fortress` with `flagValue`/`flagValues` fails this test the
 * moment it lands, before it ships.
 *
 * The scan is a source-text regex, not a parse of the built module graph,
 * because the point is to catch the SHAPE of the call before the code ever
 * runs: `flagValue(<argv-expr>, "--fortress")` or `flagValues(<argv-expr>,
 * "--fortress")` is exactly the pattern this fix removed everywhere in the
 * tree, and `consumeFlagValue(<argv-expr>, "--fortress")` is unaffected
 * (different function name, same call shape).
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const CLI_DIR = join(__dirname, "..", "..", "src", "cli");

/**
 * Files that mention `--fortress` in source but are NOT "a verb-scoped
 * --fortress parse" in the sense this fix targets: each does a
 * categorically different job that neither `flagValue` nor
 * `consumeFlagValue` is a drop-in replacement for. Every entry names the
 * file's own doc comment as the source of truth, so a reviewer does not
 * have to take this list's word for it.
 */
const EXEMPT_RELATIVE_PATHS: ReadonlySet<string> = new Set([
  // Defines flagValue/consumeFlagValue/flagValues themselves.
  "argv.ts",
  // Scans only the LEADING pre-subcommand flag region and stops at the
  // first non-flag token (the subcommand word); consumeFlagValue scans the
  // WHOLE argv and cannot express that boundary. See the module doc
  // comment (drill finding F-1.3.2-N-001) for why the scope is deliberate.
  "top-level-fortress.ts",
  // Deliberately REFUSES a post-subcommand --fortress rather than parsing
  // it (assertNoFortressFlag): two earlier attempts to repair the
  // operator's argv each traded the silent-drop defect for a new one. See
  // the module doc comment and test/cli/secrets-fortress-flag.test.ts.
  "secrets.ts",
  // Constructs an argv ARRAY to hand to a subprocess/agent invocation
  // (`["--fortress", input.fortress, ...]`); it never parses one.
  "install.ts",
]);

function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...listTsFiles(full));
    } else if (entry.endsWith(".ts") && !entry.endsWith(".test.ts")) {
      out.push(full);
    }
  }
  return out;
}

// Matches flagValue(<anything-without-a-comma>, "--fortress") or the
// repeatable flagValues(...) sibling, tolerant of whitespace/newlines
// between tokens. Deliberately does NOT match consumeFlagValue (different
// identifier) or a flag name that merely starts with "--fortress" (e.g.
// "--fortress-url", "--fortress-path") because the closing quote must
// follow "--fortress" immediately.
const PERMISSIVE_FORTRESS_PARSE =
  /\bflagValues?\(\s*[^,]+,\s*"--fortress"\s*\)/;

// A literal reference to the flag this fix is about, used to select which
// files are "fortress-scoped" candidates for the scan in the first place.
const MENTIONS_FORTRESS_FLAG = /"--fortress"/;

describe("IC-30: fortress-flag parsing is unified on consumeFlagValue", () => {
  const allFiles = listTsFiles(CLI_DIR);

  // Sanity check on the scan itself: if this drops to zero, the glob logic
  // broke, and the "no violations found" result below would be a false
  // pass rather than a real one.
  it("scans a non-trivial number of CLI source files", () => {
    expect(allFiles.length).toBeGreaterThan(30);
  });

  it("every exempt path actually exists in the tree (no stale exemption)", () => {
    for (const rel of EXEMPT_RELATIVE_PATHS) {
      const full = join(CLI_DIR, rel);
      expect(allFiles, `exempt path ${rel} not found under server/src/cli`).toContain(
        full,
      );
    }
  });

  const candidates = allFiles.filter((full) => {
    const rel = relative(CLI_DIR, full).split(sep).join("/");
    if (EXEMPT_RELATIVE_PATHS.has(rel)) return false;
    const text = readFileSync(full, "utf8");
    return MENTIONS_FORTRESS_FLAG.test(text);
  });

  // Full-set assertion: every non-exempt file that mentions the
  // `--fortress` flag is graded individually below, so a regression in one
  // file cannot be masked by the others passing (the failure names the
  // exact file), and adding a new fortress-scoped file makes this suite
  // grow rather than silently staying at today's count.
  it("found at least one fortress-scoped candidate file to grade", () => {
    expect(candidates.length).toBeGreaterThan(20);
  });

  for (const full of candidates) {
    const rel = relative(CLI_DIR, full).split(sep).join("/");
    it(`${rel} does not parse --fortress through the permissive flagValue/flagValues`, () => {
      const text = readFileSync(full, "utf8");
      expect(PERMISSIVE_FORTRESS_PARSE.test(text)).toBe(false);
    });
  }
});
