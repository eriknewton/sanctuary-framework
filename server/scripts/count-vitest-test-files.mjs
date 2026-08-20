#!/usr/bin/env node
// Reports the test files VITEST ITSELF would discover for a run, via
// `vitest list --filesOnly --json`, instead of re-implementing test file
// discovery. This is the single source of truth for CI's
// silent-test-file-drop detector (Gate 2b in
// .github/workflows/test-baseline-guard.yml and its mirror in
// .githooks/pre-commit): the gate compares this against vitest's own
// "Test Files ... (N)" run-time report, so both sides now come from vitest's
// real resolution pipeline rather than two independent models of it.
//
// FINDING THIS FIXES, ROUND 1 (2026-08-19, pre-existing on main, independent
// of any open PR): Gate 2b originally computed `expected_files` with
// `find server/test -name "*.test.ts" | wc -l`, which only scans one of
// vitest.config.ts's two `test.include` roots (`test/**/*.test.ts` and
// `../scripts/synthetic-coverage/test/**/*.test.ts`). On a real run: 992
// files on disk in server/test vs. 1006 loaded by vitest - a 14-file
// cushion baked into the comparison before any files ever went missing.
//
// FINDING THIS FIXES, ROUND 2 (2026-08-19, independent gate on the round-1
// fix, PR #1280 head 05ec7229): the round-1 fix replaced the shell `find`
// with a hand-rolled re-implementation of vitest's discovery (loading
// test.include via vite's config loader, then globbing it with tinyglobby
// directly in this script). That re-implementation only modeled
// `test.include` - it had no idea about `test.exclude`, the `dot` option,
// `test.root`/`dir`, `includeSource`, a workspace/projects config, a
// per-invocation project filter, or an include list a plugin resolves at
// runtime. Any one of those, if vitest.config.ts ever grows it, would make
// `expected_files` diverge from what vitest actually runs - in EITHER
// direction: a false failure (this script says N, vitest correctly runs
// fewer because of an exclude it didn't know about), or a fresh masking gap
// exactly like round 1's. Re-modeling vitest's resolution is a chase that
// can never fully catch up to vitest's own resolution rules. The fix is to
// stop modeling it: ask vitest for the list directly. `vitest list
// --filesOnly` calls the SAME internal method
// (`ctx.getRelevantTestSpecifications`) a real `vitest run` uses to decide
// which files to run, so whatever test.include/exclude/dot/root/projects/
// plugin-resolved config vitest.config.ts carries, this script's expected
// set is exact by construction - there is no second implementation of
// discovery left to drift.
//
// FAILURE MODE: an empty or malformed result here would make Gate 2b pass
// vacuously no matter how many test files vitest actually drops - see the
// explicit refusals below, both for a vitest exit failure and for an
// unparseable/malformed/duplicated file list.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultServerRoot = resolve(scriptDir, "..");

/**
 * Locates vitest's CLI entry point via real Node module resolution (its
 * package.json `bin` field), not a hand-picked `node_modules/.bin/vitest`
 * path - this works regardless of hoisting/monorepo layout and fails with a
 * real, legible ERR_MODULE_NOT_FOUND if vitest is not installed, rather than
 * a "file not found" on a path we guessed.
 */
function resolveVitestEntry() {
  const pkgUrl = import.meta.resolve("vitest/package.json");
  const pkg = JSON.parse(readFileSync(fileURLToPath(pkgUrl), "utf8"));
  const binRelative = typeof pkg.bin === "string" ? pkg.bin : pkg.bin?.vitest;
  if (!binRelative) {
    throw new Error(
      `vitest's package.json has no "vitest" bin entry (got: ${JSON.stringify(pkg.bin)}). ` +
        "Is the installed vitest version compatible with this script (built against vitest@4)?",
    );
  }
  return fileURLToPath(new URL(binRelative, pkgUrl));
}

/**
 * Asks vitest itself which test files it would run under `serverRoot`.
 *
 * @param {string} serverRoot absolute path to the vitest project root (the
 *   directory containing vitest.config.ts).
 * @returns {string[]} absolute, deduplicated, sorted test file paths.
 */
export function listVitestTestFiles(serverRoot = defaultServerRoot) {
  const vitestEntry = resolveVitestEntry();

  const result = spawnSync(
    process.execPath,
    [vitestEntry, "list", "--filesOnly", "--json", "--root", serverRoot],
    { cwd: serverRoot, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );

  if (result.error) {
    // FAILURE MODE: a spawn-level failure (e.g. node itself could not be
    // launched). Never swallow this into an empty file list.
    throw new Error(`Failed to spawn vitest for file discovery: ${result.error.message}`);
  }

  if (result.status !== 0) {
    // FAILURE MODE: vitest failed before it could report a file list - a
    // broken vitest.config.ts, a throwing plugin, or (flagged during review
    // of this script, though not reproduced in every environment: vitest's
    // "native" config loader path does not always need this) an EPERM
    // writing the bundled-config temp file vitest's default "bundle"
    // configLoader creates under node_modules/.vite-temp when node_modules
    // is read-only. Whatever the cause, fail closed with vitest's real
    // stderr attached instead of reporting zero expected files.
    const stderrTail = (result.stderr || "").trim().split("\n").slice(-25).join("\n");
    throw new Error(
      `vitest list --filesOnly exited ${result.status} - could not discover test files. ` +
        "This is usually a vitest.config.ts load failure: check for a read-only " +
        "node_modules (the default config loader needs write access under " +
        `node_modules/.vite-temp) or a config/plugin error. stderr:\n${stderrTail}`,
    );
  }

  let entries;
  try {
    entries = JSON.parse(result.stdout);
  } catch (err) {
    throw new Error(`Could not parse 'vitest list --filesOnly --json' output as JSON: ${err.message}`);
  }
  if (!Array.isArray(entries)) {
    throw new Error(`Expected 'vitest list --filesOnly --json' to output a JSON array, got: ${typeof entries}`);
  }

  const files = entries.map((entry, i) => {
    if (typeof entry?.file !== "string" || entry.file.length === 0) {
      throw new Error(
        `Entry ${i} in 'vitest list --filesOnly --json' output has no string "file" field: ${JSON.stringify(entry)}`,
      );
    }
    return entry.file;
  });

  const unique = new Set(files);
  if (unique.size !== files.length) {
    // FAILURE MODE: a duplicate would silently inflate expected_files, which
    // could mask a real drop of the same size elsewhere in the count.
    // Vitest should never report the same file twice; if it does, refuse to
    // trust the list rather than silently deduplicating past it.
    throw new Error(
      `'vitest list --filesOnly --json' reported ${files.length} entries but only ` +
        `${unique.size} unique file paths - refusing to trust a duplicated list.`,
    );
  }

  return [...unique].sort();
}

function main() {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes("--json");
  const rootArg = args.find((arg) => !arg.startsWith("--"));
  const serverRoot = rootArg ? resolve(rootArg) : defaultServerRoot;

  const files = listVitestTestFiles(serverRoot);

  if (jsonOutput) {
    console.log(
      JSON.stringify(
        { root: serverRoot, count: files.length, files: files.map((f) => relative(serverRoot, f)) },
        null,
        2,
      ),
    );
  } else {
    // Bare count on stdout: `expected_files=$(node scripts/count-vitest-test-files.mjs)`.
    console.log(files.length);
  }
}

// FAILURE MODE: comparing resolve()d paths here (instead of realpath()d ones)
// silently fails to detect direct invocation whenever the invocation path
// traverses a symlink Node itself resolves away when building import.meta.url
// - e.g. macOS's /tmp -> /private/tmp and /var -> /private/var. `resolve()`
// only normalizes `.`/`..`/separators; it never touches the filesystem, so it
// leaves such a symlink in place while import.meta.url has already been
// resolved through it, and the two paths compare unequal even though they
// name the same file. That mismatch made this script silently no-op (exit 0,
// no output) under `node "$FIX/..."` for any mktemp fixture on macOS - caught
// by gate2b-self-test.sh, which runs from exactly such a path.
const invokedDirectly =
  process.argv[1] &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
if (invokedDirectly) {
  try {
    main();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
