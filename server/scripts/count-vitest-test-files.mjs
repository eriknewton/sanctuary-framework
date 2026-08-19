#!/usr/bin/env node
// Computes the expected vitest test-file count from the SAME `test.include`
// globs vitest.config.ts hands to vitest at runtime, walked with the same
// glob engine vitest itself uses internally (tinyglobby is a direct vitest
// dependency, not a substitute we picked). This is the single source of
// truth for CI's silent-test-file-drop detector (Gate 2b in
// .github/workflows/test-baseline-guard.yml): the gate no longer restates
// the include roots by hand in shell, so a future include-root change in
// vitest.config.ts cannot silently widen the drop-detection blind spot the
// way it already did once.
//
// MUST MATCH: `test.include` in server/vitest.config.ts (cross-file pin).
// This script reads that array via vite's own config loader rather than
// copying it, so the normal case needs no matching edit here at all; if you
// ever DO find yourself editing this file to keep up with vitest.config.ts,
// that itself is a signal the derivation broke and should be restored.
//
// FINDING THIS FIXES (2026-08-19, pre-existing on main, independent of any
// open PR): Gate 2b computed `expected_files` with
// `find server/test -name "*.test.ts" | wc -l`, which only scans
// server/test. vitest.config.ts's `include` is BOTH `test/**/*.test.ts` AND
// `../scripts/synthetic-coverage/test/**/*.test.ts` — a second root
// `expected_files` never scanned. `actual_total` (parsed from vitest's own
// "Test Files ... (N)" summary) counts files from BOTH roots, so on a real
// run: 992 files on disk in server/test vs. 1006 loaded by vitest, a
// 14-file cushion baked into the diff before any files ever go missing. Up
// to 14 server/test files could be silently dropped (deleted, or silently
// fail to load — the exact commit-4ac95830 failure class this whole gate
// exists to catch) with the gate still reporting green, because the
// synthetic-coverage root's file count was masking the drop.
//
// FAILURE MODE: this script computing 0 (a missing/misconfigured include)
// would make Gate 2b pass vacuously no matter how many test files vitest
// actually drops — see the explicit refusal below.

import { loadConfigFromFile } from "vite";
import { globSync } from "tinyglobby";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultConfigPath = resolve(scriptDir, "..", "vitest.config.ts");

/**
 * Resolves the set of test files vitest.config.ts's `test.include` globs
 * match on disk, using the same glob library vitest uses to discover them.
 *
 * @param {string} configPath absolute path to a vitest config file.
 * @returns {Promise<{ root: string, include: string[], files: string[] }>}
 */
export async function countVitestTestFiles(configPath = defaultConfigPath) {
  const absoluteConfigPath = resolve(configPath);
  const root = dirname(absoluteConfigPath);

  const loaded = await loadConfigFromFile(
    { command: "serve", mode: "test" },
    absoluteConfigPath,
    root,
  );
  if (!loaded) {
    throw new Error(`Unable to load vitest config at ${absoluteConfigPath}`);
  }

  const include = loaded.config?.test?.include;
  if (!Array.isArray(include) || include.length === 0) {
    // See the FAILURE MODE note at the top of this file: an empty/missing
    // include here must be a hard error, never a silent expected_files=0.
    throw new Error(
      `test.include in ${absoluteConfigPath} is missing or empty ` +
        `(got: ${JSON.stringify(include)}). Refusing to compute an expected ` +
        "file count of 0 — the silent-drop gate would pass vacuously.",
    );
  }

  const files = new Set();
  for (const pattern of include) {
    const matches = globSync(pattern, {
      cwd: root,
      ignore: ["**/node_modules/**"],
      onlyFiles: true,
    });
    for (const match of matches) {
      files.add(resolve(root, match));
    }
  }

  return { root, include, files: [...files].sort() };
}

async function main() {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes("--json");
  const configArg = args.find((arg) => !arg.startsWith("--"));
  const configPath = configArg ? resolve(configArg) : defaultConfigPath;

  const result = await countVitestTestFiles(configPath);

  if (jsonOutput) {
    console.log(
      JSON.stringify(
        {
          root: result.root,
          include: result.include,
          count: result.files.length,
          files: result.files.map((file) => relative(result.root, file)),
        },
        null,
        2,
      ),
    );
  } else {
    // Bare count on stdout: `expected_files=$(node scripts/count-vitest-test-files.mjs)`.
    console.log(result.files.length);
  }
}

// FAILURE MODE: comparing resolve()d paths here (instead of realpath()d ones)
// silently fails to detect direct invocation whenever the invocation path
// traverses a symlink Node itself resolves away when building import.meta.url
// — e.g. macOS's /tmp -> /private/tmp and /var -> /private/var. `resolve()`
// only normalizes `.`/`..`/separators; it never touches the filesystem, so it
// leaves such a symlink in place while import.meta.url has already been
// resolved through it, and the two paths compare unequal even though they
// name the same file. That mismatch made this script silently no-op (exit 0,
// no output) under `node "$FIX/..."` for any mktemp fixture on macOS — caught
// by gate2b-self-test.sh, which runs from exactly such a path.
const invokedDirectly =
  process.argv[1] &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
