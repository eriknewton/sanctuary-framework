#!/usr/bin/env node
// Reports the test files VITEST ITSELF would discover for a run, via
// `vitest list --filesOnly --json`, instead of re-implementing test file
// discovery. This is the single source of truth for CI's
// silent-test-file-drop detector (Gate 2b in
// .github/workflows/test-baseline-guard.yml and its mirror in
// .githooks/pre-commit): the gate compares this against vitest's own
// "Test Files ... (N)" run-time report.
//
// SCOPE (narrowed 2026-08-19, round 3 of independent review - read this
// before touching the equivalence logic below): this script's count is
// proven equal to a real run's "Test Files" total ONLY for a FULL run
// (no --shard) of an UNFILTERED invocation (no file/test-name/project
// filter) over a NON-OVERLAPPING project set (no file claimed by more than
// one vitest project). Today's server/vitest.config.ts and package.json
// `"test": "vitest run"` script satisfy all three: no projects config, no
// filters, `npm test` takes no extra arguments. That is a fact about
// today's config, not a property this script enforces for every possible
// config - do NOT read "asks vitest for the list directly" as "handles
// sharding/filtering/overlapping projects." It does not, and does not try
// to: this repo runs one full unsharded unfiltered suite in one job, and
// building support for shapes nobody uses is exactly the overreach this
// round of review pushed back on. Where a config shape would silently
// break the equivalence (this script or gate2b-check.sh is asked to filter/
// shard, or vitest's discovery reports the same file under more than one
// project), this script REFUSES with an explanatory message pointing back
// to this paragraph, rather than silently returning a count that looks
// valid but no longer matches what a real run would report. See
// `resolveVitestEntry`'s version gate, `main`'s argument validation, and
// `listVitestTestFiles`'s overlap check below for where each bound is
// enforced.
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
// `test.root`/`dir`, `includeSource`, a workspace/projects config, or an
// include list a plugin resolves at runtime. Any one of those, if
// vitest.config.ts ever grows it, would make `expected_files` diverge from
// what vitest actually runs - in EITHER direction: a false failure (this
// script says N, vitest correctly runs fewer because of an exclude it
// didn't know about), or a fresh masking gap exactly like round 1's. The
// fix: ask vitest for the list directly. `vitest list --filesOnly` calls
// the SAME internal method (`ctx.getRelevantTestSpecifications`) a real
// `vitest run` uses to decide which files to run, so for the SCOPE above
// (full/unsharded/unfiltered/non-overlapping), this script's expected set
// matches vitest's real run set by construction - there is no second
// implementation of test.include/exclude/dot/root resolution left to drift.
//
// FINDING THIS FIXES, ROUND 3 (2026-08-19, independent gate on the round-2
// fix, PR #1280 head 31e5ba9a - SOUND-WITH-FIXES): round 2's "identical by
// construction" claim was unqualified. The gate confirmed the equivalence
// for this repo's actual static config and full run, but named four
// configuration shapes this repo does not use where the claim would not
// hold and nothing would say so: a sharded or filtered invocation, and
// overlapping vitest projects. Round 3 does not build support for any of
// them (they are out of scope by the SCOPE paragraph above) - it makes each
// one FAIL LOUDLY with an explanatory message instead of silently producing
// a count that no longer matches a real run:
//   - `main()` now rejects any CLI argument it does not explicitly
//     recognize, rather than silently ignoring an accidental --shard/
//     --project/filter argument passed to this script's own invocation.
//   - `listVitestTestFiles` now tracks identity as (projectName, file), not
//     just file, and REFUSES with a named-bound message if the same file is
//     reported under more than one project - see the overlap check below.
//   - `resolveVitestEntry` now version-gates the installed vitest against
//     the major.minor this script's equivalence claim was last verified
//     against, because a future vitest could keep `vitest list --filesOnly
//     --json`'s shape while changing what it means, and a parse of a
//     valid-looking JSON array is not proof the semantics still hold.
//
// FAILURE MODE: an empty or malformed result here would make Gate 2b pass
// vacuously no matter how many test files vitest actually drops - see the
// explicit refusals below, both for a vitest exit failure and for an
// unparseable/malformed/duplicated file list.

import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultServerRoot = resolve(scriptDir, "..");

// Last verified against vitest 4.1.10 (2026-08-19): `vitest list --filesOnly
// --json` returns an array of objects with a "file" string and an optional
// "projectName" string, and calls the same `getRelevantTestSpecifications` a
// real `vitest run` uses to decide what to run. A minor/major bump could
// keep that JSON shape while changing what it means (a new default, a
// changed resolution order) without this script's parsing ever failing -
// see checkVitestVersion below.
const VERIFIED_VITEST_MAJOR_MINOR = "4.1";

/**
 * Locates vitest's CLI entry point via real Node module resolution (its
 * package.json `bin` field), not a hand-picked `node_modules/.bin/vitest`
 * path - this works regardless of hoisting/monorepo layout and fails with a
 * real, legible ERR_MODULE_NOT_FOUND if vitest is not installed, rather than
 * a "file not found" on a path we guessed. Also enforces the version gate:
 * see VERIFIED_VITEST_MAJOR_MINOR above.
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

  const version = typeof pkg.version === "string" ? pkg.version : "";
  const majorMinorMatch = version.match(/^(\d+\.\d+)\./);
  const majorMinor = majorMinorMatch ? majorMinorMatch[1] : null;
  if (majorMinor !== VERIFIED_VITEST_MAJOR_MINOR) {
    // FAILURE MODE: a JSON array that still looks right is not proof the
    // semantics still hold - see FINDING THIS FIXES, ROUND 3 above. Refuse
    // rather than trust an unverified vitest version's interpretation of
    // `list --filesOnly --json`.
    throw new Error(
      `This script's expected/actual equivalence claim (see its header) was verified against ` +
        `vitest ${VERIFIED_VITEST_MAJOR_MINOR}.x. The installed version is ` +
        `${version || "(unparseable: " + JSON.stringify(pkg.version) + ")"}. Re-verify ` +
        "'vitest list --filesOnly --json' still means what this script assumes (rerun " +
        "scripts/gate2b-self-test.sh, especially the real-vitest-run case) and update " +
        "VERIFIED_VITEST_MAJOR_MINOR in this file before trusting Gate 2b against the new version.",
    );
  }

  return fileURLToPath(new URL(binRelative, pkgUrl));
}

/**
 * Asks vitest itself which test files it would run under `serverRoot`.
 * Identity is the (projectName, file) pair, carried as real record fields
 * rather than a concatenated string, so an overlap (the same file under
 * more than one project) can be detected and refused (see the SCOPE note
 * in this file's header) instead of silently deduplicating or
 * double-counting.
 *
 * @param {string} serverRoot absolute path to the vitest project root (the
 *   directory containing vitest.config.ts).
 * @returns {{ projectName: string | null, file: string }[]} sorted records -
 *   `projectName` is `null` when vitest reports no project name (today's
 *   single unnamed-project config), so `.length` is exactly the file count.
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

  // Records, not encoded strings: (projectName, file) identity is carried as
  // real object fields throughout, never concatenated into one string with a
  // hand-picked separator character - that separator could collide with a
  // real project name or an unusual file path, which is exactly the kind of
  // silent-miscount bug a "looks like a count" script must not have. `null`
  // means "vitest reported no projectName" (today's default, unnamed single
  // project); a named project is its actual string.
  /** @type {{ projectName: string | null, file: string }[]} */
  const records = [];
  const projectsByFile = new Map(); // file -> Set of projectName-or-null

  entries.forEach((entry, i) => {
    if (typeof entry?.file !== "string" || entry.file.length === 0) {
      throw new Error(
        `Entry ${i} in 'vitest list --filesOnly --json' output has no string "file" field: ${JSON.stringify(entry)}`,
      );
    }
    const projectName =
      typeof entry.projectName === "string" && entry.projectName.length > 0 ? entry.projectName : null;
    records.push({ projectName, file: entry.file });
    if (!projectsByFile.has(entry.file)) {
      projectsByFile.set(entry.file, new Set());
    }
    projectsByFile.get(entry.file).add(projectName);
  });

  // Duplicate (projectName, file) pairs: a Map keyed by project, each value
  // a Map of file -> occurrence count. Two levels of real Map, not a
  // concatenated key, for the same collision-safety reason as above.
  const perProjectFileCounts = new Map();
  for (const { projectName, file } of records) {
    if (!perProjectFileCounts.has(projectName)) {
      perProjectFileCounts.set(projectName, new Map());
    }
    const perFile = perProjectFileCounts.get(projectName);
    perFile.set(file, (perFile.get(file) ?? 0) + 1);
  }
  const repeated = [];
  for (const [projectName, perFile] of perProjectFileCounts) {
    for (const [file, count] of perFile) {
      if (count > 1) {
        repeated.push({ projectName, file, count });
      }
    }
  }
  if (repeated.length > 0) {
    // FAILURE MODE: a duplicate (project, file) pair would silently inflate
    // expected_files, which could mask a real drop of the same size
    // elsewhere. A single discovery call should never report the same
    // (project, file) pair twice; if it does, refuse to trust the list
    // rather than silently deduplicating past it.
    const described = repeated
      .map((r) => `${r.projectName ?? "(default)"} / ${r.file} (x${r.count})`)
      .join(", ");
    throw new Error(
      "'vitest list --filesOnly --json' reported the same (project, file) pair more than once: " +
        `${described}. This should never happen from a single discovery call - refusing to trust ` +
        "the list.",
    );
  }

  const overlapping = [...projectsByFile.entries()].filter(([, projects]) => projects.size > 1);
  if (overlapping.length > 0) {
    // FAILURE MODE: this is the OUT-OF-SCOPE case named in this file's
    // header (round 3) - an overlapping project set, where a real run
    // legitimately runs the same file once per project (verified: it
    // reports as N separate "Test Files" entries, one per project) but this
    // script has no proof its equivalence claim still holds once files are
    // shared across projects. Refuse with the bound named, rather than
    // guessing whether to count the file once or per-project.
    const [exampleFile, exampleProjects] = overlapping[0];
    const projectList = [...exampleProjects].map((p) => p ?? "(default)").join(", ");
    throw new Error(
      `${overlapping.length} file(s) are reported under more than one vitest project ` +
        `(e.g. "${exampleFile}" under [${projectList}]). This script's expected/actual ` +
        "equivalence is proven only for a NON-OVERLAPPING project set (see the SCOPE note at " +
        "the top of this file) - refusing to guess whether an overlapping file should count " +
        "once or once per project. If this repo now legitimately uses overlapping projects, " +
        "extend this script deliberately (and its self-test) before trusting Gate 2b again.",
    );
  }

  return [...records].sort((a, b) => {
    const fileCmp = a.file.localeCompare(b.file);
    if (fileCmp !== 0) {
      return fileCmp;
    }
    return (a.projectName ?? "").localeCompare(b.projectName ?? "");
  });
}

function main() {
  const args = process.argv.slice(2);

  // FAILURE MODE (round 3): silently ignoring an unrecognized argument here
  // is exactly the "looks supported, isn't" shape this round of review
  // flagged - e.g. someone adding --shard or a filter to this script's own
  // invocation, expecting it to narrow discovery the way it would narrow a
  // real `vitest run`, when in fact this script never forwards extra args to
  // vitest at all (see the fixed arg list in listVitestTestFiles). Refuse
  // instead of quietly doing something other than what the caller asked.
  const KNOWN_FLAGS = new Set(["--json"]);
  let rootArg;
  for (const arg of args) {
    if (KNOWN_FLAGS.has(arg)) {
      continue;
    }
    if (arg.startsWith("--")) {
      throw new Error(
        `Unrecognized argument '${arg}'. This script supports only --json and an optional root ` +
          "path - it does not accept or forward a filter, --shard, or a --project selector to " +
          "vitest (see the SCOPE note at the top of this file for why those are refused rather " +
          "than silently ignored).",
      );
    }
    if (rootArg !== undefined) {
      throw new Error(
        `Unexpected extra positional argument '${arg}' (root is already '${rootArg}'). A second ` +
          "positional argument would look like a file/test-name filter, which this script does " +
          "not support (see the SCOPE note at the top of this file).",
      );
    }
    rootArg = arg;
  }

  const jsonOutput = args.includes("--json");
  const serverRoot = rootArg ? resolve(rootArg) : defaultServerRoot;

  const records = listVitestTestFiles(serverRoot);

  if (jsonOutput) {
    console.log(
      JSON.stringify(
        {
          root: serverRoot,
          count: records.length,
          files: records.map(({ projectName, file }) => {
            const relFile = relative(serverRoot, file);
            return projectName === null ? relFile : `[${projectName}] ${relFile}`;
          }),
        },
        null,
        2,
      ),
    );
  } else {
    // Bare count on stdout: `expected_files=$(node scripts/count-vitest-test-files.mjs)`.
    console.log(records.length);
  }
}

// FAILURE MODE: comparing resolve()d paths here (instead of realpath()d ones)
// silently fails to detect direct invocation whenever the invocation path
// traverses a symlink Node itself resolves away when building import.meta.url
// - e.g. macOS's /tmp -> /private/tmp and /var -> /private/var, or an
// explicit fixture symlink (see scripts/gate2b-self-test.sh's dedicated
// direct-invocation case, which proves this deterministically rather than
// relying on an ambient OS symlink). `resolve()` only normalizes
// `.`/`..`/separators; it never touches the filesystem, so it leaves such a
// symlink in place while import.meta.url has already been resolved through
// it, and the two paths compare unequal even though they name the same
// file - silently no-op'ing (exit 0, no output) instead of running main().
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
