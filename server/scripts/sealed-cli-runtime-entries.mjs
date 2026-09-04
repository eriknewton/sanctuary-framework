#!/usr/bin/env node

// Single source of truth for what the sealed Castle Wall CLI runtime
// (<App>.app/Contents/Resources/cli-runtime/dist) MUST contain.
//
// The signed launcher execs `dist/cli.js`, and that bundle reaches its siblings
// by path at run time: `fork()` of `dist/directory-capability-worker.js` on
// every fortress creation, `dist/templates/` for agent templates,
// `dist/reference-plugin/` for the first-party plugins, and the catalog schema
// assets under `dist/intelligence/`. A runtime that ships `cli.js` alone boots an
// existing fortress and fails to create a new one, so the shipped set is a
// security-relevant install property, not a packaging nicety.
//
// The copy step (castle-wall-macos/scripts/stage-cli-runtime.sh) ships the WHOLE
// built `dist/` tree minus build-only artifacts; this list is the presence gate
// that runs after the copy, at manifest time, and in the release workflow, and
// it is the set the structure test reconciles against the build inputs.
//
// Cross-file pins (a change to any one side must land on all of them):
//   - must match the `entry` keys in server/tsup.config.ts (one `<key>.js` each);
//   - must match the dist outputs of server/scripts/copy-templates.js and
//     server/scripts/copy-catalog-v3-assets.mjs (and every future copy-*.mjs);
//   - must match the `required` set in server/src/cli/install.ts
//     (verifyCastleWallRuntimeManifest) for the entries listed there;
//   - reconciled whole-set by server/test/structure/sealed-cli-runtime-contents.test.ts.

import { existsSync, realpathSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Paths relative to `dist/`. A `kind: "file"` entry must be a regular file; a
 * `kind: "dir"` entry must be a directory holding at least one file.
 */
export const SEALED_CLI_RUNTIME_DIST_ENTRIES = Object.freeze([
  // tsup entries (server/tsup.config.ts `entry`): the ESM output of each.
  Object.freeze({ path: "cli.js", kind: "file", source: "tsup" }),
  Object.freeze({ path: "directory-capability-worker.js", kind: "file", source: "tsup" }),
  Object.freeze({ path: "index.js", kind: "file", source: "tsup" }),
  Object.freeze({ path: "intelligence/index.js", kind: "file", source: "tsup" }),
  Object.freeze({ path: "verify-transparency.js", kind: "file", source: "tsup" }),
  // Non-TS assets placed under dist/ by the post-build copy scripts.
  Object.freeze({ path: "templates", kind: "dir", source: "copy-templates.js" }),
  Object.freeze({ path: "reference-plugin", kind: "dir", source: "copy-templates.js" }),
  Object.freeze({ path: "intelligence/catalog-v3", kind: "dir", source: "copy-catalog-v3-assets.mjs" }),
]);

/**
 * The runtime-manifest paths (relative to <App>.app/Contents) of the file
 * entries above. Directory entries are covered by the manifest walk itself.
 */
export const SEALED_CLI_RUNTIME_MANIFEST_FILE_PATHS = Object.freeze(
  SEALED_CLI_RUNTIME_DIST_ENTRIES
    .filter((entry) => entry.kind === "file")
    .map((entry) => `Resources/cli-runtime/dist/${entry.path}`),
);

/**
 * Report which required entries a staged `dist/` directory is missing.
 * Returns an empty array when the layout is complete.
 */
export function missingSealedCliRuntimeEntries(distDir) {
  const missing = [];
  for (const entry of SEALED_CLI_RUNTIME_DIST_ENTRIES) {
    const target = join(distDir, entry.path);
    if (!existsSync(target)) {
      missing.push(entry.path);
      continue;
    }
    const stat = statSync(target);
    if (entry.kind === "file" && !stat.isFile()) missing.push(entry.path);
    if (entry.kind === "dir" && !stat.isDirectory()) missing.push(entry.path);
  }
  return missing;
}

/**
 * Report which required file entries are absent from a runtime-manifest `files`
 * array (paths relative to <App>.app/Contents) and which required directory
 * entries have no file under them. Empty when the manifest covers the set.
 */
export function missingSealedCliRuntimeManifestEntries(manifestFilePaths) {
  const paths = new Set(manifestFilePaths);
  const missing = [];
  for (const entry of SEALED_CLI_RUNTIME_DIST_ENTRIES) {
    const manifestPath = `Resources/cli-runtime/dist/${entry.path}`;
    if (entry.kind === "file") {
      if (!paths.has(manifestPath)) missing.push(entry.path);
    } else {
      const prefix = `${manifestPath}/`;
      if (![...paths].some((path) => path.startsWith(prefix))) missing.push(entry.path);
    }
  }
  return missing;
}

// CLI mode: `node sealed-cli-runtime-entries.mjs --assert <staged dist dir>`
// exits non-zero naming every missing entry. The stage script and the release
// workflow call this so an incomplete runtime fails the build instead of
// failing the first `sanctuary protect` on an installed Mac.
//
// The CLI branch runs only when this file IS the entry script; importers (the
// runtime-manifest builder, the structure test) must not see their own argv
// interpreted here.
function isEntryScript() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

const argv = isEntryScript() ? process.argv.slice(2) : [];
if (argv[0] === "--assert") {
  const distDir = argv[1];
  if (!distDir || argv.length !== 2) {
    throw new Error("usage: sealed-cli-runtime-entries.mjs --assert <staged-dist-directory>");
  }
  const missing = missingSealedCliRuntimeEntries(resolve(distDir));
  if (missing.length > 0) {
    process.stderr.write(
      `sealed CLI runtime is incomplete under ${resolve(distDir)}; missing: ${missing.join(", ")}\n`,
    );
    process.exit(1);
  }
  process.stdout.write(
    `sealed CLI runtime complete: ${SEALED_CLI_RUNTIME_DIST_ENTRIES.length} required entries present\n`,
  );
} else if (argv.length > 0) {
  throw new Error(`unknown argument: ${argv.join(" ")}`);
}
