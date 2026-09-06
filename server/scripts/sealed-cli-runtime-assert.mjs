#!/usr/bin/env node

// Build-time gate for a staged sealed CLI runtime:
//   node sealed-cli-runtime-assert.mjs <staged dist dir>
// Exits non-zero naming (a) every enforced entry that is absent (a directory
// entry counts as absent when its sentinel file is missing) and (b) every file
// under the staged tree that matches SEALED_CLI_RUNTIME_DIST_DENY.
//
// Called by castle-wall-macos/scripts/stage-cli-runtime.sh after the copy and
// by .github/workflows/castle-wall-macos-release.yml on the built and the
// extracted artifact, so an incomplete or over-inclusive runtime fails the
// build instead of the first `sanctuary protect` on an installed Mac.

import { readdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import {
  enforcedSealedCliRuntimeDistEntries,
  missingSealedCliRuntimeEntries,
  sealedCliRuntimeDenyMatch,
} from "./sealed-cli-runtime-entries.mjs";

const argv = process.argv.slice(2);
if (argv.length !== 1 || argv[0].startsWith("--")) {
  throw new Error("usage: sealed-cli-runtime-assert.mjs <staged-dist-directory>");
}
const distDir = resolve(argv[0]);

function walk(dir, out) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path, out);
    else out.push(relative(distDir, path));
  }
  return out;
}

const missing = missingSealedCliRuntimeEntries(distDir);
const denied = walk(distDir, [])
  .map((path) => [path, sealedCliRuntimeDenyMatch(path)])
  .filter(([, glob]) => glob !== null);

if (missing.length > 0 || denied.length > 0) {
  if (missing.length > 0) {
    process.stderr.write(`sealed CLI runtime is incomplete under ${distDir}; missing: ${missing.join(", ")}\n`);
  }
  for (const [path, glob] of denied) {
    process.stderr.write(`sealed CLI runtime carries a denied file: dist/${path} (matches ${glob})\n`);
  }
  process.exit(1);
}
process.stdout.write(
  `sealed CLI runtime complete: ${enforcedSealedCliRuntimeDistEntries().length} required entries present, no denied files\n`,
);
