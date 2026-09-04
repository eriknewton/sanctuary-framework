// Single source of truth for what the sealed Castle Wall CLI runtime
// (<App>.app/Contents/Resources/cli-runtime/dist) MUST and MUST NOT contain.
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
// built `dist/` tree minus build-only artifacts. This module is the contract
// that tree is checked against, in three places: the stage script (through
// sealed-cli-runtime-assert.mjs), the runtime-manifest builder, and the
// installer's manifest verifier (server/src/cli/install.ts imports it).
//
// This file is a side-effect-free library: it is bundled into dist/cli.js by
// tsup through install.ts, so it must never read process.argv or exit. The CLI
// lives in sealed-cli-runtime-assert.mjs.
//
// Cross-file pins (a change to any one side must land on all of them):
//   - `kind: "file"` entries must match the `entry` keys in server/tsup.config.ts;
//   - `kind: "dir"` entries must match the dist outputs of the post-build
//     server/scripts/copy-*.{js,mjs} scripts, each named in `source`;
//   - the rsync excludes in castle-wall-macos/scripts/stage-cli-runtime.sh must
//     each correspond to a glob in SEALED_CLI_RUNTIME_DIST_DENY;
//   - reconciled whole-set by server/test/structure/sealed-cli-runtime-contents.test.ts.

import { existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Paths relative to `dist/`. A `kind: "file"` entry must be a regular file. A
 * `kind: "dir"` entry must be a directory that contains its `sentinel` file
 * (directory presence alone is not content presence: an empty `templates/`
 * would otherwise pass). `landsWith` marks an entry whose producer script is
 * merging in a named PR; see isPendingSealedCliRuntimeEntry.
 */
export const SEALED_CLI_RUNTIME_DIST_ENTRIES = Object.freeze([
  // tsup entries (server/tsup.config.ts `entry`): the ESM output of each.
  Object.freeze({ path: "cli.js", kind: "file", source: "tsup" }),
  Object.freeze({ path: "directory-capability-worker.js", kind: "file", source: "tsup" }),
  Object.freeze({ path: "index.js", kind: "file", source: "tsup" }),
  Object.freeze({ path: "intelligence/index.js", kind: "file", source: "tsup" }),
  Object.freeze({ path: "verify-transparency.js", kind: "file", source: "tsup" }),
  // Non-TS assets placed under dist/ by the post-build copy scripts. Each
  // sentinel is a file the runtime actually reads from that directory.
  Object.freeze({
    path: "templates",
    kind: "dir",
    source: "copy-templates.js",
    // TEMPLATE_NAMES[0] in src/templates/registry.ts; template.json is the
    // metadata file loadTemplateBundle reads first.
    sentinel: "research-assistant/template.json",
  }),
  Object.freeze({
    path: "reference-plugin",
    kind: "dir",
    source: "copy-templates.js",
    // governance.yaml is the marker bundledPluginDir requires to accept a bundle.
    sentinel: "blocklist/governance.yaml",
  }),
  Object.freeze({
    path: "intelligence/catalog-v3",
    kind: "dir",
    source: "copy-catalog-v3-assets.mjs",
    // The digest manifest every schema in the directory is checked against.
    sentinel: "schemas/schema-digests.json",
  }),
  // Lands with PR #1370 (packaged signed model manifest, resolved relative to
  // the module dir by src/intelligence/packaged-model-manifest.ts). Until that
  // PR's copy script exists beside this file the entry is PENDING: the build
  // gates skip it, the installer does not require it, and the parity test
  // excludes it. Remove `landsWith` once both PRs are on main; the parity test
  // fails while the marker outlives the script.
  Object.freeze({
    path: "intelligence/model-manifest",
    kind: "dir",
    source: "copy-model-manifest-v2-asset.mjs",
    sentinel: "model-manifest.v2.json",
    landsWith: "#1370",
  }),
]);

/**
 * Globs (relative to `dist/`, `**` spans directories, `*` stays within one
 * segment, a leading `/` anchors at the dist root) that must match NOTHING in
 * the staged runtime. The whole-tree copy has no maximum inventory of its own,
 * so this is the ceiling: build-only artifacts the stage script already drops,
 * test material that must never be codesigned into a release, and anything
 * shaped like key or seed material.
 */
export const SEALED_CLI_RUNTIME_DIST_DENY = Object.freeze([
  // Build-only artifacts (the stage script's rsync excludes mirror these).
  "**/*.map",
  "**/*.d.ts",
  "**/*.d.cts",
  "**/*.d.mts",
  "**/*.cjs",
  "/boot-runtime/**",
  // Test material.
  "**/*.test.*",
  "**/*.spec.*",
  "**/fixtures/**",
  "**/__fixtures__/**",
  "**/__tests__/**",
  "**/__snapshots__/**",
  // Key, credential, and seed material shapes.
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.pfx",
  "**/*.jks",
  "**/*.keystore",
  "**/id_rsa*",
  "**/id_ecdsa*",
  "**/id_ed25519*",
  "**/*private-key*",
  "**/*private_key*",
  // Anchored to FILE shapes, not bare substrings: a legitimate code chunk such
  // as the SDW secret classifier (`secret-classifier*.js`) or a `seed-data.js`
  // helper must not red the gate, while `client-secret.json`, `operator-seed.txt`,
  // `seed.b64url`, or `wallet.seed` still do.
  "**/*secret*.pem",
  "**/*secret*.key",
  "**/*secret*.json",
  "**/*.secret",
  "**/*.seed",
  "**/*-seed.*",
  "**/*_seed.*",
  "**/seed.*",
  "**/.env",
  "**/.env.*",
]);
// Matching is case-insensitive: `operator.PEM` is the same shape as `.pem`.
const DENY_REGEXP_FLAGS = "i";

function globToRegExp(glob) {
  const anchored = glob.startsWith("/");
  let source = "";
  const body = anchored ? glob.slice(1) : glob;
  for (let index = 0; index < body.length; index++) {
    const char = body[index];
    if (char === "*" && body[index + 1] === "*") {
      const followedBySlash = body[index + 2] === "/";
      const atEnd = index + 2 === body.length;
      if (index === 0 && followedBySlash) {
        source += "(?:.*/)?";
        index += 2;
      } else if (atEnd && body[index - 1] === "/") {
        source = source.replace(/\/$/, "");
        source += "(?:/.*)?";
        index += 1;
      } else {
        source += ".*";
        index += 1;
      }
    } else if (char === "*") {
      source += "[^/]*";
    } else if (".+^${}()|[]\\?".includes(char)) {
      source += `\\${char}`;
    } else {
      source += char;
    }
  }
  return new RegExp(`^${source}$`, DENY_REGEXP_FLAGS);
}

const DENY_MATCHERS = SEALED_CLI_RUNTIME_DIST_DENY.map((glob) => ({ glob, regex: globToRegExp(glob) }));

/** The deny glob a dist-relative path matches, or null when it is allowed. */
export function sealedCliRuntimeDenyMatch(distRelativePath) {
  const normalized = distRelativePath.replace(/^\.?\//, "");
  for (const { glob, regex } of DENY_MATCHERS) {
    if (regex.test(normalized)) return glob;
  }
  return null;
}

/**
 * A `landsWith` entry is pending only while its producer script is absent from
 * server/scripts (the fact of the source tree at build time). Once the script
 * exists the entry is enforced like every other one, so the marker can never
 * mask a real omission after the producing PR merges. Build-time callers only:
 * inside the bundled CLI import.meta.url is dist/cli.js, so the installer uses
 * installerRequiredSealedCliRuntimeEntries instead.
 */
export function isPendingSealedCliRuntimeEntry(entry) {
  if (!entry.landsWith) return false;
  return !existsSync(join(dirname(fileURLToPath(import.meta.url)), entry.source));
}

/** The entries the build gates enforce right now (pending ones excluded). */
export function enforcedSealedCliRuntimeDistEntries() {
  return SEALED_CLI_RUNTIME_DIST_ENTRIES.filter((entry) => !isPendingSealedCliRuntimeEntry(entry));
}

/**
 * The entries the INSTALLER requires of a signed runtime: every entry without a
 * `landsWith` marker. An entry becomes part of the installer contract only when
 * its marker is removed, which happens after its producing PR is on main.
 */
export function installerRequiredSealedCliRuntimeEntries() {
  return SEALED_CLI_RUNTIME_DIST_ENTRIES.filter((entry) => !entry.landsWith);
}

/**
 * The runtime-manifest path (relative to <App>.app/Contents) that proves an
 * entry is present: the file itself, or the directory's sentinel file.
 */
export function sealedCliRuntimeManifestPath(entry) {
  const base = `Resources/cli-runtime/dist/${entry.path}`;
  return entry.kind === "file" ? base : `${base}/${entry.sentinel}`;
}

/**
 * Report which enforced entries a staged `dist/` directory is missing (file
 * absent, or directory absent or lacking its sentinel). Empty when complete.
 */
export function missingSealedCliRuntimeEntries(distDir) {
  const missing = [];
  for (const entry of enforcedSealedCliRuntimeDistEntries()) {
    const target = join(distDir, entry.path);
    if (!existsSync(target)) {
      missing.push(entry.path);
      continue;
    }
    const stat = statSync(target);
    if (entry.kind === "file") {
      if (!stat.isFile()) missing.push(entry.path);
    } else if (!stat.isDirectory() || !existsSync(join(target, entry.sentinel))
      || !statSync(join(target, entry.sentinel)).isFile()) {
      missing.push(`${entry.path}/${entry.sentinel}`);
    }
  }
  return missing;
}

/**
 * Report which enforced entries a runtime-manifest `files` array (paths relative
 * to <App>.app/Contents) does not prove present. Empty when covered.
 */
export function missingSealedCliRuntimeManifestEntries(manifestFilePaths) {
  const paths = new Set(manifestFilePaths);
  return enforcedSealedCliRuntimeDistEntries()
    .filter((entry) => !paths.has(sealedCliRuntimeManifestPath(entry)))
    .map((entry) => (entry.kind === "file" ? entry.path : `${entry.path}/${entry.sentinel}`));
}

/**
 * Report every runtime-manifest path under Resources/cli-runtime/dist that the
 * deny set forbids, as `[path, glob]` pairs. Empty when the runtime is clean.
 */
export function deniedSealedCliRuntimeManifestPaths(manifestFilePaths) {
  const prefix = "Resources/cli-runtime/dist/";
  const denied = [];
  for (const path of manifestFilePaths) {
    if (!path.startsWith(prefix)) continue;
    const glob = sealedCliRuntimeDenyMatch(path.slice(prefix.length));
    if (glob !== null) denied.push([path, glob]);
  }
  return denied;
}
