#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join, relative } from "node:path";
// Must match castle-wall-macos/scripts/stage-cli-runtime.sh (the copy step) and
// server/src/cli/install.ts `required` (the installer's verifier); this is the
// same list the stage script gates on, re-checked here over the manifest walk.
import {
  deniedSealedCliRuntimeManifestPaths,
  enforcedSealedCliRuntimeDistEntries,
  missingSealedCliRuntimeManifestEntries,
} from "./sealed-cli-runtime-entries.mjs";

const [app, sourceSha, cliVersion] = process.argv.slice(2);
if (!app || !/^[a-f0-9]{40}$/.test(sourceSha ?? "") || !cliVersion) {
  throw new Error("usage: build-castle-wall-runtime-manifest.mjs <app> <40-hex-source-sha> <cli-version>");
}

const contents = join(app, "Contents");
const node = join(contents, "Resources", "boot-runtime", "node");
const roots = [
  join(contents, "MacOS", "sanctuary"),
  node,
  join(contents, "Resources", "cli-runtime"),
];
const files = [];
const packages = [];

function isInstalledPackageManifest(relativePath) {
  if (relativePath === "Resources/cli-runtime/package.json") return true;
  const segments = relativePath.split("/");
  if (segments.at(-1) !== "package.json") return false;
  return (
    segments.at(-3) === "node_modules" ||
    (segments.at(-4) === "node_modules" && segments.at(-3)?.startsWith("@"))
  );
}

function readStableFile(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile()) return { directory: before.isDirectory(), bytes: null };
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    if (
      before.dev !== after.dev || before.ino !== after.ino ||
      before.size !== after.size || before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs || before.size !== BigInt(bytes.length)
    ) throw new Error(`runtime file changed while hashing: ${path}`);
    return { directory: false, bytes };
  } finally {
    closeSync(fd);
  }
}

function walk(path) {
  const opened = readStableFile(path);
  if (opened.directory) {
    for (const name of readdirSync(path).sort()) walk(join(path, name));
    return;
  }
  const bytes = opened.bytes;
  if (bytes === null) throw new Error(`runtime manifest refuses non-file: ${path}`);
  const relativePath = relative(contents, path);
  files.push({
    path: relativePath,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  });
  if (isInstalledPackageManifest(relativePath)) {
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (typeof parsed.name === "string" && typeof parsed.version === "string") {
      packages.push({ path: relativePath, name: parsed.name, version: parsed.version });
    }
  }
}

for (const root of roots) walk(root);
files.sort((a, b) => a.path.localeCompare(b.path));
packages.sort((a, b) => a.path.localeCompare(b.path));
// INVARIANT: the manifest describes a runtime that can CREATE a fortress, not
// only boot one. Every entry dist/cli.js reaches by path (the forked storage
// worker, templates, reference plugins, catalog assets) must be in the walk;
// a runtime that is missing one is refused a manifest, so the signed build
// fails here rather than on the first `sanctuary protect` of an installed Mac.
const filePathList = files.map((entry) => entry.path);
const missingDistEntries = missingSealedCliRuntimeManifestEntries(filePathList);
if (missingDistEntries.length > 0) {
  throw new Error(`sealed CLI runtime is incomplete; missing dist entries: ${missingDistEntries.join(", ")}`);
}
// The whole-tree copy has no ceiling of its own; the deny set is it. Test
// material or key-shaped files under dist/ must never be codesigned into a
// release, so their presence refuses the manifest.
const deniedDistPaths = deniedSealedCliRuntimeManifestPaths(filePathList);
if (deniedDistPaths.length > 0) {
  throw new Error(
    `sealed CLI runtime carries denied files: ${deniedDistPaths.map(([path, glob]) => `${path} (${glob})`).join(", ")}`,
  );
}
const packageJsonCount = files.filter((entry) => entry.path.endsWith("/package.json")).length;
const nestedPackageCount = packages.filter(
  (entry) => entry.path.split("/node_modules/").length > 2,
).length;
const machOInventoryPath = process.env.SANCTUARY_MACH_O_INVENTORY_FILE;
if (!machOInventoryPath) throw new Error("SANCTUARY_MACH_O_INVENTORY_FILE is required");
const filePaths = new Set(files.map((entry) => entry.path));
const machO = readFileSync(machOInventoryPath, "utf8")
  .split("\n")
  .filter(Boolean)
  .sort();
if (machO.length === 0 || machO.some((path) => !filePaths.has(path))) {
  throw new Error("Mach-O inventory is empty or names bytes outside the runtime manifest");
}
const nodeVersion = execFileSync(node, ["--version"], {
  encoding: "utf8",
  env: { PATH: "/usr/bin:/bin", NODE_OPTIONS: "", NODE_PATH: "" },
}).trim();
const manifest = {
  schema: "sanctuary.castle-wall-cli-runtime.v1",
  source_sha: sourceSha,
  cli_version: cliVersion,
  node_version: nodeVersion,
  inventory: {
    file_count: files.length,
    total_bytes: files.reduce((sum, entry) => sum + entry.size, 0),
    package_count: packages.length,
    package_json_count: packageJsonCount,
    package_internal_json_count: packageJsonCount - packages.length,
    nested_package_count: nestedPackageCount,
    packages,
    mach_o_count: machO.length,
    mach_o: machO,
    // The required dist entries this runtime was verified to carry (paths
    // relative to Resources/cli-runtime/dist), so an installer or doctor can
    // check presence without re-deriving the set from the build inputs.
    dist_entries: enforcedSealedCliRuntimeDistEntries().map((entry) => ({
      path: entry.path,
      kind: entry.kind,
      ...(entry.kind === "dir" ? { sentinel: entry.sentinel } : {}),
    })),
  },
  files,
};
writeFileSync(
  join(contents, "Resources", "cli-runtime-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
  { mode: 0o444 },
);
