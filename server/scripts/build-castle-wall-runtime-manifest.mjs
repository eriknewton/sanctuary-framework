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
  if (
    relativePath === "Resources/cli-runtime/package.json" ||
    /^Resources\/cli-runtime\/node_modules\/(?:@[^/]+\/)?[^/]+\/package\.json$/.test(relativePath)
  ) {
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (typeof parsed.name === "string" && typeof parsed.version === "string") {
      packages.push({ path: relativePath, name: parsed.name, version: parsed.version });
    }
  }
}

for (const root of roots) walk(root);
files.sort((a, b) => a.path.localeCompare(b.path));
packages.sort((a, b) => a.path.localeCompare(b.path));
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
    packages,
    mach_o_count: machO.length,
    mach_o: machO,
  },
  files,
};
writeFileSync(
  join(contents, "Resources", "cli-runtime-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
  { mode: 0o444 },
);
