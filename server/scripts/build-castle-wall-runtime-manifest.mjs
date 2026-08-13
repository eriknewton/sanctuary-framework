#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
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

function walk(path) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) throw new Error(`runtime manifest refuses symlink: ${path}`);
  if (stat.isDirectory()) {
    for (const name of readdirSync(path).sort()) walk(join(path, name));
    return;
  }
  if (!stat.isFile()) throw new Error(`runtime manifest refuses non-file: ${path}`);
  const bytes = readFileSync(path);
  files.push({
    path: relative(contents, path),
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  });
}

for (const root of roots) walk(root);
const nodeVersion = execFileSync(node, ["--version"], {
  encoding: "utf8",
  env: { PATH: "/usr/bin:/bin", NODE_OPTIONS: "", NODE_PATH: "" },
}).trim();
const manifest = {
  schema: "sanctuary.castle-wall-cli-runtime.v1",
  source_sha: sourceSha,
  cli_version: cliVersion,
  node_version: nodeVersion,
  files,
};
writeFileSync(
  join(contents, "Resources", "cli-runtime-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
  { mode: 0o444 },
);
