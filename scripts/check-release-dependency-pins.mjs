#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = new URL("..", import.meta.url);
const failures = [];

const npmManifests = [
  {
    path: "server/package.json",
    sections: ["dependencies", "devDependencies"],
    lockfile: "server/package-lock.json",
  },
  {
    path: "menubar/package.json",
    sections: ["dependencies", "devDependencies"],
    lockfile: "menubar/package-lock.json",
  },
];

const exactNpmVersion = /^(?:\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?|npm:[^@]+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$/;
const npmRangeChars = /^[~^><=*]|[|]|\s-\s|\sx\s|\sX\s|\s\*/;

function readJson(path) {
  return JSON.parse(readFileSync(join(repoRoot.pathname, path), "utf8"));
}

for (const manifestConfig of npmManifests) {
  const manifest = readJson(manifestConfig.path);
  const lockfile = readJson(manifestConfig.lockfile);
  const lockedRoot = lockfile.packages?.[""] ?? {};

  for (const section of manifestConfig.sections) {
    const deps = manifest[section] ?? {};
    const lockedDeps = lockedRoot[section] ?? {};

    for (const [name, spec] of Object.entries(deps)) {
      if (!exactNpmVersion.test(spec) || npmRangeChars.test(spec)) {
        failures.push(`${manifestConfig.path} ${section}.${name} is not exact: ${spec}`);
      }

      if (lockedDeps[name] !== spec) {
        failures.push(
          `${manifestConfig.lockfile} root ${section}.${name} (${lockedDeps[name] ?? "missing"}) does not match ${manifestConfig.path} (${spec})`,
        );
      }
    }
  }
}

const cargoToml = readFileSync(join(repoRoot.pathname, "menubar/src-tauri/Cargo.toml"), "utf8");
const releaseCriticalCargoCrates = new Set([
  "tauri-build",
  "tauri",
  "tauri-plugin-notification",
  "tauri-plugin-http",
  "serde",
  "serde_json",
  "keyring",
  "log",
  "env_logger",
]);

for (const line of cargoToml.split(/\r?\n/)) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[") || !trimmed.includes("=")) {
    continue;
  }

  const separator = trimmed.indexOf("=");
  const name = trimmed.slice(0, separator).trim();
  if (!releaseCriticalCargoCrates.has(name)) {
    continue;
  }

  const spec = trimmed.slice(separator + 1).trim();
  const stringSpec = spec.match(/^"([^"]+)"/);
  const inlineVersion = spec.match(/version\s*=\s*"([^"]+)"/);
  const version = stringSpec?.[1] ?? inlineVersion?.[1];

  if (!version?.startsWith("=")) {
    failures.push(`menubar/src-tauri/Cargo.toml ${name} is not exact: ${spec}`);
  }
}

if (failures.length > 0) {
  console.error("Release dependency pin check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Release dependency pin check passed.");
