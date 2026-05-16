/**
 * Runtime package-version helpers.
 *
 * Keep version reporting tied to installed package metadata instead of copied
 * constants in tool handlers.
 */

import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, parse } from "node:path";

const require = createRequire(import.meta.url);

interface PackageJson {
  name?: unknown;
  version?: unknown;
}

export function getSanctuaryVersion(): string {
  return packageVersion(require("../package.json"), "../package.json");
}

export function getMcpSdkVersion(): string {
  const entrypoint = require.resolve("@modelcontextprotocol/sdk/server/index.js");
  return packageVersion(readNearestPackageJson(entrypoint, "@modelcontextprotocol/sdk"), "@modelcontextprotocol/sdk");
}

export function packageVersion(pkg: unknown, source: string): string {
  if (
    pkg &&
    typeof pkg === "object" &&
    "version" in pkg &&
    typeof (pkg as PackageJson).version === "string"
  ) {
    return (pkg as PackageJson).version;
  }
  return `unknown (${source} has no version)`;
}

function readNearestPackageJson(startPath: string, expectedName: string): PackageJson {
  let dir = dirname(startPath);
  const root = parse(dir).root;

  while (dir !== root) {
    const candidate = join(dir, "package.json");
    if (existsSync(candidate)) {
      const parsed = JSON.parse(readFileSync(candidate, "utf8")) as PackageJson;
      if (parsed.name === expectedName) {
        return parsed;
      }
    }
    dir = dirname(dir);
  }

  return {};
}
