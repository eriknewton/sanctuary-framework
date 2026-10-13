import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_ROOT = join(REPO_ROOT, "server");

function readServerJson(path: string): unknown {
  return JSON.parse(readFileSync(join(SERVER_ROOT, path), "utf8"));
}

describe("server npm shrinkwrap shipping guard", () => {
  it("ships exactly the server shrinkwrap lockfile", () => {
    expect(existsSync(join(SERVER_ROOT, "npm-shrinkwrap.json"))).toBe(true);
    expect(existsSync(join(SERVER_ROOT, "package-lock.json"))).toBe(false);
  });

  it("keeps the shrinkwrap included by package filters", () => {
    const packageJson = readServerJson("package.json") as { files?: string[] };
    expect(packageJson.files ?? []).toContain("npm-shrinkwrap.json");

    const npmignore = join(SERVER_ROOT, ".npmignore");
    if (!existsSync(npmignore)) {
      return;
    }

    const ignored = readFileSync(npmignore, "utf8")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));
    expect(ignored).not.toContain("npm-shrinkwrap.json");
    expect(ignored).not.toContain("*.json");
  });
});
