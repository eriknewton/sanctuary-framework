/**
 * plugin/.mcp.json is the launcher the Claude plugin directory installs. The
 * directory rejects an unpinned `npx` launcher, and an unpinned one would also
 * run whatever npm serves at install time rather than the release the plugin
 * was reviewed with. Two rules, both checked here:
 *
 * 1. The launcher names the package at an exact stable version (x.y.z): no
 *    range, no dist-tag, no prerelease, so a directory install never lands on
 *    a release candidate.
 * 2. When server/package.json is itself a stable version (a release commit),
 *    the pin equals it. Between releases the package carries a prerelease
 *    version and the pin stays on the last stable one.
 *
 * Must match the package name in server/package.json and the release step in
 * .github/RELEASING.md. The publish workflow runs this suite against the
 * release tag, so a stale pin fails the release, not a later install.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const REPO_ROOT = new URL("../../../", import.meta.url);
const readJson = (rel: string) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(rel, REPO_ROOT)), "utf8"));

const EXACT_STABLE = /^\d+\.\d+\.\d+$/;

describe("Claude plugin launcher", () => {
  const pkg = readJson("server/package.json");
  const launcher = readJson("plugin/.mcp.json");
  const args: string[] = launcher.mcpServers.sanctuary.args;
  const spec = args.find((a) => a.startsWith(`${pkg.name}`));

  it("pins the package to an exact stable version", () => {
    expect(spec, "plugin/.mcp.json must launch the server package").toBeDefined();
    const version = spec!.slice(`${pkg.name}@`.length);
    expect(spec!.startsWith(`${pkg.name}@`), "the launcher must pin a version").toBe(true);
    expect(version).toMatch(EXACT_STABLE);
  });

  it("matches server/package.json on a stable release commit", () => {
    if (!EXACT_STABLE.test(pkg.version)) return;
    expect(spec).toBe(`${pkg.name}@${pkg.version}`);
  });
});
