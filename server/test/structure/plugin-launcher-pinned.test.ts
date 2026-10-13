/**
 * The Claude plugin under plugin/ is what Anthropic's plugin directory
 * installs. The directory rejects an unpinned `npx` launcher, and an unpinned
 * command would run whatever npm serves that day rather than the release the
 * plugin was reviewed with. The plugin therefore carries ONE version, used in
 * every place below, and this test holds them together:
 *
 * 1. Every argument of every server entry in plugin/.mcp.json that names the
 *    package pins it at an exact stable version (x.y.z): no range, no
 *    dist-tag, no prerelease, so a directory install never lands on a release
 *    candidate. All such pins are the same version.
 * 2. Every mention of the package in the plugin's text files (the README and
 *    the skill an agent follows) carries that same pin, so the commands an
 *    agent runs match the server the launcher starts. A link to the npm page
 *    is a URL, not a command, and is exempt.
 * 3. plugin/.claude-plugin/plugin.json `version` equals the pin; an installed
 *    plugin is refreshed only when that field changes.
 * 4. When server/package.json is itself a stable version (a release commit),
 *    the pin equals it. Between releases the package carries a prerelease
 *    version and the plugin stays on the last stable one.
 *
 * Must match the package name in server/package.json and the release step in
 * .github/RELEASING.md. The publish workflow runs this suite against the
 * release tag, so a stale pin fails the release, not a later install.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const read = (rel: string) => readFileSync(join(REPO_ROOT, rel), "utf8");
const readJson = (rel: string) => JSON.parse(read(rel));

const EXACT_STABLE = /^\d+\.\d+\.\d+$/;
const NPM_PAGE_PREFIX = "npmjs.com/package/";

function textFilesUnder(rel: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(join(REPO_ROOT, rel))) {
    const child = `${rel}/${name}`;
    if (statSync(join(REPO_ROOT, child)).isDirectory()) out.push(...textFilesUnder(child));
    else if (/\.(md|txt)$/.test(name)) out.push(child);
  }
  return out;
}

describe("Claude plugin version pin", () => {
  const pkg = readJson("server/package.json");
  const name: string = pkg.name;
  const launcher = readJson("plugin/.mcp.json");
  const specs: string[] = Object.values(
    launcher.mcpServers as Record<string, { args?: string[]; command?: string }>,
  ).flatMap((server) => [server.command ?? "", ...(server.args ?? [])])
    .filter((arg) => arg.includes(name));

  it("every launcher argument naming the package pins one exact stable version", () => {
    expect(specs.length, "plugin/.mcp.json must launch the server package").toBeGreaterThan(0);
    for (const spec of specs) {
      expect(spec.startsWith(`${name}@`), `unpinned launcher argument: ${spec}`).toBe(true);
      expect(spec.slice(`${name}@`.length)).toMatch(EXACT_STABLE);
    }
    expect(new Set(specs).size, "launcher pins disagree").toBe(1);
  });

  const pin = specs[0]?.slice(`${name}@`.length) ?? "";

  it("every command in the plugin's text files uses the same pin", () => {
    const unpinned: string[] = [];
    for (const file of textFilesUnder("plugin")) {
      const text = read(file);
      let at = text.indexOf(name);
      while (at !== -1) {
        const isNpmPageLink = text.slice(Math.max(0, at - NPM_PAGE_PREFIX.length), at) === NPM_PAGE_PREFIX;
        if (!isNpmPageLink && !text.startsWith(`${name}@${pin}`, at)) {
          unpinned.push(`${file}: ${text.slice(at, at + name.length + 12)}`);
        }
        at = text.indexOf(name, at + name.length);
      }
    }
    expect(unpinned, `every mention must read ${name}@${pin}`).toEqual([]);
  });

  it("plugin.json version equals the pin", () => {
    expect(readJson("plugin/.claude-plugin/plugin.json").version).toBe(pin);
  });

  it("matches server/package.json on a stable release commit", () => {
    if (!EXACT_STABLE.test(pkg.version)) return;
    expect(pin).toBe(pkg.version);
  });
});
