/**
 * server/README.md is the page npm shows for @sanctuary-framework/mcp-server,
 * and its first-screen paragraph is the harness claim an agent reads before
 * installing. It must say exactly what the root README says, so a bound added
 * to one (for example the Agent wrapping "partial" clause) cannot be missing
 * from the other.
 *
 * Must match the link rewrite used for the npm copy: a root-README anchor
 * link "(#x)" becomes
 * "(https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#x)".
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const REPO_ROOT = new URL("../../../", import.meta.url);
const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, REPO_ROOT)), "utf8");

const FIRST_SCREEN_PREFIX = "Sanctuary is the wall under the agent";
const README_ANCHOR_BASE = "https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#";

function firstScreen(markdown: string, file: string): string {
  const lines = markdown.split("\n").filter((l) => l.startsWith(FIRST_SCREEN_PREFIX));
  expect(lines, `${file} must carry exactly one first-screen paragraph`).toHaveLength(1);
  return lines[0];
}

describe("npm README first screen", () => {
  it("is the root README first-screen paragraph with anchor links made absolute", () => {
    const root = firstScreen(read("README.md"), "README.md");
    const npm = firstScreen(read("server/README.md"), "server/README.md");
    expect(npm.split(README_ANCHOR_BASE).join("#")).toBe(root);
  });
});
