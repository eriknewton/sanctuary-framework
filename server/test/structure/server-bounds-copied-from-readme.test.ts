/**
 * The bounds paragraph the MCP server sends at connect time is product copy an
 * evaluating agent reads before it decides to install. Its platform and
 * never-claimed sentences are copies of the README "Summary for agents" block,
 * and this test is what makes "copied" structural: every sentence of those two
 * entries must be a substring of README.md, so a stronger claim cannot be typed
 * into the server without first landing in the README, where the Assurance
 * Matrix guard and the public-surface review see it. Case is ignored only
 * because the README lowercases the first word after "What it is not:".
 *
 * Must match SERVER_BOUNDS in server/src/agent-native/capabilities-catalog.ts.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { SERVER_BOUNDS } from "../../src/agent-native/capabilities-catalog.js";

// Historical blog posts are intentionally outside the current public-copy contract.
const PUBLIC_SURFACES = [
  "docs/index.html", "README.md", "docs/llms-full.txt", "server/README.md",
  "docs/llms.txt", "ROADMAP.md", "server/src/agent-native/capabilities-catalog.ts",
  "plugin/skills/sanctuary/SKILL.md", "plugin/README.md",
  "plugin/.claude-plugin/plugin.json", ".claude-plugin/marketplace.json",
  "server/package.json", "server/server.json", "docs/agent-guided-install.md",
  "SANCTUARY_ARCHITECTURE.md",
];
const RETIRED_QUALIFIER = /\bpatched\s+(?:host|mac(?:os)?)\b/i;

const README = readFileSync(fileURLToPath(new URL("../../../README.md", import.meta.url)), "utf8").toLowerCase();

/** Split on a sentence end followed by whitespace; the README is read the same way. */
function sentences(text: string): string[] {
  return text.split(/(?<=\.)\s+/).map((s) => s.trim()).filter((s) => s.length > 0);
}

describe("server bounds are copied from the README", () => {
  it("every copied sentence retains its platform bound and public surfaces omit the retired qualifier", () => {
    const copied = { platforms: SERVER_BOUNDS.platforms, neverClaimed: SERVER_BOUNDS.neverClaimed };
    const missing: string[] = [];
    const unbounded: string[] = [];
    for (const [key, text] of Object.entries(copied)) {
      for (const sentence of sentences(text)) {
        if (!README.includes(sentence.toLowerCase())) missing.push(`${key}: ${sentence}`);
        if (key === "platforms" && /\bproven\b/i.test(sentence)) {
          // A proof stays attached to its platform; Linux never generalizes beyond the drilled OS and architecture.
          const macOS = sentence === "macOS: proven.";
          const linux = sentence === "Linux enforcement is proven on Ubuntu 24.04 (x86-64) only; every other distribution or architecture remains unproven.";
          if (!macOS && !linux) unbounded.push(`${key}: ${sentence}`);
        }
      }
    }
    expect.soft(missing, "a bounds sentence is not README text; change the README first").toEqual([]);
    expect.soft(unbounded, "a proof sentence lacks its platform bound").toEqual([]);
    expect.soft(SERVER_BOUNDS.platforms).toContain("macOS: proven.");
    expect.soft(SERVER_BOUNDS.platforms).toContain("Linux enforcement is proven on Ubuntu 24.04 (x86-64) only;");
    // The short macOS status inherits the drill scope from the same README wall row.
    const wallRow = README.split("\n").find((line) => line.startsWith("| **the wall.**"));
    expect(wallRow).toContain("a signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles.");
    expect(wallRow).toContain("not an audited per-rule, per-flow trail.");
    const qualified = PUBLIC_SURFACES.filter((path) => RETIRED_QUALIFIER.test(
      readFileSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url)), "utf8"),
    ));
    expect(qualified, "a public surface reintroduced the retired qualifier").toEqual([]);
  });
});
