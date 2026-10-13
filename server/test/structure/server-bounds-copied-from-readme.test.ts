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

const README = readFileSync(fileURLToPath(new URL("../../../README.md", import.meta.url)), "utf8").toLowerCase();

/** Split on a sentence end followed by whitespace; the README is read the same way. */
function sentences(text: string): string[] {
  return text.split(/(?<=\.)\s+/).map((s) => s.trim()).filter((s) => s.length > 0);
}

describe("server bounds are copied from the README", () => {
  it("every platform and never-claimed sentence is a README substring, and every proof sentence carries the patched-host bound", () => {
    const copied = { platforms: SERVER_BOUNDS.platforms, neverClaimed: SERVER_BOUNDS.neverClaimed };
    const missing: string[] = [];
    const unbounded: string[] = [];
    for (const [key, text] of Object.entries(copied)) {
      for (const sentence of sentences(text)) {
        if (!README.includes(sentence.toLowerCase())) missing.push(`${key}: ${sentence}`);
        if (/\bproven\b/i.test(sentence) && !/on a patched host/.test(sentence)) unbounded.push(`${key}: ${sentence}`);
      }
    }
    expect(missing, "a bounds sentence is not README text; change the README first").toEqual([]);
    expect(unbounded, "a proof sentence lacks the patched-host bound").toEqual([]);
  });
});
