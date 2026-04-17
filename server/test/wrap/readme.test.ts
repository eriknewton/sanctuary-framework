/**
 * README sanity check — verifies the user-facing README has dropped
 * "Cocoon" from its active copy.
 *
 * One historical mention is allowed inside the "Before (six steps)" block,
 * where we contrast the new wrap command against the old cocoon subcommand.
 */

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const README_PATH = join(__dirname, "..", "..", "..", "README.md");

describe("README", () => {
  it("advertises the new one-command wrap", async () => {
    const readme = await readFile(README_PATH, "utf-8");
    expect(readme).toContain("npx @sanctuary-framework/mcp-server wrap --openclaw");
    expect(readme).toContain("Wrap Any Agent in One Command");
  });

  it("documents export-passphrase", async () => {
    const readme = await readFile(README_PATH, "utf-8");
    expect(readme).toContain("sanctuary export-passphrase");
  });

  it("has at most one 'cocoon' reference (the Before-block contrast)", async () => {
    const readme = await readFile(README_PATH, "utf-8");
    const matches = readme.match(/cocoon/gi) ?? [];
    expect(matches.length).toBeLessThanOrEqual(1);
  });

  it("does not describe 'Cocoon' as a current feature (post-Before)", async () => {
    const readme = await readFile(README_PATH, "utf-8");
    const beforeMarker = "**Before (six steps):**";
    const afterMarker = "**After (one step):**";
    const beforeIdx = readme.indexOf(beforeMarker);
    const afterIdx = readme.indexOf(afterMarker);
    expect(beforeIdx).toBeGreaterThan(0);
    expect(afterIdx).toBeGreaterThan(beforeIdx);

    // Everything preceding the Before block, and everything from the After
    // marker onward, must be Cocoon-free.
    const preamble = readme.slice(0, beforeIdx);
    const postAmble = readme.slice(afterIdx);
    expect(preamble.toLowerCase()).not.toContain("cocoon");
    expect(postAmble.toLowerCase()).not.toContain("cocoon");
  });
});
