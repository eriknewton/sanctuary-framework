/**
 * README sanity check — verifies the user-facing README has dropped
 * "Cocoon" from its active copy.
 *
 * One historical mention is allowed inside the "Before" block,
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
    expect(readme).toContain("Wrap any harness in one command");
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
});
