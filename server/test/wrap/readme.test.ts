/**
 * README sanity check, verifies the user-facing README uses the canonical
 * vocabulary (Protect as primary user-facing verb; wrap as deprecated CLI
 * alias) and is free of retired "Cocoon" terminology.
 *
 * Vocabulary canonical ratification: 2026-05-24 (private wiki memo
 * sanctuary-vocabulary-canonical-2026-05-24). Zero "Cocoon" references in
 * active copy; "sanctuary protect" is the primary CLI verb shown to operators;
 * "sanctuary wrap" remains as a deprecated alias for backward compatibility
 * but is not the surface advertised in the README.
 */

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const README_PATH = join(__dirname, "..", "..", "..", "README.md");

describe("README", () => {
  it("advertises the one-command protect install path", async () => {
    const readme = await readFile(README_PATH, "utf-8");
    expect(readme).toContain("npx @sanctuary-framework/mcp-server protect --openclaw");
    expect(readme).toContain("What happens when you run protect");
  });

  it("documents export-passphrase", async () => {
    const readme = await readFile(README_PATH, "utf-8");
    expect(readme).toContain("sanctuary export-passphrase");
  });

  it("has zero 'cocoon' references in active copy", async () => {
    const readme = await readFile(README_PATH, "utf-8");
    const matches = readme.match(/cocoon/gi) ?? [];
    expect(matches.length).toBe(0);
  });
});
