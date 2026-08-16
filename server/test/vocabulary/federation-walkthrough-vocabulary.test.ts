/**
 * Federation walkthrough vocabulary guard.
 *
 * B7 found a pre-existing Tier-1 phrasing tell in the federation hard-gate
 * walkthrough. Keep this targeted: the phrase has legitimate uses elsewhere in
 * security comments, but this operator-facing design walkthrough should use
 * plain language for the trust-boundary explanation.
 */

import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const WALKTHROUGH_PATH = join(
  __dirname,
  "..",
  "..",
  "docs",
  "federation-v0.1-hard-gate-walkthrough.md",
);

describe("federation walkthrough vocabulary", () => {
  it("does not use the retired phrasing tell from B7", async () => {
    const walkthrough = await readFile(WALKTHROUGH_PATH, "utf-8");
    expect(walkthrough).not.toMatch(/\bload-bearing\b/i);
  });
});
