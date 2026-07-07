/**
 * Governed File-Grant v1 -- wrong-list negative test (DoD gate 2).
 *
 * Proves `file_grant` was wired to the truly non-relaxable set (must-fix
 * #1), NOT the relaxable `state_export`-class `tier1_always_approve` list a
 * hand-authored/activated policy CAN downgrade. This test would fail if a
 * builder made the exact mistake the build spec warns against: adding
 * `file_grant` directly into `DEFAULT_POLICY.tier1_always_approve` (or a
 * shipped template's relaxable tier1 list) instead of the sibling
 * non-relaxable const spread into the two force-lists.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";

const SERVER_ROOT = fileURLToPath(new URL("../..", import.meta.url));

describe("file-grant wrong-list negative test", () => {
  it("file_grant is NOT in DEFAULT_POLICY.tier1_always_approve", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).not.toContain("file_grant");
  });

  it("file_grant_revoke and file_grant_list ARE in DEFAULT_POLICY.tier3_always_allow (safe-direction, not force-pinned)", () => {
    expect(DEFAULT_POLICY.tier3_always_allow).toContain("file_grant_revoke");
    expect(DEFAULT_POLICY.tier3_always_allow).toContain("file_grant_list");
  });

  it("file_grant is not in the shipped persistent-agent.yaml template's relaxable tier1 operations list", () => {
    const templatePath = join(
      SERVER_ROOT,
      "src",
      "principal-policy",
      "templates",
      "persistent-agent.yaml",
    );
    const raw = readFileSync(templatePath, "utf-8");
    // Extract the tiers.tier1.operations block (a simple line-scoped check;
    // the template is a small hand-authored YAML file, not machine-generated).
    const tier1Start = raw.indexOf("tier1:");
    expect(tier1Start).toBeGreaterThan(-1);
    const tier1Block = raw.slice(tier1Start, raw.indexOf("tier2:", tier1Start));
    expect(tier1Block).not.toMatch(/\bfile_grant\b/);
  });
});
