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

/**
 * Structurally extract the list items nested under `tiers: > <tierName>: >
 * operations:` in a hand-authored policy template, by indentation. This is a
 * real structural parse of the YAML list (walks the indent tree and collects
 * the `- <op>` children of the target `operations:` key), NOT a fragile string
 * slice between two header substrings.
 */
function tierOperations(templateYaml: string, tierName: string): string[] {
  const lines = templateYaml.split("\n");
  const indentOf = (line: string): number => line.length - line.trimStart().length;

  // Find the line index of `<key>:` nested directly inside a parent block that
  // starts at `fromIdx` and whose header sits at `parentIndent`. Returns -1 if
  // the parent block ends (a line dedents to <= parentIndent) before the key.
  const findChild = (key: string, fromIdx: number, parentIndent: number): number => {
    for (let i = fromIdx; i < lines.length; i++) {
      const line = lines[i]!;
      if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
      const indent = indentOf(line);
      if (indent <= parentIndent) return -1; // left the parent block
      if (line.trim() === `${key}:`) return i;
    }
    return -1;
  };

  const tiersIdx = lines.findIndex((l) => l.trim() === "tiers:");
  if (tiersIdx === -1) return [];
  const tierIdx = findChild(tierName, tiersIdx + 1, indentOf(lines[tiersIdx]!));
  if (tierIdx === -1) return [];
  const opsIdx = findChild("operations", tierIdx + 1, indentOf(lines[tierIdx]!));
  if (opsIdx === -1) return [];

  const opsIndent = indentOf(lines[opsIdx]!);
  const items: string[] = [];
  for (let i = opsIdx + 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const indent = indentOf(line);
    if (indent <= opsIndent) break; // left the operations: block
    const m = line.trim().match(/^-\s+(.+)$/);
    if (m) items.push(m[1]!.trim());
  }
  return items;
}

describe("file-grant wrong-list negative test", () => {
  it("file_grant is NOT in DEFAULT_POLICY.tier1_always_approve", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).not.toContain("file_grant");
  });

  it("file_grant_revoke and file_grant_list ARE in DEFAULT_POLICY.tier3_always_allow (safe-direction, not force-pinned)", () => {
    expect(DEFAULT_POLICY.tier3_always_allow).toContain("file_grant_revoke");
    expect(DEFAULT_POLICY.tier3_always_allow).toContain("file_grant_list");
  });

  it("file_grant is not in the shipped persistent-agent.yaml template's relaxable tier1 operations (structural parse)", () => {
    const templatePath = join(
      SERVER_ROOT,
      "src",
      "principal-policy",
      "templates",
      "persistent-agent.yaml",
    );
    const raw = readFileSync(templatePath, "utf-8");

    const tier1Ops = tierOperations(raw, "tier1");
    // Sanity: the parse actually found the block (guards against a silent
    // pass if the structure ever changes and the extractor returns []).
    expect(tier1Ops).toContain("state_export");
    // The load-bearing assertion: file_grant is NOT in the relaxable tier1 list.
    expect(tier1Ops).not.toContain("file_grant");
  });
});
