/**
 * Default-policy YAML drift guard.
 *
 * Security finding (policy-surface sweep, 2026-06-13): `generateDefaultPolicyYaml()`
 * was hand-maintained and had drifted from the canonical in-memory
 * `DEFAULT_POLICY`. Eight Tier-1 operations were present in
 * `DEFAULT_POLICY.tier1_always_approve` but ABSENT from the generated YAML:
 *
 *   decommission_certificate, federation_node_join, sanctuary_forget,
 *   sanctuary_compound_execute, sanctuary_audit_search_widen,
 *   sdw_export, sdw_import, sdw_export_delete
 *
 * On a freshly generated policy those ops still resolved to Tier 1 — but only
 * via the unclassified→Tier-1 safe default in the gate, i.e. correct-by-accident.
 * A maintainer editing the YAML (or relaxing that safe default) could silently
 * drop one of these high-risk ops to a lower tier. The fix renders the YAML's op
 * lists and scalar values directly from the canonical constants; this test fails
 * if that round-trip ever diverges again, in EITHER direction.
 *
 * The test parses the RAW YAML lists as authored (it does NOT route through
 * `parsePolicy`/`validatePolicy`, which would force-add and merge ops and thus
 * mask an omission). It compares as sets, so list ORDER is intentionally not
 * asserted.
 */

import { describe, it, expect } from "vitest";
import {
  generateDefaultPolicyYaml,
  parsePolicy,
  DEFAULT_POLICY,
} from "../../src/principal-policy/loader.js";

/**
 * Pull the raw, AS-AUTHORED list under a top-level `<name>:` key out of the
 * generated YAML — every `  - <op>` line until the next non-indented, non-blank,
 * non-comment line. Deliberately bypasses the policy parser so an omitted entry
 * shows up as a real diff rather than being silently re-added by the merge logic.
 */
function rawListBlock(yaml: string, name: string): string[] {
  const lines = yaml.split("\n");
  const out: string[] = [];
  let inBlock = false;
  for (const line of lines) {
    if (line.trimStart().startsWith("#")) continue; // skip comment lines
    if (!inBlock) {
      if (line.startsWith(`${name}:`)) inBlock = true;
      continue;
    }
    const trimmed = line.trim();
    if (trimmed.startsWith("- ")) {
      out.push(trimmed.slice(2).trim().split(/\s+/)[0]!);
    } else if (trimmed === "") {
      continue; // blank lines inside the block are fine
    } else {
      break; // hit the next key — block done
    }
  }
  return out;
}

describe("default policy YAML — drift guard", () => {
  const yaml = generateDefaultPolicyYaml();

  it("tier1_always_approve in the generated YAML matches DEFAULT_POLICY exactly (set equality)", () => {
    const yamlTier1 = new Set(rawListBlock(yaml, "tier1_always_approve"));
    const canonicalTier1 = new Set(DEFAULT_POLICY.tier1_always_approve);

    const missingFromYaml = [...canonicalTier1].filter((op) => !yamlTier1.has(op));
    const extraInYaml = [...yamlTier1].filter((op) => !canonicalTier1.has(op));

    expect(
      missingFromYaml,
      `Tier-1 ops in DEFAULT_POLICY but absent from generated YAML: ${JSON.stringify(missingFromYaml)}`,
    ).toEqual([]);
    expect(
      extraInYaml,
      `Tier-1 ops in generated YAML but absent from DEFAULT_POLICY: ${JSON.stringify(extraInYaml)}`,
    ).toEqual([]);
    expect(yamlTier1.size).toBe(canonicalTier1.size);
  });

  it("tier3_always_allow in the generated YAML matches DEFAULT_POLICY exactly (set equality)", () => {
    const yamlTier3 = new Set(rawListBlock(yaml, "tier3_always_allow"));
    const canonicalTier3 = new Set(DEFAULT_POLICY.tier3_always_allow);

    const missingFromYaml = [...canonicalTier3].filter((op) => !yamlTier3.has(op));
    const extraInYaml = [...yamlTier3].filter((op) => !canonicalTier3.has(op));

    expect(
      missingFromYaml,
      `Tier-3 ops in DEFAULT_POLICY but absent from generated YAML: ${JSON.stringify(missingFromYaml)}`,
    ).toEqual([]);
    expect(
      extraInYaml,
      `Tier-3 ops in generated YAML but absent from DEFAULT_POLICY: ${JSON.stringify(extraInYaml)}`,
    ).toEqual([]);
    expect(yamlTier3.size).toBe(canonicalTier3.size);
  });

  it("tier1 and tier3 in the generated YAML are disjoint (no op is both gated and auto-allowed)", () => {
    // Codex SHOULD-FIX (policy-surface sweep): an op appearing in BOTH lists is a
    // canonical-drift smell. The gate resolves Tier 1 first, so it would not relax
    // enforcement today — but the overlap is incoherent and should fail loudly so
    // a future maintainer notices before it can matter.
    const yamlTier1 = new Set(rawListBlock(yaml, "tier1_always_approve"));
    const yamlTier3 = rawListBlock(yaml, "tier3_always_allow");
    const overlap = yamlTier3.filter((op) => yamlTier1.has(op));
    expect(overlap, `ops present in BOTH tier1 and tier3: ${JSON.stringify(overlap)}`).toEqual([]);
  });

  it("the previously-omitted Tier-1 ops are now present in the generated YAML", () => {
    // Pin the exact regression set so a future re-omission of any one of these
    // fails loudly with a named op, not just a count mismatch.
    const previouslyOmitted = [
      "decommission_certificate",
      "federation_node_join",
      "sanctuary_forget",
      "sanctuary_compound_execute",
      "sanctuary_audit_search_widen",
      "sdw_export",
      "sdw_import",
      "sdw_export_delete",
    ];
    const yamlTier1 = new Set(rawListBlock(yaml, "tier1_always_approve"));
    for (const op of previouslyOmitted) {
      expect(yamlTier1.has(op), `expected ${op} in generated YAML tier1`).toBe(true);
    }
  });

  it("the parsed generated YAML reproduces the canonical tier1/tier3 sets", () => {
    // End-to-end: generate → parse → validate must yield the canonical tiers.
    // (parsePolicy force-adds FORCED_TIER1 / merges FORCED_TIER3, but since the
    // YAML now lists every canonical op, the result is exactly the canonical set.)
    const parsed = parsePolicy(yaml);
    expect(new Set(parsed.tier1_always_approve)).toEqual(
      new Set(DEFAULT_POLICY.tier1_always_approve),
    );
    expect(new Set(parsed.tier3_always_allow)).toEqual(
      new Set(DEFAULT_POLICY.tier3_always_allow),
    );
  });

  it("tier2 / approval_channel / approval_redirect scalars round-trip to the canonical defaults", () => {
    const parsed = parsePolicy(yaml);
    expect(parsed.version).toBe(DEFAULT_POLICY.version);
    expect(parsed.tier2_anomaly).toEqual(DEFAULT_POLICY.tier2_anomaly);
    expect(parsed.approval_channel.type).toBe(DEFAULT_POLICY.approval_channel.type);
    expect(parsed.approval_channel.timeout_seconds).toBe(
      DEFAULT_POLICY.approval_channel.timeout_seconds,
    );
    expect(parsed.approval_redirect).toEqual(DEFAULT_POLICY.approval_redirect);
  });
});
