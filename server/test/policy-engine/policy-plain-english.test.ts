/**
 * Tunability UX: plain-English policy renderer suite.
 *
 * Proves the pure `renderPolicyPlainEnglish` formatter turns a live
 * Principal Policy into operator-readable sentences (not raw YAML), keeps
 * the four sections, and degrades gracefully on unknown operations. This
 * is the read-only view behind the operator-bearer-gated
 * GET /api/policy/current route (agent-opaque per AGENTS.md hard rule 7;
 * the renderer itself is a pure formatter with no I/O and no policy
 * source of its own).
 */

import { describe, it, expect } from "vitest";

import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import { renderPolicyPlainEnglish } from "../../src/policy-engine/policy-plain-english.js";

function clone(): PrincipalPolicy {
  return JSON.parse(JSON.stringify(DEFAULT_POLICY)) as PrincipalPolicy;
}

describe("renderPolicyPlainEnglish", () => {
  it("renders Tier-1 always-approve operations as plain-English approval sentences", () => {
    const view = renderPolicyPlainEnglish(clone());
    const approval = view.lines.filter((l) => l.section === "approval");
    expect(approval.length).toBeGreaterThan(0);
    // state_export is Tier-1 in DEFAULT_POLICY; it must read as a sentence,
    // not the raw token.
    const exportLine = approval.find((l) => l.text.includes("export your saved state"));
    expect(exportLine).toBeDefined();
    expect(exportLine!.text).toContain("routes to you for approval");
    // No line is raw YAML / a bare identifier.
    for (const l of view.lines) {
      expect(l.text).not.toMatch(/tier1_always_approve|tier3_always_allow|:\s*\[/);
    }
  });

  it("renders every section (approval, auto_allow, anomaly, channel)", () => {
    const view = renderPolicyPlainEnglish(clone());
    const sections = new Set(view.lines.map((l) => l.section));
    expect(sections.has("approval")).toBe(true);
    expect(sections.has("auto_allow")).toBe(true);
    expect(sections.has("anomaly")).toBe(true);
    expect(sections.has("channel")).toBe(true);
  });

  it("reports the policy version and reflects the approval channel + timeout", () => {
    const policy = clone();
    const view = renderPolicyPlainEnglish(policy);
    expect(view.policy_version).toBe(policy.version);
    const channel = view.lines.find((l) => l.section === "channel");
    expect(channel).toBeDefined();
    expect(channel!.text).toContain(String(policy.approval_channel.timeout_seconds));
    expect(channel!.text).toContain("denied");
  });

  it("renders an auto-allow operation as a 'may ... without asking' sentence", () => {
    const policy = clone();
    policy.tier3_always_allow = ["read_the_weather"];
    const view = renderPolicyPlainEnglish(policy);
    const line = view.lines.find(
      (l) => l.section === "auto_allow" && l.text.includes("read the weather"),
    );
    expect(line).toBeDefined();
    expect(line!.text).toContain("without asking you");
  });

  it("degrades gracefully: an unknown operation is humanized, never a thrown error", () => {
    const policy = clone();
    policy.tier1_always_approve = ["some_brand_new_op"];
    const view = renderPolicyPlainEnglish(policy);
    const line = view.lines.find(
      (l) => l.section === "approval" && l.text.includes("some brand new op"),
    );
    expect(line).toBeDefined();
  });

  it("handles an empty Tier-1 / Tier-3 without emitting a raw empty list", () => {
    const policy = clone();
    policy.tier1_always_approve = [];
    policy.tier3_always_allow = [];
    const view = renderPolicyPlainEnglish(policy);
    const approval = view.lines.find((l) => l.section === "approval");
    const auto = view.lines.find((l) => l.section === "auto_allow");
    expect(approval!.text).toContain("No operations");
    expect(auto!.text).toContain("No operations");
  });
});
