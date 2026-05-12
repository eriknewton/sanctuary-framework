/**
 * WP-V1.3-6 Xi-3 policy conflict detector suite.
 *
 * Coverage: direct overrides, partial overlaps, contradictions,
 * severity classification, multi-fortress local isolation, and the
 * castle-walking invariant that detection is pure local comparison.
 */

import { describe, expect, it } from "vitest";

import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type {
  CompiledPolicy,
  CompiledPolicyRule,
} from "../../src/policy-engine/english-policy-compiler.js";
import {
  detectConflicts,
  principalPolicyToRules,
  type PrincipalPolicyRule,
} from "../../src/policy-engine/conflict-detector.js";

const OBSERVED_AT = "2026-05-09T12:00:00.000Z";

function buildCompiled(
  rule: CompiledPolicyRule,
  opts?: { draftId?: string; fortressId?: string },
): CompiledPolicy {
  return {
    draft_id: opts?.draftId ?? `draft-${rule.kind}-${rule.operation ?? "x"}`,
    english_text: "fixture",
    compiled_rule: rule,
    explanation_paragraph: "fixture explanation",
    compile_confidence: "high",
    compile_warnings: [],
    substrate_used: "deterministic",
    compiled_at: OBSERVED_AT,
    operator_id: "operator",
    fortress_id: opts?.fortressId ?? "fortress_a",
  };
}

function rule(overrides: Partial<PrincipalPolicyRule>): PrincipalPolicyRule {
  return {
    rule_id: "custom:state_export",
    capability: "state_export",
    effect: "deny",
    source: "tier1_always_approve",
    ...overrides,
  };
}

describe("Xi-3 - direct_override detection", () => {
  it("detects an exact default tier1 override with low severity", () => {
    const candidate = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    const conflicts = detectConflicts(
      candidate,
      principalPolicyToRules(DEFAULT_POLICY),
    );
    const direct = conflicts.find((c) => c.conflict_type === "direct_override");
    expect(direct).toBeDefined();
    expect(direct!.severity).toBe("low");
    expect(direct!.affected_capability).toBe("state_export");
  });

  it("detects an exact custom tier3 override with medium severity", () => {
    const candidate = buildCompiled({
      kind: "tier3_add_operation",
      operation: "custom_read",
    });
    const conflicts = detectConflicts(candidate, [
      rule({
        rule_id: "tier3:custom_read",
        capability: "custom_read",
        effect: "allow",
        source: "tier3_always_allow",
        is_default: false,
      }),
    ]);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]!.conflict_type).toBe("direct_override");
    expect(conflicts[0]!.severity).toBe("medium");
  });

  it("detects exact agent and time-window tuple overrides", () => {
    const candidate = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
      bound_to_agent_id: "agent-a",
      active_window: { start_hour: 22, end_hour: 24 },
    });
    const conflicts = detectConflicts(candidate, [
      rule({
        agent_id: "agent-a",
        active_window: { start_hour: 22, end_hour: 24 },
      }),
    ]);
    expect(conflicts.some((c) => c.conflict_type === "direct_override")).toBe(
      true,
    );
  });
});

describe("Xi-3 - partial_overlap detection", () => {
  it("detects candidate agent subset against an active global rule", () => {
    const candidate = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
      bound_to_agent_id: "agent-a",
    });
    const conflicts = detectConflicts(candidate, [rule({})]);
    expect(conflicts[0]!.conflict_type).toBe("partial_overlap");
    expect(conflicts[0]!.severity).toBe("medium");
  });

  it("detects candidate global superset against an active agent rule", () => {
    const candidate = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    const conflicts = detectConflicts(candidate, [rule({ agent_id: "agent-a" })]);
    expect(conflicts[0]!.conflict_type).toBe("partial_overlap");
  });

  it("detects intersecting condition windows", () => {
    const candidate = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
      active_window: { start_hour: 20, end_hour: 23 },
    });
    const conflicts = detectConflicts(candidate, [
      rule({ active_window: { start_hour: 22, end_hour: 24 } }),
    ]);
    expect(conflicts[0]!.conflict_type).toBe("partial_overlap");
  });
});

describe("Xi-3 - contradiction detection", () => {
  it("detects allow candidate against deny existing rule", () => {
    const candidate = buildCompiled({
      kind: "tier3_add_operation",
      operation: "state_export",
    });
    const conflicts = detectConflicts(
      candidate,
      principalPolicyToRules(DEFAULT_POLICY),
    );
    const contradiction = conflicts.find(
      (c) => c.conflict_type === "contradiction",
    );
    expect(contradiction).toBeDefined();
    expect(contradiction!.severity).toBe("high");
  });

  it("detects deny candidate against allow existing rule", () => {
    const candidate = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_read",
    });
    const conflicts = detectConflicts(
      candidate,
      principalPolicyToRules(DEFAULT_POLICY),
    );
    expect(conflicts.some((c) => c.conflict_type === "contradiction")).toBe(
      true,
    );
  });

  it("treats removing tier1 approval as allow and conflicts with deny", () => {
    const candidate = buildCompiled({
      kind: "tier1_remove_operation",
      operation: "state_export",
    });
    const conflicts = detectConflicts(
      candidate,
      principalPolicyToRules(DEFAULT_POLICY),
    );
    expect(conflicts.find((c) => c.conflict_type === "contradiction")!.severity)
      .toBe("high");
  });
});

describe("Xi-3 - severity, isolation, and castle-walking", () => {
  it("classifies tier2 value changes as medium partial overlaps", () => {
    const candidate = buildCompiled({
      kind: "tier2_set_field",
      tier2_update: { field: "frequency_spike_multiplier", value: 9 },
    });
    const conflicts = detectConflicts(
      candidate,
      principalPolicyToRules(DEFAULT_POLICY),
    );
    expect(conflicts[0]!.conflict_type).toBe("direct_override");
    expect(conflicts[0]!.severity).toBe("low");
  });

  it("keeps multi-fortress isolation by only comparing supplied local rules", () => {
    const candidate = buildCompiled(
      { kind: "tier1_add_operation", operation: "state_export" },
      { fortressId: "fortress_b" },
    );
    expect(detectConflicts(candidate, [])).toEqual([]);
  });

  it("is pure local logic with stable conflict ids", () => {
    const candidate = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    const first = detectConflicts(candidate, [rule({ is_default: false })]);
    const second = detectConflicts(candidate, [rule({ is_default: false })]);
    expect(first.map((c) => c.conflict_id)).toEqual(
      second.map((c) => c.conflict_id),
    );
  });
});
