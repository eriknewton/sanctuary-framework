/**
 * Castle Wall egress-decision discriminated-union tests.
 *
 * Exhaustiveness checks against EgressDecision and BlockReason. Ensures the
 * subsequent PRs that ship the evaluator can rely on the union closure.
 */

import { describe, it, expect } from "vitest";
import {
  decisionIsTerminal,
  type BlockReason,
  type EgressDecision,
  type LearnedDecision,
} from "../../../src/castle-wall/decision/types.js";

function describeDecision(d: EgressDecision): string {
  switch (d.kind) {
    case "allow":
      return `allow:${d.rule_id}`;
    case "block":
      return `block:${d.reason}`;
    case "prompt":
      return `prompt:${d.request_id}`;
    default: {
      const exhaustive: never = d;
      return exhaustive;
    }
  }
}

describe("castle-wall/decision/types : EgressDecision", () => {
  it("decisionIsTerminal returns true for allow + block, false for prompt", () => {
    expect(decisionIsTerminal({ kind: "allow", rule_id: "r" })).toBe(true);
    expect(decisionIsTerminal({ kind: "block", reason: "no_matching_rule" })).toBe(true);
    expect(decisionIsTerminal({ kind: "prompt", request_id: "rid" })).toBe(false);
  });

  it("describeDecision exhaustively covers every variant", () => {
    expect(describeDecision({ kind: "allow", rule_id: "r1" })).toBe("allow:r1");
    expect(describeDecision({ kind: "block", reason: "explicit_deny_rule" })).toBe("block:explicit_deny_rule");
    expect(describeDecision({ kind: "prompt", request_id: "abc" })).toBe("prompt:abc");
  });

  it("every BlockReason value is recognized", () => {
    const reasons: BlockReason[] = [
      "no_matching_rule",
      "explicit_deny_rule",
      "operator_denied_now",
      "operator_denied_historically",
      "policy_validation_failed",
      "filter_in_no_wall_mode_but_explicit_deny",
      "prompt_flood_blocked",
      "queue_saturated",
    ];
    for (const reason of reasons) {
      const d: EgressDecision = { kind: "block", reason };
      expect(decisionIsTerminal(d)).toBe(true);
    }
  });
});

describe("castle-wall/decision/types : LearnedDecision shape", () => {
  it("supports per_template_domain granularity without agent_id", () => {
    const ld: LearnedDecision = {
      granularity: "per_template_domain",
      template: "claude-code",
      domain_or_etld1: "anthropic.com",
      decision: "allow",
      learned_at: "2026-05-03T12:00:00.000Z",
      last_applied_at: "2026-05-03T12:00:00.000Z",
    };
    expect(ld.template).toBe("claude-code");
  });

  it("supports per_instance_domain granularity with agent_id", () => {
    const ld: LearnedDecision = {
      granularity: "per_instance_domain",
      template: "claude-code",
      agent_id: "agent-001",
      domain_or_etld1: "openai.com",
      decision: "deny",
      learned_at: "2026-05-03T12:00:00.000Z",
      last_applied_at: "2026-05-03T12:00:00.000Z",
    };
    expect(ld.agent_id).toBe("agent-001");
  });
});
