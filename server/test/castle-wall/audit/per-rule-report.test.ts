import { describe, it, expect } from "vitest";
import type { AuditEntry } from "../../../src/l2-operational/audit-log.js";
import {
  DEFAULT_DENY_BUCKET,
  attributeFlows,
  filterFlowsByRule,
  groupFlowsByRule,
} from "../../../src/castle-wall/audit/per-rule-report.js";

/**
 * Build a stored Castle Wall flow `AuditEntry`. `ruleKey` selects which detail
 * key carries the rule id, mirroring the two real producers: `rule_id` (TS
 * macOS/unsigned path) and `rule_id_matched` (Rust producer-signed body).
 */
function flowEntry(opts: {
  timestamp: string;
  operation: "egress_allowed" | "egress_blocked" | "operator_decision";
  ruleId?: string | null;
  ruleKey?: "rule_id" | "rule_id_matched";
  decision?: string;
  host?: string;
}): AuditEntry {
  const details: Record<string, unknown> = {};
  if (opts.ruleId !== undefined && opts.ruleId !== null) {
    details[opts.ruleKey ?? "rule_id"] = opts.ruleId;
  }
  if (opts.decision !== undefined) details.decision = opts.decision;
  if (opts.host !== undefined) details.destination = { host: opts.host, ip: "1.2.3.4", port: 443, protocol: "tcp" };
  return {
    timestamp: opts.timestamp,
    layer: "l1",
    operation: opts.operation,
    identity_id: "agent-x",
    result: opts.operation === "egress_blocked" ? "failure" : "success",
    details,
  };
}

describe("castle-wall per-rule-per-flow audit read-out", () => {
  describe("attributeFlows", () => {
    it("attributes each flow to its deciding rule and decision", () => {
      const flows = attributeFlows([
        flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_allowed", ruleId: "allow-anthropic", decision: "allow" }),
        flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_blocked", ruleId: "deny-evil", decision: "drop" }),
      ]);
      expect(flows).toHaveLength(2);
      expect(flows[0]).toMatchObject({ ruleId: "allow-anthropic", decision: "allow" });
      expect(flows[1]).toMatchObject({ ruleId: "deny-evil", decision: "deny" });
    });

    it("reads the rule id from the Rust producer-signed key (rule_id_matched)", () => {
      const flows = attributeFlows([
        flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_blocked", ruleId: "r-deny", ruleKey: "rule_id_matched" }),
      ]);
      expect(flows[0]?.ruleId).toBe("r-deny");
    });

    it("records a null rule id for a default-deny flow (no matching rule)", () => {
      const flows = attributeFlows([
        flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_blocked" }),
      ]);
      expect(flows).toHaveLength(1);
      expect(flows[0]?.ruleId).toBeNull();
      expect(flows[0]?.decision).toBe("deny");
    });

    it("derives the decision from operation when no explicit decision detail is present", () => {
      const flows = attributeFlows([
        flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_allowed", ruleId: "r1" }),
        flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_blocked", ruleId: "r2" }),
      ]);
      expect(flows.map((f) => f.decision)).toEqual(["allow", "deny"]);
    });

    it("classifies an operator_decision (pending prompt) as prompt", () => {
      const flows = attributeFlows([
        flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "operator_decision", ruleId: "needs-approval" }),
      ]);
      expect(flows[0]?.decision).toBe("prompt");
    });

    it("honors a terminal DecisionValue over the operation tag", () => {
      // An operator_decision that resolved to a deny carries deny_once.
      const flows = attributeFlows([
        flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "operator_decision", ruleId: "r", decision: "deny_once" }),
      ]);
      expect(flows[0]?.decision).toBe("deny");
    });

    it("drops non-flow lifecycle entries", () => {
      const flows = attributeFlows([
        { timestamp: "2026-06-16T00:00:01Z", layer: "l1", operation: "filter_started", identity_id: "sys", result: "success", details: {} },
        { timestamp: "2026-06-16T00:00:02Z", layer: "l1", operation: "policy_loaded", identity_id: "sys", result: "success", details: {} },
        flowEntry({ timestamp: "2026-06-16T00:00:03Z", operation: "egress_allowed", ruleId: "r1" }),
      ]);
      expect(flows).toHaveLength(1);
      expect(flows[0]?.operation).toBe("egress_allowed");
    });

    it("NEVER treats a redacted rule id as a real rule (no laundering of agent-redacted entries)", () => {
      // If a caller misuses the aggregator on agent-facing-REDACTED entries, the
      // sentinel "[redacted]" must collapse to the default-deny (null) bucket,
      // never resurface as a rule id. This is the structural backstop to
      // property #11 (no-policy-inference).
      const redacted = flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_allowed", decision: "allow" });
      redacted.details!.rule_id = "[redacted]";
      const flows = attributeFlows([redacted]);
      expect(flows[0]?.ruleId).toBeNull();
    });

    it("does NOT launder a real rule across keys when an earlier key is redacted", () => {
      // A partially-redacted shape { rule_id: "[redacted]", rule_id_matched:
      // "real-rule" } must NOT fall through the redacted first key to surface the
      // sibling key's real rule. A redacted entry collapses entirely to the
      // null/default-deny bucket — it never resurfaces a rule from another key
      // (property #11; the earlier impl scanned past the redacted key and leaked
      // the second key's value).
      const partlyRedacted = flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_blocked", decision: "drop" });
      partlyRedacted.details!.rule_id = "[redacted]";
      partlyRedacted.details!.rule_id_matched = "real-rule";
      const flows = attributeFlows([partlyRedacted]);
      expect(flows[0]?.ruleId).toBeNull();
      expect(JSON.stringify(flows)).not.toContain("real-rule");
    });
  });

  describe("filterFlowsByRule", () => {
    const flows = attributeFlows([
      flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_allowed", ruleId: "allow-a" }),
      flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_blocked", ruleId: "deny-b" }),
      flowEntry({ timestamp: "2026-06-16T00:00:03Z", operation: "egress_blocked" }),
      flowEntry({ timestamp: "2026-06-16T00:00:04Z", operation: "egress_allowed", ruleId: "allow-a" }),
    ]);

    it("filters to a single rule id", () => {
      const got = filterFlowsByRule(flows, "allow-a");
      expect(got).toHaveLength(2);
      expect(got.every((f) => f.ruleId === "allow-a")).toBe(true);
    });

    it("selects the default-deny (null) flows via the null selector", () => {
      const got = filterFlowsByRule(flows, null);
      expect(got).toHaveLength(1);
      expect(got[0]?.ruleId).toBeNull();
    });

    it("returns nothing for an unknown rule id", () => {
      expect(filterFlowsByRule(flows, "no-such-rule")).toHaveLength(0);
    });

    it("treats the bucket DISPLAY label as a literal rule id (no sentinel collision)", () => {
      // A real rule literally named the bucket display string must be selectable
      // as itself, and must NOT collapse into the null-rule (default-deny) flows.
      const collisionFlows = attributeFlows([
        flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_allowed", ruleId: DEFAULT_DENY_BUCKET }),
        flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_blocked" }),
      ]);
      const literal = filterFlowsByRule(collisionFlows, DEFAULT_DENY_BUCKET);
      expect(literal).toHaveLength(1);
      expect(literal[0]?.ruleId).toBe(DEFAULT_DENY_BUCKET);
      // The null selector still picks the genuine null-rule flow, not the literal.
      const nullSel = filterFlowsByRule(collisionFlows, null);
      expect(nullSel).toHaveLength(1);
      expect(nullSel[0]?.ruleId).toBeNull();
    });
  });

  describe("groupFlowsByRule", () => {
    it("rolls up per-rule counts with an allow/deny/prompt split", () => {
      const groups = groupFlowsByRule(
        attributeFlows([
          flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_allowed", ruleId: "r1", decision: "allow" }),
          flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_allowed", ruleId: "r1", decision: "allow" }),
          flowEntry({ timestamp: "2026-06-16T00:00:03Z", operation: "egress_blocked", ruleId: "r1", decision: "drop" }),
          flowEntry({ timestamp: "2026-06-16T00:00:04Z", operation: "egress_blocked", ruleId: "r2", decision: "drop" }),
        ])
      );
      const r1 = groups.find((g) => g.ruleId === "r1");
      expect(r1).toMatchObject({ total: 3, allow: 2, deny: 1, prompt: 0 });
      const r2 = groups.find((g) => g.ruleId === "r2");
      expect(r2).toMatchObject({ total: 1, allow: 0, deny: 1, prompt: 0 });
    });

    it("rolls null-rule flows into an explicit default-deny bucket, never a fabricated rule", () => {
      const groups = groupFlowsByRule(
        attributeFlows([
          flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_blocked" }),
          flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_blocked" }),
        ])
      );
      expect(groups).toHaveLength(1);
      expect(groups[0]?.ruleId).toBe(DEFAULT_DENY_BUCKET);
      expect(groups[0]?.isDefaultDeny).toBe(true);
      expect(groups[0]?.total).toBe(2);
      expect(groups[0]?.deny).toBe(2);
    });

    it("does NOT merge a real rule literally named like the default-deny label into the synthetic bucket", () => {
      // The default-deny bucket is keyed internally on a symbol, not on its
      // display label, so a real rule an operator happened to author with the
      // exact label text stays its OWN group and never absorbs (or is absorbed
      // by) the null-rule flows.
      const groups = groupFlowsByRule(
        attributeFlows([
          // A real rule whose id == the bucket display string.
          flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_allowed", ruleId: DEFAULT_DENY_BUCKET, decision: "allow" }),
          flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_allowed", ruleId: DEFAULT_DENY_BUCKET, decision: "allow" }),
          // A genuine null-rule (default-deny) flow.
          flowEntry({ timestamp: "2026-06-16T00:00:03Z", operation: "egress_blocked" }),
        ])
      );
      // Two distinct groups share the same display string but are not merged:
      // one is the real rule (isDefaultDeny=false), one is the synthetic bucket.
      const realRule = groups.find((g) => g.ruleId === DEFAULT_DENY_BUCKET && !g.isDefaultDeny);
      const synthetic = groups.find((g) => g.ruleId === DEFAULT_DENY_BUCKET && g.isDefaultDeny);
      expect(realRule).toBeDefined();
      expect(synthetic).toBeDefined();
      expect(realRule?.total).toBe(2);
      expect(realRule?.allow).toBe(2);
      expect(synthetic?.total).toBe(1);
      expect(synthetic?.deny).toBe(1);
    });

    it("sorts by descending total, default-deny bucket always last", () => {
      const groups = groupFlowsByRule(
        attributeFlows([
          flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_blocked" }),
          flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_blocked" }),
          flowEntry({ timestamp: "2026-06-16T00:00:03Z", operation: "egress_blocked" }),
          flowEntry({ timestamp: "2026-06-16T00:00:04Z", operation: "egress_allowed", ruleId: "busy", decision: "allow" }),
          flowEntry({ timestamp: "2026-06-16T00:00:05Z", operation: "egress_allowed", ruleId: "busy", decision: "allow" }),
          flowEntry({ timestamp: "2026-06-16T00:00:06Z", operation: "egress_allowed", ruleId: "rare", decision: "allow" }),
        ])
      );
      // busy(2) > rare(1), and default-deny(3) is forced last despite the higher count.
      expect(groups.map((g) => g.ruleId)).toEqual(["busy", "rare", DEFAULT_DENY_BUCKET]);
    });

    it("counts a prompt and a separately-recorded terminal flow once each (no double-count)", () => {
      // FINDING (verified against the recorded lifecycle): the daemon records ONE
      // audit event per packet. A `PromptRequired` verdict drops the packet and
      // emits a single `egress_pending` -> `operator_decision`; there is no
      // re-evaluation that writes a second terminal entry for the SAME flow. So
      // an `operator_decision` entry and an `egress_blocked`/`egress_allowed`
      // entry are always DISTINCT flows, and each must contribute exactly one to
      // the rollup — never collapsed, never double-counted.
      const groups = groupFlowsByRule(
        attributeFlows([
          // A flow surfaced for approval (prompt) — one count, prompt category.
          flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "operator_decision", ruleId: "needs-approval" }),
          // A different flow that was terminally denied — one count, deny category.
          flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_blocked", ruleId: "deny-x", decision: "drop" }),
        ])
      );
      const prompt = groups.find((g) => g.ruleId === "needs-approval");
      const denied = groups.find((g) => g.ruleId === "deny-x");
      expect(prompt).toMatchObject({ total: 1, prompt: 1, allow: 0, deny: 0 });
      expect(denied).toMatchObject({ total: 1, deny: 1, allow: 0, prompt: 0 });
      // Total flows across all groups equals the number of distinct flow entries.
      expect(groups.reduce((n, g) => n + g.total, 0)).toBe(2);
    });

    it("caps samples per group and returns them most-recent-first", () => {
      const entries = Array.from({ length: 6 }, (_, i) =>
        flowEntry({
          timestamp: `2026-06-16T00:00:0${i}Z`,
          operation: "egress_allowed",
          ruleId: "r1",
          decision: "allow",
        })
      );
      const groups = groupFlowsByRule(attributeFlows(entries), { sampleLimit: 2 });
      expect(groups[0]?.samples).toHaveLength(2);
      expect(groups[0]?.samples[0]?.timestamp).toBe("2026-06-16T00:00:05Z");
      expect(groups[0]?.samples[1]?.timestamp).toBe("2026-06-16T00:00:04Z");
    });

    it("is deterministic across repeated runs (identical output)", () => {
      const make = () =>
        attributeFlows([
          flowEntry({ timestamp: "2026-06-16T00:00:01Z", operation: "egress_allowed", ruleId: "r-a", decision: "allow" }),
          flowEntry({ timestamp: "2026-06-16T00:00:02Z", operation: "egress_blocked", ruleId: "r-b", decision: "drop" }),
          flowEntry({ timestamp: "2026-06-16T00:00:03Z", operation: "egress_blocked", ruleId: "r-b", decision: "drop" }),
          flowEntry({ timestamp: "2026-06-16T00:00:04Z", operation: "egress_blocked" }),
        ]);
      const runs = [0, 1, 2].map(() => JSON.stringify(groupFlowsByRule(make())));
      expect(runs[1]).toBe(runs[0]);
      expect(runs[2]).toBe(runs[0]);
    });
  });
});
