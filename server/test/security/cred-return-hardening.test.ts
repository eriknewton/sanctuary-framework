import { describe, it, expect } from "vitest";
import { createSanctuaryServer } from "../../src/index.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { AuditEntry } from "../../src/l2-operational/audit-log.js";
import {
  attributeFlows,
  groupFlowsByRule,
} from "../../src/castle-wall/audit/per-rule-report.js";

async function callTool(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"],
  name: string,
  args: Record<string, unknown> = {}
) {
  const handler = (server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get(
    "tools/call"
  );
  if (!handler) throw new Error("tools/call handler not registered");
  return await handler({
    method: "tools/call" as const,
    params: { name, arguments: args },
  }, {});
}

async function listTools(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"]
) {
  const handler = (server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get(
    "tools/list"
  );
  if (!handler) throw new Error("tools/list handler not registered");
  return await handler({
    method: "tools/list" as const,
    params: {},
  }, {});
}

function parseToolResult(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0]!.text);
}

describe("credential/policy return hardening", () => {
  it("keeps policy-read and context-gate mutation tools out of Tier 3", () => {
    const tier1OnlyTools = [
      "principal_policy_view",
      "principal_baseline_view",
      "sanctuary_policy_status",
      "context_gate_set_policy",
      "context_gate_apply_template",
    ];

    for (const tool of tier1OnlyTools) {
      expect(DEFAULT_POLICY.tier1_always_approve).toContain(tool);
      expect(DEFAULT_POLICY.tier3_always_allow).not.toContain(tool);
    }
  });

  it("removes context-gate mutation tools from the agent MCP catalog", async () => {
    const { server } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-context-gate-catalog",
    });
    const result = await listTools(server);
    const names = (result.tools as Array<{ name: string }>).map((tool) => tool.name);

    expect(names).not.toContain("context_gate_set_policy");
    expect(names).not.toContain("context_gate_apply_template");
    expect(names).toContain("context_gate_filter");
    expect(names).toContain("context_gate_list_policies");
  });

  it("redacts operator handles and tier/policy metadata from monitor_audit_log", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-audit-redaction",
    });
    await auditLog.appendCritical({
      layer: "l2",
      operation: "cross_harness_approval_resolved",
      identity_id: "approval-aggregator",
      result: "success",
      details: {
        aggregator_id: "agg-1",
        decision: "approved",
        decided_by: "operator@example.test",
        identity_id: "operator-top-detail",
        policy_rule_id: "tier1:state_export",
        tier: 1,
        nested: {
          operator_id: "operator-2",
          policy_match: "tier1_always_approve",
        },
      },
    });

    const result = await callTool(server, "monitor_audit_log", { limit: 10 });
    const parsed = parseToolResult(result);
    const text = result.content[0]!.text;
    const entry = parsed.entries.find(
      (candidate: { operation: string }) =>
        candidate.operation === "cross_harness_approval_resolved"
    );

    expect(entry.identity_id).toBe("[redacted]");
    expect(entry.details.decided_by).toBe("[redacted]");
    expect(entry.details.identity_id).toBe("[redacted]");
    expect(entry.details.policy_rule_id).toBe("[redacted]");
    expect(entry.details.tier).toBe("[redacted]");
    expect(entry.details.nested.operator_id).toBe("[redacted]");
    expect(entry.details.nested.policy_match).toBe("[redacted]");
    expect(text).not.toContain("operator@example.test");
    expect(text).not.toContain("approval-aggregator");
    expect(text).not.toContain("operator-top-detail");
    expect(text).not.toContain("operator-2");
    expect(text).not.toContain("tier1:state_export");
    expect(text).not.toContain("tier1_always_approve");
  });

  it("redacts the Castle Wall matched rule_id from monitor_audit_log (#381, property #11)", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-rule-id-redaction",
    });
    // The macOS flow-event consumer writes the matched rule id into the stored
    // entry so the operator can attribute the flow (#381). The agent-facing
    // read boundary must still strip it so an agent cannot map the essentials
    // list by probing (property #11, no-policy-inference).
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: "castle-wall-agent",
      result: "success",
      details: {
        decision: "allow",
        rule_id: "allow-anthropic-api",
        source: "macos_extension",
      },
    });

    const result = await callTool(server, "monitor_audit_log", { limit: 10, layer: "l1" });
    const parsed = parseToolResult(result);
    const text = result.content[0]!.text;
    const entry = parsed.entries.find(
      (candidate: { operation: string }) => candidate.operation === "egress_allowed"
    );

    expect(entry.details.rule_id).toBe("[redacted]");
    expect(entry.details.decision).toBe("allow");
    expect(text).not.toContain("allow-anthropic-api");

    // The operator path (raw audit query, no agent redaction) still sees the
    // rule id -- that is the whole point of #381.
    const raw = await auditLog.query({ layer: "l1", limit: 10 });
    const rawEntry = raw.entries.find((e) => e.operation === "egress_allowed");
    expect(rawEntry?.details?.rule_id).toBe("allow-anthropic-api");
  });

  it("the per-rule-per-flow read-out NEVER exposes rule_id when fed the agent-facing (redacted) read path (#c4, property #11)", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-per-rule-boundary",
    });
    // A flow whose deciding rule is recorded for the operator.
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "castle-wall-agent",
      result: "failure",
      details: { decision: "drop", rule_id: "deny-secret-rule", source: "macos_extension" },
    });

    // What an AGENT sees through the agent-facing read boundary (monitor_audit_log).
    const agentView = parseToolResult(await callTool(server, "monitor_audit_log", { limit: 10, layer: "l1" }));
    const agentEntries: AuditEntry[] = agentView.entries;

    // Running the per-rule aggregator over the agent-facing output must NEVER
    // surface the rule id: the redacted sentinel collapses into the default-deny
    // bucket. This is the structural proof that the new operator surface cannot
    // become an agent-side policy-inference oracle (property #11).
    const flowsFromAgentView = attributeFlows(agentEntries);
    const blocked = flowsFromAgentView.find((f) => f.operation === "egress_blocked");
    expect(blocked).toBeDefined();
    expect(blocked?.ruleId).toBeNull();

    const groupsFromAgentView = groupFlowsByRule(flowsFromAgentView);
    expect(groupsFromAgentView.some((g) => g.ruleId === "deny-secret-rule")).toBe(false);
    expect(JSON.stringify(groupsFromAgentView)).not.toContain("deny-secret-rule");

    // Sanity: the operator path (raw query) still attributes the flow to the rule.
    const raw = await auditLog.query({ layer: "l1", limit: 10 });
    const operatorFlows = attributeFlows(raw.entries.filter((e) => e.layer === "l1"));
    expect(operatorFlows.find((f) => f.operation === "egress_blocked")?.ruleId).toBe("deny-secret-rule");
  });
});
