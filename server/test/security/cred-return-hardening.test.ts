import { describe, it, expect } from "vitest";
import { createSanctuaryServer } from "../../src/index.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { MemoryStorage } from "../../src/storage/memory.js";

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

    expect(entry.details.decided_by).toBe("[redacted]");
    expect(entry.details.policy_rule_id).toBe("[redacted]");
    expect(entry.details.tier).toBe("[redacted]");
    expect(entry.details.nested.operator_id).toBe("[redacted]");
    expect(entry.details.nested.policy_match).toBe("[redacted]");
    expect(text).not.toContain("operator@example.test");
    expect(text).not.toContain("operator-2");
    expect(text).not.toContain("tier1:state_export");
    expect(text).not.toContain("tier1_always_approve");
  });
});
