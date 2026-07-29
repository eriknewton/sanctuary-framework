import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createSanctuaryServer } from "../../src/index.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createTempHome } from "../helpers/temp-fortress.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import {
  attributeFlows,
  groupFlowsByRule,
} from "../../src/castle-wall/audit/per-rule-report.js";
import { CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY } from "../../src/castle-wall/constants.js";

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

/**
 * Run `fn` with SANCTUARY_SESSION_IDENTITY_ID bound to `identityId` so the
 * agent-facing own-identity filter (monitor_audit_log / audit_export_siem)
 * returns entries owned by that identity, restoring the prior value after.
 */
async function withSessionIdentity(identityId: string, fn: () => Promise<void>) {
  const prev = process.env.SANCTUARY_SESSION_IDENTITY_ID;
  process.env.SANCTUARY_SESSION_IDENTITY_ID = identityId;
  try {
    await fn();
  } finally {
    if (prev === undefined) delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
    else process.env.SANCTUARY_SESSION_IDENTITY_ID = prev;
  }
}


// Fortress hermeticity: `createSanctuaryServer` boots the real server, and its
// step 20 writes the config unconditionally. With `HOME` left alone that write
// lands on the operator's own `~/.sanctuary/sanctuary.json` -- measured, not
// inferred: this file was one of five bisected as rewriting it on every suite
// run. Injecting `MemoryStorage` is not enough, because `config.storage_path`
// still comes from `defaultConfig()`'s `join(homedir(), ".sanctuary")`.
// Moving `HOME` redirects the mkdir, the permission tightening, and the config
// write onto a throwaway directory without changing anything under test.
// `saveConfig` now fails such a write closed under Vitest, so removing this
// isolation turns the leak into a loud failure rather than a silent one.
let fortressHome: Awaited<ReturnType<typeof createTempHome>>;

beforeEach(async () => {
  fortressHome = await createTempHome("sanctuary-cred-return");
});

afterEach(async () => {
  await fortressHome.cleanup();
});

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

  it("monitor_audit_log emits only the allowlisted view — no operator handles, tier, or policy metadata (no details at all)", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-audit-redaction",
    });
    // Bind the session to the caller identity so the own-identity filter returns
    // this entry; assert the ALLOWLIST view carries none of the operator detail.
    await withSessionIdentity("ag-allowlist-view", async () => {
      await auditLog.appendCritical({
        layer: "l2",
        operation: "cross_harness_approval_resolved",
        identity_id: "ag-allowlist-view",
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

      // ALLOWLIST contract: exactly the safe fixed shape, nothing else.
      expect(entry).toBeDefined();
      expect(Object.keys(entry).sort()).toEqual([
        "has_details",
        "operation",
        "result",
        "timestamp",
      ]);
      expect(entry.has_details).toBe(true);
      expect(entry.details).toBeUndefined();
      expect(entry.identity_id).toBeUndefined();
      // None of the operator/policy strings appear anywhere in the response.
      expect(text).not.toContain("operator@example.test");
      expect(text).not.toContain("operator-top-detail");
      expect(text).not.toContain("operator-2");
      expect(text).not.toContain("tier1:state_export");
      expect(text).not.toContain("tier1_always_approve");
      expect(text).not.toContain("approved");
      expect(text).not.toContain("agg-1");
    });
  });

  it("monitor_audit_log never exposes the Castle Wall matched rule_id — allowlist view drops all details (#381, property #11)", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-rule-id-redaction",
    });
    // The macOS flow-event consumer writes the matched rule id into the stored
    // entry so the operator can attribute the flow (#381). The agent-facing
    // read boundary returns only the safe allowlisted view (no details), so the
    // rule id can never reach an agent (property #11, no-policy-inference).
    await withSessionIdentity("ag-castle-wall", async () => {
      await auditLog.appendCritical({
        layer: "l1",
        operation: "egress_allowed",
        identity_id: "ag-castle-wall",
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

      expect(entry).toBeDefined();
      expect(entry.details).toBeUndefined();
      expect(entry.has_details).toBe(true);
      expect(text).not.toContain("allow-anthropic-api");

      // The operator path (raw audit query, no agent redaction) still sees the
      // rule id -- that is the whole point of #381.
      const raw = await auditLog.query({ layer: "l1", limit: 10 });
      const rawEntry = raw.entries.find((e) => e.operation === "egress_allowed");
      expect(rawEntry?.details?.rule_id).toBe("allow-anthropic-api");
    });
  });

  it("monitor_audit_log never exposes the Linux producer-signed matched rule (rule_id_matched) — allowlist view drops all details (property #11)", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-rule-id-matched-redaction",
    });
    // The Linux producer-signed audit path persists the matched rule under
    // `rule_id_matched` (the Rust daemon's signed WAL body). The agent-facing
    // read boundary returns only the safe allowlisted view (no details) so an
    // agent can never learn which allow/deny rule matched and map the essentials
    // list by probing (property #11). This was a pre-existing leak (since #520);
    // the allowlist closes it durably (a new detail key cannot regress it).
    await withSessionIdentity("ag-cw-signed", async () => {
      await auditLog.appendCritical({
        layer: "l1",
        operation: "egress_blocked",
        identity_id: "ag-cw-signed",
        result: "failure",
        details: {
          decision: "deny_once",
          rule_id_matched: "deny-blocked-example",
          cw_evidence_basis: "producer_signed",
        },
      });

      const result = await callTool(server, "monitor_audit_log", { limit: 10, layer: "l1" });
      const parsed = parseToolResult(result);
      const text = result.content[0]!.text;
      const entry = parsed.entries.find(
        (candidate: { operation: string }) => candidate.operation === "egress_blocked"
      );

      expect(entry).toBeDefined();
      expect(entry.details).toBeUndefined();
      expect(entry.has_details).toBe(true);
      expect(text).not.toContain("deny-blocked-example");

      // The operator path (raw audit query, no agent redaction) still sees the
      // matched rule -- that is the whole point of operator attribution.
      const raw = await auditLog.query({ layer: "l1", limit: 10 });
      const rawEntry = raw.entries.find((e) => e.operation === "egress_blocked");
      expect(rawEntry?.details?.rule_id_matched).toBe("deny-blocked-example");
    });
  });

  it("monitor_audit_log never exposes the producer-signed canonical blob (or top-level decision_provenance) — allowlist view drops all details so the matched rule cannot be read out of the signed body (property #11)", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-producer-signed-canonical-redaction",
    });
    // The Linux producer-signed path (audit-consumer.ts buildDetailsForEvent)
    // persists the VERBATIM signed WAL body under
    // `cw_producer_signed_canonical` -- a STRING that embeds rule_id_matched,
    // decision_provenance, agent_id, dest_*. It also spreads the signed body's
    // own `details` into the entry, so `decision_provenance` lands as a
    // top-level key. The allowlist view returns NO details at all, so neither
    // the blob, the top-level decision_provenance, nor anything embedded in the
    // blob string can reach an agent. This mirrors the real persisted shape.
    const signedCanonical = JSON.stringify({
      layer: "l1",
      operation: "deny_once",
      seq: 7,
      details: {
        agent_id: "ag-cw-canonical",
        dest_host: "blocked.example.test",
        dest_port: 443,
        rule_id_matched: "deny-blocked-from-signed-body",
        decision_provenance: "operator-allowlist-miss->default-deny",
      },
    });
    await withSessionIdentity("ag-cw-canonical", async () => {
      await auditLog.appendCritical({
        layer: "l1",
        operation: "egress_blocked",
        identity_id: "ag-cw-canonical",
        result: "failure",
        details: {
          decision: "deny_once",
          // Top-level copy spread from the signed body by buildDetailsForEvent.
          decision_provenance: "operator-allowlist-miss->default-deny",
          cw_evidence_basis: "producer_signed",
          cw_producer_sig: "sig-b64url-placeholder",
          cw_producer_kid: "cw-audit-producer-v1",
          [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: signedCanonical,
        },
      });

      const result = await callTool(server, "monitor_audit_log", { limit: 10, layer: "l1" });
      const parsed = parseToolResult(result);
      const text = result.content[0]!.text;
      const entry = parsed.entries.find(
        (candidate: { operation: string }) => candidate.operation === "egress_blocked"
      );

      // The allowlist view carries NO details — not the blob, not the spread
      // decision_provenance, not even a sentinel. Nothing to parse out.
      expect(entry).toBeDefined();
      expect(entry.details).toBeUndefined();
      expect(entry.has_details).toBe(true);
      // The matched rule and the provenance string never reach the agent text,
      // neither at top level nor embedded inside the signed body.
      expect(text).not.toContain("deny-blocked-from-signed-body");
      expect(text).not.toContain("operator-allowlist-miss");
      expect(text).not.toContain("blocked.example.test");
      expect(text).not.toContain(CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY);

      // The operator path (raw audit query, no agent redaction) still sees the
      // full signed body and the provenance -- operator/auditor re-verification
      // depends on the verbatim blob.
      const raw = await auditLog.query({ layer: "l1", limit: 10 });
      const rawEntry = raw.entries.find((e) => e.operation === "egress_blocked");
      expect(rawEntry?.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]).toBe(signedCanonical);
      expect(rawEntry?.details?.decision_provenance).toBe(
        "operator-allowlist-miss->default-deny"
      );
    });
  });

  it("the per-rule-per-flow read-out NEVER exposes rule_id when fed the agent-facing (allowlisted) read path (#c4, property #11)", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "cred-return-per-rule-boundary",
    });
    await withSessionIdentity("ag-per-rule", async () => {
      // A flow whose deciding rule is recorded for the operator.
      await auditLog.appendCritical({
        layer: "l1",
        operation: "egress_blocked",
        identity_id: "ag-per-rule",
        result: "failure",
        details: { decision: "drop", rule_id: "deny-secret-rule", source: "macos_extension" },
      });

      // What an AGENT sees through the agent-facing read boundary (monitor_audit_log).
      const agentView = parseToolResult(await callTool(server, "monitor_audit_log", { limit: 10, layer: "l1" }));
      const agentEntries: AuditEntry[] = agentView.entries;

      // Running the per-rule aggregator over the agent-facing output must NEVER
      // surface the rule id: the allowlist view carries no rule_id at all, so it
      // collapses into the default-deny bucket. This is the structural proof that
      // the operator surface cannot become an agent-side policy-inference oracle.
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
});
