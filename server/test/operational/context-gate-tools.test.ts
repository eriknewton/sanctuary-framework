/**
 * L2 Context Gate Tools tests
 *
 * Covers: all 5 MCP tool handlers, policy size limits, template lookup,
 * filter with denied fields, audit logging.
 * Not covered: performance at scale, concurrent policy writes.
 */

import { describe, it, expect } from "vitest";
import { createContextGateTools } from "../../src/operational/context-gate-tools.js";
import {
  buildContextGateCombinedStatus,
  initializeContextGateEnforcerFromProfile,
} from "../../src/operational/context-gate-tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createDefaultProfile } from "../../src/sovereignty-profile.js";

function setup() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const { tools, policyStore } = createContextGateTools(storage, masterKey, auditLog);
  const findTool = (name: string) => tools.find(t => t.name === name)!;
  return { tools, policyStore, auditLog, findTool };
}

describe("Context Gate Tools", () => {
  describe("context_gate_set_policy", () => {
    it("creates a policy with valid rules", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_set_policy");
      const result = await tool.handler({
        policy_id: "test-policy",
        rules: [
          {
            provider_category: "inference",
            allow: ["model", "temperature"],
            redact: ["api_key"],
          },
        ],
      });
      const parsed = JSON.parse(result.content[0].text);
      // Policy should be created (has a policy_id and rules)
      expect(parsed.policy_id).toBeDefined();
      expect(parsed.rules || parsed.rule_count !== undefined).toBeTruthy();
    });

    it("does not return live rules or default action after creating a policy", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_set_policy");
      const result = await tool.handler({
        policy_name: "redaction-test",
        rules: [
          {
            provider: "inference",
            allow: ["model"],
            redact: ["secret_context"],
          },
        ],
        default_action: "deny",
      });
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.policy_id).toBeDefined();
      expect(parsed.rule_count).toBe(1);
      expect(parsed.rules).toBeUndefined();
      expect(parsed.default_action).toBeUndefined();
      expect(result.content[0].text).not.toContain("secret_context");
      expect(result.content[0].text).not.toContain("\"deny\"");
    });

    it("rejects policy with too many rules", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_set_policy");
      const rules = Array.from({ length: 100 }, (_, i) => ({
        provider_category: "inference",
        allow: [`field-${i}`],
      }));
      const result = await tool.handler({ policy_id: "big", rules });
      const text = result.content[0].text;
      expect(text).toContain("error");
    });
  });

  describe("context_gate_apply_template", () => {
    it("applies a known template", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_apply_template");
      const result = await tool.handler({ template_id: "inference-minimal" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.template_applied).toBe("inference-minimal");
    });

    it("does not return template rules or default action after applying a template", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_apply_template");
      const result = await tool.handler({ template_id: "inference-minimal" });
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.policy_id).toBeDefined();
      expect(parsed.rule_count).toBeGreaterThan(0);
      expect(parsed.rules).toBeUndefined();
      expect(parsed.default_action).toBeUndefined();
    });

    it("rejects unknown template", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_apply_template");
      const result = await tool.handler({ template_id: "nonexistent" });
      const text = result.content[0].text;
      expect(text).toContain("error");
    });
  });

  describe("context_gate_recommend", () => {
    it("returns recommendations for a sample context", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_recommend");
      const result = await tool.handler({
        context: { api_key: "sk-xxx", model: "gpt-4", prompt: "hello" },
        provider: "openai",
      });
      const parsed = JSON.parse(result.content[0].text);
      // Should contain some recommendation output (field classifications or policy suggestion)
      expect(parsed).toBeDefined();
      expect(Object.keys(parsed).length).toBeGreaterThan(0);
    });
  });

  describe("context_gate_list_policies", () => {
    it("returns empty list when no policies", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_list_policies");
      const result = await tool.handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.policies).toEqual([]);
    });

    it("lists created policies", async () => {
      const { findTool } = setup();
      const setPolicyTool = findTool("context_gate_set_policy");
      await setPolicyTool.handler({
        policy_id: "p1",
        rules: [{ provider_category: "inference", allow: ["model"] }],
      });

      const listTool = findTool("context_gate_list_policies");
      const result = await listTool.handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.policies.length).toBeGreaterThanOrEqual(1);
    });

    it("does not disclose live policy posture in the agent-facing list response", async () => {
      const { findTool } = setup();
      const setPolicyTool = findTool("context_gate_set_policy");
      await setPolicyTool.handler({
        policy_name: "strict-agent-redaction",
        rules: [
          {
            provider: "inference",
            allow: ["task_description"],
            redact: ["secret_context"],
          },
        ],
        default_action: "deny",
        identity_id: "operator@example.test",
      });

      const listTool = findTool("context_gate_list_policies");
      const result = await listTool.handler({});
      const parsed = JSON.parse(result.content[0].text);
      const listed = parsed.policies.find(
        (policy: { policy_name: string }) =>
          policy.policy_name === "strict-agent-redaction"
      );

      expect(listed).toBeDefined();
      expect(listed.policy_id).toBeDefined();
      expect(listed.rule_count).toBe(1);
      expect(listed.rules).toBeUndefined();
      expect(listed.providers).toBeUndefined();
      expect(listed.default_action).toBeUndefined();
      expect(listed.identity_id).toBeUndefined();
      expect(result.content[0].text).not.toContain("secret_context");
      expect(result.content[0].text).not.toContain("\"deny\"");
      expect(result.content[0].text).not.toContain("operator@example.test");
    });
  });

  describe("context_gate_filter", () => {
    it("filters context through an applied template", async () => {
      const { findTool } = setup();
      // First apply a template to create a policy
      const applyTool = findTool("context_gate_apply_template");
      const applyResult = await applyTool.handler({ template_id: "inference-standard" });
      const applied = JSON.parse(applyResult.content[0].text);
      // Use the actual policy_id from the applied template
      const policyId = applied.policy_id;

      const filterTool = findTool("context_gate_filter");
      const result = await filterTool.handler({
        policy_id: policyId,
        provider: "openai",
        context: { model: "gpt-4", api_key: "sk-xxx", prompt: "hello" },
      });
      const text = result.content[0].text;
      expect(text).not.toContain('"policy_not_found"');
    });

    it("substitutes placeholders for sensitive spans inside allowed context values", async () => {
      const { findTool } = setup();
      const setPolicyTool = findTool("context_gate_set_policy");
      const setResult = await setPolicyTool.handler({
        policy_id: "allow-prompt",
        rules: [
          {
            provider_category: "inference",
            allow: ["prompt"],
            redact: [],
          },
        ],
      });
      const policy = JSON.parse(setResult.content[0].text);

      const filterTool = findTool("context_gate_filter");
      const result = await filterTool.handler({
        policy_id: policy.policy_id,
        provider: "inference",
        context: { prompt: "Email jane@example.com about the test" },
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.safe_context.prompt).toBe(
        "Email EMAIL_1 about the test"
      );
      expect(parsed.summary.privacy_filtered_spans).toBe(1);
      expect(parsed.privacy_filter.findings[0]).toMatchObject({
        path: "$.prompt",
        class: "email",
        action: "placeholder",
        placeholder: "EMAIL_1",
      });
    });

    it("uses nesting-aware filtered output before applying the privacy backstop", async () => {
      const { findTool } = setup();
      const setPolicyTool = findTool("context_gate_set_policy");
      const setResult = await setPolicyTool.handler({
        policy_name: "nested-safe-context",
        rules: [
          {
            provider: "inference",
            allow: ["user", "name", "profile", "note", "prompt"],
            redact: ["ssn", "secret_code"],
            hash: ["user_id"],
            summarize: [],
          },
        ],
      });
      const policy = JSON.parse(setResult.content[0].text);

      const filterTool = findTool("context_gate_filter");
      const result = await filterTool.handler({
        policy_id: policy.policy_id,
        provider: "inference",
        context: {
          user: {
            name: "Ada",
            ssn: "123-45-6789",
            user_id: "user-abc-123",
            profile: {
              note: "safe nested note",
              secret_code: "deep-secret-value",
            },
          },
          prompt: "Email jane@example.com about the test",
        },
      });

      const parsed = JSON.parse(result.content[0].text);
      const user = parsed.safe_context.user;
      expect(parsed.blocked).toBe(false);
      expect(user.name).toBe("Ada");
      expect(user.ssn).toBe("[REDACTED]");
      expect(user.user_id).toMatch(/^\[HASH:[^\]]+\]$/);
      expect(user.profile.note).toBe("safe nested note");
      expect(user.profile.secret_code).toBe("[REDACTED]");
      expect(parsed.safe_context.prompt).toBe("Email EMAIL_1 about the test");
      expect(parsed.summary.privacy_filtered_spans).toBe(1);
      expect(parsed.privacy_filter.findings[0]).toMatchObject({
        path: "$.prompt",
        class: "email",
        action: "placeholder",
        placeholder: "EMAIL_1",
      });

      const serializedSafeContext = JSON.stringify(parsed.safe_context);
      expect(serializedSafeContext).not.toContain("123-45-6789");
      expect(serializedSafeContext).not.toContain("user-abc-123");
      expect(serializedSafeContext).not.toContain("deep-secret-value");
      expect(serializedSafeContext).not.toContain("jane@example.com");
    });

    it("blocks nested deny decisions without emitting safe_context", async () => {
      const { findTool } = setup();
      const setPolicyTool = findTool("context_gate_set_policy");
      const setResult = await setPolicyTool.handler({
        policy_name: "nested-deny",
        rules: [
          {
            provider: "inference",
            allow: ["user", "name"],
            redact: [],
            hash: [],
            summarize: [],
          },
        ],
        default_action: "deny",
      });
      const policy = JSON.parse(setResult.content[0].text);

      const filterTool = findTool("context_gate_filter");
      const result = await filterTool.handler({
        policy_id: policy.policy_id,
        provider: "inference",
        context: {
          user: {
            name: "Ada",
            private_note: "nested-denied-secret",
          },
        },
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.blocked).toBe(true);
      expect(parsed.safe_context).toBeUndefined();
      expect(parsed.denied_fields).toEqual([
        expect.objectContaining({ field: "user.private_note" }),
      ]);
      expect(result.content[0].text).not.toContain("nested-denied-secret");
    });

    it("returns error for non-existent policy", async () => {
      const { findTool } = setup();
      const tool = findTool("context_gate_filter");
      const result = await tool.handler({
        policy_id: "no-such-policy",
        provider: "openai",
        context: { x: 1 },
      });
      const text = result.content[0].text;
      expect(text).toContain("error");
    });
  });

  describe("profile-backed enforcer status", () => {
    it("reports inactive when the profile source disables context gating", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const profile = createDefaultProfile();
      const { tools } = createContextGateTools(storage, masterKey, auditLog, {
        getProfile: () => profile,
      });

      const statusTool = tools.find(t => t.name === "context_gate_enforcer_status")!;
      const result = await statusTool.handler({});
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.combined_status.status).toBe("inactive");
      expect(parsed.combined_status.evidence).toContain("context_gating.enabled is false");
    });

    it("reports degraded when profile says enabled but the enforcer is disabled", () => {
      const profile = createDefaultProfile();
      profile.features.context_gating.enabled = true;

      const status = buildContextGateCombinedStatus(profile, {
        enabled: false,
        log_only: false,
        default_policy_id: null,
        last_filter_success_at: null,
        stats: {
          calls_inspected: 0,
          calls_bypassed: 0,
          fields_redacted: 0,
          fields_hashed: 0,
          fields_blocked: 0,
          calls_blocked: 0,
        },
      });

      expect(status.status).toBe("degraded");
      expect(status.evidence).toContain("runtime enforcer is disabled");
    });

    it("reports active only after both profile and enforcer are enabled and filtering succeeds", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const profile = createDefaultProfile();
      profile.features.context_gating.enabled = true;
      const { tools, enforcer, policyStore } = createContextGateTools(storage, masterKey, auditLog, {
        getProfile: () => profile,
      });
      const policy = await policyStore.create(
        "status-test-policy",
        [
          {
            provider: "tool-api",
            allow: ["task"],
            redact: ["api_key"],
            hash: [],
            summarize: [],
          },
        ],
        "redact"
      );
      profile.features.context_gating.policy_id = policy.policy_id;
      initializeContextGateEnforcerFromProfile(enforcer, profile);

      await enforcer.filterArgs("proxy/test/call", { api_key: "secret", task: "ok" }, {
        respectBypass: false,
      });

      const statusTool = tools.find(t => t.name === "context_gate_enforcer_status")!;
      const result = await statusTool.handler({});
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.combined_status.status).toBe("active");
      expect(parsed.combined_status.last_filter_success_at).toEqual(expect.any(String));
    });
  });
});
