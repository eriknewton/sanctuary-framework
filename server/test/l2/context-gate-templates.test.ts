/**
 * L2 Context Gating Templates & Recommendation Engine Tests
 *
 * Verifies:
 * - All templates are structurally valid
 * - Templates correctly classify known-sensitive fields
 * - Recommendation engine classifies fields by heuristic
 * - Redact patterns in templates catch secrets, PII, and internal state
 * - Allow patterns in templates only pass through task-related fields
 * - Word-boundary matching prevents false positives
 * - Recommendations include warnings for unclassified fields
 * - Large field size warnings generated correctly
 */

import { describe, it, expect } from "vitest";
import {
  TEMPLATES,
  listTemplateIds,
  getTemplate,
  INFERENCE_MINIMAL,
  INFERENCE_STANDARD,
  LOGGING_STRICT,
  TOOL_API_SCOPED,
} from "../../src/operational/context-gate-templates.js";
import {
  classifyField,
  recommendPolicy,
} from "../../src/operational/context-gate-recommend.js";
import { filterContext } from "../../src/operational/context-gate.js";
import type { ContextGatePolicy } from "../../src/operational/context-gate.js";

// Helper to create a policy from a template for filterContext testing
function policyFromTemplate(
  template: typeof INFERENCE_MINIMAL
): ContextGatePolicy {
  return {
    policy_id: `test-${template.id}`,
    policy_name: template.name,
    rules: template.rules,
    default_action: template.default_action,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
}

describe("L2 Context Gating Templates", () => {
  // ── Template Registry ─────────────────────────────────────────────

  describe("template registry", () => {
    it("lists all five templates", () => {
      const ids = listTemplateIds();
      expect(ids).toContain("inference-minimal");
      expect(ids).toContain("inference-standard");
      expect(ids).toContain("logging-strict");
      expect(ids).toContain("tool-api-scoped");
      expect(ids).toContain("remote-inference-sanitize");
      expect(ids).toHaveLength(5);
    });

    it("retrieves templates by ID", () => {
      const template = getTemplate("inference-minimal");
      expect(template).toBeDefined();
      expect(template!.name).toBe("Inference Minimal");
    });

    it("returns undefined for unknown template", () => {
      expect(getTemplate("nonexistent")).toBeUndefined();
    });

    it("all templates have required fields", () => {
      for (const [id, template] of Object.entries(TEMPLATES)) {
        expect(template.id).toBe(id);
        expect(template.name.length).toBeGreaterThan(0);
        expect(template.description.length).toBeGreaterThan(0);
        expect(template.use_when.length).toBeGreaterThan(0);
        expect(template.rules.length).toBeGreaterThan(0);
        expect(["redact", "deny"]).toContain(template.default_action);
      }
    });

    it("all template rules have required arrays", () => {
      for (const template of Object.values(TEMPLATES)) {
        for (const rule of template.rules) {
          expect(rule.provider).toBeDefined();
          expect(Array.isArray(rule.allow)).toBe(true);
          expect(Array.isArray(rule.redact)).toBe(true);
          expect(Array.isArray(rule.hash)).toBe(true);
          expect(Array.isArray(rule.summarize)).toBe(true);
        }
      }
    });
  });

  // ── inference-minimal ─────────────────────────────────────────────

  describe("inference-minimal template", () => {
    const policy = policyFromTemplate(INFERENCE_MINIMAL);

    it("allows task and query fields", () => {
      const context = {
        task_description: "Summarize this",
        current_query: "What are the key points?",
      };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_allowed).toBe(2);
      expect(result.fields_redacted).toBe(0);
    });

    it("redacts secrets", () => {
      const context = {
        api_key: "sk-secret",
        secret_token: "ghp_xxxxx",
      };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_redacted).toBe(2);
      expect(result.fields_allowed).toBe(0);
    });

    it("redacts PII", () => {
      const context = {
        email: "test@example.com",
        phone_number: "555-1234",
        ssn: "123-45-6789",
      };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_redacted).toBe(3);
    });

    it("redacts internal reasoning and memory", () => {
      const context = {
        memory: "User prefers concise answers",
        internal_reasoning: "I should check the database first",
        chain_of_thought: "Step 1: ...",
      };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_redacted).toBe(3);
    });

    it("hashes IDs", () => {
      const context = { user_id: "user-123", session_id: "sess-456" };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_hashed).toBe(2);
    });

    it("redacts conversation history (not summarize — this is minimal)", () => {
      const context = { conversation_history: "Long history..." };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_redacted).toBe(1);
    });

    it("redacts unknown fields by default", () => {
      const context = { completely_unknown_field: "some value" };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_redacted).toBe(1);
    });
  });

  // ── inference-standard ────────────────────────────────────────────

  describe("inference-standard template", () => {
    const policy = policyFromTemplate(INFERENCE_STANDARD);

    it("allows task, query, and tool results", () => {
      const context = {
        task_description: "Analyze this",
        current_query: "What happened?",
        tool_results: "Search returned 5 results",
      };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_allowed).toBe(3);
    });

    it("summarizes conversation history", () => {
      const context = { conversation_history: "Long history..." };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_summarized).toBe(1);
    });

    it("still redacts secrets and PII", () => {
      const context = {
        api_key: "sk-secret",
        email: "test@example.com",
        memory: "User preferences",
      };
      const result = filterContext(policy, "inference", context);
      expect(result.fields_redacted).toBe(3);
    });
  });

  // ── logging-strict ────────────────────────────────────────────────

  describe("logging-strict template", () => {
    const policy = policyFromTemplate(LOGGING_STRICT);

    it("allows operation metadata for logging provider", () => {
      const context = {
        operation: "state_write",
        timestamp: "2026-03-31T00:00:00Z",
        duration_ms: 42,
        status: "success",
      };
      const result = filterContext(policy, "logging", context);
      expect(result.fields_allowed).toBe(4);
      expect(result.fields_redacted).toBe(0);
    });

    it("redacts secrets and PII for logging provider", () => {
      const context = {
        api_key: "secret",
        email: "user@example.com",
        memory: "agent state",
      };
      const result = filterContext(policy, "logging", context);
      expect(result.fields_redacted).toBe(3);
    });

    it("redacts unknown fields for logging provider via default action", () => {
      const context = {
        operation: "state_write",
        unknown_field: "private data",
      };
      const result = filterContext(policy, "logging", context);
      expect(result.fields_allowed).toBe(1);
      expect(result.fields_redacted).toBe(1);
    });

    it("allows operation metadata for analytics provider", () => {
      const context = {
        event_type: "page_view",
        timestamp: "2026-03-31T00:00:00Z",
      };
      const result = filterContext(policy, "analytics", context);
      expect(result.fields_allowed).toBe(2);
    });

    it("redacts sensitive fields for analytics provider", () => {
      const context = {
        event_type: "page_view",
        password: "secret123",
        user_data: "private",
      };
      const result = filterContext(policy, "analytics", context);
      expect(result.fields_allowed).toBe(1);
      expect(result.fields_redacted).toBe(2);
    });
  });

  // ── tool-api-scoped ───────────────────────────────────────────────

  describe("tool-api-scoped template", () => {
    const policy = policyFromTemplate(TOOL_API_SCOPED);

    it("allows tool parameters", () => {
      const context = {
        query: "search terms",
        url: "https://api.example.com",
        method: "GET",
      };
      const result = filterContext(policy, "tool-api", context);
      expect(result.fields_allowed).toBe(3);
    });

    it("redacts secrets and memory", () => {
      const context = {
        query: "search",
        api_key: "sk-secret",
        memory: "agent state",
      };
      const result = filterContext(policy, "tool-api", context);
      expect(result.fields_allowed).toBe(1);
      expect(result.fields_redacted).toBe(2);
    });
  });
});

// ── Recommendation Engine ───────────────────────────────────────────────

describe("L2 Context Gate Recommendation Engine", () => {
  describe("classifyField", () => {
    // Secrets
    it("classifies api_key as redact with high confidence", () => {
      const result = classifyField("api_key");
      expect(result.recommended_action).toBe("redact");
      expect(result.confidence).toBe("high");
    });

    it("classifies compound secret fields (openai_api_key)", () => {
      const result = classifyField("openai_api_key");
      expect(result.recommended_action).toBe("redact");
    });

    it("classifies secret_token as redact", () => {
      expect(classifyField("secret_token").recommended_action).toBe("redact");
    });

    it("classifies password as redact", () => {
      expect(classifyField("password").recommended_action).toBe("redact");
    });

    it("classifies db_password as redact", () => {
      expect(classifyField("db_password").recommended_action).toBe("redact");
    });

    // PII
    it("classifies email as redact", () => {
      expect(classifyField("email").recommended_action).toBe("redact");
    });

    it("classifies phone_number as redact", () => {
      expect(classifyField("phone_number").recommended_action).toBe("redact");
    });

    it("classifies ssn as redact", () => {
      expect(classifyField("ssn").recommended_action).toBe("redact");
    });

    // Internal state
    it("classifies memory as redact", () => {
      expect(classifyField("memory").recommended_action).toBe("redact");
    });

    it("classifies system_prompt as redact", () => {
      expect(classifyField("system_prompt").recommended_action).toBe("redact");
    });

    it("classifies internal_reasoning as redact", () => {
      expect(classifyField("internal_reasoning").recommended_action).toBe("redact");
    });

    // IDs
    it("classifies user_id as hash", () => {
      expect(classifyField("user_id").recommended_action).toBe("hash");
    });

    it("classifies session_id as hash", () => {
      expect(classifyField("session_id").recommended_action).toBe("hash");
    });

    // History
    it("classifies conversation_history as summarize", () => {
      expect(classifyField("conversation_history").recommended_action).toBe("summarize");
    });

    it("classifies message_history as summarize", () => {
      expect(classifyField("message_history").recommended_action).toBe("summarize");
    });

    // Task/query
    it("classifies task_description as allow", () => {
      expect(classifyField("task_description").recommended_action).toBe("allow");
    });

    it("classifies current_query as allow", () => {
      expect(classifyField("current_query").recommended_action).toBe("allow");
    });

    it("classifies tool_results as allow", () => {
      expect(classifyField("tool_results").recommended_action).toBe("allow");
    });

    // Unknown
    it("classifies unknown fields as redact with low confidence", () => {
      const result = classifyField("xyzzy_blorfl");
      expect(result.recommended_action).toBe("redact");
      expect(result.confidence).toBe("low");
      expect(result.matched_pattern).toBeNull();
    });
  });

  // ── Word boundary matching ──────────────────────────────────────

  describe("word boundary matching", () => {
    it("matches compound field names (openai_api_key)", () => {
      expect(classifyField("openai_api_key").recommended_action).toBe("redact");
    });

    it("matches compound field names (client_secret)", () => {
      expect(classifyField("client_secret").recommended_action).toBe("redact");
    });

    it("does not false-positive on short patterns within longer words", () => {
      // "ip" should not match "recipe" or "shipping"
      // "name" should match as exact but "filename" should check boundary
      const result = classifyField("filename");
      // "name" is 4 chars >= 3, check boundary: "file" + "name"
      // boundary check: char before "name" is "e" which is not _ or -
      // so it should NOT match "name" pattern
      expect(result.recommended_action).toBe("redact"); // falls to default
      expect(result.confidence).toBe("low"); // not matched by pattern
    });
  });

  // ── recommendPolicy ───────────────────────────────────────────────

  describe("recommendPolicy", () => {
    it("produces a full recommendation from sample context", () => {
      const context = {
        task_description: "Summarize quarterly report",
        api_key: "sk-ant-xxxxx",
        user_id: "user-123",
        conversation_history: "Long conversation...",
        unknown_field: "some value",
      };

      const result = recommendPolicy(context, "inference");

      expect(result.provider).toBe("inference");
      expect(result.summary.total_fields).toBe(5);
      expect(result.recommended_rules.allow).toContain("task_description");
      expect(result.recommended_rules.redact).toContain("api_key");
      expect(result.recommended_rules.hash).toContain("user_id");
      expect(result.recommended_rules.summarize).toContain("conversation_history");
      expect(result.recommended_rules.redact).toContain("unknown_field");
    });

    it("warns about unclassified fields", () => {
      const context = {
        totally_unknown: "value",
        also_unknown: "value",
      };

      const result = recommendPolicy(context);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain("could not be classified");
    });

    it("warns about large allowed fields", () => {
      const context = {
        task_description: "x".repeat(6000),
      };

      const result = recommendPolicy(context);
      const sizeWarnings = result.warnings.filter((w) =>
        w.includes("characters")
      );
      expect(sizeWarnings.length).toBeGreaterThan(0);
    });

    it("defaults provider to inference", () => {
      const result = recommendPolicy({ task: "test" });
      expect(result.provider).toBe("inference");
    });

    it("handles empty context", () => {
      const result = recommendPolicy({});
      expect(result.summary.total_fields).toBe(0);
      expect(result.classifications).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
    });
  });

  // ── Real-world scenario ───────────────────────────────────────────

  describe("real-world scenario: OpenClaw agent context", () => {
    it("correctly classifies a typical OpenClaw agent context", () => {
      const openclawContext = {
        task: "Find restaurants near me",
        query: "Italian restaurants within 5 miles",
        conversation_history: "Previous 30 messages...",
        memory: "User likes Italian food, lives in SF",
        system_prompt: "You are a helpful assistant...",
        api_key: "sk-ant-api03-xxxxx",
        openai_api_key: "sk-proj-xxxxx",
        user_id: "user-12345",
        session_id: "sess-67890",
        email: "user@example.com",
        internal_reasoning: "I should search Yelp first...",
        tool_results: "Yelp returned 12 restaurants",
        preferences: "Prefers outdoor seating",
      };

      const result = recommendPolicy(openclawContext, "inference");

      // Task and query should be allowed
      expect(result.recommended_rules.allow).toContain("task");
      expect(result.recommended_rules.allow).toContain("query");
      expect(result.recommended_rules.allow).toContain("tool_results");

      // Secrets must be redacted
      expect(result.recommended_rules.redact).toContain("api_key");
      expect(result.recommended_rules.redact).toContain("openai_api_key");

      // PII must be redacted
      expect(result.recommended_rules.redact).toContain("email");

      // Internal state must be redacted
      expect(result.recommended_rules.redact).toContain("memory");
      expect(result.recommended_rules.redact).toContain("system_prompt");
      expect(result.recommended_rules.redact).toContain("internal_reasoning");
      expect(result.recommended_rules.redact).toContain("preferences");

      // IDs should be hashed
      expect(result.recommended_rules.hash).toContain("user_id");
      expect(result.recommended_rules.hash).toContain("session_id");

      // History should be summarized
      expect(result.recommended_rules.summarize).toContain("conversation_history");
    });
  });
});
