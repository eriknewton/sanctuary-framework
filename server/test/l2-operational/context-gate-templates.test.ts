/**
 * Sanctuary MCP Server — Context Gate Templates Tests
 *
 * Tests for the pre-built context gating policy templates, including
 * the new remote-inference-sanitize template for Vitalik Buterin's
 * "Secure LLM" use case.
 */

import { describe, it, expect } from "vitest";
import {
  TEMPLATES,
  listTemplateIds,
  getTemplate,
  REMOTE_INFERENCE_SANITIZE,
  INFERENCE_MINIMAL,
  INFERENCE_STANDARD,
  LOGGING_STRICT,
  TOOL_API_SCOPED,
} from "../../src/l2-operational/context-gate-templates.js";

describe("Context Gate Templates", () => {
  describe("Template Registry", () => {
    it("contains all expected templates", () => {
      expect(TEMPLATES["inference-minimal"]).toBeDefined();
      expect(TEMPLATES["inference-standard"]).toBeDefined();
      expect(TEMPLATES["logging-strict"]).toBeDefined();
      expect(TEMPLATES["tool-api-scoped"]).toBeDefined();
      expect(TEMPLATES["remote-inference-sanitize"]).toBeDefined();
    });

    it("listTemplateIds returns all template IDs", () => {
      const ids = listTemplateIds();
      expect(ids).toContain("inference-minimal");
      expect(ids).toContain("inference-standard");
      expect(ids).toContain("logging-strict");
      expect(ids).toContain("tool-api-scoped");
      expect(ids).toContain("remote-inference-sanitize");
    });

    it("getTemplate retrieves templates by ID", () => {
      expect(getTemplate("inference-minimal")).toBe(INFERENCE_MINIMAL);
      expect(getTemplate("remote-inference-sanitize")).toBe(REMOTE_INFERENCE_SANITIZE);
      expect(getTemplate("nonexistent")).toBeUndefined();
    });
  });

  describe("Remote Inference Sanitize Template (Vitalik Buterin Use Case)", () => {
    it("has correct ID", () => {
      expect(REMOTE_INFERENCE_SANITIZE.id).toBe("remote-inference-sanitize");
    });

    it("has human-readable name and description", () => {
      expect(REMOTE_INFERENCE_SANITIZE.name).toBe("Remote Inference Sanitization");
      expect(REMOTE_INFERENCE_SANITIZE.description).toContain("Maximum privacy");
      expect(REMOTE_INFERENCE_SANITIZE.description).toContain("Vitalik Buterin");
    });

    it("specifies when to use it", () => {
      expect(REMOTE_INFERENCE_SANITIZE.use_when).toContain("remote");
      expect(REMOTE_INFERENCE_SANITIZE.use_when).toContain("local");
    });

    it("has inference provider rule", () => {
      const inferenceRule = REMOTE_INFERENCE_SANITIZE.rules.find(
        (r) => r.provider === "inference"
      );
      expect(inferenceRule).toBeDefined();
    });

    it("allows only minimal task/query fields to remote model", () => {
      const inferenceRule = REMOTE_INFERENCE_SANITIZE.rules.find(
        (r) => r.provider === "inference"
      )!;

      expect(inferenceRule.allow).toContain("task");
      expect(inferenceRule.allow).toContain("query");
      expect(inferenceRule.allow).toContain("prompt");
      expect(inferenceRule.allow).toContain("instruction");
      expect(inferenceRule.allow).toContain("output_format");
      expect(inferenceRule.allow).toContain("format");
      expect(inferenceRule.allow).toContain("code_context");
      expect(inferenceRule.allow).toContain("error_message");

      // Should NOT allow history, memory, internal state
      expect(inferenceRule.allow).not.toContain("conversation_history");
      expect(inferenceRule.allow).not.toContain("memory");
      expect(inferenceRule.allow).not.toContain("internal_reasoning");
    });

    it("redacts secrets, PII, and internal state", () => {
      const inferenceRule = REMOTE_INFERENCE_SANITIZE.rules.find(
        (r) => r.provider === "inference"
      )!;

      // Includes base redact patterns
      const redactPatterns = inferenceRule.redact;
      const asString = JSON.stringify(redactPatterns);

      // Should include secret patterns (from ALWAYS_REDACT_SECRETS)
      expect(asString).toContain("secret");
      expect(asString).toContain("password");
      expect(asString).toContain("api_key");

      // Should include PII patterns
      expect(asString).toContain("email");
      expect(asString).toContain("name");
      expect(asString).toContain("phone");

      // Should include internal state patterns
      expect(asString).toContain("memory");
      expect(asString).toContain("reasoning");
    });

    it("redacts tool results and previous results", () => {
      const inferenceRule = REMOTE_INFERENCE_SANITIZE.rules.find(
        (r) => r.provider === "inference"
      )!;

      expect(inferenceRule.redact).toContain("tool_results");
      expect(inferenceRule.redact).toContain("previous_results");
    });

    it("includes additional redactions for agent data and runtime config", () => {
      const inferenceRule = REMOTE_INFERENCE_SANITIZE.rules.find(
        (r) => r.provider === "inference"
      )!;

      expect(inferenceRule.redact).toContain("model_data");
      expect(inferenceRule.redact).toContain("agent_state");
      expect(inferenceRule.redact).toContain("runtime_config");
      expect(inferenceRule.redact).toContain("capabilities");
      expect(inferenceRule.redact).toContain("tool_list");
    });

    it("has deny as default action (strictest mode)", () => {
      expect(REMOTE_INFERENCE_SANITIZE.default_action).toBe("deny");
    });

    it("does not hash any fields (stripped entirely or redacted)", () => {
      const inferenceRule = REMOTE_INFERENCE_SANITIZE.rules.find(
        (r) => r.provider === "inference"
      )!;

      expect(inferenceRule.hash).toHaveLength(0);
    });

    it("does not mark any fields for summarization", () => {
      const inferenceRule = REMOTE_INFERENCE_SANITIZE.rules.find(
        (r) => r.provider === "inference"
      )!;

      expect(inferenceRule.summarize).toHaveLength(0);
    });

    it("has exactly one rule for inference provider", () => {
      expect(REMOTE_INFERENCE_SANITIZE.rules).toHaveLength(1);
      expect(REMOTE_INFERENCE_SANITIZE.rules[0].provider).toBe("inference");
    });
  });

  describe("Existing Templates Still Valid", () => {
    it("inference-minimal exists and is correctly configured", () => {
      expect(INFERENCE_MINIMAL.id).toBe("inference-minimal");
      expect(INFERENCE_MINIMAL.default_action).toBe("redact");
      expect(INFERENCE_MINIMAL.rules.length).toBeGreaterThan(0);
    });

    it("inference-standard exists and is correctly configured", () => {
      expect(INFERENCE_STANDARD.id).toBe("inference-standard");
      expect(INFERENCE_STANDARD.default_action).toBe("redact");
      expect(INFERENCE_STANDARD.rules.length).toBeGreaterThan(0);
    });

    it("logging-strict exists and is correctly configured", () => {
      expect(LOGGING_STRICT.id).toBe("logging-strict");
      expect(LOGGING_STRICT.rules.length).toBeGreaterThan(0);
    });

    it("tool-api-scoped exists and is correctly configured", () => {
      expect(TOOL_API_SCOPED.id).toBe("tool-api-scoped");
      expect(TOOL_API_SCOPED.default_action).toBe("redact");
    });
  });

  describe("Template Structure Validation", () => {
    it("all templates have required fields", () => {
      for (const template of Object.values(TEMPLATES)) {
        expect(template.id).toBeDefined();
        expect(typeof template.id).toBe("string");
        expect(template.name).toBeDefined();
        expect(typeof template.name).toBe("string");
        expect(template.description).toBeDefined();
        expect(typeof template.description).toBe("string");
        expect(template.use_when).toBeDefined();
        expect(typeof template.use_when).toBe("string");
        expect(template.rules).toBeDefined();
        expect(Array.isArray(template.rules)).toBe(true);
        expect(template.default_action).toBeDefined();
        expect(["redact", "deny"]).toContain(template.default_action);
      }
    });

    it("all templates have at least one rule", () => {
      for (const template of Object.values(TEMPLATES)) {
        expect(template.rules.length).toBeGreaterThan(0);
      }
    });

    it("all rules have provider and action arrays", () => {
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

  describe("Security: Redact Priority Over Allow", () => {
    it("remote-inference-sanitize does not allow fields in redact list", () => {
      const inferenceRule = REMOTE_INFERENCE_SANITIZE.rules[0];

      // If a pattern is in both allow and redact, redact wins
      // (This is enforced in context-gate.ts, but we verify the template doesn't
      //  accidentally allow sensitive fields)

      // Verify no overlap: if field is in redact, it shouldn't be in allow
      const redactStr = JSON.stringify(inferenceRule.redact).toLowerCase();
      const allowStr = JSON.stringify(inferenceRule.allow).toLowerCase();

      // Check for overlaps in critical patterns
      expect(allowStr).not.toContain("secret");
      expect(allowStr).not.toContain("password");
      expect(allowStr).not.toContain("api_key");
      expect(allowStr).not.toContain("memory");
    });
  });
});
