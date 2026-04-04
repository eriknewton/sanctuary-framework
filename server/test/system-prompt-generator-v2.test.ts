/**
 * System Prompt Generator v2 Tests
 *
 * Enhanced tests for the system prompt generator covering Quick Start section,
 * feature-specific tool name inclusion, sensitivity/policy annotations,
 * token budget estimates, and edge cases.
 */

import { describe, it, expect } from "vitest";
import { generateSystemPrompt } from "../src/system-prompt-generator.js";
import { createDefaultProfile, type SovereigntyProfile } from "../src/sovereignty-profile.js";

function makeProfile(
  overrides: Partial<SovereigntyProfile["features"]> = {}
): SovereigntyProfile {
  const defaults = createDefaultProfile();
  return {
    ...defaults,
    features: {
      ...defaults.features,
      ...overrides,
    },
  };
}

function allFeaturesOn(): SovereigntyProfile {
  return makeProfile({
    audit_logging: { enabled: true },
    injection_detection: { enabled: true },
    context_gating: { enabled: true },
    approval_gate: { enabled: true },
    zk_proofs: { enabled: true },
  });
}

function noFeaturesOn(): SovereigntyProfile {
  return makeProfile({
    audit_logging: { enabled: false },
    injection_detection: { enabled: false },
    context_gating: { enabled: false },
    approval_gate: { enabled: false },
    zk_proofs: { enabled: false },
  });
}

describe("generateSystemPrompt — v2 (Enhanced)", () => {
  // ──────────────────────────────────────────────────────────────────────
  // DEFAULT PROFILE
  // ──────────────────────────────────────────────────────────────────────

  describe("Default profile (audit + injection on)", () => {
    it("includes the Quick Start section", () => {
      const prompt = generateSystemPrompt(createDefaultProfile());
      expect(prompt).toContain("QUICK START:");
    });

    it("Quick Start mentions audit logging as automatic", () => {
      const prompt = generateSystemPrompt(createDefaultProfile());
      // Default has audit + injection (passive features only)
      // Quick Start should mention automatic logging
      expect(prompt).toContain("logged");
    });

    it("includes Sanctuary protection header", () => {
      const prompt = generateSystemPrompt(createDefaultProfile());
      expect(prompt).toContain(
        "You are protected by Sanctuary sovereignty infrastructure"
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // ALL FEATURES ENABLED
  // ──────────────────────────────────────────────────────────────────────

  describe("All features enabled", () => {
    it("mentions all five feature names", () => {
      const prompt = generateSystemPrompt(allFeaturesOn());
      expect(prompt).toContain("Audit Logging");
      expect(prompt).toContain("Injection Detection");
      expect(prompt).toContain("Context Gating");
      expect(prompt).toContain("Approval Gates");
      expect(prompt).toContain("Zero-Knowledge Proofs");
    });

    it("mentions all relevant tool names", () => {
      const prompt = generateSystemPrompt(allFeaturesOn());
      expect(prompt).toContain("sanctuary/context_gate_filter");
      expect(prompt).toContain("sanctuary/context_gate_set_policy");
      expect(prompt).toContain("sanctuary/zk_commit");
      expect(prompt).toContain("sanctuary/zk_prove");
      expect(prompt).toContain("sanctuary/proof_commitment");
      expect(prompt).toContain("sanctuary/monitor_audit_log");
    });

    it("does not include optional tools section when all enabled", () => {
      const prompt = generateSystemPrompt(allFeaturesOn());
      expect(prompt).not.toContain("Optional tools available but not currently enabled");
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // INDIVIDUAL FEATURE TOGGLES
  // ──────────────────────────────────────────────────────────────────────

  describe("Context gating enabled", () => {
    it("mentions sanctuary/context_gate_filter tool", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ context_gating: { enabled: true } })
      );
      expect(prompt).toContain("sanctuary/context_gate_filter");
    });

    it("Quick Start prioritizes context gating first", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ context_gating: { enabled: true } })
      );
      expect(prompt).toContain("ALWAYS call sanctuary/context_gate_filter");
    });

    it("includes policy_id when set", () => {
      const prompt = generateSystemPrompt(
        makeProfile({
          context_gating: { enabled: true, policy_id: "my-custom-policy-v2" },
        })
      );
      expect(prompt).toContain("my-custom-policy-v2");
      expect(prompt).toContain("Active policy:");
    });
  });

  describe("ZK proofs enabled", () => {
    it("mentions sanctuary/proof_commitment and sanctuary/zk_commit", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ zk_proofs: { enabled: true } })
      );
      expect(prompt).toContain("sanctuary/proof_commitment");
      expect(prompt).toContain("sanctuary/zk_commit");
    });

    it("mentions sanctuary/zk_range_prove", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ zk_proofs: { enabled: true } })
      );
      expect(prompt).toContain("sanctuary/zk_range_prove");
    });
  });

  describe("Approval gate enabled", () => {
    it("mentions async approval behavior", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ approval_gate: { enabled: true } })
      );
      expect(prompt).toContain("async");
    });

    it("mentions Tier 1 and Tier 2 operations", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ approval_gate: { enabled: true } })
      );
      expect(prompt).toContain("Tier 1");
      expect(prompt).toContain("Tier 2");
    });

    it("mentions human approval requirement", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ approval_gate: { enabled: true } })
      );
      expect(prompt).toContain("human approval");
    });
  });

  describe("Injection detection enabled", () => {
    it("mentions automatic scanning — no agent action needed", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ injection_detection: { enabled: true } })
      );
      expect(prompt).toContain("automatic");
      expect(prompt).toContain("no action needed");
    });

    it("includes sensitivity level when set", () => {
      const prompt = generateSystemPrompt(
        makeProfile({
          injection_detection: { enabled: true, sensitivity: "high" },
        })
      );
      expect(prompt).toContain("Sensitivity: high");
    });

    it("includes medium sensitivity when set", () => {
      const prompt = generateSystemPrompt(
        makeProfile({
          injection_detection: { enabled: true, sensitivity: "medium" },
        })
      );
      expect(prompt).toContain("Sensitivity: medium");
    });
  });

  describe("Audit logging enabled", () => {
    it("mentions automatic logging", () => {
      const prompt = generateSystemPrompt(
        makeProfile({ audit_logging: { enabled: true } })
      );
      expect(prompt).toContain("automatic");
      expect(prompt).toContain("logged");
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // NO FEATURES ENABLED
  // ──────────────────────────────────────────────────────────────────────

  describe("No features enabled", () => {
    it("shows 'No features are currently enabled' message", () => {
      const prompt = generateSystemPrompt(noFeaturesOn());
      expect(prompt).toContain("No features are currently enabled");
    });

    it("does not include Quick Start section", () => {
      const prompt = generateSystemPrompt(noFeaturesOn());
      expect(prompt).not.toContain("QUICK START:");
    });

    it("lists all features as optional", () => {
      const prompt = generateSystemPrompt(noFeaturesOn());
      expect(prompt).toContain("Optional tools available but not currently enabled");
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // TOKEN ESTIMATE
  // ──────────────────────────────────────────────────────────────────────

  describe("Prompt token estimate", () => {
    it("all-features prompt stays under reasonable token budget", () => {
      const prompt = generateSystemPrompt(allFeaturesOn());
      // Rough estimate: ~1.3 tokens per word for English text
      const wordCount = prompt.split(/\s+/).length;
      const estimatedTokens = wordCount * 1.3;
      // Full prompt should be under 500 tokens
      expect(estimatedTokens).toBeLessThan(500);
    });

    it("default profile prompt is concise", () => {
      const prompt = generateSystemPrompt(createDefaultProfile());
      const wordCount = prompt.split(/\s+/).length;
      const estimatedTokens = wordCount * 1.3;
      // Default (2 features on) should be shorter
      expect(estimatedTokens).toBeLessThan(400);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // QUICK START ORDERING
  // ──────────────────────────────────────────────────────────────────────

  describe("Quick Start section ordering", () => {
    it("Quick Start appears before the main feature list", () => {
      const prompt = generateSystemPrompt(allFeaturesOn());
      const quickStartIndex = prompt.indexOf("QUICK START:");
      const headerIndex = prompt.indexOf(
        "You are protected by Sanctuary sovereignty infrastructure"
      );
      expect(quickStartIndex).toBeLessThan(headerIndex);
    });

    it("context gating is first Quick Start item when enabled", () => {
      const prompt = generateSystemPrompt(allFeaturesOn());
      const quickStartSection = prompt.split("QUICK START:")[1]!.split(
        "You are protected"
      )[0]!;
      // First numbered item should mention context_gate_filter
      expect(quickStartSection).toContain("1. ALWAYS call sanctuary/context_gate_filter");
    });
  });
});
