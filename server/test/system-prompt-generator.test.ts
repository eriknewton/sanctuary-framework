/**
 * System Prompt Generator Tests
 *
 * Verifies:
 * - Default profile generates correct prompt (audit + injection on)
 * - All features enabled generates complete prompt
 * - All features disabled generates minimal prompt
 * - Each individual feature toggle changes output
 * - Prompt stays under 500 tokens
 * - Sensitivity and policy_id included when set
 * - Optional tools listed when features are disabled
 */

import { describe, it, expect } from "vitest";
import { generateSystemPrompt } from "../src/system-prompt-generator.js";
import { createDefaultProfile, type SovereigntyProfile } from "../src/sovereignty-profile.js";

function makeProfile(overrides: Partial<SovereigntyProfile["features"]> = {}): SovereigntyProfile {
  const defaults = createDefaultProfile();
  return {
    ...defaults,
    features: {
      ...defaults.features,
      ...overrides,
    },
  };
}

describe("generateSystemPrompt", () => {
  it("includes header line", () => {
    const prompt = generateSystemPrompt(createDefaultProfile());
    expect(prompt).toContain("You are protected by Sanctuary sovereignty infrastructure");
  });

  // ── Default Profile ───────────────────────────────────────────────

  describe("default profile (audit + injection on)", () => {
    it("mentions audit logging as active", () => {
      const prompt = generateSystemPrompt(createDefaultProfile());
      expect(prompt).toContain("Audit Logging");
      expect(prompt).toContain("logged");
    });

    it("mentions injection detection as active", () => {
      const prompt = generateSystemPrompt(createDefaultProfile());
      expect(prompt).toContain("Injection Detection");
      expect(prompt).toContain("scanned");
    });

    it("lists disabled features as optional", () => {
      const prompt = generateSystemPrompt(createDefaultProfile());
      expect(prompt).toContain("Optional tools available but not currently enabled");
      expect(prompt).toContain("context gating");
      expect(prompt).toContain("zero-knowledge proofs");
      // SEC-057: approval_gate is always enabled (core enforcement), so it won't appear in disabled list
      expect(prompt).toContain("Approval Gates");
    });
  });

  // ── All Features On ───────────────────────────────────────────────

  describe("all features enabled", () => {
    it("lists all features as active", () => {
      const profile = makeProfile({
        audit_logging: { enabled: true },
        injection_detection: { enabled: true },
        context_gating: { enabled: true },
        approval_gate: { enabled: true },
        zk_proofs: { enabled: true },
      });
      const prompt = generateSystemPrompt(profile);

      expect(prompt).toContain("Audit Logging");
      expect(prompt).toContain("Injection Detection");
      expect(prompt).toContain("Context Gating");
      expect(prompt).toContain("Approval Gates");
      expect(prompt).toContain("Zero-Knowledge Proofs");
    });

    it("does not include 'Optional tools' section", () => {
      const profile = makeProfile({
        audit_logging: { enabled: true },
        injection_detection: { enabled: true },
        context_gating: { enabled: true },
        approval_gate: { enabled: true },
        zk_proofs: { enabled: true },
      });
      const prompt = generateSystemPrompt(profile);
      expect(prompt).not.toContain("Optional tools available");
    });
  });

  // ── All Features Off ──────────────────────────────────────────────

  describe("all features disabled", () => {
    it("shows no features message", () => {
      const profile = makeProfile({
        audit_logging: { enabled: false },
        injection_detection: { enabled: false },
        context_gating: { enabled: false },
        approval_gate: { enabled: false },
        zk_proofs: { enabled: false },
      });
      const prompt = generateSystemPrompt(profile);
      expect(prompt).toContain("No features are currently enabled");
    });

    it("lists all features as optional", () => {
      const profile = makeProfile({
        audit_logging: { enabled: false },
        injection_detection: { enabled: false },
        context_gating: { enabled: false },
        approval_gate: { enabled: false },
        zk_proofs: { enabled: false },
      });
      const prompt = generateSystemPrompt(profile);
      expect(prompt).toContain("audit logging");
      expect(prompt).toContain("injection detection");
      expect(prompt).toContain("context gating");
      expect(prompt).toContain("approval gates");
      expect(prompt).toContain("zero-knowledge proofs");
    });
  });

  // ── Individual Feature Toggles ────────────────────────────────────

  describe("individual feature toggles", () => {
    it("context gating mentions filter tool", () => {
      const profile = makeProfile({
        context_gating: { enabled: true },
      });
      const prompt = generateSystemPrompt(profile);
      expect(prompt).toContain("context_gate_filter");
    });

    it("zk proofs mentions commit and prove tools", () => {
      const profile = makeProfile({
        zk_proofs: { enabled: true },
      });
      const prompt = generateSystemPrompt(profile);
      expect(prompt).toContain("zk_commit");
      expect(prompt).toContain("zk_prove");
    });

    it("approval gates describes tier system", () => {
      const profile = makeProfile({
        approval_gate: { enabled: true },
      });
      const prompt = generateSystemPrompt(profile);
      expect(prompt).toContain("Tier 1");
      expect(prompt).toContain("Tier 2");
    });
  });

  // ── Configuration Details ─────────────────────────────────────────

  describe("configuration details", () => {
    it("includes sensitivity when set for injection detection", () => {
      const profile = makeProfile({
        injection_detection: { enabled: true, sensitivity: "high" },
      });
      const prompt = generateSystemPrompt(profile);
      expect(prompt).toContain("Sensitivity: high");
    });

    it("includes policy_id when set for context gating", () => {
      const profile = makeProfile({
        context_gating: { enabled: true, policy_id: "cg-abc-123" },
      });
      const prompt = generateSystemPrompt(profile);
      expect(prompt).toContain("cg-abc-123");
    });
  });

  // ── Token Budget ──────────────────────────────────────────────────

  describe("token budget", () => {
    it("default profile prompt is under 500 tokens", () => {
      const prompt = generateSystemPrompt(createDefaultProfile());
      // Rough estimate: 1 token ≈ 4 characters
      const estimatedTokens = Math.ceil(prompt.length / 4);
      expect(estimatedTokens).toBeLessThan(500);
    });

    it("all-features-enabled prompt is under 500 tokens", () => {
      const profile = makeProfile({
        audit_logging: { enabled: true },
        injection_detection: { enabled: true, sensitivity: "high" },
        context_gating: { enabled: true, policy_id: "cg-test-policy-id-very-long" },
        approval_gate: { enabled: true },
        zk_proofs: { enabled: true },
      });
      const prompt = generateSystemPrompt(profile);
      const estimatedTokens = Math.ceil(prompt.length / 4);
      expect(estimatedTokens).toBeLessThan(500);
    });
  });
});
