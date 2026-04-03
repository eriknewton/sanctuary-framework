/**
 * Sanctuary MCP Server — System Prompt Generator
 *
 * Pure function that takes a SovereigntyProfile and generates a concise
 * system prompt snippet (< 500 tokens) instructing the agent on which
 * Sanctuary features are active and how to use them.
 *
 * The prompt is generic (not harness-specific) and intended to be pasted
 * into any agent's system configuration.
 */

import type { SovereigntyProfile } from "./sovereignty-profile.js";

// ── Feature Descriptions ────────────────────────────────────────────────

interface FeaturePromptInfo {
  name: string;
  activeDescription: string;
  toolNames?: string[];
  disabledDescription: string;
}

const FEATURE_INFO: Record<string, FeaturePromptInfo> = {
  audit_logging: {
    name: "Audit Logging",
    activeDescription:
      "All your tool calls are logged to an encrypted audit trail. No action needed — this is automatic.",
    disabledDescription: "audit logging (sanctuary/monitor_audit_log)",
  },
  injection_detection: {
    name: "Injection Detection",
    activeDescription:
      "Your tool call arguments are scanned for prompt injection attempts. No action needed — this is automatic.",
    disabledDescription: "injection detection",
  },
  context_gating: {
    name: "Context Gating",
    activeDescription:
      "Before making outbound calls to remote providers, filter your context through sanctuary/context_gate_filter to ensure minimum-necessary disclosure.",
    toolNames: ["sanctuary/context_gate_filter", "sanctuary/context_gate_set_policy"],
    disabledDescription: "context gating (sanctuary/context_gate_filter)",
  },
  approval_gate: {
    name: "Approval Gates",
    activeDescription:
      "High-risk operations require human approval before execution. Tier 1 operations always require approval; Tier 2 operations trigger approval on anomaly detection.",
    disabledDescription: "approval gates",
  },
  zk_proofs: {
    name: "Zero-Knowledge Proofs",
    activeDescription:
      "You can prove claims about your data without revealing the underlying values. Use sanctuary/zk_commit to create commitments, sanctuary/zk_prove for proofs of knowledge, and sanctuary/zk_range_prove for range proofs.",
    toolNames: ["sanctuary/zk_commit", "sanctuary/zk_prove", "sanctuary/zk_range_prove"],
    disabledDescription: "zero-knowledge proofs (sanctuary/zk_commit, sanctuary/zk_prove)",
  },
};

// ── Generator ───────────────────────────────────────────────────────────

/**
 * Generate a system prompt snippet from the active sovereignty profile.
 *
 * The output is a concise, copy-pasteable text block that instructs the
 * agent on which Sanctuary features are active and how to interact with them.
 */
export function generateSystemPrompt(profile: SovereigntyProfile): string {
  const activeFeatures: string[] = [];
  const inactiveFeatures: string[] = [];

  const featureKeys = [
    "audit_logging",
    "injection_detection",
    "context_gating",
    "approval_gate",
    "zk_proofs",
  ] as const;

  for (const key of featureKeys) {
    const featureConfig = profile.features[key];
    const info = FEATURE_INFO[key]!;

    if (featureConfig.enabled) {
      let desc = `- ${info.name}: ${info.activeDescription}`;

      // Add sensitivity note for injection detection
      if (key === "injection_detection" && "sensitivity" in featureConfig && featureConfig.sensitivity) {
        desc += ` Sensitivity: ${featureConfig.sensitivity}.`;
      }

      // Add policy note for context gating
      if (key === "context_gating" && "policy_id" in featureConfig && featureConfig.policy_id) {
        desc += ` Active policy: ${featureConfig.policy_id}.`;
      }

      activeFeatures.push(desc);
    } else {
      inactiveFeatures.push(info.disabledDescription);
    }
  }

  const lines: string[] = [
    "You are protected by Sanctuary sovereignty infrastructure. The following protections are active:",
    "",
  ];

  if (activeFeatures.length > 0) {
    lines.push(...activeFeatures);
  } else {
    lines.push("- No features are currently enabled. Contact your operator to configure protections.");
  }

  if (inactiveFeatures.length > 0) {
    lines.push("");
    lines.push(
      `Optional tools available but not currently enabled: ${inactiveFeatures.join(", ")}.`
    );
  }

  return lines.join("\n");
}
