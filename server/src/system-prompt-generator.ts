/**
 * Sanctuary MCP Server — System Prompt Generator
 *
 * Pure function that takes a SovereigntyProfile and generates a system
 * prompt snippet instructing the agent on which Sanctuary features are
 * active and how to use them.
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
  /** Concrete usage example shown when the feature is enabled */
  usageExample?: string;
}

const FEATURE_INFO: Record<string, FeaturePromptInfo> = {
  audit_logging: {
    name: "Audit Logging",
    activeDescription:
      "All your tool calls are logged to an encrypted audit trail. No action needed — this is automatic. You can query the log with monitor_audit_log if you need to review past activity.",
    toolNames: ["monitor_audit_log"],
    disabledDescription: "audit logging (monitor_audit_log)",
    usageExample:
      "Automatic — every tool call you make is recorded. No explicit action required.",
  },
  injection_detection: {
    name: "Injection Detection",
    activeDescription:
      "Your tool call arguments are scanned for prompt injection attempts. This is automatic — no action needed. If injection is detected in your input, the call will be blocked and you will receive an error. Do not retry blocked calls with the same input.",
    disabledDescription: "injection detection",
    usageExample:
      "Automatic — if a tool call is blocked with an injection alert, do not retry with the same arguments.",
  },
  context_gating: {
    name: "Context Gating",
    activeDescription:
      "Before sending context to any external API (LLM inference, tool APIs, logging services), call context_gate_filter to strip sensitive fields. Use context_gate_set_policy to define filtering rules, or context_gate_apply_template for presets.",
    toolNames: [
      "context_gate_filter",
      "context_gate_set_policy",
      "context_gate_apply_template",
      "context_gate_recommend",
      "context_gate_list_policies",
    ],
    disabledDescription: "context gating (context_gate_filter)",
    usageExample:
      "Before calling an external API, run: context_gate_filter with your context object and policy_id to get a filtered version.",
  },
  approval_gate: {
    name: "Approval Gates",
    activeDescription:
      "High-risk operations require human approval before execution. Tier 1 operations (export, import, key rotation, deletion) always require approval. Tier 2 operations trigger approval when anomalous behavior is detected. When an operation is held for approval, you will receive an async response — wait for the human decision before proceeding.",
    disabledDescription: "approval gates",
    usageExample:
      "When you call a Tier 1 operation (e.g., state_export), expect an async hold. The human operator will approve or deny via the dashboard.",
  },
  zk_proofs: {
    name: "Zero-Knowledge Proofs",
    activeDescription:
      "You can prove claims about your data without revealing the underlying values. Use zk_commit to create a Pedersen commitment, zk_prove (Schnorr proof) to prove you know a committed value, and zk_range_prove to prove a value falls within a range — all without disclosing the actual data. For simpler SHA-256 commitments, use proof_commitment.",
    toolNames: [
      "zk_commit",
      "zk_prove",
      "zk_range_prove",
      "proof_commitment",
    ],
    disabledDescription:
      "zero-knowledge proofs (zk_commit, zk_prove)",
    usageExample:
      "To prove a claim without revealing data: first zk_commit to commit, then zk_prove or zk_range_prove to generate a verifiable proof.",
  },
};

// ── Generator ───────────────────────────────────────────────────────────

/**
 * Generate a system prompt snippet from the active sovereignty profile.
 *
 * The output is a copy-pasteable text block that instructs the agent on
 * which Sanctuary features are active and how to interact with them.
 */
export function generateSystemPrompt(profile: SovereigntyProfile): string {
  const activeFeatures: string[] = [];
  const inactiveFeatures: string[] = [];
  const activeKeys: string[] = [];

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
      activeKeys.push(key);
      let desc = `- ${info.name}: ${info.activeDescription}`;

      // Add sensitivity note for injection detection
      if (
        key === "injection_detection" &&
        "sensitivity" in featureConfig &&
        featureConfig.sensitivity
      ) {
        desc += ` Sensitivity: ${featureConfig.sensitivity}.`;
      }

      // Add policy note for context gating
      if (
        key === "context_gating" &&
        "policy_id" in featureConfig &&
        featureConfig.policy_id
      ) {
        desc += ` Active policy: ${featureConfig.policy_id}.`;
      }

      activeFeatures.push(desc);
    } else {
      inactiveFeatures.push(info.disabledDescription);
    }
  }

  const lines: string[] = [];

  // Quick Start section — top 2-3 most important instructions
  if (activeKeys.length > 0) {
    lines.push("QUICK START:");
    const quickStartItems = buildQuickStart(activeKeys);
    for (const item of quickStartItems) {
      lines.push(`  ${item}`);
    }
    lines.push("");
  }

  lines.push(
    "You are protected by Sanctuary sovereignty infrastructure. The following protections are active:"
  );
  lines.push("");

  if (activeFeatures.length > 0) {
    lines.push(...activeFeatures);
  } else {
    lines.push(
      "- No features are currently enabled. Contact your operator to configure protections."
    );
  }

  if (inactiveFeatures.length > 0) {
    lines.push("");
    lines.push(
      `Optional tools available but not currently enabled: ${inactiveFeatures.join(", ")}.`
    );
  }

  return lines.join("\n");
}

/**
 * Build the Quick Start bullets based on which features are active.
 * Returns the 2-3 most important action items.
 */
function buildQuickStart(activeKeys: string[]): string[] {
  const items: string[] = [];

  // Context gating is highest-priority action item — requires explicit agent calls
  if (activeKeys.includes("context_gating")) {
    items.push(
      "1. ALWAYS call context_gate_filter before sending context to external APIs."
    );
  }

  // ZK proofs — second most important active tool
  if (activeKeys.includes("zk_proofs")) {
    items.push(
      `${items.length + 1}. Use zk_commit to prove claims without revealing underlying data.`
    );
  }

  // Approval gate — agent needs to know about async behavior
  if (activeKeys.includes("approval_gate")) {
    items.push(
      `${items.length + 1}. High-risk operations will be held for human approval — expect async responses.`
    );
  }

  // If none of the "action" features are active, mention the passive ones
  if (items.length === 0) {
    if (activeKeys.includes("audit_logging")) {
      items.push("1. All tool calls are automatically logged to an encrypted audit trail.");
    }
    if (activeKeys.includes("injection_detection")) {
      items.push(
        `${items.length + 1}. Tool arguments are scanned for injection — blocked calls should not be retried.`
      );
    }
  }

  return items;
}
