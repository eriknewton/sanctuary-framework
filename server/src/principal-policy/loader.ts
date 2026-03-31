/**
 * Sanctuary MCP Server — Principal Policy Loader
 *
 * Loads the Principal Policy from a YAML file at server startup.
 * The policy is immutable at runtime — no MCP tool can modify it.
 *
 * Security invariant:
 * - The policy is loaded ONCE at startup and frozen.
 * - No code path exists to modify the policy during a session.
 * - If no policy file exists, a sensible default is generated and saved.
 */

import { readFile, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import type { PrincipalPolicy, Tier2Config, ApprovalChannelConfig } from "./types.js";

/** Default Tier 2 anomaly configuration */
const DEFAULT_TIER2: Tier2Config = {
  new_namespace_access: "approve",
  new_counterparty: "approve",
  frequency_spike_multiplier: 5,
  max_signs_per_minute: 10,
  bulk_read_threshold: 20,
  first_session_policy: "approve",
};

/** Default approval channel */
const DEFAULT_CHANNEL: ApprovalChannelConfig = {
  type: "stderr",
  timeout_seconds: 300,
  // SEC-002: auto_deny is not configurable. Timeout always denies.
  // Field omitted intentionally — all channels hardcode deny on timeout.
};

/** Default Principal Policy — provides meaningful protection without configuration */
export const DEFAULT_POLICY: PrincipalPolicy = {
  version: 1,
  tier1_always_approve: [
    "state_export",
    "state_import",
    "state_delete",
    "identity_rotate",
    "reputation_import",
    "reputation_export",
    "bootstrap_provide_guarantee",
  ],
  tier2_anomaly: DEFAULT_TIER2,
  tier3_always_allow: [
    "state_read",
    "state_write",
    "state_list",
    "identity_create",
    "identity_list",
    "identity_sign",
    "identity_verify",
    "proof_commitment",
    "proof_reveal",
    "disclosure_set_policy",
    "disclosure_evaluate",
    "reputation_record",
    "reputation_query",
    "bootstrap_create_escrow",
    "exec_attest",
    "monitor_health",
    "monitor_audit_log",
    "manifest",
    "principal_policy_view",
    "principal_baseline_view",
    "shr_generate",
    "shr_verify",
    "handshake_initiate",
    "handshake_respond",
    "handshake_complete",
    "handshake_status",
    "reputation_query_weighted",
    "federation_peers",
    "federation_trust_evaluate",
    "federation_status",
    "zk_commit",
    "zk_prove",
    "zk_verify",
    "zk_range_prove",
    "zk_range_verify",
    "context_gate_set_policy",
    "context_gate_apply_template",
    "context_gate_recommend",
    "context_gate_filter",
    "context_gate_list_policies",
  ],
  approval_channel: DEFAULT_CHANNEL,
};

/**
 * Extract the operation name from a full MCP tool name.
 * "sanctuary/state_export" → "state_export"
 */
export function extractOperationName(toolName: string): string {
  return toolName.startsWith("sanctuary/")
    ? toolName.slice("sanctuary/".length)
    : toolName;
}

/**
 * Parse a YAML-like policy file into a PrincipalPolicy.
 *
 * We use a simple line-based parser rather than a YAML library
 * to avoid adding a dependency for a straightforward config format.
 * The policy file supports a subset of YAML: scalars, lists, and
 * one level of nesting.
 *
 * For robustness, we also accept JSON.
 */
export function parsePolicy(content: string): PrincipalPolicy {
  const trimmed = content.trim();

  // Try JSON first
  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed);
    return validatePolicy(parsed);
  }

  // Simple YAML-subset parser
  const policy: Record<string, unknown> = {};
  let currentKey: string | null = null;
  let currentList: string[] | null = null;
  let currentObject: Record<string, unknown> | null = null;

  for (const rawLine of trimmed.split("\n")) {
    const line = rawLine.split("#")[0]!; // Strip comments
    if (line.trim() === "") continue;

    const indent = line.length - line.trimStart().length;
    const stripped = line.trim();

    if (indent === 0 && stripped.includes(":")) {
      // Top-level key
      if (currentKey && currentList) {
        policy[currentKey] = currentList;
      } else if (currentKey && currentObject) {
        policy[currentKey] = currentObject;
      }

      const colonIdx = stripped.indexOf(":");
      const key = stripped.slice(0, colonIdx).trim();
      const value = stripped.slice(colonIdx + 1).trim();

      if (value === "" || value === "|") {
        currentKey = key;
        currentList = null;
        currentObject = null;
      } else {
        policy[key] = parseScalar(value);
        currentKey = null;
        currentList = null;
        currentObject = null;
      }
    } else if (indent > 0 && stripped.startsWith("- ")) {
      // List item
      if (!currentList) currentList = [];
      currentList.push(stripped.slice(2).trim().split(/\s+/)[0]!); // Take first word (before comments)
    } else if (indent > 0 && stripped.includes(":")) {
      // Nested key-value
      if (!currentObject) currentObject = {};
      const colonIdx = stripped.indexOf(":");
      const key = stripped.slice(0, colonIdx).trim();
      const value = stripped.slice(colonIdx + 1).trim();
      currentObject[key] = parseScalar(value.split(/\s+/)[0]!); // First word before comments
    }
  }

  // Flush last block
  if (currentKey && currentList) {
    policy[currentKey] = currentList;
  } else if (currentKey && currentObject) {
    policy[currentKey] = currentObject;
  }

  return validatePolicy(policy);
}

function parseScalar(value: string): string | number | boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  const num = Number(value);
  if (!isNaN(num) && value !== "") return num;
  return value.replace(/^["']|["']$/g, "");
}

function validatePolicy(raw: Record<string, unknown>): PrincipalPolicy {
  return {
    version: (raw.version as number) ?? 1,
    tier1_always_approve:
      (raw.tier1_always_approve as string[]) ?? DEFAULT_POLICY.tier1_always_approve,
    tier2_anomaly: {
      ...DEFAULT_TIER2,
      ...((raw.tier2_anomaly as Record<string, unknown>) ?? {}),
    } as Tier2Config,
    tier3_always_allow:
      (raw.tier3_always_allow as string[]) ?? DEFAULT_POLICY.tier3_always_allow,
    approval_channel: (() => {
      const merged = {
        ...DEFAULT_CHANNEL,
        ...((raw.approval_channel as Record<string, unknown>) ?? {}),
      } as ApprovalChannelConfig;
      // SEC-002: Strip auto_deny from user-supplied policy.
      // Timeout always denies — this is not configurable.
      delete merged.auto_deny;
      return merged;
    })(),
  };
}

/**
 * Generate the default policy file content as YAML.
 */
function generateDefaultPolicyYaml(): string {
  return `# Sanctuary Principal Policy v1
# This file controls what your agent can do without asking.
# Edit this file directly. Your agent cannot modify it.
# Changes take effect on server restart.

version: 1

# ─── Tier 1: Always Requires Approval ────────────────────────────────────
# These operations ALWAYS require your explicit approval.
# They are inherently high-risk regardless of context.
tier1_always_approve:
  - state_export
  - state_import
  - state_delete
  - identity_rotate
  - reputation_import
  - reputation_export
  - bootstrap_provide_guarantee

# ─── Tier 2: Behavioral Anomaly Detection ────────────────────────────────
# Triggers approval when agent behavior deviates from its baseline.
# Options for each setting: approve | log | allow
tier2_anomaly:
  new_namespace_access: approve
  new_counterparty: approve
  frequency_spike_multiplier: 5
  max_signs_per_minute: 10
  bulk_read_threshold: 20
  first_session_policy: approve

# ─── Tier 3: Always Allowed (Audit Only) ─────────────────────────────────
# These operations never require approval but are always logged.
tier3_always_allow:
  - state_read
  - state_write
  - state_list
  - identity_create
  - identity_list
  - identity_sign
  - identity_verify
  - proof_commitment
  - proof_reveal
  - disclosure_set_policy
  - disclosure_evaluate
  - reputation_record
  - reputation_query
  - bootstrap_create_escrow
  - exec_attest
  - monitor_health
  - monitor_audit_log
  - manifest
  - principal_policy_view
  - principal_baseline_view
  - shr_generate
  - shr_verify
  - handshake_initiate
  - handshake_respond
  - handshake_complete
  - handshake_status
  - reputation_query_weighted
  - federation_peers
  - federation_trust_evaluate
  - federation_status
  - zk_commit
  - zk_prove
  - zk_verify
  - zk_range_prove
  - zk_range_verify
  - context_gate_set_policy
  - context_gate_apply_template
  - context_gate_recommend
  - context_gate_filter
  - context_gate_list_policies

# ─── Approval Channel ────────────────────────────────────────────────────
# How Sanctuary reaches you when approval is needed.
# NOTE: Timeout always results in denial. This is not configurable (SEC-002).
approval_channel:
  type: stderr
  timeout_seconds: 300
`;
}

/**
 * Load the Principal Policy from disk.
 * If no policy file exists, generate the default and save it.
 * The returned policy is frozen — immutable at runtime.
 */
export async function loadPrincipalPolicy(
  storagePath: string
): Promise<PrincipalPolicy> {
  const policyPath = join(storagePath, "principal-policy.yaml");

  try {
    const content = await readFile(policyPath, "utf-8");
    const policy = parsePolicy(content);
    return Object.freeze(policy);
  } catch {
    // No policy file — generate default
    const defaultYaml = generateDefaultPolicyYaml();
    try {
      await writeFile(policyPath, defaultYaml, "utf-8");
      await chmod(policyPath, 0o600);
    } catch {
      // Can't write — use default in memory
    }
    return Object.freeze({ ...DEFAULT_POLICY });
  }
}
