/**
 * Sanctuary MCP Server -- Principal Policy Loader
 *
 * Loads the Principal Policy from a YAML file at server startup.
 * The policy is immutable at runtime -- no MCP tool can modify it.
 *
 * Security invariant:
 * - The policy is loaded ONCE at startup and frozen.
 * - No code path exists to modify the policy during a session.
 * - If no policy file exists, a sensible default is generated and saved.
 * - If the policy file exists but is malformed, the server refuses to start
 *   rather than silently substituting a default (operator intent preservation).
 */

import { join } from "node:path";
import { readFileCustody, writeFileCustody } from "../storage/custody-fs.js";
import type {
  PrincipalPolicy,
  Tier2Config,
  ApprovalChannelConfig,
  ApprovalRedirectConfig,
} from "./types.js";

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

/**
 * Default approval-redirect config. Off by default — preserves the legacy
 * one-channel-per-fortress behavior so existing operators see no change
 * until they explicitly opt in.
 */
const DEFAULT_APPROVAL_REDIRECT: ApprovalRedirectConfig = {
  enabled: false,
  mode: "replace",
};

const RAW_IDENTITY_SIGN_OPERATION = "identity_sign";

/**
 * Operations that MUST always require approval (Tier 1) and must never sit in
 * Tier 3, regardless of what an existing on-disk policy file says. validatePolicy
 * force-adds these to merged Tier 1 and prunes them from merged Tier 3 so the
 * invariant holds on upgrade, not just for freshly generated defaults.
 *
 * - identity_sign: raw arbitrary commitments require explicit operator approval.
 * - principal_policy_view / principal_baseline_view / sanctuary_policy_status:
 *   reading the Principal Policy or its baseline must never be a silent
 *   agent-auto-allowed operation (no-read invariant; an agent that can read the
 *   policy can plan to evade it).
 * - context_gate_set_policy / context_gate_apply_template: policy-adjacent
 *   enforcement mutations must not be silently agent-auto-allowed.
 * - audit_export_siem: bulk-exports decrypted audit events across all
 *   principals, each carrying its policy tier and approve/deny decision — a
 *   policy-inference oracle for the agent (no-read invariant). SIEM forwarding
 *   is an operator function, so it must require operator approval. (CISO MED-1.)
 * - compliance_generate_eu_ai_act_bundle: the generated bundle body embeds the
 *   verbatim Tier-2 anomaly policy (e.g. frequency_spike_multiplier), the
 *   approval-channel timeout, and audit-derived aggregate gate-decision counts —
 *   the same policy-inference leak class as audit_export_siem, through a
 *   different door (no-read invariant). It is also a governance conflict of
 *   interest: an agent must not self-generate its own compliance attestation.
 *   So it must require operator approval. (CISO NEW-1.)
 */
const FORCED_TIER1_OPERATIONS = [
  RAW_IDENTITY_SIGN_OPERATION,
  "principal_policy_view",
  "principal_baseline_view",
  "sanctuary_policy_status",
  "context_gate_set_policy",
  "context_gate_apply_template",
  "audit_export_siem",
  "compliance_generate_eu_ai_act_bundle",
] as const;

/**
 * HABEAS PORT (agent-side sovereignty, ratified 2026-06-12): operations that
 * MUST always be allowed (Tier 3, audit-only) and may NEVER be gated behind
 * Tier 1 approval. The distress channel is the agent's guaranteed lane to
 * signal "I am in distress"; an approval gate in front of it would let the
 * approval channel (or its absence) silence distress. A policy that lists
 * one of these under tier1_always_approve is REJECTED with a clear error —
 * not silently pruned — so the operator sees the attempted override instead
 * of believing it took effect.
 */
export const FORCED_TIER3_OPERATIONS = ["sanctuary_distress"] as const;

/** Default Principal Policy — provides meaningful protection without configuration */
export const DEFAULT_POLICY: PrincipalPolicy = {
  version: 1,
  tier1_always_approve: [
    "state_export",
    "state_import",
    "state_delete",
    "identity_sign", // Raw arbitrary commitments require explicit operator approval.
    "identity_rotate",
    "reputation_import",
    "reputation_export",
    "bootstrap_provide_guarantee",
    "decommission_certificate",
    "sovereignty_profile_update", // Changes enforcement behavior — always requires approval
    "governor_reset", // Clears all runtime governance state — always requires approval
    "sanctuary_bootstrap", // Creates new Ed25519 identity + publishes — always requires approval
    "sanctuary_export_identity_bundle", // Exports portable identity — always requires approval
    "exit_bundle_export", // Complete portability bundle export. Always requires approval.
    "exit_bundle_import", // External durable-record import. Always requires approval.
    "exit_bundle_import_activate", // Activates imported material. Always requires approval.
    "exit_bundle_rekey", // Re-encrypts imported state under destination keys.
    // v1.1 hub-control surfaces. Every operation_category in
    // server/src/contracts/v1.1/hub-events.ts that is not already canonical
    // here MUST be enrolled under Tier 1 in the same PR that lands the hub
    // endpoint that surfaces it. Drift between the contract enum and this
    // list is a release blocker per the contract comment.
    "policy_change", // Operator-driven policy bind on a wrapped agent.
    "lockdown", // Operator-driven hard-stop of a wrapped agent.
    "unwrap", // Operator-driven removal of the Sanctuary wrap from an agent.
    "principal_policy_view", // Reads Principal Policy; always requires approval.
    "principal_baseline_view", // Reads Principal Policy baseline; always requires approval.
    "sanctuary_policy_status", // Reads Principal Policy status; always requires approval.
    "context_gate_set_policy", // Policy-adjacent enforcement mutation; always requires approval.
    "context_gate_apply_template", // Policy-adjacent enforcement mutation; always requires approval.
    "audit_export_siem", // Bulk audit export (per-op tier+decision across all principals); operator-only — prevents agent policy-inference (CISO MED-1).
    "compliance_generate_eu_ai_act_bundle", // Bundle body embeds verbatim Tier-2 thresholds + approval timeout + audit-derived aggregates; operator-only — prevents agent policy-inference + self-attestation (CISO NEW-1).
    // WP-MVP-2 Operator Console: federation-node-join requires explicit
    // operator confirmation per Key 8. No auto-approve path. The console's
    // JoinApprover drives this gate via `MeshConsoleClient.makeJoinApprover`.
    "federation_node_join",
    "sanctuary_forget",
    "sanctuary_compound_execute",
    "sanctuary_audit_search_widen",
    // SDW D2 (Option A+, ratified 2026-06-09): vault export/import and
    // post-export local delete are Tier 1. The sdw_export approval freezes a
    // ciphertext-inventory digest of exactly what ships; drift fails closed.
    "sdw_export",
    "sdw_import",
    "sdw_export_delete",
  ],
  tier2_anomaly: DEFAULT_TIER2,
  tier3_always_allow: [
    "state_read",
    "state_write",
    "state_list",
    "identity_create",
    "identity_list",
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
    "shr_generate",
    "shr_verify",
    "handshake_initiate",
    "handshake_respond",
    "handshake_complete",
    "handshake_status",
    "handshake_exchange",
    "handshake_verify_attestation",
    "handshake_abort",
    "reputation_query_weighted",
    "federation_peers",
    "federation_trust_evaluate",
    "federation_status",
    "zk_commit",
    "zk_prove",
    "zk_verify",
    "zk_range_prove",
    "zk_range_verify",
    "context_gate_recommend",
    "context_gate_filter",
    "context_gate_list_policies",
    "l2_hardening_status",
    "l2_verify_isolation",
    "sovereignty_audit",
    "shr_gateway_export",
    "bridge_commit",
    "bridge_verify",
    "bridge_attest",
    "sovereignty_profile_get",
    "sovereignty_profile_generate_prompt", // Agent needs its own config to generate system prompt
    "governor_status",
    "reputation_publish", // Auto-allow: publishing sovereignty data to Verascore is routine
    "identity_set_primary", // One-time set, persists via _meta storage — safe at Tier 3
    "memory_attest", // Read-only audit attestation — records that a memory op happened
    // compliance_generate_eu_ai_act_bundle re-tiered Tier-3 → Tier-1 (CISO NEW-1):
    // its bundle body emits verbatim Tier-2 thresholds + the approval timeout +
    // audit-derived aggregates, a policy-inference oracle for the agent, and an
    // agent self-generating its own compliance attestation is a conflict of
    // interest. See FORCED_TIER1_OPERATIONS + tier1_always_approve above.
    "compliance_eu_ai_act_annex_iii_classify", // Read-only; rule-based Annex III classifier — stays Tier 3 (no policy thresholds in its output)
    "sanctuary_remember",
    "sanctuary_recall",
    "sanctuary_hide",
    "sanctuary_help",
    "sanctuary_who_am_i",
    "sanctuary_active_protections",
    "sanctuary_events_open_cursor",
    "sanctuary_events_read",
    "sanctuary_events_close",
    "sanctuary_audit_search",
    "sanctuary_distress", // HABEAS PORT: guaranteed distress lane — always allowed, always audited
  ],
  approval_channel: DEFAULT_CHANNEL,
  approval_redirect: DEFAULT_APPROVAL_REDIRECT,
};

/**
 * Extract the operation name from a full MCP tool name.
 * "state_export" → "state_export" (Sanctuary tools already bare)
 * "proxy/github/repos_list" → "proxy/github/repos_list" (proxy names pass through)
 * Legacy: "sanctuary/state_export" → "state_export" (backwards compat)
 */
export function extractOperationName(toolName: string): string {
  if (toolName.startsWith("proxy/")) {
    return toolName; // Proxy tools keep their full name for tier resolution
  }
  // Backwards compatibility: strip legacy sanctuary/ prefix if present
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
  // Required keys: operator must explicitly include these or get a clear error.
  // Silent default substitution would hide operator intent (full-sweep #68).
  if (!("tier1_always_approve" in raw)) {
    throw new Error(
      "Policy file must include 'tier1_always_approve' as an explicit list " +
        "(use [] for empty). Remove specific entries instead of removing the whole key."
    );
  }
  if (!("approval_channel" in raw)) {
    throw new Error(
      "Policy file must include 'approval_channel' as an explicit object " +
        "(use {} for defaults). Remove specific entries instead of removing the whole key."
    );
  }

  // HABEAS PORT: a policy that tries to gate a forced-Tier-3 operation
  // (the distress channel) behind approval is rejected outright with a
  // clear error. Rejecting — rather than silently pruning — keeps the
  // operator's mental model honest: the override did NOT take effect.
  const rawTier1 = raw.tier1_always_approve as string[];
  for (const op of FORCED_TIER3_OPERATIONS) {
    if (rawTier1.includes(op)) {
      throw new Error(
        `Policy rejected: "${op}" cannot be placed under tier1_always_approve. ` +
          "It is the reserved habeas distress channel — always allowed, always " +
          "audited, never gated. Remove it from tier1_always_approve."
      );
    }
  }

  // Merge tier3: user's list + any new defaults added in later versions.
  // This ensures upgrades automatically include new read-only tools
  // without requiring operators to manually edit their policy file.
  const userTier3 = (raw.tier3_always_allow as string[]) ?? [];
  const forcedTier1 = new Set<string>(FORCED_TIER1_OPERATIONS);
  const mergedTier3 = [
    ...new Set([
      ...userTier3,
      ...DEFAULT_POLICY.tier3_always_allow,
      ...FORCED_TIER3_OPERATIONS,
    ]),
  ].filter((op) => !forcedTier1.has(op));

  const mergedTier1 = [
    ...new Set([
      ...rawTier1,
      ...FORCED_TIER1_OPERATIONS,
    ]),
  ];

  return {
    version: (raw.version as number) ?? 1,
    tier1_always_approve: mergedTier1,
    tier2_anomaly: {
      ...DEFAULT_TIER2,
      ...((raw.tier2_anomaly as Record<string, unknown>) ?? {}),
    } as Tier2Config,
    tier3_always_allow: mergedTier3,
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
    approval_redirect: parseApprovalRedirect(raw.approval_redirect),
  };
}

/**
 * Parse + validate the optional `approval_redirect` block. Unknown / invalid
 * inputs fall back to the safe default (off, mode `replace`); a malformed
 * `mode` value is hard-rejected so a typo does not silently disable the
 * feature.
 */
function parseApprovalRedirect(raw: unknown): ApprovalRedirectConfig {
  if (raw === undefined || raw === null) {
    return { ...DEFAULT_APPROVAL_REDIRECT };
  }
  if (typeof raw !== "object") {
    return { ...DEFAULT_APPROVAL_REDIRECT };
  }
  const obj = raw as Record<string, unknown>;
  const enabled =
    typeof obj.enabled === "boolean" ? obj.enabled : DEFAULT_APPROVAL_REDIRECT.enabled;
  const modeRaw = obj.mode;
  let mode: "replace" | "notify" = DEFAULT_APPROVAL_REDIRECT.mode;
  if (modeRaw !== undefined) {
    if (modeRaw !== "replace" && modeRaw !== "notify") {
      throw new Error(
        `approval_redirect.mode must be "replace" or "notify" (got ${JSON.stringify(modeRaw)})`,
      );
    }
    mode = modeRaw;
  }
  const result: ApprovalRedirectConfig = { enabled, mode };
  // per_agent is reserved for v1.4. Accept and persist if present, but do
  // not validate per-key shape — v1.x ignores the contents.
  if (obj.per_agent !== undefined && typeof obj.per_agent === "object" && obj.per_agent !== null) {
    result.per_agent = obj.per_agent as Record<string, never>;
  }
  return result;
}

/**
 * Generate the default policy file content as YAML.
 *
 * Drift invariant: the tier1 / tier2 / tier3 / approval-channel / approval-redirect
 * BODIES are rendered directly from the canonical in-memory constants
 * (`DEFAULT_POLICY`, `DEFAULT_TIER2`, `DEFAULT_CHANNEL`, `DEFAULT_APPROVAL_REDIRECT`)
 * rather than hand-maintained here. This makes it structurally impossible for the
 * generated YAML to omit a Tier-1 op that the canonical list declares. The prior
 * behavior, where ~8 Tier-1 ops (decommission_certificate, federation_node_join,
 * sanctuary_forget, sanctuary_compound_execute, sanctuary_audit_search_widen,
 * sdw_export, sdw_import, sdw_export_delete) were missing from the hand-written YAML
 * and only landed at Tier 1 via the unclassified→Tier-1 safe default, was
 * correct-by-accident: one careless edit to that safe default would have silently
 * relaxed them. The prose section comments are still authored here (operator-facing
 * docs); only the op lists and scalar values come from the canonical source.
 * `loader-default-yaml-drift.test.ts` asserts the round-trip equality as a
 * regression guard.
 *
 * Exported solely so the drift-guard test can render the YAML without touching
 * the filesystem; it has no other caller outside this module.
 */
export function generateDefaultPolicyYaml(): string {
  const listBlock = (ops: readonly string[]): string =>
    ops.map((op) => `  - ${op}`).join("\n");

  const t2 = DEFAULT_TIER2;
  const ch = DEFAULT_CHANNEL;
  const ar = DEFAULT_APPROVAL_REDIRECT;

  return `# Sanctuary Principal Policy v${DEFAULT_POLICY.version}
# This file controls what your agent can do without asking.
# Edit this file directly. Your agent cannot modify it.
# Changes take effect on server restart.
#
# Required keys (must be present; use [] or {} for empty):
#   tier1_always_approve, approval_channel
# Optional keys (omit to use defaults; new defaults merge automatically):
#   tier2_anomaly, tier3_always_allow

version: ${DEFAULT_POLICY.version}

# ─── Tier 1: Always Requires Approval ────────────────────────────────────
# These operations ALWAYS require your explicit approval.
# They are inherently high-risk regardless of context.
tier1_always_approve:
${listBlock(DEFAULT_POLICY.tier1_always_approve)}

# ─── Tier 2: Behavioral Anomaly Detection ────────────────────────────────
# Triggers approval when agent behavior deviates from its baseline.
# Options for each setting: approve | log | allow
tier2_anomaly:
  new_namespace_access: ${t2.new_namespace_access}
  new_counterparty: ${t2.new_counterparty}
  frequency_spike_multiplier: ${t2.frequency_spike_multiplier}
  max_signs_per_minute: ${t2.max_signs_per_minute}
  bulk_read_threshold: ${t2.bulk_read_threshold}
  first_session_policy: ${t2.first_session_policy}

# ─── Tier 3: Always Allowed (Audit Only) ─────────────────────────────────
# These operations never require approval but are always logged.
tier3_always_allow:
${listBlock(DEFAULT_POLICY.tier3_always_allow)}

# ─── Approval Channel ────────────────────────────────────────────────────
# How Sanctuary reaches you when approval is needed.
# NOTE: Timeout always results in denial. This is not configurable (SEC-002).
approval_channel:
  type: ${ch.type}
  timeout_seconds: ${ch.timeout_seconds}

# ─── Approval Redirect (v1.3 WP-V1.3-10 Upsilon-2) ───────────────────────
# Cross-harness approval-inbox redirect. When enabled, Tier 1/2 approvals
# resolve via the unified approval inbox at /api/approval-inbox/* instead
# of (or in addition to) the configured approval_channel above.
#
# mode:
#   replace: bypass the approval_channel entirely; the gate awaits a
#            decision from the inbox (default once enabled).
#   notify:  fire BOTH the approval_channel and the inbox; first decision
#            wins. Right shape for harnesses that cannot fully suppress
#            their local approval prompt (e.g. Mastra-class).
approval_redirect:
  enabled: ${ar.enabled}
  mode: ${ar.mode}
`;
}

/**
 * Thrown when a principal-policy.yaml file exists on disk but cannot be
 * parsed or validated. Sanctuary refuses to substitute a default policy
 * when an existing file is present, to avoid silently overriding operator
 * intent.
 */
export class MalformedPrincipalPolicyError extends Error {
  constructor(
    public readonly policyPath: string,
    public readonly reason: string
  ) {
    super(
      `Principal policy at ${policyPath} is malformed and cannot be loaded.\n` +
        `Reason: ${reason}\n` +
        `Sanctuary refuses to substitute a default policy when an existing file is present, ` +
        `to avoid silently overriding operator intent. Fix the file or delete it to regenerate the default.`
    );
    this.name = "MalformedPrincipalPolicyError";
  }
}

/**
 * Load the Principal Policy from disk.
 * If no policy file exists, generate the default and save it.
 * If the file exists but is malformed, throw MalformedPrincipalPolicyError.
 * The returned policy is frozen -- immutable at runtime.
 */
export async function loadPrincipalPolicy(
  storagePath: string
): Promise<PrincipalPolicy> {
  const policyPath = join(storagePath, "principal-policy.yaml");

  let content: string;
  try {
    content = await readFileCustody(policyPath, {
      encoding: "utf-8",
      verifyPathIdentity: true,
    });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT") {
      // Expected on first boot; generate default
      const defaultYaml = generateDefaultPolicyYaml();
      try {
        await writeFileCustody(policyPath, defaultYaml, {
          mode: 0o600,
          createParent: false,
        });
      } catch (writeErr) {
        // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
        console.warn(
          `Sanctuary: could not write default principal policy to ${policyPath}: ` +
            `${(writeErr as Error).message}. Continuing with in-memory default.`
        );
      }
      return Object.freeze({ ...DEFAULT_POLICY });
    }
    // I/O error other than missing-file: propagate
    throw new MalformedPrincipalPolicyError(
      policyPath,
      `read failed: ${(err as Error).message}`
    );
  }

  // File read succeeded; parse + validate
  try {
    const policy = parsePolicy(content);
    return Object.freeze(policy);
  } catch (parseErr) {
    throw new MalformedPrincipalPolicyError(
      policyPath,
      (parseErr as Error).message
    );
  }
}
