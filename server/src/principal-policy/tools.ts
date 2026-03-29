/**
 * Sanctuary MCP Server — Principal Policy MCP Tools
 *
 * Read-only tools that let the agent (and human) inspect the current
 * Principal Policy and behavioral baseline. These are Tier 3 operations —
 * always allowed, audit-logged, and cannot modify the policy or baseline.
 *
 * Security invariant:
 * - These tools are strictly read-only.
 * - No tool can modify the Principal Policy (it's frozen at startup).
 * - No tool can directly modify the behavioral baseline.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { PrincipalPolicy } from "./types.js";
import type { BaselineTracker } from "./baseline.js";
import type { AuditLog } from "../l2-operational/audit-log.js";

export function createPrincipalPolicyTools(
  policy: PrincipalPolicy,
  baseline: BaselineTracker,
  auditLog: AuditLog
): ToolDefinition[] {
  return [
    {
      name: "sanctuary/principal_policy_view",
      description:
        "View the current Principal Policy — the human-controlled rules " +
        "governing what operations require approval. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          include_defaults: {
            type: "boolean",
            description: "Include tier3_always_allow list (can be long)",
            default: false,
          },
        },
      },
      handler: async (args) => {
        const includeDefaults = args.include_defaults as boolean ?? false;

        const view: Record<string, unknown> = {
          version: policy.version,
          tier1_always_approve: policy.tier1_always_approve,
          tier2_anomaly: policy.tier2_anomaly,
          approval_channel: {
            type: policy.approval_channel.type,
            timeout_seconds: policy.approval_channel.timeout_seconds,
            auto_deny: true, // SEC-002: hardcoded, not configurable
          },
        };

        if (includeDefaults) {
          view.tier3_always_allow = policy.tier3_always_allow;
        } else {
          view.tier3_always_allow_count = policy.tier3_always_allow.length;
          view.note =
            "Pass include_defaults: true to see the full tier3_always_allow list";
        }

        auditLog.append("l2", "principal_policy_view", "system", {
          include_defaults: includeDefaults,
        });

        return toolResult(view);
      },
    },

    {
      name: "sanctuary/principal_baseline_view",
      description:
        "View the current behavioral baseline — the session profile used " +
        "for anomaly detection. Shows known namespaces, counterparties, " +
        "and tool call counts. Read-only.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const profile = baseline.getProfile();

        auditLog.append("l2", "principal_baseline_view", "system");

        return toolResult({
          is_first_session: profile.is_first_session,
          session_started_at: profile.started_at,
          known_namespaces: profile.known_namespaces,
          known_counterparties: profile.known_counterparties,
          tool_call_counts: profile.tool_call_counts,
          last_saved: profile.saved_at ?? "not yet saved",
        });
      },
    },
  ];
}
