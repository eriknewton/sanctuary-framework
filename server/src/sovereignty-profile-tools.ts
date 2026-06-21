/**
 * Sanctuary MCP Server — Sovereignty Profile Tools
 *
 * MCP tools for managing the Sovereignty Profile:
 * - sanctuary/sovereignty_profile_get — Read current profile (Tier 3)
 * - sanctuary/sovereignty_profile_update — Update feature toggles (Tier 1)
 * - sanctuary/sovereignty_profile_generate_prompt — Generate system prompt (Tier 3)
 *
 * All operations are audit-logged.
 */

import type { ToolDefinition } from "./router.js";
import { toolResult } from "./router.js";
import type { AuditLog } from "./operational/audit-log.js";
import type {
  SovereigntyProfile,
  SovereigntyProfileStore,
  SovereigntyProfileUpdate,
} from "./sovereignty-profile.js";
import { generateSystemPrompt } from "./system-prompt-generator.js";

function summarizeProfileForAgent(profile: SovereigntyProfile) {
  return {
    version: profile.version,
    features: profile.features,
    upstream_servers: (profile.upstream_servers ?? []).map((server) => ({
      name: server.name,
      enabled: server.enabled,
      transport_type: server.transport.type,
      destination_category: server.destination_category,
      privacy_policy_bound: server.privacy_policy_id !== undefined,
      privacy_identity_bound: server.privacy_identity_id !== undefined,
    })),
    updated_at: profile.updated_at,
  };
}

/**
 * Create the sovereignty profile MCP tools.
 */
export function createSovereigntyProfileTools(
  profileStore: SovereigntyProfileStore,
  auditLog: AuditLog
): { tools: ToolDefinition[] } {
  const tools: ToolDefinition[] = [
    // ── Get Profile ──────────────────────────────────────────────────
    {
      name: "sovereignty_profile_get",
      description:
        "Get the current Sovereignty Profile configuration. context_gating is wired " +
        "to the runtime enforcer; approval_gate is always enabled; other flags are " +
        "configuration/signaling and may not by themselves enable/disable the " +
        "underlying tools.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const profile = profileStore.get();

        void auditLog.append("l2", "sovereignty_profile_get", "system", {
          features_enabled: Object.entries(profile.features)
            .filter(([, v]) => v.enabled)
            .map(([k]) => k),
        });

        return toolResult({
          profile: summarizeProfileForAgent(profile),
          message:
            "Current Sovereignty Profile summary. Operator-only connection " +
            "details and tier policy are not returned through this agent-facing view.",
        });
      },
    },

    // ── Update Profile ───────────────────────────────────────────────
    {
      name: "sovereignty_profile_update",
      description:
        "Update Sovereignty Profile configuration. Updating context_gating " +
        "reconfigures the runtime context-gate enforcer; approval_gate remains " +
        "always enabled; other flags update profile/signaling state unless " +
        "separate runtime wiring is present.",
      inputSchema: {
        type: "object",
        properties: {
          audit_logging: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
            },
            description: "Toggle audit logging on/off",
          },
          injection_detection: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
              sensitivity: {
                type: "string",
                enum: ["low", "medium", "high"],
                description: "Detection sensitivity threshold",
              },
            },
            description: "Toggle injection detection and set sensitivity",
          },
          context_gating: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
              policy_id: {
                type: "string",
                description: "ID of the context-gating policy to use",
              },
            },
            description: "Toggle context gating and set active policy",
          },
          approval_gate: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
            },
            description: "Toggle approval gates on/off",
          },
          zk_proofs: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
            },
            description: "Toggle zero-knowledge proofs on/off",
          },
        },
      },
      handler: async (args) => {
        const updates: SovereigntyProfileUpdate = {};

        if (args.audit_logging !== undefined) {
          updates.audit_logging = args.audit_logging as { enabled?: boolean };
        }
        if (args.injection_detection !== undefined) {
          updates.injection_detection = args.injection_detection as {
            enabled?: boolean;
            sensitivity?: "low" | "medium" | "high";
          };
        }
        if (args.context_gating !== undefined) {
          updates.context_gating = args.context_gating as {
            enabled?: boolean;
            policy_id?: string;
          };
        }
        if (args.approval_gate !== undefined) {
          updates.approval_gate = args.approval_gate as { enabled?: true };
        }
        if (args.zk_proofs !== undefined) {
          updates.zk_proofs = args.zk_proofs as { enabled?: boolean };
        }

        const updated = await profileStore.update(updates);

        await auditLog.appendCritical({
          layer: "l2",
          operation: "sovereignty_profile_update",
          identity_id: "system",
          result: "success",
          details: {
            changes: updates,
            features_enabled: Object.entries(updated.features)
              .filter(([, v]) => v.enabled)
              .map(([k]) => k),
          },
        });

        return toolResult({
          profile: updated,
          message: "Sovereignty Profile updated. Changes take effect immediately.",
        });
      },
    },

    // ── Generate System Prompt ───────────────────────────────────────
    {
      name: "sovereignty_profile_generate_prompt",
      description:
        "Generate a system prompt snippet based on the active Sovereignty " +
        "Profile. The snippet instructs an agent on which Sanctuary features " +
        "are active and how to use them. Copy and paste this into your " +
        "agent's system configuration.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const profile = profileStore.get();
        const prompt = generateSystemPrompt(profile);

        void auditLog.append("l2", "sovereignty_profile_generate_prompt", "system", {
          features_enabled: Object.entries(profile.features)
            .filter(([, v]) => v.enabled)
            .map(([k]) => k),
        });

        return toolResult({
          system_prompt: prompt,
          token_estimate: Math.ceil(prompt.length / 4),
          message:
            "Copy the system_prompt text above and paste it into your agent's " +
            "system configuration. It will update dynamically as you toggle features.",
        });
      },
    },
  ];

  return { tools };
}
