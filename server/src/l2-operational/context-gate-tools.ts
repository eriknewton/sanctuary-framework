/**
 * Sanctuary MCP Server — L2 Context Gating Tools
 *
 * MCP tools for configuring and applying context-gating policies.
 * These tools let agents control what context flows to remote providers
 * (LLM APIs, tool APIs, logging services) during outbound calls.
 *
 * Tools:
 * - sanctuary/context_gate_set_policy — Define a context-gating policy
 * - sanctuary/context_gate_apply_template — Apply a starter template
 * - sanctuary/context_gate_filter — Filter context through a policy
 * - sanctuary/context_gate_recommend — Analyze context and recommend a policy
 * - sanctuary/context_gate_list_policies — List all context-gating policies
 *
 * All operations are audit-logged. Policies are encrypted at rest.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "./audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import {
  ContextGatePolicyStore,
  filterContext,
  type ContextGateRule,
  type ProviderCategory,
} from "./context-gate.js";
import {
  TEMPLATES,
  listTemplateIds,
  getTemplate,
} from "./context-gate-templates.js";
import { recommendPolicy } from "./context-gate-recommend.js";

/**
 * Create the context-gating MCP tools.
 */
export function createContextGateTools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  auditLog: AuditLog
): { tools: ToolDefinition[]; policyStore: ContextGatePolicyStore } {
  const policyStore = new ContextGatePolicyStore(storage, masterKey);

  const tools: ToolDefinition[] = [
    // ── Set Policy ──────────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_set_policy",
      description:
        "Create a context-gating policy that controls what information flows to " +
        "remote providers (LLM APIs, tool APIs, logging services). " +
        "Each rule specifies a provider category and which context fields to " +
        "allow, redact, hash, or flag for summarization. " +
        "Redact rules take absolute priority — if a field is in both 'allow' and " +
        "'redact', it is redacted. Default action applies to any field not " +
        "mentioned in any rule. " +
        "Use this to prevent your full agent context from being sent to remote " +
        "LLM providers during inference calls.",
      inputSchema: {
        type: "object",
        properties: {
          policy_name: {
            type: "string",
            description:
              "Human-readable name for this policy (e.g., 'inference-minimal', " +
              "'tool-api-strict')",
          },
          rules: {
            type: "array",
            description:
              "Array of rules. Each rule has: provider (inference|tool-api|logging|" +
              "analytics|peer-agent|custom|*), allow (fields to pass through), " +
              "redact (fields to remove — highest priority), hash (fields to " +
              "replace with SHA-256 hash), summarize (fields to flag for compression).",
            items: {
              type: "object",
              properties: {
                provider: {
                  type: "string",
                  description:
                    "Provider category: inference, tool-api, logging, analytics, " +
                    "peer-agent, custom, or * for all",
                },
                allow: {
                  type: "array",
                  items: { type: "string" },
                  description:
                    "Fields/patterns to allow through (e.g., 'task_description', " +
                    "'current_query', 'tool_*')",
                },
                redact: {
                  type: "array",
                  items: { type: "string" },
                  description:
                    "Fields/patterns to redact (e.g., 'conversation_history', " +
                    "'secret_*', '*_pii'). Takes absolute priority.",
                },
                hash: {
                  type: "array",
                  items: { type: "string" },
                  description:
                    "Fields/patterns to replace with SHA-256 hash (e.g., 'user_id', " +
                    "'session_id')",
                },
                summarize: {
                  type: "array",
                  items: { type: "string" },
                  description:
                    "Fields/patterns to flag for summarization (advisory — agent " +
                    "should compress these before sending)",
                },
              },
              required: ["provider", "allow", "redact"],
            },
          },
          default_action: {
            type: "string",
            enum: ["redact", "deny"],
            description:
              "Action for fields not matched by any rule. 'redact' removes the " +
              "field value; 'deny' blocks the entire request. Default: 'redact'.",
          },
          identity_id: {
            type: "string",
            description: "Bind this policy to a specific identity (optional)",
          },
        },
        required: ["policy_name", "rules"],
      },
      handler: async (args) => {
        const policyName = args.policy_name as string;
        const rawRules = args.rules as Array<Record<string, unknown>>;
        const defaultAction = (args.default_action as "redact" | "deny") ?? "redact";
        const identityId = args.identity_id as string | undefined;

        // Validate and normalize rules
        const rules: ContextGateRule[] = rawRules.map((r) => ({
          provider: (r.provider as ProviderCategory | "*") ?? "*",
          allow: (r.allow as string[]) ?? [],
          redact: (r.redact as string[]) ?? [],
          hash: (r.hash as string[]) ?? [],
          summarize: (r.summarize as string[]) ?? [],
        }));

        const policy = await policyStore.create(
          policyName,
          rules,
          defaultAction,
          identityId
        );

        auditLog.append("l2", "context_gate_set_policy", identityId ?? "system", {
          policy_id: policy.policy_id,
          policy_name: policyName,
          rule_count: rules.length,
          default_action: defaultAction,
        });

        return toolResult({
          policy_id: policy.policy_id,
          policy_name: policy.policy_name,
          rules: policy.rules,
          default_action: policy.default_action,
          created_at: policy.created_at,
          message:
            "Context-gating policy created. Use sanctuary/context_gate_filter " +
            "to apply this policy before making outbound calls.",
        });
      },
    },

    // ── Apply Template ───────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_apply_template",
      description:
        "Apply a starter context-gating template. Available templates: " +
        "inference-minimal (strictest — only task and query pass through), " +
        "inference-standard (balanced — adds tool results, summarizes history), " +
        "logging-strict (redacts all content for telemetry services), " +
        "tool-api-scoped (allows tool parameters, redacts agent state). " +
        "Templates are starting points — customize after applying.",
      inputSchema: {
        type: "object",
        properties: {
          template_id: {
            type: "string",
            description:
              "Template to apply: inference-minimal, inference-standard, " +
              "logging-strict, or tool-api-scoped",
          },
          identity_id: {
            type: "string",
            description: "Bind this policy to a specific identity (optional)",
          },
        },
        required: ["template_id"],
      },
      handler: async (args) => {
        const templateId = args.template_id as string;
        const identityId = args.identity_id as string | undefined;

        const template = getTemplate(templateId);
        if (!template) {
          return toolResult({
            error: "template_not_found",
            message: `Unknown template "${templateId}"`,
            available_templates: listTemplateIds().map((id) => {
              const t = TEMPLATES[id]!;
              return { id, name: t.name, description: t.description };
            }),
          });
        }

        const policy = await policyStore.create(
          template.name,
          template.rules,
          template.default_action,
          identityId
        );

        auditLog.append("l2", "context_gate_apply_template", identityId ?? "system", {
          policy_id: policy.policy_id,
          template_id: templateId,
        });

        return toolResult({
          policy_id: policy.policy_id,
          template_applied: templateId,
          policy_name: template.name,
          description: template.description,
          use_when: template.use_when,
          rules: policy.rules,
          default_action: policy.default_action,
          created_at: policy.created_at,
          message:
            "Template applied. Use sanctuary/context_gate_filter with this " +
            "policy_id to filter context before outbound calls. " +
            "Customize rules with sanctuary/context_gate_set_policy if needed.",
        });
      },
    },

    // ── Recommend Policy ────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_recommend",
      description:
        "Analyze a sample context object and recommend a context-gating " +
        "policy based on field name heuristics. Classifies each field as " +
        "allow, redact, hash, or summarize with confidence levels. " +
        "Returns a ready-to-apply rule set. When in doubt, recommends " +
        "redact (conservative). Review the recommendations before applying.",
      inputSchema: {
        type: "object",
        properties: {
          context: {
            type: "object",
            description:
              "A sample context object to analyze. Each top-level key " +
              "will be classified. Values are inspected for size warnings " +
              "but not stored.",
          },
          provider: {
            type: "string",
            description:
              "Provider category to generate rules for. Default: 'inference'.",
          },
        },
        required: ["context"],
      },
      handler: async (args) => {
        const context = args.context as Record<string, unknown>;
        const provider = (args.provider as string) ?? "inference";

        const recommendation = recommendPolicy(context, provider);

        auditLog.append("l2", "context_gate_recommend", "system", {
          provider,
          fields_analyzed: recommendation.summary.total_fields,
          fields_allow: recommendation.summary.allow,
          fields_redact: recommendation.summary.redact,
          fields_hash: recommendation.summary.hash,
          fields_summarize: recommendation.summary.summarize,
        });

        return toolResult({
          ...recommendation,
          next_steps:
            "Review the classifications above. If they look correct, you can " +
            "apply them directly with sanctuary/context_gate_set_policy using " +
            "the recommended_rules. Or start with a template via " +
            "sanctuary/context_gate_apply_template and customize from there.",
          available_templates: listTemplateIds().map((id) => {
            const t = TEMPLATES[id]!;
            return { id, name: t.name, description: t.description };
          }),
        });
      },
    },

    // ── Filter Context ──────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_filter",
      description:
        "Filter agent context through a gating policy before sending to a " +
        "remote provider. Returns per-field decisions (allow, redact, hash, " +
        "summarize) and content hashes for the audit trail. " +
        "Call this BEFORE making any outbound API call to ensure you are only " +
        "sending the minimum necessary context. " +
        "The filtered output tells you exactly what can be sent safely.",
      inputSchema: {
        type: "object",
        properties: {
          policy_id: {
            type: "string",
            description: "ID of the context-gating policy to apply",
          },
          provider: {
            type: "string",
            description:
              "Provider category for this call: inference, tool-api, logging, " +
              "analytics, peer-agent, or custom",
          },
          context: {
            type: "object",
            description:
              "The context object to filter. Each top-level key is evaluated " +
              "against the policy. Example keys: task_description, " +
              "conversation_history, user_preferences, api_keys, memory, " +
              "internal_reasoning",
          },
        },
        required: ["policy_id", "provider", "context"],
      },
      handler: async (args) => {
        const policyId = args.policy_id as string;
        const provider = args.provider as ProviderCategory | string;
        const context = args.context as Record<string, unknown>;

        const policy = await policyStore.get(policyId);
        if (!policy) {
          return toolResult({
            error: "policy_not_found",
            message: `No context-gating policy found with ID "${policyId}"`,
          });
        }

        const result = filterContext(policy, provider, context);

        // Check for any denied fields — if so, the entire request should be blocked
        const deniedFields = result.decisions.filter((d) => d.action === "deny");
        if (deniedFields.length > 0) {
          auditLog.append("l2", "context_gate_deny", policy.identity_id ?? "system", {
            policy_id: policyId,
            provider,
            denied_fields: deniedFields.map((d) => d.field),
            original_context_hash: result.original_context_hash,
          });

          return toolResult({
            blocked: true,
            reason: "Context contains fields that trigger deny action",
            denied_fields: deniedFields.map((d) => ({
              field: d.field,
              reason: d.reason,
            })),
            recommendation:
              "Remove the denied fields from context before retrying, or " +
              "update the policy to handle these fields differently.",
          });
        }

        // Build the filtered context that is safe to send
        const safeContext: Record<string, unknown> = {};
        for (const decision of result.decisions) {
          switch (decision.action) {
            case "allow":
              safeContext[decision.field] = context[decision.field];
              break;
            case "redact":
              // Field excluded from safe context
              break;
            case "hash":
              safeContext[decision.field] = decision.hash_value;
              break;
            case "summarize":
              // Include but mark for summarization
              safeContext[decision.field] = context[decision.field];
              break;
          }
        }

        auditLog.append("l2", "context_gate_filter", policy.identity_id ?? "system", {
          policy_id: policyId,
          provider,
          fields_total: Object.keys(context).length,
          fields_allowed: result.fields_allowed,
          fields_redacted: result.fields_redacted,
          fields_hashed: result.fields_hashed,
          fields_summarized: result.fields_summarized,
          original_context_hash: result.original_context_hash,
          filtered_context_hash: result.filtered_context_hash,
        });

        return toolResult({
          blocked: false,
          safe_context: safeContext,
          summary: {
            total_fields: Object.keys(context).length,
            allowed: result.fields_allowed,
            redacted: result.fields_redacted,
            hashed: result.fields_hashed,
            summarized: result.fields_summarized,
          },
          decisions: result.decisions,
          audit: {
            original_context_hash: result.original_context_hash,
            filtered_context_hash: result.filtered_context_hash,
            filtered_at: result.filtered_at,
          },
          guidance:
            result.fields_summarized > 0
              ? "Some fields are marked for summarization. Consider compressing " +
                "them before sending to reduce context size and information exposure."
              : undefined,
        });
      },
    },

    // ── List Policies ───────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_list_policies",
      description:
        "List all configured context-gating policies. Returns policy IDs, " +
        "names, rule summaries, and default actions.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const policies = await policyStore.list();

        auditLog.append("l2", "context_gate_list_policies", "system", {
          policy_count: policies.length,
        });

        return toolResult({
          policies: policies.map((p) => ({
            policy_id: p.policy_id,
            policy_name: p.policy_name,
            rule_count: p.rules.length,
            providers: p.rules.map((r) => r.provider),
            default_action: p.default_action,
            identity_id: p.identity_id ?? null,
            created_at: p.created_at,
            updated_at: p.updated_at,
          })),
          count: policies.length,
          message:
            policies.length === 0
              ? "No context-gating policies configured. Use " +
                "sanctuary/context_gate_set_policy to create one."
              : `${policies.length} context-gating ${policies.length === 1 ? "policy" : "policies"} configured.`,
        });
      },
    },
  ];

  return { tools, policyStore };
}
