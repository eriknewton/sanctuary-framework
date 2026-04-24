/**
 * Sanctuary MCP Server — L2 Context Gating Tools
 *
 * MCP tools for configuring and applying context-gating policies.
 * These tools let agents control what context flows to remote providers
 * (LLM APIs, tool APIs, logging services) during outbound calls.
 *
 * Tools:
 * - context_gate_set_policy — Define a context-gating policy
 * - context_gate_apply_template — Apply a starter template
 * - context_gate_filter — Filter context through a policy
 * - context_gate_recommend — Analyze context and recommend a policy
 * - context_gate_list_policies — List all context-gating policies
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
  MAX_POLICY_RULES,
  MAX_PATTERNS_PER_ARRAY,
  MAX_CONTEXT_FIELDS,
  type ContextGateRule,
  type ProviderCategory,
} from "./context-gate.js";
import {
  TEMPLATES,
  listTemplateIds,
  getTemplate,
} from "./context-gate-templates.js";
import { recommendPolicy } from "./context-gate-recommend.js";
import {
  ContextGateEnforcer,
  type EnforcerConfig,
} from "./context-gate-enforcer.js";
import { applyLocalPrivacyFilter } from "./privacy-filter.js";

/**
 * Create the context-gating MCP tools.
 */
export function createContextGateTools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  auditLog: AuditLog
): {
  tools: ToolDefinition[];
  policyStore: ContextGatePolicyStore;
  enforcer: ContextGateEnforcer;
} {
  const policyStore = new ContextGatePolicyStore(storage, masterKey);

  // Create the automatic enforcer
  const enforcerConfig: EnforcerConfig = {
    enabled: false, // Off by default; agents must explicitly enable it
    bypass_prefixes: ["*"], // Skip all Sanctuary-internal tools; only proxy/ tools get filtered
    log_only: false, // Filter immediately
    on_deny: "block", // Block requests with denied fields
  };
  const enforcer = new ContextGateEnforcer(policyStore, auditLog, enforcerConfig);

  const tools: ToolDefinition[] = [
    // ── Set Policy ──────────────────────────────────────────────────
    {
      name: "context_gate_set_policy",
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

        // Validate rule count
        if (!Array.isArray(rawRules)) {
          return toolResult({ error: "invalid_rules", message: "rules must be an array" });
        }
        if (rawRules.length > MAX_POLICY_RULES) {
          return toolResult({
            error: "too_many_rules",
            message: `Policy has ${rawRules.length} rules, exceeding limit of ${MAX_POLICY_RULES}`,
          });
        }

        // Validate and normalize rules
        const rules: ContextGateRule[] = [];
        for (const r of rawRules) {
          const allow = Array.isArray(r.allow) ? (r.allow as string[]) : [];
          const redact = Array.isArray(r.redact) ? (r.redact as string[]) : [];
          const hash = Array.isArray(r.hash) ? (r.hash as string[]) : [];
          const summarize = Array.isArray(r.summarize) ? (r.summarize as string[]) : [];

          for (const [name, arr] of [["allow", allow], ["redact", redact], ["hash", hash], ["summarize", summarize]] as const) {
            if (arr.length > MAX_PATTERNS_PER_ARRAY) {
              return toolResult({
                error: "too_many_patterns",
                message: `Rule ${name} array has ${arr.length} patterns, exceeding limit of ${MAX_PATTERNS_PER_ARRAY}`,
              });
            }
          }

          rules.push({
            provider: (r.provider as ProviderCategory | "*") ?? "*",
            allow,
            redact,
            hash,
            summarize,
          });
        }

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
            "Context-gating policy created. Use context_gate_filter " +
            "to apply this policy before making outbound calls.",
        });
      },
    },

    // ── Apply Template ───────────────────────────────────────────────
    {
      name: "context_gate_apply_template",
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
            "Template applied. Use context_gate_filter with this " +
            "policy_id to filter context before outbound calls. " +
            "Customize rules with context_gate_set_policy if needed.",
        });
      },
    },

    // ── Recommend Policy ────────────────────────────────────────────
    {
      name: "context_gate_recommend",
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

        // Validate context size
        const contextKeys = Object.keys(context);
        if (contextKeys.length > MAX_CONTEXT_FIELDS) {
          return toolResult({
            error: "context_too_large",
            message: `Context has ${contextKeys.length} fields, exceeding limit of ${MAX_CONTEXT_FIELDS}`,
          });
        }

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
            "apply them directly with context_gate_set_policy using " +
            "the recommended_rules. Or start with a template via " +
            "context_gate_apply_template and customize from there.",
          available_templates: listTemplateIds().map((id) => {
            const t = TEMPLATES[id]!;
            return { id, name: t.name, description: t.description };
          }),
        });
      },
    },

    // ── Filter Context ──────────────────────────────────────────────
    {
      name: "context_gate_filter",
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

        // Validate context size
        const contextKeys = Object.keys(context);
        if (contextKeys.length > MAX_CONTEXT_FIELDS) {
          return toolResult({
            error: "context_too_large",
            message: `Context has ${contextKeys.length} fields, exceeding limit of ${MAX_CONTEXT_FIELDS}`,
          });
        }

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

        // Build the filtered context that is safe to send. Field-level policy
        // runs first; local span filtering then catches PII/secrets inside
        // otherwise-allowed strings.
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
        const privacyFiltered = applyLocalPrivacyFilter(safeContext);

        auditLog.append("l2", "context_gate_filter", policy.identity_id ?? "system", {
          policy_id: policyId,
          provider,
          fields_total: Object.keys(context).length,
          fields_allowed: result.fields_allowed,
          fields_redacted: result.fields_redacted,
          fields_hashed: result.fields_hashed,
          fields_summarized: result.fields_summarized,
          privacy_findings: privacyFiltered.findings.length,
          privacy_classes: [...new Set(privacyFiltered.findings.map((f) => f.class))],
          original_context_hash: result.original_context_hash,
          filtered_context_hash: result.filtered_context_hash,
        });

        return toolResult({
          blocked: false,
          safe_context: privacyFiltered.value,
          summary: {
            total_fields: Object.keys(context).length,
            allowed: result.fields_allowed,
            redacted: result.fields_redacted,
            hashed: result.fields_hashed,
            summarized: result.fields_summarized,
            privacy_filtered_spans: privacyFiltered.findings.length,
          },
          decisions: result.decisions,
          privacy_filter: {
            findings: privacyFiltered.findings,
          },
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
      name: "context_gate_list_policies",
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
                "context_gate_set_policy to create one."
              : `${policies.length} context-gating ${policies.length === 1 ? "policy" : "policies"} configured.`,
        });
      },
    },

    // ── Enforcer Status ─────────────────────────────────────────────────
    {
      name: "context_gate_enforcer_status",
      description:
        "Get the status of the automatic context gate enforcer, including " +
        "enabled/disabled state, log_only mode, active policy, and statistics. " +
        "The enforcer automatically filters tool arguments when enabled. " +
        "Use this to monitor what the enforcer has been filtering.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const status = enforcer.getStatus();

        auditLog.append(
          "l2",
          "context_gate_enforcer_status_query",
          "system",
          {
            enabled: status.enabled,
            log_only: status.log_only,
            default_policy_id: status.default_policy_id,
          }
        );

        return toolResult({
          enforcer_status: status,
          description:
            "The enforcer is " +
            (status.enabled ? "enabled" : "disabled") +
            ". " +
            (status.log_only
              ? "Currently in log_only mode — filtering is logged but not applied."
              : "Filtering is actively applied to tool arguments."),
          guidance:
            status.stats.calls_inspected > 0
              ? `Over ${status.stats.calls_inspected} tool calls, ` +
                `${status.stats.fields_redacted} sensitive fields were redacted. ` +
                `Use context_gate_enforcer_configure to adjust settings.`
              : "No tool calls have been inspected yet.",
        });
      },
    },

    // ── Enforcer Configuration ──────────────────────────────────────────
    {
      name: "context_gate_enforcer_configure",
      description:
        "Configure the automatic context gate enforcer. Control whether it " +
        "filters tool arguments, toggle log_only mode for gradual rollout, " +
        "set the active policy, and choose what to do when denied fields are " +
        "encountered (block the request or redact the field). " +
        "Use this to enable automatic context protection.",
      inputSchema: {
        type: "object",
        properties: {
          enabled: {
            type: "boolean",
            description:
              "Enable or disable the automatic enforcer. When disabled, " +
              "no filtering occurs. Default: leave unchanged.",
          },
          log_only: {
            type: "boolean",
            description:
              "Enable log_only mode: filter decisions are logged but original " +
              "args are passed to handlers. Useful for monitoring before " +
              "enabling actual filtering. Default: leave unchanged.",
          },
          default_policy_id: {
            type: "string",
            description:
              "Set the default context-gating policy to use for filtering. " +
              "If not set, the enforcer uses built-in sensitive field patterns. " +
              "Default: leave unchanged.",
          },
          on_deny: {
            type: "string",
            enum: ["block", "redact"],
            description:
              "Action to take when a field triggers the deny action: " +
              "'block' returns an error and prevents the call, " +
              "'redact' replaces the denied field with [REDACTED] and continues. " +
              "Default: leave unchanged.",
          },
          reset_stats: {
            type: "boolean",
            description:
              "Reset the enforcer statistics counters to zero. Default: false.",
          },
        },
      },
      handler: async (args) => {
        const changes: Record<string, unknown> = {};

        if (args.enabled !== undefined) {
          enforcer.setEnabled(args.enabled as boolean);
          changes.enabled = args.enabled;
        }

        if (args.log_only !== undefined) {
          enforcer.setLogOnly(args.log_only as boolean);
          changes.log_only = args.log_only;
        }

        if (args.default_policy_id !== undefined) {
          const policyId = args.default_policy_id as string;
          const policy = await policyStore.get(policyId);
          if (!policy) {
            return toolResult({
              error: "policy_not_found",
              message: `No context-gating policy found with ID "${policyId}"`,
            });
          }
          enforcer.setDefaultPolicy(policyId);
          changes.default_policy_id = policyId;
        }

        if (args.on_deny !== undefined) {
          const onDeny = args.on_deny as "block" | "redact";
          if (onDeny !== "block" && onDeny !== "redact") {
            return toolResult({
              error: "invalid_on_deny",
              message: "on_deny must be 'block' or 'redact'",
            });
          }
          enforcerConfig.on_deny = onDeny;
          changes.on_deny = onDeny;
        }

        if (args.reset_stats === true) {
          enforcer.resetStats();
          changes.reset_stats = true;
        }

        const newStatus = enforcer.getStatus();

        auditLog.append(
          "l2",
          "context_gate_enforcer_configure",
          "system",
          {
            changes,
            new_status: newStatus,
          }
        );

        return toolResult({
          configured: true,
          changes,
          new_status: newStatus,
          message:
            Object.keys(changes).length > 0
              ? "Enforcer configuration updated."
              : "No changes made (no configuration parameters provided).",
        });
      },
    },
  ];

  return { tools, policyStore, enforcer };
}
