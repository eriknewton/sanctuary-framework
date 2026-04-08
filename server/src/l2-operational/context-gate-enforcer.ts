/**
 * Sanctuary MCP Server — L2 Context Gating: Automatic Enforcer
 *
 * The context gate enforcer wraps tool handlers to automatically filter
 * their arguments before execution. Unlike context_gate_filter (which agents
 * call voluntarily), the enforcer runs automatically on every tool call
 * when enabled.
 *
 * This enforces minimum-necessary-context by default and makes bypassing
 * context protection explicit (requires reconfiguration).
 *
 * Security invariants:
 * - The enforcer wraps every tool handler when enabled
 * - Filtering decisions are audit-logged
 * - Default action on missing policy: fallback to built-in sensitive patterns
 * - Denied fields block the entire request (with logged reason)
 * - Redacted fields are stripped from tool arguments
 * - log_only mode logs what would be filtered but passes original args
 */

import type { ToolHandler } from "../router.js";
import type { ContextGatePolicyStore } from "./context-gate.js";
import { filterContext, matchesPattern, type ContextGatePolicy } from "./context-gate.js";
import type { AuditLog } from "./audit-log.js";
import { stringToBytes } from "../core/encoding.js";
import { hashToString } from "../core/hashing.js";
import { toolResult } from "../router.js";

// ── Configuration ───────────────────────────────────────────────────────

export interface EnforcerConfig {
  /** Enable/disable automatic filtering (default: true) */
  enabled: boolean;
  /** Policy ID to use when no specific one is set */
  default_policy_id?: string;
  /** Tool name prefixes to skip filtering (e.g., ["*"] to skip all system tools) */
  bypass_prefixes: string[];
  /** Log but don't filter — for gradual rollout (default: false) */
  log_only: boolean;
  /** What to do when a field triggers deny action: "block" or "redact" */
  on_deny: "block" | "redact";
}

// ── Built-in Sensitive Field Patterns ───────────────────────────────────

/**
 * Built-in patterns for sensitive fields.
 * Used as fallback when no explicit policy is configured.
 * These are applied even without a policy to provide baseline protection.
 */
const BUILTIN_SENSITIVE_PATTERNS = [
  "*_key",
  "*_token",
  "*_secret",
  "api_key",
  "access_token",
  "refresh_token",
  "password",
  "passwd",
  "credential*",
  "auth_*",
  "ssn",
  "social_security*",
  "tax_id*",
  "credit_card*",
  "card_number*",
  "cvv",
  "cvc",
  "private_key",
  "secret_key",
  "master_key",
];

// ── Enforcer Status ─────────────────────────────────────────────────────

export interface EnforcerStatus {
  enabled: boolean;
  log_only: boolean;
  default_policy_id: string | null;
  stats: {
    calls_inspected: number;
    calls_bypassed: number;
    fields_redacted: number;
    fields_hashed: number;
    fields_blocked: number;
    calls_blocked: number;
  };
}

// ── Enforcer Implementation ─────────────────────────────────────────────

export class ContextGateEnforcer {
  private policyStore: ContextGatePolicyStore;
  private auditLog: AuditLog;
  private config: EnforcerConfig;
  private stats = {
    calls_inspected: 0,
    calls_bypassed: 0,
    fields_redacted: 0,
    fields_hashed: 0,
    fields_blocked: 0,
    calls_blocked: 0,
  };

  constructor(
    policyStore: ContextGatePolicyStore,
    auditLog: AuditLog,
    config: EnforcerConfig
  ) {
    this.policyStore = policyStore;
    this.auditLog = auditLog;
    this.config = config;
  }

  /**
   * Wrap a tool handler to apply automatic context gating.
   *
   * The wrapped handler:
   * 1. Checks if tool should be filtered (based on bypass_prefixes)
   * 2. If not filtering, calls original handler directly
   * 3. If filtering:
   *    a. Gets the active policy or falls back to built-in patterns
   *    b. Calls filterContext() with tool arguments
   *    c. If any field triggered "deny" and on_deny is "block", returns error
   *    d. If on_deny is "redact", replaces denied fields with "[REDACTED]"
   *    e. Calls original handler with filtered arguments
   *    f. Logs the filtering decision
   * 4. In log_only mode: runs filter, logs what would happen, passes original args
   */
  wrapHandler(toolName: string, originalHandler: ToolHandler): ToolHandler {
    return async (args: Record<string, unknown>) => {
      // If enforcer is disabled, pass through
      if (!this.config.enabled) {
        return originalHandler(args);
      }

      // Check if tool should be filtered
      if (!this.shouldFilter(toolName)) {
        this.stats.calls_bypassed++;
        return originalHandler(args);
      }

      this.stats.calls_inspected++;

      // Get the active policy or null if none exists
      const policy = this.config.default_policy_id
        ? await this.policyStore.get(this.config.default_policy_id)
        : null;

      if (policy) {
        // Use explicit policy
        return this.filterWithPolicy(
          toolName,
          args,
          originalHandler,
          policy
        );
      } else {
        // Fall back to built-in sensitive pattern matching
        return this.filterWithBuiltinPatterns(
          toolName,
          args,
          originalHandler
        );
      }
    };
  }

  /**
   * Filter tool arguments using an explicit policy.
   */
  private async filterWithPolicy(
    toolName: string,
    args: Record<string, unknown>,
    originalHandler: ToolHandler,
    policy: ContextGatePolicy
  ): Promise<{ content: Array<{ type: "text"; text: string }> }> {
    // Provider category for the tool (default to "tool-api")
    const provider = this.extractProviderCategory(toolName);

    // Filter the context
    const result = filterContext(policy, provider, args);

    // Check for denied fields
    const deniedFields = result.decisions.filter((d) => d.action === "deny");

    if (deniedFields.length > 0) {
      if (this.config.on_deny === "block") {
        this.stats.calls_blocked++;
        this.auditLog.append(
          "l2",
          "context_gate_enforcer_block",
          "system",
          {
            tool_name: toolName,
            policy_id: policy.policy_id,
            provider,
            denied_fields: deniedFields.map((d) => d.field),
            original_context_hash: result.original_context_hash,
          }
        );

        return toolResult({
          error: "context_gating_blocked",
          message: "Tool call contains fields that trigger deny action",
          tool: toolName,
          denied_fields: deniedFields.map((d) => d.field),
          recommendation:
            "Remove the denied fields from context or update the context-gating policy.",
        });
      }
      // If on_deny is "redact", continue with filtered args below
    }

    // Build filtered arguments
    const filteredArgs = this.buildFilteredArgs(args, result.decisions);

    if (this.config.log_only) {
      // Log but pass original args
      this.auditLog.append(
        "l2",
        "context_gate_enforcer_log_only",
        "system",
        {
          tool_name: toolName,
          policy_id: policy.policy_id,
          provider,
          fields_total: Object.keys(args).length,
          fields_redacted: result.fields_redacted,
          fields_hashed: result.fields_hashed,
          fields_blocked: deniedFields.length,
          original_context_hash: result.original_context_hash,
        }
      );
      this.stats.fields_redacted += result.fields_redacted;
      this.stats.fields_hashed += result.fields_hashed;
      this.stats.fields_blocked += deniedFields.length;

      return originalHandler(args);
    }

    // Execute handler with filtered arguments
    this.auditLog.append(
      "l2",
      "context_gate_enforcer_filter",
      "system",
      {
        tool_name: toolName,
        policy_id: policy.policy_id,
        provider,
        fields_total: Object.keys(args).length,
        fields_redacted: result.fields_redacted,
        fields_hashed: result.fields_hashed,
        fields_blocked: deniedFields.length,
        original_context_hash: result.original_context_hash,
      }
    );

    this.stats.fields_redacted += result.fields_redacted;
    this.stats.fields_hashed += result.fields_hashed;
    this.stats.fields_blocked += deniedFields.length;

    return originalHandler(filteredArgs);
  }

  /**
   * Filter tool arguments using built-in sensitive patterns.
   * This provides baseline protection when no explicit policy is configured.
   */
  private async filterWithBuiltinPatterns(
    toolName: string,
    args: Record<string, unknown>,
    originalHandler: ToolHandler
  ): Promise<{ content: Array<{ type: "text"; text: string }> }> {
    const fieldsToRedact: string[] = [];
    const originalHash = hashToString(
      stringToBytes(JSON.stringify(args))
    );

    // Check each field against built-in patterns
    for (const field of Object.keys(args)) {
      if (matchesPattern(field, BUILTIN_SENSITIVE_PATTERNS)) {
        fieldsToRedact.push(field);
      }
    }

    if (fieldsToRedact.length === 0) {
      // No sensitive fields detected — pass through
      this.auditLog.append(
        "l2",
        "context_gate_enforcer_builtin_pass",
        "system",
        {
          tool_name: toolName,
          reason: "No sensitive field patterns detected",
        }
      );
      return originalHandler(args);
    }

    // Build filtered arguments
    const filteredArgs: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args)) {
      if (fieldsToRedact.includes(key)) {
        filteredArgs[key] = "[REDACTED]";
      } else {
        filteredArgs[key] = value;
      }
    }

    const filteredHash = hashToString(
      stringToBytes(JSON.stringify(filteredArgs))
    );

    if (this.config.log_only) {
      this.auditLog.append(
        "l2",
        "context_gate_enforcer_builtin_log_only",
        "system",
        {
          tool_name: toolName,
          fields_redacted: fieldsToRedact.length,
          redacted_fields: fieldsToRedact,
          original_context_hash: originalHash,
        }
      );
      this.stats.fields_redacted += fieldsToRedact.length;
      return originalHandler(args);
    }

    // Execute handler with filtered arguments
    this.auditLog.append(
      "l2",
      "context_gate_enforcer_builtin_filter",
      "system",
      {
        tool_name: toolName,
        fields_redacted: fieldsToRedact.length,
        redacted_fields: fieldsToRedact,
        original_context_hash: originalHash,
        filtered_context_hash: filteredHash,
      }
    );

    this.stats.fields_redacted += fieldsToRedact.length;

    return originalHandler(filteredArgs);
  }

  /**
   * Check if a tool should be filtered based on bypass prefixes.
   *
   * SEC-033: Uses exact namespace component matching, not bare startsWith().
   * A prefix of "proxy/" matches "proxy/server/tool" but NOT "proxyevil/steal".
   * The prefix must match exactly up to its length, and the prefix must end
   * with "/" to enforce namespace boundaries (if it doesn't, we add one).
   *
   * Special sentinel: "*" bypasses ALL tools (used when all Sanctuary-internal
   * tools should skip context gating — the default). Only proxy/external tools
   * should be filtered in production.
   */
  shouldFilter(toolName: string): boolean {
    for (const prefix of this.config.bypass_prefixes) {
      // Sentinel: "*" bypasses all tools
      if (prefix === "*") return false;

      // Ensure prefix ends with "/" to enforce namespace boundaries
      const safePrefix = prefix.endsWith("/") ? prefix : prefix + "/";
      if (toolName === safePrefix.slice(0, -1) || toolName.startsWith(safePrefix)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Extract provider category from tool name.
   * Default: "tool-api". Override for specific patterns.
   */
  private extractProviderCategory(toolName: string): string {
    if (toolName.includes("inference") || toolName.includes("llm")) {
      return "inference";
    }
    if (toolName.includes("log") || toolName.includes("telemetry")) {
      return "logging";
    }
    if (toolName.includes("analytics") || toolName.includes("metric")) {
      return "analytics";
    }
    return "tool-api";
  }

  /**
   * Build filtered arguments from filter decisions.
   */
  private buildFilteredArgs(
    originalArgs: Record<string, unknown>,
    decisions: Array<{ field: string; action: string; hash_value?: string }>
  ): Record<string, unknown> {
    const filtered: Record<string, unknown> = {};

    for (const decision of decisions) {
      switch (decision.action) {
        case "allow":
          filtered[decision.field] = originalArgs[decision.field];
          break;
        case "redact":
          // Include field with redacted value
          filtered[decision.field] = "[REDACTED]";
          break;
        case "hash":
          filtered[decision.field] = decision.hash_value;
          break;
        case "summarize":
          filtered[decision.field] = originalArgs[decision.field];
          break;
        case "deny":
          // Field excluded — denied
          break;
      }
    }

    return filtered;
  }

  /**
   * Set the active policy ID.
   */
  setDefaultPolicy(policyId: string): void {
    this.config.default_policy_id = policyId;
  }

  /**
   * Get current enforcer status and stats.
   */
  getStatus(): EnforcerStatus {
    return {
      enabled: this.config.enabled,
      log_only: this.config.log_only,
      default_policy_id: this.config.default_policy_id ?? null,
      stats: { ...this.stats },
    };
  }

  /**
   * Toggle enforcer enabled state.
   */
  setEnabled(enabled: boolean): void {
    this.config.enabled = enabled;
  }

  /**
   * Toggle log_only mode.
   */
  setLogOnly(logOnly: boolean): void {
    this.config.log_only = logOnly;
  }

  /**
   * Reset stats counters.
   */
  resetStats(): void {
    this.stats = {
      calls_inspected: 0,
      calls_bypassed: 0,
      fields_redacted: 0,
      fields_hashed: 0,
      fields_blocked: 0,
      calls_blocked: 0,
    };
  }
}

/**
 * Export built-in patterns for testing and reference.
 */
export { BUILTIN_SENSITIVE_PATTERNS };
