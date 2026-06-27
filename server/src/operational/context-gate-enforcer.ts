/**
 * Sanctuary MCP Server — L2 Context Gating: Automatic Enforcer
 *
 * The context gate enforcer wraps tool handlers to automatically filter
 * their arguments before execution. Unlike context_gate_filter (which agents
 * call voluntarily), the enforcer runs automatically on every tool call
 * when enabled.
 *
 * With a bound context-gating policy, this enforces minimum-necessary-context
 * and makes bypassing context protection explicit (requires reconfiguration).
 * Without a bound policy, enabled context gating fails closed.
 *
 * Security invariants:
 * - The enforcer wraps every tool handler when enabled
 * - Filtering decisions are audit-logged
 * - Default action on missing policy: block the request before egress
 * - Denied fields block the entire request (with logged reason)
 * - Redacted fields are stripped from tool arguments
 * - With a bound policy, log_only mode logs filtering and passes original args
 */

import type { ToolHandler } from "../router.js";
import type { ContextGatePolicyStore } from "./context-gate.js";
import {
  filterContext,
  type ContextGatePolicy,
} from "./context-gate.js";
import type { AuditLog } from "./audit-log.js";
import { toolResult } from "../router.js";
import {
  applyLocalPrivacyFilter,
  applyPrivacyPlaceholders,
  type PrivacyPlaceholderVault,
} from "./privacy-filter.js";

const NO_POLICY_BOUND_OPERATOR_MESSAGE =
  "context-gating enabled but no policy bound; bind a context-gating policy or disable gating.";

// ── Errors ──────────────────────────────────────────────────────────────

/**
 * Thrown by {@link ContextGateEnforcer.filterArgs} (the proxy pre-forward
 * path) when the active policy's `on_deny: block` decision fires. Unlike the
 * `wrapHandler` MCP-tool path (which RETURNS the `context_gating_blocked`
 * toolResult to its caller), the proxy path cannot return a toolResult in place
 * of filtered args, because doing so would let the original unredacted args
 * leak upstream (the historical fail-open this error closes). Instead the proxy
 * filter throws this typed error so the proxy router fails CLOSED with an honest
 * policy-block reason rather than forwarding everything (invariants #1/#5).
 */
export class ContextGateBlockedError extends Error {
  readonly toolName: string;
  readonly deniedFields: string[];

  constructor(toolName: string, deniedFields: string[]) {
    const fieldList = deniedFields.length > 0 ? deniedFields.join(", ") : "<unspecified>";
    super(`context-gating policy blocked tool ${toolName} (denied fields: ${fieldList})`);
    this.name = "ContextGateBlockedError";
    this.toolName = toolName;
    this.deniedFields = deniedFields;
    // Preserve prototype chain for instanceof across transpilation targets.
    Object.setPrototypeOf(this, ContextGateBlockedError.prototype);
  }
}

/**
 * Thrown by the proxy pre-forward path when context gating is enabled but no
 * usable policy is bound. The proxy catches this typed error, denies the call,
 * and returns only its generic denial to the agent.
 */
export class ContextGateNoPolicyError extends Error {
  readonly toolName: string;

  constructor(toolName: string) {
    super(NO_POLICY_BOUND_OPERATOR_MESSAGE);
    this.name = "ContextGateNoPolicyError";
    this.toolName = toolName;
    Object.setPrototypeOf(this, ContextGateNoPolicyError.prototype);
  }
}

// ── Configuration ───────────────────────────────────────────────────────

export interface EnforcerConfig {
  /** Enable/disable automatic filtering (default: true) */
  enabled: boolean;
  /** Policy ID to use when no specific one is set */
  default_policy_id?: string;
  /** Tool name prefixes to skip filtering (e.g., ["*"] to skip all system tools) */
  bypass_prefixes: string[];
  /** Log but don't filter, for gradual rollout (default: false) */
  log_only: boolean;
  /** What to do when a field triggers deny action: "block" or "redact" */
  on_deny: "block" | "redact";
}

// ── Enforcer Status ─────────────────────────────────────────────────────

export interface EnforcerStatus {
  enabled: boolean;
  log_only: boolean;
  default_policy_id: string | null;
  last_filter_success_at: string | null;
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
  private privacyVault?: PrivacyPlaceholderVault;
  private config: EnforcerConfig;
  private stats = {
    calls_inspected: 0,
    calls_bypassed: 0,
    fields_redacted: 0,
    fields_hashed: 0,
    fields_blocked: 0,
    calls_blocked: 0,
  };
  private lastFilterSuccessAt: string | null = null;

  constructor(
    policyStore: ContextGatePolicyStore,
    auditLog: AuditLog,
    config: EnforcerConfig,
    privacyVault?: PrivacyPlaceholderVault
  ) {
    this.policyStore = policyStore;
    this.auditLog = auditLog;
    this.privacyVault = privacyVault;
    this.config = config;
  }

  /**
   * Wrap a tool handler to apply automatic context gating.
   *
   * The wrapped handler:
   * 1. Checks if tool should be filtered (based on bypass_prefixes)
   * 2. If not filtering, calls original handler directly
   * 3. If filtering:
   *    a. Gets the active policy or denies the call if none is bound
   *    b. Calls filterContext() with tool arguments
   *    c. If any field triggered "deny" and on_deny is "block", returns error
   *    d. If on_deny is "redact", replaces denied fields with "[REDACTED]"
   *    e. Calls original handler with filtered arguments
   *    f. Logs the filtering decision
   * 4. With a bound policy in log_only mode: runs filter, logs, passes original args
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
        return this.blockNoPolicy(toolName);
      }
    };
  }

  /**
   * Apply context gating to arguments without executing a tool handler.
   *
   * Proxy routing needs a pre-forward filter because the upstream call happens
   * inside ProxyRouter, before the normal wrapped handler can see the final
   * outbound payload. This method shares the same filtering path as wrapHandler
   * but returns the filtered arguments directly.
   */
  async filterArgs(
    toolName: string,
    args: Record<string, unknown>,
    options: { respectBypass?: boolean } = {}
  ): Promise<Record<string, unknown>> {
    if (!this.config.enabled) return args;
    if (options.respectBypass !== false && !this.shouldFilter(toolName)) {
      this.stats.calls_bypassed++;
      return args;
    }

    let filteredArgs = args;
    const capture: ToolHandler = async (nextArgs) => {
      filteredArgs = nextArgs;
      return toolResult({ ok: true });
    };

    // wrapHandlerForFilter runs the shared filter path. On the redact/allow/
    // log_only path it INVOKES `capture` (so `filteredArgs` holds the filtered
    // payload). On an `on_deny:"block"` decision it RETURNS the
    // `context_gating_blocked` toolResult WITHOUT ever calling `capture`, so we
    // must inspect the returned result and refuse to return the (untouched)
    // original args. Returning them here is the fail-open this method closes.
    const result = await this.wrapHandlerForFilter(toolName, capture, args);

    const blocked = parseBlockMarker(result);
    if (blocked) {
      // capture never ran ⇒ filteredArgs would still be the ORIGINAL args.
      // Throw a typed error so the proxy router fails CLOSED with an honest
      // policy-block reason instead of forwarding unredacted args upstream.
      throw new ContextGateBlockedError(toolName, blocked.deniedFields);
    }

    return filteredArgs;
  }

  private async wrapHandlerForFilter(
    toolName: string,
    originalHandler: ToolHandler,
    args: Record<string, unknown>
  ): Promise<{ content: Array<{ type: "text"; text: string }> }> {
    if (!this.config.enabled) {
      return originalHandler(args);
    }

    this.stats.calls_inspected++;

    const policy = this.config.default_policy_id
      ? await this.policyStore.get(this.config.default_policy_id)
      : null;

    if (policy) {
      return this.filterWithPolicy(toolName, args, originalHandler, policy);
    }

    await this.auditNoPolicyBlock(toolName);
    this.stats.calls_blocked++;
    throw new ContextGateNoPolicyError(toolName);
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
        void this.auditLog.append(
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

    // Start from the recursively filtered output, then scrub sensitive spans
    // inside otherwise allowed values.
    const privacyFiltered = this.privacyVault
      ? await applyPrivacyPlaceholders(result.filtered_output, this.privacyVault, policy.policy_id)
      : applyLocalPrivacyFilter(result.filtered_output);

    if (this.config.log_only) {
      // Log but pass original args
      void this.auditLog.append(
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
          privacy_findings: privacyFiltered.findings.length,
          privacy_classes: [...new Set(privacyFiltered.findings.map((f) => f.class))],
          original_context_hash: result.original_context_hash,
        }
      );
      this.stats.fields_redacted += result.fields_redacted;
      this.stats.fields_hashed += result.fields_hashed;
      this.stats.fields_blocked += deniedFields.length;
      this.markFilterSuccess();

      return originalHandler(args);
    }

    // Execute handler with filtered arguments
    void this.auditLog.append(
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
        privacy_findings: privacyFiltered.findings.length,
        privacy_classes: [...new Set(privacyFiltered.findings.map((f) => f.class))],
        original_context_hash: result.original_context_hash,
      }
    );

    this.stats.fields_redacted += result.fields_redacted;
    this.stats.fields_hashed += result.fields_hashed;
    this.stats.fields_blocked += deniedFields.length;
    this.markFilterSuccess();

    return originalHandler(privacyFiltered.value as Record<string, unknown>);
  }

  private async blockNoPolicy(
    toolName: string
  ): Promise<{ content: Array<{ type: "text"; text: string }> }> {
    this.stats.calls_blocked++;
    await this.auditNoPolicyBlock(toolName);
    return toolResult({
      error: "Operation not permitted",
    });
  }

  private async auditNoPolicyBlock(toolName: string): Promise<void> {
    await this.auditLog.appendCritical({
      layer: "l2",
      operation: "context_gate_enforcer_no_policy_block",
      identity_id: "system",
      result: "failure",
      details: {
        tool_name: toolName,
        decision: "denied",
        reason: "context_gating_no_policy_bound",
        message: NO_POLICY_BOUND_OPERATOR_MESSAGE,
      },
    });
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
      last_filter_success_at: this.lastFilterSuccessAt,
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
   * Apply profile-backed runtime config in one place.
   */
  configureFromProfile(config: { enabled: boolean; policy_id?: string }): void {
    this.config.enabled = config.enabled;
    this.config.default_policy_id = config.policy_id;
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
    this.lastFilterSuccessAt = null;
  }

  private markFilterSuccess(): void {
    this.lastFilterSuccessAt = new Date().toISOString();
  }
}

/**
 * Robustly detect the `context_gating_blocked` marker inside a toolResult.
 *
 * The shared block branch ({@link ContextGateEnforcer.filterWithPolicy})
 * encodes its block decision as `toolResult({ error: "context_gating_blocked",
 * ... })`, i.e. a JSON object serialized into `content[0].text`. We parse that
 * structured payload rather than substring-matching the text, so an allowed
 * field value that merely contains the literal string can never be
 * mis-detected as a block. Returns the denied-field list on a confirmed block,
 * or `null` otherwise.
 */
function parseBlockMarker(
  result: { content?: Array<{ type: string; text?: string }> } | null | undefined
): { deniedFields: string[] } | null {
  const content = result?.content;
  if (!Array.isArray(content)) return null;

  for (const part of content) {
    if (!part || part.type !== "text" || typeof part.text !== "string") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(part.text);
    } catch {
      continue;
    }
    if (
      parsed &&
      typeof parsed === "object" &&
      (parsed as { error?: unknown }).error === "context_gating_blocked"
    ) {
      const rawDenied = (parsed as { denied_fields?: unknown }).denied_fields;
      const deniedFields = Array.isArray(rawDenied)
        ? rawDenied.filter((f): f is string => typeof f === "string")
        : [];
      return { deniedFields };
    }
  }
  return null;
}
