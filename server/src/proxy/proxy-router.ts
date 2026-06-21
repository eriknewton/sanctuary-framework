/**
 * Sanctuary MCP Server — Proxy Router
 *
 * Routes proxied tool calls through the full Sanctuary enforcement chain:
 * injection detection, approval gate evaluation, context gating, and audit logging.
 *
 * Upstream tools are registered under the namespace `proxy/{server_name}/{tool_name}`.
 * This ensures no collision with native `sanctuary/*` tools and makes the provenance
 * of every tool call explicit.
 *
 * Security invariants:
 * - Every proxied call passes through injection scan + gate + audit (no bypass path)
 * - Denied calls return a generic denial message (same as native Sanctuary denials)
 * - Upstream errors are passed through to the agent unmodified
 * - Native sanctuary/* tools are never affected by the proxy layer
 */

import type { ToolDefinition, ToolHandler } from "../router.js";
import { toolResult } from "../router.js";
import type { ClientManager } from "./client-manager.js";
import { UpstreamUnavailableError } from "./client-manager.js";
import type { InjectionDetector } from "../security/injection-detector.js";
import type { AuditLog } from "../operational/audit-log.js";
import {
  ContextGateBlockedError,
  ContextGateNoPolicyError,
} from "../operational/context-gate-enforcer.js";
import type { CallGovernor } from "../operational/call-governor.js";
import type { LocalPrivacyEngine, PrivacyPolicy } from "../operational/privacy-core.js";
import type { PrivacyDestinationCategory } from "../contracts/v1.1/index.js";

// ── Types ───────────────────────────────────────────────────────────────

export interface ProxyRouterOptions {
  /** Optional callback when the context gate should filter arguments */
  contextGateFilter?: (
    toolName: string,
    args: Record<string, unknown>
  ) => Promise<Record<string, unknown>>;
  /** Optional call governor for runtime governance */
  governor?: CallGovernor;
  /**
   * Optional v1.1 remote-bound privacy enforcement.
   *
   * When set, every proxied tool call is routed through
   * `engine.filterOutbound` before the upstream forward. The bound
   * `PrivacyPolicy` is resolved per-server via `policyResolver`, and the
   * destination category comes from the server's `destination_category`
   * field (defaulting to `tool-api` when absent).
   *
   * Fail-closed semantics:
   * - `policyResolver` returns null when no policy is bound for the server;
   *   the privacy engine treats that as `fail_closed_no_policy` and denies.
   * - `policyResolver` rejecting (vault unreachable, decrypt failure, etc.)
   *   is an infra outage, not a missing policy: the router denies directly with
   *   the distinct `fail_closed_filter_error` reason class (it does NOT collapse
   *   the rejection to a null policy, which would mislabel the outage as
   *   "no policy bound").
   * - Operator overrides on the policy (`operator_override.allow_on_*`)
   *   are honored by the engine itself.
   */
  privacyEnforcement?: {
    engine: LocalPrivacyEngine;
    policyResolver: (
      server: string,
      identityId: string | undefined
    ) => Promise<PrivacyPolicy | null>;
  };
  /** Optional callback after each proxy call decision (for dashboard feed) */
  onProxyCall?: (data: {
    tool: string;
    server: string;
    decision: string;
    reason?: string;
    tier?: number;
    timestamp: string;
  }) => void;
}

// ── Constants ───────────────────────────────────────────────────────────

/** Maximum time to wait for an upstream tool call response (30 seconds) */
const UPSTREAM_CALL_TIMEOUT_MS = 30_000;

// ── Proxy Router ────────────────────────────────────────────────────────

export class ProxyRouter {
  private clientManager: ClientManager;
  private injectionDetector: InjectionDetector;
  private auditLog: AuditLog;
  private options: ProxyRouterOptions;

  constructor(
    clientManager: ClientManager,
    injectionDetector: InjectionDetector,
    auditLog: AuditLog,
    options?: ProxyRouterOptions
  ) {
    this.clientManager = clientManager;
    this.injectionDetector = injectionDetector;
    this.auditLog = auditLog;
    this.options = options ?? {};
  }

  /**
   * Convert all discovered upstream tools to Sanctuary ToolDefinitions.
   * Each tool is registered as `proxy/{server_name}/{tool_name}`.
   */
  getProxiedTools(): ToolDefinition[] {
    const tools: ToolDefinition[] = [];
    const allUpstreamTools = this.clientManager.getAllTools();

    for (const [serverName, serverTools] of allUpstreamTools) {
      for (const upstreamTool of serverTools) {
        const proxyName = `proxy/${serverName}/${upstreamTool.name}`;

        tools.push({
          name: proxyName,
          description: `[via ${serverName}] ${upstreamTool.description}`,
          tool_class: "write",
          inputSchema: upstreamTool.inputSchema,
          handler: this.createHandler(serverName, upstreamTool.name),
        });
      }
    }

    return tools;
  }

  /**
   * Determine the tier for a proxied tool call.
   * Checks tool_overrides first, then falls back to default_tier.
   */
  getTierForTool(serverName: string, toolName: string): 1 | 2 | 3 {
    const serverConfig = this.clientManager.getServerConfig(serverName);
    if (!serverConfig) return 2; // Default to Tier 2 for unknown servers

    // Check per-tool overrides first
    if (serverConfig.tool_overrides?.[toolName]) {
      return serverConfig.tool_overrides[toolName].tier;
    }

    return serverConfig.default_tier;
  }

  /**
   * Parse a proxy tool name into server name and tool name.
   * Returns null if the name doesn't match the proxy namespace.
   */
  static parseProxyToolName(fullName: string): { serverName: string; toolName: string } | null {
    if (!fullName.startsWith("proxy/")) return null;

    const rest = fullName.slice("proxy/".length);
    const slashIdx = rest.indexOf("/");
    if (slashIdx === -1) return null;

    return {
      serverName: rest.slice(0, slashIdx),
      toolName: rest.slice(slashIdx + 1),
    };
  }

  // ── Private ───────────────────────────────────────────────────────────

  /**
   * Create a handler for a specific proxied tool.
   * The handler runs the full enforcement chain before forwarding.
   */
  private createHandler(serverName: string, toolName: string): ToolHandler {
    return async (args: Record<string, unknown>) => {
      const proxyName = `proxy/${serverName}/${toolName}`;
      const start = Date.now();
      const tier = this.getTierForTool(serverName, toolName);

      try {
        // Step 1: Injection detection
        const injectionResult = this.injectionDetector.scan(proxyName, args);
        if (injectionResult.flagged && injectionResult.recommendation === "block") {
          await this.auditLog.appendCritical({
            layer: "l2",
            operation: `proxy_injection_blocked:${proxyName}`,
            identity_id: "system",
            result: "failure",
            details: {
              server: serverName,
              tool: toolName,
              tier,
              confidence: injectionResult.confidence,
              latency_ms: Date.now() - start,
            },
          });

          this.notifyProxyCall(proxyName, serverName, "blocked", "injection_detected", tier);
          return toolResult({
            error: "Operation not permitted",
            proxy: true,
          });
        }

        if (injectionResult.flagged && injectionResult.recommendation === "escalate") {
          // Log the escalation — the gate will handle approval
          void this.auditLog.append("l2", `proxy_injection_escalated:${proxyName}`, "system", {
            server: serverName,
            tool: toolName,
            tier,
            confidence: injectionResult.confidence,
          });
        }

        // Step 2: Context gating (if configured)
        //
        // Fail CLOSED on a gate-filter error. The context gate is a redaction
        // control the operator configured to strip denied fields before any
        // payload leaves to the upstream server; the tool copy promises
        // "'deny' blocks the entire request." If the filter throws (policy-store
        // read failure, malformed policy, runtime exception) we must NOT forward
        // the original unredacted args, since doing so would silently degrade a
        // configured block control to "send everything" (invariant #5/#1). We
        // deny the request, record a critical gate-error denial in the audit
        // trail, and return a generic denial. The raw error is recorded in the
        // audit log only, never leaked to the agent response (invariant #7 style).
        let filteredArgs = args;
        if (this.options.contextGateFilter) {
          try {
            filteredArgs = await this.options.contextGateFilter(proxyName, args);
          } catch (gateErr) {
            // Distinguish designed context-gate denials from genuine filter
            // errors. Explicit policy blocks and no-policy misconfiguration both
            // fail closed without forwarding. Any other throw is an infra/runtime
            // fault and keeps `context_gate_filter_error`. All branches return
            // the same generic agent-facing denial; details stay operator-side.
            const isPolicyBlock = gateErr instanceof ContextGateBlockedError;
            const isNoPolicyBlock = gateErr instanceof ContextGateNoPolicyError;
            const reason = isPolicyBlock
              ? "context_gating_blocked"
              : isNoPolicyBlock
                ? "context_gating_no_policy_bound"
                : "context_gate_filter_error";
            const operation = isPolicyBlock
              ? `proxy_context_gating_blocked:${proxyName}`
              : isNoPolicyBlock
                ? `proxy_context_gating_no_policy_block:${proxyName}`
                : `proxy_context_gate_error:${proxyName}`;
            const eventType = isPolicyBlock
              ? "proxy.context_gating_blocked"
              : isNoPolicyBlock
                ? "proxy.context_gating_no_policy_block"
                : "proxy.context_gate_error";
            const gateErrorMessage =
              gateErr instanceof Error ? gateErr.message : "context gate filter error";
            await this.auditLog.appendCritical({
              layer: "l2",
              operation,
              identity_id: "system",
              result: "failure",
              details: {
                event_type: eventType,
                server: serverName,
                tool: toolName,
                tier,
                decision: "denied",
                reason,
                ...(isPolicyBlock
                  ? { denied_fields: (gateErr as ContextGateBlockedError).deniedFields }
                  : {}),
                error: gateErrorMessage,
                latency_ms: Date.now() - start,
              },
            });

            this.notifyProxyCall(proxyName, serverName, "blocked", reason, tier);
            return toolResult({
              error: "Operation not permitted",
              proxy: true,
            });
          }
        }

        // Step 3: Governor check (rate, volume, duplicate, lifetime)
        if (this.options.governor) {
          const govResult = this.options.governor.check(serverName, toolName, filteredArgs);

          if (!govResult.allowed) {
            await this.auditLog.appendCritical({
              layer: "l2",
              operation: `proxy_governor_blocked:${proxyName}`,
              identity_id: "system",
              result: "failure",
              details: {
                server: serverName,
                tool: toolName,
                tier,
                reason: govResult.reason,
                latency_ms: Date.now() - start,
              },
            });

            this.notifyProxyCall(proxyName, serverName, "blocked", govResult.reason, tier);
            return toolResult({
              error: "Operation not permitted",
              proxy: true,
              governor_reason: govResult.reason,
            });
          }

          // Duplicate cached — return cached result without forwarding
          if (govResult.reason === "duplicate_cached" && govResult.cached_result !== undefined) {
            void this.auditLog.append("l2", `proxy_governor_cached:${proxyName}`, "system", {
              server: serverName,
              tool: toolName,
              tier,
              cached: true,
              latency_ms: Date.now() - start,
            });

            return toolResult(govResult.cached_result ?? {});
          }
        }

        // Step 3.5: v1.1 remote-bound privacy enforcement.
        // When configured, route the outbound payload through the
        // LocalPrivacyEngine. On `denied`, short-circuit fail-closed before
        // any bytes leave the fortress. On `filtered`, replace the args with
        // the redacted payload so the upstream call never sees raw values.
        // Track the bound policy so the response can be rehydrated below.
        let privacyPolicy: PrivacyPolicy | null = null;
        let privacyDestination: PrivacyDestinationCategory = "tool-api";
        let outboundFiltered = false;
        if (this.options.privacyEnforcement) {
          const serverConfig = this.clientManager.getServerConfig(serverName);
          privacyDestination =
            (serverConfig?.destination_category as PrivacyDestinationCategory | undefined) ??
            "tool-api";
          const identityId = serverConfig?.privacy_identity_id;
          let resolverFailed = false;
          try {
            privacyPolicy = await this.options.privacyEnforcement.policyResolver(
              serverName,
              identityId
            );
          } catch {
            // Resolver rejection means the vault was unreachable or a decrypt
            // failed (an INFRA outage, not a missing/unbound policy). Passing
            // `policy: null` to the engine below would have it emit
            // `fail_closed_no_policy` ("no policy bound"), mislabeling the
            // outage as a configuration gap and losing the distinct
            // `fail_closed_filter_error` reason the router doc promises. We
            // still fail closed (deny, never forward) but with the honest
            // reason class.
            privacyPolicy = null;
            resolverFailed = true;
          }

          if (resolverFailed) {
            await this.auditLog.appendCritical({
              layer: "l2",
              operation: `proxy_privacy_denied:${proxyName}`,
              identity_id: "system",
              result: "failure",
              details: {
                event_type: "proxy.privacy_denied",
                server: serverName,
                tool: toolName,
                tier,
                denial_reason_class: "fail_closed_filter_error",
                latency_ms: Date.now() - start,
              },
            });
            this.notifyProxyCall(
              proxyName,
              serverName,
              "blocked",
              "privacy_denied",
              tier
            );
            return toolResult({
              error: "Operation not permitted",
              proxy: true,
              privacy_denied: true,
            });
          }

          const decision = await this.options.privacyEnforcement.engine.filterOutbound({
            payload: filteredArgs,
            policy: privacyPolicy,
            identity_id: identityId,
            agent_id: `proxy:${serverName}`,
            destination_category: privacyDestination,
            audit_log: this.auditLog,
          });

          if (decision.status === "denied") {
            await this.auditLog.appendCritical({
              layer: "l2",
              operation: `proxy_privacy_denied:${proxyName}`,
              identity_id: "system",
              result: "failure",
              details: {
                server: serverName,
                tool: toolName,
                tier,
                denial_reason_class: decision.audit_payload.denial_reason_class,
                latency_ms: Date.now() - start,
              },
            });
            this.notifyProxyCall(
              proxyName,
              serverName,
              "blocked",
              "privacy_denied",
              tier
            );
            return toolResult({
              error: "Operation not permitted",
              proxy: true,
              privacy_denied: true,
            });
          }

          if (decision.status === "filtered") {
            outboundFiltered = true;
            filteredArgs = decision.payload as Record<string, unknown>;
          }
        }

        // Step 4: Forward to upstream server
        const result = await this.callWithTimeout(
          serverName,
          toolName,
          filteredArgs,
          UPSTREAM_CALL_TIMEOUT_MS
        );

        const latencyMs = Date.now() - start;

        // Step 5: Record result for duplicate caching
        if (this.options.governor) {
          this.options.governor.recordResult(serverName, toolName, filteredArgs, result);
        }

        // Step 6: Audit log the successful call
        await this.auditLog.appendCritical({
          layer: "l2",
          operation: `proxy_call:${proxyName}`,
          identity_id: "system",
          result: "success",
          details: {
            event_type: "proxy.call",
            server: serverName,
            tool: toolName,
            tier,
            decision: "allowed",
            latency_ms: latencyMs,
          },
        });

        this.notifyProxyCall(proxyName, serverName, "allowed", undefined, tier);

        // Step 7: v1.1 rehydration of upstream response.
        // Only attempts rehydration if the outbound was filtered AND a policy
        // is bound. Engine fails closed on denied rehydration (placeholders
        // remain in the response unchanged); audit captures the decision.
        if (outboundFiltered && this.options.privacyEnforcement && privacyPolicy) {
          const serverConfig = this.clientManager.getServerConfig(serverName);
          const identityId = serverConfig?.privacy_identity_id;
          const rehydrated = await this.options.privacyEnforcement.engine.rehydrateResponse({
            response: result,
            policy: privacyPolicy,
            identity_id: identityId,
            agent_id: `proxy:${serverName}`,
            destination_category: privacyDestination,
            audit_log: this.auditLog,
          });
          if (rehydrated.status === "rehydrated") {
            return this.normalizeResponse(
              rehydrated.response as { content: Array<{ type: string; text?: string; [key: string]: unknown }> }
            );
          }
          // Denied rehydration: caller sees placeholders unchanged.
          return this.normalizeResponse(
            (rehydrated.response as { content: Array<{ type: string; text?: string; [key: string]: unknown }> })
          );
        }

        // Return the upstream response, coerced to standard text format
        return this.normalizeResponse(result);
      } catch (err) {
        const latencyMs = Date.now() - start;
        const rawErrorMessage = err instanceof Error ? err.message : "Unknown upstream error";
        const upstreamUnavailable = err instanceof UpstreamUnavailableError;

        // SEC-050: Sanitize upstream error messages to prevent info disclosure
        const sanitizeError = (msg: string): string => {
          // Truncate to 200 chars
          let safe = msg.substring(0, 200);
          // Remove file paths
          safe = safe.replace(/\/[^\s]+/g, '[path-redacted]');
          // Remove connection strings
          safe = safe.replace(/(?:mongodb|postgres|mysql|redis):\/\/[^\s]+/g, '[connection-redacted]');
          return safe;
        };

        const errorMessage = sanitizeError(rawErrorMessage);

        try {
          await this.auditLog.appendCritical({
            layer: "l2",
            operation: `proxy_call:${proxyName}`,
            identity_id: "system",
            result: "failure",
            details: {
              event_type: "proxy.call",
              server: serverName,
              tool: toolName,
              tier,
              decision: "error",
              error: errorMessage,
              error_type: upstreamUnavailable ? "UpstreamUnavailableError" : "upstream_error",
              latency_ms: latencyMs,
            },
          });
        } catch {
          // Fail closed: never forward or retry after critical audit failure.
        }

        this.notifyProxyCall(proxyName, serverName, "error", errorMessage, tier);

        // Pass upstream errors through to the agent (sanitized)
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              error: errorMessage,
              code: upstreamUnavailable ? "upstream_unavailable" : "upstream_error",
              proxy: true,
              server: serverName,
              tool: toolName,
            }),
          }],
        };
      }
    };
  }

  /**
   * Notify the onProxyCall callback if configured.
   */
  private notifyProxyCall(
    tool: string,
    server: string,
    decision: string,
    reason?: string,
    tier?: number
  ): void {
    if (this.options.onProxyCall) {
      try {
        this.options.onProxyCall({
          tool,
          server,
          decision,
          reason,
          tier,
          timestamp: new Date().toISOString(),
        });
      } catch {
        // Callback errors must not propagate
      }
    }
  }

  /**
   * Call an upstream tool with a timeout.
   */
  private async callWithTimeout(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>,
    timeoutMs: number
  ): Promise<{ content: Array<{ type: string; text?: string; [key: string]: unknown }> }> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Upstream tool call timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.clientManager
        .callTool(serverName, toolName, args)
        .then(result => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch(err => {
          clearTimeout(timer);
          reject(err);
        });
    });
  }

  /**
   * Normalize an upstream response to the standard Sanctuary response format.
   */
  private normalizeResponse(
    result: { content: Array<{ type: string; text?: string; [key: string]: unknown }> }
  ): { content: Array<{ type: "text"; text: string }> } {
    // SEC-046: Validate response size before processing
    const MAX_RESPONSE_SIZE = 1_000_000; // 1MB
    const MAX_TEXT_BLOCK_SIZE = 100_000; // 100KB per text block

    const responseStr = JSON.stringify(result);
    if (responseStr.length > MAX_RESPONSE_SIZE) {
      return toolResult({
        error: "upstream_response_too_large",
        max_bytes: MAX_RESPONSE_SIZE,
      });
    }

    if (!result.content || !Array.isArray(result.content)) {
      return toolResult({ upstream_response: result });
    }

    // Pass through text content directly, with truncation if needed
    const textContent = result.content
      .filter(c => c.type === "text" && typeof c.text === "string")
      .map(c => {
        // SEC-046: Truncate text blocks to 100KB
        const text = c.text!;
        if (text.length > MAX_TEXT_BLOCK_SIZE) {
          return {
            type: "text" as const,
            text: text.substring(0, MAX_TEXT_BLOCK_SIZE) + "\n[response truncated]",
          };
        }
        return { type: "text" as const, text };
      });

    if (textContent.length > 0) {
      return { content: textContent };
    }

    // For non-text content, serialize it as JSON
    return toolResult({ upstream_response: result.content });
  }
}
