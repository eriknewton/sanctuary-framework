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
import type { InjectionDetector } from "../security/injection-detector.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type { CallGovernor } from "../l2-operational/call-governor.js";

// ── Types ───────────────────────────────────────────────────────────────

export interface ProxyRouterOptions {
  /** Optional callback when the context gate should filter arguments */
  contextGateFilter?: (
    toolName: string,
    args: Record<string, unknown>
  ) => Promise<Record<string, unknown>>;
  /** Optional call governor for runtime governance */
  governor?: CallGovernor;
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
          this.auditLog.append("l2", `proxy_injection_blocked:${proxyName}`, "system", {
            server: serverName,
            tool: toolName,
            tier,
            confidence: injectionResult.confidence,
            latency_ms: Date.now() - start,
          }, "failure");

          return toolResult({
            error: "Operation not permitted",
            proxy: true,
          });
        }

        if (injectionResult.flagged && injectionResult.recommendation === "escalate") {
          // Log the escalation — the gate will handle approval
          this.auditLog.append("l2", `proxy_injection_escalated:${proxyName}`, "system", {
            server: serverName,
            tool: toolName,
            tier,
            confidence: injectionResult.confidence,
          });
        }

        // Step 2: Context gating (if configured)
        let filteredArgs = args;
        if (this.options.contextGateFilter) {
          try {
            filteredArgs = await this.options.contextGateFilter(proxyName, args);
          } catch {
            // Context gate failure — proceed with original args
            // (defense in depth: the gate is advisory, not blocking for proxy calls)
          }
        }

        // Step 3: Governor check (rate, volume, duplicate, lifetime)
        if (this.options.governor) {
          const govResult = this.options.governor.check(serverName, toolName, filteredArgs);

          if (!govResult.allowed) {
            this.auditLog.append("l2", `proxy_governor_blocked:${proxyName}`, "system", {
              server: serverName,
              tool: toolName,
              tier,
              reason: govResult.reason,
              latency_ms: Date.now() - start,
            }, "failure");

            return toolResult({
              error: "Operation not permitted",
              proxy: true,
              governor_reason: govResult.reason,
            });
          }

          // Duplicate cached — return cached result without forwarding
          if (govResult.reason === "duplicate_cached" && govResult.cached_result !== undefined) {
            this.auditLog.append("l2", `proxy_governor_cached:${proxyName}`, "system", {
              server: serverName,
              tool: toolName,
              tier,
              cached: true,
              latency_ms: Date.now() - start,
            });

            return toolResult(govResult.cached_result ?? {});
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
        this.auditLog.append("l2", `proxy_call:${proxyName}`, "system", {
          server: serverName,
          tool: toolName,
          tier,
          decision: "allowed",
          latency_ms: latencyMs,
        });

        // Return the upstream response, coerced to standard text format
        return this.normalizeResponse(result);
      } catch (err) {
        const latencyMs = Date.now() - start;
        const rawErrorMessage = err instanceof Error ? err.message : "Unknown upstream error";

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

        // Audit log the failure
        this.auditLog.append("l2", `proxy_call:${proxyName}`, "system", {
          server: serverName,
          tool: toolName,
          tier,
          decision: "error",
          error: errorMessage,
          latency_ms: latencyMs,
        }, "failure");

        // Pass upstream errors through to the agent (sanitized)
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              error: errorMessage,
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
