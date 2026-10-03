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
 * - Upstream-bearing responses release only after completed screening and critical audit
 * - Native sanctuary/* tools are never affected by the proxy layer
 */

import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { ResponseScreen } from "./response-screen.js";
import type { ResponseReservation } from "./response-runtime.js";
import { validateResponse, normalizeScreenedResponse, rehydrationBudget, RequestResponseBindings, type CanonicalResponse } from "./response-bounds.js";
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
    /** A factory scopes vault lookup caches to the admitted request. */
    engine: LocalPrivacyEngine | (() => LocalPrivacyEngine);
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
    private readonly responseScreen: ResponseScreen,
    options?: ProxyRouterOptions
  ) {
    // Proxy registration without a live response scanner would silently remove the release gate.
    responseScreen.assertReady();
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
    return async (args: Record<string, unknown>, _caller, context) => {
      const proxyName = `proxy/${serverName}/${toolName}`;
      const start = Date.now();
      const tier = this.getTierForTool(serverName, toolName);

      let lease: ResponseReservation | undefined;
      let withholdReason = "withhold_capacity";
      let upstreamTimedOut = false;
      const cancel = (): void => lease?.cancel();
      try {
        // Admission precedes governor/cache access and all upstream work.
        lease = this.responseScreen.session.reserve();
        withholdReason = "withhold_preparation_failure";
        context?.signal?.addEventListener("abort", cancel, { once: true });
        if (context?.signal?.aborted) lease.cancel();
        lease.assertLive();
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

        // Cancellation during an awaited gate must never authorize a later upstream dispatch.
        lease.assertLive();

        // Step 3.5: v1.1 remote-bound privacy enforcement.
        // When configured, route the outbound payload through the
        // LocalPrivacyEngine. On `denied`, short-circuit fail-closed before
        // any bytes leave the fortress. On `filtered`, replace the args with
        // the redacted payload so the upstream call never sees raw values.
        // Track the bound policy so the response can be rehydrated below.
        let privacyPolicy: PrivacyPolicy | null = null;
        let privacyDestination: PrivacyDestinationCategory = "tool-api";
        let outboundFiltered = false;
        const responseBindings = new RequestResponseBindings(() => lease!.assertLive());
        const configuredEngine = this.options.privacyEnforcement?.engine;
        const privacyEngine = typeof configuredEngine === "function" ? configuredEngine() : configuredEngine;
        if (this.options.privacyEnforcement) {
          const serverConfig = this.clientManager.getServerConfig(serverName);
          privacyDestination =
            (serverConfig?.destination_category as PrivacyDestinationCategory | undefined) ??
            "tool-api";
          const identityId = serverConfig?.privacy_identity_id;
          let resolverFailed = false;
          try {
            privacyPolicy = await lease.wait(this.options.privacyEnforcement.policyResolver(
              serverName,
              identityId
            ));
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

          const decision = await lease.wait(privacyEngine!.filterOutbound({
            payload: filteredArgs,
            responseBindings,
            policy: privacyPolicy,
            identity_id: identityId,
            agent_id: `proxy:${serverName}`,
            destination_category: privacyDestination,
            audit_log: this.auditLog,
          }));

          responseBindings.assertComplete();
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

        const reservation = lease;
        const releaseUpstreamResult = async (value: unknown, cached = false, error?: { error: string; error_type: string }) => {
          withholdReason = "withhold_scan_failure";
          reservation.observe();
          reservation.assertLive();
          validateResponse(value);
          const canonical = value;
          let prepared: CanonicalResponse = canonical;
          if (outboundFiltered && privacyEngine && privacyPolicy) {
            const rehydrated = await reservation.wait(privacyEngine.rehydrateResponse({
              response: canonical, policy: privacyPolicy,
              identity_id: this.clientManager.getServerConfig(serverName)?.privacy_identity_id,
              agent_id: `proxy:${serverName}`, destination_category: privacyDestination,
              audit_log: this.auditLog,
              // Must match incremental accounting in operational/privacy-core.ts.
              responseBudget: rehydrationBudget(() => reservation.assertLive(), placeholder => responseBindings.resolve(placeholder)),
            }));
            // A denial grants no authority to expand: only the successful result may replace canonical bytes.
            if (rehydrated.status === "rehydrated") {
              validateResponse(rehydrated.response);
              prepared = rehydrated.response;
            }
          }
          const delivered = normalizeScreenedResponse(prepared);
          // Joining without a separator detects instructions split across delivered block boundaries.
          const completion = await reservation.wait(this.responseScreen.screen(delivered.content.map(c => c.text).join(""), reservation));
          withholdReason = "withhold_audit_failure";
          await reservation.wait(this.auditLog.appendCritical({
            layer: "l2", operation: `proxy_call:${proxyName}`, identity_id: "system",
            result: error ? "failure" : "success",
            details: {
              event_type: "proxy.call", server: serverName, tool: toolName, tier,
              decision: error ? "error" : "allowed", reason: completion.label,
              ...error,
              signal_count: completion.signalCount, latency_ms: Date.now() - start,
            },
          }));
          reservation.assertLive();
          // Must precede CallGovernor.recordResult in operational/call-governor.ts: cache has no scan tokens.
          if (!cached && !error) this.options.governor?.recordResult(serverName, toolName, filteredArgs, canonical);
          this.notifyProxyCall(proxyName, serverName, error ? "error" : "allowed", error?.error ?? completion.label, tier);
          return delivered; // These exact bytes were screened; no raw envelope or later rewriting is allowed.
        };

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

            return await releaseUpstreamResult(govResult.cached_result, true);
          }
        }

        let result: unknown;
        let upstreamError: { error: string; error_type: string } | undefined;
        withholdReason = "withhold_upstream_failure";
        try {
          result = await this.callWithTimeout(serverName, toolName, filteredArgs, UPSTREAM_CALL_TIMEOUT_MS, reservation, () => { upstreamTimedOut = true; });
        } catch (err) {
          reservation.assertLive(); // Timeout/cancellation is terminal, never a sanitized fallback release.
          // SDK shape failures are incomplete content validation, not releasable upstream error envelopes.
          if (err instanceof Error && (err.name === "ZodError" || err.name === "$ZodError" ||
            (err instanceof McpError && (err.code === ErrorCode.InvalidParams || err.code === ErrorCode.InvalidRequest)))) {
            // SDK protocol failures can precede content scanning; never copy their diagnostic payload.
            withholdReason = err instanceof McpError ? "withhold_upstream_failure" : "withhold_scan_failure";
            throw err;
          }
          const upstreamUnavailable = err instanceof UpstreamUnavailableError;
          const rawErrorMessage = err instanceof Error ? err.message : "Unknown upstream error";
          const MAX_ERROR_UTF16 = 200; // Existing sanitized error truncation contract.
          let safe = rawErrorMessage.substring(0, MAX_ERROR_UTF16);
          safe = safe.replace(/\/[^\s]+/g, '[path-redacted]');
          safe = safe.replace(/(?:mongodb|postgres|mysql|redis):\/\/[^\s]+/g, '[connection-redacted]');
          upstreamError = { error: safe, error_type: upstreamUnavailable ? "UpstreamUnavailableError" : "upstream_error" };
          result = { content: [{ type: "text", text: JSON.stringify({
            error: safe, code: upstreamUnavailable ? "upstream_unavailable" : "upstream_error",
            proxy: true, server: serverName, tool: toolName,
          }) }] };
        }
        return await releaseUpstreamResult(result, false, upstreamError);
      } catch {
        // Fixed causes disclose no response bytes, including SDK validation messages.
        const reason = upstreamTimedOut ? "withhold_upstream_timeout"
          : lease?.abort.signal.aborted ? "withhold_cancelled" : withholdReason;
        try {
          const audit = this.auditLog.appendCritical({
            layer: "l2", operation: `proxy_call:${proxyName}`, identity_id: "system", result: "failure",
            details: { event_type: "proxy.call", server: serverName, tool: toolName, tier,
              decision: "blocked", reason, latency_ms: Date.now() - start },
          });
          if (lease) await lease.wait(audit);
          else await audit; // Admission refusals still leave the existing operator audit row.
        } catch { /* Audit failure cannot release upstream content. */ }
        this.notifyProxyCall(proxyName, serverName, "blocked", reason, tier);
        return toolResult({ error: "Operation not permitted", proxy: true });
      } finally {
        context?.signal?.removeEventListener("abort", cancel);
        lease?.finish();
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
    timeoutMs: number,
    reservation: ResponseReservation,
    onTimeout: () => void,
  ): Promise<CanonicalResponse> {
    reservation.assertLive(); // The last check must precede the effect, never just the awaited result.
    const work = this.clientManager.callTool(serverName, toolName, args);
    // Receipt remains observed even after the caller has timed out; settlement still owns capacity.
    void work.then(() => reservation.observe(), () => reservation.observe());
    const timer = setTimeout(() => { onTimeout(); reservation.cancel(); }, timeoutMs);
    try { return await reservation.wait(work); }
    finally { clearTimeout(timer); }
  }
}
