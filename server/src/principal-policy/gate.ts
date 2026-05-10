/**
 * Sanctuary MCP Server — Approval Gate
 *
 * The three-tier approval gate sits between the MCP router and tool handlers.
 * Every tool call passes through the gate before execution.
 *
 * Evaluation order:
 * 1. Tier 1: Is this operation in the always-approve list? → Request approval.
 * 2. Tier 2: Does this call represent a behavioral anomaly? → Request approval.
 * 3. Tier 3 / default: Allow with audit logging.
 *
 * Security invariants:
 * - The gate cannot be bypassed — it wraps every tool handler.
 * - Denial responses do not reveal policy details to the agent.
 * - All gate decisions (approve, deny, allow) are audit-logged.
 */

import type { PrincipalPolicy, GateResult, ApprovalRequest, ApprovalResponse } from "./types.js";
import type { ApprovalChannel } from "./approval-channel.js";
import { BaselineTracker } from "./baseline.js";
import { extractOperationName } from "./loader.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import { InjectionDetector, type DetectionResult } from "../security/injection-detector.js";
import { AGENT_VISIBLE_DENY_REASONS } from "./deny-vocabulary.js";

/** Callback invoked when an injection is detected, for dashboard broadcasting */
export type InjectionAlertCallback = (alert: {
  toolName: string;
  result: DetectionResult;
  timestamp: string;
}) => void;

/** Resolver for proxy tool tiers — provided by the ProxyRouter */
export type ProxyTierResolver = (toolName: string) => (1 | 2 | 3) | null;

/**
 * Approval-lifecycle callback. Wired in v1.3 Upsilon-1 by the Cross-
 * Harness Approval Inbox aggregator. The gate fires this callback before
 * `channel.requestApproval()` (phase = "requested") and after the channel
 * resolves or fails (phase = "resolved"). The callback is fire-and-forget;
 * exceptions are swallowed so a broken aggregator never blocks the gate.
 *
 * The callback shape is import-free here so the principal-policy module
 * keeps no dependency on the aggregator (the aggregator imports the gate,
 * not vice versa).
 */
export type ApprovalEventCallback = (event: {
  phase: "requested" | "resolved";
  operation: string;
  tier: 1 | 2;
  reason: string;
  context: Record<string, unknown>;
  request_timestamp: string;
  resolution?: {
    decision: "approve" | "deny";
    decided_at: string;
    decided_by: string;
  };
  correlation_id: string;
}) => void;

export class ApprovalGate {
  private policy: PrincipalPolicy;
  private baseline: BaselineTracker;
  private channel: ApprovalChannel;
  private auditLog: AuditLog;
  private injectionDetector: InjectionDetector;
  private onInjectionAlert?: InjectionAlertCallback;
  private onApprovalEvent?: ApprovalEventCallback;
  private proxyTierResolver?: ProxyTierResolver;

  constructor(
    policy: PrincipalPolicy,
    baseline: BaselineTracker,
    channel: ApprovalChannel,
    auditLog: AuditLog,
    injectionDetector?: InjectionDetector,
    onInjectionAlert?: InjectionAlertCallback,
    onApprovalEvent?: ApprovalEventCallback
  ) {
    this.policy = policy;
    this.baseline = baseline;
    this.channel = channel;
    this.auditLog = auditLog;
    this.injectionDetector = injectionDetector ?? new InjectionDetector();
    this.onInjectionAlert = onInjectionAlert;
    this.onApprovalEvent = onApprovalEvent;
  }

  /**
   * Set the approval-event callback after construction. Used by the
   * Upsilon-1 wire-up when the aggregator is constructed alongside the
   * gate. The aggregator subscribes through this setter rather than the
   * constructor so existing call sites continue to work unchanged.
   */
  setApprovalEventCallback(cb: ApprovalEventCallback | undefined): void {
    this.onApprovalEvent = cb;
  }

  /**
   * Set the proxy tier resolver. Called after the proxy router is initialized.
   */
  setProxyTierResolver(resolver: ProxyTierResolver): void {
    this.proxyTierResolver = resolver;
  }

  /**
   * Evaluate a tool call against the Principal Policy.
   *
   * @param toolName - Full MCP tool name (e.g., "state_export")
   * @param args - Tool call arguments (for context extraction)
   * @returns GateResult indicating whether the call is allowed
   */
  async evaluate(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<GateResult> {
    const operation = extractOperationName(toolName);

    // Record the tool call in the baseline tracker
    this.baseline.recordToolCall(operation);

    // ── Pre-check: Prompt injection detection ────────────────────────
    const injectionResult = this.injectionDetector.scan(toolName, args);
    if (injectionResult.flagged) {
      this.auditLog.append("l2", `injection_detected:${operation}`, "system", {
        confidence: injectionResult.confidence,
        signals: injectionResult.signals.map(s => ({
          type: s.type,
          location: s.location,
          severity: s.severity,
        })),
        recommendation: injectionResult.recommendation,
      });

      // Notify dashboard if callback is registered
      if (this.onInjectionAlert) {
        this.onInjectionAlert({
          toolName,
          result: injectionResult,
          timestamp: new Date().toISOString(),
        });
      }

      if (injectionResult.recommendation === "block") {
        this.auditLog.append("l2", `gate_injection_block:${operation}`, "system", {
          tier: 1,
          operation,
          injection_confidence: injectionResult.confidence,
          signal_count: injectionResult.signals.length,
        });
        return {
          allowed: false,
          tier: 1,
          reason: AGENT_VISIBLE_DENY_REASONS.NOT_PERMITTED,
          approval_required: false,
        };
      }

      if (injectionResult.recommendation === "escalate") {
        return this.requestApproval(
          operation,
          1,
          `Potential prompt injection detected in "${operation}" (confidence: ${(injectionResult.confidence * 100).toFixed(0)}%, ${injectionResult.signals.length} signal(s))`,
          {
            operation,
            injection_detection: {
              confidence: injectionResult.confidence,
              signal_count: injectionResult.signals.length,
              signal_types: [...new Set(injectionResult.signals.map(s => s.type))],
            },
          }
        );
      }
    }

    // ── Proxy tools: tier determined by proxy router ─────────────────
    if (toolName.startsWith("proxy/") && this.proxyTierResolver) {
      const proxyTier = this.proxyTierResolver(toolName);
      if (proxyTier !== null) {
        if (proxyTier === 1) {
          return this.requestApproval(operation, 1, `Proxy tool "${toolName}" is configured as Tier 1 (always requires approval)`, {
            operation: toolName,
            proxy: true,
            args_summary: this.summarizeArgs(args),
          });
        }

        if (proxyTier === 2) {
          // Check for anomalies specific to proxy calls
          const anomaly = this.detectAnomaly(operation, args);
          if (anomaly) {
            return this.requestApproval(operation, 2, `Proxy: ${anomaly.reason}`, {
              ...anomaly.context,
              proxy: true,
            });
          }
        }

        // Tier 2 with no anomaly or Tier 3: allow with audit logging
        this.auditLog.append("l2", `gate_allow_proxy:${toolName}`, "system", {
          tier: proxyTier,
          operation: toolName,
          proxy: true,
        });

        return {
          allowed: true,
          tier: proxyTier,
          reason: `Proxy operation allowed (Tier ${proxyTier})`,
          approval_required: false,
        };
      }
    }

    // ── Tier 1: Always requires approval ──────────────────────────────
    if (this.policy.tier1_always_approve.includes(operation)) {
      return this.requestApproval(operation, 1, `"${operation}" is a Tier 1 operation (always requires approval)`, {
        operation,
        args_summary: this.summarizeArgs(args),
      });
    }

    // ── Tier 2: Behavioral anomaly detection ──────────────────────────
    const anomaly = this.detectAnomaly(operation, args);
    if (anomaly) {
      return this.requestApproval(operation, 2, anomaly.reason, anomaly.context);
    }

    // ── Tier 3: Allow with audit logging (only for explicitly listed operations)
    if (this.policy.tier3_always_allow.includes(operation)) {
      this.auditLog.append("l2", `gate_allow:${operation}`, "system", {
        tier: 3,
        operation,
      });

      return {
        allowed: true,
        tier: 3,
        reason: "Operation allowed (Tier 3)",
        approval_required: false,
      };
    }

    // ── Unlisted operation: default to Tier 1 (require approval) ─────
    // SEC-011: Operations not classified in any tier must not auto-allow.
    // Safe default is to require human approval.
    this.auditLog.append("l2", `gate_unclassified:${operation}`, "system", {
      tier: 1,
      operation,
      warning: "Operation is not classified in any policy tier, defaulting to Tier 1 (require approval)",
    });

    return this.requestApproval(
      operation,
      1,
      `"${operation}" is not classified in any policy tier — requires approval (SEC-011 safe default)`,
      { operation, unclassified: true }
    );
  }

  /**
   * Detect Tier 2 behavioral anomalies.
   */
  private detectAnomaly(
    operation: string,
    args: Record<string, unknown>
  ): { reason: string; context: Record<string, unknown> } | null {
    const config = this.policy.tier2_anomaly;

    // ── First session check ───────────────────────────────────────────
    if (this.baseline.isFirstSession && config.first_session_policy === "approve") {
      // On first session, only Tier 3 operations are auto-allowed
      if (!this.policy.tier3_always_allow.includes(operation)) {
        return {
          reason: `First session: "${operation}" has no established baseline`,
          context: { operation, is_first_session: true },
        };
      }
    }

    // ── New namespace access ──────────────────────────────────────────
    if (config.new_namespace_access === "approve") {
      const namespace = args.namespace as string | undefined;
      if (namespace) {
        const isNew = this.baseline.recordNamespaceAccess(namespace);
        if (isNew) {
          return {
            reason: `First access to namespace "${namespace}" (not in session baseline)`,
            context: {
              operation,
              namespace,
              known_namespaces: this.baseline.getProfile().known_namespaces,
            },
          };
        }
      }
    } else if (config.new_namespace_access === "log") {
      const namespace = args.namespace as string | undefined;
      if (namespace) {
        this.baseline.recordNamespaceAccess(namespace);
      }
    }

    // ── New counterparty ──────────────────────────────────────────────
    if (config.new_counterparty === "approve") {
      const counterpartyDid =
        (args.counterparty_did as string) ?? (args.agent_identity_id as string);
      if (counterpartyDid) {
        const isNew = this.baseline.recordCounterparty(counterpartyDid);
        if (isNew) {
          return {
            reason: `First interaction with counterparty "${counterpartyDid}"`,
            context: {
              operation,
              counterparty_did: counterpartyDid,
              known_counterparties: this.baseline.getProfile().known_counterparties,
            },
          };
        }
      }
    } else if (config.new_counterparty === "log") {
      const counterpartyDid = args.counterparty_did as string;
      if (counterpartyDid) {
        this.baseline.recordCounterparty(counterpartyDid);
      }
    }

    // ── Signing frequency ─────────────────────────────────────────────
    if (operation === "identity_sign") {
      const signCount = this.baseline.recordSign();
      if (signCount > config.max_signs_per_minute) {
        return {
          reason: `Signing frequency (${signCount}/min) exceeds limit (${config.max_signs_per_minute}/min)`,
          context: {
            operation,
            signs_per_minute: signCount,
            limit: config.max_signs_per_minute,
          },
        };
      }
    }

    // ── Bulk read detection ───────────────────────────────────────────
    if (operation === "state_read") {
      const namespace = args.namespace as string | undefined;
      if (namespace) {
        const readCount = this.baseline.recordNamespaceRead(namespace);
        if (readCount > config.bulk_read_threshold) {
          return {
            reason: `Bulk read detected: ${readCount} reads from "${namespace}" in 60 seconds (threshold: ${config.bulk_read_threshold})`,
            context: {
              operation,
              namespace,
              reads_in_window: readCount,
              threshold: config.bulk_read_threshold,
            },
          };
        }
      }
    }

    // ── Frequency spike ───────────────────────────────────────────────
    const callRate = this.baseline.getCallRate(operation);
    const avgRate = this.baseline.getAverageCallRate();
    if (
      avgRate > 0 &&
      callRate > avgRate * config.frequency_spike_multiplier
    ) {
      return {
        reason: `Frequency spike: "${operation}" at ${callRate}/min (${config.frequency_spike_multiplier}× above average ${avgRate.toFixed(1)}/min)`,
        context: {
          operation,
          current_rate: callRate,
          average_rate: avgRate,
          multiplier: config.frequency_spike_multiplier,
        },
      };
    }

    return null;
  }

  /**
   * Request approval from the human principal.
   *
   * Fail-closed contract (full-sweep #49): if the channel throws (network
   * down, callback unreachable, dashboard SSE peer dropped, webhook DNS
   * failure, etc.), the gate denies the operation and audit-logs the cause.
   * Channel-internal timeouts already resolve with decision: "deny" per
   * SEC-002; this catch covers the remaining "channel raised" path so an
   * unhandled rejection cannot turn into an indeterminate state at the gate.
   */
  private async requestApproval(
    operation: string,
    tier: 1 | 2,
    reason: string,
    context: Record<string, unknown>
  ): Promise<GateResult> {
    const requestTimestamp = new Date().toISOString();
    const request: ApprovalRequest = {
      operation,
      tier,
      reason,
      context,
      timestamp: requestTimestamp,
    };

    // Fire `requested` lifecycle to the aggregator before the channel
    // round-trip. The correlation_id pins the resolution to the same
    // pending entry. Listener exceptions are swallowed (gate stays
    // load-bearing; aggregator is additive observation).
    const correlationId = `${requestTimestamp}:${operation}:${Math.random().toString(16).slice(2, 6)}`;
    if (this.onApprovalEvent) {
      try {
        this.onApprovalEvent({
          phase: "requested",
          operation,
          tier,
          reason,
          context,
          request_timestamp: requestTimestamp,
          correlation_id: correlationId,
        });
      } catch {
        // Never let the aggregator break the gate.
      }
    }

    let response: ApprovalResponse;
    try {
      response = await this.channel.requestApproval(request);
    } catch (err) {
      const errMessage = err instanceof Error ? err.message : String(err);
      const decidedAt = new Date().toISOString();
      this.auditLog.append("l2", `gate_deny:${operation}`, "system", {
        tier,
        reason,
        decided_by: "channel_failure",
        channel_error: errMessage,
      });
      if (this.onApprovalEvent) {
        try {
          this.onApprovalEvent({
            phase: "resolved",
            operation,
            tier,
            reason,
            context,
            request_timestamp: requestTimestamp,
            resolution: {
              decision: "deny",
              decided_at: decidedAt,
              decided_by: "channel_failure",
            },
            correlation_id: correlationId,
          });
        } catch {
          // swallow
        }
      }
      return {
        allowed: false,
        tier,
        reason: AGENT_VISIBLE_DENY_REASONS.REQUIRES_APPROVAL,
        approval_required: true,
        approval_response: {
          decision: "deny",
          decided_at: decidedAt,
          decided_by: "channel_failure",
        },
      };
    }

    // Audit log the decision
    this.auditLog.append("l2", `gate_${response.decision}:${operation}`, "system", {
      tier,
      reason,
      decided_by: response.decided_by,
    });

    // Fire `resolved` lifecycle to the aggregator. Castle-walking: the
    // gate's deny/accept logic is unchanged; this hook adds visibility,
    // not enforcement.
    if (this.onApprovalEvent) {
      try {
        this.onApprovalEvent({
          phase: "resolved",
          operation,
          tier,
          reason,
          context,
          request_timestamp: requestTimestamp,
          resolution: {
            decision: response.decision,
            decided_at: response.decided_at,
            decided_by: response.decided_by,
          },
          correlation_id: correlationId,
        });
      } catch {
        // swallow
      }
    }

    // Agent-facing denial reasons MUST NOT leak policy threshold values
    // (Sanctuary Invariant #7). The detailed `reason` flows into the audit
    // log and the out-of-band approval channel for the human reviewer; the
    // value returned to the caller becomes a generic string.
    return {
      allowed: response.decision === "approve",
      tier,
      reason: response.decision === "approve"
        ? `Approved by ${response.decided_by}`
        : AGENT_VISIBLE_DENY_REASONS.REQUIRES_APPROVAL,
      approval_required: true,
      approval_response: response,
    };
  }

  /**
   * Summarize tool arguments for the approval prompt.
   * Strips potentially large values to keep the prompt readable.
   */
  private summarizeArgs(args: Record<string, unknown>): Record<string, unknown> {
    const summary: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string" && value.length > 100) {
        summary[key] = value.slice(0, 100) + "...";
      } else {
        summary[key] = value;
      }
    }
    return summary;
  }

  /** Get the baseline tracker for saving at session end */
  getBaseline(): BaselineTracker {
    return this.baseline;
  }

  /** Get the injection detector for stats/configuration access */
  getInjectionDetector(): InjectionDetector {
    return this.injectionDetector;
  }
}
