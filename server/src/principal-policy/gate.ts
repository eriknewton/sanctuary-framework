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

import type { PrincipalPolicy, GateResult, ApprovalRequest } from "./types.js";
import type { ApprovalChannel } from "./approval-channel.js";
import { BaselineTracker } from "./baseline.js";
import { extractOperationName } from "./loader.js";
import type { AuditLog } from "../l2-operational/audit-log.js";

export class ApprovalGate {
  private policy: PrincipalPolicy;
  private baseline: BaselineTracker;
  private channel: ApprovalChannel;
  private auditLog: AuditLog;

  constructor(
    policy: PrincipalPolicy,
    baseline: BaselineTracker,
    channel: ApprovalChannel,
    auditLog: AuditLog
  ) {
    this.policy = policy;
    this.baseline = baseline;
    this.channel = channel;
    this.auditLog = auditLog;
  }

  /**
   * Evaluate a tool call against the Principal Policy.
   *
   * @param toolName - Full MCP tool name (e.g., "sanctuary/state_export")
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
      warning: "Operation is not classified in any policy tier — defaulting to Tier 1 (require approval)",
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
   */
  private async requestApproval(
    operation: string,
    tier: 1 | 2,
    reason: string,
    context: Record<string, unknown>
  ): Promise<GateResult> {
    const request: ApprovalRequest = {
      operation,
      tier,
      reason,
      context,
      timestamp: new Date().toISOString(),
    };

    const response = await this.channel.requestApproval(request);

    // Audit log the decision
    this.auditLog.append("l2", `gate_${response.decision}:${operation}`, "system", {
      tier,
      reason,
      decided_by: response.decided_by,
    });

    return {
      allowed: response.decision === "approve",
      tier,
      reason: response.decision === "approve"
        ? `Approved by ${response.decided_by}`
        : reason,
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
}
