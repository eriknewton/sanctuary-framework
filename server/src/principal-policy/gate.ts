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

import { randomBytes } from "node:crypto";
import type { PrincipalPolicy, GateResult, ApprovalRequest, ApprovalResponse } from "./types.js";
import type { ApprovalChannel } from "./approval-channel.js";
import { BaselineTracker } from "./baseline.js";
import {
  extractOperationName,
  FORCED_TIER3_OPERATIONS,
  NON_RELAXABLE_CLOUD_TIER1_OPERATIONS,
  NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS,
  NON_RELAXABLE_CASTLE_WALL_OBSERVE_TIER1_OPERATIONS,
} from "./loader.js";
import type { AuditLog } from "../operational/audit-log.js";
import { InjectionDetector, type DetectionResult } from "../security/injection-detector.js";
import { AGENT_VISIBLE_DENY_REASONS } from "./deny-vocabulary.js";
import {
  ApprovalProofStore,
  approvalEnvelopeHash,
  deriveTargetResource,
  normalizedArgsHash,
  resolveActiveSessionIdentity,
  type ApprovalRecord,
  type CanonicalApprovalEnvelope,
  type RiskTier,
  type SessionBinding,
} from "../agent-native/safety-base.js";

/** Callback invoked when an injection is detected, for dashboard broadcasting */
export type InjectionAlertCallback = (alert: {
  toolName: string;
  result: DetectionResult;
  timestamp: string;
}) => void;

/** Resolver for proxy tool tiers — provided by the ProxyRouter */
export type ProxyTierResolver = (toolName: string) => (1 | 2 | 3) | null;

// Runtime-classifier non-relaxable Tier-1 set. `memory_delete` plus the
// operator-cloud cloud-custody operations, the Governed File-Grant v1 mint
// operation, and the Castle Wall Observe / Learn Allow-List v1 promote
// operation, all spread from the SINGLE SOURCE OF TRUTH in loader.ts so
// this list and the loader's FORCED_TIER1_OPERATIONS cannot drift apart
// (Operator Cloud Slice 2 MED-1; a drift guard test pins the relationship).
// classifyRiskTier checks this list first, so even a policy file that lists
// these under Tier 3 still classifies them Tier 1 at runtime.
const FORCED_TIER1_OPERATIONS = [
  "memory_delete",
  ...NON_RELAXABLE_CLOUD_TIER1_OPERATIONS,
  ...NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS,
  ...NON_RELAXABLE_CASTLE_WALL_OBSERVE_TIER1_OPERATIONS,
] as const;

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
  /**
   * Canonical normalized-args hash (`normalizedArgsHash`, identical to the
   * direct approval-proof envelope's `normalized_args_hash`). Folded into the
   * aggregator dedup key and the redirect-channel match key so two same-op
   * same-ms DIFFERENT-args requests resolve to two distinct inbox cards and
   * two distinct waiters (closes approval amplification). Absent on argless
   * escalation paths. See `ApprovalRequest.args_binding`.
   */
  args_binding?: string;
  /** Operator-card disambiguation label (`deriveTargetResource`). */
  target_resource?: string;
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
  private approvalProofStore: ApprovalProofStore;
  private currentSessionBinding?: () => SessionBinding | undefined;

  constructor(
    policy: PrincipalPolicy,
    baseline: BaselineTracker,
    channel: ApprovalChannel,
    auditLog: AuditLog,
    injectionDetector?: InjectionDetector,
    onInjectionAlert?: InjectionAlertCallback,
    onApprovalEvent?: ApprovalEventCallback,
    options?: {
      approvalProofStore?: ApprovalProofStore;
      currentSessionBinding?: () => SessionBinding | undefined;
    }
  ) {
    this.policy = policy;
    this.baseline = baseline;
    this.channel = channel;
    this.auditLog = auditLog;
    this.injectionDetector = injectionDetector ?? new InjectionDetector();
    this.onInjectionAlert = onInjectionAlert;
    this.onApprovalEvent = onApprovalEvent;
    this.approvalProofStore = options?.approvalProofStore ?? new ApprovalProofStore();
    this.currentSessionBinding = options?.currentSessionBinding;
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
    args: Record<string, unknown>,
    approval?: { approval_ref: string }
  ): Promise<GateResult> {
    const operation = extractOperationName(toolName);

    // Record the tool call in the baseline tracker
    this.baseline.recordToolCall(operation);

    // ── HABEAS PORT: forced-Tier-3 distress carve-out ─────────────────
    // The distress channel must be allowed BEFORE any layer that can deny:
    // injection blocking, anomaly escalation, and tier classification can
    // each route an operation into denial or an approval wait, and any of
    // them sitting in front of distress would let the policy layer (or a
    // dead approval channel) silence it. The payload itself is structurally
    // bounded by the tool (closed enums + truncated detail), every use is
    // audited, and the emission surface is rate-limited — so the carve-out
    // does not open a data lane. The injection scan still runs for its
    // SIGNAL value (flagged scans are audited) but never blocks here.
    // The carve-out requires the EXACT bare tool name — `toolName ===
    // operation` rejects legacy "sanctuary/"-prefixed and proxy-namespaced
    // spellings, so no aliased or namespaced caller can reach the forced
    // allow with a name that merely EXTRACTS to the distress operation
    // (codex round-1 finding 3).
    if (
      toolName === operation &&
      (FORCED_TIER3_OPERATIONS as readonly string[]).includes(operation)
    ) {
      const distressScan = this.injectionDetector.scan(toolName, args);
      await this.auditLog.appendCritical({
        layer: "l2",
        operation: `gate_allow:${operation}`,
        identity_id: "system",
        result: "success",
        details: {
          tier: 3,
          operation,
          habeas_forced_tier3: true,
          ...(distressScan.flagged
            ? {
                injection_flagged: true,
                injection_confidence: distressScan.confidence,
                injection_signal_count: distressScan.signals.length,
              }
            : {}),
        },
      });
      return {
        allowed: true,
        tier: 3,
        reason: "Reserved habeas distress channel (always allowed, always audited)",
        approval_required: false,
      };
    }

    // ── Pre-check: Prompt injection detection ────────────────────────
    const injectionResult = this.injectionDetector.scan(toolName, args);
    if (injectionResult.flagged) {
      await this.auditLog.append("l2", `injection_detected:${operation}`, "system", {
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
        await this.auditLog.appendCritical({
          layer: "l2",
          operation: `gate_injection_block:${operation}`,
          identity_id: "system",
          result: "failure",
          details: {
            tier: 1,
            operation,
            injection_confidence: injectionResult.confidence,
            signal_count: injectionResult.signals.length,
          },
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
          },
          undefined,
          this.buildRequestBinding(operation, args)
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
          }, undefined, this.buildRequestBinding(operation, args));
        }

        if (proxyTier === 2) {
          // Check for anomalies specific to proxy calls
          const anomaly = this.detectAnomaly(operation, args);
          if (anomaly) {
            return this.requestApproval(operation, 2, `Proxy: ${anomaly.reason}`, {
              ...anomaly.context,
              proxy: true,
            }, anomaly.commit, this.buildRequestBinding(operation, args));
          }
        }

        // Tier 2 with no anomaly or Tier 3: allow with audit logging
        await this.auditLog.appendCritical({
          layer: "l2",
          operation: `gate_allow_proxy:${toolName}`,
          identity_id: "system",
          result: "success",
          details: {
            tier: proxyTier,
            operation: toolName,
            proxy: true,
          },
        });

        return {
          allowed: true,
          tier: proxyTier,
          reason: `Proxy operation allowed (Tier ${proxyTier})`,
          approval_required: false,
        };
      }
    }

    const classification = this.classifyOperation(toolName, args);

    if (approval) {
      return this.verifyApprovalProof(toolName, args, approval.approval_ref, classification);
    }

    // Args-binding for the redirect-inbox approval path. Reuses the EXACT
    // normalization the direct approval-proof envelope binds
    // (`normalizedArgsHash` / `deriveTargetResource` from
    // agent-native/safety-base) so the `replace`-mode redirect channel gains
    // identical args-binding. Without this, the redirect path keyed every
    // approval solely on `<timestamp>:<operation>`, so two same-op same-ms
    // requests with different args (e.g. state_export of PUBLIC vs SECRET)
    // deduped to ONE inbox card with TWO waiters and a single benign
    // approval settled both — violating Invariant #3 (irreversible op
    // requires human approval of THAT op). The binding splits them into two
    // cards / two waiters so each is decided independently.
    const requestBinding = this.buildRequestBinding(operation, args);

    // ── Tier 1: Always requires approval ──────────────────────────────
    if (classification.tier === 1) {
      if (classification.unclassified) {
        await this.auditLog.appendCritical({
          layer: "l2",
          operation: `gate_unclassified:${operation}`,
          identity_id: "system",
          result: "success",
          details: {
            tier: 1,
            operation,
            warning: "Operation is not classified in any policy tier, defaulting to Tier 1 (require approval)",
          },
        });
      }
      return this.requestApproval(operation, 1, classification.reason, {
        operation,
        args_summary: this.summarizeArgs(args),
        ...(classification.unclassified ? { unclassified: true } : {}),
      }, undefined, requestBinding);
    }

    // ── Tier 2: Behavioral anomaly detection ──────────────────────────
    if (classification.tier === 2 && classification.anomaly) {
      return this.requestApproval(
        operation,
        2,
        classification.anomaly.reason,
        classification.anomaly.context,
        classification.anomaly.commit,
        requestBinding
      );
    }

    // ── Tier 3: Allow with audit logging (only for explicitly listed operations)
    if (classification.tier === 3) {
      await this.auditLog.appendCritical({
        layer: "l2",
        operation: `gate_allow:${operation}`,
        identity_id: "system",
        result: "success",
        details: {
          tier: 3,
          operation,
        },
      });

      return {
        allowed: true,
        tier: 3,
        reason: "Operation allowed (Tier 3)",
        approval_required: false,
      };
    }

    return this.requestApproval(operation, 1, classification.reason, {
      operation,
      unclassified: true,
    }, undefined, requestBinding);
  }

  classifyRiskTier(toolName: string, args: Record<string, unknown>): RiskTier {
    return this.classifyOperation(toolName, args, { dryRun: true }).tier;
  }

  createApprovedProof(params: {
    toolName: string;
    args: Record<string, unknown>;
    session: SessionBinding;
    planHash?: `sha256:${string}`;
    stepId?: string;
    expiresAt?: string;
    auditId?: string;
  }): ApprovalRecord {
    const active = resolveActiveSessionIdentity(params.session);
    const riskTier = this.classifyRiskTier(params.toolName, params.args);
    const envelope: CanonicalApprovalEnvelope = {
      tool_name: extractOperationName(params.toolName),
      normalized_args_hash: normalizedArgsHash(params.args),
      requester_identity_fingerprint: active.requester_identity_fingerprint,
      target_resource: deriveTargetResource(extractOperationName(params.toolName), params.args),
      risk_tier: riskTier,
      ...(params.planHash ? { plan_hash: params.planHash } : {}),
      ...(params.stepId ? { step_id: params.stepId } : {}),
      expires_at: params.expiresAt ?? new Date(Date.now() + 5 * 60_000).toISOString(),
      nonce: randomBytes(16).toString("hex"),
      audit_id: params.auditId ?? `audit:approval:${Date.now()}`,
    };
    return this.approvalProofStore.createApproved(envelope);
  }

  private classifyOperation(
    toolName: string,
    args: Record<string, unknown>,
    options: { dryRun?: boolean } = {}
  ): {
    tier: RiskTier;
    reason: string;
    anomaly?: { reason: string; context: Record<string, unknown>; commit?: () => void };
    unclassified?: boolean;
  } {
    const operation = extractOperationName(toolName);

    if ((FORCED_TIER1_OPERATIONS as readonly string[]).includes(operation)) {
      return {
        tier: 1,
        reason: `"${operation}" is a forced Tier 1 operation (always requires approval)`,
      };
    }

    if (this.policy.tier1_always_approve.includes(operation)) {
      return {
        tier: 1,
        reason: `"${operation}" is a Tier 1 operation (always requires approval)`,
      };
    }

    const anomaly = this.detectAnomaly(operation, args, options);
    if (anomaly) {
      return { tier: 2, reason: anomaly.reason, anomaly };
    }

    if (this.policy.tier3_always_allow.includes(operation)) {
      return { tier: 3, reason: "Operation allowed (Tier 3)" };
    }

    return {
      tier: 1,
      reason: `"${operation}" is not classified in any policy tier — requires approval (SEC-011 safe default)`,
      unclassified: true,
    };
  }

  private async verifyApprovalProof(
    toolName: string,
    args: Record<string, unknown>,
    approvalRef: string,
    classification: { tier: RiskTier }
  ): Promise<GateResult> {
    let active;
    try {
      active = resolveActiveSessionIdentity(this.currentSessionBinding?.());
    } catch {
      return this.denyProof(toolName, args, classification.tier);
    }

    const record = this.approvalProofStore.get(approvalRef);
    if (!record) {
      return this.denyProof(toolName, args, classification.tier);
    }

    const rebuilt: CanonicalApprovalEnvelope = {
      ...record.envelope,
      tool_name: extractOperationName(toolName),
      normalized_args_hash: normalizedArgsHash(args),
      requester_identity_fingerprint: active.requester_identity_fingerprint,
      target_resource: deriveTargetResource(extractOperationName(toolName), args),
      risk_tier: classification.tier,
    };

    const proofMatches =
      approvalEnvelopeHash(rebuilt) === record.envelope_hash &&
      record.decision === "approved" &&
      record.envelope.plan_hash === undefined &&
      record.envelope.step_id === undefined &&
      Date.parse(record.envelope.expires_at) > Date.now() &&
      rebuilt.requester_identity_fingerprint === record.envelope.requester_identity_fingerprint &&
      rebuilt.nonce === record.envelope.nonce &&
      rebuilt.target_resource === record.envelope.target_resource &&
      rebuilt.tool_name === record.envelope.tool_name;

    if (!proofMatches) {
      return this.denyProof(toolName, args, classification.tier);
    }

    const consumed = this.approvalProofStore.consumeIfUnconsumed(approvalRef);
    if (!consumed) {
      return this.denyProof(toolName, args, classification.tier);
    }

    await this.auditLog.appendCritical({
      layer: "l2",
      operation: `gate_approval_proof:${extractOperationName(toolName)}`,
      identity_id: active.identity_id,
      result: "success",
      details: {
        tier: classification.tier,
        approval_ref: approvalRef,
        envelope_hash: record.envelope_hash,
      },
    });

    return {
      allowed: true,
      tier: classification.tier,
      reason: "Approval proof verified",
      approval_required: classification.tier !== 3,
      approval_response: {
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      },
    };
  }

  private async denyProof(
    toolName: string,
    args: Record<string, unknown>,
    tier: RiskTier
  ): Promise<GateResult> {
    await this.auditLog.appendCritical({
      layer: "l2",
      operation: `gate_deny:${extractOperationName(toolName)}`,
      identity_id: "system",
      result: "failure",
      details: {
        tier,
        approval_proof: "invalid",
        args_hash: normalizedArgsHash(args),
      },
    });
    return {
      allowed: false,
      tier,
      reason: AGENT_VISIBLE_DENY_REASONS.NOT_PERMITTED,
      approval_required: tier !== 3,
    };
  }

  /**
   * Detect Tier 2 behavioral anomalies.
   */
  private detectAnomaly(
    operation: string,
    args: Record<string, unknown>,
    options: { dryRun?: boolean } = {}
  ): { reason: string; context: Record<string, unknown>; commit?: () => void } | null {
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
      if (namespace && this.baseline.isNewNamespace(namespace)) {
        // Non-mutating check: do NOT record yet. The namespace is committed to
        // the baseline only if the operator APPROVES (see requestApproval's
        // onApprove). A denied probe must not poison the baseline and suppress
        // future anomaly detection for this namespace.
        return {
          reason: `First access to namespace "${namespace}" (not in session baseline)`,
          context: {
            operation,
            namespace,
            known_namespaces: this.baseline.getProfile().known_namespaces,
          },
          commit: () => {
            this.baseline.recordNamespaceAccess(namespace);
          },
        };
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
      if (counterpartyDid && this.baseline.isNewCounterparty(counterpartyDid)) {
        // Non-mutating check; commit the counterparty only on approval (see the
        // namespace branch) so a denied probe cannot poison the baseline.
        return {
          reason: `First interaction with counterparty "${counterpartyDid}"`,
          context: {
            operation,
            counterparty_did: counterpartyDid,
            known_counterparties: this.baseline.getProfile().known_counterparties,
          },
          commit: () => {
            this.baseline.recordCounterparty(counterpartyDid);
          },
        };
      }
    } else if (config.new_counterparty === "log") {
      const counterpartyDid = args.counterparty_did as string;
      if (counterpartyDid) {
        this.baseline.recordCounterparty(counterpartyDid);
      }
    }

    // ── Signing frequency ─────────────────────────────────────────────
    if (operation === "identity_sign") {
      const signCount = options.dryRun ? 0 : this.baseline.recordSign();
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
        const readCount = options.dryRun ? 0 : this.baseline.recordNamespaceRead(namespace);
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
    context: Record<string, unknown>,
    onApprove?: () => void,
    // Args-binding for the redirect-inbox match/dedup key. `argsHash` is the
    // gate's `normalizedArgsHash` — the SAME normalization the direct
    // approval-proof envelope binds via `normalized_args_hash` — so the
    // `replace`-mode redirect path gains identical args-binding and two
    // same-op same-ms DIFFERENT-args requests resolve to two distinct cards
    // and two distinct waiters (closes approval amplification). Optional so
    // the argless escalation paths (e.g. injection-escalate) keep their
    // historic `<timestamp>:<operation>` key. `targetResource` is
    // display-only (operator card disambiguation).
    binding?: { argsHash: string; targetResource?: string }
  ): Promise<GateResult> {
    const requestTimestamp = new Date().toISOString();
    const request: ApprovalRequest = {
      operation,
      tier,
      reason,
      context,
      timestamp: requestTimestamp,
      ...(binding ? { args_binding: binding.argsHash } : {}),
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
          ...(binding ? { args_binding: binding.argsHash } : {}),
          ...(binding?.targetResource
            ? { target_resource: binding.targetResource }
            : {}),
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
      await this.auditLog.appendCritical({
        layer: "l2",
        operation: `gate_deny:${operation}`,
        identity_id: "system",
        result: "failure",
        details: {
          tier,
          reason,
          decided_by: "channel_failure",
          channel_error: errMessage,
        },
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
            ...(binding ? { args_binding: binding.argsHash } : {}),
            ...(binding?.targetResource
              ? { target_resource: binding.targetResource }
              : {}),
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
    await this.auditLog.appendCritical({
      layer: "l2",
      operation: `gate_${response.decision}:${operation}`,
      identity_id: "system",
      result: response.decision === "approve" ? "success" : "failure",
      details: {
        tier,
        reason,
        decided_by: response.decided_by,
      },
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
          ...(binding ? { args_binding: binding.argsHash } : {}),
          ...(binding?.targetResource
            ? { target_resource: binding.targetResource }
            : {}),
        });
      } catch {
        // swallow
      }
    }

    // Commit deferred baseline state ONLY on approval. detectAnomaly computes
    // "is new" without mutating; the namespace/counterparty is recorded here so
    // a DENIED approval cannot poison the baseline and suppress future anomaly
    // detection. Wrapped so a baseline error can never alter the gate verdict.
    if (response.decision === "approve" && onApprove) {
      try {
        onApprove();
      } catch {
        // Baseline commit is best-effort; never let it change the gate result.
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
    // Hard Constraint #1: the approval context built from these args can be
    // sent to an external webhook / dashboard BEFORE approval, so it must
    // carry operation METADATA only, never secret content. Redact
    // secret-named fields, and summarize objects/arrays to shape so a nested
    // secret (e.g. an identity object's encrypted_private_key) cannot leak.
    const SENSITIVE_ARG_NAME =
      /pass(phrase|word)|secret|private_key|recovery_key|master_key|seed_phrase|mnemonic|credential/i;
    const summary: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args)) {
      if (SENSITIVE_ARG_NAME.test(key)) {
        summary[key] = "[redacted]";
      } else if (typeof value === "string") {
        summary[key] = value.length > 100 ? value.slice(0, 100) + "..." : value;
      } else if (value !== null && typeof value === "object") {
        summary[key] = Array.isArray(value)
          ? `[array(${value.length})]`
          : `[object(${Object.keys(value as Record<string, unknown>).length} keys)]`;
      } else {
        summary[key] = value;
      }
    }
    return summary;
  }

  /**
   * Build the redirect-inbox args-binding for an approval request. The
   * `argsHash` (gate's `normalizedArgsHash`, identical to the direct
   * proof envelope's `normalized_args_hash`) is the security-load-bearing
   * field; `targetResource` is display-only. `deriveTargetResource` can
   * throw on a malformed state bundle, so it is wrapped — a bad bundle
   * degrades the operator card label but must never crash the gate or
   * weaken the hash binding.
   */
  private buildRequestBinding(
    operation: string,
    args: Record<string, unknown>
  ): { argsHash: string; targetResource?: string } {
    let targetResource: string | undefined;
    try {
      targetResource = deriveTargetResource(operation, args);
    } catch {
      targetResource = undefined;
    }
    return { argsHash: normalizedArgsHash(args), targetResource };
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
