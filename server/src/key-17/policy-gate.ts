/**
 * Key 17 -- Policy gate for sovereign-signer operations.
 *
 * Wraps the existing three-tier approval pattern: every signing call must
 * pass a policy check before the key material is used. The gate also
 * emits audit events so the audit chain records every signing decision.
 *
 * This module defines the interface and a reference implementation. The
 * reference implementation supports pre-approved counterparties, per-protocol
 * rules, and operator-approval-required as the default for unknown operations.
 */

/** Request to check signing approval. */
export interface SigningApprovalRequest {
  protocol: "x402" | "erc8004" | "ap2";
  operatorId: string;
  action: string;
  counterparty: string;
  metadata?: Record<string, unknown>;
}

/** Audit event emitted after a signing operation. */
export interface SigningAuditEvent {
  protocol: "x402" | "erc8004" | "ap2";
  operatorId: string;
  action: string;
  counterparty: string;
  success: boolean;
  error?: string;
}

/** Policy decision result. */
export type PolicyDecision = "allow" | "deny" | "operator_approval_required";

/** Per-counterparty approval rule. */
export interface CounterpartyRule {
  counterparty: string;
  decision: PolicyDecision;
}

/** Per-protocol policy configuration. */
export interface ProtocolPolicy {
  /** Default decision for this protocol when no counterparty rule matches. */
  default_decision: PolicyDecision;
  /** Counterparty-specific overrides. */
  counterparty_rules: CounterpartyRule[];
}

/** Full policy gate configuration. */
export interface PolicyGateConfig {
  x402?: ProtocolPolicy;
  erc8004?: ProtocolPolicy;
  ap2?: ProtocolPolicy;
  /** Global default when no protocol-specific policy exists. */
  global_default: PolicyDecision;
  /** Callback for operator approval prompts. Returns true if approved. */
  requestOperatorApproval?: (
    request: SigningApprovalRequest
  ) => Promise<boolean>;
  /** Callback for audit event emission. */
  onAuditEvent?: (event: SigningAuditEvent) => void;
}

/** Signing approval denied error. */
export class SigningDeniedError extends Error {
  constructor(
    public readonly protocol: string,
    public readonly reason: string
  ) {
    super(`Signing denied for ${protocol}: ${reason}`);
    this.name = "SigningDeniedError";
  }
}

/**
 * Policy gate interface. Implementations check approval and emit audit events.
 */
export interface PolicyGate {
  checkApproval(request: SigningApprovalRequest): Promise<void>;
  emitAuditEvent(event: SigningAuditEvent): void;
}

/**
 * Reference policy gate implementation.
 *
 * Evaluation order:
 * 1. Look up protocol-specific policy
 * 2. Check counterparty-specific rules
 * 3. Fall back to protocol default decision
 * 4. Fall back to global default
 *
 * "allow" proceeds silently. "deny" throws SigningDeniedError.
 * "operator_approval_required" invokes the approval callback; if the
 * callback is missing or returns false, the operation is denied.
 */
export class DefaultPolicyGate implements PolicyGate {
  private config: PolicyGateConfig;

  constructor(config: PolicyGateConfig) {
    this.config = config;
  }

  async checkApproval(request: SigningApprovalRequest): Promise<void> {
    const decision = this.evaluate(request);

    if (decision === "allow") return;

    if (decision === "deny") {
      throw new SigningDeniedError(
        request.protocol,
        "policy denies signing for this counterparty"
      );
    }

    // operator_approval_required
    if (!this.config.requestOperatorApproval) {
      throw new SigningDeniedError(
        request.protocol,
        "operator approval required but no approval channel configured"
      );
    }

    const approved = await this.config.requestOperatorApproval(request);
    if (!approved) {
      throw new SigningDeniedError(
        request.protocol,
        "operator denied the signing request"
      );
    }
  }

  emitAuditEvent(event: SigningAuditEvent): void {
    if (this.config.onAuditEvent) {
      this.config.onAuditEvent(event);
    }
  }

  private evaluate(request: SigningApprovalRequest): PolicyDecision {
    const protocolPolicy = this.config[request.protocol];
    if (!protocolPolicy) return this.config.global_default;

    const counterpartyRule = protocolPolicy.counterparty_rules.find(
      (r) =>
        r.counterparty === request.counterparty || r.counterparty === "*"
    );
    if (counterpartyRule) return counterpartyRule.decision;

    return protocolPolicy.default_decision;
  }
}
