/**
 * Key 17 -- Unified operator key interface.
 *
 * Single entrypoint for the three sovereign-signer surfaces. Each method
 * routes through a policy gate check before signing. The policy gate
 * enforces operator-approved signing for non-pre-approved operations.
 */

import type { X402Request, SignedX402Request } from "./x402-signer.js";
import type {
  Erc8004Registration,
  SignedErc8004Registration,
} from "./erc8004-identity-signer.js";
import type { Ap2Mandate, SignedAp2Mandate } from "./ap2-mandate-signer.js";
import { signX402Request } from "./x402-signer.js";
import { signErc8004Registration } from "./erc8004-identity-signer.js";
import { signAp2Mandate } from "./ap2-mandate-signer.js";
import type { PolicyGate } from "./policy-gate.js";

/** Unified interface for all Key 17 signing operations. */
export interface OperatorKeyInterface {
  signX402(
    operatorId: string,
    request: X402Request
  ): Promise<SignedX402Request>;
  signErc8004Identity(
    operatorId: string,
    reg: Erc8004Registration
  ): Promise<SignedErc8004Registration>;
  signAp2Mandate(
    operatorId: string,
    mandate: Ap2Mandate
  ): Promise<SignedAp2Mandate>;
}

/** Configuration for the operator key service. */
export interface OperatorKeyServiceConfig {
  masterKey: Uint8Array;
  policyGate: PolicyGate;
}

/**
 * Concrete implementation of the unified operator key interface.
 *
 * Each method:
 * 1. Checks policy gate approval for the specific protocol + operator
 * 2. Signs with the protocol-specific sub-signer
 * 3. Emits an audit event via the policy gate
 */
export class OperatorKeyService implements OperatorKeyInterface {
  private masterKey: Uint8Array;
  private policyGate: PolicyGate;

  constructor(config: OperatorKeyServiceConfig) {
    this.masterKey = config.masterKey;
    this.policyGate = config.policyGate;
  }

  async signX402(
    operatorId: string,
    request: X402Request
  ): Promise<SignedX402Request> {
    await this.policyGate.checkApproval({
      protocol: "x402",
      operatorId,
      action: "sign_request",
      counterparty: request.counterparty,
      metadata: { amount: request.amount, currency: request.currency },
    });
    const signed = signX402Request(this.masterKey, operatorId, request);
    this.policyGate.emitAuditEvent({
      protocol: "x402",
      operatorId,
      action: "sign_request",
      counterparty: request.counterparty,
      success: true,
    });
    return signed;
  }

  async signErc8004Identity(
    operatorId: string,
    reg: Erc8004Registration
  ): Promise<SignedErc8004Registration> {
    await this.policyGate.checkApproval({
      protocol: "erc8004",
      operatorId,
      action: "sign_registration",
      counterparty: reg.registry,
      metadata: { identity: reg.identity, chain_id: reg.chain_id },
    });
    const signed = signErc8004Registration(this.masterKey, operatorId, reg);
    this.policyGate.emitAuditEvent({
      protocol: "erc8004",
      operatorId,
      action: "sign_registration",
      counterparty: reg.registry,
      success: true,
    });
    return signed;
  }

  async signAp2Mandate(
    operatorId: string,
    mandate: Ap2Mandate
  ): Promise<SignedAp2Mandate> {
    await this.policyGate.checkApproval({
      protocol: "ap2",
      operatorId,
      action: "sign_mandate",
      counterparty: mandate.target,
      metadata: {
        mandate_type: mandate.mandate_type,
        spec_version: mandate.spec_version,
      },
    });
    const signed = signAp2Mandate(this.masterKey, operatorId, mandate);
    this.policyGate.emitAuditEvent({
      protocol: "ap2",
      operatorId,
      action: "sign_mandate",
      counterparty: mandate.target,
      success: true,
    });
    return signed;
  }
}
