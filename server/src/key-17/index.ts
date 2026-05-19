/**
 * Key 17 -- Cross-protocol sovereign signer surface.
 *
 * Barrel export for all Key 17 signing surfaces. Each surface derives
 * operator-scoped keys from a shared master key via HKDF with protocol-
 * specific tags.
 */

export {
  signX402Request,
  verifyX402Request,
  deriveX402Key,
  type X402Request,
  type SignedX402Request,
} from "./x402-signer.js";

export {
  signErc8004Registration,
  verifyErc8004Registration,
  deriveErc8004Key,
  publicKeyToAddress,
  type Erc8004Registration,
  type SignedErc8004Registration,
} from "./erc8004-identity-signer.js";

export {
  signAp2Mandate,
  verifyAp2Mandate,
  deriveAp2Key,
  type Ap2Mandate,
  type SignedAp2Mandate,
} from "./ap2-mandate-signer.js";

export {
  OperatorKeyService,
  type OperatorKeyInterface,
  type OperatorKeyServiceConfig,
} from "./operator-key-interface.js";

export {
  DefaultPolicyGate,
  SigningDeniedError,
  type PolicyGate,
  type PolicyGateConfig,
  type ProtocolPolicy,
  type CounterpartyRule,
  type PolicyDecision,
  type SigningApprovalRequest,
  type SigningAuditEvent,
} from "./policy-gate.js";
