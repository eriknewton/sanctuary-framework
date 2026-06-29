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
  resolveErc8004Identity,
  createErc8004ResolveTools,
  ERC8004_RESOLVE_AUDIT_OPS,
  type Erc8004ResolveResult,
  type Erc8004ResolveDeps,
  type Erc8004ResolveToolsOptions,
} from "./erc8004-resolve.js";

export {
  confirmErc8004RegistryOwner,
  erc8004IdentityRegistryOwnerOfAbi,
  erc8004RpcDestination,
  type Erc8004RegistryConfirmation,
  type Erc8004RegistryConfirmationConfig,
  type Erc8004RegistryConfirmationDeps,
  type Erc8004RegistryConfirmationInput,
  type Erc8004RegistryEgressDecision,
  type Erc8004RegistryEgressGate,
  type Erc8004RegistryEgressRequest,
  type Erc8004RegistryFetch,
} from "./erc8004-registry-confirm.js";

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
