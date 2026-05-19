import { registerFixture } from "../../registry.js";
import { OperatorKeyService } from "../../../../server/src/key-17/operator-key-interface.js";
import { DefaultPolicyGate } from "../../../../server/src/key-17/policy-gate.js";
import { verifyAp2Mandate } from "../../../../server/src/key-17/ap2-mandate-signer.js";
import { verifyErc8004Registration } from "../../../../server/src/key-17/erc8004-identity-signer.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { DEFAULT_POLICY } from "../../../../server/src/principal-policy/loader.js";

// Recon: canonical raw-sign guard is DEFAULT_POLICY plus Key 17 signer
// services, mirrored by tool-registry and key-17 tests. Maps to row 19.
const CLAIM_ID = "19";
const CLAIM_LABEL = "Identity signing authority (PR #270, raw identity_sign Tier 1)";
const DOMAIN_SEPARATED_SIGN_TOOL = "sanctuary_sign_challenge";
const DOMAIN_PREFIX = "sanctuary-sign-challenge-v1";

function policyAllowsDomainSeparatedSignTool(): boolean {
  return (
    DEFAULT_POLICY.tier2_anomaly.first_session_policy === "approve" &&
    DEFAULT_POLICY.tier1_always_approve.includes("identity_sign") &&
    !DEFAULT_POLICY.tier3_always_allow.includes("identity_sign") &&
    !DEFAULT_POLICY.tier1_always_approve.includes(DOMAIN_SEPARATED_SIGN_TOOL)
  );
}

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "identity-signing-tool-registry-guard: tool-registry sign permitted",
  async () => {
    const start = performance.now();
    return {
      passed: policyAllowsDomainSeparatedSignTool(),
      message: DOMAIN_PREFIX,
      durationMs: performance.now() - start,
    };
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "identity-signing-tool-registry-guard: raw sign rejected",
  async () => {
    const start = performance.now();
    const rawSignIsTier1 =
      DEFAULT_POLICY.tier1_always_approve.includes("identity_sign") &&
      !DEFAULT_POLICY.tier3_always_allow.includes("identity_sign");
    return {
      passed: rawSignIsTier1,
      message: rawSignIsTier1 ? "identity_sign is tier1" : "identity_sign escaped tier1",
      durationMs: performance.now() - start,
    };
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "identity-signing-tool-registry-guard: AP2 mandate sign via Key 17 permitted",
  async () => {
    const start = performance.now();
    const service = new OperatorKeyService({
      masterKey: generateRandomKey(),
      policyGate: new DefaultPolicyGate({ global_default: "allow" }),
    });
    const signed = await service.signAp2Mandate("operator-fixture", {
      mandate_type: "payment",
      issuer: "operator-fixture",
      target: "agent-service",
      payload: { amount: "100", currency: "USD" },
      issued_at: "2026-05-19T12:00:00Z",
      expires_at: "2026-05-19T13:00:00Z",
      nonce: "ap2-fixture-nonce",
      spec_version: "1.0",
    });
    return {
      passed: verifyAp2Mandate(signed),
      durationMs: performance.now() - start,
    };
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "identity-signing-tool-registry-guard: ERC-8004 identity sign via Key 17 permitted",
  async () => {
    const start = performance.now();
    const service = new OperatorKeyService({
      masterKey: generateRandomKey(),
      policyGate: new DefaultPolicyGate({ global_default: "allow" }),
    });
    const signed = await service.signErc8004Identity("operator-fixture", {
      identity: "did:sanctuary:operator-fixture",
      registry: "0x1234567890abcdef1234567890abcdef12345678",
      chain_id: 1,
      nonce: 1,
      timestamp: "2026-05-19T12:00:00Z",
    });
    return {
      passed: verifyErc8004Registration(signed),
      durationMs: performance.now() - start,
    };
  },
);
