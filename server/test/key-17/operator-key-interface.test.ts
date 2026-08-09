/**
 * Key 17 -- Unified operator key interface + policy gate tests.
 *
 * Exercises unified interface routing, policy gate decisions (allow, deny,
 * operator_approval_required), audit event emission, and counterparty rules.
 */

import { describe, it, expect, vi } from "vitest";
import { randomBytes } from "../../src/core/random.js";
import { OperatorKeyService } from "../../src/key-17/operator-key-interface.js";
import {
  DefaultPolicyGate,
  SigningDeniedError,
} from "../../src/key-17/policy-gate.js";
import type { X402Request } from "../../src/key-17/x402-signer.js";
import type { Erc8004Registration } from "../../src/key-17/erc8004-identity-signer.js";
import type { Ap2Mandate } from "../../src/key-17/ap2-mandate-signer.js";
import { verifyX402Request } from "../../src/key-17/x402-signer.js";
import { verifyErc8004Registration } from "../../src/key-17/erc8004-identity-signer.js";
import { verifyAp2Mandate } from "../../src/key-17/ap2-mandate-signer.js";

const masterKey = randomBytes(32);
const operatorId = "operator-test";

function makeX402(): X402Request {
  return {
    amount: "500",
    currency: "USDC",
    counterparty: "agent-seller",
    timestamp: "2026-05-18T12:00:00Z",
    nonce: "test-nonce",
  };
}

function makeErc8004(): Erc8004Registration {
  return {
    identity: "did:sanctuary:operator-test",
    registry: "0x1234567890abcdef1234567890abcdef12345678",
    chain_id: 1,
    nonce: 1,
    timestamp: "2026-05-18T12:00:00Z",
  };
}

function makeAp2(): Ap2Mandate {
  return {
    mandate_type: "payment",
    issuer: "operator-test",
    target: "agent-service",
    payload: { amount: "100" },
    issued_at: "2026-05-18T12:00:00Z",
    expires_at: "2026-05-18T13:00:00Z",
    nonce: "ap2-nonce",
    spec_version: "1.0",
  };
}

describe("OperatorKeyService", () => {
  describe("unified interface invokes correct sub-signer", () => {
    const gate = new DefaultPolicyGate({ global_default: "allow" });
    const service = new OperatorKeyService({ masterKey, policyGate: gate });

    it("signX402 produces a valid x402 signature", async () => {
      const signed = await service.signX402(operatorId, makeX402());
      expect(signed.algorithm).toBe("EdDSA");
      expect(
        verifyX402Request(signed, { trustedPublicKey: signed.public_key }).valid
      ).toBe(true);
    });

    it("signErc8004Identity produces a valid ERC-8004 signature", async () => {
      const signed = await service.signErc8004Identity(
        operatorId,
        makeErc8004()
      );
      expect(signed.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
      expect(verifyErc8004Registration(signed)).toBe(true);
    });

    it("signAp2Mandate produces a valid AP2 signature", async () => {
      const signed = await service.signAp2Mandate(operatorId, makeAp2());
      expect(signed.algorithm).toBe("EdDSA");
      expect(
        verifyAp2Mandate(signed, { trustedPublicKey: signed.public_key }).valid
      ).toBe(true);
    });
  });

  describe("policy gate denial blocks signing", () => {
    it("denies x402 signing when policy says deny", async () => {
      const gate = new DefaultPolicyGate({
        global_default: "deny",
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      await expect(
        service.signX402(operatorId, makeX402())
      ).rejects.toThrow(SigningDeniedError);
    });

    it("denies ERC-8004 signing when protocol policy says deny", async () => {
      const gate = new DefaultPolicyGate({
        global_default: "allow",
        erc8004: {
          default_decision: "deny",
          counterparty_rules: [],
        },
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      await expect(
        service.signErc8004Identity(operatorId, makeErc8004())
      ).rejects.toThrow(SigningDeniedError);
    });

    it("denies AP2 signing when operator declines approval", async () => {
      const gate = new DefaultPolicyGate({
        global_default: "operator_approval_required",
        requestOperatorApproval: async () => false,
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      await expect(
        service.signAp2Mandate(operatorId, makeAp2())
      ).rejects.toThrow(SigningDeniedError);
    });
  });

  describe("policy gate approval prompt", () => {
    it("allows signing when operator approves", async () => {
      const approvalFn = vi.fn().mockResolvedValue(true);
      const gate = new DefaultPolicyGate({
        global_default: "operator_approval_required",
        requestOperatorApproval: approvalFn,
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      const signed = await service.signX402(operatorId, makeX402());
      expect(
        verifyX402Request(signed, { trustedPublicKey: signed.public_key }).valid
      ).toBe(true);
      expect(approvalFn).toHaveBeenCalledTimes(1);
      expect(approvalFn).toHaveBeenCalledWith(
        expect.objectContaining({
          protocol: "x402",
          operatorId,
          action: "sign_request",
        })
      );
    });

    it("denies when no approval channel configured", async () => {
      const gate = new DefaultPolicyGate({
        global_default: "operator_approval_required",
        // no requestOperatorApproval callback
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      await expect(
        service.signX402(operatorId, makeX402())
      ).rejects.toThrow("no approval channel configured");
    });
  });

  describe("audit chain captures signing events", () => {
    it("emits audit event on successful signing", async () => {
      const auditEvents: unknown[] = [];
      const gate = new DefaultPolicyGate({
        global_default: "allow",
        onAuditEvent: (event) => auditEvents.push(event),
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      await service.signX402(operatorId, makeX402());
      await service.signErc8004Identity(operatorId, makeErc8004());
      await service.signAp2Mandate(operatorId, makeAp2());

      expect(auditEvents).toHaveLength(3);
      expect(auditEvents[0]).toMatchObject({
        protocol: "x402",
        action: "sign_request",
        success: true,
      });
      expect(auditEvents[1]).toMatchObject({
        protocol: "erc8004",
        action: "sign_registration",
        success: true,
      });
      expect(auditEvents[2]).toMatchObject({
        protocol: "ap2",
        action: "sign_mandate",
        success: true,
      });
    });
  });

  describe("counterparty-specific rules", () => {
    it("allows pre-approved counterparty despite deny default", async () => {
      const gate = new DefaultPolicyGate({
        global_default: "deny",
        x402: {
          default_decision: "deny",
          counterparty_rules: [
            { counterparty: "agent-seller", decision: "allow" },
          ],
        },
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      const signed = await service.signX402(operatorId, makeX402());
      expect(
        verifyX402Request(signed, { trustedPublicKey: signed.public_key }).valid
      ).toBe(true);
    });

    it("denies non-approved counterparty despite allow default for other protocols", async () => {
      const gate = new DefaultPolicyGate({
        global_default: "allow",
        x402: {
          default_decision: "deny",
          counterparty_rules: [
            { counterparty: "trusted-only", decision: "allow" },
          ],
        },
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      await expect(
        service.signX402(operatorId, makeX402())
      ).rejects.toThrow(SigningDeniedError);
    });

    it("wildcard counterparty rule applies to all", async () => {
      const gate = new DefaultPolicyGate({
        global_default: "deny",
        ap2: {
          default_decision: "deny",
          counterparty_rules: [{ counterparty: "*", decision: "allow" }],
        },
      });
      const service = new OperatorKeyService({ masterKey, policyGate: gate });

      const signed = await service.signAp2Mandate(operatorId, makeAp2());
      expect(
        verifyAp2Mandate(signed, { trustedPublicKey: signed.public_key }).valid
      ).toBe(true);
    });
  });
});
