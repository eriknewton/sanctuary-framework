/**
 * Key 17 -- AP2 mandate signer tests.
 *
 * Exercises sign + verify round trip, tamper rejection, canonical ordering
 * preservation, operator isolation, and determinism.
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "../../src/core/random.js";
import {
  signAp2Mandate,
  verifyAp2Mandate,
  deriveAp2Key,
  type Ap2Mandate,
} from "../../src/key-17/ap2-mandate-signer.js";
import { deriveX402Key } from "../../src/key-17/x402-signer.js";

function makeMandate(overrides?: Partial<Ap2Mandate>): Ap2Mandate {
  return {
    mandate_type: "payment",
    issuer: "operator-alice",
    target: "agent-service-beta",
    payload: {
      amount: "250",
      currency: "USDC",
      conditions: ["delivery_confirmed"],
    },
    issued_at: "2026-05-18T12:00:00Z",
    expires_at: "2026-05-18T13:00:00Z",
    nonce: "ap2-nonce-001",
    spec_version: "1.0",
    ...overrides,
  };
}

describe("ap2-mandate-signer", () => {
  const masterKey = randomBytes(32);
  const operatorId = "operator-alice";

  describe("sign + verify round trip", () => {
    it("produces a valid signature that verifies", () => {
      const mandate = makeMandate();
      const signed = signAp2Mandate(masterKey, operatorId, mandate);

      expect(signed.signature).toBeDefined();
      expect(signed.algorithm).toBe("EdDSA");
      expect(signed.public_key).toBeDefined();
      expect(
        verifyAp2Mandate(signed, { trustedPublicKey: signed.public_key })
      ).toMatchObject({
        valid: true,
        signature_basis: "trusted",
        freshness: "not_checked",
      });
    });

    it("preserves all original mandate fields", () => {
      const mandate = makeMandate();
      const signed = signAp2Mandate(masterKey, operatorId, mandate);

      expect(signed.mandate_type).toBe(mandate.mandate_type);
      expect(signed.issuer).toBe(mandate.issuer);
      expect(signed.target).toBe(mandate.target);
      expect(signed.payload).toEqual(mandate.payload);
      expect(signed.issued_at).toBe(mandate.issued_at);
      expect(signed.expires_at).toBe(mandate.expires_at);
      expect(signed.nonce).toBe(mandate.nonce);
      expect(signed.spec_version).toBe(mandate.spec_version);
    });
  });

  describe("verification rejects tampering", () => {
    it("rejects a mutated signature algorithm label", () => {
      const signed = signAp2Mandate(masterKey, operatorId, makeMandate());
      const tampered = { ...signed, algorithm: "RS256" as never };

      expect(
        verifyAp2Mandate(tampered, { trustedPublicKey: signed.public_key })
      ).toMatchObject({
        valid: false,
        signature_basis: "none",
        reason: "signature_invalid",
      });
    });

    it("rejects a non-string signature algorithm label", () => {
      const signed = signAp2Mandate(masterKey, operatorId, makeMandate());
      const malformed = { ...signed, algorithm: 7 as never };

      expect(
        verifyAp2Mandate(malformed, { trustedPublicKey: signed.public_key })
      ).toMatchObject({
        valid: false,
        signature_basis: "none",
        reason: "signature_invalid",
      });
    });

    it("rejects if mandate_type is modified", () => {
      const mandate = makeMandate();
      const signed = signAp2Mandate(masterKey, operatorId, mandate);
      const tampered = { ...signed, mandate_type: "authorization" };
      expect(
        verifyAp2Mandate(tampered, { trustedPublicKey: signed.public_key }).valid
      ).toBe(false);
    });

    it("rejects if target is modified", () => {
      const mandate = makeMandate();
      const signed = signAp2Mandate(masterKey, operatorId, mandate);
      const tampered = { ...signed, target: "evil-agent" };
      expect(
        verifyAp2Mandate(tampered, { trustedPublicKey: signed.public_key }).valid
      ).toBe(false);
    });

    it("rejects if payload is modified", () => {
      const mandate = makeMandate();
      const signed = signAp2Mandate(masterKey, operatorId, mandate);
      const tampered = {
        ...signed,
        payload: { ...signed.payload, amount: "99999" },
      };
      expect(
        verifyAp2Mandate(tampered, { trustedPublicKey: signed.public_key }).valid
      ).toBe(false);
    });

    it("rejects if expires_at is modified", () => {
      const mandate = makeMandate();
      const signed = signAp2Mandate(masterKey, operatorId, mandate);
      const tampered = { ...signed, expires_at: "2099-12-31T23:59:59Z" };
      expect(
        verifyAp2Mandate(tampered, { trustedPublicKey: signed.public_key }).valid
      ).toBe(false);
    });
  });

  describe("trusted-key verification boundary", () => {
    it("refuses embedded-key verification unless explicitly opted in", () => {
      const signed = signAp2Mandate(masterKey, operatorId, makeMandate());

      expect(verifyAp2Mandate(signed)).toMatchObject({
        valid: false,
        signature_basis: "none",
        reason: "trusted_public_key_required",
      });
    });

    it("does not trust an attacker-signed mandate carrying the attacker key", () => {
      const trusted = signAp2Mandate(masterKey, operatorId, makeMandate());
      const attacker = signAp2Mandate(
        randomBytes(32),
        "operator-mallory",
        makeMandate({ issuer: "operator-mallory" })
      );

      expect(
        verifyAp2Mandate(attacker, { trustedPublicKey: trusted.public_key })
      ).toMatchObject({
        valid: false,
        signature_basis: "trusted",
        reason: "public_key_mismatch",
      });
    });

    it("labels embedded-key opt-in as internal consistency only", () => {
      const attacker = signAp2Mandate(
        randomBytes(32),
        "operator-mallory",
        makeMandate({ issuer: "operator-mallory" })
      );

      expect(verifyAp2Mandate(attacker, { trustEmbedded: true })).toMatchObject(
        {
          valid: true,
          signature_basis: "embedded",
          freshness: "not_checked",
        }
      );
    });
  });

  describe("canonical ordering preserved", () => {
    it("produces the same signature regardless of property insertion order", () => {
      const m1: Ap2Mandate = {
        mandate_type: "payment",
        issuer: "op-a",
        target: "agent-b",
        payload: { amount: "100" },
        issued_at: "2026-05-18T14:00:00Z",
        expires_at: "2026-05-18T15:00:00Z",
        nonce: "order-test",
        spec_version: "1.0",
      };
      const m2: Ap2Mandate = {
        spec_version: "1.0",
        nonce: "order-test",
        expires_at: "2026-05-18T15:00:00Z",
        issued_at: "2026-05-18T14:00:00Z",
        payload: { amount: "100" },
        target: "agent-b",
        issuer: "op-a",
        mandate_type: "payment",
      };

      const signed1 = signAp2Mandate(masterKey, operatorId, m1);
      const signed2 = signAp2Mandate(masterKey, operatorId, m2);

      expect(signed1.signature).toBe(signed2.signature);
    });
  });

  describe("operator isolation", () => {
    it("different operators produce different keys", () => {
      const key1 = deriveAp2Key(masterKey, "operator-alice");
      const key2 = deriveAp2Key(masterKey, "operator-bob");
      expect(Buffer.from(key1).toString("hex")).not.toBe(
        Buffer.from(key2).toString("hex")
      );
    });

    it("different operators produce different signatures", () => {
      const mandate = makeMandate();
      const signed1 = signAp2Mandate(masterKey, "operator-alice", mandate);
      const signed2 = signAp2Mandate(masterKey, "operator-bob", mandate);
      expect(signed1.signature).not.toBe(signed2.signature);
      expect(signed1.public_key).not.toBe(signed2.public_key);
    });
  });

  describe("determinism", () => {
    it("produces identical signatures for the same input", () => {
      const mandate = makeMandate();
      const signed1 = signAp2Mandate(masterKey, operatorId, mandate);
      const signed2 = signAp2Mandate(masterKey, operatorId, mandate);
      expect(signed1.signature).toBe(signed2.signature);
    });
  });

  describe("cross-protocol key isolation", () => {
    it("AP2 key differs from x402 key for the same operator", () => {
      const ap2Key = deriveAp2Key(masterKey, operatorId);
      const x402Key = deriveX402Key(masterKey, operatorId);
      expect(Buffer.from(ap2Key).toString("hex")).not.toBe(
        Buffer.from(x402Key).toString("hex")
      );
    });
  });
});
