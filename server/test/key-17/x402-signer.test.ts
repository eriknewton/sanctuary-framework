/**
 * Key 17 -- x402 sovereign signer tests.
 *
 * Exercises sign + verify round trip, determinism, operator isolation,
 * and canonical JSON ordering stability.
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "../../src/core/random.js";
import {
  signX402Request,
  verifyX402Request,
  deriveX402Key,
  type X402Request,
} from "../../src/key-17/x402-signer.js";

function makeRequest(overrides?: Partial<X402Request>): X402Request {
  return {
    amount: "1000",
    currency: "USDC",
    counterparty: "agent-xyz-456",
    description: "Test payment",
    timestamp: "2026-05-18T12:00:00Z",
    nonce: "test-nonce-001",
    ...overrides,
  };
}

describe("x402-signer", () => {
  const masterKey = randomBytes(32);
  const operatorId = "operator-alice";

  describe("sign + verify round trip", () => {
    it("produces a valid signature that verifies", () => {
      const request = makeRequest();
      const signed = signX402Request(masterKey, operatorId, request);

      expect(signed.signature).toBeDefined();
      expect(signed.algorithm).toBe("EdDSA");
      expect(signed.public_key).toBeDefined();
      expect(
        verifyX402Request(signed, { trustedPublicKey: signed.public_key })
      ).toMatchObject({
        valid: true,
        signature_basis: "trusted",
        freshness: "not_checked",
      });
    });

    it("preserves all original request fields", () => {
      const request = makeRequest();
      const signed = signX402Request(masterKey, operatorId, request);

      expect(signed.amount).toBe(request.amount);
      expect(signed.currency).toBe(request.currency);
      expect(signed.counterparty).toBe(request.counterparty);
      expect(signed.description).toBe(request.description);
      expect(signed.timestamp).toBe(request.timestamp);
      expect(signed.nonce).toBe(request.nonce);
    });
  });

  describe("determinism", () => {
    it("produces identical signatures for the same input", () => {
      const request = makeRequest();
      const signed1 = signX402Request(masterKey, operatorId, request);
      const signed2 = signX402Request(masterKey, operatorId, request);

      expect(signed1.signature).toBe(signed2.signature);
      expect(signed1.public_key).toBe(signed2.public_key);
    });

    it("produces different signatures for different nonces", () => {
      const req1 = makeRequest({ nonce: "nonce-a" });
      const req2 = makeRequest({ nonce: "nonce-b" });
      const signed1 = signX402Request(masterKey, operatorId, req1);
      const signed2 = signX402Request(masterKey, operatorId, req2);

      expect(signed1.signature).not.toBe(signed2.signature);
    });
  });

  describe("operator isolation", () => {
    it("different operators produce different keys", () => {
      const key1 = deriveX402Key(masterKey, "operator-alice");
      const key2 = deriveX402Key(masterKey, "operator-bob");

      expect(Buffer.from(key1).toString("hex")).not.toBe(
        Buffer.from(key2).toString("hex")
      );
    });

    it("different operators produce different signatures", () => {
      const request = makeRequest();
      const signed1 = signX402Request(masterKey, "operator-alice", request);
      const signed2 = signX402Request(masterKey, "operator-bob", request);

      expect(signed1.signature).not.toBe(signed2.signature);
      expect(signed1.public_key).not.toBe(signed2.public_key);
    });

    it("different master keys produce different signatures", () => {
      const mk1 = randomBytes(32);
      const mk2 = randomBytes(32);
      const request = makeRequest();
      const signed1 = signX402Request(mk1, operatorId, request);
      const signed2 = signX402Request(mk2, operatorId, request);

      expect(signed1.signature).not.toBe(signed2.signature);
    });
  });

  describe("canonical JSON ordering", () => {
    it("produces the same signature regardless of property insertion order", () => {
      const req1: X402Request = {
        amount: "500",
        currency: "ETH",
        counterparty: "agent-z",
        timestamp: "2026-05-18T14:00:00Z",
        nonce: "order-test",
      };
      // Same fields, different insertion order
      const req2: X402Request = {
        nonce: "order-test",
        timestamp: "2026-05-18T14:00:00Z",
        counterparty: "agent-z",
        amount: "500",
        currency: "ETH",
      };

      const signed1 = signX402Request(masterKey, operatorId, req1);
      const signed2 = signX402Request(masterKey, operatorId, req2);

      expect(signed1.signature).toBe(signed2.signature);
    });

    it("handles whitespace-only differences (no whitespace in canonical form)", () => {
      const request = makeRequest({ description: "  spaced  " });
      const signed = signX402Request(masterKey, operatorId, request);
      expect(
        verifyX402Request(signed, { trustedPublicKey: signed.public_key }).valid
      ).toBe(true);
    });
  });

  describe("verification rejects tampering", () => {
    it("rejects a mutated signature algorithm label", () => {
      const signed = signX402Request(masterKey, operatorId, makeRequest());
      const tampered = { ...signed, algorithm: "RS256" as never };

      expect(
        verifyX402Request(tampered, { trustedPublicKey: signed.public_key })
      ).toMatchObject({
        valid: false,
        signature_basis: "none",
        reason: "signature_invalid",
      });
    });

    it("rejects a non-string signature algorithm label", () => {
      const signed = signX402Request(masterKey, operatorId, makeRequest());
      const malformed = { ...signed, algorithm: 7 as never };

      expect(
        verifyX402Request(malformed, { trustedPublicKey: signed.public_key })
      ).toMatchObject({
        valid: false,
        signature_basis: "none",
        reason: "signature_invalid",
      });
    });

    it("rejects if amount is modified after signing", () => {
      const request = makeRequest();
      const signed = signX402Request(masterKey, operatorId, request);
      const tampered = { ...signed, amount: "9999" };
      expect(
        verifyX402Request(tampered, { trustedPublicKey: signed.public_key })
          .valid
      ).toBe(false);
    });

    it("rejects if counterparty is modified after signing", () => {
      const request = makeRequest();
      const signed = signX402Request(masterKey, operatorId, request);
      const tampered = { ...signed, counterparty: "evil-agent" };
      expect(
        verifyX402Request(tampered, { trustedPublicKey: signed.public_key })
          .valid
      ).toBe(false);
    });

    it("rejects if signature is replaced with a different valid signature", () => {
      const request = makeRequest();
      const signed = signX402Request(masterKey, operatorId, request);
      const otherSigned = signX402Request(
        randomBytes(32),
        "other-operator",
        request
      );
      const swapped = { ...signed, signature: otherSigned.signature };
      expect(
        verifyX402Request(swapped, { trustedPublicKey: signed.public_key })
          .valid
      ).toBe(false);
    });
  });

  describe("trusted-key verification boundary", () => {
    it("refuses embedded-key verification unless explicitly opted in", () => {
      const signed = signX402Request(masterKey, operatorId, makeRequest());

      expect(verifyX402Request(signed)).toMatchObject({
        valid: false,
        signature_basis: "none",
        reason: "trusted_public_key_required",
      });
    });

    it("does not trust an attacker-signed request carrying the attacker key", () => {
      const trusted = signX402Request(masterKey, operatorId, makeRequest());
      const attacker = signX402Request(
        randomBytes(32),
        "operator-mallory",
        makeRequest({ counterparty: "mallory-agent" })
      );

      expect(
        verifyX402Request(attacker, { trustedPublicKey: trusted.public_key })
      ).toMatchObject({
        valid: false,
        signature_basis: "trusted",
        reason: "public_key_mismatch",
      });
    });

    it("labels embedded-key opt-in as internal consistency only", () => {
      const attacker = signX402Request(
        randomBytes(32),
        "operator-mallory",
        makeRequest({ counterparty: "mallory-agent" })
      );

      expect(verifyX402Request(attacker, { trustEmbedded: true })).toMatchObject(
        {
          valid: true,
          signature_basis: "embedded",
          freshness: "not_checked",
        }
      );
    });
  });
});
