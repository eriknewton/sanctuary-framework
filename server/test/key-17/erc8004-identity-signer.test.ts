/**
 * Key 17 -- ERC-8004 Identity Registry signer tests.
 *
 * Exercises sign + recover round trip, 65-byte signature format,
 * operator isolation, and tamper rejection.
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "../../src/core/random.js";
import {
  signErc8004Registration,
  verifyErc8004Registration,
  deriveErc8004Key,
  publicKeyToAddress,
  type Erc8004Registration,
} from "../../src/key-17/erc8004-identity-signer.js";
import { secp256k1 } from "@noble/curves/secp256k1";

function makeRegistration(
  overrides?: Partial<Erc8004Registration>
): Erc8004Registration {
  return {
    identity: "did:sanctuary:operator-alice",
    registry: "0x1234567890abcdef1234567890abcdef12345678",
    chain_id: 1,
    nonce: 42,
    timestamp: "2026-05-18T12:00:00Z",
    ...overrides,
  };
}

describe("erc8004-identity-signer", () => {
  const masterKey = randomBytes(32);
  const operatorId = "operator-alice";

  describe("sign + recover round trip", () => {
    it("produces a valid signature that verifies via address recovery", () => {
      const reg = makeRegistration();
      const signed = signErc8004Registration(masterKey, operatorId, reg);

      expect(signed.signature).toBeDefined();
      expect(signed.signer_address).toMatch(/^0x[0-9a-fA-F]{40}$/);
      expect(signed.public_key).toBeDefined();
      expect(verifyErc8004Registration(signed)).toBe(true);
    });

    it("preserves all original registration fields", () => {
      const reg = makeRegistration();
      const signed = signErc8004Registration(masterKey, operatorId, reg);

      expect(signed.identity).toBe(reg.identity);
      expect(signed.registry).toBe(reg.registry);
      expect(signed.chain_id).toBe(reg.chain_id);
      expect(signed.nonce).toBe(reg.nonce);
      expect(signed.timestamp).toBe(reg.timestamp);
    });
  });

  describe("65-byte signature format", () => {
    it("produces a 65-byte hex-encoded signature (0x + 130 hex chars)", () => {
      const reg = makeRegistration();
      const signed = signErc8004Registration(masterKey, operatorId, reg);

      expect(signed.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
    });

    it("v byte is 27 or 28", () => {
      const reg = makeRegistration();
      const signed = signErc8004Registration(masterKey, operatorId, reg);
      const vHex = signed.signature.slice(130);
      const v = parseInt(vHex, 16);
      expect(v === 27 || v === 28).toBe(true);
    });
  });

  describe("Ethereum address derivation", () => {
    it("derives a valid checksummed Ethereum address from public key", () => {
      const privKey = deriveErc8004Key(masterKey, operatorId);
      const pubKey = secp256k1.getPublicKey(privKey, true);
      const address = publicKeyToAddress(pubKey);

      expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
      expect(address.length).toBe(42);
    });

    it("same key always produces the same address", () => {
      const privKey = deriveErc8004Key(masterKey, operatorId);
      const pubKey = secp256k1.getPublicKey(privKey, true);
      const addr1 = publicKeyToAddress(pubKey);
      const addr2 = publicKeyToAddress(pubKey);

      expect(addr1).toBe(addr2);
    });
  });

  describe("operator isolation", () => {
    it("different operators produce different keys", () => {
      const key1 = deriveErc8004Key(masterKey, "operator-alice");
      const key2 = deriveErc8004Key(masterKey, "operator-bob");

      expect(Buffer.from(key1).toString("hex")).not.toBe(
        Buffer.from(key2).toString("hex")
      );
    });

    it("different operators produce different signer addresses", () => {
      const reg = makeRegistration();
      const signed1 = signErc8004Registration(
        masterKey,
        "operator-alice",
        reg
      );
      const signed2 = signErc8004Registration(masterKey, "operator-bob", reg);

      expect(signed1.signer_address).not.toBe(signed2.signer_address);
    });
  });

  describe("determinism", () => {
    it("produces identical signatures for the same input", () => {
      const reg = makeRegistration();
      const signed1 = signErc8004Registration(masterKey, operatorId, reg);
      const signed2 = signErc8004Registration(masterKey, operatorId, reg);

      expect(signed1.signature).toBe(signed2.signature);
      expect(signed1.signer_address).toBe(signed2.signer_address);
    });
  });

  describe("verification rejects tampering", () => {
    it("rejects if identity is modified after signing", () => {
      const reg = makeRegistration();
      const signed = signErc8004Registration(masterKey, operatorId, reg);
      const tampered = { ...signed, identity: "did:evil:agent" };
      expect(verifyErc8004Registration(tampered)).toBe(false);
    });

    it("rejects if chain_id is modified after signing", () => {
      const reg = makeRegistration();
      const signed = signErc8004Registration(masterKey, operatorId, reg);
      const tampered = { ...signed, chain_id: 999 };
      expect(verifyErc8004Registration(tampered)).toBe(false);
    });

    it("rejects if signer_address is replaced", () => {
      const reg = makeRegistration();
      const signed = signErc8004Registration(masterKey, operatorId, reg);
      const tampered = {
        ...signed,
        signer_address: "0x0000000000000000000000000000000000000000",
      };
      expect(verifyErc8004Registration(tampered)).toBe(false);
    });
  });
});
