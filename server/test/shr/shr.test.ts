/**
 * Sovereignty Health Report (SHR) — Tests
 *
 * Tests for SHR generation, signing, verification, expiry, and tamper detection.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateSHR } from "../../src/shr/generator.js";
import { verifySHR } from "../../src/shr/verifier.js";
import { canonicalizeForSigning } from "../../src/shr/types.js";
import type { SignedSHR } from "../../src/shr/types.js";
import type { SanctuaryConfig } from "../../src/config.js";
import { defaultConfig } from "../../src/config.js";

// Minimal IdentityManager mock that satisfies the generator's needs
class TestIdentityManager {
  private identities = new Map<string, any>();
  private defaultId: string | null = null;

  constructor(storage: MemoryStorage, masterKey: Uint8Array) {
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "test",
      encKey,
      "recovery-key"
    );
    this.identities.set(publicIdentity.identity_id, storedIdentity);
    this.defaultId = publicIdentity.identity_id;
  }

  get(id: string) {
    return this.identities.get(id);
  }
  getDefault() {
    return this.defaultId ? this.identities.get(this.defaultId) : undefined;
  }
  list() {
    return Array.from(this.identities.values());
  }
}

describe("Sovereignty Health Report (SHR)", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  let identityManager: TestIdentityManager;
  let config: SanctuaryConfig;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    identityManager = new TestIdentityManager(storage, masterKey);
    config = defaultConfig();
  });

  describe("Generation", () => {
    it("generates a valid signed SHR", () => {
      const result = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      });

      expect(typeof result).not.toBe("string");
      const shr = result as SignedSHR;

      expect(shr.body.shr_version).toBe("1.0");
      expect(shr.body.instance_id).toBeTruthy();
      expect(shr.body.generated_at).toBeTruthy();
      expect(shr.body.expires_at).toBeTruthy();
      expect(shr.signed_by).toBeTruthy();
      expect(shr.signature).toBeTruthy();
    });

    it("includes all four layers", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      expect(shr.body.layers.l1).toBeTruthy();
      expect(shr.body.layers.l2).toBeTruthy();
      expect(shr.body.layers.l3).toBeTruthy();
      expect(shr.body.layers.l4).toBeTruthy();
    });

    it("reports correct degradations for MVS", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      // MVS has L2 degraded (no TEE) but L3 is active (Schnorr + Pedersen = genuine ZK)
      expect(shr.body.layers.l2.status).toBe("degraded");
      expect(shr.body.layers.l3.status).toBe("active");
      expect(shr.body.layers.l3.selective_disclosure).toBe(true);
      expect(shr.body.degradations.length).toBeGreaterThan(0);

      const codes = shr.body.degradations.map((d) => d.code);
      expect(codes).toContain("PROCESS_ISOLATION_ONLY");
      // COMMITMENT_ONLY is no longer a degradation — Schnorr proofs are genuine ZK
      expect(codes).not.toContain("COMMITMENT_ONLY");
    });

    it("respects custom validity window", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        validityMs: 5 * 60 * 1000, // 5 minutes
      }) as SignedSHR;

      const generated = new Date(shr.body.generated_at).getTime();
      const expires = new Date(shr.body.expires_at).getTime();
      expect(expires - generated).toBe(5 * 60 * 1000);
    });

    it("returns error when no identity exists", () => {
      const emptyManager = {
        get: () => undefined,
        getDefault: () => undefined,
        list: () => [],
      };

      const result = generateSHR(undefined, {
        config,
        identityManager: emptyManager as any,
        masterKey,
      });

      expect(typeof result).toBe("string");
      expect(result).toContain("No identity");
    });
  });

  describe("Verification", () => {
    it("verifies a valid SHR", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const result = verifySHR(shr);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.counterparty_id).toBe(shr.body.instance_id);
    });

    it("detects tampered body", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      // Tamper with the body
      const tampered = JSON.parse(JSON.stringify(shr)) as SignedSHR;
      tampered.body.layers.l1.encryption = "none";

      const result = verifySHR(tampered);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("signature") || e.includes("tamper"))).toBe(true);
    });

    it("detects expired SHR", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        validityMs: 1, // 1ms — will expire immediately
      }) as SignedSHR;

      // Wait a tick to ensure expiry
      const futureDate = new Date(Date.now() + 10000);
      const result = verifySHR(shr, futureDate);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("expired"))).toBe(true);
    });

    it("detects invalid signature bytes", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      // Corrupt the signature
      const corrupted = JSON.parse(JSON.stringify(shr)) as SignedSHR;
      corrupted.signature = "AAAA" + corrupted.signature.slice(4);

      const result = verifySHR(corrupted);
      expect(result.valid).toBe(false);
    });

    it("assesses sovereignty level correctly", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const result = verifySHR(shr);

      // MVS has degraded L2 and L3, so overall should be "degraded"
      expect(result.sovereignty_level).toBe("degraded");
    });
  });

  describe("Canonical serialization", () => {
    it("produces deterministic output", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const c1 = canonicalizeForSigning(shr.body);
      const c2 = canonicalizeForSigning(shr.body);
      expect(c1).toBe(c2);
    });
  });
});
