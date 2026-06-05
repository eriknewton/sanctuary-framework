/**
 * Sovereignty Health Report (SHR) — Tests
 *
 * Tests for SHR generation, signing, verification, expiry, and tamper detection.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey, randomBytes } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  createIdentity,
  generateIdentityId,
} from "../../src/core/identity.js";
import { generateSHR } from "../../src/shr/generator.js";
import { verifySHR } from "../../src/shr/verifier.js";
import { canonicalizeForSigning } from "../../src/shr/types.js";
import { SIGNATURE_SCHEME_V1 } from "../../src/mesh/constants.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
} from "../../src/core/encoding.js";
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
      expect(shr.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
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

    it("rejects SHRs with missing or unknown signature_scheme", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const missing = JSON.parse(JSON.stringify(shr)) as Partial<SignedSHR>;
      delete missing.signature_scheme;
      expect(verifySHR(missing as SignedSHR).valid).toBe(false);

      const unknown = {
        ...shr,
        signature_scheme: "ed25519+ml-dsa-v1" as typeof shr.signature_scheme,
      };
      const result = verifySHR(unknown);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("signature_scheme"))).toBe(true);
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

  // ─── HS-1: instance_id ⇄ signed_by binding (forged-peer remediation) ──
  describe("Identity binding (HS-1)", () => {
    /**
     * Forge an SHR: take a real, valid SHR, RE-SIGN its (unchanged) body with
     * a brand-new keypair, and set signed_by to the fresh pubkey — but leave
     * the victim's instance_id in the body. The signature is cryptographically
     * valid against the fresh key, yet generateIdentityId(freshKey) !==
     * instance_id, so verifySHR MUST reject it.
     */
    function forgeWithFreshKey(victim: SignedSHR): SignedSHR {
      const freshPriv = randomBytes(32);
      const freshPub = ed25519.getPublicKey(freshPriv);
      const canonical = canonicalizeForSigning(victim.body);
      const sig = ed25519.sign(stringToBytes(canonical), freshPriv);
      return {
        ...victim,
        signed_by: toBase64url(freshPub), // attacker's key
        signature: toBase64url(sig), // valid sig over the SAME body
        // body (incl. victim instance_id) is left untouched
      };
    }

    it("rejects an SHR whose instance_id is not generateIdentityId(signed_by)", () => {
      const victim = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const forged = forgeWithFreshKey(victim);

      // The forged signature DOES verify against its own (fresh) key, so the
      // ONLY check that can reject it is the identity binding: the fresh key's
      // derived id differs from the victim instance_id left in the body.
      const forgedKeyId = generateIdentityId(fromBase64url(forged.signed_by));
      expect(forgedKeyId).not.toBe(forged.body.instance_id);

      const result = verifySHR(forged);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes("not bound to signed_by"))
      ).toBe(true);
    });

    it("accepts an SHR whose instance_id correctly derives from signed_by", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      // Self-consistent by construction (generator sets instance_id =
      // identity.identity_id = generateIdentityId(pubkey)).
      const result = verifySHR(shr);
      expect(result.valid).toBe(true);
      expect(
        result.errors.some((e) => e.includes("not bound to signed_by"))
      ).toBe(false);
    });

    it("rejects a self-minted SHR claiming a victim's instance_id", () => {
      // Attacker mints their own self-consistent identity, then swaps in the
      // victim's instance_id while signing with the attacker key.
      const victim = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;
      const victimId = victim.body.instance_id;

      // Attacker's own fresh keypair + SHR over a body claiming victimId.
      const attackerPriv = randomBytes(32);
      const attackerPub = ed25519.getPublicKey(attackerPriv);
      const forgedBody = { ...victim.body, instance_id: victimId };
      const canonical = canonicalizeForSigning(forgedBody);
      const sig = ed25519.sign(stringToBytes(canonical), attackerPriv);

      const forged: SignedSHR = {
        body: forgedBody,
        signed_by: toBase64url(attackerPub),
        signature: toBase64url(sig),
        signature_scheme: SIGNATURE_SCHEME_V1,
      };

      // The attacker would need a key whose SHA-256[:16] equals victimId.
      expect(generateIdentityId(attackerPub)).not.toBe(victimId);

      const result = verifySHR(forged);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes("not bound to signed_by"))
      ).toBe(true);
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

  // ─── v0.9.1: L4 degradation emitter integration ──────────────────
  describe("L4 degradation emitter (v0.9.1)", () => {
    it("embeds L4 degradations in the signed body and flips l4.status to degraded", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        l4Evidence: {
          attestation_count: 0,
          tier_distribution: {
            "verified-sovereign": 0,
            "verified-degraded": 0,
            "self-attested": 0,
            "unverified": 0,
          },
          most_recent_attestation_at: null,
          dispute_count: 0,
          context_breakdown: {},
          verascore_linked: false,
        },
      }) as SignedSHR;

      const l4Codes = shr.body.degradations
        .filter((d) => d.layer === "l4")
        .map((d) => d.code);
      expect(l4Codes).toContain("NO_REPUTATION_HISTORY");
      expect(l4Codes).toContain("NO_VERASCORE_LINK");
      expect(shr.body.layers.l4.status).toBe("degraded");
    });

    it("leaves L4 active when evidence is healthy", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        l4Evidence: {
          attestation_count: 10,
          tier_distribution: {
            "verified-sovereign": 8,
            "verified-degraded": 2,
            "self-attested": 0,
            "unverified": 0,
          },
          most_recent_attestation_at: new Date().toISOString(),
          dispute_count: 0,
          context_breakdown: { commerce: 10 },
          verascore_linked: true,
        },
      }) as SignedSHR;

      const l4Codes = shr.body.degradations
        .filter((d) => d.layer === "l4")
        .map((d) => d.code);
      expect(l4Codes).toEqual([]);
      expect(shr.body.layers.l4.status).toBe("active");
    });

    it("keeps signature verifiable with L4 degradations present (roundtrip)", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        l4Evidence: {
          attestation_count: 5,
          tier_distribution: {
            "verified-sovereign": 0,
            "verified-degraded": 0,
            "self-attested": 4,
            "unverified": 1,
          },
          most_recent_attestation_at: new Date().toISOString(),
          dispute_count: 1,
          context_breakdown: { commerce: 5 },
          verascore_linked: false,
        },
      }) as SignedSHR;

      const result = verifySHR(shr);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);

      // Degradations must survive canonical serialization — the body we
      // verify against is the same body we signed, including every L4 code.
      const l4Codes = shr.body.degradations
        .filter((d) => d.layer === "l4")
        .map((d) => d.code)
        .sort();
      expect(l4Codes).toEqual(
        [
          "LOW_TIER_DOMINANCE",
          "DISPUTE_ON_RECORD",
          "NO_VERASCORE_LINK",
        ].sort()
      );
    });

    it("omitting l4Evidence preserves the legacy behavior (L4 active, no codes)", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const l4Codes = shr.body.degradations
        .filter((d) => d.layer === "l4")
        .map((d) => d.code);
      expect(l4Codes).toEqual([]);
      expect(shr.body.layers.l4.status).toBe("active");
    });
  });
});
