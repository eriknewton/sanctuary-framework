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
  rotateKeys,
} from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import type { SHRRotationEvent } from "../../src/shr/types.js";
import { generateSHR, SHR_MAX_LIFETIME_MS } from "../../src/shr/generator.js";
import {
  verifySHR,
  SHR_MAX_AGE_MS,
  SHR_MAX_DECLARED_LIFETIME_MS,
  SHR_MAX_CLOCK_SKEW_MS,
} from "../../src/shr/verifier.js";
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

  // ─── HIGH#1: rotation-aware identity binding ──────────────────────────
  describe("Identity binding with key rotation (HIGH#1)", () => {
    const encKeyFor = (mk: Uint8Array) =>
      derivePurposeKey(mk, "identity-encryption");

    /**
     * Build an identity, rotate its keys `times`, and return a manager that
     * serves the rotated identity as default — plus the origin key id.
     */
    function rotatedAgent(times: number) {
      const mk = generateRandomKey();
      const encKey = encKeyFor(mk);
      const { storedIdentity } = createIdentity("rot", encKey, "recovery-key");
      const originId = storedIdentity.identity_id; // == generateIdentityId(origin pubkey)

      let current: StoredIdentity = storedIdentity;
      for (let i = 0; i < times; i++) {
        current = rotateKeys(current, encKey, `rotation-${i}`).updatedIdentity;
      }
      const rotated = current;

      const manager = {
        get: (id: string) => (id === rotated.identity_id ? rotated : undefined),
        getDefault: () => rotated,
        list: () => [rotated],
      };
      return { mk, manager, rotated, originId };
    }

    function shrOf(times: number) {
      const { mk, manager, rotated, originId } = rotatedAgent(times);
      const shr = generateSHR(undefined, {
        config,
        identityManager: manager as any,
        masterKey: mk,
      });
      if (typeof shr === "string") throw new Error(shr);
      return { shr, rotated, originId };
    }

    it("accepts a rotated identity's SHR via a valid rotation chain", () => {
      const { shr, originId } = shrOf(1);

      // The signing key no longer derives instance_id directly...
      expect(generateIdentityId(fromBase64url(shr.signed_by))).not.toBe(
        shr.body.instance_id
      );
      // ...but instance_id is the STABLE origin id, and the chain is carried.
      expect(shr.body.instance_id).toBe(originId);
      expect(shr.body.key_rotation_proof).toBeDefined();
      expect(shr.body.key_rotation_proof!.length).toBe(1);

      const result = verifySHR(shr);
      expect(result.valid).toBe(true);
      expect(
        result.errors.some((e) => e.includes("not bound to signed_by"))
      ).toBe(false);
    });

    it("accepts a multi-hop rotation chain", () => {
      const { shr } = shrOf(3);
      expect(shr.body.key_rotation_proof!.length).toBe(3);
      const result = verifySHR(shr);
      expect(result.valid).toBe(true);
    });

    it("rejects a rotated SHR whose proof is stripped (proof is load-bearing)", () => {
      const { shr } = shrOf(1);
      // Drop the proof but keep the rotated signing key + stable instance_id.
      // The SHR signature is unchanged here, but without the chain the binding
      // can no longer be established → fail closed.
      const stripped: SignedSHR = {
        ...shr,
        body: { ...shr.body, key_rotation_proof: undefined },
      };
      const result = verifySHR(stripped);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes("not self-certifying"))
      ).toBe(true);
    });

    it("rejects a fabricated chain whose origin does not derive instance_id", () => {
      // Attacker claims a victim instance_id and fabricates a chain starting
      // from a key they control. generateIdentityId(theirOrigin) !== victimId,
      // which a 128-bit preimage would be required to satisfy.
      const victimId = "deadbeefdeadbeefdeadbeefdeadbeef"; // arbitrary 32-hex id
      const attackerPriv = randomBytes(32);
      const attackerPub = ed25519.getPublicKey(attackerPriv);
      const attackerPubB64 = toBase64url(attackerPub);

      // A self-signed (by attacker) rotation event — structurally complete.
      const rotated_at = new Date().toISOString();
      const eventData = JSON.stringify({
        old_public_key: attackerPubB64,
        new_public_key: attackerPubB64,
        identity_id: victimId,
        reason: "forged",
        rotated_at,
      });
      const evSig = ed25519.sign(stringToBytes(eventData), attackerPriv);
      const proof: SHRRotationEvent[] = [
        {
          old_public_key: attackerPubB64,
          new_public_key: attackerPubB64,
          identity_id: victimId,
          reason: "forged",
          rotated_at,
          signature: toBase64url(evSig),
        },
      ];

      const base = shrOf(0).shr;
      const forgedBody = {
        ...base.body,
        instance_id: victimId,
        key_rotation_proof: proof,
      };
      const sig = ed25519.sign(
        stringToBytes(canonicalizeForSigning(forgedBody)),
        attackerPriv
      );
      const forged: SignedSHR = {
        body: forgedBody,
        signed_by: attackerPubB64,
        signature: toBase64url(sig),
        signature_scheme: SIGNATURE_SCHEME_V1,
      };

      const result = verifySHR(forged);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) =>
          e.includes("origin key does not derive instance_id")
        )
      ).toBe(true);
    });

    it("rejects a chain whose terminus is redirected to an attacker key", () => {
      // Take a legitimately rotated SHR, then redirect the final event's
      // new_public_key to an attacker key and re-sign the SHR body with that
      // key. The per-event signature (made by the real origin over the real
      // new key) no longer matches the tampered event data → rejected.
      const { shr } = shrOf(1);
      const attackerPriv = randomBytes(32);
      const attackerPub = ed25519.getPublicKey(attackerPriv);
      const attackerPubB64 = toBase64url(attackerPub);

      const tamperedProof = shr.body.key_rotation_proof!.map((e) => ({ ...e }));
      tamperedProof[tamperedProof.length - 1]!.new_public_key = attackerPubB64;

      const forgedBody = { ...shr.body, key_rotation_proof: tamperedProof };
      const sig = ed25519.sign(
        stringToBytes(canonicalizeForSigning(forgedBody)),
        attackerPriv
      );
      const forged: SignedSHR = {
        body: forgedBody,
        signed_by: attackerPubB64,
        signature: toBase64url(sig),
        signature_scheme: SIGNATURE_SCHEME_V1,
      };

      const result = verifySHR(forged);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) =>
          e.includes("key_rotation_proof event signature is invalid")
        )
      ).toBe(true);
    });
  });

  // ─── LOW#5: malformed SHR (missing layers) fails closed ───────────────
  describe("Malformed SHR fails closed (LOW#5)", () => {
    it("rejects an SHR with a valid signature but no layers (no throw)", () => {
      const priv = randomBytes(32);
      const pub = ed25519.getPublicKey(priv);

      // Body omitting `layers` entirely, signed consistently so the only thing
      // that can reject it is the layer-completeness guard — and it must not
      // throw an uncaught TypeError dereferencing layers.l1.
      const body: any = {
        shr_version: "1.0",
        implementation: {
          sanctuary_version: "test",
          node_version: "test",
          generated_by: "sanctuary-mcp-server",
        },
        instance_id: generateIdentityId(pub),
        generated_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        capabilities: {
          handshake: true,
          shr_exchange: true,
          reputation_verify: true,
          encrypted_channel: false,
        },
        degradations: [],
        // layers intentionally omitted
      };
      const sig = ed25519.sign(stringToBytes(canonicalizeForSigning(body)), priv);
      const shr: SignedSHR = {
        body,
        signed_by: toBase64url(pub),
        signature: toBase64url(sig),
        signature_scheme: SIGNATURE_SCHEME_V1,
      };

      let result!: ReturnType<typeof verifySHR>;
      expect(() => {
        result = verifySHR(shr);
      }).not.toThrow();
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes("Missing one or more layer"))
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

  // ─── SHR-FRESH-01: signed-lifetime clamp + relying-party freshness ────
  describe("Freshness bounds (SHR-FRESH-01)", () => {
    it("clamps a signed SHR's lifetime to SHR_MAX_LIFETIME_MS even when a far-larger validity is requested", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        // Ask for ~10 years — far beyond the ceiling.
        validityMs: 10 * 365 * 24 * 60 * 60 * 1000,
      }) as SignedSHR;

      const generated = new Date(shr.body.generated_at).getTime();
      const expires = new Date(shr.body.expires_at).getTime();
      expect(expires - generated).toBe(SHR_MAX_LIFETIME_MS);
    });

    it("verifySHR rejects an otherwise-valid SHR whose age exceeds SHR_MAX_AGE_MS", () => {
      const genTime = new Date("2026-01-01T00:00:00.000Z");
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        now: genTime,
        validityMs: SHR_MAX_LIFETIME_MS, // long-lived so expiry itself isn't the trigger
      }) as SignedSHR;

      const staleCheckTime = new Date(genTime.getTime() + SHR_MAX_AGE_MS + 60_000);
      const result = verifySHR(shr, staleCheckTime);

      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes("exceeding the maximum relying-party age"))
      ).toBe(true);
    });

    it("verifySHR rejects an SHR whose declared lifetime exceeds SHR_MAX_DECLARED_LIFETIME_MS", () => {
      // Hand-craft a body with a declared lifetime beyond the ceiling — a
      // hostile signer's generator has no clamp of its own, so this proves
      // the verify-side check is independent enforcement.
      const priv = randomBytes(32);
      const pub = ed25519.getPublicKey(priv);
      const generatedAt = new Date("2026-01-01T00:00:00.000Z");
      const expiresAt = new Date(
        generatedAt.getTime() + SHR_MAX_DECLARED_LIFETIME_MS + 60_000
      );

      const body: any = {
        shr_version: "1.0",
        implementation: {
          sanctuary_version: "test",
          node_version: "test",
          generated_by: "sanctuary-mcp-server",
        },
        instance_id: generateIdentityId(pub),
        generated_at: generatedAt.toISOString(),
        expires_at: expiresAt.toISOString(),
        layers: {
          l1: {
            status: "active",
            encryption: "aes-256-gcm",
            key_custody: "self",
            integrity: "hmac",
            identity_type: "ed25519",
            state_portable: true,
          },
          l2: { status: "active", isolation_type: "local-process", attestation_available: false },
          l3: { status: "active", proof_system: "schnorr-pedersen", selective_disclosure: true },
          l4: { status: "active", reputation_mode: "local", attestation_format: "v1", reputation_portable: true },
        },
        capabilities: {
          handshake: true,
          shr_exchange: true,
          reputation_verify: true,
          encrypted_channel: false,
        },
        degradations: [],
      };
      const sig = ed25519.sign(stringToBytes(canonicalizeForSigning(body)), priv);
      const shr: SignedSHR = {
        body,
        signed_by: toBase64url(pub),
        signature: toBase64url(sig),
        signature_scheme: SIGNATURE_SCHEME_V1,
      };

      // Check well within the declared window so the age/expiry checks
      // above don't also fire — isolates the declared-lifetime check.
      const checkTime = new Date(generatedAt.getTime() + 60_000);
      const result = verifySHR(shr, checkTime);

      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes("exceeding the maximum of"))
      ).toBe(true);
    });

    it("verifySHR rejects a future generated_at beyond SHR_MAX_CLOCK_SKEW_MS (was only a warning before)", () => {
      const now = new Date("2026-01-01T00:00:00.000Z");
      const futureGenerated = new Date(now.getTime() + SHR_MAX_CLOCK_SKEW_MS + 60_000);
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        now: futureGenerated,
      }) as SignedSHR;

      const result = verifySHR(shr, now);

      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes("clock-skew tolerance"))
      ).toBe(true);
    });

    it("a normal fresh 60-minute SHR still verifies valid", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        validityMs: 60 * 60 * 1000,
      }) as SignedSHR;

      const result = verifySHR(shr);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });
});
