/**
 * Sovereignty Attestation Artifacts — Tests
 *
 * Tests for one-shot handshake exchange, attestation generation,
 * attestation verification, tamper detection, and expiry handling.
 */

import { describe, it, expect } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, sign } from "../../src/core/identity.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { generateSHR } from "../../src/shr/generator.js";
import { verifySHR } from "../../src/shr/verifier.js";
import { deepSortKeys } from "../../src/shr/types.js";
import {
  ATTESTATION_MAX_AGE_MS,
  ATTESTATION_MAX_CLOCK_SKEW_MS,
  ATTESTATION_MAX_DECLARED_LIFETIME_MS,
  generateAttestation,
  verifyAttestation,
  ATTESTATION_VERSION,
} from "../../src/handshake/attestation.js";
import type { SignedAttestation } from "../../src/handshake/attestation.js";
import type { SignedSHR } from "../../src/shr/types.js";
import { defaultConfig } from "../../src/config.js";
import type { StoredIdentity } from "../../src/core/identity.js";

// Lightweight IdentityManager for testing
class TestIdentityManager {
  private identities = new Map<string, StoredIdentity>();
  private defaultId: string | null = null;

  constructor(masterKey: Uint8Array) {
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

function makeAgent() {
  const masterKey = generateRandomKey();
  const identityManager = new TestIdentityManager(masterKey);
  const config = defaultConfig();
  return { masterKey, identityManager, config };
}

function agentSHR(agent: ReturnType<typeof makeAgent>): SignedSHR {
  const result = generateSHR(undefined, {
    config: agent.config,
    identityManager: agent.identityManager as any,
    masterKey: agent.masterKey,
  });
  if (typeof result === "string") throw new Error(result);
  return result;
}

function resignAttestation(
  attestation: SignedAttestation,
  agent: ReturnType<typeof makeAgent>
): void {
  attestation.summary = attestation.summary
    .replace(/^Attested: .*$/m, `Attested: ${attestation.body.attested_at}`)
    .replace(/^Expires:  .*$/m, `Expires:  ${attestation.body.expires_at}`);
  const identity = agent.identityManager.getDefault();
  if (!identity) throw new Error("test identity missing");
  const encryptionKey = derivePurposeKey(agent.masterKey, "identity-encryption");
  const canonical = JSON.stringify(deepSortKeys(attestation.body));
  attestation.signature = toBase64url(
    sign(stringToBytes(canonical), identity.encrypted_private_key, encryptionKey)
  );
}

describe("Sovereignty Attestation Artifacts", () => {
  describe("generateAttestation", () => {
    it("generates a valid signed attestation from two SHRs", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        mutual: false,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      expect("body" in attestation).toBe(true);
      if (!("body" in attestation)) return;

      expect(attestation.body.attestation_version).toBe(ATTESTATION_VERSION);
      expect(attestation.body.attester_id).toBe(shrA.body.instance_id);
      expect(attestation.body.subject_id).toBe(shrB.body.instance_id);
      expect(attestation.body.verification.subject_shr_valid).toBe(true);
      expect(attestation.body.verification.mutual).toBe(false);
      expect(attestation.signed_by).toBe(shrA.signed_by);
      expect(attestation.signature).toBeTruthy();
      expect(attestation.summary).toContain("Sovereignty Attestation");
    });

    it("includes both SHRs in the attestation body", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      expect(attestation.body.attester_shr.body.instance_id).toBe(shrA.body.instance_id);
      expect(attestation.body.subject_shr.body.instance_id).toBe(shrB.body.instance_id);
    });

    it("sets correct sovereignty level for MVS agents (liveness proven)", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        livenessProven: true, // 4-step protocol path: liveness was proven
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      // MVS has L2 degraded (no TEE), so overall is degraded
      expect(attestation.body.verification.subject_sovereignty_level).toBe("degraded");
      expect(attestation.body.verification.subject_trust_tier).toBe("verified-degraded");
      expect(attestation.body.verification.liveness_proven).toBe(true);
    });

    it("caps the trust tier at unverified when liveness is not proven (default)", () => {
      // HIGH#2: a structural attestation (no nonce challenge-response) must
      // never confer a verified tier, even for a fully-sovereign subject. The
      // sovereignty level is still reported honestly.
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        // livenessProven omitted → defaults to false
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      expect(attestation.body.verification.liveness_proven).toBe(false);
      expect(attestation.body.verification.subject_trust_tier).toBe("unverified");
      // Structural level is still honest.
      expect(attestation.body.verification.subject_sovereignty_level).toBe("degraded");
      // The signed artifact verifies, but consumers see only `unverified`.
      const result = verifyAttestation(attestation);
      expect(result.valid).toBe(true);
      expect(result.trust_tier).toBe("unverified");
    });

    it("marks mutual exchanges correctly", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        mutual: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      expect(attestation.body.verification.mutual).toBe(true);
      expect(attestation.summary).toContain("Yes");
    });

    it("returns error when no identity available", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const emptyManager = {
        get: () => undefined,
        getDefault: () => undefined,
        list: () => [],
      };

      const result = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: emptyManager as any,
        masterKey: agentA.masterKey,
      });

      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error).toContain("No identity");
      }
    });

    it("sets expiry to the earlier of both SHR expiries", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      const aExpiry = new Date(shrA.body.expires_at).getTime();
      const bExpiry = new Date(shrB.body.expires_at).getTime();
      const attExpiry = new Date(attestation.body.expires_at).getTime();

      expect(attExpiry).toBe(Math.min(aExpiry, bExpiry));
    });

    it("caps expiry at the verifier lifetime even when embedded SHR expiries are later", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      shrA.body.expires_at = "2099-01-01T00:00:00.000Z";
      shrB.body.expires_at = "2099-01-01T00:00:00.000Z";

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      const attestedAtMs = Date.parse(attestation.body.attested_at);
      const expiresAtMs = Date.parse(attestation.body.expires_at);
      expect(expiresAtMs - attestedAtMs).toBe(
        ATTESTATION_MAX_DECLARED_LIFETIME_MS
      );
    });
  });

  describe("verifyAttestation", () => {
    it("verifies a valid attestation", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        livenessProven: true, // verified tier requires proven liveness
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      const result = verifyAttestation(attestation);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.attester_id).toBe(shrA.body.instance_id);
      expect(result.subject_id).toBe(shrB.body.instance_id);
      expect(result.trust_tier).toBe("verified-degraded");
      expect(result.expired).toBe(false);
    });

    it("refuses a verified tier when the body admits liveness_proven:false", () => {
      // HIGH#2 defense in depth: even if an attestation body claims a verified
      // tier, verifyAttestation must cap it to unverified unless liveness is
      // explicitly proven in the signed body.
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        // no liveness → tier is capped at generation time
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      const result = verifyAttestation(attestation);
      // Signature is valid, but liveness was never proven → unverified.
      expect(result.valid).toBe(true);
      expect(result.trust_tier).toBe("unverified");
    });

    it("detects tampered attestation body", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      // Tamper with the body
      attestation.body.verification.subject_trust_tier = "verified-sovereign";

      const result = verifyAttestation(attestation);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes("signature is invalid"))).toBe(true);
    });

    it("rejects a summary rewritten outside the signed body", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      attestation.summary = "Verified Sovereign: rewritten by an intermediary";

      const result = verifyAttestation(attestation);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        "Attestation summary does not match signed body"
      );
    });

    it("detects tampered signature", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      // Tamper with the signature
      attestation.signature = "AAAA" + attestation.signature.slice(4);

      const result = verifyAttestation(attestation);

      expect(result.valid).toBe(false);
    });

    it("detects expired attestation", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      // Verify with a future time past expiry
      const futureDate = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours from now
      const result = verifyAttestation(attestation, futureDate);

      expect(result.valid).toBe(false);
      expect(result.expired).toBe(true);
      expect(result.errors.some(e => e.includes("expired"))).toBe(true);
    });

    it("rejects signed attestations with malformed temporal fields", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      attestation.body.attested_at = "not-a-timestamp";
      attestation.body.expires_at = "also-not-a-timestamp";
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, new Date("2026-08-12T12:00:00.000Z"));
      expect(result.valid).toBe(false);
      expect(result.expired).toBe(false);
      expect(result.errors).toContain("Attestation has an invalid attested_at timestamp");
      expect(result.errors).toContain("Attestation has an invalid expires_at timestamp");
    });

    it("rejects malformed attested_at without inventing dependent time errors", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      attestation.body.attested_at = "not-a-timestamp";
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, new Date());
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Attestation has an invalid attested_at timestamp");
      expect(result.errors.some(error => error.includes("clock-skew"))).toBe(false);
      expect(result.errors.some(error => error.includes("relying-party age"))).toBe(false);
      expect(result.errors.some(error => error.includes("declared lifetime"))).toBe(false);
    });

    it("still applies age policy when only expires_at is malformed", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      const now = new Date("2026-08-12T12:00:00.000Z");
      attestation.body.attested_at = new Date(
        now.getTime() - ATTESTATION_MAX_AGE_MS - 1
      ).toISOString();
      attestation.body.expires_at = "not-a-timestamp";
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, now);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Attestation has an invalid expires_at timestamp");
      expect(result.errors).toContain(
        "Attestation age exceeds the maximum relying-party age of 24h"
      );
      expect(result.errors.some(error => error.includes("declared lifetime"))).toBe(false);
    });

    it("rejects a signer-chosen lifetime beyond the relying-party ceiling", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      const now = new Date("2026-08-12T12:00:00.000Z");
      attestation.body.attested_at = now.toISOString();
      attestation.body.expires_at = new Date(
        now.getTime() + ATTESTATION_MAX_DECLARED_LIFETIME_MS + 1
      ).toISOString();
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, now);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        "Attestation declared lifetime exceeds the maximum of 24h"
      );
    });

    it("rejects an authentic attestation older than the relying-party age ceiling", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      const now = new Date("2026-08-12T12:00:00.000Z");
      const staleAttestedAt = now.getTime() - ATTESTATION_MAX_AGE_MS - 1;
      attestation.body.attested_at = new Date(staleAttestedAt).toISOString();
      attestation.body.expires_at = new Date(now.getTime() + 60_000).toISOString();
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, now);
      expect(result.valid).toBe(false);
      // With equal age and lifetime ceilings, any stale artifact that has not
      // expired necessarily also declares an overlong lifetime. The
      // age-specific assertion remains mutation-sensitive to the age check.
      expect(result.errors).toContain(
        "Attestation age exceeds the maximum relying-party age of 24h"
      );
      expect(result.errors).toContain(
        "Attestation declared lifetime exceeds the maximum of 24h"
      );
    });

    it("rejects attested_at beyond the bounded future clock skew", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      const now = new Date("2026-08-12T12:00:00.000Z");
      const futureAttestedAt = now.getTime() + ATTESTATION_MAX_CLOCK_SKEW_MS + 1;
      attestation.body.attested_at = new Date(futureAttestedAt).toISOString();
      attestation.body.expires_at = new Date(futureAttestedAt + 60_000).toISOString();
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, now);
      expect(result.valid).toBe(false);
      expect(result.errors.some(error => error.includes("future") && error.includes("clock-skew"))).toBe(true);
    });

    it("rejects an expiry that precedes the signed attestation time", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      const now = new Date("2026-08-12T12:00:00.000Z");
      const futureAttestedAt = now.getTime() + ATTESTATION_MAX_CLOCK_SKEW_MS / 2;
      attestation.body.attested_at = new Date(futureAttestedAt).toISOString();
      attestation.body.expires_at = new Date(
        now.getTime() + ATTESTATION_MAX_CLOCK_SKEW_MS / 4
      ).toISOString();
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, now);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(["Attestation expires_at precedes attested_at"]);
    });

    it("accepts exact freshness, lifetime, and clock-skew boundaries", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      const now = new Date("2026-08-12T12:00:00.000Z");
      const boundaryAttestedAt = now.getTime() + ATTESTATION_MAX_CLOCK_SKEW_MS;
      attestation.body.attested_at = new Date(boundaryAttestedAt).toISOString();
      attestation.body.expires_at = new Date(
        boundaryAttestedAt + ATTESTATION_MAX_DECLARED_LIFETIME_MS
      ).toISOString();
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, now);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.trust_tier).toBe("verified-degraded");

      const atOuterWallClockBoundary = verifyAttestation(
        attestation,
        new Date(boundaryAttestedAt + ATTESTATION_MAX_DECLARED_LIFETIME_MS)
      );
      expect(atOuterWallClockBoundary.valid).toBe(false);
      expect(atOuterWallClockBoundary.expired).toBe(true);
      expect(atOuterWallClockBoundary.errors).toEqual(["Attestation has expired"]);
    });

    it("rejects beyond the combined lifetime and clock-skew wall-clock horizon", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      const issuedAt = new Date("2026-08-12T12:00:00.000Z").getTime();
      const attestedAt = issuedAt + ATTESTATION_MAX_CLOCK_SKEW_MS;
      const expiresAt = attestedAt + ATTESTATION_MAX_DECLARED_LIFETIME_MS;
      attestation.body.attested_at = new Date(attestedAt).toISOString();
      attestation.body.expires_at = new Date(expiresAt).toISOString();
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, new Date(expiresAt + 1));
      expect(result.valid).toBe(false);
      expect(result.expired).toBe(true);
      expect(result.errors).toEqual([
        "Attestation has expired",
        "Attestation age exceeds the maximum relying-party age of 24h",
      ]);
    });

    it("does not classify the exact maximum age as stale", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verifySHR(shrB),
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });
      if ("error" in attestation) throw new Error(attestation.error);

      const now = new Date("2026-08-12T12:00:00.000Z");
      const boundaryAttestedAt = now.getTime() - ATTESTATION_MAX_AGE_MS;
      attestation.body.attested_at = new Date(boundaryAttestedAt).toISOString();
      attestation.body.expires_at = now.toISOString();
      resignAttestation(attestation, agentA);

      const result = verifyAttestation(attestation, now);
      expect(result.valid).toBe(false);
      expect(result.expired).toBe(true);
      expect(result.errors).toContain("Attestation has expired");
      expect(result.errors.some(error => error.includes("relying-party age"))).toBe(false);
    });

    it("rejects attestation signed by wrong key", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();
      const agentC = makeAgent(); // impersonator

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      // Agent A generates the attestation
      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      // Swap the signed_by to C's key (signature won't match)
      const shrC = agentSHR(agentC);
      attestation.signed_by = shrC.signed_by;

      const result = verifyAttestation(attestation);

      expect(result.valid).toBe(false);
    });
  });

  describe("Human-readable summary", () => {
    it("contains key information", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      const summary = attestation.summary;

      expect(summary).toContain("Sovereignty Attestation");
      expect(summary).toContain("Attester:");
      expect(summary).toContain("Subject:");
      expect(summary).toContain("Result:");
      expect(summary).toContain("L1 Cognitive Sovereignty");
      expect(summary).toContain("L2 Operational Isolation");
      expect(summary).toContain("L3 Selective Disclosure");
      expect(summary).toContain("L4 Verifiable Reputation");
      expect(summary).toContain("Ed25519");
    });

    it("shows correct tier label for degraded agents", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        livenessProven: true,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      expect(attestation.summary).toContain("Verified (Degraded)");
    });
  });

  describe("Round-trip: generate and verify", () => {
    it("attestation survives serialization round-trip", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const shrB = agentSHR(agentB);
      const verification = verifySHR(shrB);

      const attestation = generateAttestation({
        attesterSHR: shrA,
        subjectSHR: shrB,
        verificationResult: verification,
        identityManager: agentA.identityManager as any,
        masterKey: agentA.masterKey,
      });

      if ("error" in attestation) throw new Error(attestation.error);

      // Simulate sending over the wire
      const serialized = JSON.stringify(attestation);
      const deserialized: SignedAttestation = JSON.parse(serialized);

      const result = verifyAttestation(deserialized);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });
});
