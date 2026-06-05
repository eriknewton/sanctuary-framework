/**
 * Sovereignty Attestation Artifacts — Tests
 *
 * Tests for one-shot handshake exchange, attestation generation,
 * attestation verification, tamper detection, and expiry handling.
 */

import { describe, it, expect } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateSHR } from "../../src/shr/generator.js";
import { verifySHR } from "../../src/shr/verifier.js";
import {
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
