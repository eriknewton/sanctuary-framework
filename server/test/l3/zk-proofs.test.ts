/**
 * Zero-Knowledge Proofs — Tests
 *
 * Tests for Pedersen commitments, proofs of knowledge,
 * range proofs, and their verification on Ristretto255.
 */

import { describe, it, expect } from "vitest";
import {
  createPedersenCommitment,
  verifyPedersenCommitment,
  createProofOfKnowledge,
  verifyProofOfKnowledge,
  createRangeProof,
  verifyRangeProof,
} from "../../src/l3-disclosure/zk-proofs.js";

describe("Zero-Knowledge Proofs (Ristretto255)", () => {
  // ── Pedersen Commitments ─────────────────────────────────────────────

  describe("Pedersen Commitments", () => {
    it("creates a commitment to a value", () => {
      const commitment = createPedersenCommitment(42);

      expect(commitment.commitment).toBeTruthy();
      expect(commitment.blinding_factor).toBeTruthy();
      expect(commitment.committed_at).toBeTruthy();
    });

    it("produces different commitments for the same value (random blinding)", () => {
      const c1 = createPedersenCommitment(42);
      const c2 = createPedersenCommitment(42);

      // Same value but different blinding → different commitments
      expect(c1.commitment).not.toBe(c2.commitment);
    });

    it("verifies a correct commitment opening", () => {
      const commitment = createPedersenCommitment(100);
      const valid = verifyPedersenCommitment(
        commitment.commitment,
        100,
        commitment.blinding_factor
      );
      expect(valid).toBe(true);
    });

    it("rejects an incorrect value", () => {
      const commitment = createPedersenCommitment(100);
      const valid = verifyPedersenCommitment(
        commitment.commitment,
        101, // Wrong value
        commitment.blinding_factor
      );
      expect(valid).toBe(false);
    });

    it("rejects an incorrect blinding factor", () => {
      const c1 = createPedersenCommitment(100);
      const c2 = createPedersenCommitment(100);
      // Use c2's blinding factor with c1's commitment
      const valid = verifyPedersenCommitment(
        c1.commitment,
        100,
        c2.blinding_factor
      );
      expect(valid).toBe(false);
    });

    it("handles zero value", () => {
      const commitment = createPedersenCommitment(0);
      const valid = verifyPedersenCommitment(
        commitment.commitment,
        0,
        commitment.blinding_factor
      );
      expect(valid).toBe(true);
    });
  });

  // ── ZK Proof of Knowledge ───────────────────────────────────────────

  describe("Proof of Knowledge", () => {
    it("creates and verifies a valid proof", () => {
      const commitment = createPedersenCommitment(42);
      const proof = createProofOfKnowledge(
        42,
        commitment.blinding_factor,
        commitment.commitment
      );

      expect(proof.type).toBe("schnorr-pedersen-ristretto255");
      expect(verifyProofOfKnowledge(proof)).toBe(true);
    });

    it("rejects a proof with a tampered announcement", () => {
      const commitment = createPedersenCommitment(42);
      const proof = createProofOfKnowledge(
        42,
        commitment.blinding_factor,
        commitment.commitment
      );

      // Tamper with the announcement
      const tampered = { ...proof, announcement: proof.response_v }; // swap
      expect(verifyProofOfKnowledge(tampered)).toBe(false);
    });

    it("rejects a proof with tampered responses", () => {
      const commitment = createPedersenCommitment(42);
      const proof = createProofOfKnowledge(
        42,
        commitment.blinding_factor,
        commitment.commitment
      );

      // Swap responses
      const tampered = { ...proof, response_v: proof.response_b, response_b: proof.response_v };
      expect(verifyProofOfKnowledge(tampered)).toBe(false);
    });

    it("proofs for different values are independently valid", () => {
      const c1 = createPedersenCommitment(10);
      const c2 = createPedersenCommitment(20);

      const p1 = createProofOfKnowledge(10, c1.blinding_factor, c1.commitment);
      const p2 = createProofOfKnowledge(20, c2.blinding_factor, c2.commitment);

      expect(verifyProofOfKnowledge(p1)).toBe(true);
      expect(verifyProofOfKnowledge(p2)).toBe(true);
    });

    it("a proof for one commitment doesn't verify against another", () => {
      const c1 = createPedersenCommitment(10);
      const c2 = createPedersenCommitment(20);

      const proof = createProofOfKnowledge(10, c1.blinding_factor, c1.commitment);
      // Swap the commitment reference
      const wrongCommitment = { ...proof, commitment: c2.commitment };
      expect(verifyProofOfKnowledge(wrongCommitment)).toBe(false);
    });
  });

  // ── ZK Range Proofs ─────────────────────────────────────────────────

  describe("Range Proofs", () => {
    it("creates and verifies a valid range proof", () => {
      const commitment = createPedersenCommitment(75);
      const proof = createRangeProof(
        75,
        commitment.blinding_factor,
        commitment.commitment,
        0,
        100
      );

      expect("error" in proof).toBe(false);
      if (!("error" in proof)) {
        expect(proof.type).toBe("range-pedersen-ristretto255");
        expect(verifyRangeProof(proof)).toBe(true);
      }
    });

    it("rejects a value outside the range", () => {
      const commitment = createPedersenCommitment(101);
      const proof = createRangeProof(
        101,
        commitment.blinding_factor,
        commitment.commitment,
        0,
        100
      );

      expect("error" in proof).toBe(true);
    });

    it("works at range boundaries", () => {
      // Test minimum
      const cMin = createPedersenCommitment(0);
      const pMin = createRangeProof(0, cMin.blinding_factor, cMin.commitment, 0, 100);
      expect("error" in pMin).toBe(false);
      if (!("error" in pMin)) {
        expect(verifyRangeProof(pMin)).toBe(true);
      }

      // Test maximum
      const cMax = createPedersenCommitment(100);
      const pMax = createRangeProof(100, cMax.blinding_factor, cMax.commitment, 0, 100);
      expect("error" in pMax).toBe(false);
      if (!("error" in pMax)) {
        expect(verifyRangeProof(pMax)).toBe(true);
      }
    });

    it("works for small ranges", () => {
      const commitment = createPedersenCommitment(3);
      const proof = createRangeProof(
        3,
        commitment.blinding_factor,
        commitment.commitment,
        1,
        7
      );

      expect("error" in proof).toBe(false);
      if (!("error" in proof)) {
        expect(proof.bit_commitments.length).toBe(3); // ceil(log2(7)) = 3 bits
        expect(verifyRangeProof(proof)).toBe(true);
      }
    });

    it("range proof for one range doesn't verify with a different range", () => {
      const commitment = createPedersenCommitment(50);
      const proof = createRangeProof(
        50,
        commitment.blinding_factor,
        commitment.commitment,
        0,
        100
      );

      expect("error" in proof).toBe(false);
      if (!("error" in proof)) {
        // Tamper with the range
        const tampered = { ...proof, min: 60 }; // Value 50 is no longer in [60, 100]
        expect(verifyRangeProof(tampered)).toBe(false);
      }
    });
  });
});
