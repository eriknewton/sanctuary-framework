/**
 * L3 Commitment Scheme Tests
 *
 * Verifies:
 * - Commitments are hiding (hash reveals nothing about value)
 * - Commitments are binding (cannot change value after committing)
 * - Blinding factors are random and unique
 * - Verification succeeds with correct reveal
 * - Verification fails with wrong value or wrong blinding factor
 * - CommitmentStore encrypts at rest
 */

import { describe, it, expect } from "vitest";
import {
  createCommitment,
  verifyCommitment,
  CommitmentStore,
} from "../../src/l3-disclosure/commitments.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

describe("L3 Commitment Schemes", () => {
  describe("createCommitment", () => {
    it("creates a commitment with auto-generated blinding factor", () => {
      const commitment = createCommitment("secret-value");

      expect(commitment.commitment).toBeTruthy();
      expect(commitment.blinding_factor).toBeTruthy();
      expect(commitment.committed_at).toBeTruthy();
      // base64url characters only
      expect(commitment.commitment).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(commitment.blinding_factor).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it("produces different commitments for the same value (different blinding)", () => {
      const c1 = createCommitment("same-value");
      const c2 = createCommitment("same-value");

      expect(c1.commitment).not.toBe(c2.commitment);
      expect(c1.blinding_factor).not.toBe(c2.blinding_factor);
    });

    it("produces same commitment with same blinding factor", () => {
      const c1 = createCommitment("test-value");
      const c2 = createCommitment("test-value", c1.blinding_factor);

      expect(c1.commitment).toBe(c2.commitment);
    });

    it("produces different commitments for different values", () => {
      const bf = createCommitment("a").blinding_factor;
      const c1 = createCommitment("value-a", bf);
      const c2 = createCommitment("value-b", bf);

      expect(c1.commitment).not.toBe(c2.commitment);
    });
  });

  describe("verifyCommitment", () => {
    it("verifies correct reveal", () => {
      const value = "my-secret-claim";
      const commitment = createCommitment(value);

      const valid = verifyCommitment(
        commitment.commitment,
        value,
        commitment.blinding_factor
      );

      expect(valid).toBe(true);
    });

    it("rejects wrong value", () => {
      const commitment = createCommitment("correct-value");

      const valid = verifyCommitment(
        commitment.commitment,
        "wrong-value",
        commitment.blinding_factor
      );

      expect(valid).toBe(false);
    });

    it("rejects wrong blinding factor", () => {
      const commitment = createCommitment("my-value");
      const otherCommitment = createCommitment("other");

      const valid = verifyCommitment(
        commitment.commitment,
        "my-value",
        otherCommitment.blinding_factor
      );

      expect(valid).toBe(false);
    });

    it("uses constant-time comparison (audit #15)", () => {
      // Verify that the function correctly handles the constant-time path
      // by testing matching and non-matching commitments both work
      const value = "timing-safe-test";
      const c = createCommitment(value);

      // Valid commitment
      expect(verifyCommitment(c.commitment, value, c.blinding_factor)).toBe(true);

      // Commitment with single-char difference at a leading position (would
      // reveal via timing in naive ===). The hash is 32 bytes, so base64url
      // encodes to 43 chars where the *last* char only contributes 4 bits
      // with 2 forced-zero padding bits. Tampering only the last char can
      // therefore decode back to the same 32 bytes and fail this assertion.
      // Tamper the first char, which contributes all 6 of its bits to the
      // first byte — always produces different bytes.
      const tampered = (c.commitment[0] === "A" ? "B" : "A") + c.commitment.slice(1);
      expect(verifyCommitment(tampered, value, c.blinding_factor)).toBe(false);

      // Empty commitment
      expect(verifyCommitment("", value, c.blinding_factor)).toBe(false);
    });
  });

  describe("CommitmentStore", () => {
    it("stores and retrieves commitments encrypted", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new CommitmentStore(storage, masterKey);

      const commitment = createCommitment("stored-value");
      const id = await store.store(commitment, "stored-value");

      expect(id).toMatch(/^cmt-/);

      const retrieved = await store.get(id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.commitment).toBe(commitment.commitment);
      expect(retrieved!.value).toBe("stored-value");
      expect(retrieved!.revealed).toBe(false);
    });

    it("marks commitments as revealed", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new CommitmentStore(storage, masterKey);

      const commitment = createCommitment("to-reveal");
      const id = await store.store(commitment, "to-reveal");

      await store.markRevealed(id);

      const retrieved = await store.get(id);
      expect(retrieved!.revealed).toBe(true);
      expect(retrieved!.revealed_at).toBeTruthy();
    });

    it("returns null for non-existent commitment", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new CommitmentStore(storage, masterKey);

      const result = await store.get("non-existent-id");
      expect(result).toBeNull();
    });

    it("plaintext value never appears in raw storage", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new CommitmentStore(storage, masterKey);

      const secretValue = "SUPER_SECRET_VALUE_12345";
      const commitment = createCommitment(secretValue);
      await store.store(commitment, secretValue);

      // Scan all stored bytes for the plaintext
      const entries = await storage.list("_commitments");
      for (const entry of entries) {
        const raw = await storage.read("_commitments", entry.key);
        if (!raw) continue;
        const rawStr = new TextDecoder().decode(raw);
        expect(rawStr).not.toContain(secretValue);
      }
    });
  });
});
