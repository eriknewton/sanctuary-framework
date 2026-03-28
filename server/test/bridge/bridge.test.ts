/**
 * Concordia Bridge — Tests
 *
 * Tests for the Sanctuary-Concordia bridge: commitment creation,
 * verification, canonical serialization, and attestation linking.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { toBase64url, fromBase64url, stringToBytes } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import {
  createBridgeCommitment,
  verifyBridgeCommitment,
  canonicalize,
} from "../../src/bridge/bridge.js";
import type { ConcordiaOutcome, BridgeCommitment } from "../../src/bridge/types.js";

// ─── Test Helpers ────────────────────────────────────────────────────────

function makeOutcome(overrides?: Partial<ConcordiaOutcome>): ConcordiaOutcome {
  const terms = { price: 100, currency: "USD", delivery: "2026-04-15" };
  const termsHash = toBase64url(hash(stringToBytes(stableStringify(terms))));

  return {
    session_id: "concordia-session-001",
    protocol_version: "concordia-v1",
    proposer_did: "did:sanctuary:proposer123",
    acceptor_did: "did:sanctuary:acceptor456",
    terms,
    terms_hash: termsHash,
    rounds: 3,
    accepted_at: "2026-03-28T12:00:00.000Z",
    ...overrides,
  };
}

/** Same stable stringify used in the bridge module */
function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k]));
  return "{" + pairs.join(",") + "}";
}

// ─── Tests ───────────────────────────────────────────────────────────────

describe("Concordia Bridge", () => {
  let masterKey: Uint8Array;
  let identityEncKey: Uint8Array;
  let identity: ReturnType<typeof createIdentity>["storedIdentity"];
  let publicKey: Uint8Array;

  beforeEach(() => {
    masterKey = generateRandomKey();
    identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const created = createIdentity("bridge-test", identityEncKey, "recovery-key");
    identity = created.storedIdentity;
    publicKey = fromBase64url(created.publicIdentity.public_key);
  });

  // ── Canonical Serialization ────────────────────────────────────────────

  describe("canonicalize()", () => {
    it("produces deterministic output regardless of key order", () => {
      const outcome1 = makeOutcome();
      const outcome2: ConcordiaOutcome = {
        accepted_at: outcome1.accepted_at,
        rounds: outcome1.rounds,
        terms_hash: outcome1.terms_hash,
        terms: outcome1.terms,
        acceptor_did: outcome1.acceptor_did,
        proposer_did: outcome1.proposer_did,
        protocol_version: outcome1.protocol_version,
        session_id: outcome1.session_id,
      };

      const bytes1 = canonicalize(outcome1);
      const bytes2 = canonicalize(outcome2);

      expect(toBase64url(bytes1)).toBe(toBase64url(bytes2));
    });

    it("produces different output for different outcomes", () => {
      const outcome1 = makeOutcome({ rounds: 3 });
      const outcome2 = makeOutcome({ rounds: 5 });

      const bytes1 = canonicalize(outcome1);
      const bytes2 = canonicalize(outcome2);

      expect(toBase64url(bytes1)).not.toBe(toBase64url(bytes2));
    });

    it("handles nested terms objects deterministically", () => {
      const terms1 = { z: { b: 2, a: 1 }, a: "first" };
      const terms2 = { a: "first", z: { a: 1, b: 2 } };

      const termsHash = toBase64url(hash(stringToBytes(stableStringify(terms1))));

      const outcome1 = makeOutcome({ terms: terms1, terms_hash: termsHash });
      const outcome2 = makeOutcome({ terms: terms2, terms_hash: termsHash });

      expect(toBase64url(canonicalize(outcome1))).toBe(
        toBase64url(canonicalize(outcome2))
      );
    });
  });

  // ── Bridge Commit ──────────────────────────────────────────────────────

  describe("createBridgeCommitment()", () => {
    it("creates a valid bridge commitment", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      expect(commitment.bridge_commitment_id).toMatch(/^bridge-/);
      expect(commitment.session_id).toBe(outcome.session_id);
      expect(commitment.sha256_commitment).toBeTruthy();
      expect(commitment.blinding_factor).toBeTruthy();
      expect(commitment.committer_did).toBe(identity.did);
      expect(commitment.signature).toBeTruthy();
      expect(commitment.bridge_version).toBe("sanctuary-concordia-bridge-v1");
      expect(commitment.pedersen_commitment).toBeUndefined();
    });

    it("includes Pedersen commitment when requested", () => {
      const outcome = makeOutcome({ rounds: 5 });
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        true
      );

      expect(commitment.pedersen_commitment).toBeDefined();
      expect(commitment.pedersen_commitment!.commitment).toBeTruthy();
      expect(commitment.pedersen_commitment!.blinding_factor).toBeTruthy();
    });

    it("produces unique commitment IDs", () => {
      const outcome = makeOutcome();
      const c1 = createBridgeCommitment(outcome, identity, identityEncKey);
      const c2 = createBridgeCommitment(outcome, identity, identityEncKey);

      expect(c1.bridge_commitment_id).not.toBe(c2.bridge_commitment_id);
    });

    it("produces unique blinding factors", () => {
      const outcome = makeOutcome();
      const c1 = createBridgeCommitment(outcome, identity, identityEncKey);
      const c2 = createBridgeCommitment(outcome, identity, identityEncKey);

      expect(c1.blinding_factor).not.toBe(c2.blinding_factor);
      expect(c1.sha256_commitment).not.toBe(c2.sha256_commitment);
    });
  });

  // ── Bridge Verify ──────────────────────────────────────────────────────

  describe("verifyBridgeCommitment()", () => {
    it("verifies a valid commitment", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      const result = verifyBridgeCommitment(commitment, outcome, publicKey);

      expect(result.valid).toBe(true);
      expect(result.checks.sha256_match).toBe(true);
      expect(result.checks.signature_valid).toBe(true);
      expect(result.checks.session_id_match).toBe(true);
      expect(result.checks.terms_hash_match).toBe(true);
    });

    it("verifies commitment with Pedersen", () => {
      const outcome = makeOutcome({ rounds: 7 });
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        true
      );

      const result = verifyBridgeCommitment(commitment, outcome, publicKey);

      expect(result.valid).toBe(true);
      expect(result.checks.pedersen_match).toBe(true);
    });

    it("detects tampered terms", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      // Tamper with the terms
      const tamperedOutcome = makeOutcome({
        terms: { price: 999, currency: "USD", delivery: "2026-04-15" },
      });

      const result = verifyBridgeCommitment(
        commitment,
        tamperedOutcome,
        publicKey
      );

      expect(result.valid).toBe(false);
      expect(result.checks.sha256_match).toBe(false);
    });

    it("detects tampered session ID", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      const tamperedOutcome = makeOutcome({
        session_id: "tampered-session-id",
      });

      const result = verifyBridgeCommitment(
        commitment,
        tamperedOutcome,
        publicKey
      );

      expect(result.valid).toBe(false);
      expect(result.checks.session_id_match).toBe(false);
    });

    it("detects wrong public key (signature fails)", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      // Create a different identity's public key
      const otherIdentity = createIdentity("other", identityEncKey, "recovery-key");
      const wrongKey = fromBase64url(otherIdentity.publicIdentity.public_key);

      const result = verifyBridgeCommitment(commitment, outcome, wrongKey);

      expect(result.valid).toBe(false);
      expect(result.checks.signature_valid).toBe(false);
    });

    it("detects tampered round count (Pedersen fails)", () => {
      const outcome = makeOutcome({ rounds: 3 });
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        true
      );

      const tamperedOutcome = makeOutcome({ rounds: 10 });

      const result = verifyBridgeCommitment(
        commitment,
        tamperedOutcome,
        publicKey
      );

      expect(result.valid).toBe(false);
      // SHA-256 fails too since the canonical serialization includes rounds
      expect(result.checks.sha256_match).toBe(false);
      expect(result.checks.pedersen_match).toBe(false);
    });

    it("detects mismatched terms_hash", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      // Change the terms_hash to something wrong
      const tamperedOutcome = {
        ...outcome,
        terms_hash: toBase64url(hash(stringToBytes("wrong"))),
      };

      const result = verifyBridgeCommitment(
        commitment,
        tamperedOutcome,
        publicKey
      );

      expect(result.valid).toBe(false);
      // SHA-256 fails because terms_hash is part of the canonical serialization
      expect(result.checks.sha256_match).toBe(false);
      expect(result.checks.terms_hash_match).toBe(false);
    });
  });

  // ── Bridge Commitment Structure ────────────────────────────────────────

  describe("commitment structure", () => {
    it("uses the correct bridge version", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey
      );

      expect(commitment.bridge_version).toBe("sanctuary-concordia-bridge-v1");
    });

    it("sets committer_did from the signing identity", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey
      );

      expect(commitment.committer_did).toBe(identity.did);
    });

    it("includes a timestamp", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey
      );

      expect(commitment.committed_at).toBeTruthy();
      // Should be a valid ISO 8601 date
      expect(new Date(commitment.committed_at).toISOString()).toBe(
        commitment.committed_at
      );
    });
  });
});
