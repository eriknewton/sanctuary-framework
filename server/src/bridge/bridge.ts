/**
 * Sanctuary MCP Server — Concordia Bridge: Core Module
 *
 * Implements the Sanctuary side of the Concordia bridge:
 * 1. bridge_commit — Create a cryptographic commitment binding a negotiation outcome
 * 2. bridge_verify — Verify a commitment against a revealed outcome
 * 3. bridge_attest — Link a negotiation to L4 reputation via the commitment
 *
 * The bridge composes L3 (selective disclosure) and L4 (verifiable reputation)
 * to serve negotiation-specific needs. It introduces no new cryptographic
 * primitives — everything delegates to the existing L3 commitment/ZK layer
 * and L4 reputation store.
 *
 * Non-dependency principle: this module can be used without Concordia
 * running. Any system that provides a ConcordiaOutcome-shaped object
 * can create bridge commitments. Concordia is the expected caller, but
 * the interface is protocol-agnostic.
 */

import { createCommitment, verifyCommitment } from "../l3-disclosure/commitments.js";
import { createPedersenCommitment, verifyPedersenCommitment } from "../l3-disclosure/zk-proofs.js";
import { sign, verify } from "../core/identity.js";
import { toBase64url, fromBase64url, stringToBytes } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { hash } from "../core/hashing.js";
import type { StoredIdentity } from "../core/identity.js";
import type {
  ConcordiaOutcome,
  BridgeCommitment,
  BridgeVerificationResult,
} from "./types.js";

// ─── Canonical Serialization ─────────────────────────────────────────────
// Deterministic JSON serialization of the ConcordiaOutcome for commitment.
// Keys are sorted to ensure identical outcomes produce identical bytes.

/**
 * Produce a canonical byte representation of a ConcordiaOutcome.
 * Sorts all keys recursively to ensure determinism.
 */
export function canonicalize(outcome: ConcordiaOutcome): Uint8Array {
  return stringToBytes(stableStringify(outcome));
}

/** Recursively sort object keys for deterministic JSON */
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

// ─── Bridge Commit ───────────────────────────────────────────────────────

/**
 * Create a cryptographic commitment binding a Concordia negotiation outcome
 * to Sanctuary's L3 proof layer.
 *
 * Creates:
 * 1. A SHA-256 commitment over the canonical outcome (always)
 * 2. A Pedersen commitment over the round count (optional, for ZK range proofs)
 * 3. An Ed25519 signature over the commitment by the committer's identity
 *
 * @param outcome - The Concordia negotiation outcome to bind
 * @param identity - The Sanctuary identity creating the commitment
 * @param identityEncryptionKey - Key to decrypt the identity's private key
 * @param includePedersen - Whether to create a Pedersen commitment on round count
 * @returns The bridge commitment
 */
export function createBridgeCommitment(
  outcome: ConcordiaOutcome,
  identity: StoredIdentity,
  identityEncryptionKey: Uint8Array,
  includePedersen: boolean = false
): BridgeCommitment {
  const commitmentId = `bridge-${Date.now()}-${toBase64url(randomBytes(8))}`;
  const now = new Date().toISOString();

  // 1. Canonical serialization of the outcome
  const canonicalBytes = canonicalize(outcome);
  const canonicalString = new TextDecoder().decode(canonicalBytes);

  // 2. SHA-256 commitment: hash(canonical || blinding_factor)
  const sha256 = createCommitment(canonicalString);

  // 3. Pedersen commitment on round count (optional)
  let pedersenData: BridgeCommitment["pedersen_commitment"] | undefined;
  if (includePedersen && Number.isInteger(outcome.rounds) && outcome.rounds >= 0) {
    const pedersen = createPedersenCommitment(outcome.rounds);
    pedersenData = {
      commitment: pedersen.commitment,
      blinding_factor: pedersen.blinding_factor,
    };
  }

  // 4. Build the commitment payload for signing
  const commitmentPayload = {
    bridge_commitment_id: commitmentId,
    session_id: outcome.session_id,
    sha256_commitment: sha256.commitment,
    committer_did: identity.did,
    committed_at: now,
    bridge_version: "sanctuary-concordia-bridge-v1" as const,
  };

  // 5. Sign the commitment with the identity's Ed25519 key
  const payloadBytes = stringToBytes(JSON.stringify(commitmentPayload));
  const signature = sign(payloadBytes, identity.encrypted_private_key, identityEncryptionKey);

  return {
    bridge_commitment_id: commitmentId,
    session_id: outcome.session_id,
    sha256_commitment: sha256.commitment,
    blinding_factor: sha256.blinding_factor,
    committer_did: identity.did,
    signature: toBase64url(signature),
    pedersen_commitment: pedersenData,
    committed_at: now,
    bridge_version: "sanctuary-concordia-bridge-v1",
  };
}

// ─── Bridge Verify ───────────────────────────────────────────────────────

/**
 * Verify a bridge commitment against a revealed Concordia outcome.
 *
 * Checks:
 * 1. SHA-256 commitment matches the canonical outcome + blinding factor
 * 2. Ed25519 signature is valid for the committer's public key
 * 3. Session IDs match
 * 4. Terms hash matches (Concordia's own hash of the terms)
 * 5. Pedersen commitment matches round count (if present)
 *
 * @param commitment - The bridge commitment to verify
 * @param outcome - The revealed Concordia outcome
 * @param committerPublicKey - The committer's Ed25519 public key
 * @returns Verification result with per-check detail
 */
export function verifyBridgeCommitment(
  commitment: BridgeCommitment,
  outcome: ConcordiaOutcome,
  committerPublicKey: Uint8Array
): BridgeVerificationResult {
  const now = new Date().toISOString();

  // 1. SHA-256 commitment check
  const canonicalString = new TextDecoder().decode(canonicalize(outcome));
  const sha256Match = verifyCommitment(
    commitment.sha256_commitment,
    canonicalString,
    commitment.blinding_factor
  );

  // 2. Signature check
  const commitmentPayload = {
    bridge_commitment_id: commitment.bridge_commitment_id,
    session_id: commitment.session_id,
    sha256_commitment: commitment.sha256_commitment,
    committer_did: commitment.committer_did,
    committed_at: commitment.committed_at,
    bridge_version: commitment.bridge_version,
  };
  const payloadBytes = stringToBytes(JSON.stringify(commitmentPayload));
  const sigBytes = fromBase64url(commitment.signature);
  const signatureValid = verify(payloadBytes, sigBytes, committerPublicKey);

  // 3. Session ID match
  const sessionIdMatch = commitment.session_id === outcome.session_id;

  // 4. Terms hash match — verify Concordia's terms_hash against the actual terms
  const termsBytes = stringToBytes(stableStringify(outcome.terms));
  const computedTermsHash = toBase64url(hash(termsBytes));
  const termsHashMatch = computedTermsHash === outcome.terms_hash;

  // 5. Pedersen match (if present)
  let pedersenMatch: boolean | undefined;
  if (commitment.pedersen_commitment) {
    pedersenMatch = verifyPedersenCommitment(
      commitment.pedersen_commitment.commitment,
      outcome.rounds,
      commitment.pedersen_commitment.blinding_factor
    );
  }

  const valid =
    sha256Match &&
    signatureValid &&
    sessionIdMatch &&
    termsHashMatch &&
    (pedersenMatch === undefined || pedersenMatch);

  return {
    valid,
    checks: {
      sha256_match: sha256Match,
      signature_valid: signatureValid,
      session_id_match: sessionIdMatch,
      terms_hash_match: termsHashMatch,
      pedersen_match: pedersenMatch,
    },
    bridge_commitment_id: commitment.bridge_commitment_id,
    verified_at: now,
  };
}
