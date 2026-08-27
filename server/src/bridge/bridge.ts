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

import { createCommitment, verifyCommitment } from "../disclosure/commitments.js";
import { createPedersenCommitment, verifyPedersenCommitment } from "../disclosure/zk-proofs.js";
import { sign, verify } from "../core/identity.js";
import { toBase64url, fromBase64url, stringToBytes } from "../core/encoding.js";
import { hash } from "../core/hashing.js";
import { deriveContentId } from "../core/content-id.js";
import type { StoredIdentity } from "../core/identity.js";
import type {
  ConcordiaOutcome,
  BridgeCommitment,
  BridgeVerificationResult,
} from "./types.js";

/**
 * LD6 BP-DEADLINE-03 (Admission_Completion_Design_Brief_2026-08-11.md V2-3):
 * bridge commitment ids are content-derived from `(session_id, terms_hash,
 * committer_did)` rather than random, so a retried `bridge_commit` for the
 * SAME negotiation resolves to the SAME key instead of minting a duplicate.
 * `sanctuary.bridge.commitment` is the domain label; `.v1` is this
 * derivation's version -- bump the suffix (never reuse `v1`) if the tuple or
 * framing ever changes, so old and new ids can never collide in one
 * namespace. CROSS-FILE PIN: the existence guard in bridge/tools.ts
 * (`BridgeStore.save`) recomputes this SAME id from a stored record's own
 * fields to verify intent before honoring `already_committed` -- the tag and
 * tuple order here must stay in lockstep with that recomputation.
 */
export const BRIDGE_COMMITMENT_ID_DOMAIN_TAG = "sanctuary.bridge.commitment.v1";
export const BRIDGE_COMMITMENT_ID_PREFIX = "bridge";

/**
 * The ONE place the bridge id tuple/order is assembled, so
 * `createBridgeCommitment` (minting) and `BridgeStore`'s existence guard
 * (bridge/tools.ts, recomputing from a STORED record's own fields to verify
 * intent) can never drift apart on field order.
 */
export function deriveBridgeCommitmentId(
  sessionId: string,
  termsHash: string,
  committerDid: string
): string {
  return deriveContentId(BRIDGE_COMMITMENT_ID_PREFIX, BRIDGE_COMMITMENT_ID_DOMAIN_TAG, [
    sessionId,
    termsHash,
    committerDid,
  ]);
}

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

/**
 * Recursively sort object keys for deterministic JSON.
 *
 * Security hardening: rejects non-finite numbers (NaN, Infinity, -Infinity)
 * which are not representable in JSON and would produce `null`, breaking
 * commitment determinism. Omits object properties whose value is `undefined`
 * to match JSON/Python absent-optional semantics, and rejects `undefined`
 * anywhere else.
 */
function stableStringify(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) {
    throw new Error(
      "Cannot canonicalize undefined outside an object property. " +
      "Omit absent optional values before canonicalization."
    );
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(
        `Cannot canonicalize non-finite number: ${value}. ` +
        `NaN, Infinity, and -Infinity are not representable in JSON.`
      );
    }
    if (Object.is(value, -0)) {
      throw new Error(
        "Cannot canonicalize negative zero (-0). " +
        "Use 0 instead for deterministic cross-language serialization."
      );
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error(
        `Cannot canonicalize unsafe integer: ${value}. ` +
        "Use a string for integers outside JavaScript's safe range."
      );
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
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
  const now = new Date().toISOString();

  // 0. Recompute terms_hash and fail closed on mismatch.
  //    The signature below binds terms_hash, so the committer must not be able
  //    to sign a hash that is a lie about the terms. This is the SAME recompute
  //    verifyBridgeCommitment performs (terms_hash_match); moving it earlier so
  //    the signature only ever binds a true terms_hash, rather than catching the
  //    lie later at verify/attest time. Generic error: nothing is persisted or
  //    signed.
  const computedTermsHash = toBase64url(hash(stringToBytes(stableStringify(outcome.terms))));
  if (computedTermsHash !== outcome.terms_hash) {
    throw new Error("terms_hash does not match the canonical terms serialization");
  }

  // LD6 BP-DEADLINE-03: content-derived id, computed BEFORE signing (the
  // signature below binds this id inside commitmentPayload) so a retry of
  // this SAME (session_id, terms_hash, committer_did) tuple always produces
  // the SAME id, never a fresh random one. `computedTermsHash` (not
  // `outcome.terms_hash`) is used here even though the equality check above
  // already proved them equal, so the id is derived from the value THIS
  // function computed rather than trusting the caller-supplied field a
  // second time.
  const commitmentId = deriveBridgeCommitmentId(outcome.session_id, computedTermsHash, identity.did);

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
  //    Includes terms_hash so the signature binds the commitment to the specific terms
  const commitmentPayload = {
    bridge_commitment_id: commitmentId,
    session_id: outcome.session_id,
    sha256_commitment: sha256.commitment,
    terms_hash: outcome.terms_hash,
    committer_did: identity.did,
    committed_at: now,
    bridge_version: "sanctuary-concordia-bridge-v1" as const,
  };

  // 5. Sign the commitment with the identity's Ed25519 key
  //    Uses stableStringify (not JSON.stringify) for deterministic key ordering
  //    across languages — required for cross-repo signature verification (SEC-003).
  const payloadBytes = stringToBytes(stableStringify(commitmentPayload));
  const signature = sign(payloadBytes, identity.encrypted_private_key, identityEncryptionKey);

  // Signature coverage boundary: `signature` covers exactly `commitmentPayload`
  // above (bridge_commitment_id, session_id, sha256_commitment, terms_hash,
  // committer_did, committed_at, bridge_version). `blinding_factor` and
  // `pedersen_commitment` below are opening/blinding data that ride OUTSIDE
  // that signed region — a consumer must not treat their presence as
  // signature-backed. This does not open a forgery path: verifyBridgeCommitment
  // recomputes sha256_commitment from canonical(outcome) + blinding_factor
  // rather than trusting a claimed hash, so a tampered blinding_factor or
  // pedersen_commitment only breaks that recompute (or drops the optional
  // ZK-range check); it cannot make a false outcome verify against the signed
  // sha256_commitment.
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

  // 2. Signature check (must match the signing payload exactly)
  //    Uses stableStringify (not JSON.stringify) for deterministic key ordering
  //    across languages — required for cross-repo signature verification (SEC-003).
  //    Trust-boundary invariant: `committerPublicKey` is supplied by the caller.
  //    This function proves only "this key signed this commitment payload"; callers
  //    that surface an identity claim must first bind the key to
  //    `commitment.committer_did` (bridge_verify does this via publicKeyToDid;
  //    bridge_attest uses only a locally resolved identity key).
  const commitmentPayload = {
    bridge_commitment_id: commitment.bridge_commitment_id,
    session_id: commitment.session_id,
    sha256_commitment: commitment.sha256_commitment,
    terms_hash: outcome.terms_hash,
    committer_did: commitment.committer_did,
    committed_at: commitment.committed_at,
    bridge_version: commitment.bridge_version,
  };
  const payloadBytes = stringToBytes(stableStringify(commitmentPayload));
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
