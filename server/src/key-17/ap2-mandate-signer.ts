/**
 * Key 17 -- AP2 mandate signer.
 *
 * Ed25519 detached signature over canonical JSON for Google AP2 agent-payment
 * mandate envelopes. The mandate format follows the AP2 spec; Sanctuary signs
 * operator-issued mandates with operator-held keys derived via HKDF.
 *
 * Composes with Concordia v0.6 receipt envelope (similar canonical JSON shape).
 * The Concordia commitment envelope can carry AP2-compatible mandates; this
 * module provides the signing primitive that makes them operator-sovereign.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { toBase64url } from "../core/encoding.js";

/** Shape of an AP2 agent-payment mandate. */
export interface Ap2Mandate {
  /** Mandate type (e.g. "payment", "authorization", "delegation"). */
  mandate_type: string;
  /** Issuing operator or agent identifier. */
  issuer: string;
  /** Target agent or service that should act on the mandate. */
  target: string;
  /** Mandate payload per AP2 spec (amount, currency, conditions, etc.). */
  payload: Record<string, unknown>;
  /** ISO 8601 timestamp of mandate issuance. */
  issued_at: string;
  /** ISO 8601 expiration timestamp. */
  expires_at: string;
  /** Nonce for replay protection. */
  nonce: string;
  /** AP2 spec version this mandate conforms to. */
  spec_version: string;
  /** Additional fields per AP2 extensions. */
  [key: string]: unknown;
}

/** A signed AP2 mandate. */
export interface SignedAp2Mandate extends Ap2Mandate {
  /** Detached Ed25519 signature over canonical JSON of the unsigned mandate, base64url-encoded. */
  signature: string;
  /** Signature algorithm identifier. */
  algorithm: "EdDSA";
  /** Operator's public key for verification, base64url-encoded. */
  public_key: string;
}

/**
 * Derive a protocol-scoped Ed25519 private key for AP2 mandate signing.
 */
export function deriveAp2Key(
  masterKey: Uint8Array,
  operatorId: string
): Uint8Array {
  return hkdf(
    sha256,
    masterKey,
    new TextEncoder().encode(operatorId),
    new TextEncoder().encode("key-17:ap2-mandate:v1"),
    32
  );
}

/**
 * Sign an AP2 mandate with the operator's derived key.
 *
 * The signature covers the canonical JSON of the mandate (excluding
 * signature, algorithm, and public_key fields). This ensures the mandate
 * is tamper-evident and attributable to the operator.
 */
export function signAp2Mandate(
  masterKey: Uint8Array,
  operatorId: string,
  mandate: Ap2Mandate
): SignedAp2Mandate {
  const privateKey = deriveAp2Key(masterKey, operatorId);
  const publicKey = ed25519.getPublicKey(privateKey);
  const bytes = canonicalizeToBytes(mandate);
  const sig = ed25519.sign(bytes, privateKey);
  return {
    ...mandate,
    signature: toBase64url(sig),
    algorithm: "EdDSA",
    public_key: toBase64url(publicKey),
  };
}

/**
 * Verify a signed AP2 mandate.
 *
 * Strips signature, algorithm, and public_key fields, re-canonicalizes,
 * and checks the Ed25519 signature against the embedded public key.
 */
export function verifyAp2Mandate(signed: SignedAp2Mandate): boolean {
  const { signature, algorithm: _algorithm, public_key, ...unsigned } = signed;
  const bytes = canonicalizeToBytes(unsigned);
  const sigBytes = Buffer.from(
    signature.replace(/-/g, "+").replace(/_/g, "/") + "==",
    "base64"
  );
  const pubBytes = Buffer.from(
    public_key.replace(/-/g, "+").replace(/_/g, "/") + "==",
    "base64"
  );
  return ed25519.verify(
    new Uint8Array(sigBytes.buffer, sigBytes.byteOffset, sigBytes.byteLength),
    bytes,
    new Uint8Array(pubBytes.buffer, pubBytes.byteOffset, pubBytes.byteLength)
  );
}
