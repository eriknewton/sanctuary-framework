/**
 * Key 17 -- x402 sovereign signer.
 *
 * Ed25519 detached signature over canonical JSON for x402 settlement envelopes.
 * The operator's signing key is derived via HKDF from their master key with a
 * protocol-specific tag, ensuring key isolation across composition surfaces.
 *
 * The x402 spec expects an HTTP-level signed request envelope. This module
 * produces the detached signature; the caller assembles the final wire format.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { toBase64url } from "../core/encoding.js";

/** Shape of an x402 request envelope prior to signing. */
export interface X402Request {
  /** Payment amount in the smallest unit of the denominated currency. */
  amount: string;
  /** ISO 4217 currency code or chain-native token symbol. */
  currency: string;
  /** Counterparty identifier (wallet address or agent id). */
  counterparty: string;
  /** Human-readable description of the payment purpose. */
  description?: string;
  /** ISO 8601 timestamp of the request. */
  timestamp: string;
  /** Nonce to prevent replay. */
  nonce: string;
  /** Additional protocol-level fields the caller may include. */
  [key: string]: unknown;
}

/** A signed x402 request envelope. */
export interface SignedX402Request extends X402Request {
  /** Detached Ed25519 signature over canonical JSON of the unsigned request, base64url-encoded. */
  signature: string;
  /** Signature algorithm identifier. */
  algorithm: "EdDSA";
  /** Operator's public key for verification, base64url-encoded. */
  public_key: string;
}

/**
 * Derive a protocol-scoped Ed25519 private key from the operator's master key.
 *
 * Uses HKDF-SHA256 with the operator ID as salt and a protocol tag in the
 * info parameter. This ensures the same master key produces distinct keys
 * for each protocol surface and each operator.
 */
export function deriveX402Key(
  masterKey: Uint8Array,
  operatorId: string
): Uint8Array {
  return hkdf(
    sha256,
    masterKey,
    new TextEncoder().encode(operatorId),
    new TextEncoder().encode("key-17:x402-signer:v1"),
    32
  );
}

/**
 * Sign an x402 request envelope with the operator's derived key.
 *
 * The signature covers the canonical JSON of the request (excluding the
 * signature, algorithm, and public_key fields themselves). Verification
 * requires re-canonicalizing the unsigned fields and checking against the
 * included public key.
 */
export function signX402Request(
  masterKey: Uint8Array,
  operatorId: string,
  request: X402Request
): SignedX402Request {
  const privateKey = deriveX402Key(masterKey, operatorId);
  const publicKey = ed25519.getPublicKey(privateKey);
  const bytes = canonicalizeToBytes(request);
  const sig = ed25519.sign(bytes, privateKey);
  return {
    ...request,
    signature: toBase64url(sig),
    algorithm: "EdDSA",
    public_key: toBase64url(publicKey),
  };
}

/**
 * Verify a signed x402 request.
 *
 * Strips signature, algorithm, and public_key fields, re-canonicalizes,
 * and checks the Ed25519 signature against the embedded public key.
 */
export function verifyX402Request(signed: SignedX402Request): boolean {
  const { signature, algorithm, public_key, ...unsigned } = signed;
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
