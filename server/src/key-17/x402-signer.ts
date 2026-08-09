/**
 * Key 17 -- x402 sovereign signer.
 *
 * Ed25519 detached signature over canonical JSON for x402 settlement envelopes.
 * The operator's signing key is derived via HKDF from their master key with a
 * protocol-specific tag, ensuring key isolation across composition surfaces.
 *
 * The x402 spec expects an HTTP-level signed request envelope. This module
 * produces the detached signature; the caller assembles the final wire format.
 * This primitive verifies signatures only: nonce freshness and spent-set
 * replay refusal are the responsibility of the consumer that wires x402 use.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import {
  constantTimeEqual,
  fromBase64urlStrict,
  toBase64url,
} from "../core/encoding.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../core/crypto-suite-registry.js";

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

export interface VerifyX402RequestOptions {
  /** Base64url raw 32-byte Ed25519 public key obtained out-of-band. */
  trustedPublicKey?: string;
  /**
   * Explicit opt-in to verify against the key embedded in the request.
   * This proves internal consistency only, not signer identity.
   */
  trustEmbedded?: boolean;
}

export interface X402RequestVerificationResult {
  valid: boolean;
  signature_basis: "trusted" | "embedded" | "none";
  freshness: "not_checked";
  reason?:
    | "trusted_public_key_required"
    | "public_key_mismatch"
    | "malformed_signature"
    | "malformed_public_key"
    | "signature_invalid";
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
  // x402 derives a protocol-scoped subkey so a settlement signature cannot be
  // replayed as another Key 17 protocol's authority.
  const privateKey = deriveX402Key(masterKey, operatorId);
  const publicKey = ed25519.getPublicKey(privateKey);
  // The signature covers caller-supplied request fields only; verifier code
  // must strip signature metadata before recomputing these bytes.
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
 * Strips signature, algorithm, and public_key fields, re-canonicalizes, and
 * checks the Ed25519 signature. By default the verifier requires a trusted
 * out-of-band public key; `trustEmbedded` is an explicit weaker basis that
 * proves only internal consistency. This primitive does not consume or persist
 * nonces, so anti-replay MUST be enforced by any future x402 consumer before
 * it treats a valid signature as an authorization.
 */
export function verifyX402Request(
  signed: SignedX402Request,
  opts: VerifyX402RequestOptions = {}
): X402RequestVerificationResult {
  const { signature, algorithm: _algorithm, public_key, ...unsigned } = signed;
  const bytes = canonicalizeToBytes(unsigned);
  const freshness = "not_checked";

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64urlStrict(signature);
  } catch {
    return {
      valid: false,
      signature_basis: "none",
      freshness,
      reason: "malformed_signature",
    };
  }
  // 64 = RFC 8032 Ed25519 signature (R||S); a different length is not a
  // signature for this scheme and must fail before crypto verification.
  if (signatureBytes.length !== ED25519_SIGNATURE_BYTES) {
    return {
      valid: false,
      signature_basis: "none",
      freshness,
      reason: "malformed_signature",
    };
  }

  let embeddedPublicKey: Uint8Array;
  try {
    embeddedPublicKey = fromBase64urlStrict(public_key);
  } catch {
    return {
      valid: false,
      signature_basis: "none",
      freshness,
      reason: "malformed_public_key",
    };
  }
  // 32 = RFC 8032 Ed25519 public key; accepting any other byte width would
  // make the signature basis ambiguous.
  if (embeddedPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    return {
      valid: false,
      signature_basis: "none",
      freshness,
      reason: "malformed_public_key",
    };
  }

  let basis: "trusted" | "embedded";
  let verificationKey: Uint8Array;
  if (opts.trustedPublicKey) {
    try {
      verificationKey = fromBase64urlStrict(opts.trustedPublicKey);
    } catch {
      return {
        valid: false,
        signature_basis: "trusted",
        freshness,
        reason: "malformed_public_key",
      };
    }
    if (verificationKey.length !== ED25519_PUBLIC_KEY_BYTES) {
      return {
        valid: false,
        signature_basis: "trusted",
        freshness,
        reason: "malformed_public_key",
      };
    }
    // The embedded public key is unsigned metadata; a trusted-key verify must
    // also require it to match so callers cannot echo attacker-chosen key
    // material beside a valid trusted signature.
    if (!constantTimeEqual(embeddedPublicKey, verificationKey)) {
      return {
        valid: false,
        signature_basis: "trusted",
        freshness,
        reason: "public_key_mismatch",
      };
    }
    basis = "trusted";
  } else if (opts.trustEmbedded) {
    // Embedded-key verification is explicit because it proves only that this
    // request matches its own carried key, not that the key belongs to anyone.
    verificationKey = embeddedPublicKey;
    basis = "embedded";
  } else {
    return {
      valid: false,
      signature_basis: "none",
      freshness,
      reason: "trusted_public_key_required",
    };
  }

  // Verification recomputes the canonical request bytes after stripping
  // signature metadata, so unsigned metadata cannot change what was signed.
  const valid = ed25519.verify(signatureBytes, bytes, verificationKey);
  return {
    valid,
    signature_basis: basis,
    freshness,
    ...(valid ? {} : { reason: "signature_invalid" as const }),
  };
}
