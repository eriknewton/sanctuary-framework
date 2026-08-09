/**
 * Key 17 -- AP2 mandate signer.
 *
 * Ed25519 detached signature over canonical JSON for Google AP2 agent-payment
 * mandate envelopes. The mandate format follows the AP2 spec; Sanctuary signs
 * operator-issued mandates with operator-held keys derived via HKDF.
 * This primitive verifies signatures only: nonce freshness and spent-set
 * replay refusal are the responsibility of the consumer that wires AP2 use.
 *
 * Composes with Concordia v0.6 receipt envelope (similar canonical JSON shape).
 * The Concordia commitment envelope can carry AP2-compatible mandates; this
 * module provides the signing primitive that makes them operator-sovereign.
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

export interface VerifyAp2MandateOptions {
  /** Base64url raw 32-byte Ed25519 public key obtained out-of-band. */
  trustedPublicKey?: string;
  /**
   * Explicit opt-in to verify against the key embedded in the mandate.
   * This proves internal consistency only, not signer identity.
   */
  trustEmbedded?: boolean;
}

export interface Ap2MandateVerificationResult {
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
  // AP2 derives a protocol-scoped subkey so a payment mandate signature cannot
  // be replayed as another Key 17 protocol's authority.
  const privateKey = deriveAp2Key(masterKey, operatorId);
  const publicKey = ed25519.getPublicKey(privateKey);
  // The signature covers caller-supplied mandate fields only; verifier code
  // must strip signature metadata before recomputing these bytes.
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
 * Strips signature, algorithm, and public_key fields, re-canonicalizes, and
 * checks the Ed25519 signature. By default the verifier requires a trusted
 * out-of-band public key; `trustEmbedded` is an explicit weaker basis that
 * proves only internal consistency. This primitive does not consume or persist
 * nonces, so anti-replay MUST be enforced by any future AP2 consumer before it
 * treats a valid signature as an authorization.
 */
export function verifyAp2Mandate(
  signed: SignedAp2Mandate,
  opts: VerifyAp2MandateOptions = {}
): Ap2MandateVerificationResult {
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
    // mandate matches its own carried key, not that the key belongs to anyone.
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

  // Verification recomputes the canonical mandate bytes after stripping
  // signature metadata, so unsigned metadata cannot change what was signed.
  const valid = ed25519.verify(signatureBytes, bytes, verificationKey);
  return {
    valid,
    signature_basis: basis,
    freshness,
    ...(valid ? {} : { reason: "signature_invalid" as const }),
  };
}
