/**
 * Sanctuary MCP Server - Ed25519 Identity Management
 *
 * Sovereign identity based on Ed25519 keypairs.
 * Private keys are always encrypted at rest - never stored in plaintext.
 *
 * Security invariants:
 * - Private keys never appear in any MCP tool response
 * - Private keys are encrypted with identity-specific keys derived from the master key
 * - Key rotation records a signed rotation event under the old key
 */

import { ed25519 } from "@noble/curves/ed25519";
import { toBase64url, fromBase64url } from "./encoding.js";
import { encrypt, decrypt, type EncryptedPayload } from "./encryption.js";
import { hash } from "./hashing.js";
import { randomBytes } from "./random.js";

const BASE58BTC_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/** `0xed 0x01` = the multicodec varint for `ed25519-pub`, per the multicodec table. */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);
/**
 * 32 = RFC 8032 §5.1.2, the compressed encoding of an Edwards point.
 *
 * Must match `ED25519_PUBLIC_KEY_BYTES` in `core/crypto-suite-registry.ts`.
 * This module deliberately declares its own copy rather than importing it:
 * `crypto-suite-registry.ts` imports `sign`/`verify` from THIS file, so an
 * import back would close a dependency cycle. `test/structure/`
 * `key-length-constants.test.ts` asserts the two declarations stay equal.
 */
const ED25519_PUBLIC_KEY_LENGTH = 32;

/** Public identity information (safe to share) */
export interface PublicIdentity {
  identity_id: string;
  label: string;
  public_key: string; // base64url
  did: string; // did:key format
  created_at: string;
  key_type: "ed25519";
  key_protection: "passphrase" | "hardware-key" | "recovery-key";
}

/** Stored identity (private key is encrypted) */
export interface StoredIdentity extends PublicIdentity {
  encrypted_private_key: EncryptedPayload;
  /** Previous public keys (for rotation chain verification) */
  rotation_history: Array<{
    old_public_key: string;
    new_public_key: string;
    rotation_event: string; // base64url signed event
    rotated_at: string;
  }>;
}

/** Signed rotation event */
export interface RotationEvent {
  old_public_key: string;
  new_public_key: string;
  identity_id: string;
  reason: string;
  rotated_at: string;
  /** Signature over the event by the OLD key (proves the holder authorized rotation) */
  signature: string;
}

/**
 * Generate a new Ed25519 keypair.
 * Returns both the public identity info and the raw private key (for immediate encryption).
 */
export function generateKeypair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Create a DID from an Ed25519 public key.
 * Uses the did:key method with the Ed25519 multicodec prefix (0xed01).
 */
export function publicKeyToDid(publicKey: Uint8Array): string {
  assertEd25519PublicKey(publicKey);
  const multicodec = new Uint8Array([
    ...ED25519_MULTICODEC_PREFIX,
    ...publicKey,
  ]);
  return `did:key:z${base58btcEncode(multicodec)}`;
}

/**
 * Previous Sanctuary DID encoding for persisted identity migration.
 * This helper preserves the old invalid shape: "z" multibase prefix with
 * base64url payload bytes. New callers must use publicKeyToDid instead.
 */
export function legacyPublicKeyToDid(publicKey: Uint8Array): string {
  assertEd25519PublicKey(publicKey);
  const multicodec = new Uint8Array([
    ...ED25519_MULTICODEC_PREFIX,
    ...publicKey,
  ]);
  return `did:key:z${toBase64url(multicodec)}`;
}

export function assertEd25519PublicKey(publicKey: Uint8Array): void {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new RangeError(
      `Ed25519 public key must be ${ED25519_PUBLIC_KEY_LENGTH} bytes`
    );
  }
}

/**
 * Every did:key STRING encoding a given base64url public key could be stored
 * under, canonical (publicKeyToDid) and legacy (legacyPublicKeyToDid). A
 * caller that must build a DID-STRING allowlist of "identities this fortress
 * holds" (rather than compare raw bytes directly, e.g. because the consuming
 * function's contract is DID-string-shaped) needs BOTH forms — a set built
 * from only `identity.did` covers whichever ONE form that identity happens
 * to be persisted under, silently missing the other (the #1194-class
 * defect). Prefer isLocallyHeldPublicKey when the candidate is available as
 * raw bytes; this exists for the DID-string-shaped case.
 */
export function localDidEncodings(publicKeyBase64url: string): string[] {
  try {
    const bytes = fromBase64url(publicKeyBase64url);
    return [publicKeyToDid(bytes), legacyPublicKeyToDid(bytes)];
  } catch {
    return [];
  }
}

/**
 * Byte-exact equality for two public keys. Public keys are not secret, so
 * this does not need to be constant-time; it exists so every "is this the
 * same signing key" decision compares raw key material instead of a
 * canonicalized string form. `legacyPublicKeyToDid` above exists precisely
 * because the SAME key can be persisted under two different `did:key`
 * strings (canonical base58btc vs. the retired base64url form) — a DID-
 * STRING comparison silently fails to recognize a legacy-encoded identity
 * as the same key (the #1194-class defect). Comparing decoded bytes cannot
 * be fooled by encoding drift.
 */
export function publicKeyBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * THE shared "does this fortress hold this signing key" predicate (register
 * §Z RECHECK / class-level self-vouch guard). Every local-identity trust
 * check that decides whether a counterparty's signing key belongs to an
 * identity THIS fortress holds — the handshake producer chokepoint
 * (`recordHandshakeResult` in handshake/tools.ts), the federation
 * register-time defense-in-depth check (federation/tools.ts), and the
 * reputation tier cap (`resolveTierByDid` in reputation/tiers.ts) — MUST
 * route through this function rather than comparing DID strings, because
 * `identities[].did` can be stored in either DID encoding (see
 * `publicKeyBytesEqual`) and only the raw key bytes are encoding-invariant.
 * `candidatePublicKey` undefined (an undecodable signer key) is never
 * "locally held" — every caller uses the result ONLY to REFUSE trust, so a
 * decode failure just skips the refusal; the signer's key is already
 * validated elsewhere (SHR/signature verification) before this runs.
 */
export function isLocallyHeldPublicKey(
  candidatePublicKey: Uint8Array | undefined,
  identities: readonly { public_key: string }[]
): boolean {
  if (!candidatePublicKey) return false;
  for (const identity of identities) {
    let identityKeyBytes: Uint8Array;
    try {
      identityKeyBytes = fromBase64url(identity.public_key);
    } catch {
      continue;
    }
    if (publicKeyBytesEqual(candidatePublicKey, identityKeyBytes)) {
      return true;
    }
  }
  return false;
}

function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
    leadingZeroes++;
  }
  if (leadingZeroes === bytes.length) {
    return "1".repeat(leadingZeroes);
  }

  const digits = [0];
  for (let i = leadingZeroes; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let encoded = "1".repeat(leadingZeroes);
  for (let i = digits.length - 1; i >= 0; i--) {
    encoded += BASE58BTC_ALPHABET[digits[i]!]!;
  }
  return encoded;
}

/**
 * Generate a unique identity ID.
 * Derived from the public key hash for deterministic mapping.
 */
export function generateIdentityId(publicKey: Uint8Array): string {
  const keyHash = hash(publicKey);
  // First 16 bytes of SHA-256(pubkey) as hex - short, unique, deterministic
  return Array.from(keyHash.slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Create a new identity with encrypted private key storage.
 *
 * @param label - Human-readable label
 * @param encryptionKey - Key to encrypt the private key with (from master key derivation)
 * @param keyProtection - How the master key is protected
 * @returns Public identity info and the stored identity (for persistence)
 */
export function createIdentity(
  label: string,
  encryptionKey: Uint8Array,
  keyProtection: "passphrase" | "hardware-key" | "recovery-key"
): { publicIdentity: PublicIdentity; storedIdentity: StoredIdentity } {
  const { publicKey, privateKey } = generateKeypair();
  const identityId = generateIdentityId(publicKey);
  const did = publicKeyToDid(publicKey);
  const now = new Date().toISOString();

  // Encrypt the private key for storage
  const encryptedPrivateKey = encrypt(privateKey, encryptionKey);

  // Zero out the raw private key in memory
  privateKey.fill(0);

  const publicIdentity: PublicIdentity = {
    identity_id: identityId,
    label,
    public_key: toBase64url(publicKey),
    did,
    created_at: now,
    key_type: "ed25519",
    key_protection: keyProtection,
  };

  const storedIdentity: StoredIdentity = {
    ...publicIdentity,
    encrypted_private_key: encryptedPrivateKey,
    rotation_history: [],
  };

  return { publicIdentity, storedIdentity };
}

/**
 * Sign data with an identity's private key.
 *
 * @param payload - Data to sign (bytes)
 * @param encryptedPrivateKey - The encrypted private key from storage
 * @param encryptionKey - Key to decrypt the private key
 * @returns Ed25519 signature
 */
export function sign(
  payload: Uint8Array,
  encryptedPrivateKey: EncryptedPayload,
  encryptionKey: Uint8Array
): Uint8Array {
  // Decrypt the private key
  const privateKey = decrypt(encryptedPrivateKey, encryptionKey);

  try {
    return ed25519.sign(payload, privateKey);
  } finally {
    // Zero out the private key from memory
    privateKey.fill(0);
  }
}

/**
 * Verify an Ed25519 signature.
 *
 * @param payload - Original data that was signed
 * @param signature - The signature to verify
 * @param publicKey - The signer's public key
 * @returns true if signature is valid
 */
export function verify(
  payload: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    // Generic Ed25519 verification funnel used by tool-level and suite-level
    // verifiers. Malformed signature or public-key bytes must return `false`
    // here, not escape as caller-dependent exception handling.
    return ed25519.verify(signature, payload, publicKey);
  } catch {
    return false;
  }
}

/**
 * Rotate an identity's keys.
 * Generates a new keypair, signs a rotation event with the old key,
 * and returns the updated stored identity.
 *
 * @param storedIdentity - Current stored identity
 * @param encryptionKey - Key to decrypt/re-encrypt private keys
 * @param reason - Reason for rotation (audit trail)
 * @returns Updated stored identity with new keys and rotation history
 */
export function rotateKeys(
  storedIdentity: StoredIdentity,
  encryptionKey: Uint8Array,
  reason: string
): { updatedIdentity: StoredIdentity; rotationEvent: RotationEvent } {
  const { publicKey: newPublicKey, privateKey: newPrivateKey } =
    generateKeypair();
  const newIdentityDid = publicKeyToDid(newPublicKey);
  const now = new Date().toISOString();

  // Create rotation event
  // CONTRACT PIN (server/src/core/rotation-chain.ts `rotationEventSigningBytes`):
  // this object literal's field order is the signature preimage and must match
  // the verifier exactly because `JSON.stringify` is order-sensitive.
  const eventData = JSON.stringify({
    old_public_key: storedIdentity.public_key,
    new_public_key: toBase64url(newPublicKey),
    identity_id: storedIdentity.identity_id,
    reason,
    rotated_at: now,
  });

  // Sign the rotation event with the OLD key (proves authorization)
  const eventBytes = new TextEncoder().encode(eventData);
  const signature = sign(
    eventBytes,
    storedIdentity.encrypted_private_key,
    encryptionKey
  );

  const rotationEvent: RotationEvent = {
    old_public_key: storedIdentity.public_key,
    new_public_key: toBase64url(newPublicKey),
    identity_id: storedIdentity.identity_id,
    reason,
    rotated_at: now,
    signature: toBase64url(signature),
  };

  // Encrypt the new private key
  const encryptedNewPrivateKey = encrypt(newPrivateKey, encryptionKey);
  newPrivateKey.fill(0);

  const updatedIdentity: StoredIdentity = {
    ...storedIdentity,
    public_key: toBase64url(newPublicKey),
    did: newIdentityDid,
    encrypted_private_key: encryptedNewPrivateKey,
    rotation_history: [
      ...storedIdentity.rotation_history,
      {
        old_public_key: storedIdentity.public_key,
        new_public_key: toBase64url(newPublicKey),
        rotation_event: toBase64url(
          new TextEncoder().encode(JSON.stringify(rotationEvent))
        ),
        rotated_at: now,
      },
    ],
  };

  return { updatedIdentity, rotationEvent };
}
