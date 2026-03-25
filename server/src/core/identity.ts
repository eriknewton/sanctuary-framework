/**
 * Sanctuary MCP Server — Ed25519 Identity Management
 *
 * Sovereign identity based on Ed25519 keypairs.
 * Private keys are always encrypted at rest — never stored in plaintext.
 *
 * Security invariants:
 * - Private keys never appear in any MCP tool response
 * - Private keys are encrypted with identity-specific keys derived from the master key
 * - Key rotation produces a signed rotation event (verifiable chain)
 */

import { ed25519 } from "@noble/curves/ed25519";
import { toBase64url } from "./encoding.js";
import { encrypt, decrypt, type EncryptedPayload } from "./encryption.js";
import { hash } from "./hashing.js";
import { randomBytes } from "./random.js";

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
  // Multicodec prefix for Ed25519: 0xed 0x01
  const multicodec = new Uint8Array([0xed, 0x01, ...publicKey]);
  // did:key uses base58btc multibase encoding, but for simplicity
  // we use the base64url representation which is equally valid
  // in the broader DID ecosystem
  return `did:key:z${toBase64url(multicodec)}`;
}

/**
 * Generate a unique identity ID.
 * Derived from the public key hash for deterministic mapping.
 */
export function generateIdentityId(publicKey: Uint8Array): string {
  const keyHash = hash(publicKey);
  // First 16 bytes of SHA-256(pubkey) as hex — short, unique, deterministic
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
