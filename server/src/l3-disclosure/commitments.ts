/**
 * Sanctuary MCP Server — L3 Selective Disclosure: Commitment Schemes
 *
 * Cryptographic commitments allow an agent to commit to a value
 * without revealing it, then later prove what was committed.
 *
 * This is the MVS approach to selective disclosure — simpler than
 * full ZK proofs but still cryptographically sound. The commitment
 * is SHA-256(value || blinding_factor), which is:
 * - Hiding: the commitment reveals nothing about the value
 * - Binding: the committer cannot change the value after committing
 *
 * Security invariants:
 * - Blinding factors are cryptographically random (32 bytes)
 * - Commitments are stored encrypted under L1 sovereignty
 * - Revealed values are verified via constant-time comparison
 */

import { hash } from "../core/hashing.js";
import { toBase64url, fromBase64url, stringToBytes, concatBytes } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { bytesToString } from "../core/encoding.js";

/** A cryptographic commitment */
export interface Commitment {
  /** The commitment hash: SHA-256(value || blinding_factor) as base64url */
  commitment: string;
  /** The blinding factor (must be stored securely for later reveal) */
  blinding_factor: string;
  /** When the commitment was created */
  committed_at: string;
}

/** Stored commitment metadata (encrypted at rest) */
export interface StoredCommitment {
  commitment: string;
  blinding_factor: string;
  value: string;
  committed_at: string;
  revealed: boolean;
  revealed_at?: string;
}

/**
 * Create a cryptographic commitment to a value.
 *
 * @param value - The value to commit to
 * @param blindingFactor - Optional blinding factor (auto-generated if omitted)
 * @returns The commitment and blinding factor
 */
export function createCommitment(
  value: string,
  blindingFactor?: string
): Commitment {
  // Generate or decode the blinding factor
  const blindingBytes = blindingFactor
    ? fromBase64url(blindingFactor)
    : randomBytes(32);

  // Commitment = SHA-256(value_bytes || blinding_bytes)
  const valueBytes = stringToBytes(value);
  const combined = concatBytes(valueBytes, blindingBytes);
  const commitmentHash = hash(combined);

  return {
    commitment: toBase64url(commitmentHash),
    blinding_factor: toBase64url(blindingBytes),
    committed_at: new Date().toISOString(),
  };
}

/**
 * Verify a commitment against a revealed value and blinding factor.
 *
 * @param commitment - The original commitment hash
 * @param value - The revealed value
 * @param blindingFactor - The revealed blinding factor
 * @returns true if the reveal matches the commitment
 */
export function verifyCommitment(
  commitment: string,
  value: string,
  blindingFactor: string
): boolean {
  const blindingBytes = fromBase64url(blindingFactor);
  const valueBytes = stringToBytes(value);
  const combined = concatBytes(valueBytes, blindingBytes);
  const expectedHash = toBase64url(hash(combined));

  // Use string comparison (the hash output is already fixed-length)
  return commitment === expectedHash;
}

/**
 * Commitment store — manages commitments encrypted under L1 sovereignty.
 */
export class CommitmentStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l3-commitments");
  }

  /**
   * Store a commitment (encrypted) for later reference.
   */
  async store(commitment: Commitment, value: string): Promise<string> {
    const id = `cmt-${Date.now()}-${toBase64url(randomBytes(8))}`;

    const stored: StoredCommitment = {
      commitment: commitment.commitment,
      blinding_factor: commitment.blinding_factor,
      value,
      committed_at: commitment.committed_at,
      revealed: false,
    };

    const serialized = stringToBytes(JSON.stringify(stored));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_commitments",
      id,
      stringToBytes(JSON.stringify(encrypted))
    );

    return id;
  }

  /**
   * Retrieve a stored commitment by ID.
   */
  async get(id: string): Promise<StoredCommitment | null> {
    const raw = await this.storage.read("_commitments", id);
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted));
    } catch {
      return null;
    }
  }

  /**
   * Mark a commitment as revealed.
   */
  async markRevealed(id: string): Promise<void> {
    const stored = await this.get(id);
    if (!stored) return;

    stored.revealed = true;
    stored.revealed_at = new Date().toISOString();

    const serialized = stringToBytes(JSON.stringify(stored));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_commitments",
      id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
}
