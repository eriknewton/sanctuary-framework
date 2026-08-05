/**
 * Sanctuary MCP Server — Key Derivation
 *
 * Two-tier key derivation:
 * 1. Master key from passphrase via Argon2id (memory-hard, GPU-resistant)
 * 2. Namespace keys from master key via HKDF-SHA256
 *
 * This ensures:
 * - Passphrase brute-force is expensive (Argon2id)
 * - Compromise of one namespace key doesn't expose others (HKDF domain separation)
 */

import { argon2id } from "hash-wasm";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { generateSalt } from "./random.js";
import { toBase64url, fromBase64url, stringToBytes } from "./encoding.js";

/** Argon2id parameters per OWASP recommendation (2024) */
const ARGON2_MEMORY_COST = 65536; // 64 MiB
const ARGON2_TIME_COST = 3; // 3 iterations
const ARGON2_PARALLELISM = 4; // 4 lanes
const ARGON2_HASH_LENGTH = 32; // 256-bit output

/** Stored key derivation parameters (for re-deriving the master key) */
export interface KeyDerivationParams {
  /** Algorithm */
  alg: "argon2id";
  /** Salt (base64url) */
  salt: string;
  /** Memory cost in KiB */
  m: number;
  /** Time cost (iterations) */
  t: number;
  /** Parallelism */
  p: number;
  /** Output length in bytes */
  l: number;
}

/**
 * Derive a master key from a passphrase using Argon2id.
 *
 * @param passphrase - User's passphrase
 * @param existingParams - If re-deriving, use the stored params (same salt)
 * @returns The derived key and the parameters used (store the params, never the key)
 */
export async function deriveMasterKey(
  passphrase: string,
  existingParams?: KeyDerivationParams
): Promise<{ key: Uint8Array; params: KeyDerivationParams }> {
  const salt = existingParams
    ? fromBase64url(existingParams.salt)
    : generateSalt();

  const params: KeyDerivationParams = existingParams ?? {
    alg: "argon2id",
    salt: toBase64url(salt),
    m: ARGON2_MEMORY_COST,
    t: ARGON2_TIME_COST,
    p: ARGON2_PARALLELISM,
    l: ARGON2_HASH_LENGTH,
  };

  const hashHex = await argon2id({
    password: passphrase,
    salt,
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: params.l,
    outputType: "hex",
  });

  // Convert hex to bytes
  const key = new Uint8Array(params.l);
  for (let i = 0; i < params.l; i++) {
    key[i] = parseInt(hashHex.substring(i * 2, i * 2 + 2), 16);
  }

  return { key, params };
}

/**
 * Derive a namespace-specific encryption key from the master key via HKDF-SHA256.
 *
 * Each namespace gets its own 256-bit key derived from the master key.
 * Compromise of one namespace key does not expose other namespaces.
 *
 * @param masterKey - The master key (from Argon2id or recovery key)
 * @param namespace - The namespace name (used as HKDF info)
 * @returns 256-bit namespace key
 */
export function deriveNamespaceKey(
  masterKey: Uint8Array,
  namespace: string
): Uint8Array {
  // 32 = the 256-bit master key produced by `generateRandomKey()` (core/random.ts).
  // A symmetric secret, not an Ed25519 key, despite sharing the byte count.
  if (masterKey.length !== 32) {
    throw new Error("Master key must be 32 bytes");
  }

  return hkdf(
    sha256,
    masterKey,
    stringToBytes("sanctuary-namespace-v1"), // salt (fixed, acts as domain separator)
    stringToBytes(namespace), // info (namespace name)
    32 // output length: 256 bits
  );
}

/**
 * Derive a key for a specific purpose from the master key.
 * Used for identity key encryption, audit log encryption, etc.
 *
 * @param masterKey - The master key
 * @param purpose - Purpose string (e.g., "identity-encryption", "audit-log")
 * @returns 256-bit purpose-specific key
 */
export function derivePurposeKey(
  masterKey: Uint8Array,
  purpose: string
): Uint8Array {
  // Same 256-bit master-key size as `deriveNamespaceKey` above.
  if (masterKey.length !== 32) {
    throw new Error("Master key must be 32 bytes");
  }

  return hkdf(
    sha256,
    masterKey,
    stringToBytes("sanctuary-purpose-v1"),
    stringToBytes(purpose),
    32
  );
}
