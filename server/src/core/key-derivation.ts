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
import {
  toBase64url,
  fromBase64url,
  fromBase64urlStrict,
  stringToBytes,
} from "./encoding.js";

/** Argon2id parameters per OWASP recommendation (2024) */
const ARGON2_MEMORY_COST = 65536; // 64 MiB
const ARGON2_TIME_COST = 3; // 3 iterations
const ARGON2_PARALLELISM = 4; // 4 lanes
/** 32 = 256-bit master key, the width every downstream HKDF here expects. */
export const ARGON2_HASH_LENGTH = 32;

/**
 * HKDF purpose label for the key that encrypts managed-identity private keys
 * at rest. Must match the literal `"identity-encryption"` still used by the
 * older call sites across the tree and the `_identities` row in
 * `core/master-custody.ts` (derived-key inventory); the composition root
 * (`index.ts`) and `IdentityManager.encryptionKey` (`cognitive/tools.ts`)
 * consume this constant so the SDW export signing key and the identity store
 * cannot drift onto two different derivations.
 */
export const IDENTITY_ENCRYPTION_PURPOSE = "identity-encryption";

/**
 * Acceptance bounds for KeyDerivationParams that arrive from OUTSIDE this
 * process (an on-disk `_meta/key-params` marker, an exit bundle's
 * `source_key_derivation`). They are deliberately wide enough to contain every
 * value Sanctuary has ever written (m/t/p/l = 65536/3/4/32, the OWASP defaults
 * above) and narrow enough that a crafted bundle cannot turn an import into an
 * unbounded Argon2id memory burn.
 */
/** RFC 9106 §3.1 sets 8 bytes as the minimum Argon2 salt length. */
export const KDF_PARAMS_MIN_SALT_BYTES = 8;
/** 1 GiB expressed in KiB (the unit of Argon2's `m`): 1024 MiB * 1024 KiB. */
export const KDF_PARAMS_MAX_MEMORY_KIB = 1024 * 1024;
/** 16 iterations: ~5x the shipped cost (3); beyond this is a crafted bundle. */
export const KDF_PARAMS_MAX_TIME_COST = 16;
/** 16 lanes: 4x the shipped parallelism (4); Argon2's own cap is far higher. */
export const KDF_PARAMS_MAX_PARALLELISM = 16;

/**
 * Result of shape-checking untrusted Argon2id parameters.
 *
 * `reason` is operator-facing: it names the exact field that failed so a
 * refusal at the export gate or the import gate can tell the operator what to
 * repair, rather than reporting a generic "malformed".
 */
export type ParsedKeyDerivationParams =
  | { ok: true; params: KeyDerivationParams }
  | { ok: false; reason: string };

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
 * Shape- and cost-check Argon2id parameters that did NOT come from this
 * process. Returns a discriminated result rather than throwing so each caller
 * can choose its own refusal (an export-time throw, an import-time structured
 * error, a verifier warning) while classifying identically.
 *
 * CONTRACT PIN (server/src/exit/bundle.ts): the exit-bundle export embed-gate
 * (`readSourceKeyParams`) and the import derive-gate (`resolveSourceMasterKey`)
 * both classify through THIS function, and `summarizeEncryptedState` in
 * server/src/exit/verifier.ts reports the same three states
 * (`absent` / `valid` / `malformed`). If the accepted shape changes here,
 * change all three call sites in the same commit; a loosened validator would
 * let an unusable re-key path back into a signed artifact.
 *
 * @param value - untrusted JSON (a parsed `_meta/key-params` marker or an exit
 *   bundle's `source_key_derivation` field).
 */
export function parseKeyDerivationParams(
  value: unknown
): ParsedKeyDerivationParams {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, reason: "not a JSON object" };
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.alg !== "argon2id") {
    return {
      ok: false,
      reason: `alg must be "argon2id" (got ${JSON.stringify(candidate.alg)})`,
    };
  }
  if (typeof candidate.salt !== "string") {
    return { ok: false, reason: "salt must be a base64url string" };
  }
  let saltBytes: Uint8Array;
  try {
    // Strict decode: a salt that only survives a lenient decoder is a marker
    // Sanctuary never wrote, and accepting it would silently change the
    // derived master (different bytes, same string).
    saltBytes = fromBase64urlStrict(candidate.salt);
  } catch {
    return { ok: false, reason: "salt is not canonical base64url" };
  }
  if (saltBytes.length < KDF_PARAMS_MIN_SALT_BYTES) {
    return {
      ok: false,
      reason: `salt decodes to ${saltBytes.length} bytes, below the ${KDF_PARAMS_MIN_SALT_BYTES}-byte minimum`,
    };
  }

  const bounded: Array<[string, number]> = [
    ["m", KDF_PARAMS_MAX_MEMORY_KIB],
    ["t", KDF_PARAMS_MAX_TIME_COST],
    ["p", KDF_PARAMS_MAX_PARALLELISM],
    ["l", ARGON2_HASH_LENGTH],
  ];
  for (const [field, max] of bounded) {
    const raw = candidate[field];
    if (typeof raw !== "number" || !Number.isSafeInteger(raw) || raw < 1) {
      return {
        ok: false,
        reason: `${field} must be a positive integer (got ${JSON.stringify(raw)})`,
      };
    }
    if (raw > max) {
      return {
        ok: false,
        reason: `${field}=${raw} exceeds the accepted maximum ${max}`,
      };
    }
  }
  // `l` is pinned, not merely bounded: every consumer of the derived key
  // (deriveNamespaceKey, derivePurposeKey, the custody envelope) requires
  // exactly ARGON2_HASH_LENGTH bytes, so any other width derives a master no
  // downstream call can use.
  if (candidate.l !== ARGON2_HASH_LENGTH) {
    return {
      ok: false,
      reason: `l must be exactly ${ARGON2_HASH_LENGTH} (got ${String(candidate.l)})`,
    };
  }

  return {
    ok: true,
    params: {
      alg: "argon2id",
      salt: candidate.salt,
      m: candidate.m as number,
      t: candidate.t as number,
      p: candidate.p as number,
      l: candidate.l,
    },
  };
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
