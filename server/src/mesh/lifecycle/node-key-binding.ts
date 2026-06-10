/**
 * Per-node key binding (Q8).
 *
 * Wraps a per-node Ed25519 private key under AES-256-GCM. The wrapping key is
 * HKDF-derived from the fortress-master secret with the lifecycle-specific
 * info string and the node_id as salt. At boot time, the broker unlock flow
 * surfaces the master secret transiently; the lifecycle orchestrator
 * re-derives the wrapping key, decrypts, holds the per-node private key in
 * memory only, and the master secret can be zeroed.
 *
 * Why this is NOT a store-schema change: the encrypted state store holds the
 * fortress-master secret under the operator's unified passphrase exactly as
 * today. The wrapped per-node key lives alongside the node certificate as a
 * separate at-rest artifact owned by the lifecycle orchestrator. Two distinct
 * encrypted blobs, two distinct concerns, no schema migration.
 *
 * Why HKDF rather than a fresh per-node passphrase: the per-node private key
 * MUST be re-derivable under guardian-quorum recovery — otherwise a
 * compromised-master scenario forces every node to re-join, defeating the
 * purpose of the federation protocol's recovery cascade (§9). Deriving the
 * wrapping key from the master means guardian recovery automatically
 * regenerates the wrapping key, and the same on-disk wrapped blob unlocks
 * cleanly post-recovery.
 *
 * Spec §2.2 / §3.5 / §9.4.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
  decrypt,
  encrypt,
  type EncryptedPayload,
} from "../../core/encryption.js";
import { stringToBytes } from "../../core/encoding.js";
import { HKDF_NODE_KEY_WRAP_INFO_PREFIX } from "./constants.js";
import type { NodeKeyStore } from "./types.js";

/**
 * Derive the per-node at-rest wrapping key.
 *
 * Inputs:
 * - fortress_master_secret: 32-byte master secret (transient).
 * - node_id: stable 128-bit node identifier.
 *
 * Output: 32-byte AES-256 key. Deterministic — same master + same node_id
 * always yields the same wrapping key, which is what makes guardian recovery
 * non-disruptive.
 */
export function deriveNodeKeyWrappingKey(params: {
  fortress_master_secret: Uint8Array;
  node_id: string;
}): Uint8Array {
  const salt = stringToBytes(params.node_id);
  const info = stringToBytes(HKDF_NODE_KEY_WRAP_INFO_PREFIX + params.node_id);
  return hkdf(sha256, params.fortress_master_secret, salt, info, 32);
}

/**
 * Wrap a per-node Ed25519 private key for at-rest storage.
 *
 * The node_id is bound into the AAD so a wrapped blob from one node cannot
 * be substituted for another even if both share the same master.
 */
export function wrapNodePrivateKey(params: {
  node_private_key: Uint8Array;
  fortress_master_secret: Uint8Array;
  node_id: string;
}): EncryptedPayload {
  if (params.node_private_key.length !== 32) {
    throw new Error(
      `wrapNodePrivateKey: expected 32-byte Ed25519 private key seed; got ${params.node_private_key.length}`
    );
  }
  const wrappingKey = deriveNodeKeyWrappingKey({
    fortress_master_secret: params.fortress_master_secret,
    node_id: params.node_id,
  });
  // AAD format: "node:" + node_id. v0.1 epoch-free; deterministic HKDF.
  // v1.x crypto-agility (deferred to v1.4+ Crypto Agility Sprint per priority queue)
  // will introduce master-key rotation epochs; this AAD MUST update to encode
  // the wrapping epoch ("node:<node_id>:epoch:<n>"). Without epoch in AAD,
  // rotation across epochs would surface as silent decrypt failures with
  // AAD-mismatch as the only signal.
  const aad = stringToBytes("node:" + params.node_id);
  return encrypt(params.node_private_key, wrappingKey, aad);
}

/**
 * Unwrap a per-node Ed25519 private key from at-rest storage.
 *
 * Throws if the wrapped blob's AAD does not match the expected node_id —
 * cross-node substitution attempt.
 */
export function unwrapNodePrivateKey(params: {
  wrapped: EncryptedPayload;
  fortress_master_secret: Uint8Array;
  node_id: string;
}): Uint8Array {
  const wrappingKey = deriveNodeKeyWrappingKey({
    fortress_master_secret: params.fortress_master_secret,
    node_id: params.node_id,
  });
  const aad = stringToBytes("node:" + params.node_id);
  return decrypt(params.wrapped, wrappingKey, aad);
}

/**
 * In-memory NodeKeyStore. Tests only — production wires a disk-backed
 * implementation (deferred to follow-up).
 */
export class InMemoryNodeKeyStore implements NodeKeyStore {
  private blobs = new Map<string, EncryptedPayload>();

  async save(nodeId: string, wrapped: EncryptedPayload): Promise<void> {
    this.blobs.set(nodeId, wrapped);
  }

  async load(nodeId: string): Promise<EncryptedPayload | null> {
    return this.blobs.get(nodeId) ?? null;
  }

  async remove(nodeId: string): Promise<void> {
    this.blobs.delete(nodeId);
  }
}
