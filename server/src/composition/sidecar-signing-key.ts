/**
 * Sanctuary Composition v1.0 -- Sidecar Signing Key (WP-MVP-10 Follow-up #1)
 *
 * HKDF-derived Ed25519 signing keypair for composition-emitted signed events
 * (verascore signals, future composition_* envelopes).
 *
 * Per Federation Protocol v0.1 §2.2, every per-component key in the fortress
 * HKDF-derives from the fortress master. The recovery cascade (Key 13) then
 * re-anchors the subordinate key automatically on master rotation, without a
 * per-component re-generation step.
 *
 * Derivation:
 *   sidecar_signing_seed = HKDF(
 *     ikm    = fortress_master_secret,
 *     salt   = fortress_id,
 *     info   = "sanctuary-composition-v1.0-sidecar-signing-key",
 *     length = 32
 *   )
 *   private_key = sidecar_signing_seed   (Ed25519 accepts any 32-byte seed)
 *   public_key  = ed25519.getPublicKey(private_key)
 *
 * Salt-choice rationale: fortress_id is a stable fortress-wide identifier, the
 * same anchor the §2.2 per-node subkeys use (they substitute node_id). The
 * sidecar is a fortress-scoped component (one per operator, not one per node),
 * so the fortress_id is the right scope.
 *
 * v1.x invariant hold-outs (WP-MVP-10 Follow-up #1 §"Invariant holdout check"):
 *   - Multi-principal data model: the info string admits a principal-scope
 *     branch under operator-scope at v1.x, e.g.
 *     "sanctuary-composition-v1.0-{principal_id}-sidecar-signing-key".
 *   - Patron-scope key branches under operator-scope: the derivation is a
 *     pure function of (master, fortress_id, info); a v1.x patron-scope
 *     subkey derives from the fortress-scope sidecar key or directly from
 *     the master under a v1.x info prefix, either path admits patron-scope
 *     without breaking v1.0.
 *
 * Crypto-agility: the derived key is always used with signature_scheme
 * "ed25519-v1". v1.1 post-quantum migration adds hybrid signing under a
 * new scheme identifier; this module stays as-is because the derivation
 * produces the ed25519 component and the hybrid ML-DSA component is
 * orthogonal (see Review/Sanctuary/Crypto_Agility_Sprint_V1.1_Plan_2026-04-22.md).
 */

import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { stringToBytes } from "../core/encoding.js";
import { HKDF_COMPOSITION_SIDECAR_SIGNING_INFO } from "./constants.js";

export interface SidecarSigningKeypair {
  /** 32-byte Ed25519 private key (also used as the HKDF-derived seed). */
  privateKey: Uint8Array;
  /** 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
}

/**
 * Derive the composition sidecar's Ed25519 signing keypair from the fortress
 * master secret. Deterministic: same (master, fortress_id) always yields the
 * same keypair; a master rotation yields a different keypair.
 *
 * @throws RangeError if the master secret is empty or the fortress_id is empty.
 */
export function deriveSidecarSigningKey(params: {
  fortress_master_secret: Uint8Array;
  fortress_id: string;
}): SidecarSigningKeypair {
  if (params.fortress_master_secret.byteLength === 0) {
    throw new RangeError(
      "deriveSidecarSigningKey: fortress_master_secret must be non-empty"
    );
  }
  if (params.fortress_id.length === 0) {
    throw new RangeError("deriveSidecarSigningKey: fortress_id must be non-empty");
  }
  const salt = stringToBytes(params.fortress_id);
  const info = stringToBytes(HKDF_COMPOSITION_SIDECAR_SIGNING_INFO);
  const seed = hkdf(sha256, params.fortress_master_secret, salt, info, 32);
  const privateKey = Uint8Array.from(seed);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Re-derive the sidecar signing keypair under a new fortress-master secret.
 * Used by the recovery cascade on master rotation (Federation Protocol §9.4).
 *
 * Equivalent to calling deriveSidecarSigningKey with the new master; the
 * separate function name makes the call-site read as "cascade step" at the
 * rotation ceremony boundary.
 */
export function rederiveSidecarSigningKeyOnRotation(params: {
  new_fortress_master_secret: Uint8Array;
  fortress_id: string;
}): SidecarSigningKeypair {
  return deriveSidecarSigningKey({
    fortress_master_secret: params.new_fortress_master_secret,
    fortress_id: params.fortress_id,
  });
}
