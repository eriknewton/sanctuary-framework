import type { IdentityManager } from "../cognitive/tools.js";
import { fromBase64url } from "../core/encoding.js";
import { sign } from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { MemoryProvenanceSigningHandle } from "./memory-provenance-contract.js";
import { legacyPublicKeyToDid, publicKeyToDid } from "../core/identity.js";

const IDENTITY_ENCRYPTION_PURPOSE = "identity-encryption";

/** Narrow, fresh snapshot of the fortress primary identity; no key escapes. */
export function createPrimaryMemoryProvenanceSigningHandleResolver(
  identityManager: IdentityManager,
  masterKey: Uint8Array,
): () => MemoryProvenanceSigningHandle {
  const identityKey = derivePurposeKey(masterKey, IDENTITY_ENCRYPTION_PURPOSE);
  return () => {
    const primary = identityManager.getDefault();
    if (primary === undefined) throw new Error("SDW memory provenance requires a primary identity");
    return Object.freeze({
      identity_id: primary.identity_id,
      did: primary.did,
      public_key: fromBase64url(primary.public_key),
      sign: (bytes: Uint8Array) => sign(bytes, primary.encrypted_private_key, identityKey),
    });
  };
}

export function createPrimaryMemoryProvenancePublicKeyResolver(
  identityManager: IdentityManager,
): (identityId: string, did: string) => Uint8Array | undefined {
  return (identityId, did) => {
    const identity = identityManager.get(identityId);
    if (identity === undefined) return undefined;
    const candidates = [identity.public_key, ...identity.rotation_history.map((entry) => entry.old_public_key)];
    for (const encoded of candidates) {
      const key = fromBase64url(encoded);
      if (did === publicKeyToDid(key) || did === legacyPublicKeyToDid(key)) return key;
    }
    return undefined;
  };
}
