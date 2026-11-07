import { ed25519 } from "@noble/curves/ed25519";
import { decrypt } from "../core/encryption.js";
import { generateIdentityId, sign, type StoredIdentity } from "../core/identity.js";
import { decodeCanonical, refuse, roleKid } from "./contract.js";
import { validateEncryptedPayload } from "./binding-store.js";
import type { RolePin } from "./strict-verifier.js";
import type { ExactMessageProvider } from "./record-signer.js";

/** Dedicated stores alone supply this provider; it never consults IdentityManager or a primary pointer. */
export class EncryptedIdentityProvider implements ExactMessageProvider {
  #identity: StoredIdentity;
  #key: Uint8Array;
  #closed = false;
  constructor(identity: StoredIdentity, encryptionKey: Uint8Array, pin: RolePin) {
    this.#identity = structuredClone(identity);
    this.#key = new Uint8Array(encryptionKey);
    let seed: Uint8Array | undefined;
    try {
      validateEncryptedPayload(this.#identity.encrypted_private_key);
      seed = decrypt(this.#identity.encrypted_private_key, this.#key);
      if (seed.length !== 32) return refuse();
      const publicKey = ed25519.getPublicKey(seed);
      if (!Buffer.from(publicKey).equals(Buffer.from(decodeCanonical(pin.public_key, 32))) ||
          identity.public_key !== pin.public_key || identity.identity_id !== generateIdentityId(publicKey) ||
          pin.identity_id !== identity.identity_id || pin.kid !== roleKid(pin.role, pin.epoch, pin.public_key) || identity.rotation_history.length !== 0) return refuse();
    } catch {
      this.#key.fill(0);
      return refuse();
    } finally { seed?.fill(0); }
  }
  sign(message: Uint8Array): Uint8Array {
    if (this.#closed) return refuse();
    try { return sign(message, this.#identity.encrypted_private_key, this.#key); }
    catch { return refuse(); }
  }
  /** Owned-key cleanup only; process reaping is required before a lifecycle WIPED claim. */
  close(): void { this.#closed = true; this.#key.fill(0); }
}
