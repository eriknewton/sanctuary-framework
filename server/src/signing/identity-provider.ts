import { ed25519 } from "@noble/curves/ed25519";
import { decrypt } from "../core/encryption.js";
import { generateIdentityId, sign, type StoredIdentity } from "../core/identity.js";
import { parseStrict } from "../smb/parse-strict.js";
import { canonicalBytes, decodeCanonical, refuse, roleKid, roleEntry, PRODUCER_ROTATION_DOMAIN, PRODUCER_DESCRIPTOR_DOMAIN, SIGNER_PREIMAGE_MAX_BYTES, UNLOCK_CHALLENGE_DOMAIN } from "./contract.js";
import { validateEncryptedPayload } from "./binding-store.js";
import type { RolePin } from "./strict-verifier.js";
import type { ExactMessageProvider } from "./record-signer.js";

/** Dedicated stores alone supply this provider; it never consults IdentityManager or a primary pointer. */
export class EncryptedIdentityProvider implements ExactMessageProvider {
  #identity: StoredIdentity;
  #key: Uint8Array;
  #closed = false;
  #recordDomain: string;
  #lifecycleDomains: readonly string[];
  #role: RolePin["role"];
  #machineId: string;
  constructor(identity: StoredIdentity, encryptionKey: Uint8Array, pin: RolePin) {
    // Must match the role and lifecycle domains in contract.ts and core/signing-domains.ts.
    this.#recordDomain = roleEntry(pin.role).domain;
    // The lifecycle domains are role-generic despite their PRODUCER_ names (wire strings, never renamed here): every role's
    // key may sign them, so each lifecycle preimage must name its own role and machine, and verifiers check it against that
    // role's pins (rotation.ts rotationMessage binds role, machine_id, epochs and both kids; verifyRotation checks both pins).
    // Must match rotationSchema in rotation.ts: its canonical body carries the role and machine_id this provider requires.
    this.#lifecycleDomains = [PRODUCER_ROTATION_DOMAIN, PRODUCER_DESCRIPTOR_DOMAIN, UNLOCK_CHALLENGE_DOMAIN];
    this.#role = pin.role;
    this.#machineId = pin.machine_id;
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
    try {
      if (this.#closed) return refuse();
      const bytes = new Uint8Array(message);
      const startsWith = (domain: string) => Buffer.from(bytes).subarray(0, Buffer.byteLength(domain)).equals(Buffer.from(domain));
      // Only this role's record domain and the internal lifecycle protocols may use the dedicated key.
      if (!startsWith(this.#recordDomain)) {
        const lifecycle = this.#lifecycleDomains.find(startsWith);
        if (lifecycle === undefined) return refuse();
        // A lifecycle body must be canonical and name this provider's role and machine, so a key of one role can never sign
        // another role's rotation, descriptor or unlock self-test bytes.
        const body = bytes.subarray(Buffer.byteLength(lifecycle));
        const value = parseStrict(body, SIGNER_PREIMAGE_MAX_BYTES) as Record<string, unknown> | null;
        if (value === null || typeof value !== "object" || Array.isArray(value) || value.role !== this.#role ||
            value.machine_id !== this.#machineId || !Buffer.from(canonicalBytes(value)).equals(Buffer.from(body))) return refuse();
      }
      return sign(bytes, this.#identity.encrypted_private_key, this.#key);
    } catch { return refuse(); }
  }
  /** Owned-key cleanup only; process reaping is required before a lifecycle WIPED claim. */
  close(): void { this.#closed = true; this.#key.fill(0); }
}
