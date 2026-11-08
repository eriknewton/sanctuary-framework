import { createIdentity } from "../core/identity.js";
import type { CustodyEnvelope } from "../core/master-custody.js";
import { decodeCanonical, refuse, roleKid, SIGNER_EPOCHS_MAX, type SigningRole } from "./contract.js";
import type { RolePin } from "./strict-verifier.js";
import { ROLE_IDENTITY_LABEL_PREFIX } from "./reserved-label.js";

export function validatePassphrase(passphrase: string): void {
  const points = Array.from(passphrase);
  if (points.length < 20 || Buffer.byteLength(passphrase) > 1024 || passphrase.trim().length === 0 || new Set(points).size === 1) refuse();
}
/** Only the MAC-authenticated envelope returned by read-only unlock may supply these facts. */
export function validateCustodyProfile(envelope: CustodyEnvelope): void {
  if (envelope.install_mode !== "interactive" || envelope.wraps.length !== 2 ||
      envelope.wraps.some(wrap => !wrap.verified) ||
      envelope.wraps.map(wrap => wrap.type).sort().join(",") !== "passphrase,recovery-key") refuse();
  const kdf = envelope.wraps.find(wrap => wrap.type === "passphrase")?.kdf;
  if (!kdf || kdf.alg !== "argon2id" || kdf.m !== 65536 || kdf.t !== 3 || kdf.p !== 4 || kdf.l !== 32) refuse();
  decodeCanonical(kdf.salt, 32);
}
export function enrollmentKeyAvailable(publicKey: string, roster: readonly RolePin[], operatorKeys: readonly string[]): boolean {
  return !roster.some(pin => pin.public_key === publicKey) && !operatorKeys.includes(publicKey);
}
// Must match binding-store.ts: authenticated bindings establish role authority, and distinct store masters remain a supervisor obligation.
/** Prepare encrypted material only; this does not establish freshness, attendance or durable enrollment. */
export function prepareRoleIdentity(role: SigningRole, epoch: number, machineId: string, identityKey: Uint8Array,
  roster: readonly RolePin[], operatorKeys: readonly string[]) {
  if (!/^[a-f0-9]{32}$/.test(machineId) || !Number.isSafeInteger(epoch) || epoch < 1 || roster.filter(pin => pin.role === role).length >= SIGNER_EPOCHS_MAX) return refuse();
  const ownedKey = new Uint8Array(identityKey);
  let storedIdentity: ReturnType<typeof createIdentity>["storedIdentity"] | undefined;
  let returned = false;
  try {
    ({storedIdentity} = createIdentity(ROLE_IDENTITY_LABEL_PREFIX + role, ownedKey, "passphrase"));
    if (!enrollmentKeyAvailable(storedIdentity.public_key, roster, operatorKeys)) return refuse();
    const pin: RolePin = Object.freeze({role, epoch, machine_id: machineId, identity_id: storedIdentity.identity_id,
      public_key: storedIdentity.public_key, kid: roleKid(role, epoch, storedIdentity.public_key)});
    returned = true;
    return {storedIdentity, pin};
  } finally {
    // createIdentity wipes the raw seed in its own finally, so after any failed preparation only the candidate's ciphertext
    // remains, sealed under the caller's still-live identity key (the at-rest form of every stored identity); the ct and iv
    // strings are released below but cannot be wiped, because JS strings are immutable.
    // Preparation never retains its owned key copy, on success or failure, so it is zeroed on every exit.
    ownedKey.fill(0);
    if (!returned && storedIdentity) {
      storedIdentity.encrypted_private_key.ct = "";
      storedIdentity.encrypted_private_key.iv = "";
    }
  }
}
