/**
 * The shared CLI custody-unlock + operator-identity-signer path.
 *
 * Extracted from `cli/license.ts` (the ORIGINAL owner of this exact unlock
 * sequence, PR-1) so a second CLI surface signing with the SAME default
 * operator identity - `cli/fleet.ts`'s `attest export` - never copy-pastes the
 * custody unlock. Both `license.ts` and `fleet.ts` import this module; the
 * behavior is byte-identical to what shipped before this extraction.
 *
 * Keychain safety (mirrors federation-operator-signing): custody unlocks via
 * `resolveCliMasterKey` (passphrase / recovery-key via env or flag), the
 * no-modal headless path - a headless session with only a keychain credential
 * gets an actionable fail-closed error, never a macOS keychain modal and never
 * a silent downgrade. NEVER #6: the issuer private key is decrypted transiently
 * inside `sign()` (which zeroes it in a `finally`); nothing here logs, prints,
 * or returns private-key material.
 *
 * Fail-closed (throws) on: no fortress unlockable, no DEFAULT operator
 * identity, malformed identity public key.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { FilesystemStorage } from "../storage/filesystem.js";
import { IdentityManager } from "../cognitive/tools.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { sign } from "../core/identity.js";
import type { EncryptedPayload } from "../core/encryption.js";
import { loadConfig } from "../config.js";
import type { StorageBackend } from "../storage/interface.js";
import type { IssuerSigner } from "../entitlement/ledger.js";

/**
 * Open the fortress and pin the DEFAULT operator identity as a VERIFIER: the
 * keychain-safe unlock, the identity load, and the fingerprint-pinned public
 * key. Returns everything an ISSUER caller needs to also build a signer
 * without re-doing the unlock (see {@link openIssuer}). Fail-closed: throws
 * when custody cannot be unlocked or no default operator identity exists. The
 * caller owns zeroing `masterKey`.
 */
export async function openVerifier(opts: {
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}): Promise<{
  issuerId: string;
  issuerPublicKey: Uint8Array;
  masterKey: Uint8Array;
  storage: StorageBackend;
  /** Encrypted issuer private key (for the signer); never key material in the clear. */
  encryptedPrivateKey: EncryptedPayload;
  /** The purpose-derived key that decrypts the issuer key transiently in sign(). */
  identityEncryptionKey: Uint8Array;
}> {
  if (!opts.passphrase && !opts.recoveryKey) {
    throw new Error(
      "an unlocked operator identity is required: set SANCTUARY_PASSPHRASE, " +
        "--passphrase, or SANCTUARY_RECOVERY_KEY (this verb never prompts the " +
        "macOS keychain in a headless session)",
    );
  }
  if (opts.fortressPath) {
    process.env.SANCTUARY_STORAGE_PATH = opts.fortressPath;
  }
  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  const masterKey = await resolveCliMasterKey(storage, {
    ...(opts.passphrase !== undefined ? { passphrase: opts.passphrase } : {}),
    ...(opts.recoveryKey !== undefined ? { recoveryKey: opts.recoveryKey } : {}),
    storagePathHint: config.storage_path,
  });

  const identityManager = new IdentityManager(storage, masterKey);
  const loadResult = await identityManager.load();
  if (loadResult.loaded === 0) {
    masterKey.fill(0);
    throw new Error(
      loadResult.total > 0
        ? "operator identity files found but none could be decrypted (wrong passphrase?)"
        : "no operator identity in this fortress: this operation requires a " +
          "default operator identity (run `sanctuary identity create`, or " +
          "re-run `sanctuary init` without --no-identity)",
    );
  }
  const identity = identityManager.getDefault();
  if (!identity?.encrypted_private_key || !identity.public_key) {
    masterKey.fill(0);
    throw new Error("no default operator identity is set in this fortress");
  }

  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const issuerPublicKey = decodePublicKey(identity.public_key);
  if (issuerPublicKey === null) {
    masterKey.fill(0);
    throw new Error("default operator identity public key is malformed");
  }

  return {
    issuerId: identity.identity_id,
    issuerPublicKey,
    masterKey,
    storage,
    encryptedPrivateKey: identity.encrypted_private_key,
    identityEncryptionKey,
  };
}

/**
 * Open the fortress and additionally bind an {@link IssuerSigner} to the DEFAULT
 * operator identity. Thin wrapper over {@link openVerifier} so every CLI verb
 * that signs with the default operator identity (`license issue`/`revoke`,
 * `fleet attest export`) shares ONE unlock + key-pin path (no copy-paste).
 * Fail-closed as `openVerifier`; the caller owns zeroing `masterKey`.
 */
export async function openIssuer(opts: {
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}): Promise<{
  sign: IssuerSigner;
  issuerId: string;
  issuerPublicKey: Uint8Array;
  masterKey: Uint8Array;
  storage: StorageBackend;
}> {
  const v = await openVerifier(opts);
  const signer: IssuerSigner = (message: Uint8Array): Uint8Array =>
    // core/identity.sign decrypts the private key transiently and zeroes it in
    // a finally (NEVER #6). We return the raw 64-byte signature; the caller
    // base64url-encodes it. No key material is exposed here.
    sign(message, v.encryptedPrivateKey, v.identityEncryptionKey);
  return {
    sign: signer,
    issuerId: v.issuerId,
    issuerPublicKey: v.issuerPublicKey,
    masterKey: v.masterKey,
    storage: v.storage,
  };
}

function decodePublicKey(b64: string): Uint8Array | null {
  try {
    const key = Buffer.from(
      b64.replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    );
    return key.length === 32 ? new Uint8Array(key) : null;
  } catch {
    return null;
  }
}
