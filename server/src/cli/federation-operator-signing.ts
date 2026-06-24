/**
 * Operator-signing helper for the headless federation admin verbs (Slice 3b).
 *
 * The operator-driven federation verbs (`enable`, `disable`, `authorize`, and
 * `join --persist`) run on the operator's own machine and must produce the
 * inline OPERATOR_SIGNED signature the `/v1/federation/*` endpoints already
 * require (`server/src/v1/operator-signed.ts`). This module is the ONE place a
 * CLI verb opens the local fortress, resolves the DEFAULT operator identity,
 * signs the canonical operator payload, and zeroes the key. It introduces NO
 * second trust-decision code path: it only produces the signature the server
 * independently verifies.
 *
 * Keychain safety (the recurring drill blocker): custody is unlocked through
 * `resolveCliMasterKey` (passphrase / recovery-key via env or flag), the SAME
 * no-modal path every other signing CLI verb uses. A headless session with
 * only a keychain credential gets an actionable fail-closed error, never a
 * macOS keychain modal and never a silent downgrade.
 *
 * Fail closed (mirrors the server's `resolveOperatorPublicKey` returning null):
 * if no fortress can be unlocked, or no DEFAULT operator identity exists, the
 * verb errors and exits non-zero. It never signs with an inferred key and
 * never proceeds unsigned.
 *
 * Constraint 6: the operator private key is decrypted transiently inside
 * `sign()` (core/identity.ts), which zeroes it in a `finally`; nothing here
 * logs, prints, or returns private-key material.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { FilesystemStorage } from "../storage/filesystem.js";
import type { StorageBackend } from "../storage/interface.js";
import { IdentityManager } from "../cognitive/tools.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { sign } from "../core/identity.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { loadConfig } from "../config.js";
import { buildOperatorSignedMessage } from "../v1/operator-signed.js";

/** Raised when no operator identity can be unlocked; mapped to a fail-closed exit. */
export class OperatorSigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OperatorSigningError";
  }
}

export interface OperatorSignerOptions {
  /** Passphrase for custody unlock (flag or SANCTUARY_PASSPHRASE). */
  passphrase?: string;
  /** Recovery key for custody unlock (SANCTUARY_RECOVERY_KEY). */
  recoveryKey?: string;
  /** Optional fortress override; sets SANCTUARY_STORAGE_PATH before loadConfig. */
  fortressPath?: string;
}

export interface OperatorSigner {
  /** Public key of the resolved default operator identity (for diagnostics). */
  operatorPublicKey: Uint8Array;
  /** The unlocked fortress storage (reused by join --persist for the joiner store). */
  storage: StorageBackend;
  /** The unlocked custody master key (reused by join --persist for the joiner store). */
  masterKey: Uint8Array;
  /**
   * Sign the canonical operator payload for `action` and return the base64url
   * signature ready to attach as `operator_signature` in the request body.
   */
  signPayload(action: string, payload: unknown): string;
}

/**
 * Open the local fortress headless (keychain-safe), resolve the DEFAULT
 * operator identity, and return a signer bound to it. Throws
 * `OperatorSigningError` (fail closed) when custody cannot be unlocked or no
 * default operator identity exists. The caller owns zeroing the returned
 * `masterKey` after use.
 */
export async function openOperatorSigner(
  opts: OperatorSignerOptions,
): Promise<OperatorSigner> {
  if (!opts.passphrase && !opts.recoveryKey) {
    throw new OperatorSigningError(
      "an unlocked operator identity is required: set SANCTUARY_PASSPHRASE, " +
        "--passphrase, or SANCTUARY_RECOVERY_KEY (this verb never prompts the " +
        "macOS keychain in a headless session)",
    );
  }
  // --fortress override: loadConfig() reads SANCTUARY_STORAGE_PATH directly.
  if (opts.fortressPath) {
    process.env.SANCTUARY_STORAGE_PATH = opts.fortressPath;
  }

  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  // Unified custody: never derive a fortress master verb-locally. This is the
  // no-modal headless unlock path (passphrase / recovery key only).
  const masterKey = await resolveCliMasterKey(storage, {
    ...(opts.passphrase !== undefined ? { passphrase: opts.passphrase } : {}),
    ...(opts.recoveryKey !== undefined ? { recoveryKey: opts.recoveryKey } : {}),
    storagePathHint: config.storage_path,
  });

  const identityManager = new IdentityManager(storage, masterKey);
  const loadResult = await identityManager.load();
  if (loadResult.loaded === 0) {
    masterKey.fill(0);
    throw new OperatorSigningError(
      loadResult.total > 0
        ? "operator identity files found but none could be decrypted (wrong passphrase?)"
        : "no operator identity in this fortress: federation admin verbs require " +
          "a default operator identity (run `sanctuary identity` to create one)",
    );
  }

  const identity = identityManager.getDefault();
  if (!identity?.encrypted_private_key || !identity.public_key) {
    masterKey.fill(0);
    throw new OperatorSigningError(
      "no default operator identity is set in this fortress",
    );
  }

  const operatorPublicKey = decodePublicKey(identity.public_key);
  if (operatorPublicKey === null) {
    masterKey.fill(0);
    throw new OperatorSigningError("default operator identity public key is malformed");
  }

  // The identity private key is encrypted under derivePurposeKey(master,
  // "identity-encryption") (see IdentityManager.encryptionKey). sign() decrypts
  // it transiently and zeroes it in a finally (constraint 6).
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const encryptedPrivateKey = identity.encrypted_private_key;

  return {
    operatorPublicKey,
    storage,
    masterKey,
    signPayload(action: string, payload: unknown): string {
      const message = buildOperatorSignedMessage(action, payload);
      const signature = sign(message, encryptedPrivateKey, identityEncryptionKey);
      try {
        return toBase64url(signature);
      } finally {
        signature.fill(0);
      }
    },
  };
}

function decodePublicKey(b64: string): Uint8Array | null {
  try {
    const key = fromBase64url(b64);
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}
