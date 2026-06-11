/**
 * Transparency-checkpoint signer resolution.
 *
 * Reuses the Castle Wall signing custody chain (#387 helper-as-signer):
 *
 *   - "helper" (production, macOS): the root signer helper owns the Ed25519
 *     key; this process relays opaque domain-separated bytes through the
 *     code-signed shim and never sees the private key. When the root-owned
 *     global pin exists it is cross-checked against the live helper key
 *     (mismatch refuses — same F-A2-1 #4 discipline as the daemon).
 *   - "local" (dev/test, explicit opt-in): the fortress-local castle-pinned
 *     key, decrypted transiently with the master key.
 *
 * FAIL-CLOSED: if no signer can be resolved, this throws. There is no
 * unsigned-emission path anywhere downstream.
 */

import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { toBase64url } from "../core/encoding.js";
import { decrypt, encrypt, type EncryptedPayload } from "../core/encryption.js";
import { sign as identitySign } from "../core/identity.js";
import {
  HelperSignerClient,
  type ShimInvoker,
} from "../castle-wall/runtime/helper-signer.js";
import { TransparencyEmitError, type TransparencySigner } from "./emitter.js";

const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";
const CASTLE_PINNED_PRIVKEY = "castle-pinned-privkey.enc";
export const CASTLE_GLOBAL_PINNED_PUBKEY_PATH =
  "/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin";

export interface ResolveTransparencySignerInput {
  fortressPath: string;
  /** Master key; needed only for the local-sign path. */
  masterKey: Uint8Array;
  env?: NodeJS.ProcessEnv;
  /** "auto" (default): local when SANCTUARY_CASTLE_LOCAL_SIGN=1, else helper. */
  mode?: "auto" | "helper" | "local";
  /** Override the shim runner (tests). */
  signerClientInvoke?: ShimInvoker;
  /** Override the root-owned global pin path (tests). */
  globalPinnedPublicKeyPath?: string;
}

export async function resolveTransparencySigner(
  input: ResolveTransparencySignerInput
): Promise<TransparencySigner> {
  const env = input.env ?? process.env;
  const mode =
    input.mode === undefined || input.mode === "auto"
      ? env.SANCTUARY_CASTLE_LOCAL_SIGN === "1"
        ? "local"
        : "helper"
      : input.mode;

  if (mode === "local") {
    return loadLocalTransparencySigner(input.fortressPath, input.masterKey);
  }

  const clientBinaryPath = env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  if (!clientBinaryPath && !input.signerClientInvoke) {
    throw new TransparencyEmitError(
      "no checkpoint signer available: set SANCTUARY_CASTLE_SIGNER_CLIENT to the castle-wall-signer-client shim path (helper custody), or pass --local-sign / SANCTUARY_CASTLE_LOCAL_SIGN=1 for the dev local-key path; refusing to emit unsigned"
    );
  }
  const client = new HelperSignerClient({
    clientBinaryPath: clientBinaryPath ?? "castle-wall-signer-client",
    ...(input.signerClientInvoke ? { invoke: input.signerClientInvoke } : {}),
  });
  let publicKey: Uint8Array;
  try {
    publicKey = await client.getPublicKey();
  } catch (err) {
    throw new TransparencyEmitError(
      `signer helper unreachable: ${err instanceof Error ? err.message : String(err)}; refusing to emit unsigned`
    );
  }
  await assertGlobalPinMatches(
    publicKey,
    input.globalPinnedPublicKeyPath ?? CASTLE_GLOBAL_PINNED_PUBKEY_PATH
  );
  return {
    signer_kid: `castle-wall:${toBase64url(publicKey)}`,
    publicKey,
    sign: (bytes) => client.signManifest(bytes),
  };
}

/**
 * Cross-check the root-owned global pin against the live helper key
 * (defense-in-depth, same policy as the daemon's F-A2-1 #4 check). Only a
 * root-owned pin is authoritative; absent / non-root pins are skipped.
 */
async function assertGlobalPinMatches(
  liveKey: Uint8Array,
  pinPath: string
): Promise<void> {
  let pin: { uid: number; bytes: Uint8Array } | null;
  try {
    const uid = (await stat(pinPath)).uid;
    const bytes = await readFile(pinPath);
    pin = { uid, bytes };
  } catch {
    return;
  }
  if (!pin || pin.uid !== 0) return;
  const equal =
    pin.bytes.length === liveKey.length &&
    Buffer.compare(Buffer.from(pin.bytes), Buffer.from(liveKey)) === 0;
  if (!equal) {
    throw new TransparencyEmitError(
      "trust-anchor mismatch: the root-owned global pin does not match the live signer helper key; refusing to emit (run 'sanctuary castle-wall re-pin' to re-establish the trust anchor)"
    );
  }
}

/** Dev/test local path: decrypt the fortress castle-pinned key per emission. */
async function loadLocalTransparencySigner(
  fortressPath: string,
  masterKey: Uint8Array
): Promise<TransparencySigner> {
  let publicKey: Uint8Array;
  let encryptedPrivateKey: EncryptedPayload;
  try {
    publicKey = await readFile(join(fortressPath, CASTLE_PINNED_PUBKEY));
    encryptedPrivateKey = JSON.parse(
      await readFile(join(fortressPath, CASTLE_PINNED_PRIVKEY), "utf8")
    ) as EncryptedPayload;
  } catch (err) {
    throw new TransparencyEmitError(
      `local signing key unavailable (${err instanceof Error ? err.message : String(err)}): run 'sanctuary castle-wall provision-pin' first, or use the helper path; refusing to emit unsigned`
    );
  }
  if (publicKey.length !== 32) {
    throw new TransparencyEmitError(
      `pinned public key must be 32 bytes (found ${publicKey.length}); refusing to emit`
    );
  }
  // Legacy 64-byte (seed||pub) private keys normalize to the 32-byte seed,
  // mirroring the daemon's loadLocalSigningKey.
  let privateKey: Uint8Array;
  try {
    privateKey = decrypt(encryptedPrivateKey, masterKey);
  } catch {
    throw new TransparencyEmitError(
      "pinned private key could not be decrypted (wrong passphrase for this fortress); refusing to emit"
    );
  }
  try {
    if (privateKey.length === 64) {
      encryptedPrivateKey = encrypt(privateKey.slice(0, 32), masterKey);
    } else if (privateKey.length !== 32) {
      throw new TransparencyEmitError(
        `pinned private key must decrypt to 32 bytes (found ${privateKey.length}); refusing to emit`
      );
    }
  } finally {
    privateKey.fill(0);
  }
  const frozenEncrypted = encryptedPrivateKey;
  return {
    signer_kid: `castle-wall:${toBase64url(publicKey)}`,
    publicKey: new Uint8Array(publicKey),
    sign: async (bytes) => identitySign(bytes, frozenEncrypted, masterKey),
  };
}
