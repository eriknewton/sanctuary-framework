/**
 * Ed25519 identity generation for Sanctuary quickstart.
 *
 * Replicates the DID encoding from server/src/core/identity.ts:
 *   did:key:z{base64url(0xed 0x01 || publicKey)}
 *
 * This is the same did:key method used by the full Sanctuary
 * identity subsystem, so quickstart identities are forward-compatible.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "node:crypto";

export interface QuickstartIdentity {
  did: string;
  publicKey: string; // base64url, no padding
  privateKey: string; // base64url, no padding
  createdAt: string;
}

/** Encode bytes to base64url (no padding) — RFC 4648 §5. */
export function toBase64url(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url (no padding) to bytes. */
export function fromBase64url(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) base64 += "=";
  const buf = Buffer.from(base64, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/**
 * Derive a did:key from an Ed25519 public key.
 * Matches publicKeyToDid() in server/src/core/identity.ts.
 */
export function publicKeyToDid(publicKey: Uint8Array): string {
  // Ed25519 multicodec prefix: 0xed 0x01
  const multicodec = new Uint8Array(2 + publicKey.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(publicKey, 2);
  return `did:key:z${toBase64url(multicodec)}`;
}

/** Generate a new Ed25519 keypair + DID. */
export function generateIdentity(): QuickstartIdentity {
  const priv = new Uint8Array(randomBytes(32));
  const pub = ed25519.getPublicKey(priv);
  const did = publicKeyToDid(pub);
  return {
    did,
    publicKey: toBase64url(pub),
    privateKey: toBase64url(priv),
    createdAt: new Date().toISOString(),
  };
}

/** Sign bytes with the identity's Ed25519 private key. Returns base64url. */
export function signBytes(
  message: Uint8Array,
  privateKeyB64url: string,
): string {
  const priv = fromBase64url(privateKeyB64url);
  const sig = ed25519.sign(message, priv);
  return toBase64url(sig);
}
