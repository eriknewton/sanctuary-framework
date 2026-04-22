/**
 * Sanctuary Federation Protocol v0.1 — Peer-ID derivation.
 *
 * HARD RULE (spawn prompt §5 + §7.2):
 *   peer-id = Ed25519 public key of the node's NodeIdentityCertificate.
 *
 * No second keypair. A peer presenting any other peer-id is rejected pre-
 * application-layer (libp2p's Noise handshake enforces peer-id matches the
 * static keypair's pubkey — we rely on that). The application layer then
 * verifies the NodeIdentityCertificate against the pinned fortress-master;
 * a matched peer-id that fails cert-chain verification is an impersonation
 * attempt and the connection is dropped.
 *
 * This module is the one-way bridge between Sanctuary's Ed25519 key material
 * (32-byte seed) and libp2p's key primitives (protobuf-wrapped, typed).
 */

import {
  generateKeyPairFromSeed,
  publicKeyFromRaw,
} from "@libp2p/crypto/keys";
import { peerIdFromPrivateKey, peerIdFromPublicKey } from "@libp2p/peer-id";
import type {
  Ed25519PeerId,
  Ed25519PrivateKey,
  Ed25519PublicKey,
  PeerId,
} from "@libp2p/interface";
import { fromBase64url } from "../../core/encoding.js";

/**
 * Convert the 32-byte Ed25519 private-key seed from Sanctuary's identity
 * layer into a libp2p Ed25519PrivateKey. The returned key's public component
 * matches the Ed25519 public key Sanctuary's `generateKeypair()` produced.
 */
export async function libp2pPrivateKeyFromSanctuarySeed(
  seed: Uint8Array
): Promise<Ed25519PrivateKey> {
  if (seed.length !== 32) {
    throw new Error(
      `libp2pPrivateKeyFromSanctuarySeed: expected 32-byte Ed25519 seed; got ${seed.length}`
    );
  }
  return await generateKeyPairFromSeed("Ed25519", seed);
}

/**
 * Derive the libp2p peer-id from a Sanctuary 32-byte Ed25519 seed. This is
 * the peer-id the node will present during the Noise handshake.
 */
export async function peerIdFromSanctuarySeed(
  seed: Uint8Array
): Promise<Ed25519PeerId> {
  const privateKey = await libp2pPrivateKeyFromSanctuarySeed(seed);
  return peerIdFromPrivateKey(privateKey);
}

/**
 * Derive the libp2p peer-id from a base64url-encoded Ed25519 public key —
 * the shape Sanctuary's NodeIdentityCertificate carries in `node_pubkey`.
 *
 * This is the function the transport calls for every peer it learns about
 * (static-peer config, discovery, roster); it turns the on-cert pubkey into
 * a PeerId so we can pin the Noise handshake against it.
 */
export function peerIdFromSanctuaryPubkey(pubkeyBase64url: string): PeerId {
  const raw = fromBase64url(pubkeyBase64url);
  if (raw.length !== 32) {
    throw new Error(
      `peerIdFromSanctuaryPubkey: expected 32-byte Ed25519 pubkey; got ${raw.length}`
    );
  }
  const publicKey = publicKeyFromRaw(raw) as Ed25519PublicKey;
  if (publicKey.type !== "Ed25519") {
    throw new Error(
      `peerIdFromSanctuaryPubkey: expected Ed25519 public key; got ${publicKey.type}`
    );
  }
  return peerIdFromPublicKey(publicKey);
}
