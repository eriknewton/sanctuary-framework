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
import {
  ED25519_PRIVATE_KEY_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
} from "../../core/crypto-suite-registry.js";

/**
 * Cross-`@libp2p/interface`-major key bridges.
 *
 * The dependency graph deliberately carries two `@libp2p/interface` majors at
 * once during the libp2p 2.x -> 3.x migration. The core transport stack
 * (`libp2p` 2.10.x, `@libp2p/peer-id` 5.x, `@chainsafe/libp2p-noise`,
 * `it-length-prefixed`) pins `@libp2p/interface` ^2.11 / `uint8arraylist` ^2,
 * while `@libp2p/crypto` 5.1.20 (and `kad-dht`/`ping`) pin `@libp2p/interface`
 * ^3.2.4 / `uint8arraylist` ^3. The two majors are mutually exclusive at the
 * `uint8arraylist` peer range, so a single deduped `@libp2p/interface` is not
 * expressible without dragging an incompatible major onto the other half of
 * the stack (it breaks `transport.ts`). This module sits exactly on the seam:
 * it gets key objects from `@libp2p/crypto` (interface 3.x types) and hands
 * them to `@libp2p/peer-id` 5.x (interface 2.x types).
 *
 * The `Ed25519PrivateKey` / `Ed25519PublicKey` interface bodies are
 * byte-for-byte identical across the two majors; the ONLY type-level delta is
 * that `verify`/`sign` reference `uint8arraylist`, which became generic
 * (`Uint8ArrayList<ArrayBufferLike>` with a branded `[symbol]`) in v3. TS
 * therefore treats the two copies as distinct nominal types (TS2322) even
 * though they are structurally and behaviourally the same. We verified the
 * runtime interop directly: a `generateKeyPairFromSeed` key (3.x) passed to
 * `peerIdFromPrivateKey` (2.x) yields the same peer-id as the matching public
 * key passed to `peerIdFromPublicKey`.
 *
 * These bridges re-type the crypto-produced key as the consumer-side
 * (`@libp2p/interface` 2.x) key the peer-id functions expect. The cast goes
 * through `unknown` so it is a single, named, intentional seam crossing rather
 * than a silent `any` - it does NOT loosen any validation: callers still gate
 * on `seed.length === 32`, `raw.length === 32`, and `publicKey.type ===
 * "Ed25519"` before any key crosses the bridge. Delete these bridges once the
 * whole libp2p stack is on a single interface major.
 */
// The crypto-side key types are captured from the call site (see the two
// helpers below) so we never have to name the `@libp2p/interface` 3.x copy
// directly; the generic input infers whatever `@libp2p/crypto` produced.
function asConsumerPrivateKey<T extends { readonly type: "Ed25519" }>(
  key: T
): Ed25519PrivateKey {
  return key as unknown as Ed25519PrivateKey;
}
function asConsumerPublicKey<T extends { readonly type: string }>(
  key: T
): Ed25519PublicKey {
  return key as unknown as Ed25519PublicKey;
}

/**
 * Convert the 32-byte Ed25519 private-key seed from Sanctuary's identity
 * layer into a libp2p Ed25519PrivateKey. The returned key's public component
 * matches the Ed25519 public key Sanctuary's `generateKeypair()` produced.
 */
export async function libp2pPrivateKeyFromSanctuarySeed(
  seed: Uint8Array
): Promise<Ed25519PrivateKey> {
  if (seed.length !== ED25519_PRIVATE_KEY_BYTES) {
    throw new Error(
      `libp2pPrivateKeyFromSanctuarySeed: expected 32-byte Ed25519 seed; got ${seed.length}`
    );
  }
  return asConsumerPrivateKey(await generateKeyPairFromSeed("Ed25519", seed));
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
  if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(
      `peerIdFromSanctuaryPubkey: expected 32-byte Ed25519 pubkey; got ${raw.length}`
    );
  }
  const cryptoPublicKey = publicKeyFromRaw(raw);
  if (cryptoPublicKey.type !== "Ed25519") {
    throw new Error(
      `peerIdFromSanctuaryPubkey: expected Ed25519 public key; got ${cryptoPublicKey.type}`
    );
  }
  return peerIdFromPublicKey(asConsumerPublicKey(cryptoPublicKey));
}
