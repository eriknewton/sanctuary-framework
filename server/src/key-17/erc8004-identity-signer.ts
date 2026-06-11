/**
 * Key 17 -- ERC-8004 Identity Registry signer.
 *
 * secp256k1 keypair derived from the operator's master key for signing
 * Ethereum-style messages compatible with the ERC-8004 Identity Registry.
 * Produces 65-byte signatures (r + s + recovery byte) that can be verified
 * on-chain via ecrecover.
 *
 * The operator's gas wallet is a separate concern; this module handles only
 * the Identity-signing primitive. Verascore's ERC-8004 write adapter handles
 * the gas-paying side.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";


/** Shape of an ERC-8004 Identity registration payload. */
export interface Erc8004Registration {
  /** The agent's DID or identity string to register. */
  identity: string;
  /** ERC-8004 registry contract address (checksummed hex). */
  registry: string;
  /** Chain ID (e.g. 1 for mainnet, 11155111 for Sepolia). */
  chain_id: number;
  /** Registration nonce from the registry contract. */
  nonce: number;
  /** ISO 8601 timestamp of the registration request. */
  timestamp: string;
  /** Additional metadata fields. */
  [key: string]: unknown;
}

/** A signed ERC-8004 registration with Ethereum-compatible signature. */
export interface SignedErc8004Registration extends Erc8004Registration {
  /** 65-byte secp256k1 signature (r + s + v), hex-encoded. */
  signature: string;
  /** Ethereum address derived from the signing public key, checksummed hex. */
  signer_address: string;
  /** Compressed public key, hex-encoded. */
  public_key: string;
}

/**
 * Derive a protocol-scoped secp256k1 private key from the operator's master key.
 */
export function deriveErc8004Key(
  masterKey: Uint8Array,
  operatorId: string
): Uint8Array {
  return hkdf(
    sha256,
    masterKey,
    new TextEncoder().encode(operatorId),
    new TextEncoder().encode("key-17:erc8004-identity:v1"),
    32
  );
}

/**
 * Derive the Ethereum address from a secp256k1 public key.
 * Takes the uncompressed public key (65 bytes), strips the 0x04 prefix,
 * keccak256-hashes the remaining 64 bytes, and takes the last 20 bytes.
 */
export function publicKeyToAddress(publicKey: Uint8Array): string {
  // Get uncompressed public key (65 bytes with 0x04 prefix)
  const uncompressed =
    publicKey.length === 33
      ? secp256k1.ProjectivePoint.fromHex(publicKey).toRawBytes(false)
      : publicKey;
  // Hash the 64 bytes after the 0x04 prefix
  const hash = keccak_256(uncompressed.slice(1));
  const addressBytes = hash.slice(12);
  return checksumAddress(addressBytes);
}

/**
 * EIP-55 checksum encoding for an Ethereum address.
 */
function checksumAddress(addressBytes: Uint8Array): string {
  const hex = Array.from(addressBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const hashHex = Array.from(keccak_256(new TextEncoder().encode(hex)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  let result = "0x";
  for (let i = 0; i < 40; i++) {
    result += parseInt(hashHex[i], 16) >= 8 ? hex[i].toUpperCase() : hex[i];
  }
  return result;
}

/**
 * Produce the Ethereum-style message hash for signing.
 * Follows the "\x19Ethereum Signed Message:\n" prefix convention.
 */
function ethMessageHash(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(
    `\x19Ethereum Signed Message:\n${message.length}`
  );
  const combined = new Uint8Array(prefix.length + message.length);
  combined.set(prefix);
  combined.set(message, prefix.length);
  return keccak_256(combined);
}

/**
 * Sign an ERC-8004 Identity registration.
 *
 * Signs using the Ethereum personal_sign convention (prefixed message hash).
 * Produces a 65-byte signature (r[32] + s[32] + v[1]) compatible with
 * on-chain ecrecover.
 */
export function signErc8004Registration(
  masterKey: Uint8Array,
  operatorId: string,
  registration: Erc8004Registration
): SignedErc8004Registration {
  const privateKey = deriveErc8004Key(masterKey, operatorId);
  const publicKey = secp256k1.getPublicKey(privateKey, true); // compressed
  const address = publicKeyToAddress(publicKey);

  const messageBytes = canonicalizeToBytes(registration);
  const msgHash = ethMessageHash(messageBytes);

  const sig = secp256k1.sign(msgHash, privateKey);
  // Construct 65-byte signature: r (32 bytes) + s (32 bytes) + recovery (1 byte)
  const rBytes = sig.r.toString(16).padStart(64, "0");
  const sBytes = sig.s.toString(16).padStart(64, "0");
  const vByte = (sig.recovery + 27).toString(16).padStart(2, "0");
  const signatureHex = "0x" + rBytes + sBytes + vByte;

  return {
    ...registration,
    signature: signatureHex,
    signer_address: address,
    public_key: Buffer.from(publicKey).toString("hex"),
  };
}

/**
 * Verify a signed ERC-8004 registration.
 *
 * Recovers the signer address from the signature and compares against
 * the embedded signer_address.
 */
export function verifyErc8004Registration(
  signed: SignedErc8004Registration
): boolean {
  const { signature, signer_address, public_key: _public_key, ...unsigned } = signed;

  const messageBytes = canonicalizeToBytes(unsigned);
  const msgHash = ethMessageHash(messageBytes);

  // Parse the 65-byte signature
  const sigHex = signature.startsWith("0x") ? signature.slice(2) : signature;
  if (sigHex.length !== 130) return false;

  const r = BigInt("0x" + sigHex.slice(0, 64));
  const s = BigInt("0x" + sigHex.slice(64, 128));
  const v = parseInt(sigHex.slice(128, 130), 16);
  const recovery = v >= 27 ? v - 27 : v;

  try {
    const sig = new secp256k1.Signature(r, s, recovery);
    const recoveredPoint = sig.recoverPublicKey(msgHash);
    const recoveredAddress = publicKeyToAddress(
      recoveredPoint.toRawBytes(false)
    );
    return recoveredAddress.toLowerCase() === signer_address.toLowerCase();
  } catch {
    return false;
  }
}
