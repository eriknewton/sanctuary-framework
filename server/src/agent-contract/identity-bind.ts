/**
 * Sanctuary Agent Contract v0.1 — Per-Agent Identity Binding (§2.2).
 *
 * Each agent gets its own Ed25519 keypair at launch, generated fresh with 256
 * bits of independent entropy (HKDF is NOT used for asymmetric-key material
 * — see mesh/lifecycle/node-key-binding.ts for the same reasoning).
 *
 * The agent's private key is wrapped at rest under a per-agent wrapping key
 * derived from the fortress-master secret via HKDF. On guardian recovery the
 * same wrapping key re-derives, so a compromised-master event does not force
 * every wrapped agent to rotate.
 *
 * Symmetric per-agent subkeys (envelope-wrap, audit-chain,
 * attestation-nonce) are HKDF-derived and named by the AgentSubkeyPurpose
 * enum so auditors can enumerate what subkeys exist for an agent.
 *
 * Invariant: the agent's private key MUST NOT be surfaced to the harness
 * address space. Tier B adapters (§5) spawn the harness as a managed child
 * and route signing through the broker IPC, never exposing the key material.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import {
  decrypt,
  encrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { stringToBytes, toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import {
  AGENT_SUBKEY_PURPOSES,
  HKDF_AGENT_SUBKEY_INFO_PREFIX,
  type AgentSubkeyPurpose,
} from "./constants.js";
import { IdentityBindingError } from "./errors.js";
import type { AgentIdentityBinding } from "./types.js";

/**
 * Derive the per-agent at-rest wrapping key from the fortress-master secret.
 *
 * Deterministic in (fortress_master_secret, agent_id): guardian recovery
 * re-derives the same key so on-disk wrapped blobs survive master rotation
 * without per-agent rotation.
 */
export function deriveAgentKeyWrappingKey(params: {
  fortress_master_secret: Uint8Array;
  agent_id: string;
}): Uint8Array {
  const salt = stringToBytes(params.agent_id);
  const info = stringToBytes(
    `${HKDF_AGENT_SUBKEY_INFO_PREFIX}|wrap|${params.agent_id}`
  );
  return hkdf(sha256, params.fortress_master_secret, salt, info, 32);
}

/**
 * Derive a per-agent symmetric subkey for one of the enumerated purposes.
 *
 * The subkey is 32 bytes of HKDF-SHA256 output with info-string
 * `${PREFIX}|${purpose}|${agent_id}`. Two different purposes on the same
 * agent yield unrelated keys (domain separation).
 */
export function deriveAgentSubkey(params: {
  fortress_master_secret: Uint8Array;
  agent_id: string;
  purpose: AgentSubkeyPurpose;
}): Uint8Array {
  if (!AGENT_SUBKEY_PURPOSES.includes(params.purpose)) {
    throw new IdentityBindingError(
      `unknown AgentSubkeyPurpose "${params.purpose}"; allowed: ${AGENT_SUBKEY_PURPOSES.join(",")}`
    );
  }
  const salt = stringToBytes(params.agent_id);
  const info = stringToBytes(
    `${HKDF_AGENT_SUBKEY_INFO_PREFIX}|${params.purpose}|${params.agent_id}`
  );
  return hkdf(sha256, params.fortress_master_secret, salt, info, 32);
}

/**
 * Generate a fresh Ed25519 keypair for an agent. Returns the private seed
 * (raw 32 bytes) and the public key (32 bytes). Caller MUST wrap and zero
 * the private seed as soon as it is persisted.
 */
export function generateAgentKeypair(): {
  private_key: Uint8Array;
  public_key: Uint8Array;
} {
  const private_key = randomBytes(32);
  const public_key = ed25519.getPublicKey(private_key);
  return { private_key, public_key };
}

/**
 * Wrap a per-agent private seed for at-rest storage. AAD binds `agent:<id>`
 * so a wrapped blob from one agent cannot be substituted for another.
 */
export function wrapAgentPrivateKey(params: {
  agent_private_key: Uint8Array;
  fortress_master_secret: Uint8Array;
  agent_id: string;
}): EncryptedPayload {
  if (params.agent_private_key.length !== 32) {
    throw new IdentityBindingError(
      `wrapAgentPrivateKey: expected 32-byte Ed25519 seed; got ${params.agent_private_key.length}`
    );
  }
  const wrappingKey = deriveAgentKeyWrappingKey({
    fortress_master_secret: params.fortress_master_secret,
    agent_id: params.agent_id,
  });
  const aad = stringToBytes("agent:" + params.agent_id);
  return encrypt(params.agent_private_key, wrappingKey, aad);
}

/**
 * Unwrap a per-agent private seed. Throws if AAD mismatches — cross-agent
 * substitution attempt.
 */
export function unwrapAgentPrivateKey(params: {
  wrapped: EncryptedPayload;
  fortress_master_secret: Uint8Array;
  agent_id: string;
}): Uint8Array {
  const wrappingKey = deriveAgentKeyWrappingKey({
    fortress_master_secret: params.fortress_master_secret,
    agent_id: params.agent_id,
  });
  const aad = stringToBytes("agent:" + params.agent_id);
  return decrypt(params.wrapped, wrappingKey, aad);
}

/**
 * Per-agent key store. Wire a disk-backed implementation in production; the
 * in-memory store below is for tests and the default broker-process
 * lifecycle. Mirror of InMemoryNodeKeyStore in mesh/lifecycle.
 */
export interface AgentKeyStore {
  save(agent_id: string, wrapped: EncryptedPayload): Promise<void>;
  load(agent_id: string): Promise<EncryptedPayload | null>;
  remove(agent_id: string): Promise<void>;
  list(): Promise<string[]>;
}

export class InMemoryAgentKeyStore implements AgentKeyStore {
  private blobs = new Map<string, EncryptedPayload>();

  async save(agent_id: string, wrapped: EncryptedPayload): Promise<void> {
    this.blobs.set(agent_id, wrapped);
  }

  async load(agent_id: string): Promise<EncryptedPayload | null> {
    return this.blobs.get(agent_id) ?? null;
  }

  async remove(agent_id: string): Promise<void> {
    this.blobs.delete(agent_id);
  }

  async list(): Promise<string[]> {
    return Array.from(this.blobs.keys());
  }
}

/**
 * Bind a fresh identity to an agent_id: generates a keypair, wraps the
 * private key under the master-derived wrapping key, persists to the store,
 * zeroes the raw private key, and returns the AgentIdentityBinding record.
 *
 * The raw private key is NEVER returned from this function — signing goes
 * through `signWithAgentKey` which unwraps transiently.
 *
 * Spec §2.2. Invariant: this function does not expose the private seed to
 * callers (Tier B adapters). It zeroes the seed in the stack frame on return.
 */
export async function bindAgentIdentity(params: {
  agent_id: string;
  fortress_id: string;
  fortress_master_secret: Uint8Array;
  store: AgentKeyStore;
  now?: () => Date;
}): Promise<AgentIdentityBinding> {
  if (!params.agent_id || params.agent_id.length === 0) {
    throw new IdentityBindingError("bindAgentIdentity: agent_id required");
  }
  if (!params.fortress_id || params.fortress_id.length === 0) {
    throw new IdentityBindingError("bindAgentIdentity: fortress_id required");
  }
  const existing = await params.store.load(params.agent_id);
  if (existing) {
    throw new IdentityBindingError(
      `bindAgentIdentity: agent ${params.agent_id} already has a binding`
    );
  }
  const { private_key, public_key } = generateAgentKeypair();
  const wrapped = wrapAgentPrivateKey({
    agent_private_key: private_key,
    fortress_master_secret: params.fortress_master_secret,
    agent_id: params.agent_id,
  });
  private_key.fill(0);
  await params.store.save(params.agent_id, wrapped);
  const now = (params.now ?? (() => new Date()))();
  return {
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
    agent_pubkey: toBase64url(public_key),
    // Subkey purposes are derived lazily — none derived by this step alone.
    derived_subkey_purposes: [],
    bound_at: now.toISOString(),
  };
}

/**
 * Sign data with the per-agent key. Transiently unwraps the private seed,
 * signs, zeroes, returns the raw 64-byte Ed25519 signature.
 *
 * Callers that need base64url: encode in their own layer; this primitive
 * returns raw bytes to match `ed25519.sign` in mesh/envelope.ts.
 */
export async function signWithAgentKey(params: {
  agent_id: string;
  fortress_master_secret: Uint8Array;
  store: AgentKeyStore;
  payload: Uint8Array;
}): Promise<Uint8Array> {
  const wrapped = await params.store.load(params.agent_id);
  if (!wrapped) {
    throw new IdentityBindingError(
      `signWithAgentKey: no binding for agent ${params.agent_id}`
    );
  }
  const seed = unwrapAgentPrivateKey({
    wrapped,
    fortress_master_secret: params.fortress_master_secret,
    agent_id: params.agent_id,
  });
  try {
    return ed25519.sign(params.payload, seed);
  } finally {
    seed.fill(0);
  }
}

/**
 * Get the public key bytes for an agent. Convenience for verifiers on the
 * same node; cross-node verification goes through the Agent Card which is
 * envelope-signed by the issuing node and carries agent_pubkey.
 */
export async function getAgentPublicKey(params: {
  agent_id: string;
  fortress_master_secret: Uint8Array;
  store: AgentKeyStore;
}): Promise<Uint8Array> {
  const wrapped = await params.store.load(params.agent_id);
  if (!wrapped) {
    throw new IdentityBindingError(
      `getAgentPublicKey: no binding for agent ${params.agent_id}`
    );
  }
  const seed = unwrapAgentPrivateKey({
    wrapped,
    fortress_master_secret: params.fortress_master_secret,
    agent_id: params.agent_id,
  });
  try {
    return ed25519.getPublicKey(seed);
  } finally {
    seed.fill(0);
  }
}
