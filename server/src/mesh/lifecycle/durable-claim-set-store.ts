/**
 * Encrypted-at-rest durable backend for the operator-cloud provision-claim set.
 *
 * Sibling of {@link DurableSpentSetStore}: same fail-closed AES-256-GCM pattern,
 * but the records are full provision claims (with their single-use `consumed`
 * flag and digest bindings) rather than bare key->expiry entries. Persisting the
 * claim set lets a recorded-but-unconsumed claim survive a daemon restart AND,
 * critically, keeps a CONSUMED claim consumed across a restart so the cloud join
 * is not replayable mid-TTL.
 *
 * Invariants mirrored from the trust-root store:
 *   - one encrypted record holds the whole claim set (a corrupt blob fails closed
 *     for the entire set, never silently drops an attacker-corrupted entry),
 *   - load THROWS on a corrupt / tampered record so the caller fails closed
 *     (cannot prove a claim is unconsumed -> deny), never a silent reset,
 *   - persist THROWS on write failure so the caller can deny rather than act on
 *     a claim whose state was not durably committed.
 */

import type { StorageBackend } from "../../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../../core/encryption.js";
import { derivePurposeKey } from "../../core/key-derivation.js";
import { bytesToString, stringToBytes } from "../../core/encoding.js";

/**
 * A Tier-1-approved operator-cloud provision claim, recorded by the home node
 * before delivery. Defined here (the lower-level persistence module) so the
 * durable backend and the approver share one contract without a circular import.
 */
export interface OperatorCloudProvisionClaim {
  fortress_id: string;
  node_id: string;
  node_mode: "operator_cloud";
  node_pubkey_hash: string;
  bootstrap_nonce: string;
  manifest_digest: string;
  scoped_secret_ciphertext_digest: string;
  scope_digest: string;
  bundle_digest: string;
  expires_at: string;
  consumed: boolean;
}

export interface PersistedClaimSet {
  /** Format version for forward-compatibility. */
  v: 1;
  /** Map storage key -> claim, flattened to an array for JSON. */
  entries: Array<{ key: string; claim: OperatorCloudProvisionClaim }>;
}

export class DurableClaimSetStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DurableClaimSetStoreError";
  }
}

/**
 * Encrypted persistence for the operator-cloud provision-claim set (storage key
 * -> claim). One record at (`namespace`, `recordKey`) holds the whole encrypted
 * set. `load` returns the decrypted claims (THROWS on a corrupt record so the
 * caller fails closed); `persist` re-encrypts and writes the whole set (THROWS on
 * write failure).
 */
export class DurableClaimSetStore {
  private readonly storage: StorageBackend;
  private readonly namespace: string;
  private readonly recordKey: string;
  private readonly encryptionKey: Uint8Array;

  constructor(params: {
    storage: StorageBackend;
    masterKey: Uint8Array;
    namespace: string;
    recordKey: string;
    hkdfLabel: string;
  }) {
    this.storage = params.storage;
    this.namespace = params.namespace;
    this.recordKey = params.recordKey;
    this.encryptionKey = derivePurposeKey(params.masterKey, params.hkdfLabel);
  }

  /**
   * Load the claim set, pruning entries already expired at `nowMs`. Returns an
   * empty map when no record exists. THROWS {@link DurableClaimSetStoreError}
   * when a record exists but cannot be decrypted/parsed: the caller MUST fail
   * closed, never silently reset.
   */
  async load(nowMs: number): Promise<Map<string, OperatorCloudProvisionClaim>> {
    const raw = await this.storage.read(this.namespace, this.recordKey);
    if (raw === null) return new Map();

    let plaintext: Uint8Array | null = null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      plaintext = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(plaintext)) as unknown;
      return decodeClaimSet(parsed, nowMs);
    } catch (err) {
      throw new DurableClaimSetStoreError(
        `durable claim set failed to load: ${publicErrorReason(err)}`,
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  /** Persist the whole claim set. THROWS on any encrypt/write failure. */
  async persist(
    claims: ReadonlyMap<string, OperatorCloudProvisionClaim>,
  ): Promise<void> {
    const set: PersistedClaimSet = {
      v: 1,
      entries: [...claims].map(([key, claim]) => ({ key, claim })),
    };
    const serialized = stringToBytes(JSON.stringify(set));
    try {
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        this.namespace,
        this.recordKey,
        stringToBytes(JSON.stringify(encrypted)),
      );
    } finally {
      serialized.fill(0);
    }
  }
}

function decodeClaimSet(
  value: unknown,
  nowMs: number,
): Map<string, OperatorCloudProvisionClaim> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DurableClaimSetStoreError("record is not an object");
  }
  const obj = value as Record<string, unknown>;
  if (obj.v !== 1) {
    throw new DurableClaimSetStoreError(`unsupported record version: ${String(obj.v)}`);
  }
  if (!Array.isArray(obj.entries)) {
    throw new DurableClaimSetStoreError("entries is not an array");
  }
  const out = new Map<string, OperatorCloudProvisionClaim>();
  for (const entry of obj.entries) {
    if (typeof entry !== "object" || entry === null) {
      throw new DurableClaimSetStoreError("entry is not an object");
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.key !== "string" || e.key.length === 0) {
      throw new DurableClaimSetStoreError("entry key is invalid");
    }
    const claim = decodeClaim(e.claim);
    // Prune expired claims on load; they would be denied anyway (consume checks
    // expiry) and pruning keeps the set bounded.
    if (Date.parse(claim.expires_at) < nowMs) continue;
    out.set(e.key, claim);
  }
  return out;
}

function decodeClaim(value: unknown): OperatorCloudProvisionClaim {
  if (typeof value !== "object" || value === null) {
    throw new DurableClaimSetStoreError("claim is not an object");
  }
  const c = value as Record<string, unknown>;
  const str = (k: string): string => {
    const v = c[k];
    if (typeof v !== "string" || v.length === 0) {
      throw new DurableClaimSetStoreError(`claim.${k} is invalid`);
    }
    return v;
  };
  if (c.node_mode !== "operator_cloud") {
    throw new DurableClaimSetStoreError("claim.node_mode is invalid");
  }
  if (typeof c.consumed !== "boolean") {
    throw new DurableClaimSetStoreError("claim.consumed is invalid");
  }
  return {
    fortress_id: str("fortress_id"),
    node_id: str("node_id"),
    node_mode: "operator_cloud",
    node_pubkey_hash: str("node_pubkey_hash"),
    bootstrap_nonce: str("bootstrap_nonce"),
    manifest_digest: str("manifest_digest"),
    scoped_secret_ciphertext_digest: str("scoped_secret_ciphertext_digest"),
    scope_digest: str("scope_digest"),
    bundle_digest: str("bundle_digest"),
    expires_at: str("expires_at"),
    consumed: c.consumed,
  };
}

function publicErrorReason(err: unknown): string {
  if (err instanceof DurableClaimSetStoreError) return err.message;
  if (err instanceof SyntaxError) return "malformed JSON";
  return "decrypt_or_parse_failed";
}
