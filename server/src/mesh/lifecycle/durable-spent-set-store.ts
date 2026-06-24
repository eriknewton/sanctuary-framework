/**
 * Encrypted-at-rest durable backend for the federation single-use replay stores.
 *
 * Both the local-join nonce store ({@link BootstrapNonceStore}) and the
 * operator-cloud provision-claim store ({@link OperatorCloudProvisionClaimStore})
 * are single-use gates: a nonce / claim may be consumed exactly once. In memory
 * the gate is the event loop's synchronous check-and-set. The DEBT this backend
 * closes is durability: an in-memory-only gate FORGETS the spent set on a daemon
 * restart, re-allowing one already-authorized token until its (<=15 min) expiry.
 *
 * This module persists the spent set so single-use survives a restart. It mirrors
 * the {@link FederationTrustRootStore} at-rest pattern exactly:
 *   - AES-256-GCM ciphertext under a purpose key derived from the custody master
 *     (`derivePurposeKey(masterKey, <hkdf-label>)`), one additive label per store,
 *   - AEAD tamper-evidence: a corrupt / tampered record fails decryption,
 *   - FAIL CLOSED on a corrupt record: load THROWS, and the consuming store must
 *     treat "cannot read the spent set" as "cannot prove not-spent" -> deny. It
 *     must NOT silently reset to an empty set (that would re-open the replay).
 *
 * The whole spent set is one encrypted record (not one record per key) so a
 * corrupt blob fails closed for the ENTIRE set rather than silently dropping the
 * one entry an attacker corrupted. The set is tiny and TTL-bounded (a spent
 * entry only needs to outlive the token that could bear it, <=15 min), so
 * re-writing the blob on each consume is cheap and keeps the fail-closed
 * semantics simple and total.
 *
 * Records carry the spent key plus its expiry so expired entries can be pruned
 * (the token itself is expiry-checked upstream, so an expired spent record is
 * moot). Pruning happens on load and is the caller's responsibility on consume.
 */

import type { StorageBackend } from "../../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../../core/encryption.js";
import { derivePurposeKey } from "../../core/key-derivation.js";
import { bytesToString, stringToBytes } from "../../core/encoding.js";

/** A single persisted spent entry: the opaque key and its absolute expiry (ms). */
interface PersistedSpentEntry {
  key: string;
  expires_at_ms: number;
}

interface PersistedSpentSet {
  /** Format version for forward-compatibility. */
  v: 1;
  entries: PersistedSpentEntry[];
}

export class DurableSpentSetStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DurableSpentSetStoreError";
  }
}

/**
 * Encrypted persistence for a single-use spent set (key -> expiry-ms).
 *
 * Storage layout: ONE record at (`namespace`, `recordKey`) holding the whole
 * encrypted set. `load` returns the decrypted set (THROWS on a corrupt record so
 * the caller fails closed); `persist` re-encrypts and writes the whole set
 * (THROWS on a write failure so the caller denies rather than allow-without-
 * persist).
 */
export class DurableSpentSetStore {
  private readonly storage: StorageBackend;
  private readonly namespace: string;
  private readonly recordKey: string;
  private readonly encryptionKey: Uint8Array;

  constructor(params: {
    storage: StorageBackend;
    masterKey: Uint8Array;
    /** At-rest namespace for this store's single record (additive, frozen). */
    namespace: string;
    /** Record key within the namespace. */
    recordKey: string;
    /** HKDF purpose label for this store's encryption key (additive, frozen). */
    hkdfLabel: string;
  }) {
    this.storage = params.storage;
    this.namespace = params.namespace;
    this.recordKey = params.recordKey;
    this.encryptionKey = derivePurposeKey(params.masterKey, params.hkdfLabel);
  }

  /**
   * Load the spent set, pruning entries already expired at `nowMs`. Returns an
   * empty map when no record exists yet (a fresh fortress). THROWS
   * {@link DurableSpentSetStoreError} when a record exists but cannot be
   * decrypted/parsed: the caller MUST fail closed (treat every key as possibly
   * spent / deny), never silently reset the set.
   */
  async load(nowMs: number): Promise<Map<string, number>> {
    const raw = await this.storage.read(this.namespace, this.recordKey);
    if (raw === null) return new Map();

    let plaintext: Uint8Array | null = null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      plaintext = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(plaintext)) as unknown;
      return decodeSpentSet(parsed, nowMs);
    } catch (err) {
      throw new DurableSpentSetStoreError(
        `durable spent set failed to load: ${publicErrorReason(err)}`,
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  /**
   * Persist the whole spent set (the in-memory map is the source of truth). THROWS
   * on any encrypt/write failure so the caller can fail closed: a consume whose
   * persist throws MUST deny rather than allow a token whose spent record was not
   * durably committed.
   */
  async persist(spent: ReadonlyMap<string, number>): Promise<void> {
    const set: PersistedSpentSet = {
      v: 1,
      entries: [...spent].map(([key, expires_at_ms]) => ({ key, expires_at_ms })),
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

function decodeSpentSet(value: unknown, nowMs: number): Map<string, number> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DurableSpentSetStoreError("record is not an object");
  }
  const obj = value as Record<string, unknown>;
  if (obj.v !== 1) {
    throw new DurableSpentSetStoreError(`unsupported record version: ${String(obj.v)}`);
  }
  if (!Array.isArray(obj.entries)) {
    throw new DurableSpentSetStoreError("entries is not an array");
  }
  const out = new Map<string, number>();
  for (const entry of obj.entries) {
    if (typeof entry !== "object" || entry === null) {
      throw new DurableSpentSetStoreError("entry is not an object");
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.key !== "string" || e.key.length === 0) {
      throw new DurableSpentSetStoreError("entry key is invalid");
    }
    if (typeof e.expires_at_ms !== "number" || !Number.isFinite(e.expires_at_ms)) {
      throw new DurableSpentSetStoreError("entry expiry is invalid");
    }
    // Prune entries already expired at load time; they are moot (the token is
    // expiry-checked upstream) and keep the set bounded.
    if (e.expires_at_ms < nowMs) continue;
    out.set(e.key, e.expires_at_ms);
  }
  return out;
}

function publicErrorReason(err: unknown): string {
  if (err instanceof DurableSpentSetStoreError) return err.message;
  if (err instanceof SyntaxError) return "malformed JSON";
  return "decrypt_or_parse_failed";
}
