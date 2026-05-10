/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-3
 *
 * At-rest encrypted persistence for full request payloads tied to
 * AggregatedApproval entries. Sibling store to ApprovalAggregator: the
 * aggregator's own entry record (status, provenance, hashes) is persisted
 * by the aggregator class under `_approval_aggregator`; this store holds
 * the original request payload separately under
 * `_approval_aggregator_payloads` so the operator can replay the full
 * payload after a server restart.
 *
 * Storage layout:
 *   namespace: `_approval_aggregator_payloads`
 *   key:       `payload.{aggregator_id}` (one record per approval)
 *   payload:   AES-256-GCM ciphertext of the JSON-serialised bundle.
 *   key:       `l2-approval-aggregator-payload-v1` HKDF subkey of fortress
 *              master.
 *   AAD:       UTF-8 bytes of `aggregator_id`. Swapping records across
 *              aggregator_ids breaks the auth tag. Castle-walking
 *              discipline: the encryption boundary holds even against
 *              on-disk shuffle.
 *
 * Retention:
 * Each bundle carries an ISO-8601 `retention_until`. `pruneExpired()`
 * iterates payloads and drops entries whose retention_until is in the
 * past. Default retention is 30 days, mirroring the audit-log retention
 * envelope. Operator override flows through the aggregator's deps.
 *
 * Multi-fortress isolation:
 * The HKDF subkey is derived from the fortress master key. Two
 * fortresses never produce identical encryption keys for identical
 * aggregator_ids. Isolation is enforced cryptographically; the AAD
 * binds the ciphertext to a specific aggregator_id within a fortress.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

export const AGGREGATOR_PAYLOAD_NAMESPACE = "_approval_aggregator_payloads";
export const AGGREGATOR_PAYLOAD_KEY_PREFIX = "payload.";
const HKDF_INFO = "l2-approval-aggregator-payload-v1";

/** Default retention window when the operator has not tuned a custom value. */
export const DEFAULT_AGGREGATOR_PAYLOAD_RETENTION_DAYS = 30;

/** Hard upper bound on per-bundle decode size. Single payload past 4 MiB
 * means the gate context itself is degenerate; reject rather than crash. */
const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;

/** Persisted bundle. */
interface AggregatorPayloadBundle {
  /** Forward-compat field; bump on schema change. */
  version: 1;
  aggregator_id: string;
  /** Stable fortress id stamped for audit clarity. */
  fortress_id: string;
  /** ISO-8601 timestamp of bundle creation. */
  created_at: string;
  /** ISO-8601 timestamp after which prune drops this payload. */
  retention_until: string;
  /** The original request payload (gate context). */
  payload: unknown;
}

export interface AggregatorPayloadStoreOptions {
  /** Storage backend that persists the encrypted bundles. */
  storage: StorageBackend;
  /** 32-byte fortress master key. */
  masterKey: Uint8Array;
  /** Stable fortress id stamped on every bundle for audit clarity. */
  fortressId: string;
  /** Operator-tunable retention window. Default 30 days. */
  retentionDays?: number;
}

/**
 * Encrypted, AAD-bound, retention-aware payload persistence for the
 * cross-harness approval inbox.
 */
export class AggregatorPayloadStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly retentionDays: number;

  constructor(opts: AggregatorPayloadStoreOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
    this.retentionDays =
      opts.retentionDays !== undefined && opts.retentionDays > 0
        ? opts.retentionDays
        : DEFAULT_AGGREGATOR_PAYLOAD_RETENTION_DAYS;
  }

  /**
   * Persist `payload` under the given aggregator_id. Idempotent; calling
   * twice with the same id rewrites the bundle (retention_until is
   * recomputed). Returns the bundle's retention_until ISO-8601 timestamp
   * so callers can log it.
   */
  async savePayload(aggregatorId: string, payload: unknown): Promise<string> {
    const now = new Date();
    const retentionMs = this.retentionDays * 24 * 60 * 60 * 1000;
    const retentionUntil = new Date(now.getTime() + retentionMs);
    const bundle: AggregatorPayloadBundle = {
      version: 1,
      aggregator_id: aggregatorId,
      fortress_id: this.fortressId,
      created_at: now.toISOString(),
      retention_until: retentionUntil.toISOString(),
      payload,
    };
    const aad = stringToBytes(aggregatorId);
    const plaintext = stringToBytes(JSON.stringify(bundle));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      AGGREGATOR_PAYLOAD_NAMESPACE,
      payloadKey(aggregatorId),
      stringToBytes(JSON.stringify(envelope)),
    );
    return bundle.retention_until;
  }

  /**
   * Read the persisted payload for the aggregator_id. Returns null if no
   * bundle exists, the bundle is corrupted, or AAD binding fails.
   */
  async loadPayload(aggregatorId: string): Promise<unknown> {
    const key = payloadKey(aggregatorId);
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(AGGREGATOR_PAYLOAD_NAMESPACE, key);
    } catch {
      return null;
    }
    if (!raw) return null;
    if (raw.length > MAX_BUNDLE_BYTES) return null;

    try {
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const aad = stringToBytes(aggregatorId);
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const parsed = JSON.parse(
        bytesToString(plaintext),
      ) as AggregatorPayloadBundle;
      if (parsed.version !== 1) return null;
      if (parsed.aggregator_id !== aggregatorId) return null;
      return parsed.payload;
    } catch {
      return null;
    }
  }

  /**
   * Delete the persisted payload. Returns true when a bundle was removed,
   * false when none existed.
   */
  async deletePayload(aggregatorId: string): Promise<boolean> {
    const key = payloadKey(aggregatorId);
    const existed = await this.storage.exists(
      AGGREGATOR_PAYLOAD_NAMESPACE,
      key,
    );
    if (!existed) return false;
    try {
      await this.storage.delete(AGGREGATOR_PAYLOAD_NAMESPACE, key);
    } catch {
      return false;
    }
    return true;
  }

  /**
   * Drop expired payload bundles. Returns the count of bundles pruned.
   * Caller wires this into the cocoon-unlock initialization path.
   */
  async pruneExpired(now?: Date): Promise<{ pruned: number }> {
    const cutoff = (now ?? new Date()).toISOString();
    const entries = await this.storage.list(
      AGGREGATOR_PAYLOAD_NAMESPACE,
      AGGREGATOR_PAYLOAD_KEY_PREFIX,
    );
    let pruned = 0;
    for (const meta of entries) {
      const aggregatorId = stripKeyPrefix(meta.key);
      if (aggregatorId === null) continue;
      const raw = await this.storage.read(
        AGGREGATOR_PAYLOAD_NAMESPACE,
        meta.key,
      );
      if (!raw) continue;
      try {
        const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
        const aad = stringToBytes(aggregatorId);
        const plaintext = decrypt(envelope, this.encryptionKey, aad);
        const parsed = JSON.parse(
          bytesToString(plaintext),
        ) as AggregatorPayloadBundle;
        if (parsed.retention_until <= cutoff) {
          await this.storage.delete(AGGREGATOR_PAYLOAD_NAMESPACE, meta.key);
          pruned += 1;
        }
      } catch {
        // Corrupt bundle: leave in place. Rotation handled by audit log.
      }
    }
    return { pruned };
  }
}

function payloadKey(aggregatorId: string): string {
  return `${AGGREGATOR_PAYLOAD_KEY_PREFIX}${aggregatorId}`;
}

function stripKeyPrefix(key: string): string | null {
  if (!key.startsWith(AGGREGATOR_PAYLOAD_KEY_PREFIX)) return null;
  return key.slice(AGGREGATOR_PAYLOAD_KEY_PREFIX.length);
}
