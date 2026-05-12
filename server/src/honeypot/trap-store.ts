/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-2 Trap Store.
 *
 * Encrypted at-rest persistence for deployed honeypot TrapSpecs.
 * Sibling to Phi-1's SentinelFindingStore: same fortress-master-key-
 * derived HKDF subkey shape, AAD-bound to the trap_id, per-fortress
 * scoped.
 *
 * Storage layout:
 *   namespace: `_honeypot_traps`
 *   key:       `trap.{trap_id}` (one record per deployed trap)
 *   payload:   AES-256-GCM ciphertext of the JSON-serialized spec.
 *   key:       `l2-honeypot-trap-v1` HKDF subkey of fortress master.
 *   AAD:       UTF-8 bytes of `trap_id`.
 *
 * Multi-fortress isolation: HKDF subkey derives from the fortress
 * master key. Two fortresses never produce identical encryption keys
 * for identical trap_ids; a fortress that reads another fortress's
 * encrypted record cannot decrypt it.
 *
 * Persistence contract:
 *   - save(spec): write the spec under its trap_id. Idempotent;
 *     re-saves overwrite.
 *   - delete(trapId): remove the record. Idempotent.
 *   - loadAll(): rehydrate every persisted spec. Used at boot to
 *     populate the in-memory TrapRegistry. Corrupted records are
 *     dropped (best-effort recovery: a malformed entry should not
 *     block the rest of the fortress).
 *
 * Pi-2 ships traps with no retention window (traps stay deployed
 * until explicitly undeployed). The store mirrors SentinelFindingStore's
 * AES-256-GCM envelope shape but omits retention deadlines.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

import type { TrapSpec } from "./types.js";

export const TRAP_STORE_NAMESPACE = "_honeypot_traps";
export const TRAP_STORE_KEY_PREFIX = "trap.";
const HKDF_INFO = "l2-honeypot-trap-v1";

/** Hard upper bound on per-trap decode size. */
const MAX_TRAP_BYTES = 64 * 1024;

interface PersistedTrap {
  /** Bump on schema change. */
  version: 1;
  spec: TrapSpec;
}

export interface TrapStoreOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
}

export class TrapStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;

  constructor(opts: TrapStoreOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
  }

  /** Persist (or overwrite) one trap. Returns the trap_id on success. */
  async save(spec: TrapSpec): Promise<string> {
    const persisted: PersistedTrap = { version: 1, spec };
    const aad = stringToBytes(spec.trap_id);
    const plaintext = stringToBytes(JSON.stringify(persisted));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      TRAP_STORE_NAMESPACE,
      trapKey(spec.trap_id),
      stringToBytes(JSON.stringify(envelope)),
    );
    return spec.trap_id;
  }

  /**
   * Remove one trap by id. Returns true when a record was removed,
   * false when no record existed (idempotent).
   */
  async delete(trapId: string): Promise<boolean> {
    try {
      const raw = await this.storage.read(
        TRAP_STORE_NAMESPACE,
        trapKey(trapId),
      );
      if (!raw) return false;
      await this.storage.delete(TRAP_STORE_NAMESPACE, trapKey(trapId));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Load every persisted trap. Used at boot to repopulate the
   * in-memory TrapRegistry. Corrupted records are silently skipped
   * so one malformed entry never blocks the rest of the fortress's
   * traps from rehydrating.
   *
   * Returns the specs sorted by `compiled_at` ascending so the
   * in-memory registry's insertion order matches the original
   * deploy order (relevant for Pi-1's "first-deployed wins on
   * overlapping match" contract).
   */
  async loadAll(): Promise<TrapSpec[]> {
    const metas = await this.storage.list(
      TRAP_STORE_NAMESPACE,
      TRAP_STORE_KEY_PREFIX,
    );
    const out: TrapSpec[] = [];
    for (const meta of metas) {
      const trapId = stripKeyPrefix(meta.key);
      if (trapId === null) continue;
      const raw = await this.storage.read(TRAP_STORE_NAMESPACE, meta.key);
      if (!raw) continue;
      if (raw.length > MAX_TRAP_BYTES) continue;
      const spec = this.decode(trapId, raw);
      if (spec !== null) out.push(spec);
    }
    out.sort((a, b) =>
      a.compiled_at < b.compiled_at ? -1 : a.compiled_at > b.compiled_at ? 1 : 0,
    );
    return out;
  }

  /** Read-only fortress-id getter. */
  getFortressId(): string {
    return this.fortressId;
  }

  private decode(trapId: string, raw: Uint8Array): TrapSpec | null {
    try {
      const aad = stringToBytes(trapId);
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const persisted = JSON.parse(bytesToString(plaintext)) as PersistedTrap;
      if (persisted.version !== 1) return null;
      if (persisted.spec.trap_id !== trapId) return null;
      return persisted.spec;
    } catch {
      return null;
    }
  }
}

function trapKey(trapId: string): string {
  return `${TRAP_STORE_KEY_PREFIX}${trapId}`;
}

function stripKeyPrefix(key: string): string | null {
  if (!key.startsWith(TRAP_STORE_KEY_PREFIX)) return null;
  return key.slice(TRAP_STORE_KEY_PREFIX.length);
}
