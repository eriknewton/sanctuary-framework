/**
 * Sanctuary MCP Server — Intelligence Substrate Config Store
 *
 * Encrypted persistence for the operator's substrate selection. Mirrors the
 * ContextGatePolicyStore pattern (`operational/context-gate.ts`) but
 * simpler: substrate config is a single per-fortress record, not a
 * multi-policy collection.
 *
 * Storage layout:
 *   namespace: `_intelligence` (underscore-prefixed = reserved L1 namespace)
 *   key:       `substrate-config`
 *   payload:   AES-256-GCM-encrypted `SubstrateConfig` JSON, key derived
 *              via HKDF from the fortress master key with info string
 *              `intelligence-substrate-config`.
 *
 * Sub-namespace for credentials:
 * Operator API keys (Venice, frontier provider keys) are stored as part
 * of the SubstrateConfig record; the entire record is encrypted under L1
 * before persist. There is no separate credentials namespace at v1.2 —
 * v1.3+ may split credentials into a per-purpose key store if hardware
 * keys / Secret Service backends warrant it.
 *
 * Forward-compat:
 * The on-disk record carries a `version: 1` field. Selector load reads
 * the version field and refuses to load configs from a future version
 * (returns null + emits `intelligence_config_reset` audit event +
 * applies defaults). Migration code lands in v1.x bumps as needed.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import { buildDefaultConfig } from "./defaults.js";
import type { SubstrateConfig } from "./types.js";

export const INTELLIGENCE_NAMESPACE = "_intelligence";
export const SUBSTRATE_CONFIG_KEY = "substrate-config";
const HKDF_INFO = "intelligence-substrate-config";

/**
 * Outcome of a load attempt. The selector audit-emits based on which
 * branch fired so the on-disk config history is reconstructable.
 */
export type LoadOutcome =
  | { kind: "loaded"; config: SubstrateConfig }
  | { kind: "default"; config: SubstrateConfig }
  | { kind: "version-too-new"; persistedVersion: number; config: SubstrateConfig }
  | { kind: "corrupt"; config: SubstrateConfig };

export class IntelligenceConfigStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, HKDF_INFO);
  }

  /**
   * Load the operator's substrate config from disk. Returns the config
   * plus a discriminator describing the outcome; on first boot or after
   * a corrupt-record path the default config is returned and the caller
   * is responsible for emitting the right audit event.
   */
  async load(): Promise<LoadOutcome> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
    } catch {
      return { kind: "default", config: buildDefaultConfig() };
    }
    if (!raw) {
      return { kind: "default", config: buildDefaultConfig() };
    }

    let parsed: SubstrateConfig;
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      parsed = JSON.parse(bytesToString(decrypted)) as SubstrateConfig;
    } catch {
      return { kind: "corrupt", config: buildDefaultConfig() };
    }

    if (typeof parsed.version !== "number" || parsed.version < 1) {
      return { kind: "corrupt", config: buildDefaultConfig() };
    }
    if (parsed.version > 1) {
      return {
        kind: "version-too-new",
        persistedVersion: parsed.version,
        config: buildDefaultConfig(),
      };
    }

    return { kind: "loaded", config: parsed };
  }

  /**
   * Persist the operator's substrate config. Encrypts under the
   * fortress master key via the HKDF-derived purpose key.
   */
  async save(config: SubstrateConfig): Promise<void> {
    const stamped: SubstrateConfig = {
      ...config,
      updatedAt: new Date().toISOString(),
    };
    const serialized = stringToBytes(JSON.stringify(stamped));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      INTELLIGENCE_NAMESPACE,
      SUBSTRATE_CONFIG_KEY,
      stringToBytes(JSON.stringify(encrypted))
    );
  }

  /**
   * Remove the persisted config. The selector treats subsequent loads as
   * fresh and applies defaults. Used by `selector.resetToDefaults()`.
   */
  async clear(): Promise<void> {
    try {
      await this.storage.delete(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
    } catch {
      // Storage backend may not support delete on a non-existent key;
      // the selector tolerates this and proceeds with defaults.
    }
  }
}
