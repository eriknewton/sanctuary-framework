/**
 * Sanctuary Fortress Modes -- Config Persistence
 *
 * Per-fortress mode config load/save using the StorageBackend directly
 * with HKDF-derived encryption key (same pattern as ContextGatePolicyStore).
 * Stored in the _fortress_mode reserved namespace.
 *
 * Config is operator-sovereign: read on boot, never broadcast to the mesh.
 * The transition event (signed envelope) is what gets broadcast;
 * the config is the local ground truth.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import { deriveNamespaceKey } from "../core/key-derivation.js";
import type { ModeTier } from "./constants.js";
import {
  FORTRESS_MODE_NAMESPACE,
  FORTRESS_MODE_CONFIG_KEY,
  FORTRESS_MODE_HISTORY_KEY,
  HKDF_FORTRESS_MODE_INFO,
  TIER_CAPABILITY_DEFAULTS,
  MAX_TRANSITION_HISTORY,
} from "./constants.js";
import type {
  FortressModeConfig,
  TransitionHistory,
  TransitionHistoryEntry,
} from "./types.js";
import { FortressConfigError } from "./errors.js";

// ---------------------------------------------------------------------------
// FortressModeStore
// ---------------------------------------------------------------------------

export class FortressModeStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private cachedConfig: FortressModeConfig | null = null;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = deriveNamespaceKey(masterKey, HKDF_FORTRESS_MODE_INFO);
  }

  // -----------------------------------------------------------------------
  // Config read/write
  // -----------------------------------------------------------------------

  /**
   * Load the current fortress mode config from storage.
   * Returns null if no config exists yet (first boot).
   */
  async load(): Promise<FortressModeConfig | null> {
    if (this.cachedConfig) return this.cachedConfig;

    const raw = await this.storage.read(
      FORTRESS_MODE_NAMESPACE,
      FORTRESS_MODE_CONFIG_KEY
    );
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const config: FortressModeConfig = JSON.parse(bytesToString(decrypted));

      if (config.schema_version !== "1.0") {
        throw new FortressConfigError(
          `Unsupported fortress mode config schema version: ${config.schema_version}`
        );
      }

      this.cachedConfig = config;
      return config;
    } catch (err) {
      if (err instanceof FortressConfigError) throw err;
      throw new FortressConfigError(
        `Failed to decrypt/parse fortress mode config: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Save the fortress mode config to storage.
   */
  async save(config: FortressModeConfig): Promise<void> {
    const serialized = stringToBytes(JSON.stringify(config));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      FORTRESS_MODE_NAMESPACE,
      FORTRESS_MODE_CONFIG_KEY,
      stringToBytes(JSON.stringify(encrypted))
    );
    this.cachedConfig = config;
  }

  /**
   * Initialize a default config for a new fortress.
   * Defaults to Tier 1 Private (structural moat invariant: framework alone
   * is fully operational with zero external dependency).
   */
  async initialize(fortressId: string): Promise<FortressModeConfig> {
    const now = new Date().toISOString();
    const config: FortressModeConfig = {
      schema_version: "1.0",
      current_tier: "tier_1_private",
      fortress_id: fortressId,
      capability_bits: TIER_CAPABILITY_DEFAULTS.tier_1_private,
      last_transition_at: null,
      last_transition_event_id: null,
      created_at: now,
      updated_at: now,
    };
    await this.save(config);
    return config;
  }

  /**
   * Update the config after a successful mode transition.
   */
  async applyTransition(
    toTier: ModeTier,
    eventId: string,
    capabilityBits: number
  ): Promise<FortressModeConfig> {
    const config = await this.load();
    if (!config) {
      throw new FortressConfigError(
        "Cannot apply transition: no fortress mode config exists. Call initialize() first."
      );
    }

    const now = new Date().toISOString();
    const updated: FortressModeConfig = {
      ...config,
      current_tier: toTier,
      capability_bits: capabilityBits,
      last_transition_at: now,
      last_transition_event_id: eventId,
      updated_at: now,
    };

    await this.save(updated);
    return updated;
  }

  /**
   * Clear the cached config (e.g., after master key rotation).
   */
  clearCache(): void {
    this.cachedConfig = null;
  }

  // -----------------------------------------------------------------------
  // Transition history
  // -----------------------------------------------------------------------

  /**
   * Load the transition history from storage.
   * Returns an empty history if none exists.
   */
  async loadHistory(): Promise<TransitionHistory> {
    const raw = await this.storage.read(
      FORTRESS_MODE_NAMESPACE,
      FORTRESS_MODE_HISTORY_KEY
    );
    if (!raw) return { entries: [] };

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted)) as TransitionHistory;
    } catch {
      return { entries: [] };
    }
  }

  /**
   * Append a transition to the history log, trimming oldest
   * entries if the log exceeds MAX_TRANSITION_HISTORY.
   */
  async appendHistory(entry: TransitionHistoryEntry): Promise<void> {
    const history = await this.loadHistory();
    history.entries.push(entry);

    if (history.entries.length > MAX_TRANSITION_HISTORY) {
      history.entries = history.entries.slice(-MAX_TRANSITION_HISTORY);
    }

    const serialized = stringToBytes(JSON.stringify(history));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      FORTRESS_MODE_NAMESPACE,
      FORTRESS_MODE_HISTORY_KEY,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
}
