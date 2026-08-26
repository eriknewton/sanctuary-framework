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
 * Version 1 remains the legacy-unarmed shape. Version 2 is created only by
 * the injected Q5 provisioning commit and must carry one complete, reverified
 * `LocalIntegrityStateV2`; a partial V2 is never salvaged as legacy.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import { parseStrictJson } from "../substrate/strict-json.js";
import { buildDefaultConfig } from "./defaults.js";
import {
  loadPinnedModelManifestKey,
} from "./model-manifest.js";
import {
  validateLocalIntegrityStateV2,
  type ModelManifestV2RefusalReason,
} from "./model-manifest-v2.js";
import {
  SURFACES,
  isTier2PinViolation,
  type SubstrateConfig,
  type SubstrateConfigV2,
} from "./types.js";

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
  | {
    kind: "integrity-state-invalid";
    reason: ModelManifestV2RefusalReason;
    config: SubstrateConfig;
  }
  | { kind: "corrupt"; config: SubstrateConfig };

export class LocalIntegrityStateLoadError extends Error {
  constructor(readonly reason: ModelManifestV2RefusalReason) {
    super(`Q5 integrity state refused: ${reason}`);
    this.name = "LocalIntegrityStateLoadError";
  }
}

export interface IntelligenceConfigStoreOptions {
  /** Test/fixture seam; production uses the pinned release key. */
  modelManifestV2PublicKey?: Uint8Array;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function configBindingsMatch(config: SubstrateConfigV2): boolean {
  if (
    !isRecord(config.perSurface) ||
    (config.customLocalModelTags !== undefined &&
      !isRecord(config.customLocalModelTags))
  ) {
    return false;
  }
  const bindings = config.localIntegrityState.bindings;
  for (const surface of SURFACES) {
    const configured = config.perSurface[surface];
    const isLocal = configured === "local" || isTier2PinViolation(surface, configured);
    const binding = bindings[surface];
    if (isLocal) {
      if (
        binding === undefined ||
        config.customLocalModelTags?.[surface] !== binding.runtime_tag
      ) {
        return false;
      }
    } else if (binding !== undefined) {
      return false;
    }
  }
  return true;
}

export class IntelligenceConfigStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private modelManifestV2PublicKey: Uint8Array | null;

  constructor(
    storage: StorageBackend,
    masterKey: Uint8Array,
    options: IntelligenceConfigStoreOptions = {},
  ) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, HKDF_INFO);
    this.modelManifestV2PublicKey =
      options.modelManifestV2PublicKey ?? loadPinnedModelManifestKey();
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

    let parsedValue: unknown;
    try {
      const encrypted = parseStrictJson(bytesToString(raw)) as EncryptedPayload;
      const decrypted = decrypt(encrypted, this.encryptionKey);
      parsedValue = parseStrictJson(bytesToString(decrypted));
    } catch {
      return { kind: "corrupt", config: buildDefaultConfig() };
    }

    if (!isRecord(parsedValue) || typeof parsedValue.version !== "number" || parsedValue.version < 1) {
      return { kind: "corrupt", config: buildDefaultConfig() };
    }
    if (parsedValue.version !== 1 && parsedValue.version !== 2) {
      if (parsedValue.version <= 1) {
        return { kind: "corrupt", config: buildDefaultConfig() };
      }
      return {
        kind: "version-too-new",
        persistedVersion: parsedValue.version,
        config: buildDefaultConfig(),
      };
    }

    if (parsedValue.version === 2) {
      if (this.modelManifestV2PublicKey === null) {
        return {
          kind: "integrity-state-invalid",
          reason: "integrity_state_invalid",
          config: buildDefaultConfig(),
        };
      }
      const validated = validateLocalIntegrityStateV2(
        parsedValue.localIntegrityState,
        this.modelManifestV2PublicKey,
      );
      if (!validated.ok) {
        return {
          kind: "integrity-state-invalid",
          reason: validated.reason,
          config: buildDefaultConfig(),
        };
      }
      const config = {
        ...parsedValue,
        version: 2,
        localIntegrityState: validated.state,
      } as unknown as SubstrateConfigV2;
      // The config/runtime-tag projection and Q5 bindings are one authority;
      // accepting only one side would recreate the mixed-field state Q5D closes.
      if (!configBindingsMatch(config)) {
        return {
          kind: "integrity-state-invalid",
          reason: "binding_mismatch",
          config: buildDefaultConfig(),
        };
      }
      return { kind: "loaded", config };
    }

    return { kind: "loaded", config: parsedValue as unknown as SubstrateConfig };
  }

  /**
   * Persist the operator's substrate config. Encrypts under the
   * fortress master key via the HKDF-derived purpose key.
   */
  async save(config: SubstrateConfig): Promise<SubstrateConfig> {
    const stamped: SubstrateConfig = {
      ...config,
      updatedAt: new Date().toISOString(),
    };
    if (stamped.version === 2) {
      if (this.modelManifestV2PublicKey === null) {
        throw new LocalIntegrityStateLoadError("integrity_state_invalid");
      }
      const validated = validateLocalIntegrityStateV2(
        stamped.localIntegrityState,
        this.modelManifestV2PublicKey,
      );
      if (!validated.ok) throw new LocalIntegrityStateLoadError(validated.reason);
      if (!configBindingsMatch({ ...stamped, localIntegrityState: validated.state })) {
        throw new LocalIntegrityStateLoadError("binding_mismatch");
      }
    }
    const serialized = stringToBytes(JSON.stringify(stamped));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      INTELLIGENCE_NAMESPACE,
      SUBSTRATE_CONFIG_KEY,
      stringToBytes(JSON.stringify(encrypted))
    );
    return stamped;
  }

  /**
   * Remove a legacy-unarmed persisted config. Armed/indeterminate records
   * require a future reviewed reset ceremony and are never cleared here.
   */
  async clear(): Promise<void> {
    const current = await this.load();
    // Deleting an armed or unreadable record could silently manufacture
    // legacy-unarmed state; Q5 has no reviewed disarm/reset ceremony.
    if (current.kind === "integrity-state-invalid" || current.config.version === 2) {
      throw new LocalIntegrityStateLoadError(
        current.kind === "integrity-state-invalid"
          ? current.reason
          : "integrity_state_invalid",
      );
    }
    try {
      await this.storage.delete(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
    } catch {
      // Storage backend may not support delete on a non-existent key;
      // the selector tolerates this and proceeds with defaults.
    }
  }
}
