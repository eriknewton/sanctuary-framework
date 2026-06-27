/**
 * Sanctuary WP-V1.x-QUERY-LAYER-ANONYMITY Rho-2 Tier B config store.
 *
 * Per-fortress, encrypted-at-rest store for the Tier B PII rewrite
 * operator toggle.
 *
 * Shape:
 *   - `enabled` (boolean, default FALSE). When true, every
 *     substrate-selector call in this fortress is routed through
 *     `rewritePiiWithLlm` before invocation.
 *   - `consented_to_trade_off` (boolean, default FALSE). Set to true
 *     by the patch route after the operator acknowledges the
 *     trade-off explainer. The route refuses to flip `enabled = true`
 *     unless this is already true (or set in the same patch).
 *   - `consented_at` (ISO timestamp, optional). Set when consent
 *     first recorded; never cleared.
 *   - `last_toggled_at` (ISO timestamp, optional). Tracks the most
 *     recent `enabled` flip in either direction.
 *   - `smart_mode_enabled` (boolean, default FALSE). Rho-3 extension:
 *     when true, Tier B is effective even if the basic `enabled` flag
 *     is false, because smart mode depends on the Tier B rewrite.
 *
 * Storage layout:
 *   namespace: `_query_anonymity_tier_b`
 *   key:       `config`
 *   payload:   AES-256-GCM ciphertext of the JSON-serialized config.
 *   HKDF info: `l2-query-anonymity-tier-b-v1`
 *   AAD:       UTF-8 bytes of the fortress id.
 *
 * Sovereignty invariant: per-fortress AAD binding ensures two
 * fortresses sharing storage never decode each other's config.
 * Mirrors the Nu-1 ThresholdConfigStore + Chi-1 ClassifierStateStore
 * patterns exactly.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

export const TIER_B_NAMESPACE = "_query_anonymity_tier_b";
export const TIER_B_CONFIG_KEY = "config";
const HKDF_INFO = "l2-query-anonymity-tier-b-v1";
const MAX_PAYLOAD_BYTES = 16 * 1024;

/**
 * Operator-overridable per-fortress config. Default values represent
 * "Tier B has never been touched on this fortress": OFF, no consent
 * recorded.
 */
export interface PiiRewriteConfig {
  /** Master toggle. Default false. */
  enabled: boolean;
  /** Rho-3 smart mode toggle. Default false; implies effective Tier B. */
  smart_mode_enabled: boolean;
  /** Operator acknowledged the trade-off explainer. Default false. */
  consented_to_trade_off: boolean;
  /** ISO timestamp of first consent. Set once; never overwritten. */
  consented_at?: string;
  /** ISO timestamp of the most recent `enabled` flip. */
  last_toggled_at?: string;
  /** ISO timestamp of the last config write (any field). */
  updated_at: string;
}

export interface PiiConfigStoreOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
}

/**
 * Result of `PiiConfigStore.patch()`. Carries the updated config plus
 * an EXPLICIT consent-transition signal so callers (the route's audit
 * emission) never have to infer the false->true consent flip from
 * timestamp comparisons.
 */
export interface PiiPatchResult {
  /** The merged + persisted config after the patch. */
  config: PiiRewriteConfig;
  /**
   * True iff this patch recorded consent for the first time (the
   * `consented_to_trade_off` false->true transition). False on a
   * no-op re-PATCH where consent was already true, on a true->false
   * revocation, and on any patch that does not flip consent on.
   */
  consentJustRecorded: boolean;
}

interface PersistedConfig {
  version: 1;
  fortress_id: string;
  saved_at: string;
  config: PiiRewriteConfig;
}

/**
 * Build the canonical default config. Default-off, no consent yet.
 * Exposed so the route layer can return it on first-read without a
 * round-trip through the encrypted store.
 */
export function defaultPiiRewriteConfig(
  now: () => Date = () => new Date(),
): PiiRewriteConfig {
  return {
    enabled: false,
    smart_mode_enabled: false,
    consented_to_trade_off: false,
    updated_at: now().toISOString(),
  };
}

export class PiiConfigStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly now: () => Date;

  constructor(opts: PiiConfigStoreOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
    this.now = opts.now ?? (() => new Date());
  }

  /**
   * Read the persisted config. Returns the canonical default when
   * the fortress has never set one. Returns null only on decode
   * failure (corrupt payload, wrong fortress, version mismatch).
   */
  async get(): Promise<PiiRewriteConfig | null> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(TIER_B_NAMESPACE, TIER_B_CONFIG_KEY);
    } catch {
      return defaultPiiRewriteConfig(this.now);
    }
    if (!raw) return defaultPiiRewriteConfig(this.now);
    if (raw.length > MAX_PAYLOAD_BYTES) return null;
    try {
      const aad = stringToBytes(this.fortressId);
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const persisted = JSON.parse(bytesToString(plaintext)) as PersistedConfig;
      if (persisted.version !== 1) return null;
      if (persisted.fortress_id !== this.fortressId) return null;
      return {
        ...defaultPiiRewriteConfig(this.now),
        ...persisted.config,
        smart_mode_enabled: persisted.config.smart_mode_enabled ?? false,
      };
    } catch {
      return null;
    }
  }

  /**
   * Write the config. AAD-binds to the fortress id. Caller is
   * responsible for setting `updated_at` (or letting `patch` do it).
   */
  async set(config: PiiRewriteConfig): Promise<void> {
    const persisted: PersistedConfig = {
      version: 1,
      fortress_id: this.fortressId,
      saved_at: this.now().toISOString(),
      config: {
        ...config,
        updated_at: this.now().toISOString(),
      },
    };
    const aad = stringToBytes(this.fortressId);
    const plaintext = stringToBytes(JSON.stringify(persisted));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      TIER_B_NAMESPACE,
      TIER_B_CONFIG_KEY,
      stringToBytes(JSON.stringify(envelope)),
    );
  }

  /**
   * Apply a partial patch. Refuses to flip `enabled = true` unless
   * `consented_to_trade_off` is true (in the merged result). On
   * consent-flip transitions to true, stamps `consented_at` if not
   * already set. On any `enabled` flip, stamps `last_toggled_at`.
   *
   * Returns the updated config plus an explicit `consentJustRecorded`
   * signal: true iff this patch flipped `consented_to_trade_off` from
   * false to true. The signal is computed from state (the merged
   * patch vs the existing record), NOT from comparing timestamps, so
   * audit emission keyed on it is deterministic regardless of how the
   * wall clock samples.
   *
   * Throws `PiiConsentRequired` when the caller asked for
   * `enabled = true` but `consented_to_trade_off` would not also be
   * true post-patch.
   */
  async patch(patch: Partial<PiiRewriteConfig>): Promise<PiiPatchResult> {
    const existing =
      (await this.get()) ?? defaultPiiRewriteConfig(this.now);
    const merged: PiiRewriteConfig = {
      ...existing,
      ...patch,
      updated_at: this.now().toISOString(),
    };
    if (
      (merged.enabled || merged.smart_mode_enabled) &&
      !merged.consented_to_trade_off
    ) {
      throw new PiiConsentRequired(
        "cannot enable Tier B without consent_to_trade_off=true",
      );
    }
    // Explicit false->true consent transition, derived from state.
    const consentJustRecorded =
      patch.consented_to_trade_off === true &&
      !existing.consented_to_trade_off;
    if (consentJustRecorded) {
      merged.consented_at = this.now().toISOString();
    }
    if (
      (patch.enabled !== undefined && patch.enabled !== existing.enabled) ||
      (patch.smart_mode_enabled !== undefined &&
        patch.smart_mode_enabled !== existing.smart_mode_enabled)
    ) {
      merged.last_toggled_at = this.now().toISOString();
    }
    await this.set(merged);
    return { config: merged, consentJustRecorded };
  }

  /**
   * Whether Tier B should fire for THIS call. Combines the
   * per-fortress flag with an optional per-query override.
   *
   * Per-query semantics:
   *   - `undefined`: defer to fortress config.
   *   - `true`: force-on (still requires consent). Throws if consent
   *     not recorded.
   *   - `false`: force-off (operator opting out of a specific call).
   */
  async shouldRewrite(perQueryOverride?: boolean): Promise<boolean> {
    if (perQueryOverride === false) return false;
    const config = await this.get();
    if (!config) return false;
    if (perQueryOverride === true) {
      if (!config.consented_to_trade_off) {
        throw new PiiConsentRequired(
          "per-query opt-in requires recorded consent",
        );
      }
      return true;
    }
    return config.enabled || config.smart_mode_enabled;
  }

  /**
   * Whether Rho-3 smart mode should fire for this call. Smart mode is
   * default-off, and enabling it implies effective Tier B for the
   * query path while keeping the persisted basic toggle independent.
   */
  async shouldRewriteSmartMode(perQueryOverride?: boolean): Promise<boolean> {
    if (perQueryOverride === false) return false;
    const config = await this.get();
    if (!config) return false;
    if (perQueryOverride === true) {
      if (!config.consented_to_trade_off) {
        throw new PiiConsentRequired(
          "per-query smart-mode opt-in requires recorded consent",
        );
      }
      return true;
    }
    return config.smart_mode_enabled;
  }
}

/** Raised when consent has not been recorded but enable is requested. */
export class PiiConsentRequired extends Error {
  readonly code = "consent_required" as const;
  constructor(message: string) {
    super(message);
    this.name = "PiiConsentRequired";
  }
}
