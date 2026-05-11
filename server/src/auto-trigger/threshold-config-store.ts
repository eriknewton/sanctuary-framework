/**
 * Sanctuary v1.3 WP-V1.3-7 Nu-1 Auto-Trigger threshold config store.
 *
 * Encrypted at-rest persistence for per-rule threshold + rung config.
 * Mirrors the Chi-1 ClassifierStateStore pattern: HKDF subkey derived
 * from fortress master, AAD-bound per (rule_id, fortress_id) tuple
 * so two fortresses never produce identical ciphertext for the same
 * rule_id.
 *
 * Storage layout:
 *   namespace: `_auto_trigger_rules`
 *   key:       `rule.{rule_id}`
 *   payload:   AES-256-GCM ciphertext of the JSON-serialized config.
 *   key (HKDF):`l2-auto-trigger-rules-v1` subkey of fortress master.
 *   AAD:       UTF-8 bytes of `{rule_id}|{fortress_id}`.
 *
 * Sovereignty invariant: state never leaves the fortress. No outbound
 * surface. Operator may inspect or delete via the standard storage
 * tools or `sanctuary auto-trigger rules ...` CLI.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

import {
  appendHistory,
  defaultRuleConfig,
  AutoTriggerError,
  type ActionHistoryEntry,
  type AutoTriggerRuleType,
  type AutoTriggerRung,
  type RuleThresholdConfig,
  type ThresholdOverrides,
} from "./types.js";

export const AUTO_TRIGGER_RULES_NAMESPACE = "_auto_trigger_rules";
export const AUTO_TRIGGER_RULE_KEY_PREFIX = "rule.";
const HKDF_INFO = "l2-auto-trigger-rules-v1";

/** Hard upper bound on per-record decode size; defends against malformed input. */
const MAX_RULE_BYTES = 256 * 1024;

/** Persistence envelope; versioned for forward-compat. */
interface PersistedRule {
  version: 1;
  rule_id: string;
  fortress_id: string;
  saved_at: string;
  config: RuleThresholdConfig;
}

export interface ThresholdConfigStoreOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  /** Wall-clock provider; tests inject a deterministic clock. */
  now?: () => Date;
}

/**
 * Per-fortress threshold-config store. One instance per fortress; all
 * writes are AAD-bound to (rule_id, fortress_id).
 */
export class ThresholdConfigStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly now: () => Date;

  constructor(opts: ThresholdConfigStoreOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
    this.now = opts.now ?? (() => new Date());
  }

  /** Read a rule config. Returns null when absent. */
  async get(ruleId: string): Promise<RuleThresholdConfig | null> {
    const key = ruleStorageKey(ruleId);
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(AUTO_TRIGGER_RULES_NAMESPACE, key);
    } catch {
      return null;
    }
    if (!raw) return null;
    if (raw.length > MAX_RULE_BYTES) return null;
    try {
      const aad = stringToBytes(aadFor(ruleId, this.fortressId));
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const persisted = JSON.parse(
        bytesToString(plaintext),
      ) as PersistedRule;
      if (persisted.version !== 1) return null;
      if (persisted.rule_id !== ruleId) return null;
      if (persisted.fortress_id !== this.fortressId) return null;
      return persisted.config;
    } catch {
      return null;
    }
  }

  /**
   * Read a rule config, creating a fresh Rung-1 default if absent. The
   * default is persisted on first access so the dispatcher sees a
   * consistent shape on subsequent reads.
   */
  async getOrInit(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
  ): Promise<RuleThresholdConfig> {
    const existing = await this.get(ruleId);
    if (existing) return existing;
    const fresh = defaultRuleConfig(
      ruleId,
      ruleType,
      this.fortressId,
      this.now,
    );
    await this.set(fresh);
    return fresh;
  }

  /** Persist a rule config. AAD-binds to (rule_id, fortress_id). */
  async set(config: RuleThresholdConfig): Promise<void> {
    if (config.fortress_id !== this.fortressId) {
      throw new Error(
        `ThresholdConfigStore: fortress_id mismatch (got ${config.fortress_id}, store bound to ${this.fortressId})`,
      );
    }
    const persisted: PersistedRule = {
      version: 1,
      rule_id: config.rule_id,
      fortress_id: this.fortressId,
      saved_at: this.now().toISOString(),
      config: {
        ...config,
        updated_at: this.now().toISOString(),
      },
    };
    const aad = stringToBytes(aadFor(config.rule_id, this.fortressId));
    const plaintext = stringToBytes(JSON.stringify(persisted));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      AUTO_TRIGGER_RULES_NAMESPACE,
      ruleStorageKey(config.rule_id),
      stringToBytes(JSON.stringify(envelope)),
    );
  }

  /** Promote a rule one rung up. Throws on ceiling (rung 3). */
  async promote(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
  ): Promise<RuleThresholdConfig> {
    const config = await this.getOrInit(ruleId, ruleType);
    if (config.current_rung >= 3) {
      throw new AutoTriggerError(
        `rule ${ruleId} already at rung 3 (ceiling)`,
        "rung_ceiling",
      );
    }
    const next: RuleThresholdConfig = {
      ...config,
      current_rung: (config.current_rung + 1) as AutoTriggerRung,
      last_promoted_at: this.now().toISOString(),
    };
    await this.set(next);
    return next;
  }

  /** Demote a rule one rung down. Throws on floor (rung 1). */
  async demote(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
  ): Promise<RuleThresholdConfig> {
    const config = await this.getOrInit(ruleId, ruleType);
    if (config.current_rung <= 1) {
      throw new AutoTriggerError(
        `rule ${ruleId} already at rung 1 (floor)`,
        "rung_floor",
      );
    }
    const next: RuleThresholdConfig = {
      ...config,
      current_rung: (config.current_rung - 1) as AutoTriggerRung,
      last_demoted_at: this.now().toISOString(),
    };
    await this.set(next);
    return next;
  }

  /** Patch the threshold overrides + optional cancel-window. */
  async updateConfig(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
    patch: {
      threshold_overrides?: ThresholdOverrides;
      cancel_window_seconds?: number;
    },
  ): Promise<RuleThresholdConfig> {
    const config = await this.getOrInit(ruleId, ruleType);
    const next: RuleThresholdConfig = {
      ...config,
      threshold_overrides:
        patch.threshold_overrides ?? config.threshold_overrides,
      cancel_window_seconds:
        patch.cancel_window_seconds ?? config.cancel_window_seconds,
    };
    await this.set(next);
    return next;
  }

  /**
   * Append an action history entry. Bounded ring buffer (max 200 per
   * rule); oldest entries drop.
   */
  async recordAction(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
    entry: ActionHistoryEntry,
  ): Promise<RuleThresholdConfig> {
    const config = await this.getOrInit(ruleId, ruleType);
    const next: RuleThresholdConfig = {
      ...config,
      history: appendHistory(config.history, entry),
    };
    await this.set(next);
    return next;
  }

  /**
   * Update the outcome of a specific pending history entry (e.g. when a
   * cancel-window expires or the operator cancels). Identified by
   * finding_id. No-op when the entry is absent. Returns the updated
   * config; the matched entry's outcome is replaced.
   */
  async updateActionOutcome(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
    findingId: string,
    outcome: ActionHistoryEntry["outcome"],
  ): Promise<RuleThresholdConfig> {
    const config = await this.getOrInit(ruleId, ruleType);
    const idx = config.history.findIndex((h) => h.finding_id === findingId);
    if (idx < 0) return config;
    const updatedHistory = [...config.history];
    updatedHistory[idx] = { ...updatedHistory[idx]!, outcome };
    const next: RuleThresholdConfig = { ...config, history: updatedHistory };
    await this.set(next);
    return next;
  }

  /** Delete a rule config (and its history) by id. */
  async delete(ruleId: string): Promise<boolean> {
    const key = ruleStorageKey(ruleId);
    const exists = await this.storage.exists(
      AUTO_TRIGGER_RULES_NAMESPACE,
      key,
    );
    if (!exists) return false;
    try {
      await this.storage.delete(AUTO_TRIGGER_RULES_NAMESPACE, key);
    } catch {
      return false;
    }
    return true;
  }

  /** Enumerate every rule id persisted for this fortress. */
  async listRuleIds(): Promise<string[]> {
    const metas = await this.storage.list(
      AUTO_TRIGGER_RULES_NAMESPACE,
      AUTO_TRIGGER_RULE_KEY_PREFIX,
    );
    const out: string[] = [];
    for (const meta of metas) {
      if (!meta.key.startsWith(AUTO_TRIGGER_RULE_KEY_PREFIX)) continue;
      out.push(meta.key.slice(AUTO_TRIGGER_RULE_KEY_PREFIX.length));
    }
    return out;
  }
}

function ruleStorageKey(ruleId: string): string {
  return `${AUTO_TRIGGER_RULE_KEY_PREFIX}${ruleId}`;
}

function aadFor(ruleId: string, fortressId: string): string {
  return `${ruleId}|${fortressId}`;
}
