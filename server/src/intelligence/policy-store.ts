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
 *
 * Unreadable durable records (Q5E residual 2):
 * A record that does not decrypt or parse (`corrupt`) or that carries a
 * version this build does not know (`version-too-new`) fails EVERY config
 * write closed with `IntelligenceConfigUnreadableError`, whose message names
 * the one recovery verb. That verb calls `quarantineUnreadable()`, which
 * copies the raw bytes to a timestamped sidecar file beside the record (a
 * plain file, never a `.enc` entry, so namespace enumeration and master
 * rotation skip it) and only then removes the record. An "empty V2" cannot
 * exist (V2 by contract carries a complete verified integrity state), so the
 * reinitialized state is the ABSENT record, which `load()` reads as the
 * default legacy-unarmed config. Readable records, armed or legacy, are never
 * quarantined; an armed record that fails Q5 validation is an integrity
 * refusal, not an unreadable record, and has no in-product disarm.
 */

import type {
  FilesystemStorageCapabilities,
  StorageBackend,
} from "../storage/interface.js";
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
  type ModelLoadIntegrityFailureReason,
  type ModelManifestV2RefusalReason,
} from "./model-manifest-v2.js";
import {
  SURFACES,
  isTier2PinViolation,
  type SubstrateConfig,
  type SubstrateConfigV2,
  type Surface,
} from "./types.js";
import { LOCAL_INTELLIGENCE_OPT_IN_HINT } from "./provisioning-consent.js";
import {
  withCrossProcessLock,
  type CrossProcessLockOptions,
} from "../storage/cross-process-lock.js";
import { writeFileCustody } from "../storage/custody-fs.js";
import { stat } from "node:fs/promises";
import { join } from "node:path";

export const INTELLIGENCE_NAMESPACE = "_intelligence";
export const SUBSTRATE_CONFIG_KEY = "substrate-config";
/** Distinct from the provisioning lock: every config writer shares this save chokepoint. */
export const Q5_CONFIG_SAVE_LOCK_FILE = ".q5-config-save.lock";
const HKDF_INFO = "intelligence-substrate-config";
/**
 * The one operator verb that recovers an unreadable durable record. Must match
 * the `config-reset` subcommand and help text in `cli/intelligence.ts`; the
 * typed refusal below quotes it so the remedy travels with the error.
 */
export const INTELLIGENCE_CONFIG_RESET_VERB = "sanctuary intelligence config-reset";
/**
 * Sidecar file prefix for quarantined record bytes. The full name is
 * `<prefix><UTC stamp>.bin`, deliberately NOT ending in `.enc`: it must stay
 * outside the `.enc` filter in `storage/filesystem.ts list()` so namespace
 * enumeration and the master-rotation walk never try to decrypt it.
 */
export const SUBSTRATE_CONFIG_QUARANTINE_PREFIX = "substrate-config.quarantine.";
const QUARANTINE_FILE_SUFFIX = ".bin";
/** 0o600: the quarantined ciphertext keeps the record's owner-only custody. */
const QUARANTINE_FILE_MODE = 0o600;

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
    reason: ModelLoadIntegrityFailureReason;
    /**
     * Convenience defaults only, never a reinterpretation of the invalid
     * durable V2 record as legacy-unarmed authority. Callers must branch on
     * `kind` before consuming this field; security-sensitive reads use
     * `loadAuthoritative()` and throw instead.
     */
    config: SubstrateConfig;
  }
  | { kind: "corrupt"; config: SubstrateConfig };

/**
 * A load classified for an OPERATOR DIAGNOSTIC rather than for the boot path.
 *
 * It adds the one distinction {@link IntelligenceConfigStore.load} deliberately
 * collapses: `load()` treats ANY storage read failure as a fresh fortress so a
 * first boot proceeds, which is right for booting and wrong for reporting,
 * because an EACCES or an I/O error on an EXISTING record would then be
 * announced as "no durable record exists" together with a set-it-up remedy.
 * Absent and indeterminate are different answers and neither may be rendered
 * as the other (AGENTS.md assurance rule 1).
 */
export type DiagnosticLoadOutcome =
  | LoadOutcome
  | { kind: "read-failed" };

/**
 * The operator-visible name for each durable-record state. The classifier
 * consumes the runtime's own {@link LoadOutcome} branch rather than re-deriving
 * a verdict from the bytes, because a diagnostic that re-parses the record can
 * disagree with the selector about whether this fortress is armed.
 *
 * The mapping is one state per branch with ONE deliberate exception: a
 * `loaded` record splits by what the selector would do with it (a V1 record is
 * `legacy-unarmed`; a V2 record with no verified binding is refused surface by
 * surface and so reports `integrity_state_invalid`, never `armed`).
 */
export type LocalIntelligenceArmedState =
  | "armed"
  | "legacy-unarmed"
  | "absent"
  | "integrity_state_invalid"
  | "corrupt"
  | "version-too-new"
  /** The record store itself could not be read, so the answer is indeterminate. */
  | "storage_unreadable";

/** One armed surface binding, flattened for display. Public manifest data only. */
export interface LocalIntelligenceBindingReport {
  surface: Surface;
  model_id: string;
  runtime_tag: string;
  /** The signed Ollama manifest root this binding was verified against. */
  ollama_manifest_sha256: string;
  assurance: string;
}

/**
 * What an operator surface may say about the durable record. Every field is
 * either public manifest content or a local path; a master key, a passphrase,
 * and the record's plaintext operator credentials never appear here.
 */
export interface LocalIntelligenceStateReport {
  state: LocalIntelligenceArmedState;
  /** Closed reason for a non-armed state, or null when there is nothing to add. */
  detail: string | null;
  manifest_version: number | null;
  signed_body_sha256: string | null;
  ollama_models_root: string | null;
  committed_at: string | null;
  bindings: readonly LocalIntelligenceBindingReport[];
  /** The operator action that changes this state, or null when none applies. */
  remedy: string | null;
}

/**
 * The fields a non-armed report leaves empty. Declared once so every branch
 * below is a single object literal and no branch can forget to null a field it
 * has no evidence for.
 */
const EMPTY_LOCAL_INTELLIGENCE_REPORT_FIELDS = {
  detail: null,
  manifest_version: null,
  signed_body_sha256: null,
  ollama_models_root: null,
  committed_at: null,
  bindings: [] as readonly LocalIntelligenceBindingReport[],
} as const;

/**
 * Classify a durable-record load for display. Consumes the SAME
 * {@link LoadOutcome} the selector and every config writer consume, so an
 * operator report cannot claim a fortress is armed when the runtime refuses it.
 * One branch per {@link LoadOutcome} kind; the `loaded` kind delegates to
 * {@link classifyLoadedRecord} rather than nesting a second discriminator here.
 */
export function classifyLocalIntelligenceState(
  outcome: DiagnosticLoadOutcome,
): LocalIntelligenceStateReport {
  switch (outcome.kind) {
    case "read-failed":
      return {
        ...EMPTY_LOCAL_INTELLIGENCE_REPORT_FIELDS,
        state: "storage_unreadable",
        // Deliberately generic: the underlying storage error can carry the
        // fortress path and an OS string, and neither belongs in a report a
        // caller may forward. Whether a record exists is unknown here, so this
        // branch claims neither presence nor absence.
        detail:
          "the durable record store could not be read from this host, so whether a record exists is indeterminate",
        remedy:
          "check that this user can read the fortress state directory, then re-run",
      };
    case "default":
      return {
        ...EMPTY_LOCAL_INTELLIGENCE_REPORT_FIELDS,
        state: "absent",
        detail: "no durable local-intelligence config record exists",
        remedy: LOCAL_INTELLIGENCE_OPT_IN_HINT,
      };
    case "loaded":
      return classifyLoadedRecord(outcome.config);
    case "integrity-state-invalid":
      return {
        ...EMPTY_LOCAL_INTELLIGENCE_REPORT_FIELDS,
        state: "integrity_state_invalid",
        detail:
          `the armed record failed Q5 integrity validation (${outcome.reason}); ` +
          "there is no in-product recovery for this state today",
        // INVARIANT: no remedy is offered because none exists. `config-reset`
        // refuses this state ("not an unreadable record, and there is no
        // in-product disarm"), and re-running the ceremony cannot write over it
        // either: every config write goes through `saveWhileLocked`, whose
        // `loadAuthoritative()` read throws `LocalIntegrityStateLoadError` on
        // exactly this record. Naming either verb here would send the operator
        // in a loop between two refusals.
        remedy: null,
      };
    case "corrupt":
      return {
        ...EMPTY_LOCAL_INTELLIGENCE_REPORT_FIELDS,
        state: "corrupt",
        detail: "the durable record does not decrypt or parse",
        remedy: `run "${INTELLIGENCE_CONFIG_RESET_VERB}"`,
      };
    case "version-too-new":
      return {
        ...EMPTY_LOCAL_INTELLIGENCE_REPORT_FIELDS,
        state: "version-too-new",
        detail:
          `the durable record is version ${outcome.persistedVersion}, newer than this build supports`,
        remedy: `run "${INTELLIGENCE_CONFIG_RESET_VERB}"`,
      };
  }
}

/**
 * Classify a readable record by what the SELECTOR would do with it, which is
 * the only reading that cannot disagree with the runtime.
 */
function classifyLoadedRecord(
  config: SubstrateConfig,
): LocalIntelligenceStateReport {
  if (config.version !== 2) {
    return {
      ...EMPTY_LOCAL_INTELLIGENCE_REPORT_FIELDS,
      state: "legacy-unarmed",
      detail: "a readable record exists but carries no verified model binding",
      remedy: LOCAL_INTELLIGENCE_OPT_IN_HINT,
    };
  }
  const integrity = config.localIntegrityState;
  const bindings: LocalIntelligenceBindingReport[] = [];
  for (const surface of SURFACES) {
    const binding = integrity.bindings[surface];
    if (binding === undefined) continue;
    bindings.push({
      surface,
      model_id: binding.model_id,
      runtime_tag: binding.runtime_tag,
      ollama_manifest_sha256: binding.ollama_identity.ollama_manifest_sha256,
      assurance: binding.assurance,
    });
  }
  if (bindings.length === 0) {
    // INVARIANT: `armed` means at least one surface has a verified binding the
    // selector will honor. A V2 record with an empty binding set makes
    // `gatedLocalHandle` refuse EVERY local surface with `integrity_state_invalid`,
    // so reporting `armed` here would be the diagnostic contradicting the
    // runtime — the exact disagreement this classifier exists to prevent.
    return {
      ...EMPTY_LOCAL_INTELLIGENCE_REPORT_FIELDS,
      state: "integrity_state_invalid",
      detail:
        "the record carries no verified model binding, so every local surface refuses",
      remedy: LOCAL_INTELLIGENCE_OPT_IN_HINT,
    };
  }
  return {
    state: "armed",
    detail: null,
    manifest_version: integrity.manifest_version_floor,
    signed_body_sha256: integrity.signed_body_sha256,
    ollama_models_root: integrity.ollama_models_root,
    committed_at: integrity.committed_at,
    bindings,
    remedy: null,
  };
}

export class LocalIntegrityStateLoadError extends Error {
  constructor(
    readonly reason: ModelLoadIntegrityFailureReason,
  ) {
    super(`Q5 integrity state refused: ${reason}`);
    this.name = "LocalIntegrityStateLoadError";
  }
}

/** The two durable-record shapes no writer may reinterpret and no reader can use. */
export type UnreadableConfigKind = "corrupt" | "version-too-new";

/**
 * A durable record exists but cannot be consumed by this build. Extends the
 * closed Q5 refusal (reason stays `integrity_state_invalid`, so provisioning's
 * refusal taxonomy is unchanged) and adds the remedy: every write fails closed
 * until the operator runs {@link INTELLIGENCE_CONFIG_RESET_VERB}.
 */
export class IntelligenceConfigUnreadableError extends LocalIntegrityStateLoadError {
  readonly remedy: string;

  constructor(
    readonly kind: UnreadableConfigKind,
    /** Present only for `version-too-new`; a corrupt record has no trusted version. */
    readonly persistedVersion: number | null = null,
  ) {
    super("integrity_state_invalid");
    this.name = "IntelligenceConfigUnreadableError";
    this.remedy =
      `run "${INTELLIGENCE_CONFIG_RESET_VERB}" to quarantine the unreadable record ` +
      "and reinitialize local-intelligence config to the default legacy-unarmed state " +
      "(a fortress armed on that record is unarmed until re-provisioned)";
    const shape = kind === "version-too-new"
      ? `version ${persistedVersion} is newer than this build supports`
      : "the record does not decrypt or parse";
    this.message =
      `Q5 integrity state refused: integrity_state_invalid (durable config is ${kind}: ` +
      `${shape}; ${this.remedy})`;
  }
}

/** Result of {@link IntelligenceConfigStore.quarantineUnreadable}. */
export type QuarantineOutcome =
  | {
    kind: "quarantined";
    persisted: UnreadableConfigKind;
    persistedVersion: number | null;
    /** Sidecar file name inside the `_intelligence` namespace directory. */
    quarantineFile: string;
    /** Absolute sidecar path, for the operator-facing report. */
    quarantinePath: string;
    bytes: number;
  }
  | { kind: "absent" }
  | {
    kind: "refused";
    reason:
      /** The record loads; quarantining it would discard live operator state. */
      | "readable"
      /** An armed V2 record failed Q5 validation; that is not an unreadable record. */
      | "integrity-state-invalid"
      /** A sidecar with this stamp already exists; never overwrite quarantined bytes. */
      | "quarantine-exists";
    detail: string;
  };

export interface IntelligenceConfigStoreOptions {
  /** Test/fixture seam; production uses the pinned release key. */
  modelManifestV2PublicKey?: Uint8Array;
  /**
   * Test seam for the config-save lock: `onContended` lets an adversarial-
   * schedule test prove a second saver actually blocked on the lock instead
   * of inferring it from elapsed time. Never changes acquire behavior.
   */
  saveLockOptions?: Pick<CrossProcessLockOptions, "onContended" | "retryMs" | "timeoutMs">;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function loadRefusalReason(
  reason: ModelManifestV2RefusalReason,
): ModelLoadIntegrityFailureReason {
  if (reason === "binding_mismatch" || reason === "model_root_invalid") {
    return reason;
  }
  if (reason === "rollback" || reason === "downgrade") {
    return "manifest_rollback";
  }
  if (
    reason === "bad_signature" || reason === "bad_signature_encoding" ||
    reason === "bad_signature_length" || reason === "zero_signature" ||
    reason === "bad_pinned_key_length" || reason === "zero_pinned_key"
  ) {
    return "manifest_signature_invalid";
  }
  return "integrity_state_invalid";
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
  private saveLockOptions: IntelligenceConfigStoreOptions["saveLockOptions"];
  private saveLockDepth = 0;

  constructor(
    storage: StorageBackend,
    masterKey: Uint8Array,
    options: IntelligenceConfigStoreOptions = {},
  ) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, HKDF_INFO);
    this.modelManifestV2PublicKey =
      options.modelManifestV2PublicKey ?? loadPinnedModelManifestKey();
    this.saveLockOptions = options.saveLockOptions;
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

    return this.decode(raw);
  }

  /**
   * Read the durable config for an operator diagnostic. Identical to
   * {@link load} except that a storage read FAILURE returns `read-failed`
   * instead of the default config: `load()`'s swallow is correct for booting a
   * fresh fortress and wrong for reporting, where it would turn "this record
   * could not be read" into the positive claim "no record exists".
   *
   * Failure mode to expect: on a fortress whose state directory this user
   * cannot read, `load()` reports a pristine new fortress and this method
   * reports that it does not know. Reading the first as the truth is the
   * mistake this method exists to prevent.
   */
  async loadForDiagnostics(): Promise<DiagnosticLoadOutcome> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
    } catch {
      // The caught error is not carried forward: a storage error message can
      // embed the fortress path and an OS-level string, and the classifier's
      // fixed text is the whole operator-facing surface for this state.
      return { kind: "read-failed" };
    }
    if (!raw) return { kind: "default", config: buildDefaultConfig() };
    return this.decode(raw);
  }

  /**
   * Read the durable config as security authority rather than as a boot-time
   * convenience. Missing is represented by null; unreadable or invalid state
   * throws so a writer can never reinterpret indeterminate bytes as legacy V1.
   */
  async loadAuthoritative(): Promise<SubstrateConfig | null> {
    const raw = await this.storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
    if (raw === null) return null;
    const outcome = this.decode(raw);
    if (outcome.kind === "loaded") return outcome.config;
    if (outcome.kind === "integrity-state-invalid") {
      throw new LocalIntegrityStateLoadError(outcome.reason);
    }
    // An unreadable record names its remedy at the refusal, because every
    // config write funnels through this read and would otherwise fail with a
    // generic reason the operator cannot act on.
    if (outcome.kind === "corrupt") {
      throw new IntelligenceConfigUnreadableError("corrupt");
    }
    if (outcome.kind === "version-too-new") {
      throw new IntelligenceConfigUnreadableError(
        "version-too-new",
        outcome.persistedVersion,
      );
    }
    throw new LocalIntegrityStateLoadError("integrity_state_invalid");
  }

  private decode(raw: Uint8Array): LoadOutcome {
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
          reason: loadRefusalReason(validated.reason),
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
    return this.withSaveLock(() => this.saveWhileLocked(config));
  }

  /**
   * Serialize an authority read plus its eventual config save. Provisioning
   * acquires its own lock first and then this lock, while routine writers take
   * only this lock; no path may reverse that fixed order. Provisioning holds
   * this lock across its interactive confirmation, model pulls, verification,
   * authority reload, and commit, so a live ceremony may own it for minutes.
   */
  async withSaveLock<T>(operation: () => Promise<T>): Promise<T> {
    return withCrossProcessLock(
      this.storage,
      INTELLIGENCE_NAMESPACE,
      Q5_CONFIG_SAVE_LOCK_FILE,
      async () => {
        this.saveLockDepth += 1;
        try {
          return await operation();
        } finally {
          this.saveLockDepth -= 1;
        }
      },
      { ...this.saveLockOptions, metadata: { purpose: "q5-intelligence-config-save" } },
    );
  }

  /**
   * Save while the caller already owns {@link Q5_CONFIG_SAVE_LOCK_FILE}.
   * This is deliberately separate because the O_EXCL primitive is not
   * reentrant and provisioning holds the save lock across reload-through-commit.
   */
  async saveWhileLocked(config: SubstrateConfig): Promise<SubstrateConfig> {
    if (this.saveLockDepth <= 0) {
      // The unlocked form would reopen the check-then-write lost-update window.
      throw new LocalIntegrityStateLoadError("integrity_io_unavailable");
    }
    const stamped: SubstrateConfig = {
      ...config,
      updatedAt: new Date().toISOString(),
    };
    // INVARIANT (Q5E residual 1): the durable read below and the write at the
    // end of this method are one critical section under the cross-process
    // config-save lock, for every writer, provisioning or routine. A lock was
    // chosen over a post-write verify because a verify can only detect a lost
    // update after the armed V2 bytes are already gone and cannot restore
    // them; the lock makes the V1-over-V2 interleaving unconstructible, and
    // the loser re-reads the committed V2 record and refuses with a typed
    // error instead of overwriting it.
    const durable = await this.loadAuthoritative();
    if (durable?.version === 2) {
      // INVARIANT: the durable record, not any in-memory snapshot, is the
      // rollback authority; every config writer converges on this chokepoint.
      if (stamped.version !== 2) {
        throw new LocalIntegrityStateLoadError("integrity_state_invalid");
      }
      if (
        stamped.localIntegrityState.manifest_version_floor <
          durable.localIntegrityState.manifest_version_floor
      ) {
        throw new LocalIntegrityStateLoadError("manifest_rollback");
      }
    }
    if (stamped.version === 2) {
      if (this.modelManifestV2PublicKey === null) {
        throw new LocalIntegrityStateLoadError("integrity_state_invalid");
      }
      const validated = validateLocalIntegrityStateV2(
        stamped.localIntegrityState,
        this.modelManifestV2PublicKey,
      );
      if (!validated.ok) {
        throw new LocalIntegrityStateLoadError(loadRefusalReason(validated.reason));
      }
      if (!configBindingsMatch({ ...stamped, localIntegrityState: validated.state })) {
        throw new LocalIntegrityStateLoadError("binding_mismatch");
      }
    }
    const serialized = stringToBytes(JSON.stringify(stamped));
    const encrypted = encrypt(serialized, this.encryptionKey);
    const durableWrite = (
      this.storage as Partial<FilesystemStorageCapabilities>
    ).writeDurable;
    // A reported authoritative save must survive the power-loss window after
    // rename; non-filesystem single-process backends retain the base contract.
    await (durableWrite === undefined ? this.storage.write : durableWrite).call(
      this.storage,
      INTELLIGENCE_NAMESPACE,
      SUBSTRATE_CONFIG_KEY,
      stringToBytes(JSON.stringify(encrypted)),
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
    if (current.kind === "integrity-state-invalid") {
      throw new LocalIntegrityStateLoadError(current.reason);
    }
    // An unreadable record leaves only through the quarantine verb, which
    // preserves its bytes; a silent delete here would discard the evidence.
    if (current.kind === "corrupt") {
      throw new IntelligenceConfigUnreadableError("corrupt");
    }
    if (current.kind === "version-too-new") {
      throw new IntelligenceConfigUnreadableError(
        "version-too-new",
        current.persistedVersion,
      );
    }
    if (current.config.version === 2) {
      throw new LocalIntegrityStateLoadError("integrity_state_invalid");
    }
    try {
      await this.storage.delete(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
    } catch {
      // Storage backend may not support delete on a non-existent key;
      // the selector tolerates this and proceeds with defaults.
    }
  }

  /**
   * Recovery path for an unreadable durable record (the only one). Copies the
   * raw record bytes to a timestamped sidecar file, then removes the record so
   * the next `load()` returns the default legacy-unarmed config. Runs under
   * the config-save lock so no writer can observe the record half-moved.
   *
   * Ordering is write-sidecar-then-delete: a crash after the sidecar write
   * leaves both files (a rerun quarantines again under a new stamp), and a
   * crash after the delete leaves the sidecar; at no point is the record gone
   * with no copy of its bytes. Refuses a readable record (armed or legacy) and
   * an armed record that failed Q5 validation, because neither is unreadable.
   *
   * INVARIANT (consent): this method carries only the data-plane refusals
   * above. It has no terminal check, no typed confirmation, and no unlock of
   * its own, so EVERY caller must repeat the `config-reset` gates (interactive
   * TTY, typed word, write-intent master unlock) before reaching it, and it
   * must never be reachable from an MCP tool or an HTTP route. The result
   * leaves a fortress that was armed on the unreadable record in the default
   * legacy-unarmed state. `test/structure/q5e-config-reset-chokepoint.test.ts`
   * pins the single production caller.
   */
  async quarantineUnreadable(
    options: { now?: () => Date } = {},
  ): Promise<QuarantineOutcome> {
    return this.withSaveLock(async () => {
      const capabilities = this.storage as Partial<FilesystemStorageCapabilities>;
      if (capabilities.namespacePath === undefined) {
        // Only a filesystem-backed fortress has a sibling location that stays
        // outside the encrypted-record set; no other backend may quarantine.
        throw new LocalIntegrityStateLoadError("integrity_io_unavailable");
      }
      const raw = await this.storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
      if (raw === null) return { kind: "absent" };
      const outcome = this.decode(raw);
      if (outcome.kind === "loaded" || outcome.kind === "default") {
        return {
          kind: "refused",
          reason: "readable",
          detail: `the durable record is readable (version ${outcome.config.version})`,
        };
      }
      if (outcome.kind === "integrity-state-invalid") {
        return {
          kind: "refused",
          reason: "integrity-state-invalid",
          detail: `the armed record failed Q5 integrity validation (${outcome.reason})`,
        };
      }
      const persistedVersion = outcome.kind === "version-too-new"
        ? outcome.persistedVersion
        : null;
      // ISO-8601 with ":" and "." folded to "-" so the stamp is one plain
      // path component on every filesystem this fortress may live on.
      const stamp = (options.now ?? (() => new Date))().toISOString()
        .replace(/[:.]/g, "-");
      const quarantineFile =
        `${SUBSTRATE_CONFIG_QUARANTINE_PREFIX}${stamp}${QUARANTINE_FILE_SUFFIX}`;
      const quarantinePath = join(
        capabilities.namespacePath.call(this.storage, INTELLIGENCE_NAMESPACE),
        quarantineFile,
      );
      // Quarantined bytes are evidence and are never overwritten; the atomic
      // temp-and-rename below would replace a same-stamp sidecar silently.
      if (await pathExists(quarantinePath)) {
        return {
          kind: "refused",
          reason: "quarantine-exists",
          detail: `a quarantine sidecar already exists at ${quarantinePath}`,
        };
      }
      await writeFileCustody(quarantinePath, raw, { mode: QUARANTINE_FILE_MODE });
      await this.storage.delete(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
      return {
        kind: "quarantined",
        persisted: outcome.kind,
        persistedVersion,
        quarantineFile,
        quarantinePath,
        bytes: raw.length,
      };
    });
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}
