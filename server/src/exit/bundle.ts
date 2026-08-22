/**
 * Sanctuary v1.1 exit-bundle export/import implementation.
 *
 * The public bundle is a directory containing `manifest.json` and hashed JSON
 * artifacts. Private keys and passphrases are never emitted. Encrypted user
 * state can be re-keyed on import when the operator supplies source key
 * material and the destination has a signing identity.
 */

import { mkdir, readdir, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { StorageBackend } from "../storage/interface.js";
import {
  StateStore,
  isReservedNamespace,
  type StateEntry,
  // CONTRACT PIN: must match the export in
  // server/src/cognitive/state-store.ts - see that file's comment on these
  // constants. Used by activationSnapshotLocations to snapshot the exact
  // `_meta` keys a state re-key touches (coordinator gate, 2026-08-22).
  STATE_ENVELOPE_PUBLIC_KEYS_KEY,
  STATE_ENVELOPE_VERSION_ANCHORS_KEY,
} from "../cognitive/state-store.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { AuditLog, AuditEntry } from "../operational/audit-log.js";
import type { PrincipalPolicy } from "../principal-policy/types.js";
import type { SanctuaryConfig } from "../config.js";
import { defaultConfig, SANCTUARY_VERSION } from "../config.js";
import {
  EXIT_BUNDLE_ARTIFACT_KINDS,
  EXIT_BUNDLE_MANIFEST_VERSION,
  SIGNATURE_SCHEME_V1,
  type ExitBundleArtifactKind,
} from "../contracts/v1.1/constants.js";
import type {
  ExitBundleArtifactEntry,
  ExitBundleDidWebBinding,
  ExitBundleManifest,
  ExitBundleManifestBody,
} from "../contracts/v1.1/exit-bundle-manifest.js";
import {
  parseDidWeb,
  resolveDidWeb,
  type ResolveDidWebOpts,
} from "../recognition/did-web.js";
import { canonicalize, canonicalizeToBytes } from "../mesh/canonical-json.js";
import { hash, hashToString } from "../core/hashing.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import {
  deriveMasterKey,
  deriveNamespaceKey,
  derivePurposeKey,
  parseKeyDerivationParams,
  type KeyDerivationParams,
} from "../core/key-derivation.js";
import { decrypt, type EncryptedPayload } from "../core/encryption.js";
import {
  unwrapMasterFromWraps,
  wrapMasterWithRecoveryKey,
  type CustodyWrap,
} from "../core/master-custody.js";
import { generateRandomKey } from "../core/random.js";
import {
  sign as identitySign,
  verify as identityVerify,
  publicKeyToDid,
  type StoredIdentity,
} from "../core/identity.js";
import {
  verifyRotationChain,
  type RotationChainInvalidReason,
  type VerifiedRotationChain,
} from "../core/rotation-chain.js";
import {
  ReputationStore,
  ReputationBundleVerificationError,
  type ReputationBundle,
} from "../reputation/reputation-store.js";
import {
  verifyExitBundle,
  readManifest,
  loadExitArtifact,
  isWellFormedExitStateEntryElement,
  checkEncryptedStateStructure,
  type EncryptedStateStructureProblem,
} from "./verifier.js";
import {
  isValidSourceCustody,
  SOURCE_CUSTODY_FORMAT,
} from "./source-custody.js";
import {
  partitionByMemoryClass,
  type PartitionConsentRelease,
  type PartitionCandidate,
  type PartitionResult,
} from "./memory-class.js";
// the parser proves this is a string but not that it is short; the diagnostic
// goes through the untrusted-diagnostic chokepoint for its length bound
// (STATE-STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../errors/index.js";

const ARTIFACT_DIR = "artifacts";

/**
 * Recognition-Layer Path C primary build 2 audit operations.
 *
 * EXPORT_INCLUDED fires when the operator's export embeds a did:web
 * pointer in the manifest's identity_binding.
 *
 * IMPORT_VERIFIED fires when the import path resolves the pointer
 * and reports the outcome via the `outcome` details field:
 *   - "success":            DID Document fetched + pubkey matched.
 *   - "mismatch":           DID Document fetched but pubkey did not
 *                           match the manifest's claimed key. The
 *                           importer raises ExitBundleImportError
 *                           with code `did_web_mismatch`; the audit
 *                           event captures the attempt regardless.
 *   - "resolution_failure": Network, DNS, or parse failure. The
 *                           importer treats this as a degraded-
 *                           confidence import: operator can re-run
 *                           with --skip-did-web-verify to proceed
 *                           without the recognition-layer check.
 *   - "skipped":            Operator passed --skip-did-web-verify;
 *                           the import proceeds without resolution.
 *
 * AUTHORITY_HOST fires alongside IMPORT_VERIFIED to capture the host
 * that served the DID Document. Operator-visible for audit trails;
 * matches the manifest's claimed authority_host on success and may
 * differ from it on resolution failure (the audit captures what
 * Sanctuary attempted, not what succeeded).
 */
export const EXIT_BUNDLE_DID_WEB_AUDIT_OPS = {
  EXPORT_INCLUDED: "exit_bundle_did_web_export_included",
  IMPORT_VERIFIED: "exit_bundle_did_web_import_verified",
  AUTHORITY_HOST: "exit_bundle_did_web_authority_host",
} as const;

export type ExitBundleDidWebAuditOp =
  (typeof EXIT_BUNDLE_DID_WEB_AUDIT_OPS)[keyof typeof EXIT_BUNDLE_DID_WEB_AUDIT_OPS];

const EXIT_IMPORT_NAMESPACE = "_exit_imports";
const EXIT_PUBLIC_IDENTITIES_NAMESPACE = "_exit_public_identities";
const EXIT_AUDIT_RECEIPTS_NAMESPACE = "_exit_audit_receipts";
const EXIT_POLICY_SETS_NAMESPACE = "_exit_policy_sets";
const EXIT_COMMITMENTS_NAMESPACE = "_exit_commitments";
const EXIT_PLACEHOLDER_METADATA_NAMESPACE = "_exit_placeholder_metadata";
const PRIVACY_PLACEHOLDER_NAMESPACE = "_privacy_placeholder_vault";
/**
 * F1 (Exit V2 drill D1, 2026-08-22): a per-import durable rollback journal,
 * under the fortress's own reserved `_exit_*` family (staging-only; never
 * appears in an exported bundle - export only reads the named artifact
 * namespaces above, never this one). Written BEFORE any staging write below
 * begins and deleted only after a successful activation OR a successful
 * rollback, so a leftover entry here always means "an import was
 * interrupted before it finished either way." See
 * `recoverInterruptedExitImports` for the read side.
 */
const EXIT_IMPORT_JOURNAL_NAMESPACE = "_exit_import_journal";

/**
 * Custody-envelope re-key block (post-#496). Carries a wrap of the SOURCE
 * master under a fresh, random, export-scoped "bundle re-key key" minted at
 * export time and disclosed to the operator (never written into the
 * bundle). Import recovers the source master by unwrapping with that key -
 * no parallel derivation path, no fortress credential travels.
 *
 * Deliberately NOT the fortress's own envelope wraps (codex round-1 MED):
 * exporting a passphrase wrap would turn every fresh-envelope bundle into
 * an offline passphrase-guessing oracle (a random-master fortress's bundle
 * otherwise contains no passphrase-checkable material). The bundle re-key
 * key is a full-entropy 32-byte key, so the embedded wrap verifies nothing
 * an attacker could enumerate, and its HKDF unwrap path carries no
 * attacker-controlled KDF parameters (codex round-1 LOW).
 *
 * Security: the wrap is AES-256-GCM authenticated (a wrong key or tampered
 * wrap fails closed), and the artifact carrying this block is sha256-pinned
 * in the Ed25519-signed manifest, so a tampered bundle fails verification
 * before any wrap is touched.
 */
export interface ExitSourceCustody {
  format: "SANCTUARY_EXIT_SOURCE_CUSTODY_V1";
  /** Bundle-scoped re-key wraps; only `recovery-key` wraps are permitted. */
  wraps: CustodyWrap[];
}

/**
 * Why a zero-entry `encrypted_state.json` is empty.
 *
 * `fortress_state_empty`   - the source fortress had no exportable state.
 * `partition_excluded_all` - state existed but the ownership partition
 *                            withheld every entry (they stay with the operator).
 *
 * CONTRACT PIN (server/src/exit/verifier.ts `summarizeEncryptedState`): the
 * verifier reports these tokens verbatim and treats a zero-entry artifact
 * WITHOUT one as pre-marker evidence. Adding a member here means adding it
 * there in the same commit.
 */
export const EXIT_EMPTY_REASONS = {
  FORTRESS_STATE_EMPTY: "fortress_state_empty",
  PARTITION_EXCLUDED_ALL: "partition_excluded_all",
} as const;

export type ExitEmptyReason =
  (typeof EXIT_EMPTY_REASONS)[keyof typeof EXIT_EMPTY_REASONS];

export interface ExitEncryptedStateBundle {
  format: "SANCTUARY_EXIT_ENCRYPTED_STATE_V1";
  exported_at: string;
  key_source: "passphrase" | "recovery-key" | "unknown";
  /**
   * Present IFF `entries` is empty: names why. Absent on every non-empty
   * bundle and on every bundle written before this marker existed, so an
   * absent marker on a zero-entry artifact means "pre-marker or buggy
   * exporter", never "the fortress was empty".
   *
   * It lives in the ARTIFACT, not the manifest, so it is covered by the
   * Ed25519-signed manifest transitively through the artifact's sha256 +
   * size pins - no `manifest_version` bump, no `contracts/v1.1` edit.
   */
  empty_reason?: ExitEmptyReason;
  /**
   * Additive Slice-2 signal: true when this artifact was filtered through the
   * verified ownership partition, false/absent for legacy full-fortress exports.
   */
  ownership_partitioned?: boolean;
  /**
   * Legacy re-key parameters (pre-envelope custody): Argon2id params under
   * which `master = Argon2id(passphrase, params)`. Still emitted when the
   * legacy `_meta/key-params` marker exists (migrated fortresses keep their
   * markers - #496) so older importers keep working on those bundles. For
   * envelope-custody fortresses this mechanism is legacy-only; the
   * authoritative re-key path is `source_custody`.
   */
  source_key_derivation?: KeyDerivationParams;
  /**
   * Envelope-era re-key block. Present iff the export minted a bundle
   * re-key key (`mintStateRekeyKey`) and the bundle carries state entries.
   */
  source_custody?: ExitSourceCustody;
  namespaces: string[];
  total_keys: number;
  contains_reserved_namespaces: false;
  entries: Array<{
    namespace: string;
    key: string;
    entry: StateEntry;
  }>;
}

export interface ExitPublicIdentityArtifact {
  bundle: {
    format: "SANCTUARY_IDENTITY_BUNDLE_V1";
    publicKey: string;
    did: string;
    identity_id: string;
    label: string;
    key_type: "ed25519";
    key_protection: string;
    rotation_history: StoredIdentity["rotation_history"];
    exported_at: string;
  };
  signature: string;
  signed_by: string;
}

export interface ExitPolicySetArtifact {
  format: "SANCTUARY_EXIT_POLICY_SET_V1";
  exported_at: string;
  principal_policy: PrincipalPolicy;
  config_summary: {
    version: string;
    state: SanctuaryConfig["state"];
    execution: SanctuaryConfig["execution"];
    disclosure: SanctuaryConfig["disclosure"];
    reputation: SanctuaryConfig["reputation"];
    privacy_filter: SanctuaryConfig["privacy_filter"];
  };
}

export interface ExitAuditReceiptsArtifact {
  format: "SANCTUARY_AUDIT_RECEIPTS_V1";
  exported_at: string;
  total: number;
  recovery_semantics: "archive_only";
  normal_audit_query_continuity: false;
  individual_entry_signatures: false;
  /**
   * True when the audit population (`total`) exceeded the export cap and the
   * oldest entries were dropped from `entries`. Honesty marker: without it,
   * `total` (full population) silently disagrees with `entries.length`
   * (the capped slice), overclaiming the artifact's completeness. Absent
   * (implicitly false) when the whole population fit under the cap.
   */
  truncated?: boolean;
  /**
   * How many of the oldest entries were omitted by the export cap
   * (`total - entries.length`). Present only when `truncated` is true.
   */
  omitted_count?: number;
  entries: AuditEntry[];
}

/**
 * Hard cap on the number of audit receipts carried in an exit bundle. The
 * `query` slice keeps the most-recent entries; anything older than the cap is
 * omitted and disclosed via the `truncated`/`omitted_count` honesty marker.
 */
export const EXIT_AUDIT_RECEIPTS_EXPORT_CAP = 100_000;

export interface ExitCommitmentsArtifact {
  format: "SANCTUARY_EXIT_COMMITMENTS_V1";
  exported_at: string;
  public_commitments: Array<{
    commitment_id: string;
    commitment: string;
    committed_at: string;
    revealed: boolean;
    revealed_at?: string;
  }>;
  unreadable_count: number;
  redacted_fields: ["value", "blinding_factor"];
}

export interface ExitPlaceholderVaultMetadataArtifact {
  format: "SANCTUARY_PLACEHOLDER_VAULT_METADATA_V1";
  exported_at: string;
  entries: Array<Record<string, unknown>>;
  unreadable_count: number;
  redacted_fields: ["raw_value", "raw_path"];
}

export interface ExportExitBundleOptions {
  bundleDir: string;
  storage: StorageBackend;
  masterKey: Uint8Array;
  identityManager: IdentityManager;
  auditLog: AuditLog;
  policy: PrincipalPolicy;
  config?: SanctuaryConfig;
  reputationStore?: ReputationStore;
  stateStoragePath?: string;
  /**
   * Restrict the encrypted-state export to these namespaces. OMIT the option
   * to export every namespace discovered under `stateStoragePath`; that is the
   * behavior an operator-driven full-fortress export wants.
   *
   * Supplying an EMPTY array throws. It is never "export zero state": an empty
   * array is what a repeated-flag parser produces when the operator passed no
   * flag at all, and treating it as a real selection is what made
   * `sanctuary exit export` emit signed, empty bundles. Callers that build this
   * from CLI flags must spread it conditionally
   * (`...(names.length > 0 ? { stateNamespaces: names } : {})`), the same shape
   * the import path uses for `didWebAllowedHosts`.
   */
  stateNamespaces?: string[];
  keySource?: "passphrase" | "recovery-key" | "unknown";
  /**
   * When the export is gated by a Tier 1 approval flow (e.g. the hub's
   * fortress-scope export endpoint), the caller supplies the approval's
   * audit id here. The value is embedded in the manifest's
   * `export_approval_audit_id` field and as the `approval_id` of the L1
   * "exit_bundle_export" audit entry, tying the manifest to the operator's
   * actual approval rather than an internally-generated id (v1.0.2 (j)).
   * When omitted, the export self-generates an id.
   */
  exportApprovalAuditId?: string;
  /**
   * Recognition-Layer Path C primary build 2: optional did:web binding
   * to embed in the manifest's identity_binding. When provided, the
   * export validates that the binding's identifier resolves (per the
   * did:web spec) to a pointer over the same authority host as
   * `binding.authority_host`, and that the operator's fortress public
   * key matches the key the did:web identifier was issued against
   * (the export does NOT re-fetch the published DID Document; that
   * check is the receiving regime's job at import time).
   *
   * Omit to skip did:web embedding entirely. Receiving regimes that
   * import the bundle treat absence as backward-compatible (no
   * recognition-layer verification step).
   */
  didWeb?: ExitBundleDidWebBinding;
  /**
   * Mint a fresh, random bundle re-key key, embed a wrap of the source
   * master under it (`source_custody`), and return the key in
   * `state_rekey_key` for operator disclosure. OPT-IN because the caller
   * must have a secure, non-persisted channel to the operator: the exit
   * CLI prints it to the operator's terminal; callers whose results are
   * persisted (e.g. the hub's `resolution_payload`) must NOT enable this
   * (key material must never be persisted - CLAUDE.md #6). Known intentional
   * non-minting caller: `fortressExportBundle` in `dashboard/v1_1/wiring.ts`
   * (the dashboard exit endpoint), whose omission is a custody boundary, not
   * an oversight; must match the acknowledgement comment there.
   *
   * Without it, an envelope-custody bundle's state can only be re-keyed by
   * a programmatic `sourceMasterKey` (legacy fortresses keep the legacy
   * `source_key_derivation` path).
   */
  mintStateRekeyKey?: boolean;
  /**
   * Exit machinery Slice 1: ownership partition. When supplied, the encrypted-
   * state export applies the CONSERVATIVE memory-class partition: an entry is
   * included in the outbound (agent) bundle ONLY when the caller supplies a
   * sealed `agent_owned` stamp BOUND to its `namespace/key` (or an audited
   * consent receipt releases its `shared_entangled` lineage). Every other entry
   * - unsealed, binding-mismatched, operator-owned, or shared-entangled without
   * consent - is EXCLUDED and fails toward "stays with the operator," never
   * `agent_owned`.
   *
   * Slice 2: the export path no longer trusts caller-supplied stamp maps. It
   * verifies each state envelope first and re-mints a live sealed stamp from the
   * signed `provenance_stamp` field. Legacy or unstamped records are excluded.
   */
  memoryClassPartition?: {
    readonly consentReleases?: readonly PartitionConsentRelease[];
  };
  /**
   * Codex HIGH (06-13) reconciliation: backward compatibility requires the
   * pre-Slice-1 single-operator export (every non-`_` namespace, no ownership
   * partition) to remain the behavior when no partition is supplied - the
   * shipped CLI, hub, dashboard, and drill paths all rely on it, and Slice 1 is
   * explicitly scoped as an OPT-IN ownership axis.
   *
   * To keep that compatibility WITHOUT silently masking the absence, an
   * unpartitioned export now requires the caller to acknowledge it explicitly
   * with `unpartitionedLegacyExport: true`. An export that supplies neither
   * `memoryClassPartition` nor this flag throws - so an *agent-exit* caller
   * (which must partition) cannot accidentally fall through to "export
   * everything." Operator-driven full-fortress exports pass this flag; agent
   * exit flows pass `memoryClassPartition`.
   *
   * This is NOT a clean-exit guarantee: the unpartitioned path exports all
   * state by design. It is the named, auditable acknowledgement that the
   * ownership partition was deliberately not applied.
   */
  unpartitionedLegacyExport?: boolean;
  /**
   * Override the audit-receipts export cap (default
   * `EXIT_AUDIT_RECEIPTS_EXPORT_CAP` = 100k). When the audit population
   * exceeds the cap, the oldest receipts are omitted and the omission is
   * disclosed via the artifact's `truncated`/`omitted_count` marker plus an
   * export warning. Primarily a test/operability knob; production exports use
   * the default cap.
   */
  auditReceiptsExportCap?: number;
  /**
   * Optional deterministic export clock. Beyond making tests reproducible,
   * this single read anchors `manifest.body.exported_at`, which the import
   * path feeds into did:web resolution as `assertion_time` (see
   * `resolveDidWeb` callers below) - the value that decides whether a
   * historical, since-revoked verification method is still inside its valid
   * window. An uninjected caller gets the real wall clock, as before; a
   * caller that injects `now` gets both a reproducible manifest AND a
   * reproducible revoked-key window evaluation from the same read.
   */
  now?: () => Date;
}

export interface ExportExitBundleResult {
  bundle_dir: string;
  manifest: ExitBundleManifest;
  manifest_hash: string;
  artifact_count: number;
  unsupported_artifacts: string[];
  /**
   * Number of state entries carried in `encrypted_state.json`. Always present,
   * including when it is 0, so a caller can gate on "did this export actually
   * carry state" without parsing an artifact or a warning string. Mirrors the
   * import path's `state.imported_keys`.
   */
  state_entry_count: number;
  /**
   * The minted bundle re-key key (base64url, 32 bytes), present only when
   * `mintStateRekeyKey` was set and the bundle carries state entries. It is
   * disclosed ONCE here and never written into the bundle or audit log;
   * the importing operator supplies it as `--source-recovery-key`.
   */
  state_rekey_key?: string;
  /**
   * Exit machinery Slice 1: ownership-partition summary, present only when
   * `memoryClassPartition` was supplied. `included` entries traveled in the
   * outbound bundle; `excluded` entries were withheld under the conservative
   * default (unsealed, operator-owned, or shared-entangled without consent).
   * This is telemetry for the operator's review, NOT a non-leakage proof: the
   * cleanliness claim is only as strong as the sealed-minter coverage (Slice 2).
   */
  state_partition?: {
    included: number;
    excluded: number;
    excluded_unstamped: number;
    excluded_unsealed: number;
  };
  /**
   * Operator-facing, non-fatal advisories raised during export. Currently
   * carries the audit-receipts truncation notice when the audit population
   * exceeded the export cap (the oldest entries were omitted). Absent when the
   * export raised no warnings.
   */
  warnings?: string[];
}

export interface ImportExitBundleOptions {
  bundleDir: string;
  storage: StorageBackend;
  masterKey: Uint8Array;
  identityManager: IdentityManager;
  auditLog: AuditLog;
  reputationStore?: ReputationStore;
  activate?: boolean;
  conflictResolution?: "skip" | "overwrite" | "version";
  sourcePassphrase?: string;
  sourceRecoveryKey?: string;
  /**
   * Confirm the LEGACY interpretation of `sourceRecoveryKey`: on a bundle that
   * carries no `source_custody` block, treat the supplied key as the source
   * fortress's raw master rather than as a bundle re-key key. Required because
   * those two meanings are indistinguishable from the bundle alone, and
   * guessing produced a downstream SOURCE_KEY_MISMATCH that named the symptom
   * instead of the cause. CLI surface: `--legacy-source-master` (only
   * meaningful together with `--source-recovery-key`).
   */
  legacyRecoveryKeyIsMaster?: boolean;
  sourceMasterKey?: Uint8Array;
  destinationSignerIdentityId?: string;
  /**
   * v1.0.2 (i) / full-sweep #54. When the destination fortress already has a
   * staged `public_identity` for the bundle's identity_id, activation is refused
   * unless the operator passes this flag. The CLI surfaces the flag as
   * `--force-rebind` and re-prompts Tier 1 confirmation. When `forceRebind` is
   * true and the rebind triggers, an `exit_bundle_force_rebind` L1 audit entry
   * records the explicit replacement.
   */
  forceRebind?: boolean;
  /**
   * Recognition-Layer Path C primary build 2: hosts the importing
   * operator has explicitly allowed for outbound did:web resolution.
   * Empty array means resolution refuses to leave the fortress
   * (preserves no-outbound-by-default). The same allowlist is also
   * enforced at the kernel level by the operator's Castle Wall egress
   * filter; this option is the application-level coordinator.
   *
   * Absent + did_web present in manifest = the importer surfaces a
   * warning and proceeds with the manifest-signature check alone
   * (degraded confidence). The operator can re-run with the
   * allowlist set or with `skipDidWebVerify: true`.
   */
  didWebAllowedHosts?: string[];
  /**
   * Recognition-Layer Path C primary build 2: when true, the importer
   * skips did:web resolution entirely even if the manifest carries a
   * did_web binding. Operator surface: CLI flag
   * `--skip-did-web-verify`. Tradeoff is operator-visible: skipping
   * loses the recognition-layer cross-check that the bundle's claimed
   * origin matches the published DID Document.
   */
  skipDidWebVerify?: boolean;
  /**
   * Operator opt-in for importing entries whose only valid source signature is
   * a key retired by a compromised-reason rotation. CLI surface:
   * `--accept-compromised-rotation-keys`.
   */
  acceptCompromisedRotationKeys?: boolean;
  /**
   * Recognition-Layer Path C primary build 2: optional fetcher
   * override for tests. Defaults to globalThis.fetch via the did:web
   * foundation's resolver. Production callers leave undefined.
   */
  didWebFetcher?: ResolveDidWebOpts["fetcher"];
  /**
   * Recognition-Layer Path C primary build 2: resolution timeout.
   * Defaults to the did:web foundation's 5000ms default.
   */
  didWebTimeoutMs?: number;
}

/**
 * Structured error raised by `importExitBundle` for codes the CLI / hub want
 * to branch on without parsing free-text messages. v1.0.2 (i) / full-sweep #54.
 */
export class ExitBundleImportError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ExitBundleImportError";
    this.code = code;
  }
}

export interface ExitBundleConflictReport {
  public_identity_exists: boolean;
  state_conflicts: Array<{ namespace: string; key: string }>;
  reputation_conflicts: string[];
  policy_set_exists: boolean;
  audit_receipts_exist: boolean;
  commitments_exist?: boolean;
  import_record_exists?: boolean;
}

export interface ImportExitBundleResult {
  verified: boolean;
  activated: boolean;
  conflicts: ExitBundleConflictReport;
  state: {
    /**
     * `empty_bundle` (additive) is the honest answer to "I asked for state and
     * supplied credentials, and the bundle carried none": it used to report
     * `not_requested`, which is false and also suppresses nothing, so the CLI's
     * "re-run with --import-state" advice fired at an operator who already had.
     */
    status:
      | "not_requested"
      | "empty_bundle"
      | "rekeyed"
      | "staged_requires_source_key"
      | "skipped_no_destination_signer";
    imported_keys: number;
    skipped_keys: number;
    skipped_invalid_sig: number;
    skipped_unknown_kid: number;
    conflicts: number;
  };
  reputation: {
    imported_attestations: number;
    invalid_attestations: number;
    unverifiable_attestations: number;
  };
  rotation?: {
    identity_id: string;
    hop_count: number;
    chain_signature_verified: boolean;
    compromised_hops: number;
    entries_admitted_by_current_key: number;
    entries_admitted_by_retired_key: number;
    entries_admitted_by_compromised_retired_key: number;
  };
  staged_artifacts: string[];
  warnings: string[];
  unsupported_artifacts: string[];
}

function stateHasNonConflictSkippedEntries(
  state: ImportExitBundleResult["state"]
): boolean {
  return (
    state.skipped_invalid_sig > 0 ||
    state.skipped_unknown_kid > 0 ||
    state.skipped_keys > state.conflicts
  );
}

function stateSkippedOnlyConflicts(
  state: ImportExitBundleResult["state"]
): boolean {
  return state.skipped_keys > 0 && !stateHasNonConflictSkippedEntries(state);
}

function stateImportIncompleteMessage(
  state: ImportExitBundleResult["state"]
): string {
  return (
    "state import incomplete: " +
    `state_skipped_keys=${state.skipped_keys}, ` +
    `state_skipped_invalid_sig=${state.skipped_invalid_sig}, ` +
    `state_skipped_unknown_kid=${state.skipped_unknown_kid}. ` +
    "Refusing activation and rolling back staged artifacts; inspect or " +
    "re-export the source bundle before retrying."
  );
}

function stateImportIncompleteMessageWithRotationKeys(
  state: ImportExitBundleResult["state"],
  publicKeysByIdentityId: Map<string, SourceIdentityPublicKeyCandidate[]>
): string {
  const base = stateImportIncompleteMessage(state);
  const keyCounts = [...publicKeysByIdentityId.values()].map(
    (candidates) => candidates.length
  );
  const maxKeysTried = keyCounts.length > 0 ? Math.max(...keyCounts) : 0;
  return maxKeysTried > 1
    ? base +
        ` Verified rotation history was present; signature checks tried ${maxKeysTried} key candidates (current plus ${maxKeysTried - 1} retired) before refusing.`
    : base;
}

export class ExitBundleStateImportIncompleteError extends ExitBundleImportError {
  readonly state: ImportExitBundleResult["state"];

  constructor(
    state: ImportExitBundleResult["state"],
    message = stateImportIncompleteMessage(state),
    options?: { cause?: unknown },
  ) {
    super("STATE_IMPORT_INCOMPLETE", message, options);
    this.name = "ExitBundleStateImportIncompleteError";
    this.state = state;
  }
}

function sha256Hex(bytes: Uint8Array): string {
  return Array.from(hash(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function jsonBytes(value: unknown): Uint8Array {
  return stringToBytes(JSON.stringify(value, null, 2) + "\n");
}

/**
 * CONTRACT PIN: mirrors `EncryptedStateStructureProblem` (verifier.ts,
 * `checkEncryptedStateStructure`). The first two codes are unchanged from
 * before F3/F4 (server/test/exit/exit-verifier-aggregator.test.ts and
 * server/test/exit/exit-inspect-declares.test.ts pin
 * `ENCRYPTED_STATE_ENTRIES_UNREADABLE` for both); the other two are new,
 * named separately from that code because they describe a DIFFERENT
 * defect (a stale header count, a disallowed namespace) than "the entries
 * list itself cannot be read."
 */
function encryptedStateStructureErrorCode(
  problem: EncryptedStateStructureProblem | undefined
): string {
  switch (problem) {
    case "total_keys_mismatch":
      return "ENCRYPTED_STATE_TOTAL_KEYS_MISMATCH";
    case "reserved_namespace_entry":
      return "ENCRYPTED_STATE_RESERVED_NAMESPACE_ENTRY";
    case "entries_unreadable":
    case "entries_malformed_elements":
    default:
      return "ENCRYPTED_STATE_ENTRIES_UNREADABLE";
  }
}

function encryptedStateStructureErrorMessage(check: {
  problem?: EncryptedStateStructureProblem;
  detail?: string;
}): string {
  switch (check.problem) {
    case "total_keys_mismatch":
      return (
        "This bundle's encrypted_state artifact declares a total_keys count " +
        `that does not match its readable entries (${check.detail ?? "mismatch"}). ` +
        "The manifest signature is valid, but the artifact's own header " +
        "disagrees with its own body. Re-export the bundle from the source " +
        "fortress."
      );
    case "reserved_namespace_entry":
      return (
        "This bundle's encrypted_state artifact carries an entry under a " +
        `reserved namespace (${check.detail ?? "reserved namespace"}), which ` +
        "is never a legitimate export and is refused before any write. " +
        "Re-export the bundle from the source fortress."
      );
    case "entries_unreadable":
    case "entries_malformed_elements":
    default:
      return (
        "This bundle's encrypted_state artifact has no readable entries list " +
        "(the `entries` field is absent or is not an array), or its entries " +
        "list contains a malformed element (missing or wrong-typed " +
        "namespace/key/entry fields). This is not an empty bundle: the " +
        "entry list itself cannot be read. Re-export the bundle from the " +
        "source fortress."
      );
  }
}

async function writeJsonArtifact(
  bundleDir: string,
  path: string,
  value: unknown,
  kind: ExitBundleArtifactKind
): Promise<ExitBundleArtifactEntry> {
  const bytes = jsonBytes(value);
  const fullPath = join(bundleDir, path);
  await mkdir(join(bundleDir, ARTIFACT_DIR), { recursive: true, mode: 0o700 });
  await writeFile(fullPath, bytes, { mode: 0o600 });
  return {
    kind,
    path,
    hash_alg: "sha256",
    hash: sha256Hex(bytes),
    size_bytes: bytes.length,
  };
}

/**
 * Three-state read of the legacy `_meta/key-params` marker.
 *
 * `absent`    - no marker on disk (envelope-era or never-migrated fortress).
 * `ok`        - marker parsed AND passed `parseKeyDerivationParams`.
 * `malformed` - marker exists but is unparseable or out of accepted bounds;
 *               `reason` names the failing field for the operator.
 */
type SourceKeyParamsRead =
  | { state: "absent" }
  | { state: "ok"; params: KeyDerivationParams }
  | { state: "malformed"; reason: string };

async function readSourceKeyParams(
  storage: StorageBackend
): Promise<SourceKeyParamsRead> {
  const raw = await storage.read("_meta", "key-params");
  if (!raw) return { state: "absent" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch (err) {
    return {
      state: "malformed",
      reason: `not parseable JSON (${err instanceof Error ? err.message : String(err)})`,
    };
  }
  // CONTRACT PIN (server/src/core/key-derivation.ts parseKeyDerivationParams):
  // the export embed-gate, the import derive-gate below, and the verifier's
  // `legacy_kdf_params` report all classify through that one validator.
  const checked = parseKeyDerivationParams(parsed);
  return checked.ok
    ? { state: "ok", params: checked.params }
    : { state: "malformed", reason: checked.reason };
}

/**
 * Audit op emitted when an export refuses to sign a bundle because the
 * fortress's legacy `_meta/key-params` marker is malformed.
 */
const EXIT_EXPORT_REFUSED_MALFORMED_KDF_MARKER_OP =
  "exit_bundle_export_refused_malformed_kdf_marker";

/**
 * Mint the bundle re-key key and the source_custody block that carries the
 * source master wrapped under it. The key is returned for operator
 * disclosure and is NEVER written into the bundle - it is the only
 * credential that re-keys this bundle's state, held separately from it.
 *
 * Fortress envelope wraps are deliberately not copied (see
 * {@link ExitSourceCustody}); the fortress's own credentials never leave
 * the fortress in any form.
 */
function mintSourceCustody(masterKey: Uint8Array): {
  custody: ExitSourceCustody;
  rekeyKey: string;
} {
  const rekeyKeyBytes = generateRandomKey();
  const wrap = wrapMasterWithRecoveryKey(masterKey, rekeyKeyBytes, {
    verified: true,
  });
  const rekeyKey = toBase64url(rekeyKeyBytes);
  rekeyKeyBytes.fill(0);
  return {
    // CONTRACT PIN (server/src/exit/source-custody.ts `SOURCE_CUSTODY_FORMAT`):
    // the mint and the validator read the token from one declaration, so a
    // freshly minted block can never fail its own shape-check.
    custody: { format: SOURCE_CUSTODY_FORMAT, wraps: [wrap] },
    rekeyKey,
  };
}

async function discoverFilesystemStateNamespaces(
  stateStoragePath?: string
): Promise<string[]> {
  if (!stateStoragePath) return [];
  try {
    const names = await readdir(stateStoragePath);
    const namespaces: string[] = [];
    for (const name of names) {
      const full = join(stateStoragePath, name);
      const entryStat = await stat(full);
      if (!entryStat.isDirectory()) continue;
      if (name.startsWith("_")) continue;
      namespaces.push(name);
    }
    return namespaces.sort();
  } catch {
    return [];
  }
}

/**
 * Every option-SHAPE refusal for an export, in one place, so it can run before
 * the first side effect (see the A9 invariant at the `exportExitBundle` call
 * site) and again inside `exportEncryptedState` as defense in depth for any
 * future direct caller. Pure: reads only `opts`, touches no storage.
 */
function assertExportOptionsShape(opts: ExportExitBundleOptions): void {
  // "The caller named no namespaces" MUST resolve to discover-and-export
  // everything, never to an empty selection. A supplied-but-empty array is
  // exactly what a repeated-flag parser returns when the operator omitted the
  // flag, so honoring it as "export zero namespaces" is how `sanctuary exit
  // export` produced signed, well-formed, TOTALLY EMPTY bundles. Reject the
  // ambiguous shape at the boundary instead of interpreting it: a caller that
  // wants everything omits the option, and no caller has a legitimate reason to
  // ask for precisely zero namespaces (a fortress with no state already yields
  // an empty discovery). This is the same fail-closed posture as the
  // partition/legacy-opt-out check below.
  if (opts.stateNamespaces !== undefined && opts.stateNamespaces.length === 0) {
    throw new Error(
      "exit-bundle: stateNamespaces was supplied but empty. Omit the option to " +
        "export every discoverable namespace; an empty list is never a request " +
        "to export zero state.",
    );
  }

  // Exit machinery Slice 1: apply the conservative ownership partition. The
  // caller MUST make an explicit choice (codex HIGH): supply
  // `memoryClassPartition` (partition on) OR `unpartitionedLegacyExport: true`
  // (loud, named full-export opt-out). Supplying neither - or both - throws, so
  // an agent-exit caller cannot silently fall through to "export everything."
  const hasPartition = opts.memoryClassPartition !== undefined;
  const hasLegacyOptOut = opts.unpartitionedLegacyExport === true;
  if (hasPartition === hasLegacyOptOut) {
    throw new Error(
      "exit-bundle: exactly one of memoryClassPartition or " +
        "unpartitionedLegacyExport must be supplied. The ownership partition is " +
        "not silently skippable; pass memoryClassPartition for an ownership-classed " +
        "exit, or unpartitionedLegacyExport: true to deliberately export all state.",
    );
  }
}

async function exportEncryptedState(
  opts: ExportExitBundleOptions,
  exportedAt: string,
): Promise<{
  bundle: ExitEncryptedStateBundle;
  rekeyKey?: string;
  partition?: PartitionResult;
}> {
  assertExportOptionsShape(opts);
  const namespaceSet = new Set(
    opts.stateNamespaces ??
      (await discoverFilesystemStateNamespaces(opts.stateStoragePath))
  );
  const collected: ExitEncryptedStateBundle["entries"] = [];
  for (const namespace of [...namespaceSet].sort()) {
    // F6: never export internal `_`-prefixed namespaces - the rekey/import path
    // rejects them, so exporting one (e.g. an explicit `--state-namespace _x`)
    // would silently fail to round-trip. Symmetric with the import guard.
    // RESERVED-NS-DIVERGE-01: `isReservedNamespace` applies the blanket
    // underscore rule on its own, so no separate `startsWith("_")` is needed.
    if (isReservedNamespace(namespace)) continue;
    const metas = await opts.storage.list(namespace);
    for (const meta of metas) {
      const raw = await opts.storage.read(namespace, meta.key);
      if (!raw) continue;
      try {
        collected.push({
          namespace,
          key: meta.key,
          entry: JSON.parse(bytesToString(raw)) as StateEntry,
        });
      } catch {
        // Corrupt state is omitted rather than trusted into the exit bundle.
      }
    }
  }

  // An entry travels in the outbound bundle ONLY when it carries a live sealed
  // `agent_owned` stamp bound to its entry key (or its lineage was released by
  // an audited consent receipt). Everything else fails toward "stays with the
  // operator." The legacy opt-out exports all collected entries unchanged.
  let partition: PartitionResult | undefined;
  let entries = collected;
  if (opts.memoryClassPartition !== undefined) {
    const stateStore = new StateStore(opts.storage, opts.masterKey);
    const candidates: PartitionCandidate[] = [];
    for (const entry of collected) {
      const id = `${entry.namespace}/${entry.key}`;
      const reminted = await stateStore.remintVerifiedProvenanceStampForExport(
        entry.entry,
        entry.namespace,
        entry.key,
      );
      if (reminted.status === "sealed") {
        candidates.push({
          id,
          declaredStamp: reminted.declaredStamp,
          sealedStamp: reminted.sealedStamp,
        });
      } else if (reminted.status === "unsealed") {
        candidates.push({
          id,
          ...(reminted.declaredStamp !== undefined
            ? { declaredStamp: reminted.declaredStamp }
            : {}),
        });
      } else if (reminted.status === "verification_failed") {
        candidates.push({ id, verificationFailed: true });
      } else {
        candidates.push({ id });
      }
    }
    partition = partitionByMemoryClass(candidates, {
      consentReleases: opts.memoryClassPartition.consentReleases,
    });
    const includableIds = new Set(
      partition.includable.map((decision) => decision.id),
    );
    entries = collected.filter((entry) =>
      includableIds.has(`${entry.namespace}/${entry.key}`),
    );
  }

  // Mint the bundle re-key key only when requested AND there is state to
  // re-key: minting a secret for an empty bundle would hand the operator a
  // key that unlocks nothing.
  const minted =
    opts.mintStateRekeyKey && entries.length > 0
      ? mintSourceCustody(opts.masterKey)
      : undefined;

  // DETECTION is unconditional; EMBEDDING is entries-gated. Reading the marker
  // for every export is what makes the A3 refusal below fire on an empty
  // fortress too: an entries-gated READ let a zero-entry export (empty
  // fortress, or a partition that withheld everything) sail past a CORRUPT
  // marker and sign an artifact asserting the legacy params are ABSENT, which
  // is source-metadata corruption hidden at the worst possible moment. The
  // embed stays gated because an empty bundle has nothing to re-key, so
  // shipping the fortress's Argon2id salt + cost profile with it is gratuitous
  // (symmetric with `source_custody`, entries-gated above via `minted`).
  const keyParams: SourceKeyParamsRead = await readSourceKeyParams(opts.storage);
  // INVARIANT (A3): _meta/key-params is untrusted bytes until shape-checked.
  // Whatever passes this gate is embedded VERBATIM in encrypted_state.json and
  // pinned by the Ed25519-signed manifest, so a malformed marker here becomes a
  // signed re-key path that NO import can use. Malformed => structured throw at
  // export; never embed unvalidated, never silently omit (hard constraint 5).
  if (keyParams.state === "malformed") {
    await opts.auditLog.appendCritical({
      layer: "l1",
      operation: EXIT_EXPORT_REFUSED_MALFORMED_KDF_MARKER_OP,
      identity_id: opts.identityManager.getDefault()?.identity_id ?? "unknown",
      result: "failure",
      details: { reason: keyParams.reason },
    });
    throw new Error(
      "exit-bundle: refusing to export. The fortress's legacy re-key marker at " +
        `_meta/key-params is malformed (${keyParams.reason}). Embedding it would ` +
        "produce a cryptographically valid, signed bundle whose legacy re-key " +
        "path no import can ever use, and the failure would only surface after " +
        "the source fortress is gone. Repair the marker, or - if this is an " +
        "envelope-custody fortress where the marker is vestigial - remove " +
        "_meta/key-params and re-export; the authoritative re-key path is the " +
        "bundle re-key key printed at export.",
    );
  }

  // INVARIANT (A8): a zero-entry artifact MUST name why it is empty. The signed
  // manifest covers an empty artifact exactly as a full one, so without this
  // marker verify/import cannot distinguish "fortress was empty" from "an export
  // bug dropped everything". Enum, not free text; a zero-entry artifact WITHOUT
  // this marker is downstream evidence of a pre-marker or buggy exporter.
  const emptyReason: ExitEmptyReason | undefined =
    entries.length > 0
      ? undefined
      : collected.length > 0
        ? EXIT_EMPTY_REASONS.PARTITION_EXCLUDED_ALL
        : EXIT_EMPTY_REASONS.FORTRESS_STATE_EMPTY;

  return {
    bundle: {
      format: "SANCTUARY_EXIT_ENCRYPTED_STATE_V1",
      exported_at: exportedAt,
      key_source: opts.keySource ?? "unknown",
      ownership_partitioned: opts.memoryClassPartition !== undefined,
      ...(emptyReason !== undefined ? { empty_reason: emptyReason } : {}),
      // The entries-gate that used to sit on the READ (see the A3 detection
      // note above) lives here instead: an empty bundle has nothing to re-key,
      // so it must not carry the fortress's Argon2id salt + cost profile.
      ...(entries.length > 0 && keyParams.state === "ok"
        ? { source_key_derivation: keyParams.params }
        : {}),
      ...(minted !== undefined ? { source_custody: minted.custody } : {}),
      namespaces: [...new Set(entries.map((entry) => entry.namespace))].sort(),
      total_keys: entries.length,
      contains_reserved_namespaces: false,
      entries,
    },
    ...(minted !== undefined ? { rekeyKey: minted.rekeyKey } : {}),
    ...(partition !== undefined ? { partition } : {}),
  };
}

function exportPublicIdentity(
  identity: StoredIdentity,
  masterKey: Uint8Array,
  exportedAt: string,
): ExitPublicIdentityArtifact {
  const body: ExitPublicIdentityArtifact["bundle"] = {
    format: "SANCTUARY_IDENTITY_BUNDLE_V1",
    publicKey: identity.public_key,
    did: identity.did,
    identity_id: identity.identity_id,
    label: identity.label,
    key_type: identity.key_type,
    key_protection: identity.key_protection,
    rotation_history: identity.rotation_history ?? [],
    exported_at: exportedAt,
  };
  const signature = identitySign(
    canonicalizeToBytes(body),
    identity.encrypted_private_key,
    derivePurposeKey(masterKey, "identity-encryption")
  );
  return {
    bundle: body,
    signature: toBase64url(signature),
    signed_by: identity.did,
  };
}

function redactedPolicy(policy: PrincipalPolicy): PrincipalPolicy {
  return {
    ...policy,
    approval_channel: {
      type: policy.approval_channel.type,
      timeout_seconds: policy.approval_channel.timeout_seconds,
      webhook_url: policy.approval_channel.webhook_url,
    },
  };
}

function exportPolicySet(
  policy: PrincipalPolicy,
  config: SanctuaryConfig | undefined,
  exportedAt: string,
): ExitPolicySetArtifact {
  const cfg = config ?? defaultConfig();

  return {
    format: "SANCTUARY_EXIT_POLICY_SET_V1",
    exported_at: exportedAt,
    principal_policy: redactedPolicy(policy),
    config_summary: {
      version: cfg.version,
      state: cfg.state,
      execution: cfg.execution,
      disclosure: cfg.disclosure,
      reputation: cfg.reputation,
      privacy_filter: cfg.privacy_filter,
    },
  };
}

async function exportAuditReceipts(
  auditLog: AuditLog,
  cap: number,
  exportedAt: string,
): Promise<{ artifact: ExitAuditReceiptsArtifact; warning?: string }> {
  await auditLog.flush();
  const result = await auditLog.query({ limit: cap });
  // `total` is the full post-filter population; `entries` is the most-recent
  // `cap`-sized slice. When the population exceeds the cap the oldest entries
  // are dropped - mark it honestly so the artifact's `total` does not silently
  // overclaim completeness against `entries.length` (NEVER #5: no silent
  // degrade; the flagship "you control your data" pillar).
  const omitted = result.total - result.entries.length;
  const truncated = omitted > 0;
  const artifact: ExitAuditReceiptsArtifact = {
    format: "SANCTUARY_AUDIT_RECEIPTS_V1",
    exported_at: exportedAt,
    total: result.total,
    recovery_semantics: "archive_only",
    normal_audit_query_continuity: false,
    individual_entry_signatures: false,
    ...(truncated ? { truncated: true, omitted_count: omitted } : {}),
    entries: result.entries,
  };
  const warning = truncated
    ? `audit export carried ${result.entries.length} of ${result.total} ` +
      `entries; the oldest ${omitted} were omitted by the ${cap}-entry export cap`
    : undefined;
  return { artifact, ...(warning !== undefined ? { warning } : {}) };
}

async function exportCommitments(
  storage: StorageBackend,
  masterKey: Uint8Array,
  exportedAt: string,
): Promise<ExitCommitmentsArtifact> {
  const encryptionKey = derivePurposeKey(masterKey, "l3-commitments");
  const publicCommitments: ExitCommitmentsArtifact["public_commitments"] = [];
  let unreadable = 0;
  for (const meta of await storage.list("_commitments")) {
    const raw = await storage.read("_commitments", meta.key);
    if (!raw) continue;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      const decrypted = decrypt(encrypted, encryptionKey);
      const parsed = JSON.parse(bytesToString(decrypted)) as {
        commitment: string;
        committed_at: string;
        revealed: boolean;
        revealed_at?: string;
      };
      publicCommitments.push({
        commitment_id: meta.key,
        commitment: parsed.commitment,
        committed_at: parsed.committed_at,
        revealed: parsed.revealed,
        revealed_at: parsed.revealed_at,
      });
    } catch {
      unreadable++;
    }
  }
  return {
    format: "SANCTUARY_EXIT_COMMITMENTS_V1",
    exported_at: exportedAt,
    public_commitments: publicCommitments,
    unreadable_count: unreadable,
    redacted_fields: ["value", "blinding_factor"],
  };
}

async function exportPlaceholderVaultMetadata(
  storage: StorageBackend,
  masterKey: Uint8Array,
  exportedAt: string,
): Promise<ExitPlaceholderVaultMetadataArtifact> {
  const encryptionKey = derivePurposeKey(masterKey, "l2-privacy-placeholders");
  const entries: Array<Record<string, unknown>> = [];
  let unreadable = 0;
  for (const meta of await storage.list(PRIVACY_PLACEHOLDER_NAMESPACE)) {
    const raw = await storage.read(PRIVACY_PLACEHOLDER_NAMESPACE, meta.key);
    if (!raw) continue;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      const decrypted = decrypt(encrypted, encryptionKey);
      const parsed = JSON.parse(bytesToString(decrypted)) as Record<string, unknown>;
      const safe: Record<string, unknown> = {
        key: meta.key,
        version: parsed.version,
        kind: parsed.kind ?? (meta.key.endsWith("__index") ? "index" : "metadata"),
        scope: parsed.scope,
        class: parsed.class,
        placeholder: parsed.placeholder,
        alias: parsed.alias,
        raw_hash: parsed.raw_hash,
        counters: parsed.counters,
        next: parsed.next,
        created_at: parsed.created_at,
      };
      entries.push(
        Object.fromEntries(
          Object.entries(safe).filter(([, value]) => value !== undefined)
        )
      );
    } catch {
      unreadable++;
    }
  }
  return {
    format: "SANCTUARY_PLACEHOLDER_VAULT_METADATA_V1",
    exported_at: exportedAt,
    entries,
    unreadable_count: unreadable,
    redacted_fields: ["raw_value", "raw_path"],
  };
}

export async function exportExitBundle(
  opts: ExportExitBundleOptions
): Promise<ExportExitBundleResult> {
  // INVARIANT: manifest `exported_at` is the did:web assertion time, so
  // deterministic callers pin it here instead of comparing historical keys
  // against the real wall clock. The `Date` is read exactly once and reused
  // (see `exportApprovalAuditId` below) - a second ambient `Date.now()` read
  // anywhere else in this function would reintroduce non-determinism even
  // when the caller injects `now`.
  const exportClock = opts.now ?? (() => new Date());
  const exportedAtDate = exportClock();
  const exportedAt = exportedAtDate.toISOString();
  // INVARIANT (A9): every option-shape refusal fires BEFORE the first side
  // effect (mkdir / audit append / artifact write). A throw after
  // public_identity.json lands leaves a partial, unsigned artifact directory a
  // later run may mistake for a bundle. There are exactly three such refusals
  // and both statements below run before the first `mkdir`:
  // `assertExportOptionsShape` (the empty-stateNamespaces and the
  // partition/legacy-opt-out XOR) and `validateExportDidWeb` (the did:web
  // shape + host-agreement checks). Both are pure functions of `opts`. The
  // identical checks deeper in exportEncryptedState are retained as defense in
  // depth for any future direct caller of that function.
  assertExportOptionsShape(opts);
  // Recognition-Layer Path C primary build 2: validate + embed the
  // did:web pointer when the caller supplied one. Two structural
  // checks before embedding so a malformed binding fails loudly at
  // export rather than at the receiving regime's resolver:
  //
  //   1. `identifier` parses as a did:web URI under the supplied
  //      `authority_host` (`parseDidWeb` throws on shape mismatch).
  //   2. The parsed `authority_host` matches `binding.authority_host`
  //      (defends against an operator typo where the URI's host and
  //      the published host diverge).
  //
  // Pubkey match is the import-side verifier's job: the receiving
  // regime is the one that benefits from confirming the operator's
  // claimed pubkey matches the resolved DID Document. The export
  // side does not re-fetch the published document; it embeds the
  // pointer the operator declared.
  const didWebBinding = validateExportDidWeb(opts.didWeb);
  const bundleDir = resolve(opts.bundleDir);
  await mkdir(bundleDir, { recursive: true, mode: 0o700 });
  await mkdir(join(bundleDir, ARTIFACT_DIR), { recursive: true, mode: 0o700 });

  const identity = opts.identityManager.getDefault();
  if (!identity) {
    throw new Error("Cannot export exit bundle: no default identity exists.");
  }

  // INVARIANT: the fallback audit id's timestamp is derived from the SAME
  // captured `exportedAtDate` (the injected `now` seam when the caller
  // supplies one) rather than a fresh `Date.now()` read. This id lands
  // unchanged in the SIGNED manifest body as `export_approval_audit_id`
  // below; a second, uncaptured wall-clock read here would make the signed
  // manifest non-reproducible across two runs even when the export clock is
  // pinned for determinism.
  const exportApprovalAuditId =
    opts.exportApprovalAuditId ?? `exit-export-${exportedAtDate.getTime()}`;
  void opts.auditLog.append("l1", "exit_bundle_export", identity.identity_id, {
    approval_id: exportApprovalAuditId,
    manifest_version: EXIT_BUNDLE_MANIFEST_VERSION,
  });

  const reputationStore =
    opts.reputationStore ?? new ReputationStore(opts.storage, opts.masterKey);
  const identityEncryptionKey = derivePurposeKey(opts.masterKey, "identity-encryption");

  const artifacts: ExitBundleArtifactEntry[] = [];
  const exportWarnings: string[] = [];
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/public_identity.json`,
      exportPublicIdentity(identity, opts.masterKey, exportedAt),
      "public_identity"
    )
  );
  const encryptedStateExport = await exportEncryptedState(opts, exportedAt);
  // A zero-entry export is a legitimate outcome for a fresh fortress, but it
  // must never READ as a successful state export: the bundle still carries a
  // valid signed manifest and an `encrypted_state.json`, so an operator running
  // an exit drill cannot tell an empty fortress from a broken selection by
  // looking at the bundle. Say it out loud on every surface (result warning,
  // audit trail, CLI) rather than letting the silence imply success.
  if (encryptedStateExport.bundle.total_keys === 0) {
    exportWarnings.push(
      "NO STATE EXPORTED: this bundle carries zero state entries. It can " +
        "restore identity, policy, and audit receipts, but no memory or " +
        "namespace data. Confirm the source fortress is genuinely empty " +
        "before treating this bundle as a complete exit.",
    );
  }
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/encrypted_state.json`,
      encryptedStateExport.bundle,
      "encrypted_state"
    )
  );
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/policy_set.json`,
      exportPolicySet(opts.policy, opts.config, exportedAt),
      "policy_set"
    )
  );
  const auditReceiptsExport = await exportAuditReceipts(
    opts.auditLog,
    opts.auditReceiptsExportCap ?? EXIT_AUDIT_RECEIPTS_EXPORT_CAP,
    exportedAt,
  );
  if (auditReceiptsExport.warning !== undefined) {
    exportWarnings.push(auditReceiptsExport.warning);
  }
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/audit_receipts.json`,
      auditReceiptsExport.artifact,
      "audit_receipts"
    )
  );
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/reputation_bundle.json`,
      await reputationStore.exportBundle(identity, identityEncryptionKey),
      "reputation_bundle"
    )
  );
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/commitments.json`,
      await exportCommitments(opts.storage, opts.masterKey, exportedAt),
      "commitments"
    )
  );
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/placeholder_vault_metadata.json`,
      await exportPlaceholderVaultMetadata(opts.storage, opts.masterKey, exportedAt),
      "placeholder_vault_metadata"
    )
  );

  // `didWebBinding` was validated at the top of this function, before the
  // first side effect (A9), and is embedded here unchanged.
  const body: ExitBundleManifestBody = {
    manifest_version: EXIT_BUNDLE_MANIFEST_VERSION,
    exported_at: exportedAt,
    identity_binding: {
      identity_id: identity.identity_id,
      fortress_id: identity.did,
      fortress_master_pubkey: identity.public_key,
      did: identity.did,
      ...(didWebBinding !== undefined ? { did_web: didWebBinding } : {}),
    },
    source_sanctuary_version: opts.config?.version ?? SANCTUARY_VERSION,
    artifacts,
    artifacts_aggregate_hash: sha256Hex(
      stringToBytes(canonicalize(artifacts))
    ),
    artifacts_aggregate_hash_alg: "sha256",
    export_approval_audit_id: exportApprovalAuditId,
    signature_scheme: SIGNATURE_SCHEME_V1,
  };
  const signature = identitySign(
    canonicalizeToBytes(body),
    identity.encrypted_private_key,
    identityEncryptionKey
  );
  const manifest: ExitBundleManifest = {
    body,
    signature: toBase64url(signature),
  };
  const manifestBytes = jsonBytes(manifest);
  await writeFile(join(bundleDir, "manifest.json"), manifestBytes, { mode: 0o600 });

  // Recognition-Layer Path C primary build 2: audit-emit the
  // did:web inclusion. Fires only when the body embedded the
  // binding; absent-binding bundles emit nothing (backward-compat
  // for tooling that filters on this op).
  if (didWebBinding !== undefined) {
    void opts.auditLog.append(
      "l1",
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.EXPORT_INCLUDED,
      identity.identity_id,
      {
        approval_id: exportApprovalAuditId,
        identifier: didWebBinding.identifier,
        authority_host: didWebBinding.authority_host,
      },
    );
  }
  if (encryptedStateExport.partition !== undefined) {
    const partitionSummary = summarizePartition(encryptedStateExport.partition);
    void opts.auditLog.append(
      "l1",
      "exit_bundle_state_partition",
      identity.identity_id,
      {
        approval_id: exportApprovalAuditId,
        state_partition: partitionSummary,
      },
    );
  }
  // Honesty marker also lands in the audit trail when the export cap dropped
  // the oldest receipts, so the truncation is recorded where the operator
  // queries it, not just in the carried artifact.
  if (auditReceiptsExport.warning !== undefined) {
    void opts.auditLog.append(
      "l1",
      "exit_bundle_audit_receipts_truncated",
      identity.identity_id,
      {
        approval_id: exportApprovalAuditId,
        carried: auditReceiptsExport.artifact.entries.length,
        total: auditReceiptsExport.artifact.total,
        omitted_count: auditReceiptsExport.artifact.omitted_count ?? 0,
      },
    );
  }
  // Same honesty posture for a zero-state export: record it where an exit-drill
  // operator queries after the fact, so "the bundle was empty" is provable from
  // the source fortress rather than only inferable from the bundle.
  //
  // `appendCritical` and AWAITED, not `void append(...)`: `append`'s own
  // contract reserves itself for low-risk telemetry and states that export/exit
  // operations MUST use `appendCritical()`. The await is part of that contract,
  // not style. Even though critical writes are also tracked for shutdown
  // flushes, this export must fail at the local durability boundary if the
  // zero-state evidence cannot be persisted (never silently degrade,
  // AGENTS.md #5).
  if (encryptedStateExport.bundle.total_keys === 0) {
    await opts.auditLog.appendCritical({
      layer: "l1",
      operation: "exit_bundle_export_no_state",
      identity_id: identity.identity_id,
      result: "success",
      details: {
        approval_id: exportApprovalAuditId,
        namespaces_requested: opts.stateNamespaces ?? null,
        state_storage_path_supplied: opts.stateStoragePath !== undefined,
      },
    });
  }
  // Still required and still correct after the change above: the zero-state
  // entry is already durably verified by the time control reaches here, so this
  // flush is draining the sibling `void append(...)` calls (partition summary,
  // receipts truncation) and the append queue. Same order as
  // exit/consent.ts: appendCritical, then flush.
  await opts.auditLog.flush();

  const statePartitionSummary =
    encryptedStateExport.partition !== undefined
      ? summarizePartition(encryptedStateExport.partition)
      : undefined;

  return {
    bundle_dir: bundleDir,
    manifest,
    manifest_hash: sha256Hex(manifestBytes),
    artifact_count: artifacts.length,
    unsupported_artifacts: [
      "audit_receipts: legacy L2 audit entries are manifest-pinned but not individually signed",
    ],
    state_entry_count: encryptedStateExport.bundle.total_keys,
    ...(encryptedStateExport.rekeyKey !== undefined
      ? { state_rekey_key: encryptedStateExport.rekeyKey }
      : {}),
    ...(statePartitionSummary !== undefined
      ? { state_partition: statePartitionSummary }
      : {}),
    ...(exportWarnings.length > 0 ? { warnings: exportWarnings } : {}),
  };
}

function summarizePartition(partition: PartitionResult): ExportExitBundleResult["state_partition"] {
  return {
    included: partition.includable.length,
    excluded: partition.excluded.length,
    excluded_unstamped: partition.excluded.filter(
      (decision) => decision.reason === "unstamped_defaulted_operator_owned",
    ).length,
    excluded_unsealed: partition.excluded.filter(
      (decision) =>
        decision.reason === "unsealed_stamp_defaulted_operator_owned" ||
        decision.reason === "stamp_binding_mismatch_defaulted_operator_owned",
    ).length,
  };
}

/**
 * Validate + normalize the did:web binding supplied to the export
 * options. Returns undefined when the caller did not supply a binding,
 * the normalized binding otherwise. Throws Error on a binding that
 * fails the export-side shape checks (parse, authority-host
 * coherence).
 */
function validateExportDidWeb(
  binding: ExitBundleDidWebBinding | undefined,
): ExitBundleDidWebBinding | undefined {
  if (binding === undefined) return undefined;
  if (!binding.identifier || typeof binding.identifier !== "string") {
    throw new Error(
      "exit-bundle: did_web.identifier must be a non-empty did:web URI",
    );
  }
  if (!binding.authority_host || typeof binding.authority_host !== "string") {
    throw new Error(
      "exit-bundle: did_web.authority_host must be a non-empty DNS host",
    );
  }
  // parseDidWeb throws on malformed input; we let that error
  // propagate verbatim so the operator sees the foundation-side
  // validation message.
  const parsed = parseDidWeb(binding.identifier);
  if (parsed.authority_host.toLowerCase() !== binding.authority_host.toLowerCase()) {
    throw new Error(
      `exit-bundle: did_web.identifier authority host '${describeUntrusted(parsed.authority_host)}' does not match did_web.authority_host '${binding.authority_host}'`,
    );
  }
  return {
    identifier: binding.identifier,
    authority_host: binding.authority_host,
    ...(binding.published_at !== undefined
      ? { published_at: binding.published_at }
      : {}),
  };
}

interface SourceIdentityPublicKeyCandidate {
  publicKey: Uint8Array;
  source: "current" | "retired";
  retiredIndex?: number;
  compromised: boolean;
}

type IdentityPublicKeyResolution =
  | {
      status: "verified";
      byIdentityId: Map<string, SourceIdentityPublicKeyCandidate[]>;
      byDid: Map<string, Uint8Array>;
      chain: VerifiedRotationChain;
    }
  | {
      status: "invalid";
      reason: RotationChainInvalidReason;
      detail: string;
      identityId: string;
      hopCount: number;
    };

function publicKeysFromIdentityArtifact(
  identityArtifact: ExitPublicIdentityArtifact
): IdentityPublicKeyResolution {
  const chainResult = verifyRotationChain({
    identityId: identityArtifact.bundle.identity_id,
    currentPublicKey: identityArtifact.bundle.publicKey,
    rotationHistory: identityArtifact.bundle.rotation_history,
  });
  if (chainResult.status !== "verified") {
    return {
      status: "invalid",
      reason: chainResult.reason,
      detail: chainResult.detail,
      identityId: identityArtifact.bundle.identity_id,
      hopCount: Array.isArray(identityArtifact.bundle.rotation_history)
        ? identityArtifact.bundle.rotation_history.length
        : 0,
    };
  }

  const candidates: SourceIdentityPublicKeyCandidate[] = [
    {
      publicKey: chainResult.chain.current_public_key,
      source: "current",
      compromised: false,
    },
    ...chainResult.chain.retired.map((retired, index) => ({
      publicKey: retired.public_key,
      source: "retired" as const,
      retiredIndex: index + 1,
      compromised: retired.compromised,
    })),
  ];
  const byDid = new Map<string, Uint8Array>([
    [identityArtifact.bundle.did, chainResult.chain.current_public_key],
  ]);
  for (const retired of chainResult.chain.retired) {
    byDid.set(publicKeyToDid(retired.public_key), retired.public_key);
  }
  return {
    status: "verified",
    byIdentityId: new Map([[identityArtifact.bundle.identity_id, candidates]]),
    byDid,
    chain: chainResult.chain,
  };
}

function rotationChainRefusalMessage(
  result: Extract<IdentityPublicKeyResolution, { status: "invalid" }>
): string {
  return (
    `rotation chain unverifiable for identity ${result.identityId}: ` +
    `${result.reason} (${result.detail}; hop_count=${result.hopCount}). ` +
    "Keep the source fortress intact and re-export after verifying its identity " +
    "rotation history."
  );
}

function compromisedRetiredSignatureUse(
  encryptedState: ExitEncryptedStateBundle | null,
  publicKeysByIdentityId: Map<string, SourceIdentityPublicKeyCandidate[]>
): { count: number; firstRetiredIndex?: number } {
  let count = 0;
  let firstRetiredIndex: number | undefined;
  for (const item of encryptedState?.entries ?? []) {
    // RESERVED-NS-DIVERGE-01: `isReservedNamespace` applies the blanket
    // underscore rule on its own, so no separate `startsWith("_")` is needed.
    if (isReservedNamespace(item.namespace)) {
      continue;
    }
    const candidates = publicKeysByIdentityId.get(item.entry.kid) ?? [];
    if (candidates.length === 0) continue;
    let payload: Uint8Array;
    let signature: Uint8Array;
    try {
      payload = fromBase64url(item.entry.payload.ct);
      signature = fromBase64url(item.entry.sig);
    } catch {
      continue;
    }
    const matching = candidates.filter((candidate) =>
      identityVerify(payload, signature, candidate.publicKey)
    );
    if (matching.some((candidate) => candidate.compromised)) {
      const acceptedByNonCompromised = matching.some(
        (candidate) => !candidate.compromised
      );
      if (!acceptedByNonCompromised) {
        count++;
        firstRetiredIndex ??= matching.find((candidate) => candidate.compromised)
          ?.retiredIndex;
      }
    }
  }
  return firstRetiredIndex === undefined ? { count } : { count, firstRetiredIndex };
}

async function conflictReport(
  storage: StorageBackend,
  identityArtifact: ExitPublicIdentityArtifact | null,
  encryptedState: ExitEncryptedStateBundle | null,
  reputationBundle: ReputationBundle | null,
  manifest: ExitBundleManifest
): Promise<ExitBundleConflictReport> {
  const stateConflicts: Array<{ namespace: string; key: string }> = [];
  for (const item of encryptedState?.entries ?? []) {
    if (await storage.exists(item.namespace, item.key)) {
      stateConflicts.push({ namespace: item.namespace, key: item.key });
    }
  }
  const reputationConflicts: string[] = [];
  for (const attestation of reputationBundle?.attestations ?? []) {
    if (await storage.exists("_reputation", attestation.attestation_id)) {
      reputationConflicts.push(attestation.attestation_id);
    }
  }
  const importId = importIdForManifest(manifest);
  return {
    public_identity_exists: identityArtifact
      ? await storage.exists(
          EXIT_PUBLIC_IDENTITIES_NAMESPACE,
          identityArtifact.bundle.identity_id
        )
      : false,
    state_conflicts: stateConflicts,
    reputation_conflicts: reputationConflicts,
    policy_set_exists: await storage.exists(EXIT_POLICY_SETS_NAMESPACE, importId),
    audit_receipts_exist: await storage.exists(EXIT_AUDIT_RECEIPTS_NAMESPACE, importId),
    commitments_exist: await storage.exists(EXIT_COMMITMENTS_NAMESPACE, importId),
    import_record_exists: await storage.exists(EXIT_IMPORT_NAMESPACE, importId),
  };
}

function stagedArtifactConflicts(
  conflicts: ExitBundleConflictReport,
  importId: string,
): Array<{ namespace: string; key: string }> {
  const artifactConflicts: Array<{ namespace: string; key: string }> = [];
  if (conflicts.policy_set_exists) {
    artifactConflicts.push({ namespace: EXIT_POLICY_SETS_NAMESPACE, key: importId });
  }
  if (conflicts.audit_receipts_exist) {
    artifactConflicts.push({ namespace: EXIT_AUDIT_RECEIPTS_NAMESPACE, key: importId });
  }
  if (conflicts.commitments_exist) {
    artifactConflicts.push({ namespace: EXIT_COMMITMENTS_NAMESPACE, key: importId });
  }
  if (conflicts.import_record_exists) {
    artifactConflicts.push({ namespace: EXIT_IMPORT_NAMESPACE, key: importId });
  }
  return artifactConflicts;
}

function importIdForManifest(manifest: ExitBundleManifest): string {
  return `${manifest.body.identity_binding.identity_id}-${manifest.body.exported_at.replace(/[^0-9a-zA-Z_.-]/g, "_")}`;
}

/**
 * Shape-check a bundle's `source_custody` block before any wrap is tried.
 * A crafted or corrupted block fails closed with a structured error rather
 * than being silently ignored (which would demote the import to the legacy
 * derivation path - a downgrade, #5).
 *
 * INVARIANT: the block-level rules and the per-wrap payload rule are quantified
 * DIFFERENTLY, and the asymmetry is load-bearing rather than an oversight.
 * `unwrapMatchingWrap` (server/src/core/master-custody.ts) walks the wraps in
 * order, catches each wrap's failure individually, and returns on the FIRST
 * that authenticates, so a block carrying one intact wrap beside one damaged
 * wrap IS importable. `isValidSourceCustody` therefore requires the structural
 * and security rules of EVERY wrap but an openable payload from only SOME wrap.
 *
 * FAILURE MODE if this drifts: promoting the payload rule to EVERY reads as
 * harmless hardening in review, passes every test written against a
 * single-wrap bundle, and silently converts "imports fine" into
 * SOURCE_CUSTODY_MALFORMED for a mixed block - on the exit path, where the
 * source fortress may already be gone and a refusal is unrecoverable. It was
 * shipped once and reverted. The regression tests that hold it are the mixed
 * intact/damaged wrap rows of the custody differential in
 * server/test/exit/exit-inspect-declares.test.ts and the import-tolerance case
 * in server/test/exit/exit-credential-path.test.ts.
 *
 * CONTRACT PIN (server/src/exit/source-custody.ts `isValidSourceCustody`): the
 * rules live in that one predicate, which the verifier's
 * `summarizeEncryptedState` also classifies through, so `exit inspect` can
 * never describe a block this gate would refuse.
 */
function validateSourceCustody(custody: ExitSourceCustody): void {
  if (!isValidSourceCustody(custody)) {
    throw new ExitBundleImportError(
      "SOURCE_CUSTODY_MALFORMED",
      "This bundle's source_custody block is malformed or carries a wrap type " +
        "that may not travel in an exit bundle. Refusing to fall back to legacy " +
        "key derivation. Re-export the bundle from the source fortress."
    );
  }
}

function decodeSourceRecoveryKey(sourceRecoveryKey: string): Uint8Array {
  const key = fromBase64url(sourceRecoveryKey);
  // 32 = the 256-bit recovery key minted by `generateRandomKey()`. The SOURCE
  // fortress's recovery key, so the width must match `decodeRecoveryKey` in
  // `core/master-custody.ts`. Symmetric material, not an Ed25519 key.
  if (key.length !== 32) {
    throw new Error("Source recovery key must decode to 32 bytes.");
  }
  return key;
}

/**
 * Recover the SOURCE fortress master for state re-key.
 *
 * Precedence:
 *  1. An explicit `sourceMasterKey` (programmatic callers, tests).
 *  2. Passphrase + legacy `source_key_derivation`: the explicit legacy path
 *     (`master = Argon2id(passphrase, params)`, pre-envelope semantics).
 *     Kept for migrated fortresses, whose bundles carry the legacy params
 *     by design; the params are shape/cost-checked first
 *     (SOURCE_KDF_PARAMS_MALFORMED), and a wrong passphrase is caught by the
 *     all-entries-failed check in `rekeyState` (SOURCE_KEY_MISMATCH).
 *  3. Passphrase WITHOUT legacy params: fails closed. Envelope-era bundles
 *     deliberately carry no passphrase-checkable material (no offline
 *     oracle), so a passphrase cannot re-key them - the error points the
 *     operator at the bundle re-key key. No silent staging, no fallback.
 *  4. Recovery key + `source_custody`: the bundle re-key key minted at
 *     export, GCM-authenticated against the embedded wrap. A key that
 *     unwraps nothing FAILS CLOSED with `SOURCE_CREDENTIAL_INVALID` -
 *     never falls through to the legacy raw-key path (that would silently
 *     treat an arbitrary 32 bytes as the master and drop every entry).
 *  5. Recovery key on a bundle with NO `source_custody`: AMBIGUOUS, and
 *     refused by default (`SOURCE_RECOVERY_KEY_AMBIGUOUS`). The pre-envelope
 *     semantics (the recovery key IS the master) run only under the explicit
 *     `legacyRecoveryKeyIsMaster` opt-in, and a wrong key there is still
 *     mismatch-checked in `rekeyState`.
 *
 * The recovered master is transient: it only decrypts bundle entries, which
 * are immediately re-encrypted and re-signed under the DESTINATION
 * fortress's custody (whose master is established exclusively by
 * `establishMaster` - import has no parallel establishment path).
 */
async function resolveSourceMasterKey(
  encryptedState: ExitEncryptedStateBundle | null,
  opts: ImportExitBundleOptions
): Promise<Uint8Array | null> {
  // LD2-01 (extended by EXIT-STRUCT-02, one level deeper): `encryptedState`
  // is an unchecked cast of parsed, untrusted JSON
  // (`loadExitArtifact<ExitEncryptedStateBundle>` in the caller) — its
  // `entries` field is declared non-optional and its element shape
  // (`namespace`/`key`/`entry.kid`/`entry.payload.ct`/`entry.sig`) is
  // declared non-optional too, but NEITHER is runtime-guaranteed: `entries`
  // may not be an array at all (LD2-01), or it may be an array containing a
  // `null` or otherwise malformed element (EXIT-STRUCT-02).
  // `importExitBundle` already refuses both shapes with the same typed
  // error before calling in (see the LD2-01/EXIT-STRUCT-02 comment at its
  // call site), so this check is defense in depth for any other caller
  // reaching this function: fail closed with a named error, never a raw
  // TypeError. `isWellFormedExitStateEntryElement` is the SAME predicate
  // that call site and `verifier.ts` `summarizeEncryptedState` use, so
  // "malformed" means the same thing in all three places.
  if (
    encryptedState &&
    (!Array.isArray(encryptedState.entries) ||
      encryptedState.entries.some((item) => !isWellFormedExitStateEntryElement(item)))
  ) {
    throw new ExitBundleImportError(
      "ENCRYPTED_STATE_ENTRIES_UNREADABLE",
      "This bundle's encrypted_state artifact has no readable entries list " +
        "(the `entries` field is absent or is not an array), or its entries " +
        "list contains a malformed element (missing or wrong-typed " +
        "namespace/key/entry fields). This is not an empty bundle: the " +
        "entry list itself cannot be read. Re-export the bundle from the " +
        "source fortress."
    );
  }
  if (!encryptedState || encryptedState.entries.length === 0) return null;
  // This return precedes `validateSourceCustody` deliberately: a caller who
  // already holds the source master needs no re-key material at all, so a
  // damaged `source_custody` block is irrelevant to them. There is no CLI flag
  // for it (see the import branch of `cli.ts`), so only a programmatic caller
  // reaches it.
  if (opts.sourceMasterKey) return opts.sourceMasterKey;

  const sourceCustody = encryptedState.source_custody;
  if (sourceCustody !== undefined) validateSourceCustody(sourceCustody);

  if (opts.sourcePassphrase) {
    if (encryptedState.source_key_derivation) {
      // INVARIANT (A3): bundle-carried KDF params are attacker-influenceable
      // input to Argon2id. Shape + cost bounds are enforced here, at the single
      // site that feeds them to deriveMasterKey; out-of-bounds params fail
      // closed with SOURCE_KDF_PARAMS_MALFORMED rather than burning unbounded
      // memory or deriving a garbage master that dies later as
      // SOURCE_KEY_MISMATCH. CONTRACT PIN (server/src/core/key-derivation.ts
      // parseKeyDerivationParams): same validator as the export embed-gate.
      const checked = parseKeyDerivationParams(
        encryptedState.source_key_derivation
      );
      if (!checked.ok) {
        throw new ExitBundleImportError(
          "SOURCE_KDF_PARAMS_MALFORMED",
          "This bundle's legacy re-key parameters (source_key_derivation) are " +
            `unusable: ${checked.reason}. A passphrase cannot recover the source ` +
            "master from them, and Sanctuary will not run a key derivation on " +
            "parameters it cannot validate. Re-export the bundle from the source " +
            "fortress, or supply the source master key programmatically.",
        );
      }
      return (await deriveMasterKey(opts.sourcePassphrase, checked.params)).key;
    }
    if (sourceCustody !== undefined) {
      throw new ExitBundleImportError(
        "SOURCE_PASSPHRASE_UNSUPPORTED",
        "This bundle's state cannot be re-keyed with a passphrase: it was " +
          "exported from an envelope-custody fortress, and bundles deliberately " +
          "carry no passphrase-checkable material (that would be an offline " +
          "guessing oracle). Supply the bundle re-key key that was displayed " +
          "when the bundle was exported: --source-recovery-key <key>."
      );
    }
    throw new ExitBundleImportError(
      "SOURCE_KEY_UNAVAILABLE",
      "A source passphrase was supplied, but this bundle carries neither a " +
        "source_custody block nor legacy key-derivation parameters, so the " +
        "passphrase cannot recover the source master key. Re-export the bundle " +
        "from the source fortress (the export prints a bundle re-key key), or " +
        "supply the source master key programmatically."
    );
  }

  if (opts.sourceRecoveryKey) {
    if (sourceCustody !== undefined) {
      const master = await unwrapMasterFromWraps(sourceCustody.wraps, {
        recoveryKey: decodeSourceRecoveryKey(opts.sourceRecoveryKey),
      });
      if (!master) {
        throw new ExitBundleImportError(
          "SOURCE_CREDENTIAL_INVALID",
          "The supplied key does not unlock this bundle's encrypted state: it " +
            "failed to authenticate against the bundle's re-key wrap. Supply the " +
            "exact bundle re-key key displayed when this bundle was exported " +
            "(--source-recovery-key). Refusing to re-key with an unverified key."
        );
      }
      return master;
    }
    // INVARIANT (A4): a recovery key with NO source_custody block is AMBIGUOUS -
    // either a bundle re-key key aimed at a bundle that cannot use it, or a
    // legacy (pre-envelope) source recovery key that IS the master. Guessing
    // "raw master" silently was how the operator's first signal became a
    // downstream SOURCE_KEY_MISMATCH naming the symptom, never the cause.
    // Refuse by default (symmetric with SOURCE_PASSPHRASE_UNSUPPORTED above);
    // the legacy interpretation requires the explicit
    // legacyRecoveryKeyIsMaster opt-in.
    if (opts.legacyRecoveryKeyIsMaster !== true) {
      throw new ExitBundleImportError(
        "SOURCE_RECOVERY_KEY_AMBIGUOUS",
        "This bundle carries no source_custody block, so the supplied " +
          "--source-recovery-key has two possible meanings and Sanctuary will " +
          "not guess between them. Either (a) it is a BUNDLE RE-KEY KEY from a " +
          "different export and this is the wrong bundle (or a pre-envelope " +
          "one) - in which case re-export from the source fortress and use the " +
          "re-key key that export prints; or (b) this is a LEGACY bundle whose " +
          "fortress used recovery-key custody, where the recovery key IS the " +
          "source master - in which case confirm that interpretation by " +
          "re-running with --legacy-source-master: " +
          "sanctuary exit import <dir> --activate --import-state " +
          "--source-recovery-key <key> --legacy-source-master",
      );
    }
    // Legacy semantics, explicitly confirmed by the operator: the recovery key
    // IS the master. A wrong key is still caught downstream by rekeyState's
    // all-entries-failed SOURCE_KEY_MISMATCH.
    return decodeSourceRecoveryKey(opts.sourceRecoveryKey);
  }

  return null;
}

/**
 * True when the caller supplied ANY source credential, i.e. explicitly asked
 * for the bundle's encrypted state. Mirrors the credentials
 * `resolveSourceMasterKey` accepts; keep the two in step.
 */
function importRequestedSourceCredential(
  opts: ImportExitBundleOptions
): boolean {
  return (
    opts.sourcePassphrase !== undefined ||
    opts.sourceRecoveryKey !== undefined ||
    opts.sourceMasterKey !== undefined
  );
}

/**
 * Operator-facing warning for a zero-entry encrypted_state artifact, keyed on
 * the A8 marker. An ABSENT marker is the louder case: it means a pre-marker or
 * buggy exporter wrote this bundle, so nothing in it distinguishes an empty
 * fortress from an export that dropped everything.
 */
function emptyStateWarning(encryptedState: ExitEncryptedStateBundle): string {
  switch (encryptedState.empty_reason) {
    case EXIT_EMPTY_REASONS.FORTRESS_STATE_EMPTY:
      return (
        "this bundle carries zero state entries and its exporter recorded " +
        `empty_reason=${EXIT_EMPTY_REASONS.FORTRESS_STATE_EMPTY}: the source ` +
        "fortress had no exportable state."
      );
    case EXIT_EMPTY_REASONS.PARTITION_EXCLUDED_ALL:
      return (
        "this bundle carries zero state entries and its exporter recorded " +
        `empty_reason=${EXIT_EMPTY_REASONS.PARTITION_EXCLUDED_ALL}: the source ` +
        "fortress had state, but the ownership partition withheld every entry."
      );
    default:
      return (
        "this bundle carries zero state entries and NO empty_reason marker: it " +
        "was written by a pre-marker (or buggy) exporter, so an empty source " +
        "fortress cannot be distinguished from an export that dropped " +
        "everything. Verify the source fortress before treating this as a " +
        "complete exit."
      );
  }
}

/**
 * A staged artifact location written during importExitBundle. Used to
 * undo partial imports when the re-key handler fails partway through.
 * Hardening wave 6 finding #78.
 */
interface StagedLocation {
  namespace: string;
  key: string;
}

interface StorageSnapshot extends StagedLocation {
  data: Uint8Array | null;
}

interface StorageNamespaceSnapshot {
  namespace: string;
  entries: StorageSnapshot[];
}

function locationDedupeKey(loc: StagedLocation): string {
  return `${loc.namespace.length}:${loc.namespace}${loc.key}`;
}

function dedupeLocations(locations: StagedLocation[]): StagedLocation[] {
  const seen = new Set<string>();
  const deduped: StagedLocation[] = [];
  for (const loc of locations) {
    const key = locationDedupeKey(loc);
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(loc);
  }
  return deduped;
}

async function snapshotStorageLocations(
  storage: StorageBackend,
  locations: StagedLocation[]
): Promise<StorageSnapshot[]> {
  const snapshots: StorageSnapshot[] = [];
  for (const loc of dedupeLocations(locations)) {
    snapshots.push({
      ...loc,
      data: await storage.read(loc.namespace, loc.key),
    });
  }
  return snapshots;
}

// `snapshotStorageNamespace` (whole-namespace snapshot) was removed
// (coordinator gate HIGH finding, 2026-08-22): its restore path deletes
// every key present at restore time that was absent from the snapshot,
// which is imprecise for a durable, possibly-days-later replay - see the
// "PRECISE `_meta` LOCATIONS" comment in `activationSnapshotLocations`.
// `StorageNamespaceSnapshot` / `namespaceSnapshots` plumbing stays in
// `restoreStorageSnapshots` below (always called with `[]` today) so a
// future genuinely-namespace-scoped need does not have to rebuild it.

async function restoreStorageSnapshots(
  storage: StorageBackend,
  snapshots: StorageSnapshot[],
  namespaceSnapshots: StorageNamespaceSnapshot[] = []
): Promise<{
  removed: number;
  restored: number;
  failed: StagedLocation[];
}> {
  let removed = 0;
  let restored = 0;
  const failed: StagedLocation[] = [];
  for (const namespaceSnapshot of namespaceSnapshots) {
    const originalKeys = new Set(
      namespaceSnapshot.entries.map((entry) => entry.key)
    );
    try {
      for (const current of await storage.list(namespaceSnapshot.namespace)) {
        if (originalKeys.has(current.key)) continue;
        try {
          const ok = await storage.delete(
            namespaceSnapshot.namespace,
            current.key
          );
          if (ok) removed++;
        } catch {
          failed.push({
            namespace: namespaceSnapshot.namespace,
            key: current.key,
          });
        }
      }
    } catch {
      failed.push({ namespace: namespaceSnapshot.namespace, key: "*" });
    }
  }

  const allSnapshots = [
    ...snapshots,
    ...namespaceSnapshots.flatMap((snapshot) => snapshot.entries),
  ];
  for (const snapshot of allSnapshots) {
    try {
      if (snapshot.data) {
        await storage.write(snapshot.namespace, snapshot.key, snapshot.data);
        restored++;
      } else {
        const ok = await storage.delete(snapshot.namespace, snapshot.key);
        if (ok) removed++;
      }
    } catch {
      failed.push({ namespace: snapshot.namespace, key: snapshot.key });
    }
  }
  return { removed, restored, failed };
}

/** On-disk (JSON-safe) form of a {@link StorageSnapshot}: `data` base64url'd. */
interface SerializedStorageSnapshot {
  namespace: string;
  key: string;
  data: string | null;
}

interface SerializedStorageNamespaceSnapshot {
  namespace: string;
  entries: SerializedStorageSnapshot[];
}

/**
 * F1 (Exit V2 drill D1, 2026-08-22): the durable record `writeImportJournal`
 * persists and `recoverInterruptedExitImports` replays. Its `snapshots` /
 * `namespace_snapshots` fields are byte-for-byte what `importExitBundle`
 * already computes as `activationSnapshots` / `activationNamespaceSnapshots`
 * before it starts writing - this record is just that same data made
 * durable, so a hard kill and a caught exception roll back through the
 * exact same `restoreStorageSnapshots` call with the exact same input.
 *
 * UNCONDITIONAL RESTORE (coordinator gate finding, 2026-08-22): recovery
 * writes every snapshotted byte back verbatim with no check that the
 * CURRENT bytes at that namespace/key still match what the import
 * actually wrote. Scoped narrow today because every known caller
 * (`importExitBundle`'s own start-of-call recovery, and every fortress-open
 * call site that constructs a masterKey+AuditLog for a real fortress) runs
 * recovery before any OTHER writer has had a chance to touch the same
 * locations - see `recoverInterruptedExitImportsOrThrow`'s doc comment for
 * the call-site inventory and its stated bound. DEBT: if a future caller can
 * legitimately write to a fortress BETWEEN a kill and the next recovery
 * call (a currently-uncovered call site, or a second fortress-owning
 * process), an unconditional restore can clobber a legitimate later write.
 * The fix is to restore a location only where its current on-disk bytes
 * still equal what the import wrote (a hash comparison before each
 * `storage.write`/`storage.delete` in `restoreStorageSnapshots`), not
 * implemented this PR - tracked as follow-up, not silently accepted.
 */
interface ExitImportJournalRecord {
  import_id: string;
  identity_id: string;
  started_at: string;
  snapshots: SerializedStorageSnapshot[];
  namespace_snapshots: SerializedStorageNamespaceSnapshot[];
}

/**
 * CONTRACT PIN (AGENTS.md rule 11 / coordinator gate MEDIUM-4, 2026-08-22):
 * `recoverInterruptedExitImports` used to cast a bare `JSON.parse` result
 * straight to `ExitImportJournalRecord` with no shape check - a journal
 * entry that was itself corrupted (`{}`, a non-string `data` field, a
 * missing array) threw a raw TypeError out of `recoverInterruptedExitImports`,
 * which every fortress-open call site awaits directly, so a single
 * malformed journal entry would have crashed fortress open entirely rather
 * than routing to the named, fail-closed `failed` list. This is the ONE
 * shape check every journal entry passes through before its bytes are
 * trusted.
 */
function isWellFormedSerializedStorageSnapshot(
  value: unknown
): value is SerializedStorageSnapshot {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  if (typeof record.namespace !== "string") return false;
  if (typeof record.key !== "string") return false;
  if (record.data !== null && typeof record.data !== "string") return false;
  return true;
}

function isWellFormedSerializedStorageNamespaceSnapshot(
  value: unknown
): value is SerializedStorageNamespaceSnapshot {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  if (typeof record.namespace !== "string") return false;
  if (!Array.isArray(record.entries)) return false;
  return record.entries.every(isWellFormedSerializedStorageSnapshot);
}

/**
 * CONFINEMENT (Codex gate HIGH finding, 2026-08-22): a journal entry is
 * only ever TRUSTED if every location it names is one `activationSnapshotLocations`
 * could actually have produced for SOME import - the exit staging
 * namespaces (keyed by import id or identity id), `_reputation` (keyed by
 * attestation id), the two named `_meta` keys `StateStore.write` touches,
 * or a non-reserved state namespace (the operator's own data, any key). A
 * journal is read from disk and, short of a MAC, is only as trustworthy as
 * the filesystem it lives on; without this confinement a corrupted or
 * adversarially-written journal entry naming an UNRELATED sensitive
 * location (`_meta/custody-envelope-v1`, an `_audit` entry) would be
 * blindly "restored" by `restoreStorageSnapshots`, which is exactly the
 * kind of write this recovery path must never be tricked into making.
 *
 * BOUND: this is a shape/membership check, not an authenticator - it
 * proves a location is the RIGHT KIND of thing an import writes, not that
 * THIS SPECIFIC journal is the one `importExitBundle` actually wrote. A
 * MAC over the journal record, keyed from the master key (mirroring
 * `state-store.ts`'s version-anchor MAC), would close that gap and is not
 * implemented this PR - a filesystem-level write to `_exit_import_journal`
 * already requires the same access an attacker would need to tamper with
 * every other `_exit_*`/`_reputation`/state file this confinement allows
 * touching anyway, so the bound is narrow, but it is a bound, not zero.
 */
function isLocationWithinImportWriteSet(
  namespace: string,
  key: string
): boolean {
  switch (namespace) {
    case EXIT_PUBLIC_IDENTITIES_NAMESPACE:
    case EXIT_POLICY_SETS_NAMESPACE:
    case EXIT_AUDIT_RECEIPTS_NAMESPACE:
    case EXIT_COMMITMENTS_NAMESPACE:
    case EXIT_PLACEHOLDER_METADATA_NAMESPACE:
    case EXIT_IMPORT_NAMESPACE:
    case "_reputation":
      return true;
    case "_meta":
      return (
        key === STATE_ENVELOPE_PUBLIC_KEYS_KEY ||
        key === STATE_ENVELOPE_VERSION_ANCHORS_KEY
      );
    default:
      // Any OTHER reserved (underscore-prefixed) namespace is never a
      // legitimate import-write location; a non-reserved namespace is the
      // operator's own state and is always in bounds (any key).
      return !isReservedNamespace(namespace);
  }
}

function isWellFormedExitImportJournalRecord(
  value: unknown
): value is ExitImportJournalRecord {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  if (typeof record.import_id !== "string") return false;
  if (typeof record.identity_id !== "string") return false;
  if (typeof record.started_at !== "string") return false;
  if (!Array.isArray(record.snapshots)) return false;
  if (!record.snapshots.every(isWellFormedSerializedStorageSnapshot)) return false;
  if (
    !record.snapshots.every((snapshot) =>
      isLocationWithinImportWriteSet(
        (snapshot as SerializedStorageSnapshot).namespace,
        (snapshot as SerializedStorageSnapshot).key
      )
    )
  ) {
    return false;
  }
  if (!Array.isArray(record.namespace_snapshots)) return false;
  if (
    !record.namespace_snapshots.every(
      isWellFormedSerializedStorageNamespaceSnapshot
    )
  ) {
    return false;
  }
  if (
    !record.namespace_snapshots.every((ns) => {
      const namespaceSnapshot = ns as SerializedStorageNamespaceSnapshot;
      return namespaceSnapshot.entries.every((entry) =>
        isLocationWithinImportWriteSet(entry.namespace, entry.key)
      );
    })
  ) {
    return false;
  }
  return true;
}

function serializeStorageSnapshot(
  snapshot: StorageSnapshot
): SerializedStorageSnapshot {
  return {
    namespace: snapshot.namespace,
    key: snapshot.key,
    data: snapshot.data ? toBase64url(snapshot.data) : null,
  };
}

function deserializeStorageSnapshot(
  record: SerializedStorageSnapshot
): StorageSnapshot {
  return {
    namespace: record.namespace,
    key: record.key,
    data: record.data ? fromBase64url(record.data) : null,
  };
}

function deserializeStorageNamespaceSnapshot(
  record: SerializedStorageNamespaceSnapshot
): StorageNamespaceSnapshot {
  return {
    namespace: record.namespace,
    entries: record.entries.map(deserializeStorageSnapshot),
  };
}

/**
 * Persist the pre-import snapshot to durable storage BEFORE any staging
 * write below begins. A SIGKILL, power loss, or OOM never reaches the
 * `catch` block's in-memory `restoreStorageSnapshots` call a few lines
 * below in `importExitBundle`; without a durable copy of "what this import
 * is about to overwrite," a hard kill would leave the target half-applied
 * with no way to detect or undo it. Idempotent per `importId`: a caller
 * that retries the exact same import after a kill overwrites its own
 * leftover record with an equivalent one (recovered first, by
 * `recoverInterruptedExitImportsOrThrow` at the top of `importExitBundle`,
 * before this write ever runs again).
 */
async function writeImportJournal(
  storage: StorageBackend,
  importId: string,
  identityId: string,
  snapshots: StorageSnapshot[],
  namespaceSnapshots: StorageNamespaceSnapshot[]
): Promise<void> {
  const record: ExitImportJournalRecord = {
    import_id: importId,
    identity_id: identityId,
    started_at: new Date().toISOString(),
    snapshots: snapshots.map(serializeStorageSnapshot),
    namespace_snapshots: namespaceSnapshots.map((ns) => ({
      namespace: ns.namespace,
      entries: ns.entries.map(serializeStorageSnapshot),
    })),
  };
  await stageArtifact(storage, EXIT_IMPORT_JOURNAL_NAMESPACE, importId, record);
}

/**
 * Clears the journal entry once activation OR rollback has fully finished.
 *
 * INVARIANT (Codex gate HIGH finding, 2026-08-22): `secureOverwrite: false`
 * is deliberate. The default filesystem delete overwrites the file with
 * random bytes across three fsync'd passes BEFORE unlinking it; a kill
 * mid-overwrite leaves the journal as neither valid JSON nor gone - a
 * corrupt file `recoverInterruptedExitImports` can no longer parse, so a
 * fully-resolved import (data already correctly restored or promoted)
 * would read as a permanently stuck `failed` entry with nothing left to
 * actually recover. Skipping the overwrite makes this a single `unlink`
 * syscall: from a crash-consistency standpoint it either fully happens or
 * it doesn't, so the file is always either the last complete journal or
 * gone entirely; there is no third, corrupted state. This is safe because
 * a journal entry's `data` fields are exact copies of bytes this function's
 * caller already read from the fortress's own encrypted-at-rest storage
 * (state entries, reputation attestations, staged identity/policy
 * artifacts are all ciphertext on disk before the journal ever copies
 * them) - the journal introduces no NEW plaintext secret exposure that
 * secure overwrite-on-delete would otherwise protect.
 */
async function deleteImportJournal(
  storage: StorageBackend,
  importId: string
): Promise<void> {
  await storage.delete(EXIT_IMPORT_JOURNAL_NAMESPACE, importId, false);
}

/**
 * F1 (Exit V2 drill D1, 2026-08-22): roll back any import whose journal
 * entry survived a hard kill, using the SAME `restoreStorageSnapshots` the
 * exception-path cleanup in `importExitBundle` uses - a killed run and a
 * thrown-exception run roll back through one mechanism, not two. Called
 * from the START of `importExitBundle` (so a retry of a killed import
 * begins from a clean target) AND from fortress open in `exit/cli.ts`'s
 * `openExitContext` (so a killed import is undone even if the operator
 * never retries it, and any OTHER fortress operation that opens storage
 * next never observes half-applied exit-import state). Safe to call on a
 * fortress with no interrupted import: the journal namespace is then
 * empty and this is a single no-op `list()`.
 *
 * A snapshot whose restoration itself fails (disk error, permissions) is
 * NOT deleted from the journal: it stays discoverable so the next fortress
 * open or import attempt retries it, rather than silently dropping a
 * rollback that did not actually complete.
 */
export async function recoverInterruptedExitImports(
  storage: StorageBackend,
  auditLog: AuditLog
): Promise<{ recovered: number; failed: string[] }> {
  const entries = await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE);
  // INVARIANT (Codex gate HIGH finding, 2026-08-22): recovery assumes AT
  // MOST ONE journal entry exists at a time - importExitBundle's own
  // top-of-function recovery call drains any leftover journal before it
  // ever writes a new one, so under normal sequential use there is never
  // more than one. More than one can only mean either a genuine
  // concurrent-import race (two importExitBundle calls against the same
  // fortress storage overlapping their own recovery-then-write windows) or
  // an already-inconsistent fortress. Replaying multiple journals in
  // whatever order `list()` happens to return them is ORDER-DEPENDENT: two
  // journals can snapshot overlapping locations, and restoring them in one
  // order produces a different final byte-for-byte result than the other
  // order. Refuse ALL of them via `failed` (which `recoverInterruptedExitImportsOrThrow`
  // turns into a hard stop) rather than silently pick an order and risk
  // producing a result no operator asked for.
  if (entries.length > 1) {
    return { recovered: 0, failed: entries.map((entry) => entry.key) };
  }
  let recovered = 0;
  const failed: string[] = [];
  for (const entry of entries) {
    const raw = await storage.read(EXIT_IMPORT_JOURNAL_NAMESPACE, entry.key);
    if (!raw) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      failed.push(entry.key);
      continue;
    }
    // MEDIUM-4 (coordinator gate, 2026-08-22): a malformed journal entry
    // (`{}`, a non-string `data`, a missing array) must route to `failed`
    // like any other unrecoverable entry, never throw a raw TypeError out
    // of this function - every caller awaits it directly at fortress open.
    if (!isWellFormedExitImportJournalRecord(parsed)) {
      failed.push(entry.key);
      continue;
    }
    const record = parsed;
    // INVARIANT (kill-during-promote-and-delete case, coordinator gate,
    // 2026-08-22): a kill AFTER the final `activated_at`-stamped import
    // record is written but BEFORE this journal entry is deleted leaves a
    // journal whose import ALREADY SUCCEEDED - restoring its snapshot would
    // silently revert a fully successful, already-promoted import back to
    // its pre-image, which is worse than the half-applied case this
    // function exists to fix. Check the import's OWN completion record
    // first: if it exists and carries `activated_at`, this import is done;
    // the journal is a harmless stale leftover and is deleted, never
    // replayed.
    const importRecordRaw = await storage.read(
      EXIT_IMPORT_NAMESPACE,
      record.import_id
    );
    let alreadyActivated = false;
    if (importRecordRaw) {
      try {
        const importRecordParsed = JSON.parse(
          bytesToString(importRecordRaw)
        ) as Record<string, unknown>;
        alreadyActivated =
          importRecordParsed !== null &&
          typeof importRecordParsed === "object" &&
          typeof importRecordParsed.activated_at === "string";
      } catch {
        // An unparseable import record is handled by the normal path below
        // (attempt the restore); it is not evidence of completion.
      }
    }
    if (alreadyActivated) {
      await deleteImportJournal(storage, entry.key);
      recovered++;
      void auditLog.append(
        "l1",
        "exit_bundle_stale_journal_cleared",
        record.identity_id,
        {
          import_id: record.import_id,
          started_at: record.started_at,
          reason: "import already activated; journal was a stale leftover",
        }
      );
      continue;
    }
    const snapshots = record.snapshots.map(deserializeStorageSnapshot);
    const namespaceSnapshots = record.namespace_snapshots.map(
      deserializeStorageNamespaceSnapshot
    );
    const cleanup = await restoreStorageSnapshots(
      storage,
      snapshots,
      namespaceSnapshots
    );
    if (cleanup.failed.length > 0) {
      failed.push(entry.key);
      continue;
    }
    await deleteImportJournal(storage, entry.key);
    recovered++;
    void auditLog.append(
      "l1",
      "exit_bundle_interrupted_import_recovered",
      record.identity_id,
      {
        import_id: record.import_id,
        started_at: record.started_at,
        removed_total: cleanup.removed,
        restored_total: cleanup.restored,
      }
    );
  }
  if (recovered > 0) {
    await auditLog.flush();
  }
  return { recovered, failed };
}

/**
 * MEDIUM-3 (coordinator gate, 2026-08-22): `recoverInterruptedExitImports`
 * returning `{ failed }` is not enough on its own - a caller that awaits it
 * and discards the result treats a PARTIAL or unparseable rollback exactly
 * like "nothing to recover," then proceeds to read and write the
 * half-applied target as though it were the legitimate pre-import state
 * (AGENTS.md rule 5: never silently degrade to a less-secure behavior on
 * error). This wrapper is the ONE place that turns `failed.length > 0` into
 * a hard stop, so the fail-closed behavior cannot drift between callers.
 *
 * Call-site inventory (HIGH-2, coordinator gate, 2026-08-22): every place
 * that constructs BOTH a real fortress `FilesystemStorage` AND derives its
 * master key (so an `AuditLog` exists to log the recovery) now routes
 * through this wrapper before any other store reads or writes:
 * `importExitBundle` (top of function), `exit/cli.ts` `openExitContext`
 * (every `sanctuary exit` subcommand), `index.ts` `createSanctuaryServer`
 * (the MCP composition root), `dashboard-standalone.ts`, `cli/distress.ts`,
 * `cli/anomaly.ts` (every verb that derives a master key), and
 * `cli/transparency.ts` (every verb that derives a master key). See the
 * call sites themselves for the exact line; this comment is the map, not a
 * substitute for reading them.
 *
 * STATED BOUND: dozens of other narrower CLI verbs across the codebase
 * (`cli/castle-wall.ts`, `cli/sentinel.ts`, `cli/policy.ts`,
 * `cli/checkpoint.ts`, `cli/custody-unlock.ts`, `cli/restore-attest.ts`,
 * and others) also construct a fortress `FilesystemStorage` directly and
 * are NOT wired to this wrapper. The specific data-loss window the gate
 * named - a killed exit-import surviving into normal operation until a
 * LATER `exit verify`/`exit import` silently reconciles it - is closed at
 * the call sites listed above; the remaining CLI verbs are a narrower,
 * pre-existing exposure (each already had its own independent risk profile
 * before this PR) and are tracked as follow-up, not fixed here.
 * `cli/doctor.ts`'s custody-factor check is a DELIBERATE exception: it is
 * documented read-only and never derives a master key by design
 * (`checkCustodyFactors`'s own doc comment), so it has no `AuditLog` to
 * call this wrapper with; recovering there would mean unlocking the
 * fortress specifically to check whether it needs unlocking, which is a
 * larger behavior change than this fix round scopes.
 */
export async function recoverInterruptedExitImportsOrThrow(
  storage: StorageBackend,
  auditLog: AuditLog
): Promise<{ recovered: number }> {
  const result = await recoverInterruptedExitImports(storage, auditLog);
  if (result.failed.length > 0) {
    throw new ExitBundleImportError(
      "INTERRUPTED_IMPORT_RECOVERY_FAILED",
      `${result.failed.length} interrupted exit-bundle import journal entr${
        result.failed.length === 1 ? "y" : "ies"
      } could not be safely rolled back (journal entries: ` +
        `${result.failed.join(", ")}). Refusing to proceed against this ` +
        "fortress while it may hold half-applied exit-import state. Do not " +
        "run further Sanctuary operations against this storage path until " +
        "this is resolved."
    );
  }
  return { recovered: result.recovered };
}

function activationSnapshotLocations(
  importId: string,
  identityArtifact: { json: ExitPublicIdentityArtifact } | null,
  encryptedState: { json: ExitEncryptedStateBundle } | null,
  reputationArtifact: { json: ReputationBundle } | null,
  policySet: { json: ExitPolicySetArtifact } | null,
  auditReceipts: { json: ExitAuditReceiptsArtifact } | null,
  commitments: { json: ExitCommitmentsArtifact } | null,
  placeholderMetadata: { json: ExitPlaceholderVaultMetadataArtifact } | null
): StagedLocation[] {
  const locations: StagedLocation[] = [];
  if (identityArtifact) {
    locations.push({
      namespace: EXIT_PUBLIC_IDENTITIES_NAMESPACE,
      key: identityArtifact.json.bundle.identity_id,
    });
  }
  if (policySet) {
    locations.push({ namespace: EXIT_POLICY_SETS_NAMESPACE, key: importId });
  }
  if (auditReceipts) {
    locations.push({ namespace: EXIT_AUDIT_RECEIPTS_NAMESPACE, key: importId });
  }
  if (commitments) {
    locations.push({ namespace: EXIT_COMMITMENTS_NAMESPACE, key: importId });
  }
  if (placeholderMetadata) {
    locations.push({
      namespace: EXIT_PLACEHOLDER_METADATA_NAMESPACE,
      key: importId,
    });
  }
  locations.push({ namespace: EXIT_IMPORT_NAMESPACE, key: importId });

  for (const attestation of reputationArtifact?.json.attestations ?? []) {
    locations.push({
      namespace: "_reputation",
      key: attestation.attestation_id,
    });
  }

  for (const item of encryptedState?.json.entries ?? []) {
    // RESERVED-NS-DIVERGE-01: `isReservedNamespace` applies the blanket
    // underscore rule on its own, so no separate `startsWith("_")` is needed.
    if (isReservedNamespace(item.namespace)) {
      continue;
    }
    locations.push({ namespace: item.namespace, key: item.key });
  }

  // PRECISE `_meta` LOCATIONS (coordinator gate HIGH finding, 2026-08-22):
  // `StateStore.write` (called per entry by `rekeyState` below) touches
  // exactly these two `_meta` keys - the writer-public-key registry and the
  // version-anchor rollback floor - and nothing else in `_meta`. Naming them
  // precisely here, instead of snapshotting the WHOLE `_meta` namespace,
  // means restore only ever touches bytes THIS import could have written:
  // no unrelated `_meta` key written by anything else, at any point between
  // this import and a later recovery replay, is ever deleted or overwritten.
  // A whole-namespace snapshot could not make that guarantee: its restore
  // deletes every key present at restore time that was absent from the
  // snapshot, which is any unrelated write, not just this import's own.
  // Snapshotting these two keys is harmless even when the import carries no
  // state entries or `rekeyState` never runs (a snapshot of an unwritten
  // location is a no-op restore). If `StateStore.write` starts touching a
  // different or additional `_meta` key, update this list in the same
  // change (see the "must match" pin on the import above).
  if (encryptedState) {
    locations.push({ namespace: "_meta", key: STATE_ENVELOPE_PUBLIC_KEYS_KEY });
    locations.push({
      namespace: "_meta",
      key: STATE_ENVELOPE_VERSION_ANCHORS_KEY,
    });
  }

  return locations;
}

/**
 * One phrase naming which credential semantics `resolveSourceMasterKey`
 * applied, for the SOURCE_KEY_MISMATCH message. Mirrors that function's
 * precedence; if the precedence changes, change this in the same commit.
 */
function describeSourceCredentialInterpretation(
  encryptedState: ExitEncryptedStateBundle,
  opts: ImportExitBundleOptions
): string {
  if (opts.sourceMasterKey) return "the caller supplied the source master key directly";
  if (opts.sourcePassphrase) {
    return "the passphrase was run through the bundle's legacy source_key_derivation parameters";
  }
  if (opts.sourceRecoveryKey) {
    return encryptedState.source_custody !== undefined
      ? "the key was unwrapped from the bundle's source_custody block"
      : "the key was applied under legacy raw-master semantics (--legacy-source-master)";
  }
  return "no source credential was supplied";
}

async function rekeyState(
  encryptedState: ExitEncryptedStateBundle,
  opts: ImportExitBundleOptions,
  sourceMasterKey: Uint8Array,
  publicKeysByIdentityId: Map<string, SourceIdentityPublicKeyCandidate[]>,
  rotationStats: {
    entriesAdmittedByCurrentKey: number;
    entriesAdmittedByRetiredKey: number;
    entriesAdmittedByCompromisedRetiredKey: number;
  },
  /**
   * Accumulator threaded by importExitBundle so the outer cleanup path
   * can remove every entry rekeyState successfully wrote prior to a
   * fatal error. Populated even when the import succeeds so callers can
   * inspect for telemetry; only consumed on the failure path.
   */
  importedRekeyEntries?: StagedLocation[]
): Promise<ImportExitBundleResult["state"]> {
  const destinationSigner = opts.destinationSignerIdentityId
    ? opts.identityManager.get(opts.destinationSignerIdentityId)
    : opts.identityManager.getDefault();
  if (!destinationSigner) {
    return {
      status: "skipped_no_destination_signer",
      imported_keys: 0,
      skipped_keys: encryptedState.entries.length,
      skipped_invalid_sig: 0,
      skipped_unknown_kid: 0,
      conflicts: 0,
    };
  }

  const stateStore = new StateStore(opts.storage, opts.masterKey);
  const identityEncryptionKey = derivePurposeKey(opts.masterKey, "identity-encryption");
  let imported = 0;
  let skipped = 0;
  let skippedInvalidSig = 0;
  let skippedUnknownKid = 0;
  let conflicts = 0;
  // Source-master sanity (custody-envelope follow-on to #496): count how
  // many entries reached AEAD decryption and how many failed it. When the
  // source master decrypts NOTHING, the key is wrong (e.g. a legacy bundle
  // from a dual-path-damaged fortress whose key-params derive a divergent
  // master) - that must fail closed, not silently skip every entry.
  let decryptAttempts = 0;
  let decryptFailures = 0;

  for (const item of encryptedState.entries) {
    // F6: reject ALL underscore-prefixed (internal) namespaces on import.
    // Export only ever emits non-`_` namespaces (see
    // discoverFilesystemStateNamespaces / exportEncryptedState), so any
    // `_`-namespace in a bundle is crafted. RESERVED-NS-DIVERGE-01:
    // `isReservedNamespace` applies the blanket underscore rule itself, so
    // it can't miss a newer internal `_`-namespace the curated list lags.
    if (isReservedNamespace(item.namespace)) {
      skipped++;
      continue;
    }
    const signerPubkeys = publicKeysByIdentityId.get(item.entry.kid);
    if (!signerPubkeys || signerPubkeys.length === 0) {
      skippedUnknownKid++;
      skipped++;
      continue;
    }
    const admittingKey = signerPubkeys.find((candidate) =>
      identityVerify(
        fromBase64url(item.entry.payload.ct),
        fromBase64url(item.entry.sig),
        candidate.publicKey
      )
    );
    if (!admittingKey) {
      skippedInvalidSig++;
      skipped++;
      continue;
    }
    if (
      admittingKey.source === "retired" &&
      admittingKey.compromised &&
      opts.acceptCompromisedRotationKeys !== true
    ) {
      throw new ExitBundleImportError(
        "COMPROMISED_ROTATION_KEY_REFUSED",
        `Refusing to import state entry ${item.namespace}/${item.key}: its ` +
          `source signature verifies only under retired rotation key ` +
          `retired-${admittingKey.retiredIndex ?? "unknown"}, whose rotation ` +
          `reason declares compromise. Re-run only if the operator explicitly ` +
          `accepts that risk with --accept-compromised-rotation-keys.`,
      );
    }

    const exists = await opts.storage.exists(item.namespace, item.key);
    if (exists) {
      conflicts++;
      const resolution = opts.conflictResolution ?? "skip";
      if (resolution === "skip") {
        skipped++;
        continue;
      }
      if (resolution === "version") {
        const raw = await opts.storage.read(item.namespace, item.key);
        if (raw) {
          try {
            const existing = JSON.parse(bytesToString(raw)) as StateEntry;
            if (item.entry.ver <= existing.ver) {
              skipped++;
              continue;
            }
          } catch {
            // Corrupt local entry is overwritten by the verified import.
          }
        }
      }
    }

    let plaintext: Uint8Array;
    decryptAttempts++;
    try {
      plaintext = decrypt(
        item.entry.payload,
        deriveNamespaceKey(sourceMasterKey, item.namespace)
      );
      if (hashToString(plaintext) !== item.entry.integrity_hash) {
        skippedInvalidSig++;
        skipped++;
        continue;
      }
    } catch {
      // AEAD verification failed for this entry. When OTHER entries
      // decrypt fine this is a per-entry data issue (skip and continue);
      // when EVERY entry fails, the source master itself is wrong - the
      // post-loop check below fails the import closed.
      decryptFailures++;
      skippedInvalidSig++;
      skipped++;
      continue;
    }

    // Destination-side write failures DO trigger cleanup. Disk full,
    // permission denied, signer-key corruption, anything that prevents
    // a write, must roll back the partial import per finding #78.
    await stateStore.write(
      item.namespace,
      item.key,
      bytesToString(plaintext),
      destinationSigner.identity_id,
      destinationSigner.encrypted_private_key,
      identityEncryptionKey,
      {
        content_type: item.entry.metadata.content_type,
        ttl_seconds: item.entry.metadata.ttl_seconds,
        tags: [
          ...(item.entry.metadata.tags ?? []),
          "exit-import",
          `source:${item.entry.kid}`,
          ...(admittingKey.source === "retired"
            ? [
                `source-key:retired-${admittingKey.retiredIndex ?? "unknown"}`,
                ...(admittingKey.compromised
                  ? ["source-key:compromised-rotation"]
                  : []),
              ]
            : []),
        ],
      }
    );
    imported++;
    if (admittingKey.source === "current") {
      rotationStats.entriesAdmittedByCurrentKey++;
    } else {
      rotationStats.entriesAdmittedByRetiredKey++;
      if (admittingKey.compromised) {
        rotationStats.entriesAdmittedByCompromisedRetiredKey++;
      }
    }
    importedRekeyEntries?.push({ namespace: item.namespace, key: item.key });
  }

  if (decryptAttempts > 0 && decryptFailures === decryptAttempts) {
    // Nothing decrypted under the recovered source master: wrong source
    // credential (legacy derivation path) or a bundle whose embedded key
    // material does not match its entries. Fail closed - never report a
    // "successful" re-key that silently imported zero entries (#5). No
    // state writes happened on this path; the caller's cleanup handler
    // removes the staged artifacts.
    throw new ExitBundleImportError(
      "SOURCE_KEY_MISMATCH",
      `The recovered source master key failed to decrypt any of the bundle's ` +
        `${decryptAttempts} encrypted state entr${decryptAttempts === 1 ? "y" : "ies"}. ` +
        "The source credential does not match the key this state was actually " +
        "encrypted under (on legacy bundles this can indicate a fortress whose " +
        "passphrase-derived key diverged from its true master). Re-run with the " +
        "correct source credential, or re-export the bundle from the source fortress. " +
        // A4 follow-through: name the INTERPRETATION that was in effect, so even
        // the residual mismatch says which credential semantics were applied
        // rather than leaving the operator to infer it from the flags they typed.
        `Interpretation in effect: ${describeSourceCredentialInterpretation(encryptedState, opts)}.`
    );
  }

  return {
    status: "rekeyed",
    imported_keys: imported,
    skipped_keys: skipped,
    skipped_invalid_sig: skippedInvalidSig,
    skipped_unknown_kid: skippedUnknownKid,
    conflicts,
  };
}

async function stageArtifact(
  storage: StorageBackend,
  namespace: string,
  key: string,
  value: unknown
): Promise<void> {
  await storage.write(namespace, key, jsonBytes(value));
}

export async function importExitBundle(
  opts: ImportExitBundleOptions
): Promise<ImportExitBundleResult> {
  // F1 (Exit V2 drill D1): roll back any import left `in_progress` by a
  // prior hard kill on THIS fortress before doing anything else - including
  // before `conflictReport` below runs, so a killed import of the SAME
  // importId does not read as a staged-artifact conflict against a target
  // that recovery is about to clean up anyway. MEDIUM-3 (coordinator gate):
  // `...OrThrow` so a partial/unparseable rollback stops this import
  // instead of silently proceeding against a possibly half-applied target.
  await recoverInterruptedExitImportsOrThrow(opts.storage, opts.auditLog);
  // The IMPORT path ALWAYS verifies strictly: there is no accept-unverifiable
  // relaxation here regardless of `activate`. An unverifiable-signer or forged
  // attestation fails the bundle whether the caller is doing a dry-run
  // (activate:false) preview or a real activation. The only relaxed, write-free
  // "accept unverifiable" verdict lives in the standalone read-only previewer
  // (verifyExitBundle called WITH acceptUnverifiableAttestations, e.g. the
  // `exit verify` CLI command), whose result is a non-authoritative preview and
  // which never writes to any store or audit log.
  const verification = await verifyExitBundle(opts.bundleDir);
  // A "not verified, nothing staged" result. Used when the strict preview
  // verdict fails AND when the pre-staging reputation signature gate rejects a
  // bundle, so both refusals return the same clean shape instead of one path
  // throwing and the other returning.
  const notVerifiedResult = (
    invalidAttestations: number,
    unverifiableAttestations: number
  ): ImportExitBundleResult => ({
    verified: false,
    activated: false,
    conflicts: {
      public_identity_exists: false,
      state_conflicts: [],
      reputation_conflicts: [],
      policy_set_exists: false,
      audit_receipts_exist: false,
      commitments_exist: false,
      import_record_exists: false,
    },
    state: {
      status: "not_requested",
      imported_keys: 0,
      skipped_keys: 0,
      skipped_invalid_sig: 0,
      skipped_unknown_kid: 0,
      conflicts: 0,
    },
    reputation: {
      imported_attestations: 0,
      invalid_attestations: invalidAttestations,
      unverifiable_attestations: unverifiableAttestations,
    },
    staged_artifacts: [],
    warnings: verification.warnings,
    unsupported_artifacts: verification.unsupported_artifacts,
  });

  if (
    !verification.passed &&
    verification.failure_class !== "reputation_unverifiable_attestations" &&
    // EXIT-PASS-01: rotation_chain_invalid now fails the verifier `passed`
    // boolean (so `exit verify`/`inspect` report FAIL). Do NOT let it short to
    // the generic not-verified result here — falling through preserves the
    // specific, more diagnosable ROTATION_CHAIN_UNVERIFIABLE throw below
    // (line ~2421), which names the rotation chain as the cause instead of a
    // bare "not verified". Import stays fail-closed either way: it never admits
    // data on an unverifiable chain.
    verification.failure_class !== "rotation_chain_invalid" &&
    // LD2-01 (same #1189 pattern), extended by EXIT-STRUCT-02 for a
    // malformed ELEMENT rather than an unreadable container:
    // encrypted_state_entries_unreadable now fails `passed` for both shapes
    // (verifier.ts aggregator). Do NOT let it short to the generic
    // not-verified result here either — falling through preserves the
    // specific ENCRYPTED_STATE_ENTRIES_UNREADABLE throw below, once
    // `encryptedState` is loaded, instead of a bare "not verified" that gives
    // the operator no named cause. Import stays fail-closed either way.
    verification.failure_class !== "encrypted_state_entries_unreadable"
  ) {
    return notVerifiedResult(
      0,
      verification.reputation?.unverifiable_attestations ?? 0
    );
  }

  const manifest = await readManifest(opts.bundleDir);
  const importWarnings: string[] = [];

  const identityArtifact = await loadExitArtifact<ExitPublicIdentityArtifact>(
    opts.bundleDir,
    manifest,
    "public_identity"
  );
  const encryptedState = await loadExitArtifact<ExitEncryptedStateBundle>(
    opts.bundleDir,
    manifest,
    "encrypted_state"
  );
  const policySet = await loadExitArtifact<ExitPolicySetArtifact>(
    opts.bundleDir,
    manifest,
    "policy_set"
  );
  const auditReceipts = await loadExitArtifact<ExitAuditReceiptsArtifact>(
    opts.bundleDir,
    manifest,
    "audit_receipts"
  );
  const reputationArtifact = await loadExitArtifact<ReputationBundle>(
    opts.bundleDir,
    manifest,
    "reputation_bundle"
  );
  const commitments = await loadExitArtifact<ExitCommitmentsArtifact>(
    opts.bundleDir,
    manifest,
    "commitments"
  );
  const placeholderMetadata =
    await loadExitArtifact<ExitPlaceholderVaultMetadataArtifact>(
      opts.bundleDir,
      manifest,
      "placeholder_vault_metadata"
    );

  const publicKeys = identityArtifact
    ? publicKeysFromIdentityArtifact(identityArtifact.json)
    : {
        status: "verified" as const,
        byIdentityId: new Map<string, SourceIdentityPublicKeyCandidate[]>(),
        byDid: new Map<string, Uint8Array>(),
        chain: {
          identity_id: manifest.body.identity_binding.identity_id,
          current_public_key: new Uint8Array(),
          retired: [],
          hop_count: 0,
        },
      };
  if (publicKeys.status === "invalid") {
    // INVARIANT: a bundle whose rotation history cannot be consumed must fail
    // before import can fall back to current-key-only verification and report a
    // partial PASS over silently dropped pre-rotation data.
    throw new ExitBundleImportError(
      "ROTATION_CHAIN_UNVERIFIABLE",
      rotationChainRefusalMessage(publicKeys)
    );
  }
  // LD2-01 (verify/import parity aggregator, class fix), extended by
  // EXIT-STRUCT-02 one level deeper: an encrypted_state artifact whose
  // `entries` field is missing or not an array is structural damage to the
  // artifact itself — verifier.ts `summarizeEncryptedState` classifies it as
  // `entry_count === null`, and the aggregator in `verifyExitBundle` now
  // fails `passed` on it too (`encrypted_state_entries_unreadable`). The
  // SAME is true one level deeper when `entries` IS an array but an
  // ELEMENT in it is malformed (`entries: [null]`, or an element missing
  // `namespace`/`entry`/`entry.kid`/`entry.payload.ct`/`entry.sig`):
  // `summarizeEncryptedState` reports `entries_malformed`, and the
  // aggregator fails `passed` on that too, through the SAME
  // `encrypted_state_entries_unreadable` failure_class (both are "the
  // entries list could not be read in the expected shape" from an
  // operator's perspective). Checked here unconditionally and BEFORE the
  // generic not-verified gate below, mirroring the rotation-chain-invalid
  // throw immediately above: without this, the raw `item.namespace`/
  // `item.entry.kid` dereferences in `compromisedRetiredSignatureUse`
  // (three calls below) throw an unhandled TypeError for the same input.
  // Fail closed with a NAMED, typed error instead — never a crash — so an
  // operator (or a programmatic caller passing `sourceMasterKey`, which
  // bypasses the credential-resolution branches below entirely but still
  // reaches this same dereference) gets a diagnosable code, not a stack
  // trace. CONTRACT PIN: the code string mirrors failure_class
  // "encrypted_state_entries_unreadable" in
  // contracts/v1.1/exit-bundle-manifest.ts.
  //
  // NULL-ROOT RECHECK: `encryptedState.json` is an unchecked cast of parsed,
  // untrusted JSON (`loadExitArtifact<ExitEncryptedStateBundle>` above) — a
  // signed, hash-verified artifact whose bytes happen to be the JSON literal
  // `null` (or any other non-object root) satisfies no object shape at all.
  // The original guard here dereferenced `encryptedState.json.entries`
  // directly, which throws a raw TypeError on a null/non-object root BEFORE
  // `Array.isArray` ever runs — the exact crash class this fix exists to
  // close, one property access earlier than the case it was written for.
  // Narrow the JSON ROOT itself first, through `unknown`, so a malformed
  // root reaches the SAME named error instead.
  //
  // INVARIANT (EXIT-STRUCT-02, extended by F3/F4 - Exit V2 drill D1,
  // 2026-08-22): verify fails closed on a malformed ELEMENT, a stale
  // `total_keys`, or a reserved-namespace entry exactly where import would
  // otherwise dereference it or silently skip it; container+count checks
  // alone are not enough. `checkEncryptedStateStructure` (verifier.ts) is
  // the SAME shared function `summarizeEncryptedState` uses (rule 11,
  // AGENTS.md: "must match" - if this call site's shape changes, change
  // that function's doc comment too), so this check and verify's `passed`
  // boolean can never disagree about which entry is damaged, and the
  // refusal below happens BEFORE any staging write, not after (F4 used to
  // let `rekeyState`'s reserved-namespace skip trip an incomplete-state
  // rollback AFTER staging; this gate now catches it first).
  const encryptedStateJsonRoot: unknown = encryptedState?.json;
  const encryptedStateStructureCheck =
    encryptedStateJsonRoot !== null && typeof encryptedStateJsonRoot === "object"
      ? checkEncryptedStateStructure(
          encryptedStateJsonRoot as { entries?: unknown; total_keys?: unknown }
        )
      : ({
          ok: false,
          problem: "entries_unreadable",
        } as const);
  if (encryptedState && !encryptedStateStructureCheck.ok) {
    throw new ExitBundleImportError(
      encryptedStateStructureErrorCode(encryptedStateStructureCheck.problem),
      encryptedStateStructureErrorMessage(encryptedStateStructureCheck)
    );
  }
  if (!verification.passed) {
    return notVerifiedResult(
      0,
      verification.reputation?.unverifiable_attestations ?? 0
    );
  }

  const compromisedUse = compromisedRetiredSignatureUse(
    encryptedState?.json ?? null,
    publicKeys.byIdentityId
  );
  if (
    compromisedUse.count > 0 &&
    opts.acceptCompromisedRotationKeys !== true
  ) {
    throw new ExitBundleImportError(
      "COMPROMISED_ROTATION_KEY_REFUSED",
      `${compromisedUse.count} state entr${compromisedUse.count === 1 ? "y" : "ies"} ` +
        "verify only under a key retired by a compromised-reason rotation " +
        `(first retired key: retired-${compromisedUse.firstRetiredIndex ?? "unknown"}). ` +
        "Refusing by default. Re-run only if the operator explicitly accepts " +
        "that risk with --accept-compromised-rotation-keys."
    );
  }

  const reputationStore = reputationArtifact
    ? opts.reputationStore ?? new ReputationStore(opts.storage, opts.masterKey)
    : null;
  // Strict reputation-signature gate. Runs on BOTH the dry-run (activate:false)
  // and the activation (activate:true) path, and BEFORE any write below
  // (including the did:web audit appends). Signature verification is not
  // bypassable on the import path: a forged, unknown-signer, absent, malformed,
  // or tampered per-attestation signature fails the whole bundle here, so an
  // unverifiable bundle can neither be reported as verified nor schedule a
  // single audit or store write. When it rejects, return the clean "not
  // verified" result (nothing staged, nothing written). The relaxed, write-free
  // "accept unverifiable" verdict lives only in the read-only previewer
  // (exit/verifier.ts, verifyExitBundle with acceptUnverifiableAttestations).
  if (reputationArtifact && reputationStore) {
    try {
      reputationStore.verifyBundle(reputationArtifact.json, publicKeys.byDid);
    } catch (err) {
      if (err instanceof ReputationBundleVerificationError) {
        return notVerifiedResult(
          err.invalidAttestations,
          err.unverifiableAttestations
        );
      }
      throw err;
    }
  }

  // Recognition-Layer Path C primary build 2: did:web cross-check.
  // The manifest signature has already verified above; the did:web
  // step is the recognition-layer cross-check that the resolved DID
  // Document's verificationMethod public key matches the manifest's
  // claimed fortress_master_pubkey. Three structurally distinct
  // outcomes feed the audit log:
  //
  //   - success: the resolver returned a DID Document whose pubkey
  //     matched. Import proceeds with recognition-layer confidence.
  //   - mismatch: the resolver returned a DID Document whose pubkey
  //     DID NOT match. Import FAILS with ExitBundleImportError code
  //     `did_web_mismatch`. Receiving regime treats this as a hard
  //     signal that the bundle's claimed origin is inconsistent with
  //     the published DID Document.
  //   - resolution_failure: the resolver could not fetch the document
  //     (host not in allowlist, network failure, timeout, not_found,
  //     invalid JSON). Import proceeds with a warning; operator
  //     decides whether the degraded-confidence import is acceptable
  //     or re-runs with --skip-did-web-verify to skip the check
  //     deliberately.
  const manifestDidWeb = manifest.body.identity_binding.did_web;
  if (manifestDidWeb !== undefined && !opts.skipDidWebVerify) {
    const parsedDidWeb = parseDidWeb(manifestDidWeb.identifier);
    const authorityHost = parsedDidWeb.authority_host;
    if (authorityHost.toLowerCase() !== manifestDidWeb.authority_host.toLowerCase()) {
      void opts.auditLog.append(
        "l1",
        EXIT_BUNDLE_DID_WEB_AUDIT_OPS.AUTHORITY_HOST,
        manifest.body.identity_binding.identity_id,
        { authority_host: authorityHost, identifier: manifestDidWeb.identifier },
      );
      void opts.auditLog.append(
        "l1",
        EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
        manifest.body.identity_binding.identity_id,
        {
          outcome: "mismatch",
          identifier: manifestDidWeb.identifier,
          authority_host: authorityHost,
          manifest_authority_host: manifestDidWeb.authority_host,
        },
      );
      await opts.auditLog.flush();
      throw new ExitBundleImportError(
        "did_web_mismatch",
        `did:web cross-check failed: identifier authority host '${authorityHost}' does not match manifest authority_host '${manifestDidWeb.authority_host}'.`,
      );
    }
    const expectedPublicKey = fromBase64url(
      manifest.body.identity_binding.fortress_master_pubkey,
    );
    const resolveOpts: ResolveDidWebOpts = {
      allowed_hosts: opts.didWebAllowedHosts ?? [],
      expected_public_key: expectedPublicKey,
      assertion_time: manifest.body.exported_at,
      ...(opts.didWebFetcher !== undefined ? { fetcher: opts.didWebFetcher } : {}),
      ...(opts.didWebTimeoutMs !== undefined
        ? { timeout_ms: opts.didWebTimeoutMs }
        : {}),
    };
    const resolution = await resolveDidWeb(
      manifestDidWeb.identifier,
      resolveOpts,
    );
    void opts.auditLog.append(
      "l1",
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.AUTHORITY_HOST,
      manifest.body.identity_binding.identity_id,
      { authority_host: authorityHost, identifier: manifestDidWeb.identifier },
    );
    if (resolution.ok) {
      void opts.auditLog.append(
        "l1",
        EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
        manifest.body.identity_binding.identity_id,
        {
          outcome: "success",
          identifier: manifestDidWeb.identifier,
          authority_host: authorityHost,
          resolved_url: resolution.url,
          ...(resolution.selected_verification_method_id !== undefined
            ? { verification_method_id: resolution.selected_verification_method_id }
            : {}),
        },
      );
      if (resolution.historical_verification_used) {
        void opts.auditLog.append(
          "l1",
          "did_web_historical_verification_used",
          manifest.body.identity_binding.identity_id,
          {
            identifier: manifestDidWeb.identifier,
            authority_host: authorityHost,
            verification_method_id: resolution.selected_verification_method_id,
            assertion_time: manifest.body.exported_at,
          },
        );
      }
    } else if (resolution.failure === "signature_mismatch") {
      void opts.auditLog.append(
        "l1",
        EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
        manifest.body.identity_binding.identity_id,
        {
          outcome: "mismatch",
          identifier: manifestDidWeb.identifier,
          authority_host: authorityHost,
          resolved_url: resolution.url,
        },
      );
      await opts.auditLog.flush();
      throw new ExitBundleImportError(
        "did_web_mismatch",
        `did:web cross-check failed: the DID Document at ${resolution.url} resolved successfully, but the verificationMethod public key did not match the manifest's claimed fortress_master_pubkey. The bundle's claimed origin (${manifestDidWeb.identifier}) is inconsistent with the published DID Document. To proceed anyway with the manifest signature alone, re-run import with --skip-did-web-verify.`,
      );
    } else {
      // host_not_allowed / fetch_failed / timeout / not_found /
      // invalid_json: surface as a warning, emit resolution_failure
      // audit, let the import proceed at degraded confidence.
      void opts.auditLog.append(
        "l1",
        EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
        manifest.body.identity_binding.identity_id,
        {
          outcome: "resolution_failure",
          failure: resolution.failure,
          identifier: manifestDidWeb.identifier,
          authority_host: authorityHost,
          resolved_url: resolution.url,
        },
      );
      importWarnings.push(
        `did:web resolution failed (${resolution.failure}): ${resolution.message}. Import proceeded with manifest-signature verification alone; recognition-layer cross-check was skipped. Re-run with --did-web-allowed-host=<host> to enable resolution, or --skip-did-web-verify to skip deliberately.`,
      );
    }
  } else if (manifestDidWeb !== undefined && opts.skipDidWebVerify) {
    void opts.auditLog.append(
      "l1",
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
      manifest.body.identity_binding.identity_id,
      {
        outcome: "skipped",
        identifier: manifestDidWeb.identifier,
        authority_host: manifestDidWeb.authority_host,
      },
    );
  }

  const conflicts = await conflictReport(
    opts.storage,
    identityArtifact?.json ?? null,
    encryptedState?.json ?? null,
    reputationArtifact?.json ?? null,
    manifest
  );

  // Finding RRR: detect mismatched local active identity.
  // The original predicate only checked if the SAME identity_id existed in
  // storage. The drill scenario is importing into a fortress that already has
  // a DIFFERENT active identity, which must also be refused without --force-rebind.
  if (
    !conflicts.public_identity_exists &&
    identityArtifact?.json &&
    opts.identityManager.getPrimaryIdentityId() !== null &&
    opts.identityManager.getPrimaryIdentityId() !== identityArtifact.json.bundle.identity_id
  ) {
    conflicts.public_identity_exists = true;
  }

  if (!opts.activate) {
    return {
      verified: true,
      activated: false,
      conflicts,
      state: {
        status: "not_requested",
        imported_keys: 0,
        skipped_keys: 0,
        skipped_invalid_sig: 0,
        skipped_unknown_kid: 0,
        conflicts: conflicts.state_conflicts.length,
      },
      reputation: {
        imported_attestations: 0,
        invalid_attestations: 0,
        unverifiable_attestations: verification.reputation?.unverifiable_attestations ?? 0,
      },
      staged_artifacts: [],
      warnings: [...verification.warnings, ...importWarnings],
      unsupported_artifacts: verification.unsupported_artifacts,
    };
  }

  if (conflicts.public_identity_exists && !opts.forceRebind) {
    throw new ExitBundleImportError(
      "IDENTITY_OVERWRITE_REFUSED",
      "Importing this exit bundle would overwrite an existing fortress public identity " +
        "(either the same identity already imported, or a different identity is currently active). " +
        "Pass forceRebind: true (CLI: --force-rebind) to confirm explicit replacement."
    );
  }
  if (conflicts.public_identity_exists && opts.forceRebind && identityArtifact) {
    void opts.auditLog.append(
      "l1",
      "exit_bundle_force_rebind",
      identityArtifact.json.bundle.identity_id,
      {
        manifest_version: manifest.body.manifest_version,
        fortress_id: manifest.body.identity_binding.fortress_id,
      }
    );
  }

  const importId = importIdForManifest(manifest);
  const stagedConflicts = stagedArtifactConflicts(conflicts, importId);
  const allowStagedOverwrite =
    opts.conflictResolution === "overwrite" || opts.forceRebind === true;
  if (stagedConflicts.length > 0 && !allowStagedOverwrite) {
    throw new ExitBundleImportError(
      "STAGED_ARTIFACT_CONFLICT",
      "Importing this exit bundle would overwrite existing staged exit artifacts. " +
        `Conflicts: ${stagedConflicts
          .map((conflict) => `${conflict.namespace}/${conflict.key}`)
          .join(", ")}. ` +
        "Pass conflictResolution: \"overwrite\" to confirm explicit replacement."
    );
  }
  if (stagedConflicts.length > 0 && allowStagedOverwrite) {
    void opts.auditLog.append(
      "l1",
      "exit_bundle_staged_artifact_overwrite",
      identityArtifact?.json.bundle.identity_id ??
        manifest.body.identity_binding.identity_id,
      {
        import_id: importId,
        conflicts: stagedConflicts,
      }
    );
  }
  const stagedArtifacts: string[] = [];
  const activationSnapshots = await snapshotStorageLocations(
    opts.storage,
    activationSnapshotLocations(
      importId,
      identityArtifact ?? null,
      encryptedState ?? null,
      reputationArtifact ?? null,
      policySet ?? null,
      auditReceipts ?? null,
      commitments ?? null,
      placeholderMetadata ?? null
    )
  );
  // (coordinator gate HIGH finding, 2026-08-22): NOT a namespace-wide
  // `_meta` snapshot any more - see the "PRECISE `_meta` LOCATIONS" comment
  // in `activationSnapshotLocations` above for why. `activationSnapshots`
  // already carries the two precise `_meta` locations this import can
  // touch; there is nothing left for a namespace-level snapshot to add, and
  // keeping it empty is what removes the "delete every unrelated key
  // written since" imprecision from restore.
  const activationNamespaceSnapshots: StorageNamespaceSnapshot[] = [];
  // F1 (Exit V2 drill D1): make the pre-import snapshot durable BEFORE the
  // `try` block below writes anything. See `writeImportJournal`'s doc
  // comment - this is what lets a hard-killed import be rolled back on the
  // next `importExitBundle` call or fortress open, not just on a caught
  // exception.
  await writeImportJournal(
    opts.storage,
    importId,
    manifest.body.identity_binding.identity_id,
    activationSnapshots,
    activationNamespaceSnapshots
  );
  // Track every staged storage location for result telemetry and cleanup
  // accounting. Snapshot restoration below is what preserves overwritten
  // pre-existing bytes.
  const stagedLocations: StagedLocation[] = [];
  // Same accumulator for the per-entry rekey writes, populated by
  // rekeyState as it succeeds, consumed on failure.
  const importedRekeyEntries: StagedLocation[] = [];
  let reputationResult = {
    imported_attestations: 0,
    invalid_attestations: 0,
    unverifiable_attestations: verification.reputation?.unverifiable_attestations ?? 0,
  };
  const rotationStats = {
    entriesAdmittedByCurrentKey: 0,
    entriesAdmittedByRetiredKey: 0,
    entriesAdmittedByCompromisedRetiredKey: 0,
  };
  let stateResult: ImportExitBundleResult["state"];
  // Resolved INSIDE the try block: a fail-closed source-credential error
  // (SOURCE_CREDENTIAL_INVALID / SOURCE_KEY_UNAVAILABLE / malformed
  // source_custody) must roll back the artifacts staged above, exactly like
  // a re-key failure - otherwise a refused import leaves staged state behind.
  let sourceMasterKey: Uint8Array | null = null;
  // Provenance for the finally-block zeroing: we MUST zero key material the
  // import path itself derived/unwrapped (deriveMasterKey /
  // unwrapMasterFromWraps / decodeSourceRecoveryKey are import-owned), but we
  // MUST NOT zero a caller-supplied `opts.sourceMasterKey` - that buffer is
  // owned by the programmatic caller (hub fortress-scope endpoint / SDK /
  // tests), which may reuse it after import returns. Zeroing it here is a
  // silent use-after-zero that corrupts the caller's master key. When
  // `opts.sourceMasterKey` is supplied, resolveSourceMasterKey returns that
  // exact buffer by reference, so we own the key only when no caller key was
  // passed.
  const ownsSourceKey = !opts.sourceMasterKey;
  let stateRekeyStarted = false;
  try {
    if (identityArtifact) {
      await stageArtifact(
        opts.storage,
        EXIT_PUBLIC_IDENTITIES_NAMESPACE,
        identityArtifact.json.bundle.identity_id,
        identityArtifact.json
      );
      stagedArtifacts.push("public_identity");
      stagedLocations.push({
        namespace: EXIT_PUBLIC_IDENTITIES_NAMESPACE,
        key: identityArtifact.json.bundle.identity_id,
      });
    }
    if (policySet) {
      await stageArtifact(opts.storage, EXIT_POLICY_SETS_NAMESPACE, importId, policySet.json);
      stagedArtifacts.push("policy_set");
      stagedLocations.push({ namespace: EXIT_POLICY_SETS_NAMESPACE, key: importId });
    }
    if (auditReceipts) {
      await stageArtifact(
        opts.storage,
        EXIT_AUDIT_RECEIPTS_NAMESPACE,
        importId,
        auditReceipts.json
      );
      stagedArtifacts.push("audit_receipts");
      stagedLocations.push({ namespace: EXIT_AUDIT_RECEIPTS_NAMESPACE, key: importId });
    }
    if (commitments) {
      await stageArtifact(opts.storage, EXIT_COMMITMENTS_NAMESPACE, importId, commitments.json);
      stagedArtifacts.push("commitments");
      stagedLocations.push({ namespace: EXIT_COMMITMENTS_NAMESPACE, key: importId });
    }
    if (placeholderMetadata) {
      await stageArtifact(
        opts.storage,
        EXIT_PLACEHOLDER_METADATA_NAMESPACE,
        importId,
        placeholderMetadata.json
      );
      stagedArtifacts.push("placeholder_vault_metadata");
      stagedLocations.push({
        namespace: EXIT_PLACEHOLDER_METADATA_NAMESPACE,
        key: importId,
      });
    }
    // F1: stage an `in_progress` interim record here, BEFORE the
    // reputation import or state re-key run; the `activated_at`-stamped
    // FINAL record is written LAST, after both have actually succeeded,
    // below - so the record's own claim of completion is always accurate,
    // including if this import is interrupted between the two writes.
    await stageArtifact(opts.storage, EXIT_IMPORT_NAMESPACE, importId, {
      manifest: manifest.body,
      verified_at: verification.verified_at,
      in_progress: true,
    });
    stagedLocations.push({ namespace: EXIT_IMPORT_NAMESPACE, key: importId });

    // Anti-rollback Stage 1 (#506) interaction: the activation path above emits
    // its audit entries fire-and-forget (`void opts.auditLog.append(...)`), so a
    // head-anchor write for the first such entry can still be in flight when the
    // trust-bearing-write gate below runs. `enforceCustodyFloor` (reached via
    // reputation import / state re-key) calls `probeAuditHeadAnchor`, which reads
    // "audit entries exist on disk but no head anchor file yet" as the custody
    // SPLICE signature - a FALSE rollback freeze that fails a LEGITIMATE import
    // (exit-bundle establish into a fresh epoch-0 destination). Draining the audit
    // queue here makes the gate observe a settled, self-consistent audit state
    // (entry on disk => its head anchor on disk), so a genuine import is never
    // mistaken for a credential-resurrecting splice. This weakens nothing: a real
    // splice (old custody envelope grafted onto an audit chain written under a
    // different master) still fails the head-anchor MAC after the flush.
    await opts.auditLog.flush();

    if (reputationArtifact && reputationStore) {
      // Signature verification is not bypassable on the import path: there is no
      // accept-unverifiable relaxation, so an unknown-signer or otherwise
      // unverifiable attestation is never admitted into the store. The strict
      // gate above already rejected any such bundle before reaching activation;
      // importBundle re-verifies strictly here as defense in depth. The only
      // relaxed verdict is confined to the read-only previewer
      // (exit/verifier.ts, verifyExitBundle).
      const imported = await reputationStore.importBundle(
        reputationArtifact.json,
        true,
        publicKeys.byDid
      );
      reputationResult = {
        imported_attestations: imported.imported,
        invalid_attestations: imported.invalid,
        unverifiable_attestations: imported.unverifiable,
      };
      stagedArtifacts.push("reputation_bundle");
    }

    stateRekeyStarted = true;
    sourceMasterKey = await resolveSourceMasterKey(
      encryptedState?.json ?? null,
      opts
    );
    stateResult =
      encryptedState && encryptedState.json.entries.length > 0
        ? sourceMasterKey
          ? await rekeyState(
              encryptedState.json,
              opts,
              sourceMasterKey,
              publicKeys.byIdentityId,
              rotationStats,
              importedRekeyEntries
            )
          : {
              status: "staged_requires_source_key" as const,
              imported_keys: 0,
              skipped_keys: encryptedState.json.entries.length,
              skipped_invalid_sig: 0,
              skipped_unknown_kid: 0,
              conflicts: conflicts.state_conflicts.length,
            }
        : {
            // INVARIANT (A8): "the bundle carried zero entries" is NOT
            // "no state import was requested". When the operator supplied a
            // source credential they explicitly asked for state, so reporting
            // `not_requested` here was a false negative that also mis-fired the
            // CLI's "re-run with --import-state" advice. Credentials supplied
            // => `empty_bundle`; no credentials => `not_requested` stays, plus
            // a warning naming the empty_reason marker (or its absence).
            status: importRequestedSourceCredential(opts)
              ? ("empty_bundle" as const)
              : ("not_requested" as const),
            imported_keys: 0,
            skipped_keys: 0,
            skipped_invalid_sig: 0,
            skipped_unknown_kid: 0,
            conflicts: 0,
          };
    if (encryptedState && encryptedState.json.entries.length === 0) {
      importWarnings.push(emptyStateWarning(encryptedState.json));
    }
    if (stateHasNonConflictSkippedEntries(stateResult)) {
      // A dropped state entry must be surfaced, never reported as a successful import.
      throw new ExitBundleStateImportIncompleteError(
        stateResult,
        stateImportIncompleteMessageWithRotationKeys(
          stateResult,
          publicKeys.byIdentityId
        )
      );
    }
    if (stateSkippedOnlyConflicts(stateResult)) {
      importWarnings.push(
        `state import skipped ${stateResult.skipped_keys} existing destination ` +
          `entr${stateResult.skipped_keys === 1 ? "y" : "ies"} due to ` +
          `conflict policy; state_skipped_keys=${stateResult.skipped_keys}, ` +
          `state_skipped_invalid_sig=${stateResult.skipped_invalid_sig}, ` +
          `state_skipped_unknown_kid=${stateResult.skipped_unknown_kid}. ` +
          `Re-run with --conflict overwrite or --conflict version if these ` +
          `source entries should replace destination state.`
      );
    }
    // M2-slice (warn): the destination `stateStore.write` mints a fresh
    // `written_at` and a fresh monotonic `ver` - both are bound into the
    // signed envelope, so they cannot be back-stamped to the source values
    // without a signed-envelope schema change (deliberately out of scope; the
    // absolute-`expires_at` redesign is a flagged Erik decision). Surface the
    // reset honestly so the operator knows relative TTLs were renewed from the
    // import time and source versions were not preserved.
    if (stateResult.status === "rekeyed" && stateResult.imported_keys > 0) {
      importWarnings.push(
        `re-keyed state entries were re-stamped at import time: their ` +
          `written_at and version were reset to the import, so relative ` +
          `ttl_seconds are renewed from now (source TTL remaining and source ` +
          `version are not preserved across re-key).`
      );
    }
    void opts.auditLog.append("l1", "exit_bundle_import_activate", manifest.body.identity_binding.identity_id, {
      import_id: importId,
      manifest_version: manifest.body.manifest_version,
      state_status: stateResult.status,
      state_imported_keys: stateResult.imported_keys,
      reputation_imported_attestations: reputationResult.imported_attestations,
    });
    if (identityArtifact && publicKeys.chain.hop_count > 0) {
      await opts.auditLog.appendCritical({
        layer: "l1",
        operation: "exit_bundle_rotation_chain_consumed",
        identity_id: identityArtifact.json.bundle.identity_id,
        result: "success",
        details: {
          hop_count: publicKeys.chain.hop_count,
          entries_admitted_by_current_key:
            rotationStats.entriesAdmittedByCurrentKey,
          entries_admitted_by_retired_key:
            rotationStats.entriesAdmittedByRetiredKey,
          compromised_hops: publicKeys.chain.retired.filter(
            (retired) => retired.compromised
          ).length,
          entries_admitted_by_compromised_retired_key:
            rotationStats.entriesAdmittedByCompromisedRetiredKey,
          accept_compromised_rotation_keys:
            opts.acceptCompromisedRotationKeys === true,
        },
      });
    }
    // F1 (Exit V2 drill D1): promote the interim `in_progress` import
    // record to its final `activated_at`-stamped form LAST - only after the
    // reputation import and state re-key above have both actually
    // succeeded. This is the write that makes an import "done"; everything
    // the journal protects has already completed by the time it runs, so a
    // kill after this point has nothing left to roll back.
    await stageArtifact(opts.storage, EXIT_IMPORT_NAMESPACE, importId, {
      manifest: manifest.body,
      verified_at: verification.verified_at,
      activated_at: new Date().toISOString(),
    });
    await deleteImportJournal(opts.storage, importId);
    await opts.auditLog.flush();
  } catch (err) {
    const cleanup = await restoreStorageSnapshots(
      opts.storage,
      activationSnapshots,
      activationNamespaceSnapshots
    );
    // F1 (Exit V2 drill D1): only clear the durable journal once the
    // in-memory restore above actually finished cleanly. A partial restore
    // (disk error mid-cleanup) must stay discoverable so the next fortress
    // open or import attempt retries it, mirroring
    // `recoverInterruptedExitImports`'s own "leave it on partial failure"
    // rule - one retry policy for both the kill path and the exception path.
    if (cleanup.failed.length === 0) {
      await deleteImportJournal(opts.storage, importId);
    }
    const cleanupOperation =
      stateRekeyStarted || err instanceof ExitBundleImportError
        ? "exit_bundle_rekey_failed_cleanup"
        : "exit_bundle_activation_failed_cleanup";
    void opts.auditLog.append(
      "l1",
      cleanupOperation,
      manifest.body.identity_binding.identity_id,
      {
        import_id: importId,
        manifest_version: manifest.body.manifest_version,
        rekey_entries_removed: importedRekeyEntries.length,
        staged_artifacts_removed: stagedLocations.length,
        removed_total: cleanup.removed,
        restored_total: cleanup.restored,
        cleanup_failed_count: cleanup.failed.length,
        original_error: err instanceof Error ? err.message : String(err),
        meta_namespace_snapshotted: true,
      },
      "failure"
    );
    await opts.auditLog.flush();
    const originalMessage = err instanceof Error ? err.message : String(err);
    const failureKind =
      stateRekeyStarted || err instanceof ExitBundleImportError
        ? "re-key"
        : "activation";
    const fallbackCode = err instanceof ReputationBundleVerificationError
      ? "REPUTATION_IMPORT_FAILED_AND_CLEANED"
      : stateRekeyStarted
        ? "REKEY_FAILED_AND_CLEANED"
        : "ACTIVATION_FAILED_AND_CLEANED";
    const cleanupMessage =
      // Preserve structured fail-closed codes (SOURCE_CREDENTIAL_INVALID,
      // SOURCE_KEY_MISMATCH, ...) so callers can branch on the cause; the
      // generic code covers non-structured failures (disk full, etc.).
      `Exit-bundle ${failureKind} failed: ${originalMessage}. ` +
        `Cleanup removed ${cleanup.removed} and restored ${cleanup.restored} of ` +
        `${activationSnapshots.length} snapshotted paths ` +
        `plus ${activationNamespaceSnapshots.length} snapshotted namespaces ` +
        `(${importedRekeyEntries.length} re-keyed entries plus ${stagedLocations.length} staged artifacts; ` +
        `${cleanup.failed.length} cleanup writes/deletes failed).`;
    if (err instanceof ExitBundleStateImportIncompleteError) {
      throw new ExitBundleStateImportIncompleteError(err.state, cleanupMessage, {
        cause: err,
      });
    }
    throw new ExitBundleImportError(
      err instanceof ExitBundleImportError ? err.code : fallbackCode,
      cleanupMessage,
      { cause: err }
    );
  } finally {
    // Zero ONLY key material the import path derived/unwrapped itself
    // (deriveMasterKey / unwrapMasterFromWraps / decodeSourceRecoveryKey).
    // A caller-supplied `opts.sourceMasterKey` is returned by reference and
    // owned by the caller; zeroing it would be a silent use-after-zero of the
    // caller's master key. See `ownsSourceKey` above.
    if (ownsSourceKey && sourceMasterKey instanceof Uint8Array) {
      sourceMasterKey.fill(0);
    }
  }

  return {
    verified: true,
    activated: true,
    conflicts,
    state: stateResult,
    reputation: reputationResult,
    ...(identityArtifact && publicKeys.chain.hop_count > 0
      ? {
          rotation: {
            identity_id: identityArtifact.json.bundle.identity_id,
            hop_count: publicKeys.chain.hop_count,
            chain_signature_verified: true,
            compromised_hops: publicKeys.chain.retired.filter(
              (retired) => retired.compromised
            ).length,
            entries_admitted_by_current_key:
              rotationStats.entriesAdmittedByCurrentKey,
            entries_admitted_by_retired_key:
              rotationStats.entriesAdmittedByRetiredKey,
            entries_admitted_by_compromised_retired_key:
              rotationStats.entriesAdmittedByCompromisedRetiredKey,
          },
        }
      : {}),
    staged_artifacts: stagedArtifacts,
    warnings: [...verification.warnings, ...importWarnings],
    unsupported_artifacts: verification.unsupported_artifacts,
  };
}

export function exitBundleManifestShape(): Record<string, unknown> {
  return {
    manifest_version: EXIT_BUNDLE_MANIFEST_VERSION,
    artifacts: [...EXIT_BUNDLE_ARTIFACT_KINDS],
    hash_alg: "sha256",
    signature_scheme: SIGNATURE_SCHEME_V1,
    required_top_level_file: "manifest.json",
    artifact_paths: [
      "artifacts/public_identity.json",
      "artifacts/encrypted_state.json",
      "artifacts/policy_set.json",
      "artifacts/audit_receipts.json",
      "artifacts/reputation_bundle.json",
      "artifacts/commitments.json",
      "artifacts/placeholder_vault_metadata.json",
    ],
  };
}
