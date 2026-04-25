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
import { StateStore, isReservedNamespace, type StateEntry } from "../l1-cognitive/state-store.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type { AuditLog, AuditEntry } from "../l2-operational/audit-log.js";
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
  ExitBundleManifest,
  ExitBundleManifestBody,
} from "../contracts/v1.1/exit-bundle-manifest.js";
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
  type KeyDerivationParams,
} from "../core/key-derivation.js";
import { decrypt, type EncryptedPayload } from "../core/encryption.js";
import {
  sign as identitySign,
  verify as identityVerify,
  type StoredIdentity,
} from "../core/identity.js";
import {
  ReputationStore,
  type ReputationBundle,
} from "../l4-reputation/reputation-store.js";
import { verifyExitBundle, readManifest, loadExitArtifact } from "./verifier.js";

const ARTIFACT_DIR = "artifacts";
const EXIT_IMPORT_NAMESPACE = "_exit_imports";
const EXIT_PUBLIC_IDENTITIES_NAMESPACE = "_exit_public_identities";
const EXIT_AUDIT_RECEIPTS_NAMESPACE = "_exit_audit_receipts";
const EXIT_POLICY_SETS_NAMESPACE = "_exit_policy_sets";
const EXIT_COMMITMENTS_NAMESPACE = "_exit_commitments";
const EXIT_PLACEHOLDER_METADATA_NAMESPACE = "_exit_placeholder_metadata";
const PRIVACY_PLACEHOLDER_NAMESPACE = "_privacy_placeholder_vault";

export interface ExitEncryptedStateBundle {
  format: "SANCTUARY_EXIT_ENCRYPTED_STATE_V1";
  exported_at: string;
  key_source: "passphrase" | "recovery-key" | "unknown";
  source_key_derivation?: KeyDerivationParams;
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
  individual_entry_signatures: false;
  entries: AuditEntry[];
}

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
  stateNamespaces?: string[];
  keySource?: "passphrase" | "recovery-key" | "unknown";
}

export interface ExportExitBundleResult {
  bundle_dir: string;
  manifest: ExitBundleManifest;
  manifest_hash: string;
  artifact_count: number;
  unsupported_artifacts: string[];
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
  sourceMasterKey?: Uint8Array;
  destinationSignerIdentityId?: string;
}

export interface ExitBundleConflictReport {
  public_identity_exists: boolean;
  state_conflicts: Array<{ namespace: string; key: string }>;
  reputation_conflicts: string[];
  policy_set_exists: boolean;
  audit_receipts_exist: boolean;
}

export interface ImportExitBundleResult {
  verified: boolean;
  activated: boolean;
  conflicts: ExitBundleConflictReport;
  state: {
    status:
      | "not_requested"
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
  staged_artifacts: string[];
  warnings: string[];
  unsupported_artifacts: string[];
}

function sha256Hex(bytes: Uint8Array): string {
  return Array.from(hash(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function jsonBytes(value: unknown): Uint8Array {
  return stringToBytes(JSON.stringify(value, null, 2) + "\n");
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

async function readSourceKeyParams(
  storage: StorageBackend
): Promise<KeyDerivationParams | undefined> {
  const raw = await storage.read("_meta", "key-params");
  if (!raw) return undefined;
  return JSON.parse(bytesToString(raw)) as KeyDerivationParams;
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

async function exportEncryptedState(
  opts: ExportExitBundleOptions
): Promise<ExitEncryptedStateBundle> {
  const namespaceSet = new Set(
    opts.stateNamespaces ??
      (await discoverFilesystemStateNamespaces(opts.stateStoragePath))
  );
  const entries: ExitEncryptedStateBundle["entries"] = [];
  for (const namespace of [...namespaceSet].sort()) {
    if (isReservedNamespace(namespace)) continue;
    const metas = await opts.storage.list(namespace);
    for (const meta of metas) {
      const raw = await opts.storage.read(namespace, meta.key);
      if (!raw) continue;
      try {
        entries.push({
          namespace,
          key: meta.key,
          entry: JSON.parse(bytesToString(raw)) as StateEntry,
        });
      } catch {
        // Corrupt state is omitted rather than trusted into the exit bundle.
      }
    }
  }

  return {
    format: "SANCTUARY_EXIT_ENCRYPTED_STATE_V1",
    exported_at: new Date().toISOString(),
    key_source: opts.keySource ?? "unknown",
    source_key_derivation: await readSourceKeyParams(opts.storage),
    namespaces: [...new Set(entries.map((entry) => entry.namespace))].sort(),
    total_keys: entries.length,
    contains_reserved_namespaces: false,
    entries,
  };
}

function exportPublicIdentity(
  identity: StoredIdentity,
  masterKey: Uint8Array
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
    exported_at: new Date().toISOString(),
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
  config?: SanctuaryConfig
): ExitPolicySetArtifact {
  const cfg = config ?? defaultConfig();

  return {
    format: "SANCTUARY_EXIT_POLICY_SET_V1",
    exported_at: new Date().toISOString(),
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
  auditLog: AuditLog
): Promise<ExitAuditReceiptsArtifact> {
  await auditLog.flush();
  const result = await auditLog.query({ limit: 100_000 });
  return {
    format: "SANCTUARY_AUDIT_RECEIPTS_V1",
    exported_at: new Date().toISOString(),
    total: result.total,
    individual_entry_signatures: false,
    entries: result.entries,
  };
}

async function exportCommitments(
  storage: StorageBackend,
  masterKey: Uint8Array
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
    exported_at: new Date().toISOString(),
    public_commitments: publicCommitments,
    unreadable_count: unreadable,
    redacted_fields: ["value", "blinding_factor"],
  };
}

async function exportPlaceholderVaultMetadata(
  storage: StorageBackend,
  masterKey: Uint8Array
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
    exported_at: new Date().toISOString(),
    entries,
    unreadable_count: unreadable,
    redacted_fields: ["raw_value", "raw_path"],
  };
}

export async function exportExitBundle(
  opts: ExportExitBundleOptions
): Promise<ExportExitBundleResult> {
  const bundleDir = resolve(opts.bundleDir);
  await mkdir(bundleDir, { recursive: true, mode: 0o700 });
  await mkdir(join(bundleDir, ARTIFACT_DIR), { recursive: true, mode: 0o700 });

  const identity = opts.identityManager.getDefault();
  if (!identity) {
    throw new Error("Cannot export exit bundle: no default identity exists.");
  }

  const exportApprovalAuditId = `exit-export-${Date.now()}`;
  opts.auditLog.append("l1", "exit_bundle_export", identity.identity_id, {
    approval_id: exportApprovalAuditId,
    manifest_version: EXIT_BUNDLE_MANIFEST_VERSION,
  });

  const reputationStore =
    opts.reputationStore ?? new ReputationStore(opts.storage, opts.masterKey);
  const identityEncryptionKey = derivePurposeKey(opts.masterKey, "identity-encryption");

  const artifacts: ExitBundleArtifactEntry[] = [];
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/public_identity.json`,
      exportPublicIdentity(identity, opts.masterKey),
      "public_identity"
    )
  );
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/encrypted_state.json`,
      await exportEncryptedState(opts),
      "encrypted_state"
    )
  );
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/policy_set.json`,
      exportPolicySet(opts.policy, opts.config),
      "policy_set"
    )
  );
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/audit_receipts.json`,
      await exportAuditReceipts(opts.auditLog),
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
      await exportCommitments(opts.storage, opts.masterKey),
      "commitments"
    )
  );
  artifacts.push(
    await writeJsonArtifact(
      bundleDir,
      `${ARTIFACT_DIR}/placeholder_vault_metadata.json`,
      await exportPlaceholderVaultMetadata(opts.storage, opts.masterKey),
      "placeholder_vault_metadata"
    )
  );

  const body: ExitBundleManifestBody = {
    manifest_version: EXIT_BUNDLE_MANIFEST_VERSION,
    exported_at: new Date().toISOString(),
    identity_binding: {
      identity_id: identity.identity_id,
      fortress_id: identity.did,
      fortress_master_pubkey: identity.public_key,
      did: identity.did,
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
  await opts.auditLog.flush();

  return {
    bundle_dir: bundleDir,
    manifest,
    manifest_hash: sha256Hex(manifestBytes),
    artifact_count: artifacts.length,
    unsupported_artifacts: [
      "audit_receipts: legacy L2 audit entries are manifest-pinned but not individually signed",
    ],
  };
}

function publicKeysFromIdentityArtifact(
  identityArtifact: ExitPublicIdentityArtifact
): {
  byIdentityId: Map<string, Uint8Array>;
  byDid: Map<string, Uint8Array>;
} {
  const pubkey = fromBase64url(identityArtifact.bundle.publicKey);
  return {
    byIdentityId: new Map([[identityArtifact.bundle.identity_id, pubkey]]),
    byDid: new Map([[identityArtifact.bundle.did, pubkey]]),
  };
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
  };
}

function importIdForManifest(manifest: ExitBundleManifest): string {
  return `${manifest.body.identity_binding.identity_id}-${manifest.body.exported_at.replace(/[^0-9a-zA-Z_.-]/g, "_")}`;
}

async function resolveSourceMasterKey(
  encryptedState: ExitEncryptedStateBundle | null,
  opts: ImportExitBundleOptions
): Promise<Uint8Array | null> {
  if (!encryptedState || encryptedState.entries.length === 0) return null;
  if (opts.sourceMasterKey) return opts.sourceMasterKey;
  if (opts.sourcePassphrase && encryptedState.source_key_derivation) {
    return (await deriveMasterKey(
      opts.sourcePassphrase,
      encryptedState.source_key_derivation
    )).key;
  }
  if (opts.sourceRecoveryKey) {
    const key = fromBase64url(opts.sourceRecoveryKey);
    if (key.length !== 32) {
      throw new Error("Source recovery key must decode to 32 bytes.");
    }
    return key;
  }
  return null;
}

async function rekeyState(
  encryptedState: ExitEncryptedStateBundle,
  opts: ImportExitBundleOptions,
  sourceMasterKey: Uint8Array,
  publicKeysByIdentityId: Map<string, Uint8Array>
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

  for (const item of encryptedState.entries) {
    if (isReservedNamespace(item.namespace)) {
      skipped++;
      continue;
    }
    const signerPubkey = publicKeysByIdentityId.get(item.entry.kid);
    if (!signerPubkey) {
      skippedUnknownKid++;
      skipped++;
      continue;
    }
    const sourceSigValid = identityVerify(
      fromBase64url(item.entry.payload.ct),
      fromBase64url(item.entry.sig),
      signerPubkey
    );
    if (!sourceSigValid) {
      skippedInvalidSig++;
      skipped++;
      continue;
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

    try {
      const plaintext = decrypt(
        item.entry.payload,
        deriveNamespaceKey(sourceMasterKey, item.namespace)
      );
      if (hashToString(plaintext) !== item.entry.integrity_hash) {
        skippedInvalidSig++;
        skipped++;
        continue;
      }
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
          ],
        }
      );
      imported++;
    } catch {
      skippedInvalidSig++;
      skipped++;
    }
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
  const verification = await verifyExitBundle(opts.bundleDir);
  if (!verification.passed) {
    return {
      verified: false,
      activated: false,
      conflicts: {
        public_identity_exists: false,
        state_conflicts: [],
        reputation_conflicts: [],
        policy_set_exists: false,
        audit_receipts_exist: false,
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
        invalid_attestations: 0,
        unverifiable_attestations: verification.reputation?.unverifiable_attestations ?? 0,
      },
      staged_artifacts: [],
      warnings: verification.warnings,
      unsupported_artifacts: verification.unsupported_artifacts,
    };
  }

  const manifest = await readManifest(opts.bundleDir);
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

  const conflicts = await conflictReport(
    opts.storage,
    identityArtifact?.json ?? null,
    encryptedState?.json ?? null,
    reputationArtifact?.json ?? null,
    manifest
  );

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
      warnings: verification.warnings,
      unsupported_artifacts: verification.unsupported_artifacts,
    };
  }

  const importId = importIdForManifest(manifest);
  const stagedArtifacts: string[] = [];
  if (identityArtifact) {
    await stageArtifact(
      opts.storage,
      EXIT_PUBLIC_IDENTITIES_NAMESPACE,
      identityArtifact.json.bundle.identity_id,
      identityArtifact.json
    );
    stagedArtifacts.push("public_identity");
  }
  if (policySet) {
    await stageArtifact(opts.storage, EXIT_POLICY_SETS_NAMESPACE, importId, policySet.json);
    stagedArtifacts.push("policy_set");
  }
  if (auditReceipts) {
    await stageArtifact(
      opts.storage,
      EXIT_AUDIT_RECEIPTS_NAMESPACE,
      importId,
      auditReceipts.json
    );
    stagedArtifacts.push("audit_receipts");
  }
  if (commitments) {
    await stageArtifact(opts.storage, EXIT_COMMITMENTS_NAMESPACE, importId, commitments.json);
    stagedArtifacts.push("commitments");
  }
  if (placeholderMetadata) {
    await stageArtifact(
      opts.storage,
      EXIT_PLACEHOLDER_METADATA_NAMESPACE,
      importId,
      placeholderMetadata.json
    );
    stagedArtifacts.push("placeholder_vault_metadata");
  }
  await stageArtifact(opts.storage, EXIT_IMPORT_NAMESPACE, importId, {
    manifest: manifest.body,
    verified_at: verification.verified_at,
    activated_at: new Date().toISOString(),
  });

  const publicKeys = identityArtifact
    ? publicKeysFromIdentityArtifact(identityArtifact.json)
    : { byIdentityId: new Map<string, Uint8Array>(), byDid: new Map<string, Uint8Array>() };

  let reputationResult = {
    imported_attestations: 0,
    invalid_attestations: 0,
    unverifiable_attestations: verification.reputation?.unverifiable_attestations ?? 0,
  };
  if (reputationArtifact) {
    const reputationStore =
      opts.reputationStore ?? new ReputationStore(opts.storage, opts.masterKey);
    const imported = await reputationStore.importBundle(
      reputationArtifact.json,
      true,
      publicKeys.byDid
    );
    reputationResult = {
      imported_attestations: imported.imported,
      invalid_attestations: imported.invalid,
      unverifiable_attestations: verification.reputation?.unverifiable_attestations ?? 0,
    };
    stagedArtifacts.push("reputation_bundle");
  }

  const sourceMasterKey = await resolveSourceMasterKey(
    encryptedState?.json ?? null,
    opts
  );
  const stateResult =
    encryptedState && encryptedState.json.entries.length > 0
      ? sourceMasterKey
        ? await rekeyState(
            encryptedState.json,
            opts,
            sourceMasterKey,
            publicKeys.byIdentityId
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
          status: "not_requested" as const,
          imported_keys: 0,
          skipped_keys: 0,
          skipped_invalid_sig: 0,
          skipped_unknown_kid: 0,
          conflicts: 0,
        };

  opts.auditLog.append("l1", "exit_bundle_import_activate", manifest.body.identity_binding.identity_id, {
    import_id: importId,
    manifest_version: manifest.body.manifest_version,
    state_status: stateResult.status,
    state_imported_keys: stateResult.imported_keys,
    reputation_imported_attestations: reputationResult.imported_attestations,
  });
  await opts.auditLog.flush();

  return {
    verified: true,
    activated: true,
    conflicts,
    state: stateResult,
    reputation: reputationResult,
    staged_artifacts: stagedArtifacts,
    warnings: verification.warnings,
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
