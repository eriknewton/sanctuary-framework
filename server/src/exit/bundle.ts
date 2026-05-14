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
  recovery_semantics: "archive_only";
  normal_audit_query_continuity: false;
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
   * v1.0.2 / full-sweep #55. Reputation attestations whose signer DID is not
   * present in the bundle's published identity material are marked
   * `unverifiable` by the verifier. By default the verdict is now strict and
   * an unverifiable attestation fails the bundle. Setting this flag opts the
   * operator in to an explicit relaxed verdict (Tier 1 confirmation in CLI).
   */
  acceptUnverifiableAttestations?: boolean;
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
  constructor(code: string, message: string) {
    super(message);
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
    recovery_semantics: "archive_only",
    normal_audit_query_continuity: false,
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

  const exportApprovalAuditId =
    opts.exportApprovalAuditId ?? `exit-export-${Date.now()}`;
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

  const body: ExitBundleManifestBody = {
    manifest_version: EXIT_BUNDLE_MANIFEST_VERSION,
    exported_at: new Date().toISOString(),
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
    opts.auditLog.append(
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
      `exit-bundle: did_web.identifier authority host '${parsed.authority_host}' does not match did_web.authority_host '${binding.authority_host}'`,
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

/**
 * A staged artifact location written during importExitBundle. Used to
 * undo partial imports when the re-key handler fails partway through.
 * Hardening wave 6 finding #78.
 */
interface StagedLocation {
  namespace: string;
  key: string;
}

async function rekeyState(
  encryptedState: ExitEncryptedStateBundle,
  opts: ImportExitBundleOptions,
  sourceMasterKey: Uint8Array,
  publicKeysByIdentityId: Map<string, Uint8Array>,
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

    let plaintext: Uint8Array;
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
      // Source-key derivation or AEAD verification failed. Skip and
      // continue, this is a per-entry data issue, not a fatal-import
      // condition, so it does NOT trigger cleanup of prior writes.
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
        ],
      }
    );
    imported++;
    importedRekeyEntries?.push({ namespace: item.namespace, key: item.key });
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

/**
 * Best-effort cleanup of staged paths after a re-key failure. Each
 * delete is independent, one delete failing should not prevent later
 * deletes from running. Failures are collected and surfaced in the
 * thrown ExitBundleImportError so the operator sees what was and was
 * not cleaned. Hardening wave 6 finding #78.
 */
async function cleanupStagedPaths(
  storage: StorageBackend,
  staged: StagedLocation[]
): Promise<{ removed: number; failed: StagedLocation[] }> {
  let removed = 0;
  const failed: StagedLocation[] = [];
  for (const loc of staged) {
    try {
      const ok = await storage.delete(loc.namespace, loc.key);
      if (ok) {
        removed++;
      } else {
        failed.push(loc);
      }
    } catch {
      failed.push(loc);
    }
  }
  return { removed, failed };
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
  const verification = await verifyExitBundle(opts.bundleDir, {
    acceptUnverifiableAttestations: opts.acceptUnverifiableAttestations,
  });
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
        invalid_attestations: 0,
        unverifiable_attestations: verification.reputation?.unverifiable_attestations ?? 0,
      },
      staged_artifacts: [],
      warnings: verification.warnings,
      unsupported_artifacts: verification.unsupported_artifacts,
    };
  }

  const manifest = await readManifest(opts.bundleDir);
  const importWarnings: string[] = [];

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
    const authorityHost = manifestDidWeb.authority_host;
    opts.auditLog.append(
      "l1",
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.AUTHORITY_HOST,
      manifest.body.identity_binding.identity_id,
      { authority_host: authorityHost, identifier: manifestDidWeb.identifier },
    );
    if (resolution.ok) {
      opts.auditLog.append(
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
        opts.auditLog.append(
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
      opts.auditLog.append(
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
      opts.auditLog.append(
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
    opts.auditLog.append(
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
    opts.auditLog.append(
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
    opts.auditLog.append(
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
  // Hardening wave 6 finding #78: track every staged storage location so
  // a re-key failure can roll back the partial import. Each entry is a
  // (namespace, key) tuple suitable for opts.storage.delete().
  const stagedLocations: StagedLocation[] = [];
  // Same accumulator for the per-entry rekey writes, populated by
  // rekeyState as it succeeds, consumed on failure.
  const importedRekeyEntries: StagedLocation[] = [];
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
  await stageArtifact(opts.storage, EXIT_IMPORT_NAMESPACE, importId, {
    manifest: manifest.body,
    verified_at: verification.verified_at,
    activated_at: new Date().toISOString(),
  });
  stagedLocations.push({ namespace: EXIT_IMPORT_NAMESPACE, key: importId });

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
  let stateResult: ImportExitBundleResult["state"];
  try {
    stateResult =
      encryptedState && encryptedState.json.entries.length > 0
        ? sourceMasterKey
          ? await rekeyState(
              encryptedState.json,
              opts,
              sourceMasterKey,
              publicKeys.byIdentityId,
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
            status: "not_requested" as const,
            imported_keys: 0,
            skipped_keys: 0,
            skipped_invalid_sig: 0,
            skipped_unknown_kid: 0,
            conflicts: 0,
          };
  } catch (err) {
    // Hardening wave 6 finding #78: re-key failed partway through.
    // Walk back through every successfully staged artifact and every
    // successfully imported state entry, then re-throw with an error
    // that names the cleanup so the operator can see what was undone.
    const toCleanup: StagedLocation[] = [
      ...importedRekeyEntries,
      ...stagedLocations,
    ];
    const cleanup = await cleanupStagedPaths(opts.storage, toCleanup);
    opts.auditLog.append(
      "l1",
      "exit_bundle_rekey_failed_cleanup",
      manifest.body.identity_binding.identity_id,
      {
        import_id: importId,
        manifest_version: manifest.body.manifest_version,
        rekey_entries_removed: importedRekeyEntries.length,
        staged_artifacts_removed: stagedLocations.length,
        removed_total: cleanup.removed,
        cleanup_failed_count: cleanup.failed.length,
        original_error: err instanceof Error ? err.message : String(err),
      },
      "failure"
    );
    await opts.auditLog.flush();
    const originalMessage = err instanceof Error ? err.message : String(err);
    throw new ExitBundleImportError(
      "REKEY_FAILED_AND_CLEANED",
      `Exit-bundle re-key failed: ${originalMessage}. ` +
        `Cleanup removed ${cleanup.removed} of ${toCleanup.length} staged paths ` +
        `(${importedRekeyEntries.length} re-keyed entries plus ${stagedLocations.length} staged artifacts; ` +
        `${cleanup.failed.length} cleanup deletes failed).`
    );
  }

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
