/**
 * Sanctuary v1.1 exit-bundle verifier.
 *
 * Verifies the signed SANCTUARY_EXIT_BUNDLE_V1 manifest, every artifact hash,
 * and the exported identity / reputation signatures and exported-set
 * completeness manifests that are independently verifiable from public
 * material in the bundle.
 */

/**
 * v1.2.1 (Finding PPP): thrown when a directory is not a valid exit bundle
 * (e.g., missing manifest.json). Distinguished from verification failures
 * (signature mismatch, hash mismatch) which return `passed: false`.
 */
export class InvalidExitBundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidExitBundleError";
  }
}

import { lstat, realpath } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import {
  EXIT_BUNDLE_ARTIFACT_KINDS,
  EXIT_BUNDLE_MANIFEST_VERSION,
  SIGNATURE_SCHEME_V1,
  type ExitBundleArtifactKind,
} from "../contracts/v1.1/constants.js";
import {
  EXIT_BUNDLE_PATH_MAX_BYTES,
  EXIT_BUNDLE_PATH_PATTERN,
  type ExitBundleArtifactEntry,
  type ExitBundleManifest,
  type ExitBundleVerifierResult,
} from "../contracts/v1.1/exit-bundle-manifest.js";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { parseKeyDerivationParams } from "../core/key-derivation.js";
import { hash } from "../core/hashing.js";
import { canonicalize, canonicalizeToBytes } from "../mesh/canonical-json.js";
import {
  reputationBundleSigningBytes,
  verifyReputationBundleCompleteness,
  type ReputationBundle,
  type ReputationBundleCompletenessVerification,
} from "../reputation/reputation-store.js";
import {
  readFileCustody,
  readFileCustodyWithStats,
} from "../storage/custody-fs.js";
import {
  readSourceCustodyState,
  type SourceCustodyState,
} from "./source-custody.js";

/**
 * Which re-key material the encrypted_state artifact DECLARES it needs, read
 * from the artifact alone (no fortress access, no operator secret).
 *
 * This is deliberately a statement about the ARTIFACT, not a prediction about
 * an import. Three successive attempts to make it the latter failed the same
 * way: a classifier that has no credential cannot know whether an import will
 * succeed, and each time it claimed to, the claim was wrong for some bundle.
 * Read every member below as "the bundle says it needs X", never as "X will
 * work":
 *
 *  `bundle-rekey-key`     a well-formed `source_custody` block is present, so
 *                         the bundle re-key key minted at export is the
 *                         credential it names.
 *  `legacy-passphrase`    no custody block, but well-formed legacy
 *                         `source_key_derivation` parameters, so the bundle
 *                         names the source fortress passphrase.
 *  `none-declared`        the artifact carries state and declares NO re-key
 *                         material of either kind. Pre-envelope bundles look
 *                         like this, and for them the source recovery key IS
 *                         the master - but nothing in the artifact says so, and
 *                         inspect does not guess (see the `--legacy-source-master`
 *                         opt-in on the import branch of `cli.ts`).
 *  `no-state`             the artifact carries a readable, empty entry list, so
 *                         it declares no re-key material because there is
 *                         nothing to re-key.
 *  `damaged`              the artifact DECLARES re-key material and that
 *                         material does not have a usable shape, or its entry
 *                         list cannot be read at all. Something is wrong with
 *                         the artifact itself; this one is a statement about
 *                         damage, not about what an import would do with it.
 *
 * CONTRACT PIN (server/src/exit/source-custody.ts `isValidSourceCustody` and
 * server/src/core/key-derivation.ts `parseKeyDerivationParams`): the two
 * shape-checks are not restated here - both sides call the same validators, so
 * `valid` and `malformed` mean here exactly what they mean at the import gate.
 * Held mechanically by the custody differential in
 * server/test/exit/exit-inspect-declares.test.ts, which drives every crafted
 * block through both `exit inspect` and a real `importExitBundle` and asserts
 * they never CONTRADICT each other.
 */
export type ExitBundleDeclaredRekeyMaterial =
  | "bundle-rekey-key"
  | "legacy-passphrase"
  | "none-declared"
  | "no-state"
  | "damaged";

/**
 * What the encrypted_state artifact says about itself, read from the parsed
 * JSON without trusting any declared type. Deliberately structural: the
 * verifier must not import `ExitEncryptedStateBundle` from bundle.ts (bundle.ts
 * already imports this module, and the reverse edge would be an import cycle),
 * and a verifier that narrows untrusted JSON itself is the right posture anyway.
 */
export interface ExitEncryptedStateSummary {
  /**
   * How many state entries the artifact carries, or `null` when its `entries`
   * field is absent or is not an array.
   *
   * INVARIANT: `null` is NOT `0`, and collapsing the two is the defect this
   * field's type exists to prevent. A malformed artifact reported as zero
   * entries reads to an operator as a benign empty bundle, and the import that
   * follows dereferences `entries.length` on the same artifact and does not
   * agree. Absent is not empty; every consumer must branch on it.
   */
  entry_count: number | null;
  namespace_count: number;
  namespaces: string[];
  ownership_partitioned: boolean;
  /**
   * CONTRACT PIN (server/src/exit/bundle.ts `EXIT_EMPTY_REASONS`): the token
   * set is owned there; this field carries whatever the artifact declared,
   * verbatim, so an unknown future token surfaces rather than being erased.
   */
  empty_reason?: string;
  /**
   * True IFF the artifact carries a READABLE, EMPTY entry list and declares no
   * `empty_reason`. False when `entry_count` is `null`: an artifact whose
   * entries cannot be read is a different, louder problem, and reporting a
   * missing empty-marker for it would name the wrong defect.
   */
  empty_reason_missing: boolean;
  legacy_kdf_params: "absent" | "valid" | "malformed";
  /**
   * The same three-state read of `source_custody` the import gate performs.
   * Reported alongside {@link declared_rekey_material} because both a damaged
   * custody block and a damaged legacy marker collapse to `damaged`, and the
   * operator needs to know WHICH block is broken to know what to re-export.
   */
  source_custody: SourceCustodyState;
  declared_rekey_material: ExitBundleDeclaredRekeyMaterial;
}

export interface ExitBundleDetailedVerifierResult
  extends ExitBundleVerifierResult {
  manifest_path: string;
  manifest_hash: string | null;
  warnings: string[];
  unsupported_artifacts: string[];
  /**
   * Additive: what the encrypted_state artifact carries and which credential
   * re-keys it. Absent when the bundle has no encrypted_state artifact or the
   * verifier failed before the artifact pass. This is a verifier-local
   * interface, NOT the frozen `ExitBundleVerifierResult` contract type.
   */
  state?: ExitEncryptedStateSummary;
  identity?: {
    signature_valid: boolean;
    identity_id?: string;
    did?: string;
  };
  audit?: {
    receipt_count: number;
    individual_signatures_verified: boolean;
  };
  reputation?: {
    bundle_signature_valid: boolean | "unverifiable";
    completeness:
      | ReputationBundleCompletenessVerification
      | "mismatch";
    completeness_error?: string;
    attestation_count: number;
    verified_attestations: number;
    invalid_attestations: number;
    unverifiable_attestations: number;
  };
}

export interface LoadedExitArtifact<T = unknown> {
  entry: ExitBundleArtifactEntry;
  path: string;
  json: T;
  bytes: Uint8Array;
}

const PRIVATE_MATERIAL_KEYS = new Set([
  "private_key",
  "privatekey",
  "encrypted_private_key",
  "encryptedprivatekey",
  "passphrase",
  "recovery_key",
  "recoverykey",
  "seed",
  "mnemonic",
]);

function sha256Hex(bytes: Uint8Array): string {
  return Array.from(hash(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function resultBase(
  bundleDir: string,
  manifest: ExitBundleManifest | null,
  warnings: string[] = [],
  unsupported: string[] = []
): ExitBundleDetailedVerifierResult {
  const body = manifest?.body;
  return {
    version: "1.1",
    passed: false,
    verified_at: new Date().toISOString(),
    manifest_path: join(bundleDir, "manifest.json"),
    manifest_hash: null,
    manifest_summary: {
      manifest_version:
        body?.manifest_version ?? EXIT_BUNDLE_MANIFEST_VERSION,
      fortress_id: body?.identity_binding?.fortress_id ?? "",
      identity_id: body?.identity_binding?.identity_id ?? "",
      exported_at: body?.exported_at ?? "",
      artifact_count: body?.artifacts?.length ?? 0,
    },
    artifact_results:
      body?.artifacts?.map((artifact) => ({
        path: artifact.path,
        kind: artifact.kind,
        hash_passed: false,
        size_passed: false,
      })) ?? [],
    warnings,
    unsupported_artifacts: unsupported,
  };
}

function fail(
  bundleDir: string,
  manifest: ExitBundleManifest | null,
  failureClass: NonNullable<ExitBundleVerifierResult["failure_class"]>,
  warnings: string[] = [],
  unsupported: string[] = []
): ExitBundleDetailedVerifierResult {
  return {
    ...resultBase(bundleDir, manifest, warnings, unsupported),
    failure_class: failureClass,
  };
}

function isKnownKind(kind: string): kind is ExitBundleArtifactKind {
  return (EXIT_BUNDLE_ARTIFACT_KINDS as readonly string[]).includes(kind);
}

function validateArtifactPath(path: string): "ok" | "unsafe" {
  if (Buffer.byteLength(path, "utf8") > EXIT_BUNDLE_PATH_MAX_BYTES) {
    return "unsafe";
  }
  if (!EXIT_BUNDLE_PATH_PATTERN.test(path)) return "unsafe";
  if (path.startsWith("/") || path.includes("\\") || path.includes("\0")) {
    return "unsafe";
  }
  const normalized = decodeURIComponentSafe(path).normalize("NFKC");
  if (normalized.split("/").some((segment) => segment === "." || segment === "..")) {
    return "unsafe";
  }
  return "ok";
}

function decodeURIComponentSafe(value: string): string {
  let current = value;
  for (let i = 0; i < 2; i++) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) return decoded;
      current = decoded;
    } catch {
      return current;
    }
  }
  return current;
}

async function assertDescendant(root: string, candidate: string): Promise<boolean> {
  const rootReal = await realpath(root);
  const candidateDir = await realpath(dirname(candidate));
  const rootWithSep = rootReal.endsWith(sep) ? rootReal : rootReal + sep;
  return candidateDir === rootReal || candidateDir.startsWith(rootWithSep);
}

function findPrivateMaterial(value: unknown, path = "$"): string[] {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      findPrivateMaterial(item, `${path}[${index}]`)
    );
  }

  const findings: string[] = [];
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const normalized = key.toLowerCase().replace(/[-\s]/g, "_");
    if (PRIVATE_MATERIAL_KEYS.has(normalized)) {
      findings.push(`${path}.${key}`);
      continue;
    }
    findings.push(...findPrivateMaterial(child, `${path}.${key}`));
  }
  return findings;
}

/**
 * Summarize a parsed `artifacts/encrypted_state.json`. Pure, total, and
 * defensive: every field is narrowed from `unknown`, so a hand-crafted or
 * truncated artifact yields a conservative summary rather than throwing.
 *
 * @param artifact - the parsed encrypted_state JSON (already hash-verified
 *   against the signed manifest by the caller).
 */
export function summarizeEncryptedState(
  artifact: unknown
): ExitEncryptedStateSummary {
  const record =
    artifact !== null && typeof artifact === "object" && !Array.isArray(artifact)
      ? (artifact as Record<string, unknown>)
      : {};
  // INVARIANT: an unreadable `entries` field becomes `null`, never `[]`. The
  // substitution that reads naturally here - default to an empty array and
  // report its length - is precisely the absent-as-benign conflation: it turns
  // a corrupt artifact into a confident "0 entries" for the operator while the
  // import path, which reads `entries.length` off the same JSON, does something
  // else entirely.
  const entries: unknown[] | null = Array.isArray(record.entries)
    ? record.entries
    : null;
  const namespaces = Array.isArray(record.namespaces)
    ? record.namespaces.filter((n): n is string => typeof n === "string")
    : [];
  const emptyReason =
    typeof record.empty_reason === "string" ? record.empty_reason : undefined;

  // CONTRACT PIN (server/src/core/key-derivation.ts parseKeyDerivationParams):
  // the same validator the export embed-gate and the import derive-gate use, so
  // "malformed" here means exactly what makes an import refuse.
  const legacyKdfParams: ExitEncryptedStateSummary["legacy_kdf_params"] =
    record.source_key_derivation === undefined
      ? "absent"
      : parseKeyDerivationParams(record.source_key_derivation).ok
        ? "valid"
        : "malformed";

  // CONTRACT PIN (server/src/exit/source-custody.ts `readSourceCustodyState`):
  // the same predicate import's `validateSourceCustody` refuses on, so
  // "malformed" here means exactly what makes an import throw
  // SOURCE_CUSTODY_MALFORMED. An object-shape check was NOT enough: it reported
  // a live re-key path for a block no import would accept.
  const sourceCustody = readSourceCustodyState(record.source_custody);

  let declared: ExitBundleDeclaredRekeyMaterial;
  if (entries === null) {
    // An unreadable entry list is damage, and it is NOT the zero-entry case:
    // reporting "no state, no credential needed" for an artifact whose entries
    // cannot be read is the absent-as-benign conflation, and the import reads
    // `entries.length` off the same JSON and does not agree.
    declared = "damaged";
  } else if (entries.length === 0) {
    declared = "no-state";
  } else if (sourceCustody === "malformed" || legacyKdfParams === "malformed") {
    declared = "damaged";
  } else if (sourceCustody === "valid") {
    declared = "bundle-rekey-key";
  } else if (legacyKdfParams === "valid") {
    declared = "legacy-passphrase";
  } else {
    declared = "none-declared";
  }

  return {
    entry_count: entries === null ? null : entries.length,
    namespace_count: namespaces.length,
    namespaces,
    ownership_partitioned: record.ownership_partitioned === true,
    ...(emptyReason !== undefined ? { empty_reason: emptyReason } : {}),
    empty_reason_missing: entries?.length === 0 && emptyReason === undefined,
    legacy_kdf_params: legacyKdfParams,
    source_custody: sourceCustody,
    declared_rekey_material: declared,
  };
}

export async function readManifest(bundleDir: string): Promise<ExitBundleManifest> {
  const bytes = await readFileCustody(join(bundleDir, "manifest.json"), {
    verifyPathIdentity: true,
  });
  return JSON.parse(Buffer.from(bytes).toString("utf8")) as ExitBundleManifest;
}

export async function loadExitArtifact<T = unknown>(
  bundleDir: string,
  manifest: ExitBundleManifest,
  kind: ExitBundleArtifactKind
): Promise<LoadedExitArtifact<T> | null> {
  const entry = manifest.body.artifacts.find((artifact) => artifact.kind === kind);
  if (!entry) return null;
  const artifactPath = join(bundleDir, entry.path);
  const bytes = await readFileCustody(artifactPath, {
    verifyPathIdentity: true,
  });
  return {
    entry,
    path: artifactPath,
    bytes: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    json: JSON.parse(Buffer.from(bytes).toString("utf8")) as T,
  };
}

function verifyIdentityArtifact(
  identityArtifact: unknown
): {
  signature_valid: boolean;
  identity_id?: string;
  did?: string;
  public_key?: string;
} {
  const wrapper = identityArtifact as {
    bundle?: Record<string, unknown>;
    signature?: string;
  };
  const bundle = wrapper.bundle;
  if (!bundle || typeof wrapper.signature !== "string") {
    return { signature_valid: false };
  }
  const publicKey = bundle.publicKey;
  if (typeof publicKey !== "string") {
    return { signature_valid: false };
  }
  const signatureValid = ed25519.verify(
    fromBase64url(wrapper.signature),
    canonicalizeToBytes(bundle),
    fromBase64url(publicKey)
  );
  return {
    signature_valid: signatureValid,
    identity_id:
      typeof bundle.identity_id === "string" ? bundle.identity_id : undefined,
    did: typeof bundle.did === "string" ? bundle.did : undefined,
    public_key: publicKey,
  };
}

function verifyReputationArtifact(
  reputationArtifact: unknown,
  publicKeysByDid: Map<string, Uint8Array>
): ExitBundleDetailedVerifierResult["reputation"] {
  const bundle = reputationArtifact as Partial<ReputationBundle>;
  const attestations = Array.isArray(bundle.attestations)
    ? bundle.attestations
    : [];

  let bundleSignatureValid: boolean | "unverifiable" = "unverifiable";
  if (
    bundle.version === "SANCTUARY_REP_V1" &&
    typeof bundle.exported_at === "string" &&
    typeof bundle.exporter_did === "string" &&
    typeof bundle.bundle_signature === "string"
  ) {
    const exporterKey = publicKeysByDid.get(bundle.exporter_did);
    if (exporterKey) {
      const signedBody = {
        version: "SANCTUARY_REP_V1" as const,
        attestations,
        exported_at: bundle.exported_at,
        exporter_did: bundle.exporter_did,
        completeness_manifest: bundle.completeness_manifest,
      };
      const signature = fromBase64url(bundle.bundle_signature);
      const currentSignatureValid = ed25519.verify(
        signature,
        reputationBundleSigningBytes(signedBody),
        exporterKey
      );
      const legacySignatureValid =
        bundle.completeness_manifest === undefined &&
        ed25519.verify(
          signature,
          stringToBytes(
            JSON.stringify({
              version: signedBody.version,
              attestations: signedBody.attestations,
              exported_at: signedBody.exported_at,
              exporter_did: signedBody.exporter_did,
            })
          ),
          exporterKey
        );
      bundleSignatureValid = currentSignatureValid || legacySignatureValid;
    }
  }

  let completeness:
    | ReputationBundleCompletenessVerification
    | "mismatch" = "mismatch";
  let completenessError: string | undefined;
  try {
    completeness = verifyReputationBundleCompleteness(bundle, {
      allowUnverifiedLegacy: true,
    });
  } catch (error) {
    completenessError =
      error instanceof Error
        ? error.message
        : "Reputation bundle completeness verification failed";
  }

  let verified = 0;
  let invalid = 0;
  let unverifiable = 0;
  for (const attestation of attestations) {
    const signerKey = publicKeysByDid.get(attestation.signer);
    if (!signerKey) {
      unverifiable++;
      continue;
    }
    const ok = ed25519.verify(
      fromBase64url(attestation.signature),
      stringToBytes(JSON.stringify(attestation.data)),
      signerKey
    );
    if (ok) verified++;
    else invalid++;
  }

  return {
    bundle_signature_valid: bundleSignatureValid,
    completeness,
    ...(completenessError !== undefined
      ? { completeness_error: completenessError }
      : {}),
    attestation_count: attestations.length,
    verified_attestations: verified,
    invalid_attestations: invalid,
    unverifiable_attestations: unverifiable,
  };
}

/**
 * Caller-supplied verifier knobs. v1.0.2 / full-sweep #55.
 *
 * `acceptUnverifiableAttestations` flips the bundle verdict from strict-by-default
 * (any unverifiable attestation fails the bundle) to a relaxed verdict that
 * tolerates attestations whose signer DID is not in the bundle's published
 * identity material. Operators opt in explicitly through the CLI
 * `--accept-unverifiable-attestations` flag (Tier 1 confirmation).
 */
export interface VerifyExitBundleOptions {
  acceptUnverifiableAttestations?: boolean;
}

export async function verifyExitBundle(
  bundleDir: string,
  options: VerifyExitBundleOptions = {}
): Promise<ExitBundleDetailedVerifierResult> {
  const root = resolve(bundleDir);
  let manifest: ExitBundleManifest;
  let manifestBytes: Uint8Array;
  try {
    const raw = await readFileCustody(join(root, "manifest.json"), {
      verifyPathIdentity: true,
    });
    manifestBytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
    manifest = JSON.parse(Buffer.from(raw).toString("utf8")) as ExitBundleManifest;
  } catch {
    throw new InvalidExitBundleError(
      `Not a valid SANCTUARY_EXIT_BUNDLE_V1 directory: manifest.json missing at ${join(root, "manifest.json")}`,
    );
  }

  const warnings: string[] = [];
  const unsupportedArtifacts: string[] = [];
  const body = manifest.body;
  if (!body || body.manifest_version !== EXIT_BUNDLE_MANIFEST_VERSION) {
    return fail(root, manifest, "manifest_unknown_version", warnings, unsupportedArtifacts);
  }
  if (body.signature_scheme !== SIGNATURE_SCHEME_V1) {
    return fail(
      root,
      manifest,
      "manifest_signature_scheme_invalid",
      warnings,
      unsupportedArtifacts
    );
  }

  const seenPaths = new Set<string>();
  for (const artifact of body.artifacts) {
    if (!isKnownKind(artifact.kind)) {
      return fail(root, manifest, "other", [`unknown artifact kind: ${artifact.kind}`]);
    }
    if (seenPaths.has(artifact.path)) {
      return fail(root, manifest, "artifact_path_duplicate", warnings, unsupportedArtifacts);
    }
    seenPaths.add(artifact.path);
    if (validateArtifactPath(artifact.path) !== "ok") {
      return fail(root, manifest, "artifact_path_unsafe", warnings, unsupportedArtifacts);
    }
  }

  const signatureOk = ed25519.verify(
    fromBase64url(manifest.signature),
    canonicalizeToBytes(body),
    fromBase64url(body.identity_binding.fortress_master_pubkey)
  );
  if (!signatureOk) {
    return fail(root, manifest, "manifest_signature_invalid", warnings, unsupportedArtifacts);
  }

  const expectedAggregate = sha256Hex(
    stringToBytes(canonicalize(body.artifacts))
  );
  if (expectedAggregate !== body.artifacts_aggregate_hash) {
    return fail(root, manifest, "aggregate_hash_mismatch", warnings, unsupportedArtifacts);
  }

  const artifactResults: ExitBundleVerifierResult["artifact_results"] = [];
  let artifactFailure:
    | NonNullable<ExitBundleVerifierResult["failure_class"]>
    | null = null;
  // Captured from the artifact-hash pass below rather than re-read afterwards:
  // the loop already parses every artifact for the private-material scan, and a
  // second read could observe a DIFFERENT file than the one just hash-verified.
  let encryptedStateJson: unknown;
  let sawEncryptedState = false;

  for (const artifact of body.artifacts) {
    const artifactPath = join(root, artifact.path);
    let bytes: Uint8Array;
    let fileSize: number;
    try {
      const linkStat = await lstat(artifactPath);
      if (linkStat.isSymbolicLink()) {
        artifactFailure = "archive_contains_symlink";
        artifactResults.push({
          path: artifact.path,
          kind: artifact.kind,
          hash_passed: false,
          size_passed: false,
        });
        continue;
      }
      const descends = await assertDescendant(root, artifactPath);
      if (!descends) {
        artifactFailure = "artifact_path_escapes_root";
        artifactResults.push({
          path: artifact.path,
          kind: artifact.kind,
          hash_passed: false,
          size_passed: false,
        });
        continue;
      }
      const { data: raw, stats: fileStat } = await readFileCustodyWithStats(
        artifactPath,
        { verifyPathIdentity: true },
      );
      fileSize = fileStat.size;
      bytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
    } catch {
      artifactFailure = "artifact_missing";
      artifactResults.push({
        path: artifact.path,
        kind: artifact.kind,
        hash_passed: false,
        size_passed: false,
      });
      continue;
    }

    const hashPassed = sha256Hex(bytes) === artifact.hash;
    const sizePassed = fileSize === artifact.size_bytes;
    if (!hashPassed && !artifactFailure) artifactFailure = "artifact_hash_mismatch";
    if (!sizePassed && !artifactFailure) artifactFailure = "artifact_size_mismatch";
    artifactResults.push({
      path: artifact.path,
      kind: artifact.kind,
      hash_passed: hashPassed,
      size_passed: sizePassed,
    });

    try {
      const parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
      if (artifact.kind === "encrypted_state") {
        encryptedStateJson = parsed;
        sawEncryptedState = true;
      }
      const privateFindings = findPrivateMaterial(parsed);
      if (privateFindings.length > 0) {
        artifactFailure = "private_material_present";
        warnings.push(
          `${artifact.path} contains private-material field(s): ${privateFindings.join(", ")}`
        );
      }
    } catch {
      warnings.push(`${artifact.path} is not parseable JSON`);
    }
  }

  if (artifactFailure) {
    return {
      ...fail(root, manifest, artifactFailure, warnings, unsupportedArtifacts),
      manifest_hash: sha256Hex(manifestBytes),
      artifact_results: artifactResults,
    };
  }

  const stateSummary = sawEncryptedState
    ? summarizeEncryptedState(encryptedStateJson)
    : undefined;
  if (stateSummary !== undefined && stateSummary.entry_count === null) {
    warnings.push(
      "encrypted state carries no readable entries list (the `entries` field " +
        "is absent or is not an array): this artifact is signed and " +
        "hash-verified but structurally damaged, and it is NOT an empty " +
        "bundle - re-export from the source fortress"
    );
  }
  if (stateSummary?.empty_reason_missing === true) {
    warnings.push(
      "encrypted state carries zero entries and no empty_reason marker: " +
        "exported by a pre-marker (or buggy) exporter; cannot distinguish an " +
        "empty fortress from a broken export - verify the source fortress " +
        "before treating this as a complete exit"
    );
  }
  if (stateSummary?.legacy_kdf_params === "malformed") {
    warnings.push(
      "encrypted state carries malformed legacy re-key parameters " +
        "(source_key_derivation): the bundle is signed and intact, but its " +
        "passphrase re-key path cannot run. Re-export from the source fortress"
    );
  }

  const publicKeysByDid = new Map<string, Uint8Array>();
  const identityArtifact = await loadExitArtifact(root, manifest, "public_identity");
  let identity: ExitBundleDetailedVerifierResult["identity"] | undefined;
  if (identityArtifact) {
    const identityVerification = verifyIdentityArtifact(identityArtifact.json);
    identity = {
      signature_valid: identityVerification.signature_valid,
      identity_id: identityVerification.identity_id,
      did: identityVerification.did,
    };
    if (identityVerification.did && identityVerification.public_key) {
      publicKeysByDid.set(
        identityVerification.did,
        fromBase64url(identityVerification.public_key)
      );
    }
    if (!identityVerification.signature_valid) {
      warnings.push("public identity artifact signature is invalid");
    }
  }

  const auditArtifact = await loadExitArtifact(root, manifest, "audit_receipts");
  const audit = auditArtifact
    ? {
        receipt_count: Array.isArray((auditArtifact.json as { entries?: unknown[] }).entries)
          ? ((auditArtifact.json as { entries: unknown[] }).entries.length)
          : 0,
        individual_signatures_verified: false,
      }
    : undefined;
  if (auditArtifact) {
    unsupportedArtifacts.push(
      "audit_receipts: individual audit entries are not signed in the legacy L2 audit log; verifier pins them by signed manifest hash"
    );
    // Surface the export-cap truncation marker so the operator is told the
    // carried receipts are an incomplete (most-recent) slice, not the full
    // population that `total` reports.
    const auditJson = auditArtifact.json as {
      truncated?: unknown;
      omitted_count?: unknown;
    };
    if (auditJson.truncated === true) {
      const omitted =
        typeof auditJson.omitted_count === "number"
          ? auditJson.omitted_count
          : undefined;
      warnings.push(
        omitted !== undefined
          ? `audit receipts are truncated: the oldest ${omitted} entries were omitted by the export cap`
          : "audit receipts are truncated: the oldest entries were omitted by the export cap"
      );
    }
  }

  const reputationArtifact = await loadExitArtifact(root, manifest, "reputation_bundle");
  const reputation = reputationArtifact
    ? verifyReputationArtifact(reputationArtifact.json, publicKeysByDid)
    : undefined;
  if (reputation) {
    if (reputation.bundle_signature_valid === "unverifiable") {
      warnings.push("reputation bundle signature is unverifiable from included public identities");
    } else if (!reputation.bundle_signature_valid) {
      warnings.push("reputation bundle signature is invalid");
    }
    if (reputation.unverifiable_attestations > 0) {
      warnings.push(
        `${reputation.unverifiable_attestations} reputation attestation(s) have unknown signer public keys`
      );
    }
    if (reputation.invalid_attestations > 0) {
      warnings.push(
        `${reputation.invalid_attestations} reputation attestation(s) failed signature verification`
      );
    }
    if (reputation.completeness === "mismatch") {
      warnings.push(
        reputation.completeness_error !== undefined
          ? `reputation bundle completeness mismatch: ${reputation.completeness_error}`
          : "reputation bundle completeness mismatch"
      );
    } else if (
      reputation.completeness === "unverified-completeness-legacy-bundle"
    ) {
      warnings.push(
        "reputation bundle has no completeness manifest; exported-set completeness is unverified"
      );
    }
  }

  const reputationBundleFailed = reputation?.bundle_signature_valid === false;
  const reputationAttestationFailed = (reputation?.invalid_attestations ?? 0) > 0;
  const reputationCompletenessFailed = reputation?.completeness === "mismatch";
  const reputationFailed =
    reputationBundleFailed ||
    reputationAttestationFailed ||
    reputationCompletenessFailed;
  const identityFailed = identity ? !identity.signature_valid : false;
  const unverifiableCount = reputation?.unverifiable_attestations ?? 0;
  const unverifiableFailed =
    unverifiableCount > 0 && !options.acceptUnverifiableAttestations;
  if (unverifiableFailed) {
    warnings.push(
      `${unverifiableCount} reputation attestation(s) have unknown signer public keys; ` +
        `pass --accept-unverifiable-attestations to relax this read-only preview ` +
        `verdict. Import is unaffected: it always verifies strictly and never ` +
        `admits an unverifiable attestation.`
    );
  }

  // Full-sweep #77: route the specific failure cause so importers and
  // operators see what went wrong without having to parse the warnings
  // array. Priority ordering: identity (cryptographic-binding broken)
  // beats reputation-bundle (provenance broken) beats completeness
  // mismatch (signed manifest does not describe the body) beats
  // individual attestation invalidity beats unverifiable signers
  // (which is policy-relaxable via the explicit opt-in flag).
  let detailedFailureClass:
    | NonNullable<ExitBundleVerifierResult["failure_class"]>
    | undefined;
  if (identityFailed) {
    detailedFailureClass = "identity_signature_invalid";
  } else if (reputationBundleFailed) {
    detailedFailureClass = "reputation_bundle_signature_invalid";
  } else if (reputationCompletenessFailed) {
    detailedFailureClass = "reputation_completeness_mismatch";
  } else if (reputationAttestationFailed) {
    detailedFailureClass = "reputation_attestation_signature_invalid";
  } else if (unverifiableFailed) {
    detailedFailureClass = "reputation_unverifiable_attestations";
  }

  return {
    version: "1.1",
    passed: !reputationFailed && !identityFailed && !unverifiableFailed,
    verified_at: new Date().toISOString(),
    manifest_path: join(root, "manifest.json"),
    manifest_hash: sha256Hex(manifestBytes),
    manifest_summary: {
      manifest_version: body.manifest_version,
      fortress_id: body.identity_binding.fortress_id,
      identity_id: body.identity_binding.identity_id,
      exported_at: body.exported_at,
      artifact_count: body.artifacts.length,
    },
    artifact_results: artifactResults,
    warnings,
    unsupported_artifacts: unsupportedArtifacts,
    identity,
    audit,
    reputation,
    ...(stateSummary !== undefined ? { state: stateSummary } : {}),
    failure_class: detailedFailureClass,
  };
}
