/**
 * Sanctuary v1.1 exit-bundle verifier.
 *
 * Verifies the signed SANCTUARY_EXIT_BUNDLE_V1 manifest, every artifact hash,
 * and the exported identity / reputation signatures that are independently
 * verifiable from public material in the bundle.
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
import { hash } from "../core/hashing.js";
import { canonicalize, canonicalizeToBytes } from "../mesh/canonical-json.js";
import {
  reputationBundleSigningBytes,
  type ReputationBundle,
} from "../reputation/reputation-store.js";
import {
  readFileCustody,
  readFileCustodyWithStats,
} from "../storage/custody-fs.js";

export interface ExitBundleDetailedVerifierResult
  extends ExitBundleVerifierResult {
  manifest_path: string;
  manifest_hash: string | null;
  warnings: string[];
  unsupported_artifacts: string[];
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
  }

  const reputationBundleFailed = reputation?.bundle_signature_valid === false;
  const reputationAttestationFailed = (reputation?.invalid_attestations ?? 0) > 0;
  const reputationFailed = reputationBundleFailed || reputationAttestationFailed;
  const identityFailed = identity ? !identity.signature_valid : false;
  const unverifiableCount = reputation?.unverifiable_attestations ?? 0;
  const unverifiableFailed =
    unverifiableCount > 0 && !options.acceptUnverifiableAttestations;
  if (unverifiableFailed) {
    warnings.push(
      `${unverifiableCount} reputation attestation(s) have unknown signer public keys; ` +
        `pass --accept-unverifiable-attestations to import anyway`
    );
  }

  // Full-sweep #77: route the specific failure cause so importers and
  // operators see what went wrong without having to parse the warnings
  // array. Priority ordering: identity (cryptographic-binding broken)
  // beats reputation-bundle (provenance broken) beats individual
  // attestation invalidity beats unverifiable signers (which is
  // policy-relaxable via the explicit opt-in flag).
  let detailedFailureClass:
    | NonNullable<ExitBundleVerifierResult["failure_class"]>
    | undefined;
  if (identityFailed) {
    detailedFailureClass = "identity_signature_invalid";
  } else if (reputationBundleFailed) {
    detailedFailureClass = "reputation_bundle_signature_invalid";
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
    failure_class: detailedFailureClass,
  };
}
