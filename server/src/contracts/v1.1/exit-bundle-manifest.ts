/**
 * Sanctuary v1.1 — Exit Bundle Manifest Contract
 *
 * `SANCTUARY_EXIT_BUNDLE_V1` is the canonical manifest produced by the v1.1
 * exit-bundle workstream (Prompt 7) and consumed by the standalone verifier
 * CLI plus the import command.
 *
 * Local-only invariant:
 * The bundle is produced by a single fortress on a single operator's machine
 * and consumed by another single-operator destination. v1.1 ships local-only,
 * single-operator scope. Cross-operator transfer is deferred to v1.3.
 *
 * Identity-binding invariant:
 * The manifest is signed by the operator's fortress-master identity. The
 * verifier MUST refuse to activate any artifact whose hash chain does not
 * match the manifest, and MUST refuse to activate any manifest whose
 * signature does not verify against the bound public identity.
 *
 * Public-only invariant:
 * The bundle MUST NOT contain private keys, raw passphrases, or recovery
 * seeds. Encrypted state may travel inside the bundle, but the master key
 * MUST NOT. Re-keying happens on import using new operator-supplied
 * material.
 *
 * Manifest-version invariant:
 * v1.1 ships only "SANCTUARY_EXIT_BUNDLE_V1". Future versions land through
 * coordinator-approved spec amendments. v1.1 verifiers MUST reject unknown
 * manifest versions rather than silently accept.
 */

import type {
  ExitBundleArtifactKind,
  ExitBundleManifestVersion,
  SignatureScheme,
} from "./constants.js";

/**
 * Hashing algorithm identifier embedded in every artifact entry. v1.1 uses
 * SHA-256. Forward-compat: a future bundle version may add SHA-3 or BLAKE3.
 */
export type ExitBundleHashAlg = "sha256";

/**
 * One artifact entry inside the manifest. Each artifact lives at a relative
 * path inside the bundle archive. The verifier reads the file at that path
 * and confirms its hash.
 */
export interface ExitBundleArtifactEntry {
  /** Coarse artifact kind. */
  kind: ExitBundleArtifactKind;
  /** Relative path inside the bundle, POSIX-style. */
  path: string;
  /** Hash algorithm. v1.1 ships only "sha256". */
  hash_alg: ExitBundleHashAlg;
  /** Hex-encoded artifact hash. */
  hash: string;
  /** Size in bytes. Convenience field; verifier MAY skip if it independently sizes the file. */
  size_bytes: number;
  /**
   * Optional discriminator inside the kind, e.g., "audit-receipt-2026-Q2".
   * Verifier does not interpret this; the import command may use it to order
   * artifacts.
   */
  subkind?: string;
}

/**
 * Identity binding embedded in the manifest. Carries only public material.
 */
export interface ExitBundleIdentityBinding {
  /** Operator identity id. */
  identity_id: string;
  /** Fortress id. */
  fortress_id: string;
  /** Base64url-encoded Ed25519 public key of the fortress-master. */
  fortress_master_pubkey: string;
  /** Optional DID, when one is bound to this identity. */
  did?: string;
}

/**
 * v1 manifest body — what the operator's fortress-master signs.
 */
export interface ExitBundleManifestBody {
  /** Manifest version constant. */
  manifest_version: ExitBundleManifestVersion;
  /** ISO8601 timestamp at export time. */
  exported_at: string;
  /** Source fortress / operator identity binding. */
  identity_binding: ExitBundleIdentityBinding;
  /**
   * Sanctuary version string at export time. Verifier surfaces version skew
   * to the operator if the destination fortress is older.
   */
  source_sanctuary_version: string;
  /** Every artifact carried in the bundle. */
  artifacts: ExitBundleArtifactEntry[];
  /**
   * Aggregate hash over canonicalize(artifacts[]). Lets the verifier perform
   * a fast sanity check before walking each entry.
   */
  artifacts_aggregate_hash: string;
  /** Aggregate hash algorithm. v1.1 ships only "sha256". */
  artifacts_aggregate_hash_alg: ExitBundleHashAlg;
  /**
   * Tier 1 audit-event id that captured the export approval. Consumers MAY
   * cross-reference with the source fortress audit chain.
   */
  export_approval_audit_id: string;
}

/**
 * Full signed manifest. Top-level shape that ships in the bundle archive.
 */
export interface ExitBundleManifest {
  /** Body — what the signature covers. */
  body: ExitBundleManifestBody;
  /**
   * Base64url-encoded Ed25519 signature over canonicalize(body) by the
   * fortress-master private key. The bundle archive is otherwise unsigned;
   * artifact integrity comes from artifact hashes inside the body.
   */
  signature: string;
  /** Signature scheme. v1.1 ships only "ed25519-v1". */
  signature_scheme: SignatureScheme;
}

/**
 * Verifier output shape. The standalone verifier CLI emits this structure on
 * stdout (or as JSON for tool consumers) so import commands can branch
 * cleanly. v1.1 ships one VerifierResult shape; future versions extend.
 */
export interface ExitBundleVerifierResult {
  version: "1.1";
  /** True iff manifest signature, every artifact hash, and the aggregate hash all verify. */
  passed: boolean;
  /** ISO8601 timestamp of verification. */
  verified_at: string;
  /** Reference to the verified manifest body. */
  manifest_summary: {
    manifest_version: ExitBundleManifestVersion;
    fortress_id: string;
    identity_id: string;
    exported_at: string;
    artifact_count: number;
  };
  /**
   * Per-artifact verification result. Order matches `manifest.body.artifacts`.
   */
  artifact_results: Array<{
    path: string;
    kind: ExitBundleArtifactKind;
    hash_passed: boolean;
    size_passed: boolean;
  }>;
  /**
   * Coarse failure-class enum, when `passed` is false. Distinct from a free-text
   * error message so import commands can branch.
   */
  failure_class?:
    | "manifest_signature_invalid"
    | "manifest_unknown_version"
    | "artifact_hash_mismatch"
    | "artifact_missing"
    | "artifact_size_mismatch"
    | "aggregate_hash_mismatch"
    | "private_material_present"
    | "other";
}
