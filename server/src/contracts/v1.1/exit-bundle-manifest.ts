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
 * Safe-path rules for `ExitBundleArtifactEntry.path`.
 *
 * The verifier MUST reject any artifact entry whose `path` does not satisfy
 * EVERY rule below. The export command MUST refuse to emit a manifest
 * containing any path that fails any rule. Together these constraints
 * defeat path-traversal, separator-bypass, and link-substitution attacks
 * that would otherwise let a malicious bundle write outside the extraction
 * root or impersonate a different artifact.
 *
 * Rejection rules:
 *
 *   1. Path MUST match `EXIT_BUNDLE_PATH_PATTERN`. POSIX-style only:
 *      lowercase `[a-z0-9._-]+` segments separated by single forward
 *      slashes. No leading slash. No trailing slash. No empty segments.
 *      No segment equal to "." or "..". Maximum total length 256 bytes.
 *
 *   2. Path MUST NOT be absolute (no leading "/" or drive letter).
 *
 *   3. Path MUST NOT contain ".." in any segment, in any encoding
 *      (URL-encoded, double-encoded, percent-encoded, Unicode-normalized).
 *      Verifier MUST decode and normalize before checking.
 *
 *   4. Path MUST NOT contain backslashes ("\\"), null bytes ("\\0"), or any
 *      character outside the regex range. Windows-style separators are
 *      rejected even on Windows hosts; POSIX-style is canonical.
 *
 *   5. Two `ExitBundleArtifactEntry` entries within a single manifest MUST
 *      NOT share the same `path`. Duplicate paths are rejected.
 *
 *   6. The verifier MUST refuse to follow filesystem symlinks or hardlinks
 *      during extraction. If the archive format embeds link entries, the
 *      verifier rejects the entire bundle.
 *
 *   7. Resolved extraction destination (extraction_root + path) MUST be a
 *      direct descendant of `extraction_root`. Verifier MUST `realpath`
 *      both sides and confirm the prefix match before opening any file.
 *
 *   8. The verifier MUST NOT extract before verification. Verification
 *      reads from the archive in-place; extraction (if any) happens only
 *      after every artifact's hash + size pass.
 */
export const EXIT_BUNDLE_PATH_PATTERN = /^[a-z0-9._-]+(?:\/[a-z0-9._-]+)*$/;
export const EXIT_BUNDLE_PATH_MAX_BYTES = 256;

/**
 * One artifact entry inside the manifest. Each artifact lives at a relative
 * path inside the bundle archive. The verifier reads the file at that path
 * and confirms its hash. See `EXIT_BUNDLE_PATH_PATTERN` and the safe-path
 * rules block above for the full set of constraints.
 */
export interface ExitBundleArtifactEntry {
  /** Coarse artifact kind. */
  kind: ExitBundleArtifactKind;
  /**
   * Relative path inside the bundle, POSIX-style. MUST satisfy
   * `EXIT_BUNDLE_PATH_PATTERN` and the safe-path rules block above.
   * The verifier rejects any entry whose path is absolute, contains "..",
   * contains backslashes, or duplicates another entry's path. The verifier
   * does NOT follow symlinks or hardlinks during extraction.
   */
  path: string;
  /** Hash algorithm. v1.1 ships only "sha256". */
  hash_alg: ExitBundleHashAlg;
  /** Hex-encoded artifact hash. */
  hash: string;
  /** Size in bytes. Verifier MAY independently re-size and reject on mismatch. */
  size_bytes: number;
  /**
   * Optional discriminator inside the kind, e.g., "audit-receipt-2026-Q2".
   * Verifier does not interpret this; the import command may use it to order
   * artifacts. Same path-pattern constraints DO NOT apply to subkind, but
   * subkind MUST NOT contain control characters.
   */
  subkind?: string;
}

/**
 * did:web pointer embedded in the identity binding when the operator
 * has issued a did:web identifier for the source fortress and asked
 * the exit-bundle exporter to publish that pointer alongside the
 * manifest (Recognition-Layer Path C primary build 2).
 *
 * The bundle does NOT carry the did:web DID Document itself; the
 * receiving regime resolves the DID Document via standard DNS + TLS
 * against `authority_host`. That dependency is intentional: it is
 * the operator's HTTPS infrastructure that publishes the document,
 * not Sanctuary's, and it is the receiving regime's resolver that
 * verifies the document, not Sanctuary's. Recognition flows along
 * the web's existing trust chain without trusting Sanctuary as a
 * middleman.
 *
 * The signature scheme over the manifest body covers this field by
 * construction (it lives inside `ExitBundleManifestBody`), so an
 * attacker who substituted the did:web pointer without re-signing
 * the body would be rejected at the existing manifest-signature
 * gate.
 */
export interface ExitBundleDidWebBinding {
  /**
   * The did:web URI string the operator published, e.g.,
   * `did:web:alice.example.com:fortress:abc123`. The receiving
   * regime resolves this to fetch the DID Document.
   */
  identifier: string;
  /** Authority host the operator's DID Document is published on. */
  authority_host: string;
  /**
   * Optional ISO 8601 timestamp at which the operator confirmed
   * HTTPS publication. Surfaces to the verifier as evidence that
   * the operator believes the document is reachable; the verifier
   * still re-resolves to confirm.
   */
  published_at?: string;
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
  /**
   * Optional did:web pointer (Recognition-Layer Path C primary build 2).
   * Present only when the operator has issued a did:web identifier
   * for the source fortress AND has not explicitly opted out at
   * export time via `--include-did-web=false`. The receiving regime
   * resolves the pointer via DNS + TLS to verify the bundle's origin
   * without trusting Sanctuary as intermediary. Absent on bundles
   * exported before the recognition-layer integration shipped
   * (backward-compatible).
   */
  did_web?: ExitBundleDidWebBinding;
}

/**
 * v1 manifest body — what the operator's fortress-master signs.
 *
 * `signature_scheme` lives INSIDE the body deliberately so the scheme is
 * covered by the fortress-master signature. Without this, an attacker who
 * substituted both `signature` and `signature_scheme` on the wrapper could
 * present a valid-looking manifest with a different scheme. Pinning the
 * scheme inside the signed bytes makes the crypto-agility hinge non-
 * substitutable.
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
  /**
   * Signature scheme covering the wrapper's `signature` field. v1.1 ships
   * only "ed25519-v1". Embedded inside the signed body so the scheme cannot
   * be substituted independently of the signature.
   */
  signature_scheme: SignatureScheme;
}

/**
 * Full signed manifest. Top-level shape that ships in the bundle archive.
 *
 * The wrapper carries only the `signature` and a pointer to the body. The
 * scheme that produced the signature lives inside `body.signature_scheme`,
 * so the signature itself attests to which scheme produced it.
 */
export interface ExitBundleManifest {
  /** Body — what the signature covers. */
  body: ExitBundleManifestBody;
  /**
   * Base64url-encoded Ed25519 signature over canonicalize(body) by the
   * fortress-master private key. The bundle archive is otherwise unsigned;
   * artifact integrity comes from artifact hashes inside the body. The
   * signing scheme is `body.signature_scheme`.
   */
  signature: string;
}

/**
 * Verifier output shape. The standalone verifier CLI emits this structure on
 * stdout (or as JSON for tool consumers) so import commands can branch
 * cleanly. v1.1 ships one VerifierResult shape; future versions extend.
 */
export interface ExitBundleVerifierResult {
  version: "1.1";
  /** True iff manifest, artifacts, and offline artifact-level checks all verify. */
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
    | "manifest_signature_scheme_invalid"
    | "artifact_hash_mismatch"
    | "artifact_missing"
    | "artifact_size_mismatch"
    | "aggregate_hash_mismatch"
    | "artifact_path_unsafe"
    | "artifact_path_duplicate"
    | "artifact_path_escapes_root"
    | "archive_contains_symlink"
    | "private_material_present"
    // Per full-sweep #77: failures from the post-artifact verification
    // pass (identity / reputation) used to collapse to "other"; surface
    // the specific cause so importers can branch on it without parsing
    // the warnings array.
    | "identity_binding_mismatch"
    | "identity_signature_invalid"
    // EXIT-PASS-01: a present rotation chain that does not verify. Distinct
    // from identity_signature_invalid (the artifact's own signature) — this is
    // the chain from a retired key to the current one failing verification.
    | "rotation_chain_invalid"
    | "reputation_bundle_signature_invalid"
    | "reputation_completeness_mismatch"
    | "reputation_attestation_signature_invalid"
    | "reputation_unverifiable_attestations"
    // The encrypted_state artifact passed its own hash and manifest-
    // signature checks, but its internal entries list could not be read in
    // the expected shape — either the CONTAINER (`entries` missing or not
    // an array, LD2-01) or, one level deeper, an ELEMENT inside it
    // (`entries: [null]`, or an element missing `namespace`/`entry`/
    // `entry.kid`/`entry.payload.ct`/`entry.sig`, EXIT-STRUCT-02). Both
    // share this one failure_class: from an operator's perspective both are
    // "the entries list could not be read in the expected shape". Distinct
    // from `"damaged"` in
    // `ExitBundleDeclaredRekeyMaterial` (server/src/exit/verifier.ts), which
    // covers a bundle whose entries ARE readable but whose re-key material
    // is malformed — that case stays verify-PASS by design and fails import
    // for a typed credential reason instead.
    | "encrypted_state_entries_unreadable"
    | "other";
}
