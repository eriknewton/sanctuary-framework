/**
 * Castle Wall allowlist manifest types.
 *
 * The manifest is the signed root document that lists every rule file in the
 * allowlist directory along with its SHA-256 digest. The filter daemon verifies
 * the manifest signature against a pinned fortress public key (TOFU per scope-lock
 * section 4 OQ #1) and then verifies each rule file's bytes match the manifest's
 * recorded digest. Either check failing means: keep prior ruleset, emit audit,
 * surface to menubar.
 */

import { CASTLE_WALL_SCHEMA_VERSION_V1, CASTLE_WALL_SIGNATURE_SCHEME_V1 } from "../constants.js";

/** A single entry in the manifest's rules array. */
export interface ManifestRuleEntry {
  /** Stable rule id matching the rule file's `id` field. */
  rule_id: string;
  /** Path of the rule file relative to the manifest's directory. */
  file: string;
  /** SHA-256 hex digest of the rule file's UTF-8 bytes. */
  sha256: string;
}

/**
 * The unsigned manifest. Canonical-JSON of this structure is the signing input.
 */
export interface AllowlistManifest {
  schema_version: typeof CASTLE_WALL_SCHEMA_VERSION_V1;
  fortress_id: string;
  issued_at: string;
  rules: ManifestRuleEntry[];
}

/**
 * The Ed25519 signature wrapper produced by Sanctuary main and verified by
 * the filter daemon. The `signing_key_id` is a fingerprint of the public key
 * used so the daemon can detect mismatch against its pinned key without
 * loading the manifest body. `signature_scheme` is the post-quantum migration
 * hinge field already shipped on federation v0.1.
 */
export interface ManifestSignature {
  signature_scheme: typeof CASTLE_WALL_SIGNATURE_SCHEME_V1;
  signing_key_id: string;
  signature_b64url: string;
}

/** A manifest plus its signature. This is the structure persisted on disk. */
export interface SignedManifest {
  manifest: AllowlistManifest;
  signature: ManifestSignature;
}
