/**
 * Exit V2 contract for one operator-directed encrypted SDW memory archive.
 *
 * V2 is deliberately separate from the frozen V1 manifest. A V1 verifier
 * rejects this version, and `sdw_memory_archive` never enters V1's closed
 * artifact-kind set.
 */

import type { EncryptedPayload } from "../../core/encryption.js";

export const EXIT_V2_MANIFEST_VERSION = "SANCTUARY_EXIT_BUNDLE_V2" as const;
export const SDW_MEMORY_ARCHIVE_ARTIFACT_KIND = "sdw_memory_archive" as const;
export const EXIT_V2_SIGNATURE_SCHEME = "ed25519-v1" as const;
export const EXIT_V2_HASH_ALGORITHM = "sha256" as const;
export const EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT =
  "SANCTUARY_EXIT_V2_SDW_MEMORY_ARCHIVE_V1" as const;
export const EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT =
  "SANCTUARY_EXIT_V2_SDW_MEMORY_LOGICAL_ARCHIVE_V1" as const;
export const EXIT_V2_SDW_MEMORY_AAD_VERSION =
  "sanctuary.exit-v2.sdw-memory-archive.aad.v1" as const;
export const EXIT_V2_SDW_MEMORY_LINEAGE_VERSION =
  "SANCTUARY_EXIT_V2_SDW_MEMORY_LINEAGE_V1" as const;

export interface ExitV2IdentityBinding {
  readonly identity_id: string;
  readonly fortress_id: string;
  readonly fortress_master_pubkey: string;
  readonly did?: string;
}

export interface ExitV2SdwMemoryArtifactEntry {
  readonly kind: typeof SDW_MEMORY_ARCHIVE_ARTIFACT_KIND;
  readonly path: "artifacts/sdw-memory-archive.json";
  readonly hash_alg: typeof EXIT_V2_HASH_ALGORITHM;
  readonly hash: string;
  readonly size_bytes: number;
}

export interface ExitV2SdwMemoryManifestBody {
  readonly manifest_version: typeof EXIT_V2_MANIFEST_VERSION;
  readonly exported_at: string;
  readonly identity_binding: ExitV2IdentityBinding;
  readonly source_sanctuary_version: string;
  readonly artifacts: readonly [ExitV2SdwMemoryArtifactEntry];
  readonly artifacts_aggregate_hash: string;
  readonly artifacts_aggregate_hash_alg: typeof EXIT_V2_HASH_ALGORITHM;
  readonly export_approval_audit_id: string;
  readonly signature_scheme: typeof EXIT_V2_SIGNATURE_SCHEME;
}

export interface ExitV2SdwMemoryManifest {
  readonly body: ExitV2SdwMemoryManifestBody;
  readonly signature: string;
}

/** Public authenticated context. No source path, owner scope, or key enters it. */
export interface ExitV2SdwMemoryAad {
  readonly version: typeof EXIT_V2_SDW_MEMORY_AAD_VERSION;
  readonly source_fortress_id: string;
  readonly export_approval_audit_id: string;
  readonly source_archive_lineage_ref: string;
  readonly source_set_sha256: string;
}

export interface ExitV2SdwMemoryLogicalFile {
  readonly path: string;
  readonly source_class: string;
  readonly bytes_base64url: string;
  readonly size_bytes: number;
  readonly sha256: string;
}

/** The canonical plaintext encrypted by the per-artifact transfer key. */
export interface ExitV2SdwMemoryLogicalPayload {
  readonly format: typeof EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT;
  readonly transcode_version: "SANCTUARY_MEMORY_TRANSCODE_V1";
  readonly state: "complete";
  readonly source_harness: "claude-code" | "codex";
  readonly destination_harness: "claude-code" | "codex";
  readonly source_owner_ref: string;
  readonly source_archive_lineage_ref: string;
  readonly source_file_count: number;
  readonly source_set_sha256: string;
  readonly projection_file_count: number;
  readonly projection_set_sha256: string;
  readonly files: readonly ExitV2SdwMemoryLogicalFile[];
}

export interface ExitV2SdwMemoryArtifact {
  readonly format: typeof EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT;
  readonly aad: ExitV2SdwMemoryAad;
  readonly encrypted_payload: EncryptedPayload;
}

export interface ExitV2SdwMemoryLineageBody {
  readonly version: typeof EXIT_V2_SDW_MEMORY_LINEAGE_VERSION;
  readonly signature_scheme: typeof EXIT_V2_SIGNATURE_SCHEME;
  readonly source_fortress_id: string;
  readonly source_archive_lineage_ref: string;
  readonly source_artifact_sha256: string;
  readonly destination_fortress_id: string;
  readonly destination_owner_ref: string;
  readonly destination_archive_id: string;
  readonly source_harness: "claude-code" | "codex";
  readonly destination_harness: "claude-code" | "codex";
  readonly source_set_sha256: string;
  readonly imported_at: string;
  readonly destination_signer_identity_id: string;
  readonly destination_signer_public_key: string;
  readonly destination_signer_did?: string;
}

export interface ExitV2SdwMemorySignedLineage {
  readonly body: ExitV2SdwMemoryLineageBody;
  readonly signature: string;
}
