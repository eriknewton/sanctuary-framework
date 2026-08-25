/**
 * Operator-directed Exit V2 carriage for one completed SDW memory archive.
 *
 * This module is a local library boundary only. It opens no network path and
 * owns no background process. The transfer key crosses the API solely as a
 * 32-byte Uint8Array; import consumes and clears that buffer in `finally`.
 */

import { createHash } from "node:crypto";

import {
  EXIT_V2_HASH_ALGORITHM,
  EXIT_V2_MANIFEST_VERSION,
  EXIT_V2_SDW_MEMORY_AAD_VERSION,
  EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT,
  EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT_V2,
  EXIT_V2_SDW_MEMORY_LINEAGE_VERSION,
  EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT,
  EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2,
  EXIT_V2_SIGNATURE_SCHEME,
  SDW_MEMORY_ARCHIVE_ARTIFACT_KIND,
  type ExitV2SdwMemoryAad,
  type ExitV2SdwMemoryArtifact,
  type ExitV2SdwMemoryArtifactUnion,
  type ExitV2SdwMemoryLineageBody,
  type ExitV2SdwMemoryLogicalFile,
  type ExitV2SdwMemoryLogicalPayload,
  type ExitV2SdwMemoryLogicalPayloadUnion,
  type ExitV2SdwMemoryLogicalPayloadV2,
  type ExitV2SdwMemoryManifest,
  type ExitV2SdwMemorySignedLineage,
} from "../contracts/v1.2/exit-bundle-manifest.js";
import {
  checkKnownSignersStructure,
  knownSignersSigningBytes,
  resolveKnownSigners,
  type KnownSignersArtifact,
  type KnownSignersEntry,
} from "./verifier.js";
import {
  createBoundedMemoryProvenanceSignerResolver,
  parseMemoryProvenanceCompanionValue,
  verifyMemoryProvenanceCompanion,
  type MemoryProvenanceCompanion,
  MAX_MEMORY_PROVENANCE_SIGNER_ENTRIES,
} from "../sdw/memory-provenance-contract.js";
import { decrypt, encrypt, type EncryptedPayload } from "../core/encryption.js";
import {
  fromBase64urlStrict,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import {
  legacyPublicKeyToDid,
  publicKeyToDid,
  verify as verifyIdentitySignature,
} from "../core/identity.js";
import { generateRandomKey } from "../core/random.js";
import { canonicalize, canonicalizeToBytes } from "../mesh/canonical-json.js";
import type {
  MemoryBackendAdapter,
  MemoryPassage,
  MemoryPassageInput,
} from "../sdw/adapters/memory-backend.js";
import { exitV2ForeignImportIngress, legacyExitV1ImportIngress, memoryTranscodeIngress } from "../sdw/memory-provenance-ingress.js";
import {
  KNOWN_SIGNERS_NAMESPACE,
  KnownSignersStore,
  knownSignerStorageKey,
} from "../reputation/known-signers-store.js";
import type { SdwMemoryBackendAdapter } from "../sdw/adapters/sdw-memory-backend.js";
import { passageContentHash } from "../sdw/write-gate.js";
import { isMemoryProvenanceOutboundSyncEligible } from "../sdw/memory-provenance-routing.js";
import {
  buildMemoryTranscodeArchivePassages,
  MEMORY_TRANSCODE_VERSION,
  readMemoryTranscodeArchive,
  type MemoryTranscodeLogicalArchive,
} from "../sdw/memory-transcode.js";

const TRANSFER_KEY_BYTES = 32;
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const MAX_SOURCE_FILES = 500;
const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
const MAX_SOURCE_SET_BYTES = 16 * 1024 * 1024;
const MAX_SOURCE_PATH_BYTES = 256;
const OPAQUE_ARCHIVE_ID_HEX_CHARS = 32;
const C0_CONTROL_CODE_POINT_MAX = 31;
const DELETE_CONTROL_CODE_POINT = 127;
// Base64 expands the 16 MiB plaintext ceiling by 4/3; 24 MiB leaves bounded
// room for canonical JSON fields and per-file metadata.
const MAX_ARTIFACT_BYTES = 24 * 1024 * 1024;
const MAX_OWNER_SCOPE_PAGES = 10_000;
const OWNER_SCOPE_PAGE_SIZE = 500;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9:._-]{1,256}$/;
const SAFE_SOURCE_CLASS = /^[a-z0-9._-]{1,128}$/;
const LINEAGE_SIGNING_DOMAIN = "sanctuary.exit-v2.sdw-memory-lineage.signature.v1";
const SOURCE_LINEAGE_DOMAIN = "sanctuary.exit-v2.sdw-memory-source-lineage.v1";
const DESTINATION_ARCHIVE_ID_DOMAIN = "memory-transcode-import-v2";
const DESTINATION_LINEAGE_ID_DOMAIN = "memory-transcode-lineage-v1";
const LINEAGE_TAG = "memory_transcode_lineage";
const LINEAGE_SOURCE_REF_KEY = "exit_v2_source_lineage_ref";
const LINEAGE_ARTIFACT_SHA_KEY = "exit_v2_source_artifact_sha256";
const LINEAGE_DESTINATION_ARCHIVE_KEY = "exit_v2_destination_archive_id";
const ARTIFACT_PATH = "artifacts/sdw-memory-archive.json" as const;

export interface ExitV2MemorySigner {
  readonly identity_id: string;
  readonly fortress_id: string;
  readonly public_key: string;
  readonly did?: string;
  sign(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface ExportExitV2SdwMemoryArchiveOptions {
  readonly adapter: MemoryBackendAdapter & Pick<SdwMemoryBackendAdapter,
    "getPassageProvenance" | "getMemoryIntegrityState">;
  readonly archiveId: string;
  readonly sourceFortressId: string;
  readonly exportApprovalAuditId: string;
  readonly sourceSanctuaryVersion: string;
  readonly signer: ExitV2MemorySigner;
  readonly now?: () => string;
  readonly formatVersion?: 1 | 2;
  readonly resolveProvenanceSigner?: (identityId: string, did: string) => Uint8Array | undefined;
}

export interface ExportExitV2SdwMemoryArchiveResult {
  readonly manifest: ExitV2SdwMemoryManifest;
  readonly artifact_path: typeof ARTIFACT_PATH;
  readonly artifact_bytes: Uint8Array;
  readonly artifact_sha256: string;
  readonly source_lineage_ref: string;
  /** One-use recovery material. The caller must keep it off disk and argv. */
  readonly transfer_key: Uint8Array;
}

export interface VerifyExitV2SdwMemoryArchiveOptions {
  readonly manifest: ExitV2SdwMemoryManifest;
  readonly artifactBytes: Uint8Array;
  /** Consumed and zeroed on every return path. */
  readonly transferKey: Uint8Array;
}

export interface VerifyExitV2SdwMemoryArchiveResult {
  readonly passed: true;
  readonly artifact_sha256: string;
  readonly source_lineage_ref: string;
  readonly source_file_count: number;
  readonly source_set_sha256: string;
  readonly source_harness: "claude-code" | "codex";
  readonly destination_harness: "claude-code" | "codex";
}

export interface ImportExitV2SdwMemoryArchiveOptions
  extends VerifyExitV2SdwMemoryArchiveOptions {
  readonly adapter: MemoryBackendAdapter;
  readonly signer: ExitV2MemorySigner;
  readonly now?: () => string;
  readonly knownSignersStore?: KnownSignersStore;
  readonly onProvenanceSignerPersisted?: (did: string, publicKey: Uint8Array) => void;
}

export interface ImportExitV2SdwMemoryArchiveResult {
  readonly replayed: boolean;
  readonly source_lineage_ref: string;
  readonly destination_archive_id: string;
  readonly artifact_sha256: string;
  readonly lineage_signature: string;
  readonly lineage_signed_by: string;
}

export interface ExitV2SdwMemoryAdmissionPlan {
  readonly importId: string;
  readonly locations: readonly { namespace: string; key: string }[];
}

function buildDestinationLineageBody(options: {
  readonly validated: ValidatedArchive;
  readonly adapter: MemoryBackendAdapter;
  readonly signer: ExitV2MemorySigner;
  readonly destinationArchiveId: string;
  readonly importedAt: string;
}): ExitV2SdwMemoryLineageBody {
  return {
    version: EXIT_V2_SDW_MEMORY_LINEAGE_VERSION,
    signature_scheme: EXIT_V2_SIGNATURE_SCHEME,
    source_fortress_id: options.validated.sourceFortressId,
    source_archive_lineage_ref: options.validated.payload.source_archive_lineage_ref,
    source_artifact_sha256: options.validated.artifactSha256,
    destination_fortress_id: options.signer.fortress_id,
    destination_owner_ref: options.adapter.ownerRef,
    destination_archive_id: options.destinationArchiveId,
    source_harness: options.validated.payload.source_harness,
    destination_harness: options.validated.payload.destination_harness,
    source_set_sha256: options.validated.payload.source_set_sha256,
    imported_at: options.importedAt,
    destination_signer_identity_id: options.signer.identity_id,
    destination_signer_public_key: options.signer.public_key,
    ...(options.signer.did === undefined
      ? {}
      : { destination_signer_did: options.signer.did }),
  };
}

/** Read-only complete write-set preflight; its caller supplies a key copy. */
export async function planExitV2SdwMemoryAdmission(options: {
  readonly manifest: ExitV2SdwMemoryManifest;
  readonly artifactBytes: Uint8Array;
  readonly transferKey: Uint8Array;
  readonly adapter: SdwMemoryBackendAdapter;
  readonly signer: ExitV2MemorySigner;
  /** Exact commit timestamp the paired import will use. */
  readonly importedAt?: string;
}): Promise<ExitV2SdwMemoryAdmissionPlan> {
  const validated = validateAndDecrypt(options);
  if (validated.payload.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2 &&
      await options.adapter.getMemoryIntegrityState() !== "state_COMPLETE") {
    throw new Error("Exit V2 signed-memory admission preflight requires completed provenance migration");
  }
  const destinationArchiveId = options.adapter.derivePassageId(
    DESTINATION_ARCHIVE_ID_DOMAIN, validated.artifactSha256,
  );
  const lineagePassageId = options.adapter.derivePassageId(
    DESTINATION_LINEAGE_ID_DOMAIN, validated.payload.source_archive_lineage_ref,
  );
  const archiveInputs = buildMemoryTranscodeArchivePassages(
    options.adapter, destinationArchiveId, validated.logicalArchive,
    "2000-01-01T00:00:00.000Z",
  );
  // Ed25519 signatures have a fixed encoded length. Using a same-length
  // placeholder and a fixed-width ISO timestamp therefore plans the exact
  // lineage chunk count without performing a signature during preflight.
  const plannedLineageBody = buildDestinationLineageBody({
    validated,
    adapter: options.adapter,
    signer: options.signer,
    destinationArchiveId,
    importedAt: options.importedAt ?? "2000-01-01T00:00:00.000Z",
  });
  const plannedLineageText = canonicalize({
    body: plannedLineageBody,
    signature: toBase64url(new Uint8Array(ED25519_SIGNATURE_BYTES)),
  } satisfies ExitV2SdwMemorySignedLineage);
  const passageLocations = options.adapter.planPassageWriteSet([
    ...archiveInputs,
    { passage_id: lineagePassageId, text: plannedLineageText },
  ]);
  const signerLocations = validated.payload.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2
    ? validated.payload.files.map((file) => ({
        namespace: KNOWN_SIGNERS_NAMESPACE,
        key: knownSignerStorageKey(file.provenance.origin.body.signer_did, "memory_provenance"),
      }))
    : [];
  return {
    importId: validated.artifactSha256,
    locations: [...signerLocations, ...passageLocations],
  };
}

export interface ParticipantExitSdwMemoryRetentionReceipt {
  readonly memory_portability_complete: boolean;
  readonly retained_sdw_archive_count: number;
  readonly retained_source_lineage_refs: readonly string[];
}

interface ValidatedArchive {
  readonly artifactSha256: string;
  readonly sourceFortressId: string;
  readonly payload: ExitV2SdwMemoryLogicalPayloadUnion;
  readonly logicalArchive: MemoryTranscodeLogicalArchive;
  readonly v2Origins?: readonly {
    readonly publicKey: Uint8Array;
    readonly trustTier: "foreign_direct" | "foreign_relayed";
  }[];
}

/** Export reads and validates the encrypted source vault without staging plaintext. */
export async function exportExitV2SdwMemoryArchive(
  options: ExportExitV2SdwMemoryArchiveOptions,
): Promise<ExportExitV2SdwMemoryArchiveResult> {
  assertSigner(options.signer, options.sourceFortressId);
  assertSafeIdentifier(options.sourceFortressId, "source fortress id");
  assertSafeIdentifier(options.exportApprovalAuditId, "export approval audit id");
  assertSafeIdentifier(options.sourceSanctuaryVersion, "source Sanctuary version");
  const archive = await readMemoryTranscodeArchive(options.adapter, options.archiveId);
  const sourceLineageRef = sourceLineageReference(
    options.sourceFortressId,
    archive.archive_id,
    archive.source_set_sha256,
  );
  const payload = options.formatVersion === 2
    ? await logicalPayloadV2(archive, sourceLineageRef, options)
    : logicalPayload(archive, sourceLineageRef);
  const payloadBytes = canonicalizeToBytes(payload);
  if (payloadBytes.byteLength > MAX_ARTIFACT_BYTES) {
    throw new Error("Exit V2 SDW memory logical payload exceeds its size bound");
  }
  const aad: ExitV2SdwMemoryAad = {
    version: EXIT_V2_SDW_MEMORY_AAD_VERSION,
    source_fortress_id: options.sourceFortressId,
    export_approval_audit_id: options.exportApprovalAuditId,
    source_archive_lineage_ref: sourceLineageRef,
    source_set_sha256: archive.source_set_sha256,
  };
  const transferKey = generateRandomKey();
  try {
    const artifact: ExitV2SdwMemoryArtifactUnion = {
      format: options.formatVersion === 2
        ? EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT_V2
        : EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT,
      aad,
      encrypted_payload: encrypt(payloadBytes, transferKey, canonicalizeToBytes(aad)),
    };
    const artifactBytes = canonicalizeToBytes(artifact);
    if (artifactBytes.byteLength > MAX_ARTIFACT_BYTES) {
      throw new Error("Exit V2 SDW memory artifact exceeds its size bound");
    }
    const artifactSha = sha256Hex(artifactBytes);
    const artifactEntry = {
      kind: SDW_MEMORY_ARCHIVE_ARTIFACT_KIND,
      path: ARTIFACT_PATH,
      hash_alg: EXIT_V2_HASH_ALGORITHM,
      hash: artifactSha,
      size_bytes: artifactBytes.byteLength,
    } as const;
    const body: ExitV2SdwMemoryManifest["body"] = {
      manifest_version: EXIT_V2_MANIFEST_VERSION,
      exported_at: options.now?.() ?? new Date().toISOString(),
      identity_binding: {
        identity_id: options.signer.identity_id,
        fortress_id: options.signer.fortress_id,
        fortress_master_pubkey: options.signer.public_key,
        ...(options.signer.did === undefined ? {} : { did: options.signer.did }),
      },
      source_sanctuary_version: options.sourceSanctuaryVersion,
      artifacts: [artifactEntry],
      artifacts_aggregate_hash: sha256Hex(canonicalizeToBytes([artifactEntry])),
      artifacts_aggregate_hash_alg: EXIT_V2_HASH_ALGORITHM,
      export_approval_audit_id: options.exportApprovalAuditId,
      signature_scheme: EXIT_V2_SIGNATURE_SCHEME,
    };
    const signature = await options.signer.sign(canonicalizeToBytes(body));
    assertSignature(signature, options.signer.public_key, canonicalizeToBytes(body));
    return {
      manifest: { body, signature: toBase64url(signature) },
      artifact_path: ARTIFACT_PATH,
      artifact_bytes: artifactBytes,
      artifact_sha256: artifactSha,
      source_lineage_ref: sourceLineageRef,
      transfer_key: transferKey,
    };
  } catch (error) {
    transferKey.fill(0);
    throw error;
  }
}

export async function verifyExitV2SdwMemoryArchive(
  options: VerifyExitV2SdwMemoryArchiveOptions,
): Promise<VerifyExitV2SdwMemoryArchiveResult> {
  const validated = validateAndDecrypt(options);
  return verificationReceipt(validated);
}

export async function importExitV2SdwMemoryArchive(
  options: ImportExitV2SdwMemoryArchiveOptions,
): Promise<ImportExitV2SdwMemoryArchiveResult> {
  const validated = validateAndDecrypt(options);
  assertSigner(options.signer);
  if (validated.payload.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2) {
    const resolveState = (options.adapter as MemoryBackendAdapter &
      Partial<Pick<SdwMemoryBackendAdapter, "getMemoryIntegrityState">>).getMemoryIntegrityState;
    if (typeof resolveState !== "function" ||
        await resolveState.call(options.adapter) !== "state_COMPLETE") {
      throw new Error("Exit V2 signed-memory import requires completed provenance migration");
    }
  }
  const destinationArchiveId = options.adapter.derivePassageId(
    DESTINATION_ARCHIVE_ID_DOMAIN,
    validated.artifactSha256,
  );
  const lineagePassageId = options.adapter.derivePassageId(
    DESTINATION_LINEAGE_ID_DOMAIN,
    validated.payload.source_archive_lineage_ref,
  );
  const existingLineage = await options.adapter.getPassage(lineagePassageId);
  if (existingLineage !== null) {
    return replayReceipt(
      existingLineage,
      validated,
      options.adapter.ownerRef,
      destinationArchiveId,
      options.signer,
    );
  }

  if (validated.payload.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2) {
    if (options.knownSignersStore === undefined || validated.v2Origins === undefined) {
      throw new Error("Exit V2 signed-memory import requires provenance signer persistence");
    }
    const entries = validated.payload.files.map((file, index) => ({
      did: file.provenance.origin.body.signer_did,
      publicKey: validated.v2Origins![index]!.publicKey,
    }));
    const capacity = await options.knownSignersStore.wouldExceedCapacity(entries);
    if (capacity.exceeds) {
      throw new Error("Exit V2 signed-memory signer capacity is exhausted");
    }
    await options.knownSignersStore.persistIfAbsent(entries, validated.artifactSha256);
    for (const entry of entries) {
      options.onProvenanceSignerPersisted?.(entry.did, entry.publicKey.slice());
    }
  }

  // A source lineage may map to one artifact digest only. The scan is bounded
  // and completes before destination ids are checked or any passage is written.
  for (const passage of await listAllPassages(options.adapter)) {
    if (!passage.tags.includes(LINEAGE_TAG)) continue;
    const lineage = parseStoredLineage(passage);
    if (
      lineage.body.destination_owner_ref !== options.adapter.ownerRef ||
      lineage.body.destination_fortress_id !== options.signer.fortress_id
    ) {
      throw new Error("Exit V2 SDW memory stored lineage destination binding is invalid");
    }
    if (
      lineage.body.source_archive_lineage_ref ===
        validated.payload.source_archive_lineage_ref &&
      lineage.body.source_artifact_sha256 !== validated.artifactSha256
    ) {
      throw new Error(
        "Exit V2 SDW memory source lineage already maps to a different artifact digest",
      );
    }
  }

  const createdAt = options.now?.() ?? new Date().toISOString();
  const builtArchiveInputs = buildMemoryTranscodeArchivePassages(
    options.adapter,
    destinationArchiveId,
    validated.logicalArchive,
    createdAt,
  );
  const archiveInputs = builtArchiveInputs.map((input, index) => {
    if (validated.payload.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT) {
      return { ...input, provenanceContext: legacyExitV1ImportIngress(validated.payload.source_archive_lineage_ref) };
    }
    if (index >= validated.payload.files.length) {
      return { ...input, provenanceContext: memoryTranscodeIngress("system:memory-transcode", "transcode_manifest") };
    }
    const file = validated.payload.files[index]!;
    const origin = validated.v2Origins?.[index];
    if (origin === undefined) throw new Error("Exit V2 signed-memory origin resolution is incomplete");
    return { ...input, provenanceContext: exitV2ForeignImportIngress({
      origin: file.provenance.origin,
      originPublicKey: origin.publicKey,
      trustTier: origin.trustTier,
      transferLineageRef: validated.payload.source_archive_lineage_ref,
    }) };
  });
  for (const input of archiveInputs) {
    if (input.passage_id === undefined) {
      throw new Error("Exit V2 SDW memory import produced an unbound destination passage");
    }
    if (await options.adapter.getPassage(input.passage_id) !== null) {
      throw new Error("Exit V2 SDW memory destination-local archive id is already occupied");
    }
  }

  const lineageBody = buildDestinationLineageBody({
    validated,
    adapter: options.adapter,
    signer: options.signer,
    destinationArchiveId,
    importedAt: createdAt,
  });
  const lineageBytes = lineageSigningBytes(lineageBody);
  const lineageSignature = await options.signer.sign(lineageBytes);
  assertSignature(lineageSignature, options.signer.public_key, lineageBytes);
  const signedLineage: ExitV2SdwMemorySignedLineage = {
    body: lineageBody,
    signature: toBase64url(lineageSignature),
  };
  const lineageInput: MemoryPassageInput = {
    passage_id: lineagePassageId,
    text: canonicalize(signedLineage),
    tags: [LINEAGE_TAG],
    metadata: [
      { key: LINEAGE_SOURCE_REF_KEY, value: lineageBody.source_archive_lineage_ref },
      { key: LINEAGE_ARTIFACT_SHA_KEY, value: lineageBody.source_artifact_sha256 },
      { key: LINEAGE_DESTINATION_ARCHIVE_KEY, value: destinationArchiveId },
    ],
    created_at: createdAt,
    provenanceContext: validated.payload.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT
      ? legacyExitV1ImportIngress(validated.payload.source_archive_lineage_ref)
      : memoryTranscodeIngress("system:memory-transcode", "exit_lineage"),
  };

  if (validated.payload.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2) {
    const resolveState = (options.adapter as MemoryBackendAdapter &
      Partial<Pick<SdwMemoryBackendAdapter, "getMemoryIntegrityState">>).getMemoryIntegrityState;
    if (typeof resolveState !== "function" ||
        await resolveState.call(options.adapter) !== "state_COMPLETE") {
      throw new Error("Exit V2 signed-memory migration state changed before visibility commit");
    }
  }

  // Files, completed manifest, and signed lineage share this one atomic batch;
  // no committed archive can exist without its destination lineage record.
  const inserted = await options.adapter.putPassagesIfAbsent(
    [...archiveInputs, lineageInput],
    "user_content",
  );
  if (inserted === null) {
    // Another importer won after our fail-before prechecks. Only the exact,
    // trusted-signer-bound lineage is an idempotent replay; any partial or
    // different occupancy fails closed and is never overwritten.
    const racedLineage = await options.adapter.getPassage(lineagePassageId);
    if (racedLineage === null) {
      throw new Error("Exit V2 SDW memory destination-local archive id is already occupied");
    }
    return replayReceipt(
      racedLineage,
      validated,
      options.adapter.ownerRef,
      destinationArchiveId,
      options.signer,
    );
  }
  return {
    replayed: false,
    source_lineage_ref: lineageBody.source_archive_lineage_ref,
    destination_archive_id: destinationArchiveId,
    artifact_sha256: validated.artifactSha256,
    lineage_signature: signedLineage.signature,
    lineage_signed_by: options.signer.public_key,
  };
}

/** Metadata-only receipt for the conservative participant-Exit split. */
export async function participantExitSdwMemoryRetention(input: {
  readonly adapter: MemoryBackendAdapter;
  readonly sourceFortressId: string;
}): Promise<ParticipantExitSdwMemoryRetentionReceipt> {
  assertSafeIdentifier(input.sourceFortressId, "source fortress id");
  const refs: string[] = [];
  const passages = await listAllPassages(input.adapter);
  for (const passage of passages) {
    if (
      !passage.tags.includes("memory_transcode_archive") ||
      !passage.tags.includes("memory_transcode_complete")
    ) {
      continue;
    }
    const archive = await readMemoryTranscodeArchive(input.adapter, passage.passage_id);
    refs.push(sourceLineageReference(
      input.sourceFortressId,
      archive.archive_id,
      archive.source_set_sha256,
    ));
  }
  refs.sort();
  return {
    // Any SDW passage means participant Exit retained operator-custodied
    // memory, even when no completed transcode archive exists to name.
    memory_portability_complete: passages.length === 0,
    retained_sdw_archive_count: refs.length,
    retained_source_lineage_refs: refs,
  };
}

function validateAndDecrypt(
  options: VerifyExitV2SdwMemoryArchiveOptions,
): ValidatedArchive {
  const callerKey = options.transferKey;
  const transferKey = new Uint8Array(callerKey);
  try {
    if (transferKey.byteLength !== TRANSFER_KEY_BYTES) {
      throw new Error("Exit V2 SDW memory transfer key must be exactly 32 bytes");
    }
    const body = validateManifest(options.manifest, options.artifactBytes);
    const artifactSha = sha256Hex(options.artifactBytes);
    let parsedArtifact: unknown;
    try {
      parsedArtifact = JSON.parse(Buffer.from(options.artifactBytes).toString("utf8"));
    } catch {
      throw new Error("Exit V2 SDW memory artifact is not valid canonical JSON");
    }
    if (canonicalize(parsedArtifact) !== Buffer.from(options.artifactBytes).toString("utf8")) {
      throw new Error("Exit V2 SDW memory artifact is not valid canonical JSON");
    }
    const artifact = parseExitV2SdwMemoryArtifactUnion(parsedArtifact);
    const expectedAad: ExitV2SdwMemoryAad = {
      version: EXIT_V2_SDW_MEMORY_AAD_VERSION,
      source_fortress_id: body.identity_binding.fortress_id,
      export_approval_audit_id: body.export_approval_audit_id,
      source_archive_lineage_ref: artifact.aad.source_archive_lineage_ref,
      source_set_sha256: artifact.aad.source_set_sha256,
    };
    if (canonicalize(artifact.aad) !== canonicalize(expectedAad)) {
      throw new Error("Exit V2 SDW memory authenticated context is invalid");
    }
    let plaintext: Uint8Array;
    try {
      plaintext = decrypt(
        artifact.encrypted_payload,
        transferKey,
        canonicalizeToBytes(expectedAad),
      );
    } catch {
      throw new Error("Exit V2 SDW memory archive authentication failed");
    }
    try {
      if (plaintext.byteLength > MAX_ARTIFACT_BYTES) {
        throw new Error("Exit V2 SDW memory logical payload exceeds its size bound");
      }
      let parsedPayload: unknown;
      try {
        parsedPayload = JSON.parse(Buffer.from(plaintext).toString("utf8"));
      } catch {
        throw new Error("Exit V2 SDW memory logical payload is invalid");
      }
      if (canonicalize(parsedPayload) !== Buffer.from(plaintext).toString("utf8")) {
        throw new Error("Exit V2 SDW memory logical payload is not canonical");
      }
      const payload = parseExitV2SdwMemoryLogicalPayloadUnion(parsedPayload);
      if (
        payload.source_archive_lineage_ref !== expectedAad.source_archive_lineage_ref ||
        payload.source_set_sha256 !== expectedAad.source_set_sha256
      ) {
        throw new Error("Exit V2 SDW memory logical payload binding is invalid");
      }
      const v2Origins = payload.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2
        ? verifyV2PayloadProvenance(payload, body)
        : undefined;
      return {
        artifactSha256: artifactSha,
        sourceFortressId: body.identity_binding.fortress_id,
        payload,
        logicalArchive: payloadToLogicalArchive(payload),
        ...(v2Origins === undefined ? {} : { v2Origins }),
      };
    } finally {
      plaintext.fill(0);
    }
  } finally {
    transferKey.fill(0);
    callerKey.fill(0);
  }
}

function verifyV2PayloadProvenance(
  payload: ExitV2SdwMemoryLogicalPayloadV2,
  manifestBody: ExitV2SdwMemoryManifest["body"],
): readonly { publicKey: Uint8Array; trustTier: "foreign_direct" | "foreign_relayed" }[] {
  const exportingDid = manifestBody.identity_binding.did;
  if (exportingDid === undefined) {
    throw new Error("Exit V2 signed-memory manifest lacks an exporter DID");
  }
  const exportingKey = fromBase64urlStrict(manifestBody.identity_binding.fortress_master_pubkey);
  const known = resolveKnownSigners(payload.known_signers, exportingDid, exportingKey);
  if (!known.ok) throw new Error(`Exit V2 signed-memory known_signers is invalid: ${known.problem}`);
  const signerRows = new Map<string, { signer_identity_id: string; signer_did: string; public_key: string }>();
  const add = (identityId: string, did: string, key: Uint8Array) => {
    const prior = signerRows.get(did);
    if (prior !== undefined && (prior.signer_identity_id !== identityId ||
        prior.public_key !== toBase64url(key))) {
      throw new Error("Exit V2 signed-memory signer evidence conflicts");
    }
    signerRows.set(did, { signer_identity_id: identityId, signer_did: did, public_key: toBase64url(key) });
  };
  const origins: Array<{ publicKey: Uint8Array; trustTier: "foreign_direct" | "foreign_relayed" }> = [];
  for (const file of payload.files) {
    for (const signed of [file.provenance.origin, file.provenance.admission]) {
      const did = signed.body.signer_did;
      const key = did === exportingDid ? exportingKey : known.signers.get(did);
      if (key === undefined) throw new Error("Exit V2 signed-memory provenance signer is unknown");
      add(signed.body.signer_identity_id, did, key);
    }
  }
  const resolver = createBoundedMemoryProvenanceSignerResolver([...signerRows.values()]);
  if (!resolver.ok) throw new Error(`Exit V2 signed-memory signer resolver is invalid: ${resolver.error.code}`);
  for (const file of payload.files) {
    const companion = file.provenance;
    const result = verifyMemoryProvenanceCompanion(companion, resolver.value, {
      origin: {
        origin_fortress_id: companion.origin.body.origin_fortress_id,
        owner_ref: companion.origin.body.owner_ref,
        passage_id: companion.origin.body.passage_id,
        content_hash: passageContentHash(Buffer.from(fromBase64urlStrict(file.bytes_base64url)).toString("utf8")),
        chunk_count: companion.origin.body.chunk_count,
      },
      destination: {
        destination_fortress_id: manifestBody.identity_binding.fortress_id,
        destination_owner_ref: payload.source_owner_ref,
        passage_id: file.source_passage_id,
      },
    });
    if (!result.ok) throw new Error(`Exit V2 signed-memory provenance verification failed: ${result.error.code}`);
    const originKey = resolver.value.resolve(
      companion.origin.body.signer_identity_id,
      companion.origin.body.signer_did,
    );
    if (originKey === undefined) throw new Error("Exit V2 signed-memory origin signer is unknown");
    origins.push({
      publicKey: originKey,
      trustTier: Buffer.from(originKey).equals(Buffer.from(exportingKey))
        ? "foreign_direct"
        : "foreign_relayed",
    });
  }
  return origins;
}

function validateManifest(
  manifest: ExitV2SdwMemoryManifest,
  artifactBytes: Uint8Array,
): ExitV2SdwMemoryManifest["body"] {
  if (artifactBytes.byteLength > MAX_ARTIFACT_BYTES) {
    throw new Error("Exit V2 SDW memory artifact exceeds its size bound");
  }
  assertExactKeys(manifest, ["body", "signature"], "manifest");
  assertExactKeys(manifest.body, [
    "artifacts",
    "artifacts_aggregate_hash",
    "artifacts_aggregate_hash_alg",
    "export_approval_audit_id",
    "exported_at",
    "identity_binding",
    "manifest_version",
    "signature_scheme",
    "source_sanctuary_version",
  ], "manifest body");
  const body = manifest.body;
  if (body.manifest_version !== EXIT_V2_MANIFEST_VERSION) {
    throw new Error("Exit V2 SDW memory manifest version is unsupported");
  }
  if (body.signature_scheme !== EXIT_V2_SIGNATURE_SCHEME) {
    throw new Error("Exit V2 SDW memory manifest signature scheme is unsupported");
  }
  assertIsoTimestamp(body.exported_at, "manifest export timestamp");
  assertSafeIdentifier(body.export_approval_audit_id, "export approval audit id");
  assertSafeIdentifier(body.source_sanctuary_version, "source Sanctuary version");
  assertIdentityBinding(body.identity_binding);
  if (!Array.isArray(body.artifacts) || body.artifacts.length !== 1) {
    throw new Error("Exit V2 SDW memory manifest must contain exactly one artifact");
  }
  const entry = body.artifacts[0]!;
  assertExactKeys(entry, ["hash", "hash_alg", "kind", "path", "size_bytes"], "artifact entry");
  if (
    entry.kind !== SDW_MEMORY_ARCHIVE_ARTIFACT_KIND ||
    entry.path !== ARTIFACT_PATH ||
    entry.hash_alg !== EXIT_V2_HASH_ALGORITHM ||
    !SHA256_HEX.test(entry.hash) ||
    !Number.isSafeInteger(entry.size_bytes) ||
    entry.size_bytes < 1 ||
    entry.size_bytes > MAX_ARTIFACT_BYTES
  ) {
    throw new Error("Exit V2 SDW memory artifact entry is invalid");
  }
  let publicKey: Uint8Array;
  let signature: Uint8Array;
  try {
    publicKey = fromBase64urlStrict(body.identity_binding.fortress_master_pubkey);
    signature = fromBase64urlStrict(manifest.signature);
  } catch {
    throw new Error("Exit V2 SDW memory manifest signature is invalid");
  }
  if (
    publicKey.byteLength !== ED25519_PUBLIC_KEY_BYTES ||
    signature.byteLength !== ED25519_SIGNATURE_BYTES ||
    !verifyIdentitySignature(canonicalizeToBytes(body), signature, publicKey)
  ) {
    throw new Error("Exit V2 SDW memory manifest signature is invalid");
  }
  if (
    entry.size_bytes !== artifactBytes.byteLength ||
    entry.hash !== sha256Hex(artifactBytes)
  ) {
    throw new Error("Exit V2 SDW memory artifact hash or size is invalid");
  }
  if (
    body.artifacts_aggregate_hash_alg !== EXIT_V2_HASH_ALGORITHM ||
    !SHA256_HEX.test(body.artifacts_aggregate_hash) ||
    body.artifacts_aggregate_hash !== sha256Hex(canonicalizeToBytes(body.artifacts))
  ) {
    throw new Error("Exit V2 SDW memory artifact aggregate hash is invalid");
  }
  return body;
}

function validateArtifact(value: unknown): ExitV2SdwMemoryArtifact {
  assertExactKeys(value, ["aad", "encrypted_payload", "format"], "artifact");
  if (value.format !== EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT) {
    throw new Error("Exit V2 SDW memory artifact format is unsupported");
  }
  assertExactKeys(value.aad, [
    "export_approval_audit_id",
    "source_archive_lineage_ref",
    "source_fortress_id",
    "source_set_sha256",
    "version",
  ], "artifact authenticated context");
  if (
    value.aad.version !== EXIT_V2_SDW_MEMORY_AAD_VERSION ||
    !SHA256_HEX.test(asString(value.aad.source_archive_lineage_ref)) ||
    !SHA256_HEX.test(asString(value.aad.source_set_sha256))
  ) {
    throw new Error("Exit V2 SDW memory authenticated context is invalid");
  }
  assertSafeIdentifier(asString(value.aad.source_fortress_id), "source fortress id");
  assertSafeIdentifier(asString(value.aad.export_approval_audit_id), "export approval audit id");
  validateEncryptedPayload(value.encrypted_payload);
  return value as unknown as ExitV2SdwMemoryArtifact;
}

/** Exact outer-format union whose frozen V1 leg calls the shipped parser. */
export function parseExitV2SdwMemoryArtifactUnion(
  value: unknown,
): ExitV2SdwMemoryArtifactUnion {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Exit V2 SDW memory artifact shape is invalid");
  }
  const format = (value as Record<string, unknown>).format;
  if (format === EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT) return validateArtifact(value);
  if (format !== EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT_V2) {
    throw new Error("Exit V2 SDW memory artifact format is unsupported");
  }
  const parsed = validateArtifact({
    ...(value as Record<string, unknown>),
    format: EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT,
  });
  return { ...parsed, format: EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT_V2 };
}

function validateEncryptedPayload(value: unknown): asserts value is EncryptedPayload {
  assertExactKeys(value, ["alg", "ct", "iv", "ts", "v"], "encrypted payload");
  if (value.v !== 1 || value.alg !== "aes-256-gcm") {
    throw new Error("Exit V2 SDW memory encrypted payload shape is invalid");
  }
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    iv = fromBase64urlStrict(asString(value.iv));
    ciphertext = fromBase64urlStrict(asString(value.ct));
  } catch {
    throw new Error("Exit V2 SDW memory encrypted payload shape is invalid");
  }
  if (iv.byteLength !== AES_GCM_IV_BYTES || ciphertext.byteLength < AES_GCM_TAG_BYTES) {
    throw new Error("Exit V2 SDW memory encrypted payload shape is invalid");
  }
  assertIsoTimestamp(asString(value.ts), "encrypted payload timestamp");
}

function validateLogicalPayload(value: unknown): ExitV2SdwMemoryLogicalPayload {
  assertExactKeys(value, [
    "destination_harness",
    "files",
    "format",
    "projection_file_count",
    "projection_set_sha256",
    "source_archive_lineage_ref",
    "source_file_count",
    "source_harness",
    "source_owner_ref",
    "source_set_sha256",
    "state",
    "transcode_version",
  ], "logical payload");
  const sourceFileCount = value.source_file_count;
  const projectionFileCount = value.projection_file_count;
  if (
    value.format !== EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT ||
    value.transcode_version !== MEMORY_TRANSCODE_VERSION ||
    value.state !== "complete" ||
    !isHarness(value.source_harness) ||
    !isHarness(value.destination_harness) ||
    value.source_harness === value.destination_harness ||
    !SHA256_HEX.test(asString(value.source_archive_lineage_ref)) ||
    !SHA256_HEX.test(asString(value.source_set_sha256)) ||
    !SHA256_HEX.test(asString(value.projection_set_sha256)) ||
    typeof sourceFileCount !== "number" ||
    !Number.isSafeInteger(sourceFileCount) ||
    typeof projectionFileCount !== "number" ||
    !Number.isSafeInteger(projectionFileCount) ||
    sourceFileCount < 1 ||
    sourceFileCount > MAX_SOURCE_FILES ||
    projectionFileCount < 1 ||
    projectionFileCount > MAX_SOURCE_FILES ||
    !Array.isArray(value.files) ||
    value.files.length !== sourceFileCount
  ) {
    throw new Error("Exit V2 SDW memory logical payload shape is invalid");
  }
  assertSafeIdentifier(asString(value.source_owner_ref), "source owner scope");
  const paths = new Set<string>();
  let totalBytes = 0;
  const files: ExitV2SdwMemoryLogicalFile[] = [];
  for (const rawFile of value.files) {
    assertExactKeys(rawFile, [
      "bytes_base64url",
      "path",
      "sha256",
      "size_bytes",
      "source_class",
    ], "logical file");
    const path = asString(rawFile.path);
    const sourceClass = asString(rawFile.source_class);
    assertSourcePath(path, value.source_harness);
    if (!SAFE_SOURCE_CLASS.test(sourceClass) || paths.has(path)) {
      throw new Error("Exit V2 SDW memory logical file metadata is invalid");
    }
    paths.add(path);
    const fileSize = rawFile.size_bytes;
    if (
      typeof fileSize !== "number" ||
      !Number.isSafeInteger(fileSize) ||
      fileSize < 0 ||
      fileSize > MAX_SOURCE_FILE_BYTES ||
      !SHA256_HEX.test(asString(rawFile.sha256))
    ) {
      throw new Error("Exit V2 SDW memory logical file binding is invalid");
    }
    let bytes: Uint8Array;
    try {
      bytes = fromBase64urlStrict(asString(rawFile.bytes_base64url));
    } catch {
      throw new Error("Exit V2 SDW memory logical file bytes are invalid");
    }
    if (
      bytes.byteLength !== fileSize ||
      sha256Hex(bytes) !== rawFile.sha256
    ) {
      throw new Error("Exit V2 SDW memory logical file binding is invalid");
    }
    const roundTrip = Buffer.from(bytes).toString("utf8");
    if (!Buffer.from(roundTrip, "utf8").equals(Buffer.from(bytes))) {
      throw new Error("Exit V2 SDW memory logical file is not canonical UTF-8");
    }
    totalBytes += bytes.byteLength;
    files.push(rawFile as unknown as ExitV2SdwMemoryLogicalFile);
  }
  if (totalBytes > MAX_SOURCE_SET_BYTES || sourceSetSha256(files) !== value.source_set_sha256) {
    throw new Error("Exit V2 SDW memory logical source-set binding is invalid");
  }
  return value as unknown as ExitV2SdwMemoryLogicalPayload;
}

/** Exact-format union. V2 can never become V1 by omitting a V2 field. */
export function parseExitV2SdwMemoryLogicalPayloadUnion(
  value: unknown,
): ExitV2SdwMemoryLogicalPayloadUnion {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Exit V2 SDW memory logical payload shape is invalid");
  }
  const record = value as Record<string, unknown>;
  if (record.format === EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT) {
    // The frozen V1 leg is the shipped parser itself, never a mirror.
    return validateLogicalPayload(value);
  }
  if (record.format !== EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2) {
    throw new Error("Exit V2 SDW memory logical payload format is unsupported");
  }
  assertExactKeys(record, [
    "destination_harness", "files", "format", "known_signers",
    "projection_file_count", "projection_set_sha256",
    "source_archive_lineage_ref", "source_file_count", "source_harness",
    "source_owner_ref", "source_set_sha256", "state", "transcode_version",
  ], "logical payload v2");
  if (!Array.isArray(record.files)) {
    throw new Error("Exit V2 SDW memory logical payload v2 files are invalid");
  }
  const v1Files: unknown[] = [];
  for (const raw of record.files) {
    assertExactKeys(raw, [
      "bytes_base64url", "path", "provenance", "sha256", "size_bytes",
      "source_class", "source_passage_id",
    ], "logical file v2");
    assertSafeIdentifier(asString(raw.source_passage_id), "source passage id");
    const provenance = parseMemoryProvenanceCompanionValue(raw.provenance);
    if (!provenance.ok) {
      throw new Error(`Exit V2 SDW memory logical payload v2 provenance is invalid: ${provenance.error.code}`);
    }
    v1Files.push({
      bytes_base64url: raw.bytes_base64url, path: raw.path, sha256: raw.sha256,
      size_bytes: raw.size_bytes, source_class: raw.source_class,
    });
  }
  const rawKnownSigners = record.known_signers as { version?: unknown; signers?: unknown };
  if (Array.isArray(rawKnownSigners?.signers) &&
      rawKnownSigners.signers.length > MAX_MEMORY_PROVENANCE_SIGNER_ENTRIES) {
    throw new Error("Exit V2 SDW memory logical payload v2 known_signers exceeds its memory-provenance bound");
  }
  const signerCheck = checkKnownSignersStructure(rawKnownSigners);
  if (!signerCheck.ok || record.known_signers === null ||
      typeof record.known_signers !== "object" ||
      typeof (record.known_signers as Record<string, unknown>).signature !== "string") {
    throw new Error("Exit V2 SDW memory logical payload v2 known_signers is invalid");
  }
  // Reuse V1 validation for every unchanged logical field and file binding.
  const { known_signers: _knownSigners, ...sharedFields } = record;
  validateLogicalPayload({ ...sharedFields,
    format: EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT, files: v1Files });
  return value as ExitV2SdwMemoryLogicalPayloadV2;
}

function logicalPayload(
  archive: MemoryTranscodeLogicalArchive,
  sourceLineageRef: string,
): ExitV2SdwMemoryLogicalPayload {
  return {
    format: EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT,
    transcode_version: MEMORY_TRANSCODE_VERSION,
    state: "complete",
    source_harness: archive.from_harness,
    destination_harness: archive.to_harness,
    source_owner_ref: archive.owner_ref,
    source_archive_lineage_ref: sourceLineageRef,
    source_file_count: archive.source_file_count,
    source_set_sha256: archive.source_set_sha256,
    projection_file_count: archive.projection_file_count,
    projection_set_sha256: archive.projection_set_sha256,
    files: archive.files.map((file) => ({
      path: file.path,
      source_class: file.source_class,
      bytes_base64url: toBase64url(Buffer.from(file.text, "utf8")),
      size_bytes: file.size,
      sha256: file.sha256,
    })),
  };
}

async function logicalPayloadV2(
  archive: MemoryTranscodeLogicalArchive,
  sourceLineageRef: string,
  options: ExportExitV2SdwMemoryArchiveOptions,
): Promise<ExitV2SdwMemoryLogicalPayloadV2> {
  if (options.signer.did === undefined || options.resolveProvenanceSigner === undefined) {
    throw new Error("Exit V2 signed-memory export requires a DID and provenance signer resolver");
  }
  const integrityState = await options.adapter.getMemoryIntegrityState();
  if (integrityState !== "state_COMPLETE") {
    throw new Error("Exit V2 signed-memory export requires completed provenance migration");
  }
  const companions: MemoryProvenanceCompanion[] = [];
  const signerEntries = new Map<string, Uint8Array>();
  for (const file of archive.files) {
    if (file.source_passage_id === undefined) {
      throw new Error("Exit V2 signed-memory export lacks a source passage binding");
    }
    const status = await options.adapter.getPassageProvenance(file.source_passage_id);
    if (status.status !== "verified") {
      throw new Error("Exit V2 signed-memory export refuses an unsigned or quarantined passage");
    }
    const companion = status.companion;
    if (!isMemoryProvenanceOutboundSyncEligible({
      state: integrityState, companionVerified: true, companion, quarantined: false,
    })) {
      throw new Error("Exit V2 signed-memory export refuses legacy-unattested provenance");
    }
    for (const signed of [companion.origin, companion.admission]) {
      const publicKey = options.resolveProvenanceSigner(
        signed.body.signer_identity_id,
        signed.body.signer_did,
      );
      if (publicKey === undefined) {
        throw new Error("Exit V2 signed-memory export cannot resolve a provenance signer");
      }
      const ownKey = fromBase64urlStrict(options.signer.public_key);
      if (signed.body.signer_did === options.signer.did &&
          !Buffer.from(publicKey).equals(Buffer.from(ownKey))) {
        throw new Error("Exit V2 signed-memory exporter DID resolves to a conflicting key");
      }
      // Exclude only the manifest's exact exporter DID. A legacy DID can
      // legitimately name the same Ed25519 key and still needs its own row.
      if (signed.body.signer_did !== options.signer.did) {
        const prior = signerEntries.get(signed.body.signer_did);
        if (prior !== undefined && !Buffer.from(prior).equals(Buffer.from(publicKey))) {
          throw new Error("Exit V2 signed-memory export found a conflicting provenance signer");
        }
        signerEntries.set(signed.body.signer_did, publicKey);
      }
    }
    companions.push(companion);
  }
  const signers: KnownSignersEntry[] = [...signerEntries]
    .map(([did, publicKey]) => ({ did, public_key: toBase64url(publicKey) }))
    .sort((a, b) => a.did.localeCompare(b.did));
  const signature = await options.signer.sign(knownSignersSigningBytes({ version: 1, signers }));
  const knownSigners: KnownSignersArtifact = { version: 1, signers, signature: toBase64url(signature) };
  const base = logicalPayload(archive, sourceLineageRef);
  return {
    ...base,
    format: EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2,
    files: base.files.map((file, index) => ({
      ...file,
      source_passage_id: archive.files[index]!.source_passage_id!,
      provenance: companions[index]!,
    })),
    known_signers: knownSigners,
  };
}

function payloadToLogicalArchive(
  payload: ExitV2SdwMemoryLogicalPayloadUnion,
): MemoryTranscodeLogicalArchive {
  return {
    // Source opaque archive ids are intentionally absent from the artifact.
    // This placeholder is never persisted; destination ids derive locally.
    archive_id: payload.source_archive_lineage_ref.slice(0, OPAQUE_ARCHIVE_ID_HEX_CHARS),
    owner_ref: payload.source_owner_ref,
    version: MEMORY_TRANSCODE_VERSION,
    state: "complete",
    from_harness: payload.source_harness,
    to_harness: payload.destination_harness,
    source_file_count: payload.source_file_count,
    source_set_sha256: payload.source_set_sha256,
    projection_file_count: payload.projection_file_count,
    projection_set_sha256: payload.projection_set_sha256,
    files: payload.files.map((file) => ({
      path: file.path,
      source_class: file.source_class,
      text: Buffer.from(fromBase64urlStrict(file.bytes_base64url)).toString("utf8"),
      size: file.size_bytes,
      sha256: file.sha256,
    })),
  };
}

function verificationReceipt(validated: ValidatedArchive): VerifyExitV2SdwMemoryArchiveResult {
  return {
    passed: true,
    artifact_sha256: validated.artifactSha256,
    source_lineage_ref: validated.payload.source_archive_lineage_ref,
    source_file_count: validated.payload.source_file_count,
    source_set_sha256: validated.payload.source_set_sha256,
    source_harness: validated.payload.source_harness,
    destination_harness: validated.payload.destination_harness,
  };
}

function replayReceipt(
  passage: MemoryPassage,
  validated: ValidatedArchive,
  destinationOwnerRef: string,
  destinationArchiveId: string,
  signer: ExitV2MemorySigner,
): ImportExitV2SdwMemoryArchiveResult {
  const lineage = parseStoredLineage(passage);
  if (
    lineage.body.source_archive_lineage_ref === validated.payload.source_archive_lineage_ref &&
    lineage.body.source_artifact_sha256 !== validated.artifactSha256
  ) {
    throw new Error(
      "Exit V2 SDW memory source lineage already maps to a different artifact digest",
    );
  }
  if (
    lineage.body.source_archive_lineage_ref !== validated.payload.source_archive_lineage_ref ||
    lineage.body.source_artifact_sha256 !== validated.artifactSha256 ||
    lineage.body.destination_owner_ref !== destinationOwnerRef ||
    lineage.body.destination_archive_id !== destinationArchiveId ||
    lineage.body.destination_fortress_id !== signer.fortress_id ||
    lineage.body.destination_signer_identity_id !== signer.identity_id ||
    lineage.body.destination_signer_public_key !== signer.public_key ||
    lineage.body.destination_signer_did !== signer.did
  ) {
    throw new Error("Exit V2 SDW memory replay lineage does not match the imported artifact");
  }
  return {
    replayed: true,
    source_lineage_ref: lineage.body.source_archive_lineage_ref,
    destination_archive_id: lineage.body.destination_archive_id,
    artifact_sha256: lineage.body.source_artifact_sha256,
    lineage_signature: lineage.signature,
    lineage_signed_by: lineage.body.destination_signer_public_key,
  };
}

function parseStoredLineage(passage: MemoryPassage): ExitV2SdwMemorySignedLineage {
  let value: unknown;
  try {
    value = JSON.parse(passage.text);
  } catch {
    throw new Error("Exit V2 SDW memory stored lineage is invalid");
  }
  assertExactKeys(value, ["body", "signature"], "stored lineage");
  assertExactKeys(value.body, [
    "destination_archive_id",
    "destination_fortress_id",
    "destination_harness",
    "destination_owner_ref",
    "destination_signer_did",
    "destination_signer_identity_id",
    "destination_signer_public_key",
    "imported_at",
    "signature_scheme",
    "source_archive_lineage_ref",
    "source_artifact_sha256",
    "source_fortress_id",
    "source_harness",
    "source_set_sha256",
    "version",
  ], "stored lineage body", ["destination_signer_did"]);
  const body = value.body;
  if (
    body.version !== EXIT_V2_SDW_MEMORY_LINEAGE_VERSION ||
    body.signature_scheme !== EXIT_V2_SIGNATURE_SCHEME ||
    !SHA256_HEX.test(asString(body.source_archive_lineage_ref)) ||
    !SHA256_HEX.test(asString(body.source_artifact_sha256)) ||
    !SHA256_HEX.test(asString(body.source_set_sha256)) ||
    !isHarness(body.source_harness) ||
    !isHarness(body.destination_harness) ||
    body.source_harness === body.destination_harness
  ) {
    throw new Error("Exit V2 SDW memory stored lineage is invalid");
  }
  for (const [raw, label] of [
    [body.source_fortress_id, "source fortress id"],
    [body.destination_fortress_id, "destination fortress id"],
    [body.destination_owner_ref, "destination owner scope"],
    [body.destination_archive_id, "destination archive id"],
    [body.destination_signer_identity_id, "destination signer identity id"],
  ] as const) {
    assertSafeIdentifier(asString(raw), label);
  }
  assertIsoTimestamp(asString(body.imported_at), "lineage import timestamp");
  let publicKey: Uint8Array;
  let signature: Uint8Array;
  try {
    publicKey = fromBase64urlStrict(asString(body.destination_signer_public_key));
    signature = fromBase64urlStrict(asString(value.signature));
  } catch {
    throw new Error("Exit V2 SDW memory stored lineage is invalid");
  }
  if (
    publicKey.byteLength !== ED25519_PUBLIC_KEY_BYTES ||
    signature.byteLength !== ED25519_SIGNATURE_BYTES ||
    (
      body.destination_signer_did !== undefined &&
      body.destination_signer_did !== publicKeyToDid(publicKey) &&
      body.destination_signer_did !== legacyPublicKeyToDid(publicKey)
    ) ||
    !verifyIdentitySignature(
      lineageSigningBytes(body as unknown as ExitV2SdwMemoryLineageBody),
      signature,
      publicKey,
    )
  ) {
    throw new Error("Exit V2 SDW memory stored lineage signature is invalid");
  }
  if (
    metadataValue(passage, LINEAGE_SOURCE_REF_KEY) !== body.source_archive_lineage_ref ||
    metadataValue(passage, LINEAGE_ARTIFACT_SHA_KEY) !== body.source_artifact_sha256 ||
    metadataValue(passage, LINEAGE_DESTINATION_ARCHIVE_KEY) !== body.destination_archive_id
  ) {
    throw new Error("Exit V2 SDW memory stored lineage metadata binding is invalid");
  }
  return value as unknown as ExitV2SdwMemorySignedLineage;
}

function lineageSigningBytes(body: ExitV2SdwMemoryLineageBody): Uint8Array {
  return stringToBytes(`${LINEAGE_SIGNING_DOMAIN}\n${canonicalize(body)}`);
}

function sourceLineageReference(
  sourceFortressId: string,
  sourceArchiveId: string,
  sourceSetSha256: string,
): string {
  return sha256Hex(canonicalizeToBytes({
    domain: SOURCE_LINEAGE_DOMAIN,
    source_fortress_id: sourceFortressId,
    source_archive_id: sourceArchiveId,
    source_set_sha256: sourceSetSha256,
  }));
}

function sourceSetSha256(files: readonly ExitV2SdwMemoryLogicalFile[]): string {
  const digest = createHash("sha256");
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    updateLengthPrefixed(digest, Buffer.from(file.path, "utf8"));
    updateLengthPrefixed(digest, fromBase64urlStrict(file.bytes_base64url));
  }
  return digest.digest("hex");
}

function metadataValue(passage: MemoryPassage, key: string): string | undefined {
  return passage.metadata.find((entry) => entry.key === key)?.value;
}

function updateLengthPrefixed(digest: ReturnType<typeof createHash>, bytes: Uint8Array): void {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.byteLength));
  digest.update(length);
  digest.update(bytes);
}

async function listAllPassages(
  adapter: MemoryBackendAdapter,
): Promise<readonly MemoryPassage[]> {
  const passages: MemoryPassage[] = [];
  let after: string | undefined;
  for (let pageNumber = 0; pageNumber < MAX_OWNER_SCOPE_PAGES; pageNumber++) {
    const page = await adapter.listPassages({ limit: OWNER_SCOPE_PAGE_SIZE, after });
    if (page.length === 0) return passages;
    const next = page.at(-1)!.passage_id;
    if (after !== undefined && next <= after) {
      throw new Error("Exit V2 SDW memory owner-scope cursor did not advance");
    }
    passages.push(...page);
    after = next;
  }
  throw new Error("Exit V2 SDW memory owner-scope scan exceeded its page bound");
}

function assertSigner(signer: ExitV2MemorySigner, expectedFortressId?: string): void {
  assertSafeIdentifier(signer.identity_id, "signer identity id");
  assertSafeIdentifier(signer.fortress_id, "signer fortress id");
  if (expectedFortressId !== undefined && signer.fortress_id !== expectedFortressId) {
    throw new Error("Exit V2 SDW memory signer fortress binding is invalid");
  }
  try {
    const publicKey = fromBase64urlStrict(signer.public_key);
    if (publicKey.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
      throw new Error();
    }
    if (
      signer.did !== undefined &&
      signer.did !== publicKeyToDid(publicKey) &&
      signer.did !== legacyPublicKeyToDid(publicKey)
    ) {
      throw new Error();
    }
  } catch {
    throw new Error("Exit V2 SDW memory signer public identity is invalid");
  }
}

function assertSignature(
  signature: Uint8Array,
  publicKeyBase64url: string,
  payload: Uint8Array,
): void {
  if (
    signature.byteLength !== ED25519_SIGNATURE_BYTES ||
    !verifyIdentitySignature(
      payload,
      signature,
      fromBase64urlStrict(publicKeyBase64url),
    )
  ) {
    throw new Error("Exit V2 SDW memory signer returned an invalid signature");
  }
}

function assertIdentityBinding(value: unknown): void {
  assertExactKeys(value, [
    "did",
    "fortress_id",
    "fortress_master_pubkey",
    "identity_id",
  ], "identity binding", ["did"]);
  assertSafeIdentifier(asString(value.identity_id), "identity id");
  assertSafeIdentifier(asString(value.fortress_id), "fortress id");
  try {
    const publicKey = fromBase64urlStrict(asString(value.fortress_master_pubkey));
    if (publicKey.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
      throw new Error();
    }
    if (
      value.did !== undefined &&
      value.did !== publicKeyToDid(publicKey) &&
      value.did !== legacyPublicKeyToDid(publicKey)
    ) {
      throw new Error();
    }
  } catch {
    throw new Error("Exit V2 SDW memory identity binding public identity is invalid");
  }
}

function assertSourcePath(path: string, harness: "claude-code" | "codex"): void {
  if (
    path.length === 0 ||
    Buffer.byteLength(path, "utf8") > MAX_SOURCE_PATH_BYTES ||
    path === "." ||
    path === ".." ||
    !path.endsWith(".md") ||
    path.includes("/") ||
    path.includes("\\") ||
    [...path].some((character) => {
      const code = character.codePointAt(0)!;
      return code <= C0_CONTROL_CODE_POINT_MAX || code === DELETE_CONTROL_CODE_POINT;
    })
  ) {
    throw new Error("Exit V2 SDW memory logical file path is unsafe");
  }
  if (
    harness === "codex" &&
    !["MEMORY.md", "memory_summary.md", "raw_memories.md"].includes(path)
  ) {
    throw new Error("Exit V2 SDW memory Codex logical file path is unsupported");
  }
}

function assertSafeIdentifier(value: string, label: string): void {
  if (!SAFE_IDENTIFIER.test(value)) {
    throw new Error(`Exit V2 SDW memory ${label} is invalid`);
  }
}

function assertIsoTimestamp(value: string, label: string): void {
  if (!Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error(`Exit V2 SDW memory ${label} is invalid`);
  }
}

function assertExactKeys(
  value: unknown,
  allowedKeys: readonly string[],
  label: string,
  optionalKeys: readonly string[] = [],
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Exit V2 SDW memory ${label} is invalid`);
  }
  const keys = Object.keys(value).sort();
  const allowed = new Set(allowedKeys);
  if (keys.some((key) => !allowed.has(key))) {
    throw new Error(`Exit V2 SDW memory ${label} has unknown fields`);
  }
  const optional = new Set(optionalKeys);
  for (const key of allowedKeys) {
    if (!optional.has(key) && !Object.hasOwn(value, key)) {
      throw new Error(`Exit V2 SDW memory ${label} is missing a required field`);
    }
  }
}

function asString(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("Exit V2 SDW memory field must be a string");
  }
  return value;
}

function isHarness(value: unknown): value is "claude-code" | "codex" {
  return value === "claude-code" || value === "codex";
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
