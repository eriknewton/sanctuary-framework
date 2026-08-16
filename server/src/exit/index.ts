export {
  exportExitBundle,
  importExitBundle,
  exitBundleManifestShape,
  ExitBundleImportError,
  EXIT_EMPTY_REASONS,
  type ExitEmptyReason,
  type ExportExitBundleOptions,
  type ExportExitBundleResult,
  type ImportExitBundleOptions,
  type ImportExitBundleResult,
  type ExitEncryptedStateBundle,
  type ExitSourceCustody,
  type ExitPublicIdentityArtifact,
  type ExitPolicySetArtifact,
  type ExitAuditReceiptsArtifact,
  type ExitCommitmentsArtifact,
  type ExitPlaceholderVaultMetadataArtifact,
} from "./bundle.js";

export {
  verifyExitBundle,
  readManifest,
  loadExitArtifact,
  summarizeEncryptedState,
  type ExitBundleDeclaredRekeyMaterial,
  type ExitBundleDetailedVerifierResult,
  type ExitEncryptedStateSummary,
  type LoadedExitArtifact,
  type VerifyExitBundleOptions,
} from "./verifier.js";
// `encryptedStateSubVerdictFailed` / `EncryptedStateStructuralHealth`
// (aggregator mutation-test helper, server/test/exit/exit-verifier-aggregator
// .test.ts) are deliberately NOT re-exported here: they are module-internal
// to verifier.ts, not an MCP/CLI-facing surface, and the package's public
// surface is frozen by test/structure/public-surface-snapshot.test.ts. The
// test imports them directly from "../../src/exit/verifier.js" instead,
// matching the existing pattern of several sibling exit tests that import
// straight from bundle.ts for the same reason.

export {
  inspectExitBundle,
  inspectExitCode,
  type ExitBundleInspectionReport,
} from "./inspect.js";

export {
  exportExitV2SdwMemoryArchive,
  importExitV2SdwMemoryArchive,
  participantExitSdwMemoryRetention,
  verifyExitV2SdwMemoryArchive,
  type ExitV2MemorySigner,
  type ExportExitV2SdwMemoryArchiveOptions,
  type ExportExitV2SdwMemoryArchiveResult,
  type VerifyExitV2SdwMemoryArchiveOptions,
  type VerifyExitV2SdwMemoryArchiveResult,
  type ImportExitV2SdwMemoryArchiveOptions,
  type ImportExitV2SdwMemoryArchiveResult,
  type ParticipantExitSdwMemoryRetentionReceipt,
} from "./v2-memory-archive.js";

export {
  runExitCommand,
  printExitHelp,
  printExitExportHelp,
  type ExitCommandArgs,
} from "./cli.js";

export {
  mintProvenanceStamp,
  classifyMemoryClass,
  isSealedStamp,
  assertSealedStamp,
  serializeStamp,
  partitionByMemoryClass,
  MemoryClassError,
  type MemoryClass,
  type OriginActor,
  type ProvenanceStamp,
  type SealedProvenanceStamp,
  type MintStampInput,
  type DerivedFromEdge,
  type PartitionCandidate,
  type PartitionDecision,
  type PartitionResult,
  type PartitionExclusionReason,
  type PartitionConsentRelease,
} from "./memory-class.js";

export {
  recordConsentRelease,
  writeExitTombstone,
  isIntentToRemoveNotErasure,
  EXIT_CONSENT_AUDIT_OPS,
  type ConsentDisposition,
  type ConsentReleaseInput,
  type ConsentReleaseReceipt,
  type ExitConsentAuditOp,
  type ExitTombstone,
  type ExitTombstoneReason,
  type ExitTombstoneInput,
} from "./consent.js";
