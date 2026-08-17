/**
 * Sanctuary Federation Protocol v0.1 — Guardian + Recovery Cascade
 *
 * Module entry point for WP-MVP-3 Follow-up #3 guardian + recovery scope.
 *
 * Spec: §9 (recovery cascade), Architecture Walk Key 13 (M-of-N guardian
 * quorum + DMswitch + master rotation).
 *
 * Public surface:
 *   - GuardianRoster + GuardianIdentity types
 *   - issueGuardianRoster / verifyGuardianRoster / verifyGuardianQuorum
 *   - signMasterRotationAsGuardian
 *   - acceptMasterRotation / buildMasterRotationPayload
 *   - rekeyOnMasterRotation (cascade re-derivations)
 *   - buildMasterRotationAuditPayload + walkAuditContinuity
 *   - Post-recovery prompt builder + store
 *
 * Non-dependency invariant: this module imports only from the mesh
 * foundation (server/src/mesh/) and the core helpers (server/src/core/).
 * No Concordia, no Verascore, no cross-fortress primitive.
 */

export * from "./constants.js";
export * from "./errors.js";
export * from "./types.js";
export {
  canonicalGuardianKey,
  assertValidRosterShape,
  isValidRosterShape,
  issueGuardianRoster,
  verifyGuardianRoster,
  verifyGuardianQuorum,
  signMasterRotationAsGuardian,
} from "./guardian-roster.js";
export {
  acceptMasterRotation,
  buildMasterRotationPayload,
  rekeyOnMasterRotation,
  buildMasterRotationAuditPayload,
  walkAuditContinuity,
  type AcceptMasterRotationParams,
  type AcceptMasterRotationResult,
  type BuildMasterRotationPayloadParams,
  type CascadeReKeyParams,
  type CascadeReKeyResult,
  type AuditContinuityWalkInput,
  type AuditContinuityWalkResult,
} from "./master-rotation.js";
export {
  buildPostRecoveryPrompt,
  PostRecoveryPromptStore,
  type BrokerCredentialPromptItem,
  type PostRecoveryPromptState,
  type BrokerCredentialLister,
} from "./recovery-prompt.js";
// C12-REPLAY / QI-SIBLING-01 / QI-SIBLING-02: v2 guardian quorum-input
// freshness (single source of truth for all three ceremonies).
export {
  GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
  GUARDIAN_DEVICE_RECOVERY_QUORUM_SCHEMA_V2,
  GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
  REVOKE_QUORUM_MAX_LIFETIME_MS,
  REVOKE_QUORUM_DEFAULT_LIFETIME_MS,
  REVOKE_QUORUM_CLOCK_SKEW_MS,
  mintRevokeCollectionContext,
  mintCeremonyId,
  buildGuardianRevokeQuorumInput,
  buildGuardianDeviceRecoveryQuorumInput,
  buildGuardianMasterRotationQuorumInput,
  toWireQuorumContext,
  toWireMasterRotationQuorumContext,
  parseGuardianRevokeQuorumContext,
  parseMasterRotationQuorumContext,
  assertQuorumContextFresh,
  assertRotatedAtWithinContext,
  computeRevokeAuthorizationKey,
  QuorumFreshnessError,
  type GuardianRevokeQuorumContext,
  type GuardianRevokeQuorumInput,
  type GuardianDeviceRecoveryQuorumInput,
  type GuardianMasterRotationQuorumInput,
  type NodeRevokeQuorumContextWire,
  type MasterRotationQuorumContextWire,
  type ParsedQuorumContext,
  type QuorumContextParseResult,
  type QuorumContextParseFailure,
  type QuorumContextSchema,
  type FreshnessMode,
} from "./revoke-quorum-input.js";
