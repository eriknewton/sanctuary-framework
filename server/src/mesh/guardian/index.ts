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
