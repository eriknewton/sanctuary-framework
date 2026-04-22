/**
 * Recovery Cascade -- barrel exports.
 *
 * WP-MVP-8: guardian-threshold recovery, DMswitch evaluator, multi-principal
 * commitment boundary, cascade orchestrator.
 *
 * Non-dependency invariant: this module imports only from recovery/*,
 * mesh/guardian/, mesh/canonical-json, mesh/constants, and core/.
 * No Concordia, no Verascore.
 */

// Foundation
export * from "./constants.js";
export * from "./errors.js";
export * from "./types.js";

// Guardian roster management
export {
  enrollGuardian,
  revokeGuardian,
  verifyRecoveryEventSignature,
} from "./guardian-roster.js";

// Recovery event packing + verification
export {
  packRecoveryEvent,
  verifyRecoveryEvent,
  type PackRecoveryEventParams,
} from "./recovery-event.js";

// DMswitch
export {
  validateDmswitchConfig,
  recordActivity,
  evaluateDmswitch,
  enforceDmswitchExpired,
  emitCascadeEntry,
  type DmswitchEvaluation,
} from "./dmswitch.js";

// Threshold evaluator
export {
  buildApprovalSigningInput,
  evaluateThreshold,
  enforceThreshold,
  signApproval,
  type ApprovalSigningInput,
  type ThresholdEvaluationResult,
} from "./threshold-evaluator.js";

// Cascade orchestrator
export {
  initiateCascade,
  beginAwaitingThreshold,
  registerApproval,
  evaluateCascade,
  executeCascade,
  failCascade,
} from "./cascade.js";

// Multi-principal boundary
export { evaluateMultiPrincipalBoundary } from "./multi-principal.js";

// Recovery service (public API)
export {
  RecoveryStore,
  initRecovery,
  registerGuardianApproval,
  queryCascadeState,
  executeRecovery,
  type RecoveryServiceContext,
} from "./recovery-service.js";
