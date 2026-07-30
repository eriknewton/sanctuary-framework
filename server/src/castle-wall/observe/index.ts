/**
 * Castle Wall Observe / Learn Allow-List v1 -- public module surface.
 *
 * Consumers (the CLI, and any future dashboard wiring) import from this
 * barrel rather than reaching into individual files, per the repo's barrel
 * convention (see server/src/README.md).
 */

export {
  OBSERVE_NAMESPACE,
  OBSERVE_SCHEMA_VERSION,
  OBSERVE_AUDIT_SOURCE_IDS,
  DEFAULT_OBSERVE_GRANULARITY,
  candidateKey,
  candidateKeyDigest,
  isObserveAuditSourceId,
} from "./types.js";
export type {
  HostnameSource,
  ObserveAuditSourceId,
  ObserveGranularity,
  ObserveProvenance,
  FlowObservationEvent,
  CandidateObservation,
  ObserveCandidateReviewAction,
  ObserveCandidateReviewRecord,
  ObserveModeState,
  FoldWatermark,
} from "./types.js";

export { flagExfilRisk, foldObservations, mergeCandidateObservations } from "./fold.js";

export { flowEventsFromAuditEntries, flowEventFromAuditEntry } from "./adapter.js";

export {
  refreshCandidatesFromAudit,
  candidateCurrentlyAllowed,
  candidatePromotedAwaitingRearm,
  inProcessRefreshLock,
} from "./refresh.js";
export type {
  RefreshAuditSource,
  RefreshAuditSourceDescriptor,
  ObserveAuditSourceReadOutcome,
  ObserveQuarantinedSourceState,
  RefreshCandidateStore,
  RefreshAllowlistRead,
  RefreshDeps,
  RefreshLock,
  RefreshOutcome,
} from "./refresh.js";

export {
  naiveRegisteredDomain,
  widenableRegisteredDomain,
  REFUSED_MULTI_LABEL_PUBLIC_SUFFIXES,
  OBSERVE_PROMOTED_RULE_ID_PREFIX,
  synthesizeCandidateRule,
  synthesizeCandidateRules,
} from "./synthesize.js";
export type { SynthesizeCandidateRulesResult, PromoteRouting } from "./synthesize.js";

export { ObserveStore } from "./store.js";
export type {
  ObserveSourceReadStatus,
  ObserveSourceState,
  ObserveSourceStateSnapshot,
  ObserveWriteIdentity,
  ObserveCandidateReviewSnapshot,
  ObserveLastRefreshOutcome,
  ObserveLastRefreshSourceRead,
  ObserveLastRefreshStatus,
  QuarantinedObserveSourceState,
  QuarantinedObserveCandidateReviewRecord,
} from "./store.js";

export { promoteCandidates, describeEffectiveRule, ruleScopesEqual } from "./promote.js";
export type {
  PromoteSelectionRow,
  PromotePublishResult,
  PromoteApprover,
  PromoteDeps,
  PromoteDroppedReason,
  PromoteOutcome,
  VerifiedManifestRead,
} from "./promote.js";
