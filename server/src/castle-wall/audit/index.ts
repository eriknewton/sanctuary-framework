/** Public surface of the audit module. */

export type {
  CastleWallAuditEvent,
  CastleWallEventType,
  CastleWallEventDestination,
  CastleWallEventAgent,
} from "./events.js";

export type { BuildEventInput } from "./builder.js";
export {
  buildAuditEvent,
  canonicalizeAuditEvent,
  canonicalizeAuditEventToBytes,
} from "./builder.js";

export type {
  EmissionLivenessNotes,
  EmissionLivenessSnapshot,
  EmissionLivenessWatchdogOptions,
  EmissionRecoveryFinding,
  EmissionStallFinding,
} from "./emission-liveness.js";
export {
  DEFAULT_EMISSION_STALL_GRACE_MS,
  DEFAULT_EMISSION_STALL_MIN_DECISIONS,
  EMISSION_STALL_AUDIT_OP,
  EMISSION_STALL_LOG_PREFIX,
  EMISSION_STALL_RECOVERED_AUDIT_OP,
  EmissionLivenessWatchdog,
} from "./emission-liveness.js";

export type {
  FlowAttribution,
  FlowDecisionCategory,
  PerRuleGroup,
  GroupByRuleOptions,
} from "./per-rule-report.js";
export {
  DEFAULT_DENY_BUCKET,
  attributeFlows,
  filterFlowsByRule,
  groupFlowsByRule,
} from "./per-rule-report.js";
