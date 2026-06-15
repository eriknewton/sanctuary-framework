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
