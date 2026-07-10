/**
 * Public surface of the auto-provision module (Build 1 / step 2): folds the
 * manual "create agent account -> re-home -> install daemon -> arm" runbook
 * into one `sanctuary protect` flow. See `orchestrate.ts` for the full
 * folded-fix flow description.
 */

export type {
  RunAsIdentity,
  DetectProvisionNeedInput,
  ProvisionNeedResult,
  AccountShapeVerdict,
} from "./detect.js";
export { detectProvisionNeed } from "./detect.js";

export {
  SAFE_SERVICE_ACCOUNT_RE,
  deriveAgentAccountName,
  planAccountCreate,
  executeAccountProvisionPlan,
  planAndCreateAccount,
} from "./account.js";
export type {
  AccountProvisionOptions,
  AccountProvisionOps,
  AccountProvisionPlan,
} from "./account.js";

export { checkUidExistenceBeforeArm } from "./uid-gate.js";
export type {
  UidExistenceOps,
  UidExistenceCheckResult,
} from "./uid-gate.js";

export {
  planRehome,
  executeRehomePlan,
  restoreRehomeSteps,
  hermesRehomeAdapter,
  RehomeExecutionError,
} from "./rehome.js";
export type {
  AgentRehomeAdapter,
  RehomePathEntry,
  RehomeOps,
  RehomeStep,
  RehomePlan,
  RehomeStepResult,
  RestoreStepOutcome,
  RestoreRehomeResult,
} from "./rehome.js";

export {
  verifyReachabilityBeforeArm,
  verifyReachabilityAfterArm,
} from "./verify.js";
export type {
  EndpointProbeTarget,
  EndpointProbeResult,
  ConnectivityVerifyResult,
} from "./verify.js";

export { withProvisionLock, ProvisionLockHeldError } from "./lockfile.js";
export type { ProvisionLockOps } from "./lockfile.js";

export { unprovision, unprovisionFullyOk } from "./unprovision.js";
export type {
  UnprovisionOps,
  UnprovisionInput,
  UnprovisionStepOutcome,
} from "./unprovision.js";

export { resolveHermesGatewayArgv } from "./harness-argv.js";
export type { HarnessArgvOps, ResolvedHarnessArgv } from "./harness-argv.js";

export { runProvisionFlow } from "./orchestrate.js";
export type {
  ProvisionFlowContext,
  ProvisionFlowOps,
  ProvisionFlowOutcome,
} from "./orchestrate.js";

export { resolvePolicyDaemonAction } from "./policy-daemon.js";
export type { PolicyDaemonState, PolicyDaemonAction } from "./policy-daemon.js";

export {
  HERMES_ENDPOINT_SET,
  EGRESS_PROVISIONED_AUDIT_OP,
  EGRESS_PROVISION_REFUSED_AUDIT_OP,
  EGRESS_PROBE_FAILED_AUDIT_OP,
  AGENT_EGRESS_NEGATIVE_CONTROL_HOST,
  provisionedRuleIdPrefix,
  provisionedRuleId,
  endpointIsMessagingExfilRisk,
  buildProvisionedEgressRules,
  renderEgressPlanLines,
  renderEndpointCheckLines,
  renderAgentEgressReportLines,
  verifyProvisionedEgressStatically,
  egressRulesDir,
  readEgressRulesFromDisk,
  publishProvisionedEgressRules,
  scrubProvisionedEgressRules,
  buildAgentEgressProbeSpecs,
  buildAgentEgressReport,
  asUidTlsProbeArgv,
  asUidProbeReachableDecision,
} from "./egress.js";
export type {
  HarnessEndpoint,
  HarnessEndpointSet,
  HarnessEndpointRiskClass,
  EndpointStaticCheck,
  StaticEgressVerifyResult,
  PolicyReloadTrigger,
  PublishProvisionedEgressInput,
  PublishProvisionedEgressResult,
  ScrubProvisionedEgressInput,
  ScrubProvisionedEgressResult,
  AgentEgressProbeSpec,
  AgentEgressProbeRow,
  AgentEgressVerifyReport,
} from "./egress.js";
