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
} from "./rehome.js";
export type {
  AgentRehomeAdapter,
  RehomePathEntry,
  RehomeOps,
  RehomeStep,
  RehomePlan,
  RehomeStepResult,
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
