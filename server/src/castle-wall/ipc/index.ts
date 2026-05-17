/** Public surface of the IPC module. */

export type {
  CastleWallMessage,
  IpcRequestId,
  StatusRequest,
  StatusResponse,
  PolicyReloadRequest,
  PolicyReloadResponse,
  IpcDestination,
  IpcAgentAttribution,
  DecisionRequest,
  DecisionResponse,
  DecisionValue,
  LearnedGranularity,
  AuditEmitNotification,
  AuditEmitMetricBatchNotification,
  UnlockNotification,
  LockNotification,
  HandshakeChallenge,
  HandshakeResponse,
  ManifestSubscribeRequest,
  ManifestUpdatedNotification,
  FlowDecisionRecordedNotification,
  FlowPendingApprovalNotification,
} from "./messages.js";

export type { ParseStep } from "./framing.js";
export { frame, parseFrame, parseSingleFrame, MAX_FRAME_BYTES } from "./framing.js";
