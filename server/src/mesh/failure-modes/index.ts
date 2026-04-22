/**
 * Sanctuary Federation Protocol v0.1 — Failure-Mode Operator Surfaces
 *
 * Public surface for WP-MVP-3 Follow-up #3 failure-mode + recovery scope.
 *
 * Spec: §8 (failure modes), §9 (recovery cascade), Architecture Walk Key 8
 * (incident-response ladder), Key 13 (recovery cascade integration).
 *
 * Public exports:
 *   - FailureModeDetector — orchestrator that wires MeshNode hooks +
 *     periodic ticks into operator-facing alert surfaces.
 *   - FailureMode constants + types for failure mode classification.
 *   - Alert emission helpers (sentinel_alert / gate_approved / gate_denied /
 *     policy_pinned).
 *   - DMswitch trigger emission + receipt path.
 *
 * Non-dependency invariant: this module imports only from the mesh
 * foundation (server/src/mesh/), the lifecycle module
 * (server/src/mesh/lifecycle/), the agent-contract usage-event surface
 * (server/src/agent-contract/usage-event.ts), and core helpers. No
 * Concordia, no Verascore, no cross-fortress primitive.
 */

export * from "./constants.js";
export * from "./types.js";
export {
  emitSentinelAlert,
  emitGateApproved,
  emitGateDenied,
  emitPolicyPinned,
  MESH_SYSTEM_POLICY_VERSION_HASH,
  type AlertEmitContext,
  type EmittedAlert,
} from "./alerts.js";
export {
  FailureModeDetector,
  type FailureModeDetectorOptions,
} from "./detector.js";
export {
  packDmswitchTriggeredEvent,
  shouldTriggerDmswitch,
  type DmswitchTriggeredPayload,
} from "./dmswitch.js";
export {
  FailureModeDashboardBridge,
  type MeshHealthBroadcastTarget,
} from "./dashboard-bridge.js";
