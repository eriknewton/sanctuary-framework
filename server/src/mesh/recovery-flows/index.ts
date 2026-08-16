/**
 * Recovery Flows — WP-MVP-8 public surface.
 *
 * Ties the FU #3 primitives (guardian roster, DMswitch, post-recovery prompt,
 * master-rotation cascade, canonical-audit promotion) into four operator-
 * driven ceremonies:
 *
 *   1. Device-loss recovery      → `DeviceRecoveryCeremony`
 *   2. Compromised-node revoke   → `NodeRevokeCeremony`
 *   3. Canonical-audit promotion → `CanonicalAuditPromotionCeremony`
 *   4. Master rotation + wire-level broadcast orchestration with acks
 *                                 → `MasterRotationCeremony` + `MasterRotationReceiver`
 *
 * Plus:
 *   - DMswitch grace-window enforcement (`enforceDMswitchGraceWindow`)
 *   - Encrypted per-peer secret bundle for master-rotation distribution
 *     (`wrapMasterRotationBundle` / `unwrapMasterRotationBundle`)
 *   - Post-recovery prompt integration (`firePostRecoveryPrompt`,
 *     `acknowledgePostRecoveryPrompt`)
 *
 * Non-dependency invariant: this module imports only from
 * server/src/mesh/ (foundation), server/src/mesh/lifecycle/,
 * server/src/mesh/guardian/, server/src/mesh/failure-modes/,
 * server/src/agent-contract/usage-event.ts (via alerts), and
 * server/src/core/. No Concordia, no Verascore.
 *
 * §10 hard-gate check: no reserved extension envelope keys, no reserved
 * event_type prefixes, no reserved capability bits touched. Every signed
 * event class used is from the approved set:
 *   - `gate_approved` / `gate_denied` / `policy_pinned` / `sentinel_alert`.
 * The wire event_types used (`node_revoke`, `master_rotation`,
 * `canonical_audit_change`) are existing V01_EVENT_TYPES. The
 * orchestration-layer unicast kinds (`master_rotation_bundle`,
 * `master_rotation_ack`) are NOT federation protocol events.
 */

// Foundation
export * from "./constants.js";
export * from "./errors.js";
export * from "./types.js";

// Secret bundle + DMswitch
export {
  wrapMasterRotationBundle,
  unwrapMasterRotationBundle,
  toBundleSecret,
  fromBundleSecret,
  type MasterRotationBundleEnvelope,
  type MasterRotationBundlePlaintext,
} from "./secret-bundle.js";
export {
  evaluateDMswitchGraceWindow,
  enforceDMswitchGraceWindow,
  type DMswitchGraceWindowInput,
  type DMswitchGraceWindowEvaluation,
} from "./dmswitch.js";

// Ceremonies
export {
  DEVICE_RECOVERY_REVOKE_REASON,
  DeviceRecoveryCeremony,
  deviceRecoveryQuorumInput,
  deviceRecoveryRevokeQuorumInput,
  type DeviceRecoveryContext,
} from "./device-recovery.js";
export {
  NodeRevokeCeremony,
  revokeQuorumInput,
  type NodeRevokeContext,
} from "./node-revoke.js";
export {
  CanonicalAuditPromotionCeremony,
  canonicalAuditPromoteQuorumInput,
  type CanonicalAuditPromotionContext,
} from "./canonical-audit-promotion.js";
export {
  MasterRotationCeremony,
  MasterRotationReceiver,
  createMasterRotationAckSubscription,
  buildRotationBoundaryFor,
  type MasterRotationInitiatorContext,
  type MasterRotationReceiverOptions,
  type MasterRotationAckMessage,
  type MasterRotationAckSubscription,
} from "./master-rotation.js";

// Post-recovery prompt
export {
  firePostRecoveryPrompt,
  acknowledgePostRecoveryPrompt,
  StaticBrokerCredentialLister,
  type FirePostRecoveryPromptParams,
} from "./post-recovery-prompt.js";
