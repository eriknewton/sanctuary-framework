/**
 * Recovery Flows — Ceremony constants.
 *
 * Spec §9 (recovery cascade), Architecture Walk Key 8 (incident-response
 * ladder, operator-in-the-loop invariant), Key 13 (recovery cascade).
 *
 * These constants live at the orchestration layer and are NOT part of the
 * federation protocol wire format. Protocol constants live in mesh/constants.ts;
 * lifecycle constants live in mesh/lifecycle/constants.ts; guardian/DMswitch
 * defaults live in mesh/guardian/constants.ts.
 */

/**
 * Default timeout for collecting master-rotation install acks from every peer.
 *
 * At 10s, the orchestrator's view is: any peer that has not acked within this
 * window is a dissenting node that the operator must resolve out-of-band
 * (bring online, revoke, re-admit).
 *
 * This is an orchestration-layer knob, not a federation protocol constant.
 * A v0.1.1 spec amendment may promote it to a protocol-level surface.
 */
export const DEFAULT_BROADCAST_ACK_TIMEOUT_MS = 10_000;

/**
 * Orchestration-layer unicast message kinds. These flow over the shipped
 * MeshTransport.unicast path but are NOT federation protocol events; they
 * carry orchestration state between peers during recovery ceremonies.
 *
 * v0.1 receivers that do not run the orchestrator silently ignore them
 * (matches MeshNode.handleIncomingUnicast's unknown-kind drop).
 *
 * Flagged in the handoff as a v0.1.1 spec-surface candidate.
 */
export const RECOVERY_UNICAST_KINDS = {
  /**
   * Per-peer encrypted secret bundle pre-distributed ahead of a
   * `master_rotation` broadcast. Carries the new fortress-master secret plus
   * this peer's re-issued certificate + the new root principal certificate,
   * AES-256-GCM-wrapped under the peer's OLD per-node transport key (HKDF from
   * the OLD master) so only the intended peer can unwrap.
   */
  MASTER_ROTATION_BUNDLE: "master_rotation_bundle",
  /**
   * Per-peer install ack returned to the rotation initiator after a peer has
   * successfully unwrapped its bundle, verified the `master_rotation`
   * broadcast, and called `installMasterRotation` locally.
   */
  MASTER_ROTATION_ACK: "master_rotation_ack",
} as const;

export type RecoveryUnicastKind =
  (typeof RECOVERY_UNICAST_KINDS)[keyof typeof RECOVERY_UNICAST_KINDS];

/**
 * Ceremony identifiers used by `capability_target` on emitted usage events
 * and by the post-recovery prompt state so downstream filters can route by
 * ceremony.
 */
export const CEREMONY = {
  DEVICE_RECOVERY: "device_recovery",
  NODE_REVOKE: "node_revoke",
  CANONICAL_AUDIT_PROMOTION: "canonical_audit_promotion",
  MASTER_ROTATION: "master_rotation",
} as const;

export type CeremonyId = (typeof CEREMONY)[keyof typeof CEREMONY];
