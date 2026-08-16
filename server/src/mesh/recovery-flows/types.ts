/**
 * Recovery Flows — ceremony parameter and result types.
 *
 * Every ceremony follows the same shape:
 *   1. `propose(params)` — computes the cryptographic artifact and caches it.
 *      No state mutation beyond the in-memory ceremony record.
 *   2. `confirm(params?)` — explicit operator-confirmation step. This is the
 *      Key 8 invariant gate; without it, no state changes are applied.
 *   3. Per-ceremony `execute*` step — runs the install + broadcast + ack
 *      collection, emits the final signed usage event, and wires the post-
 *      recovery prompt.
 *
 * Ceremonies are one-shot records. A new ceremony instance is constructed per
 * operator-driven incident. The orchestrator retains them for the post-recovery
 * prompt store integration.
 */

import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../types.js";
import type { GuardianQuorumSignature } from "../guardian/types.js";
import type { CeremonyId } from "./constants.js";

/**
 * Shared shape for operator-confirmation. Every ceremony requires the caller
 * to pass a non-empty `note` so the emitted gate_approved event carries the
 * operator's intent in its detail field.
 *
 * `note` is human-readable free-form text — it ends up in the signed envelope
 * payload, which is hashed + signed. Downstream consumers render it as
 * rationale.
 */
export interface OperatorConfirmation {
  /** Non-empty explanation from the operator. Empty strings rejected. */
  note: string;
  /** ISO8601 of the operator's confirmation click. Defaults to now. */
  at?: string;
}

export type CeremonyState =
  | "proposed"
  | "confirmed"
  | "executing"
  | "completed"
  | "failed";

export interface CeremonyRecord {
  ceremony_id: string;
  ceremony_type: CeremonyId;
  state: CeremonyState;
  proposed_at: string;
  confirmed_at?: string;
  completed_at?: string;
  failed_at?: string;
  failure_reason?: string;
}

/** Device-recovery ceremony inputs. */
export interface DeviceRecoveryProposal {
  /** The node_id whose identity the replacement will inherit. */
  lost_node_id: string;
  /** The replacement node's identity certificate — will take over lost_node_id's slot. */
  replacement_node_cert: NodeIdentityCertificate;
  /** Assembled guardian quorum signatures over the recovery payload. */
  guardian_signatures: GuardianQuorumSignature[];
  /**
   * Guardian quorum signatures over the node_revoke quorum input for the
   * lost node (built by `deviceRecoveryRevokeQuorumInput`). Required: the
   * recovery quorum above covers the recovery intent (lost -> replacement),
   * NOT the revocation the ceremony performs, so the guardians explicitly
   * sign the revocation too. Collected on the same ceremony device in the
   * same signing session as `guardian_signatures`.
   */
  revoke_guardian_signatures: GuardianQuorumSignature[];
  /** ISO8601 timestamp the ceremony was initiated at. */
  initiated_at?: string;
}

export interface DeviceRecoveryResult {
  /** Re-issued replacement cert (may differ from input if the orchestrator re-issues under new master). */
  replacement_cert: NodeIdentityCertificate;
  /** The `lost_node_id` that is now marked inactive in every roster. */
  retired_node_id: string;
  /** ISO8601 timestamp of ceremony completion. */
  completed_at: string;
}

/** Compromised-node revoke ceremony inputs. */
export interface NodeRevokeProposal {
  /** The compromised node_id. */
  target_node_id: string;
  /** Free-form reason, recorded in the node_revoke payload. */
  reason: string;
  /** Guardian quorum signatures — required per Key 13 for revoke. */
  guardian_signatures: GuardianQuorumSignature[];
  /**
   * Optional: if the ceremony operator judges the compromise may have
   * exposed the fortress-master secret, flag this so the orchestrator chains
   * a master rotation. v1.0: operator judgment; v1.x may use heuristic.
   */
  require_master_rotation?: boolean;
  /** Master-rotation proposal if `require_master_rotation` is set. */
  chained_master_rotation?: MasterRotationProposal;
}

export interface NodeRevokeResult {
  target_node_id: string;
  completed_at: string;
  /** Whether a master rotation was chained into this revoke. */
  master_rotation_chained: boolean;
}

/** Canonical-audit promotion inputs. */
export interface CanonicalAuditPromotionProposal {
  /** Incumbent canonical audit node id that is being demoted. */
  current_canonical_node_id: string;
  /** Replica chosen by the operator to take over. */
  new_canonical_node_id: string;
  /**
   * Guardian quorum signatures over a canonical `promote_replica` input. The
   * ceremony uses the same quorum-verification machinery as master rotation
   * so the same M-of-N threshold applies to this operator-gated cascade.
   */
  guardian_signatures: GuardianQuorumSignature[];
}

export interface CanonicalAuditPromotionResult {
  new_canonical_node_id: string;
  previous_canonical_node_id: string;
  completed_at: string;
}

/** Master-rotation ceremony inputs (also used as a chain-leg inside NodeRevokeProposal). */
export interface MasterRotationProposal {
  /** The NEW fortress-master public key the rotation will install. */
  new_master_public: FortressMasterPublicKey;
  /** Transient handle on the NEW master private key for the ceremony operator. */
  new_master_secret: Uint8Array;
  /** NEW root-principal keypair (private zeroed by caller after ceremony). */
  new_root_principal_private_key: Uint8Array;
  new_root_principal_public_key: Uint8Array;
  /** Guardian quorum signatures over the canonical rotation input. */
  guardian_signatures: GuardianQuorumSignature[];
  /** ISO8601 timestamp embedded in the rotation payload. Defaults to now. */
  rotated_at?: string;
  /**
   * Optional ack-timeout override. Default `DEFAULT_BROADCAST_ACK_TIMEOUT_MS`.
   * Set to a lower value in tests; production operators default to the 10s
   * window.
   */
  ack_timeout_ms?: number;
}

export interface MasterRotationResult {
  rotated_at: string;
  new_master_pubkey: string;
  /** Acks received, keyed by node_id. */
  acks_received: string[];
  /** Nodes that did not ack within the timeout; surface to operator. */
  dissenting_nodes: string[];
  /** Re-issued root principal cert the operator must persist alongside the new master. */
  new_root_principal_cert: PrincipalCertificate;
}
