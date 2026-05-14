/**
 * Ceremony 1 — Device-loss recovery.
 *
 * Spec §9 (recovery cascade), Architecture Walk Key 8 (operator-in-the-loop),
 * Key 13 (recovery cascade integration), §3.6.1 (guardian-initiated path).
 *
 * Scenario: operator's primary node (phone stolen, laptop bricked, cocoon
 * unreadable) is gone. Operator authenticates to any surviving node, holds
 * the guardian-quorum recovery bundle, and drives this ceremony:
 *   1. `propose` — operator names the lost node_id + the replacement's
 *      NodeIdentityCertificate (signed under the CURRENT fortress-master
 *      during a prior join step, or freshly issued by a surviving principal
 *      for the replacement). Guardian quorum signs a recovery intent.
 *   2. DMswitch grace-window enforcement: if the DMswitch has NOT yet
 *      fired AND operator activity is within the configured grace window,
 *      `propose` throws `DMswitchGraceWindowActive`. Outside the window
 *      (or if dmswitch_already_fired is set because the §8.5 operator-
 *      presence DMswitch has fired), it proceeds.
 *   3. `confirm` — operator explicit confirmation.
 *   4. `execute` — revokes the lost node's cert (via a guardian-quorum-
 *      signed revoke event), emits `launched` event_class for the
 *      replacement node, wires the replacement cert into the roster with
 *      admitPeerCertificate if the replacement is a peer.
 *
 * HKDF re-derivation: because the operator still holds the fortress-master
 * (via the guardian bundle), the replacement node receives its cert + the
 * fortress-master secret and can re-derive `node_audit_chain_key` +
 * `node_transport_key` via `deriveNodeAuditChainKey` /
 * `deriveNodeTransportKey`. This is tested in the integration drill against
 * the byte-identical re-derivation invariant.
 *
 * v1.0 scope: device recovery uses the SAME current fortress-master. A full
 * master rotation is handled by `MasterRotationCeremony`. Operators who
 * judge the lost device was compromised chain a rotation via
 * `NodeRevokeCeremony.require_master_rotation` or by driving both ceremonies
 * in sequence.
 */

import type { MeshNode } from "../lifecycle/mesh-node.js";
import {
  verifyGuardianQuorum,
  type GuardianQuorumProof,
  type GuardianRoster,
  type MasterRotationQuorumInput,
} from "../guardian/index.js";
import {
  deriveNodeAuditChainKey,
  deriveNodeTransportKey,
  verifyCertChain,
} from "../trust-root.js";
import type {
  FortressMasterPublicKey,
  PrincipalCertificate,
} from "../types.js";
import {
  emitGateApproved,
  type AlertEmitContext,
  type EmittedAlert,
} from "../failure-modes/alerts.js";
import {
  CeremonyError,
  CeremonyNotConfirmedError,
} from "./errors.js";
import {
  enforceDMswitchGraceWindow,
  type DMswitchGraceWindowInput,
} from "./dmswitch.js";
import type {
  DeviceRecoveryProposal,
  DeviceRecoveryResult,
  OperatorConfirmation,
} from "./types.js";

export interface DeviceRecoveryContext {
  /** The node driving the ceremony — typically a surviving peer. */
  node: MeshNode;
  /** Principal cert chain re-used for chain verification. */
  root_principal_cert: PrincipalCertificate;
  pinned_master: FortressMasterPublicKey;
  pinned_roster: GuardianRoster;
  emit_ctx: AlertEmitContext;
  /** Fortress-master secret for HKDF re-derivation verification. */
  fortress_master_secret: Uint8Array;
  /**
   * DMswitch grace-window input. The ceremony enforces per §9.2 — see
   * `dmswitch.ts`. Operators may set `dmswitch_already_fired: true` to
   * signal the §8.5 operator-presence DMswitch has fired (per §3.6.1 the
   * guardian-revocation path is unlocked, and device-recovery proceeds
   * without grace-window gating).
   */
  dmswitch_input: DMswitchGraceWindowInput;
}

export class DeviceRecoveryCeremony {
  readonly ceremony_id: string;
  readonly ceremony_type = "device_recovery" as const;
  state: "proposed" | "confirmed" | "executing" | "completed" | "failed" =
    "proposed";
  proposed_at: string;
  confirmed_at?: string;
  completed_at?: string;
  failure_reason?: string;

  private readonly proposal: DeviceRecoveryProposal;
  private readonly ctx: DeviceRecoveryContext;

  private constructor(params: {
    ceremony_id: string;
    proposal: DeviceRecoveryProposal;
    ctx: DeviceRecoveryContext;
  }) {
    this.ceremony_id = params.ceremony_id;
    this.proposed_at =
      params.proposal.initiated_at ?? new Date().toISOString();
    this.proposal = params.proposal;
    this.ctx = params.ctx;
  }

  static propose(params: {
    proposal: DeviceRecoveryProposal;
    ctx: DeviceRecoveryContext;
  }): DeviceRecoveryCeremony {
    // 1. DMswitch grace-window gate.
    enforceDMswitchGraceWindow(params.ctx.dmswitch_input);

    // 2. Replacement cert MUST chain under the current fortress-master.
    verifyCertChain(
      params.proposal.replacement_node_cert,
      params.ctx.root_principal_cert,
      params.ctx.pinned_master
    );

    // 3. Verify the guardian quorum.
    const input = deviceRecoveryQuorumInput(
      params.proposal,
      params.ctx.pinned_master.fortress_id
    );
    const proof: GuardianQuorumProof = {
      roster_version: params.ctx.pinned_roster.version,
      signatures: params.proposal.guardian_signatures,
    };
    verifyGuardianQuorum({
      input,
      proof,
      pinned_roster: params.ctx.pinned_roster,
    });

    return new DeviceRecoveryCeremony({
      ceremony_id: generateCeremonyId(),
      proposal: params.proposal,
      ctx: params.ctx,
    });
  }

  confirm(confirmation: OperatorConfirmation): void {
    if (this.state !== "proposed") {
      throw new CeremonyError(
        `cannot confirm device_recovery from state=${this.state}`
      );
    }
    if (!confirmation.note || confirmation.note.trim().length === 0) {
      throw new CeremonyError(
        "operator confirmation requires a non-empty note"
      );
    }
    this.state = "confirmed";
    this.confirmed_at = confirmation.at ?? new Date().toISOString();
  }

  async execute(): Promise<{
    result: DeviceRecoveryResult;
    gate_event: EmittedAlert;
    /** Proof the replacement can re-derive HKDF material under the shared master. */
    hkdf_re_derivation_proof: {
      audit_chain_key: Uint8Array;
      transport_key: Uint8Array;
    };
  }> {
    if (this.state !== "confirmed") {
      throw new CeremonyNotConfirmedError("device_recovery");
    }
    this.state = "executing";

    try {
      // 1. Revoke the lost node (guardian-quorum-signed revoke event).
      const quorumSignaturesForRevoke = this.proposal.guardian_signatures.map(
        (s) => {
          const g = this.ctx.pinned_roster.guardians.find(
            (x) => x.guardian_id === s.guardian_id
          );
          if (!g) {
            throw new CeremonyError(
              `guardian ${s.guardian_id} not in pinned roster`
            );
          }
          return { guardian_pubkey: g.public_key, signature: s.signature };
        }
      );
      this.ctx.node.registerGuardianRoster(this.ctx.pinned_roster);
      await this.ctx.node.revokePeer({
        target_node_id: this.proposal.lost_node_id,
        reason: "device_loss_recovery",
        quorum_signatures: quorumSignaturesForRevoke,
        guardian_quorum_verified_by_ceremony: true,
      });

      // 2. Admit the replacement cert so roster state knows about it.
      this.ctx.node.admitPeerCertificate({
        certificate: this.proposal.replacement_node_cert,
        issuing_principal_cert: this.ctx.root_principal_cert,
      });

      // 3. Re-derive the replacement node's HKDF subkeys under the current
      //    fortress-master. This is the "replacement inherits the same
      //    symmetric key material as the lost node under guardian recovery"
      //    invariant — the drill asserts byte-identical re-derivation.
      const auditChainKey = deriveNodeAuditChainKey({
        fortress_master_secret: this.ctx.fortress_master_secret,
        node_id: this.proposal.replacement_node_cert.node_id,
      });
      const transportKey = deriveNodeTransportKey({
        fortress_master_secret: this.ctx.fortress_master_secret,
        node_id: this.proposal.replacement_node_cert.node_id,
        node_mode: this.proposal.replacement_node_cert.node_mode,
      });

      // 4. Emit operator-visible gate_approved audit event. Uses the same
      //    failure_mode category as compromised-node revoke because
      //    EmitGateApproved's API is typed against FailureMode | "master_rotation"
      //    | "canonical_audit_loss"; device_recovery is modeled as a
      //    compromise ceremony for audit-trail grouping (the detector treats
      //    lost-device alerts as compromise signals too — §8.2 fourth
      //    bullet).
      const gateEvent = emitGateApproved(this.ctx.emit_ctx, {
        failure_mode: "compromised",
        target: this.proposal.replacement_node_cert.node_id,
        decision: "device_recovery_admit_replacement",
        detail: {
          ceremony_id: this.ceremony_id,
          lost_node_id: this.proposal.lost_node_id,
          replacement_node_id: this.proposal.replacement_node_cert.node_id,
          quorum_size: this.proposal.guardian_signatures.length,
        },
      });

      this.state = "completed";
      this.completed_at = new Date().toISOString();
      return {
        result: {
          replacement_cert: this.proposal.replacement_node_cert,
          retired_node_id: this.proposal.lost_node_id,
          completed_at: this.completed_at,
        },
        gate_event: gateEvent,
        hkdf_re_derivation_proof: {
          audit_chain_key: auditChainKey,
          transport_key: transportKey,
        },
      };
    } catch (e) {
      this.state = "failed";
      this.failure_reason = e instanceof Error ? e.message : String(e);
      throw e;
    }
  }
}

/**
 * Canonical quorum-input for device-recovery. Re-uses
 * `MasterRotationQuorumInput` shape. v0.1.1 spec will define a dedicated
 * `DeviceRecoveryQuorumInput` shape.
 *
 * Binding:
 *   - old_master_pubkey = `node:${lost_node_id}`
 *   - new_master_pubkey = holder of the replacement cert's node_pubkey
 *   - rotated_at = `device_recovery:${lost_node_id}->${replacement_node_id}`
 */
export function deviceRecoveryQuorumInput(
  proposal: DeviceRecoveryProposal,
  fortressId: string
): MasterRotationQuorumInput {
  const rotatedAt =
    "device_recovery:" +
    proposal.lost_node_id +
    "->" +
    proposal.replacement_node_cert.node_id;
  return {
    old_master_pubkey: "node:" + proposal.lost_node_id,
    new_master_pubkey: {
      public_key: proposal.replacement_node_cert.node_pubkey,
      fortress_id: fortressId,
      created_at: rotatedAt,
    },
    rotated_at: rotatedAt,
    fortress_id: fortressId,
  };
}

function generateCeremonyId(): string {
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}
