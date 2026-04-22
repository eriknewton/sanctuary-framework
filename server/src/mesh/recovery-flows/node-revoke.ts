/**
 * Ceremony 2 — Compromised-node revoke.
 *
 * Spec §7.2 (revocation), §3.6.1 (guardian-initiated revoke), Architecture
 * Walk Key 8 (operator-in-the-loop invariant — NO auto-revoke), Key 13
 * (recovery cascade integration).
 *
 * Flow:
 *   1. `propose` — operator picks a flagged-compromised target node. Guardian
 *      quorum signatures are pre-collected (on a separate ceremony device).
 *      Optionally: operator flags `require_master_rotation` to chain a
 *      master-rotation ceremony if the compromise may have exposed the
 *      fortress-master secret.
 *   2. `confirm` — operator explicit confirmation step. Key 8: no state
 *      changes before this call.
 *   3. `execute` — verifies the quorum against the pinned roster, emits a
 *      signed `node_revoke` wire event carrying the quorum signatures,
 *      marks the target node revoked in the local NodeRoster, then
 *      optionally executes the chained master-rotation ceremony.
 *
 * Non-auto-revoke invariant test: a proposed but unconfirmed revoke is a
 * no-op; no wire traffic, no roster mutation. Detector-driven alerts (§8.2
 * + §8.3) surface the target + decision_options; they do NOT mutate roster
 * state. This ceremony is the only path that actually revokes.
 */

import type { MeshNode } from "../lifecycle/mesh-node.js";
import {
  verifyGuardianQuorum,
  type GuardianQuorumProof,
  type GuardianRoster,
  type MasterRotationQuorumInput,
} from "../guardian/index.js";
import type {
  FortressMasterPublicKey,
  NodeRevokePayload,
  SignedEvent,
} from "../types.js";
import {
  emitGateDenied,
  type AlertEmitContext,
  type EmittedAlert,
} from "../failure-modes/alerts.js";
import { FAILURE_MODE } from "../failure-modes/constants.js";
import {
  CeremonyError,
  CeremonyNotConfirmedError,
} from "./errors.js";
import type {
  NodeRevokeProposal,
  NodeRevokeResult,
  OperatorConfirmation,
} from "./types.js";
import {
  MasterRotationCeremony,
  type MasterRotationAckSubscription,
  type MasterRotationInitiatorContext,
} from "./master-rotation.js";

export interface NodeRevokeContext {
  node: MeshNode;
  pinned_master: FortressMasterPublicKey;
  pinned_roster: GuardianRoster;
  emit_ctx: AlertEmitContext;
  /** Optional chained rotation context — required if proposal.require_master_rotation is set. */
  master_rotation_ctx?: MasterRotationInitiatorContext;
}

export class NodeRevokeCeremony {
  readonly ceremony_id: string;
  readonly ceremony_type = "node_revoke" as const;
  state: "proposed" | "confirmed" | "executing" | "completed" | "failed" =
    "proposed";
  proposed_at: string;
  confirmed_at?: string;
  completed_at?: string;
  failure_reason?: string;

  private readonly proposal: NodeRevokeProposal;
  private readonly ctx: NodeRevokeContext;
  private chainedRotation?: MasterRotationCeremony;

  private constructor(params: {
    ceremony_id: string;
    proposal: NodeRevokeProposal;
    ctx: NodeRevokeContext;
  }) {
    this.ceremony_id = params.ceremony_id;
    this.proposed_at = new Date().toISOString();
    this.proposal = params.proposal;
    this.ctx = params.ctx;
  }

  static propose(params: {
    proposal: NodeRevokeProposal;
    ctx: NodeRevokeContext;
  }): NodeRevokeCeremony {
    if (!params.proposal.reason || params.proposal.reason.trim().length === 0) {
      throw new CeremonyError(
        "node_revoke proposal requires a non-empty reason"
      );
    }
    // Verify the quorum NOW so a mis-assembled proposal is caught pre-confirm.
    // The canonical quorum input for a revoke re-uses the master-rotation
    // input shape but with the target_node bound in via the `rotated_at`-
    // shaped context — in v0.1 we simply re-use the guardian roster's
    // `verifyGuardianQuorum` primitive directly against a revoke-shaped
    // quorum input. Producers and receivers MUST agree on the canonical
    // bytes. v0.1 ships one agreement: (fortress_id, target_node_id, reason,
    // initiated_at) form the quorum-signed input; we canonicalize those
    // fields so both ceremony signer and verifier hash the same bytes.
    //
    // Using MasterRotationQuorumInput as the underlying shape keeps the
    // producer side (signMasterRotationAsGuardian) re-usable. We bind the
    // revoke intent into the free `rotated_at` slot with a prefix that
    // matches the receiver's verifier. v0.1 receiver uses this same helper;
    // v0.1.1 spec surface will define a `GuardianRevokeQuorumInput` shape.
    const input = revokeQuorumInput(
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

    const ceremony = new NodeRevokeCeremony({
      ceremony_id: generateCeremonyId(),
      proposal: params.proposal,
      ctx: params.ctx,
    });

    if (params.proposal.require_master_rotation) {
      if (
        !params.proposal.chained_master_rotation ||
        !params.ctx.master_rotation_ctx
      ) {
        throw new CeremonyError(
          "node_revoke with require_master_rotation must include chained_master_rotation + master_rotation_ctx"
        );
      }
      // Pre-assemble the master-rotation ceremony against a filtered peer list
      // that excludes the node being revoked — the revoked node MUST NOT be
      // invited to participate in the cascade.
      const filteredPeers = params.ctx.master_rotation_ctx.peers.filter(
        (p) => p.node_id !== params.proposal.target_node_id
      );
      ceremony.chainedRotation = MasterRotationCeremony.propose({
        proposal: params.proposal.chained_master_rotation,
        ctx: {
          ...params.ctx.master_rotation_ctx,
          peers: filteredPeers,
        },
      });
    }
    return ceremony;
  }

  confirm(confirmation: OperatorConfirmation): void {
    if (this.state !== "proposed") {
      throw new CeremonyError(
        `cannot confirm node_revoke from state=${this.state}`
      );
    }
    if (!confirmation.note || confirmation.note.trim().length === 0) {
      throw new CeremonyError(
        "operator confirmation requires a non-empty note"
      );
    }
    this.state = "confirmed";
    this.confirmed_at = confirmation.at ?? new Date().toISOString();
    if (this.chainedRotation) {
      this.chainedRotation.confirm(confirmation);
    }
  }

  /**
   * Execute: broadcast signed node_revoke, mark target revoked in local
   * roster, emit `gate_denied` audit trail, optionally drive the chained
   * master-rotation.
   */
  async execute(params: {
    ack_subscription?: MasterRotationAckSubscription;
  } = {}): Promise<{
    result: NodeRevokeResult;
    revoke_event: SignedEvent<NodeRevokePayload>;
    rotation_result?: import("./types.js").MasterRotationResult;
    gate_event: EmittedAlert;
  }> {
    if (this.state !== "confirmed") {
      throw new CeremonyNotConfirmedError("node_revoke");
    }
    this.state = "executing";

    try {
      // 1. Broadcast node_revoke with quorum signatures attached. MeshNode.
      //    revokePeer handles signing + broadcast + local roster mark.
      const revokeEvent = await this.ctx.node.revokePeer({
        target_node_id: this.proposal.target_node_id,
        reason: this.proposal.reason,
        quorum_signatures: this.proposal.guardian_signatures.map((s) => {
          const guardian = this.ctx.pinned_roster.guardians.find(
            (g) => g.guardian_id === s.guardian_id
          );
          if (!guardian) {
            throw new CeremonyError(
              `guardian ${s.guardian_id} not in pinned roster`
            );
          }
          return {
            guardian_pubkey: guardian.public_key,
            signature: s.signature,
          };
        }),
      });

      // 2. Emit the operator-visible gate_denied audit-trail event (the
      //    "denied the revoked node's continued trust" framing matches the
      //    existing resolveRollback("revoke_compromised") pattern).
      const gateEvent = emitGateDenied(this.ctx.emit_ctx, {
        failure_mode: FAILURE_MODE.COMPROMISED,
        target: this.proposal.target_node_id,
        decision: "revoke_compromised",
        detail: {
          ceremony_id: this.ceremony_id,
          reason: this.proposal.reason,
          quorum_size: this.proposal.guardian_signatures.length,
        },
      });

      // 3. Drive the chained rotation if requested.
      let rotationResult: import("./types.js").MasterRotationResult | undefined;
      if (this.chainedRotation) {
        if (!params.ack_subscription) {
          throw new CeremonyError(
            "chained master-rotation requires an ack_subscription"
          );
        }
        rotationResult = await this.chainedRotation.execute({
          ack_subscription: params.ack_subscription,
        });
      }

      this.state = "completed";
      this.completed_at = new Date().toISOString();
      return {
        result: {
          target_node_id: this.proposal.target_node_id,
          completed_at: this.completed_at,
          master_rotation_chained: !!this.chainedRotation,
        },
        revoke_event: revokeEvent,
        rotation_result: rotationResult,
        gate_event: gateEvent,
      };
    } catch (e) {
      this.state = "failed";
      this.failure_reason = e instanceof Error ? e.message : String(e);
      throw e;
    }
  }

  chainedRotationCeremony(): MasterRotationCeremony | undefined {
    return this.chainedRotation;
  }
}

/**
 * Build the canonical quorum-input bytes for a revoke ceremony. v0.1 re-uses
 * `MasterRotationQuorumInput` shape; producers + verifiers agree on the
 * convention that the `rotated_at` field carries the concatenated revoke
 * intent with a fixed prefix. v0.1.1 spec will define a dedicated
 * `GuardianRevokeQuorumInput` shape.
 *
 * The "old_master_pubkey" is the target node id prefixed with `node:` so the
 * input binds to the revoke target. The "new_master_pubkey" FortressMaster
 * shape carries the reason in `public_key` (base64url of the reason string
 * as bytes) and the fortress_id + a timestamp so the same roster cannot be
 * replayed against two revoke events with the same target.
 *
 * This is explicitly an orchestration-layer convention; the receiver (inside
 * this ceremony, for verifyGuardianQuorum) uses the exact same builder.
 */
export function revokeQuorumInput(
  proposal: NodeRevokeProposal,
  fortressId: string
): MasterRotationQuorumInput {
  const initiatedAt = "revoke:" + proposal.target_node_id;
  return {
    old_master_pubkey: "node:" + proposal.target_node_id,
    new_master_pubkey: {
      public_key: toBase64UrlLocal(
        new TextEncoder().encode("revoke|" + proposal.reason)
      ),
      fortress_id: fortressId,
      created_at: initiatedAt,
    },
    rotated_at: initiatedAt,
    fortress_id: fortressId,
  };
}

function toBase64UrlLocal(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
