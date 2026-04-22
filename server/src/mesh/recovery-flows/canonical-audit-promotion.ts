/**
 * Ceremony 3 — Canonical-audit-node promotion.
 *
 * Spec §5.4 (canonical audit replica + §8.5 loss detection), Architecture
 * Walk Key 8 (operator-in-the-loop), Key 13 (recovery cascade — canonical-
 * audit loss unlocks a replica-election ceremony).
 *
 * The FU #3 FailureModeDetector has a `promoteCanonicalAudit` operator-
 * decision helper that emits `policy_pinned` + retargets its internal
 * staleness tracker. This ceremony drives the full operator-visible surface:
 * propose → confirm → execute (emit policy_pinned + broadcast
 * canonical_audit_change + retarget roster).
 *
 * Guardian quorum: §5.4 canonical-audit election is guardian-gated at v1.0
 * because it is an authority re-assignment. The detector helper does NOT
 * verify quorum; this ceremony does, before unlocking confirm().
 */

import type { MeshNode } from "../lifecycle/mesh-node.js";
import {
  verifyGuardianQuorum,
  type GuardianQuorumProof,
  type GuardianRoster,
  type MasterRotationQuorumInput,
} from "../guardian/index.js";
import type {
  CanonicalAuditChangePayload,
  FortressMasterPublicKey,
  SignedEvent,
} from "../types.js";
import {
  emitPolicyPinned,
  type AlertEmitContext,
  type EmittedAlert,
} from "../failure-modes/alerts.js";
import {
  CeremonyError,
  CeremonyNotConfirmedError,
} from "./errors.js";
import type {
  CanonicalAuditPromotionProposal,
  CanonicalAuditPromotionResult,
  OperatorConfirmation,
} from "./types.js";

export interface CanonicalAuditPromotionContext {
  /** The node driving the ceremony — must have the principal private key. */
  node: MeshNode;
  /** Principal private key for signing the canonical_audit_change wire event. */
  principal_private_key: Uint8Array;
  emitter_principal: string;
  pinned_master: FortressMasterPublicKey;
  pinned_roster: GuardianRoster;
  emit_ctx: AlertEmitContext;
}

export class CanonicalAuditPromotionCeremony {
  readonly ceremony_id: string;
  readonly ceremony_type = "canonical_audit_promotion" as const;
  state: "proposed" | "confirmed" | "executing" | "completed" | "failed" =
    "proposed";
  proposed_at: string;
  confirmed_at?: string;
  completed_at?: string;
  failure_reason?: string;

  private readonly proposal: CanonicalAuditPromotionProposal;
  private readonly ctx: CanonicalAuditPromotionContext;

  private constructor(params: {
    ceremony_id: string;
    proposal: CanonicalAuditPromotionProposal;
    ctx: CanonicalAuditPromotionContext;
  }) {
    this.ceremony_id = params.ceremony_id;
    this.proposed_at = new Date().toISOString();
    this.proposal = params.proposal;
    this.ctx = params.ctx;
  }

  static propose(params: {
    proposal: CanonicalAuditPromotionProposal;
    ctx: CanonicalAuditPromotionContext;
  }): CanonicalAuditPromotionCeremony {
    if (
      params.proposal.new_canonical_node_id ===
      params.proposal.current_canonical_node_id
    ) {
      throw new CeremonyError(
        "canonical_audit_promotion: new_canonical_node_id must differ from current_canonical_node_id"
      );
    }
    // Verify quorum up front.
    const input = canonicalAuditPromoteQuorumInput(
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
    return new CanonicalAuditPromotionCeremony({
      ceremony_id: generateCeremonyId(),
      proposal: params.proposal,
      ctx: params.ctx,
    });
  }

  confirm(confirmation: OperatorConfirmation): void {
    if (this.state !== "proposed") {
      throw new CeremonyError(
        `cannot confirm canonical_audit_promotion from state=${this.state}`
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
    result: CanonicalAuditPromotionResult;
    canonical_audit_change_event: SignedEvent<CanonicalAuditChangePayload>;
    policy_pinned_event: EmittedAlert;
  }> {
    if (this.state !== "confirmed") {
      throw new CeremonyNotConfirmedError("canonical_audit_promotion");
    }
    this.state = "executing";

    try {
      // 1. Broadcast canonical_audit_change signed event — the on-wire
      //    retargeting signal every peer's dispatcher consumes.
      const evt = await this.ctx.node.designateCanonicalAudit({
        new_canonical_node: this.proposal.new_canonical_node_id,
        principal_private_key: this.ctx.principal_private_key,
        emitter_principal: this.ctx.emitter_principal,
      });

      // 2. Emit policy_pinned — matches FailureModeDetector.promoteCanonicalAudit's
      //    audit-trail pattern (subject="canonical_audit_node", pinned_to=new_id).
      const policyPinned = emitPolicyPinned(this.ctx.emit_ctx, {
        subject: "canonical_audit_node",
        pinned_to: this.proposal.new_canonical_node_id,
        detail: {
          ceremony_id: this.ceremony_id,
          previous_canonical: this.proposal.current_canonical_node_id,
          quorum_size: this.proposal.guardian_signatures.length,
        },
      });

      this.state = "completed";
      this.completed_at = new Date().toISOString();
      return {
        result: {
          new_canonical_node_id: this.proposal.new_canonical_node_id,
          previous_canonical_node_id: this.proposal.current_canonical_node_id,
          completed_at: this.completed_at,
        },
        canonical_audit_change_event: evt,
        policy_pinned_event: policyPinned,
      };
    } catch (e) {
      this.state = "failed";
      this.failure_reason = e instanceof Error ? e.message : String(e);
      throw e;
    }
  }
}

/**
 * Canonical quorum-input for a canonical-audit promotion ceremony. Re-uses
 * the MasterRotationQuorumInput shape; binds:
 *   - old_master_pubkey = `canonical_audit:${current_id}`
 *   - new_master_pubkey = FortressMasterPublicKey-shaped holder of the new id
 *   - rotated_at = `promote_replica:${new_id}` (prevents cross-ceremony replay)
 *
 * v0.1.1 spec will define `CanonicalAuditPromotionQuorumInput` as a first-
 * class shape.
 */
export function canonicalAuditPromoteQuorumInput(
  proposal: CanonicalAuditPromotionProposal,
  fortressId: string
): MasterRotationQuorumInput {
  const rotatedAt = "promote_replica:" + proposal.new_canonical_node_id;
  return {
    old_master_pubkey: "canonical_audit:" + proposal.current_canonical_node_id,
    new_master_pubkey: {
      public_key: toBase64UrlLocal(
        new TextEncoder().encode("canonical_audit:" + proposal.new_canonical_node_id)
      ),
      fortress_id: fortressId,
      created_at: rotatedAt,
    },
    rotated_at: rotatedAt,
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
