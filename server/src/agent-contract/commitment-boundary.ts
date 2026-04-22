/**
 * Sanctuary Agent Contract v0.1 — Commitment-Boundary Wiring (§7.1).
 *
 * Wraps the policy engine's `evaluateCommitmentBoundary` with an
 * Agent Contract shape: consumes an Agent Card + CommitmentProposal inputs,
 * invokes the gate, and on allow emits a signed `agent_commitment_proposed`
 * envelope. On deny it throws CommitmentBoundaryRefusedError and emits NO
 * signed proposal event (the denied gate receipt is the audit record).
 *
 * Why a wrapper: the policy engine's surface is slot-agnostic and takes a
 * raw (delegates_or_accepts, counterparty, bounded_scope, commitment_class)
 * tuple. The Agent Contract layer tracks cards + policies + audit links;
 * this wrapper gives callers one entry point that does both.
 *
 * Sentinel short-circuit: the policy engine's gate already refuses sentinel
 * policies at `checkSentinelRestriction`. We consume that refusal verbatim;
 * no additional clause per coordinator decision §11.4.
 */

import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { packSignedEvent } from "../mesh/envelope.js";
import type { SignedEvent } from "../mesh/types.js";
import { evaluateCommitmentBoundary } from "../policy-engine/commitment-boundary.js";
import type {
  CommitmentBoundaryRequest,
  CommitmentBoundaryCtx,
} from "../policy-engine/commitment-boundary.js";
import type { GateResult } from "../policy-engine/types.js";
import {
  AGENT_CONTRACT_VERSION,
  SIGNATURE_SCHEME_V1,
  type AgentContractEventType,
  type CommitmentClass,
} from "./constants.js";
import { CommitmentBoundaryRefusedError } from "./errors.js";
import { validateCommitmentProposal } from "./schema.js";
import type { AgentCard, CommitmentProposal } from "./types.js";

export const AGENT_COMMITMENT_PROPOSED_EVENT_TYPE: AgentContractEventType =
  "agent_commitment_proposed";

export interface ProposeCommitmentParams {
  card: AgentCard;
  commitment_class: CommitmentClass | string;
  counterparty: string;
  bounded_scope: {
    deliverable: string;
    deadline_or_terminal: string;
    budget_ref: string;
  };
  /**
   * Condition 1 "delegation/accept" per §7.1. Callers pass `true` only when
   * the action is unambiguously one or the other — e.g. a `task-delegate`
   * class maps to `true` by construction; `output-publish` without a named
   * counterparty does not.
   */
  delegates_or_accepts: boolean;
  /** Gate context (policy + node signing key) — passthrough to policy engine. */
  gate_ctx: CommitmentBoundaryCtx;
  /** Envelope emission context. */
  emitter_node: string;
  emitter_principal: string;
  node_private_key: Uint8Array;
  principal_private_key?: Uint8Array;
  monotonic_seq: number;
  emitted_at?: string;
}

export interface ProposeCommitmentResult {
  /** Decision from the policy engine's gate. Always emitted; `signed_event` only on allow. */
  gate_result: GateResult;
  /** Only present when the gate decided allow. */
  signed_event?: SignedEvent<CommitmentProposal>;
  /** Only present when the gate decided allow. */
  proposal?: CommitmentProposal;
}

/**
 * Evaluate the four §7.1 conditions against the agent's pinned policy. On
 * allow, emit a signed CommitmentProposal on the mesh envelope. On deny,
 * throw CommitmentBoundaryRefusedError carrying the gate's reason_code +
 * explanation.
 */
export function proposeCommitment(
  params: ProposeCommitmentParams
): ProposeCommitmentResult {
  const req: CommitmentBoundaryRequest = {
    agent_id: params.card.agent_id,
    delegates_or_accepts: params.delegates_or_accepts,
    counterparty: params.counterparty,
    bounded_scope: params.bounded_scope,
    commitment_class: params.commitment_class,
  };
  const gate = evaluateCommitmentBoundary(params.gate_ctx, req);
  if (gate.decision !== "allow") {
    throw new CommitmentBoundaryRefusedError(
      params.card.agent_id,
      gate.reason_code,
      gate.explanation
    );
  }
  const emitted_at = params.emitted_at ?? new Date().toISOString();
  const proposal: CommitmentProposal = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    proposal_id: generateProposalId(),
    agent_id: params.card.agent_id,
    fortress_id: params.card.fortress_id,
    commitment_class: params.commitment_class,
    counterparty: params.counterparty,
    bounded_scope: params.bounded_scope,
    policy_version: params.card.policy_version,
    policy_version_hash: params.card.policy_version_hash,
    emitted_at,
    gate_receipt_id: gate.receipt.receipt_id,
  };
  validateCommitmentProposal(proposal);
  const signed_event = packSignedEvent<CommitmentProposal>({
    event_type: AGENT_COMMITMENT_PROPOSED_EVENT_TYPE,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.card.fortress_id,
    payload: proposal,
    monotonic_seq: params.monotonic_seq,
    node_private_key: params.node_private_key,
    principal_private_key: params.principal_private_key,
  });
  return { gate_result: gate, signed_event, proposal };
}

/**
 * Compute a canonical hash of a proposal — used when a commitment flows
 * across mesh nodes and the receiver wants a stable id independent of
 * emitter metadata.
 */
export function hashProposal(proposal: CommitmentProposal): string {
  return toBase64url(sha256(canonicalizeToBytes(proposal)));
}

function generateProposalId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}
