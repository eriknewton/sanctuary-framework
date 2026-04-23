/**
 * Sanctuary Composition v1.0 -- Production Pipeline Wire-up
 *
 * WP-MVP-10 Follow-up #2b. Bridges the three existing surfaces that were
 * shipped as tested primitives but were not wired into a production flow:
 *
 *   1. policy-engine/commitment-boundary.evaluateCommitmentBoundary()
 *      Agent Contract v0.1 §7.1 four-condition gate (delegation-or-accept,
 *      identifiable counterparty, bounded scope, operator-policy permits).
 *   2. agent-contract/commitment-boundary.proposeCommitment()
 *      On allow, produces a signed CommitmentProposal envelope.
 *   3. composition/composition-service.emitForCommitment()
 *      On enabled, packs the proposal into a ConcordiaReceipt shape and
 *      publishes a VerascoreSignal to the operator-private or public hook.
 *
 * Production callers that own a tool-invocation path which may cross an
 * Agent Contract §7.1 commitment boundary call runCompositionPipeline()
 * once per invocation AFTER the policy-engine approval gate has already
 * allowed the action (so the operator's policy has authorized the action)
 * and BEFORE the tool handler's side effect executes (so the signed
 * proposal envelope is emitted before the thing it records happens).
 *
 * Default-off invariant (A6): when compositionService is null OR
 * compositionService.isEnabled() is false, the pipeline never touches
 * composition module emission paths. The only composition-module call on
 * the disabled path is isEnabled() itself (a boolean read).
 *
 * Multi-principal invariant holdout (A7): the pipeline accepts an
 * optional principal_id that flows through to emitForCommitment's input.
 * The v1.0 emitter ignores it; v1.x populates per-principal scope under
 * the Public Pool Federation Mode design.
 *
 * Spec: Review/Sanctuary/Agent_Contract_V0.1_Spec_2026-04-21.md §7.1
 * Spawn prompt:
 *   Review/Sanctuary/WP-MVP-10_Followup_2b_Composition_Production_Pipeline_Spawn_Prompt_2026-04-22.md
 */

import {
  evaluateCommitmentBoundary,
  type CommitmentBoundaryCtx,
  type CommitmentBoundaryRequest,
} from "../policy-engine/commitment-boundary.js";
import { GATE_REASON_CODES } from "../policy-engine/constants.js";
import type { GateResult } from "../policy-engine/types.js";
import { proposeCommitment } from "../agent-contract/commitment-boundary.js";
import type { AgentCard, CommitmentProposal } from "../agent-contract/types.js";
import type { SignedEvent } from "../mesh/types.js";
import type { CompositionService } from "./composition-service.js";
import {
  CONCORDIA_RECEIPT_SCHEMA_URN,
  SIGNATURE_SCHEME_V1,
  type VerascoreScope,
} from "./constants.js";
import type { ConcordiaReceipt, VerascoreSignal } from "./types.js";

/**
 * Tagged status the pipeline returns. Consumers route observability on this
 * value, not on internal gate reason codes.
 *
 * not_a_commitment            conditions 1, 2, or 3 failed. The action is
 *                             not commitment-shaped (not a delegation, no
 *                             counterparty, or unbounded scope). No
 *                             composition emission; no proposal envelope.
 * commitment_denied           action IS commitment-shaped but the pinned
 *                             policy refuses the specific class, or the
 *                             agent is a sentinel, or the policy is null.
 *                             No composition emission; no proposal envelope.
 * commitment_composition_off  all four conditions satisfied, signed proposal
 *                             envelope was emitted, but compositionService
 *                             is null or disabled. The proposal went to the
 *                             audit log; no VerascoreSignal.
 * commitment_emitted          all four conditions satisfied AND composition
 *                             enabled. Signed proposal envelope emitted, a
 *                             VerascoreSignal was published via the
 *                             existing verascore-hook, and both are on the
 *                             audit stream.
 */
export type CompositionPipelineStatus =
  | "not_a_commitment"
  | "commitment_denied"
  | "commitment_composition_off"
  | "commitment_emitted";

/**
 * A single audit-stream entry the pipeline may emit. Two kinds:
 *
 * commitment_proposed  signed CommitmentProposal envelope (mesh event).
 *                      Emitted whenever conditions 1-4 hold, regardless
 *                      of whether composition is enabled.
 * composition_signal   published VerascoreSignal. Emitted only when
 *                      composition is enabled and the proposal was sent.
 *
 * Callers route these wherever they route other federation signed events
 * (AuditLog.append in production). The pipeline itself is transport-agnostic.
 */
export type CompositionAuditEntry =
  | {
      kind: "commitment_proposed";
      signed_event: SignedEvent<CommitmentProposal>;
      /** For per-principal audit slicing at v1.x. Undefined at v1.0 callers. */
      principal_id?: string;
    }
  | {
      kind: "composition_signal";
      signal: VerascoreSignal;
      fortress_id: string;
      /** For per-principal audit slicing at v1.x. Undefined at v1.0 callers. */
      principal_id?: string;
    };

export type CompositionAuditAppender = (
  entry: CompositionAuditEntry
) => void | Promise<void>;

export interface CompositionPipelineInput {
  /** The four §7.1 conditions the pipeline evaluates. */
  request: CommitmentBoundaryRequest;
  /** Gate context (pinned policy, node signing key). */
  gateCtx: CommitmentBoundaryCtx;
  /** Agent card for the invoking agent. Read-only input to proposeCommitment. */
  agentCard: AgentCard;
  /** Envelope emission context passed through to proposeCommitment. */
  emitterNode: string;
  emitterPrincipal: string;
  nodePrivateKey: Uint8Array;
  principalPrivateKey?: Uint8Array;
  monotonicSeq: number;
  /**
   * Composition service instance (the v1.0 default-off framework ships with
   * null here). The pipeline treats null and isEnabled()=false identically.
   */
  compositionService: CompositionService | null;
  /**
   * Audit-stream appender. Called once per proposal (on allow) and once per
   * composition signal (on allow + enabled). A no-op appender is valid for
   * tests; production wires this to the L4 audit log.
   */
  auditAppend: CompositionAuditAppender;
  /**
   * Public Pool Federation Mode multi-principal invariant holdout.
   * Optional at v1.0. When present, the value flows through to the signed
   * proposal's audit entry and to emitForCommitment's input. The v1.0
   * emitter ignores it on the signal itself; v1.x surfaces will populate
   * per-principal scope.
   */
  principal_id?: string;
  /** Optional scope override. Defaults to composition config default (private). */
  verascoreScope?: VerascoreScope;
  /** Required when verascoreScope is 'public'; enforced by emitForCommitment. */
  explicitPublicOptIn?: boolean;
}

export interface CompositionPipelineResult {
  status: CompositionPipelineStatus;
  gateResult: GateResult;
  /** Present when status is commitment_composition_off or commitment_emitted. */
  proposal?: CommitmentProposal;
  signedProposal?: SignedEvent<CommitmentProposal>;
  /** Present only when status is commitment_emitted. */
  signal?: VerascoreSignal;
}

/**
 * Reason codes that indicate the action is not commitment-shaped. A gate
 * receipt with one of these codes is treated as a no-op by the pipeline:
 * the action simply was not a commitment candidate (no delegation, no
 * counterparty, or no bounded scope), not a policy refusal.
 */
const NOT_COMMITMENT_REASON_CODES: ReadonlySet<string> = new Set([
  GATE_REASON_CODES.COMMITMENT_BOUNDARY_NOT_DELEGATION,
  GATE_REASON_CODES.COMMITMENT_BOUNDARY_NO_COUNTERPARTY,
  GATE_REASON_CODES.COMMITMENT_BOUNDARY_UNBOUNDED_SCOPE,
]);

/**
 * Run the full commitment-boundary and composition-emission pipeline for
 * a single tool invocation. See module header for semantics and invariants.
 */
export async function runCompositionPipeline(
  input: CompositionPipelineInput
): Promise<CompositionPipelineResult> {
  const gateResult = evaluateCommitmentBoundary(input.gateCtx, input.request);

  if (gateResult.decision !== "allow") {
    const status: CompositionPipelineStatus =
      NOT_COMMITMENT_REASON_CODES.has(gateResult.reason_code)
        ? "not_a_commitment"
        : "commitment_denied";
    return { status, gateResult };
  }

  const proposeResult = proposeCommitment({
    card: input.agentCard,
    commitment_class: input.request.commitment_class,
    counterparty: input.request.counterparty ?? "",
    bounded_scope: input.request.bounded_scope ?? {
      deliverable: "",
      deadline_or_terminal: "",
      budget_ref: "",
    },
    delegates_or_accepts: input.request.delegates_or_accepts,
    gate_ctx: input.gateCtx,
    emitter_node: input.emitterNode,
    emitter_principal: input.emitterPrincipal,
    node_private_key: input.nodePrivateKey,
    principal_private_key: input.principalPrivateKey,
    monotonic_seq: input.monotonicSeq,
  });

  const signed_event = proposeResult.signed_event;
  const proposal = proposeResult.proposal;
  if (!signed_event || !proposal) {
    // proposeCommitment throws on deny, so allow always yields both. This
    // branch is a defensive narrow for TypeScript; it should be unreachable
    // by construction.
    return { status: "commitment_denied", gateResult: proposeResult.gate_result };
  }

  await input.auditAppend({
    kind: "commitment_proposed",
    signed_event,
    principal_id: input.principal_id,
  });

  const service = input.compositionService;
  if (!service || !service.isEnabled()) {
    return {
      status: "commitment_composition_off",
      gateResult,
      proposal,
      signedProposal: signed_event,
    };
  }

  const receipt: ConcordiaReceipt = {
    receipt_id: proposal.proposal_id,
    schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
    source_event_id: signed_event.event_id,
    source_event_type: signed_event.event_type,
    agent_id: proposal.agent_id,
    counterparty_id: proposal.counterparty,
    commitment_class: proposal.commitment_class,
    references: [],
    signature: signed_event.node_signature,
    signature_scheme: SIGNATURE_SCHEME_V1,
    packed_at: proposal.emitted_at,
  };

  const emitResult = service.emitForCommitment({
    receipt,
    fortressId: input.agentCard.fortress_id,
    principal_id: input.principal_id,
    scope: input.verascoreScope,
    explicitPublicOptIn: input.explicitPublicOptIn,
  });

  await input.auditAppend({
    kind: "composition_signal",
    signal: emitResult.signal,
    fortress_id: input.agentCard.fortress_id,
    principal_id: input.principal_id,
  });

  return {
    status: "commitment_emitted",
    gateResult,
    proposal,
    signedProposal: signed_event,
    signal: emitResult.signal,
  };
}
