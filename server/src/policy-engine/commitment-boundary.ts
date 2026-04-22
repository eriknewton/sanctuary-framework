/**
 * Sanctuary Policy Engine — Commitment-boundary gate.
 *
 * Agent Contract v0.1 §7.1: an agent action becomes a Concordia commitment
 * candidate when ALL FOUR of these hold:
 *
 *   1. Delegation or accept — action either delegates a task or accepts one.
 *   2. Identifiable counterparty — action names counterparty by agent_id,
 *      peer_agent_id, or external DID. Broadcast / one-to-many not allowed.
 *   3. Bounded scope — deliverable description + deadline/terminal + budget.
 *   4. Operator-policy permits commitment emission — the policy declares
 *      the relevant concordia-commitment-class capability.
 *
 * If any condition fails, this gate returns deny with a specific reason_code
 * so the broker refuses to emit the commitment. A signed receipt is emitted
 * either way so the audit log records the attempt.
 *
 * This gate does NOT sign the commitment itself — that's Concordia's job
 * (Python sidecar at v1.0 per WP-MVP-10). We gate the *boundary*: "may this
 * agent emit a commitment at all, given its pinned policy?" Concordia's
 * engine handles the negotiation cycle downstream.
 *
 * Open decision at spec §11 #4: whether to add a fifth clause explicitly
 * excluding sentinel-emitted commitments. We enforce it structurally via
 * sentinel-role: sentinelPolicyIsValid() rejects any sentinel policy that
 * declares commitment classes, and the runtime check here also refuses
 * because a sentinel policy cannot carry the capability. That satisfies
 * the intent of the open decision without waiting on Erik's pick. Noted in
 * the build summary.
 */

import { GATE_REASON_CODES } from "./constants.js";
import { issueGateReceipt } from "./gate-receipts.js";
import { buildNullPolicy } from "./null-policy.js";
import { checkSentinelRestriction } from "./sentinel-role.js";
import type { GateContext, GateResult } from "./types.js";

export interface CommitmentBoundaryRequest {
  agent_id: string;
  /** Condition 1: true if the action delegates or accepts. */
  delegates_or_accepts: boolean;
  /** Condition 2: named counterparty id — empty / missing fails condition 2. */
  counterparty?: string;
  /** Condition 3: bounded-scope triplet. All three fields required. */
  bounded_scope?: {
    deliverable: string;
    /** ISO8601 deadline OR terminal-condition expression; non-empty string either way. */
    deadline_or_terminal: string;
    /** Budget reference — must be a non-empty id. */
    budget_ref: string;
  };
  /** Condition 4: which commitment class is being emitted. */
  commitment_class: string;
}

export interface CommitmentBoundaryCtx extends GateContext {
  now?: () => Date;
}

/**
 * Evaluate all four §7.1 conditions. Returns allow only if all four hold.
 * Emits a signed receipt keyed under slot = "commitment_boundary".
 */
export function evaluateCommitmentBoundary(
  ctx: CommitmentBoundaryCtx,
  req: CommitmentBoundaryRequest
): GateResult {
  const policy =
    ctx.policy ??
    buildNullPolicy({ agent_id: req.agent_id, fortress_id: ctx.fortressId });

  const emit = (
    decision: "allow" | "deny",
    reason_code: string,
    explanation: string
  ): GateResult => {
    const receipt = issueGateReceipt({
      decision,
      slot: "commitment_boundary",
      agent_id: req.agent_id,
      counterparty: req.counterparty,
      action: `commit:${req.commitment_class}`,
      policy_version: ctx.policy === null ? null : policy.policy_version,
      reason_code,
      fortress_id: ctx.fortressId,
      evaluating_node_id: ctx.nodeId,
      node_signing_key: ctx.nodeSigningKey,
      now: ctx.now,
    });
    return { decision, reason_code, receipt, explanation };
  };

  // Null policy ⇒ deny (same hermetic default as the slot gates).
  if (ctx.policy === null) {
    return emit(
      "deny",
      GATE_REASON_CODES.NULL_POLICY_HERMETIC_DENY,
      `no pinned policy for ${req.agent_id}; commitments cannot be emitted under the hermetic default`
    );
  }

  // Sentinel short-circuit — sentinels cannot emit commitments at v1.0 per
  // Walkthrough Key 11 LOCKED. Receipts still get issued for audit.
  const sent = checkSentinelRestriction(policy, req.counterparty ?? "");
  if (policy.capabilities.is_sentinel) {
    return emit(
      "deny",
      GATE_REASON_CODES.SENTINEL_INWARD_RESTRICTION,
      sent.explanation ??
        `sentinel agents are inward-facing at v1.0 and cannot emit commitments`
    );
  }

  // Condition 1.
  if (!req.delegates_or_accepts) {
    return emit(
      "deny",
      GATE_REASON_CODES.COMMITMENT_BOUNDARY_NOT_DELEGATION,
      `action does not delegate or accept a task; not a commitment candidate per Agent Contract §7.1 condition 1`
    );
  }

  // Condition 2.
  if (!req.counterparty || req.counterparty.length === 0) {
    return emit(
      "deny",
      GATE_REASON_CODES.COMMITMENT_BOUNDARY_NO_COUNTERPARTY,
      `action has no identifiable counterparty; commitments require a named agent_id / peer_agent_id / DID per §7.1 condition 2`
    );
  }

  // Condition 3.
  const bs = req.bounded_scope;
  if (
    !bs ||
    !bs.deliverable ||
    !bs.deadline_or_terminal ||
    !bs.budget_ref ||
    bs.deliverable.length === 0 ||
    bs.deadline_or_terminal.length === 0 ||
    bs.budget_ref.length === 0
  ) {
    return emit(
      "deny",
      GATE_REASON_CODES.COMMITMENT_BOUNDARY_UNBOUNDED_SCOPE,
      `action lacks a bounded scope (deliverable + deadline/terminal + budget_ref) per §7.1 condition 3`
    );
  }

  // Condition 4.
  if (
    !policy.capabilities.concordia_commitment_classes.includes(
      req.commitment_class
    )
  ) {
    return emit(
      "deny",
      GATE_REASON_CODES.COMMITMENT_BOUNDARY_MISSING_CAPABILITY,
      `pinned policy for ${req.agent_id} does not declare commitment class "${req.commitment_class}" per §7.1 condition 4`
    );
  }

  return emit(
    "allow",
    GATE_REASON_CODES.COMMITMENT_BOUNDARY_ALLOW,
    `all four §7.1 conditions satisfied; ${req.agent_id} may emit "${req.commitment_class}" commitment to ${req.counterparty}`
  );
}
