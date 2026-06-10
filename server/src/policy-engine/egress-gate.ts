/**
 * Sanctuary Policy Engine — Egress gate (WP-MVP-6).
 *
 * Per-agent allowlist of outbound destinations. Compiled from plain-English
 * operator policy; pinned as a signed policy_update. Enforced at the egress
 * chokepoint — the same boundary the wrap pipeline uses for outbound
 * network calls.
 *
 * Denials emit `egress_blocked` usage events (existing event_class).
 * Allows emit `egress_request` usage events for audit completeness.
 *
 * Design: egress gate sits alongside slot gates and commitment-boundary in
 * the gate evaluation hierarchy. It reads the optional `egress` field from
 * the pinned CompiledPolicy. If absent, all egress is blocked (hermetic
 * default). If present with an empty allowlist, all egress is also blocked.
 *
 * Matching: destination is matched literally (exact domain or domain:port).
 * Method matching: if the rule's methods array is empty, all methods are
 * allowed. Otherwise, the request method must appear in the array (case-
 * insensitive).
 *
 * No network, no LLM at gate time — same structural invariant as slot gates.
 */

import { EGRESS_BUDGET_RETENTION_REASON_CODES } from "./constants.js";
import { issueGateReceipt } from "./gate-receipts.js";
import type { GateContext, GateResult } from "./types.js";

export interface EgressRequest {
  agent_id: string;
  /** Outbound destination: domain or domain:port. */
  destination: string;
  /** HTTP method (GET, POST, etc.). Compared case-insensitively. */
  method: string;
}

export interface EgressGateContext extends GateContext {
  now?: () => Date;
}

/**
 * Evaluate an outbound egress request against the pinned policy.
 *
 * Returns allow if a matching rule exists; deny otherwise.
 */
export function evaluateEgressGate(
  ctx: EgressGateContext,
  req: EgressRequest
): GateResult {
  const emit = (
    decision: "allow" | "deny",
    reason_code: string,
    explanation: string
  ): GateResult => {
    const receipt = issueGateReceipt({
      decision,
      slot: "commitment_boundary", // egress uses same receipt slot shape
      agent_id: req.agent_id,
      action: `egress:${req.method}`,
      counterparty: req.destination,
      policy_version: ctx.policy?.policy_version ?? null,
      reason_code,
      fortress_id: ctx.fortressId,
      evaluating_node_id: ctx.nodeId,
      node_signing_key: ctx.nodeSigningKey,
      now: ctx.now,
    });
    return { decision, reason_code, receipt, explanation };
  };

  // No policy at all: hermetic deny.
  if (!ctx.policy) {
    return emit(
      "deny",
      EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_NO_POLICY,
      `no pinned policy for ${req.agent_id}; egress denied by hermetic default`
    );
  }

  // No egress field: hermetic deny.
  if (!ctx.policy.egress) {
    return emit(
      "deny",
      EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_NO_POLICY,
      `pinned policy for ${req.agent_id} has no egress allowlist; all egress denied`
    );
  }

  const { allowlist } = ctx.policy.egress;
  const methodUpper = req.method.toUpperCase();

  for (const rule of allowlist) {
    if (rule.destination !== req.destination) continue;

    // Empty methods array = all methods allowed for this destination.
    if (rule.methods.length === 0) {
      return emit(
        "allow",
        EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_ALLOWED,
        `egress to ${req.destination} ${req.method} allowed by policy`
      );
    }

    // Check method match (case-insensitive).
    if (rule.methods.some((m) => m.toUpperCase() === methodUpper)) {
      return emit(
        "allow",
        EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_ALLOWED,
        `egress to ${req.destination} ${req.method} allowed by policy`
      );
    }

    // Destination matches but method doesn't.
    return emit(
      "deny",
      EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_METHOD_DENIED,
      `egress to ${req.destination} denied: method ${req.method} not in allowlist [${rule.methods.join(", ")}]`
    );
  }

  // No matching destination.
  return emit(
    "deny",
    EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_DESTINATION_DENIED,
    `egress to ${req.destination} denied: destination not in allowlist`
  );
}
