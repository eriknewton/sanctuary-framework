/**
 * Recovery Cascade -- multi-principal commitment boundary.
 *
 * Extends Agent Contract section 7.1 four-condition commitment boundary with
 * a second principal: the guardian group state.
 *
 * Acceptance criterion 6: the four-condition check runs with guardian-group
 * state as second principal. Fails closed if guardian threshold unreached.
 *
 * Key 14 LOCKED: multi-principal delegation. Recovery events evaluate the
 * commitment boundary with both operator principal and guardian-group
 * principal.
 */

import { RECOVERY_GATE_REASON_CODES } from "./constants.js";
import {
  buildApprovalSigningInput,
  evaluateThreshold,
} from "./threshold-evaluator.js";
import type {
  MultiPrincipalBoundaryRequest,
  MultiPrincipalBoundaryResult,
} from "./types.js";

/**
 * Evaluate the multi-principal commitment boundary for a recovery action.
 *
 * This is the guardian-group second principal check. It supplements (does
 * not replace) the standard four-condition commitment boundary from the
 * policy engine.
 *
 * The check is:
 *   1. Guardian roster must exist and be non-empty.
 *   2. Cascade state must reference the current roster version.
 *   3. Guardian approval threshold (M-of-N) must be met with valid signatures.
 *
 * Fails closed: if any condition is not met, the result is "deny".
 */
export function evaluateMultiPrincipalBoundary(
  request: MultiPrincipalBoundaryRequest
): MultiPrincipalBoundaryResult {
  const { cascade_state, guardian_roster } = request;

  // Condition 1: guardian roster exists.
  if (!guardian_roster || guardian_roster.guardians.length === 0) {
    return {
      decision: "deny",
      reason_code: RECOVERY_GATE_REASON_CODES.NO_GUARDIAN_ROSTER,
      explanation: `no guardian roster configured for fortress ${cascade_state.fortress_id}; recovery requires an active roster`,
      valid_approvals: 0,
      threshold_required: 0,
    };
  }

  // Condition 2: roster version match.
  if (cascade_state.roster_version !== guardian_roster.version) {
    return {
      decision: "deny",
      reason_code: RECOVERY_GATE_REASON_CODES.GUARDIAN_ROSTER_STALE,
      explanation: `cascade references roster v${cascade_state.roster_version}, pinned roster is v${guardian_roster.version}; approvals must match the current roster`,
      valid_approvals: 0,
      threshold_required: guardian_roster.m,
    };
  }

  // Condition 3: threshold evaluation.
  const signingInput = buildApprovalSigningInput({
    cascade_id: cascade_state.cascade_id,
    recovery_action: cascade_state.action,
    fortress_id: cascade_state.fortress_id,
    roster_version: cascade_state.roster_version,
  });

  const thresholdResult = evaluateThreshold({
    approvals: cascade_state.approvals,
    roster: guardian_roster,
    signing_input: signingInput,
  });

  if (!thresholdResult.threshold_met) {
    return {
      decision: "deny",
      reason_code: RECOVERY_GATE_REASON_CODES.GUARDIAN_THRESHOLD_NOT_MET,
      explanation: `guardian threshold not met: ${thresholdResult.valid_count} valid approvals out of ${thresholdResult.threshold_m} required`,
      valid_approvals: thresholdResult.valid_count,
      threshold_required: thresholdResult.threshold_m,
    };
  }

  return {
    decision: "allow",
    reason_code: RECOVERY_GATE_REASON_CODES.RECOVERY_BOUNDARY_ALLOW,
    explanation: `multi-principal boundary satisfied: ${thresholdResult.valid_count} valid guardian approvals meet threshold of ${thresholdResult.threshold_m}`,
    valid_approvals: thresholdResult.valid_count,
    threshold_required: thresholdResult.threshold_m,
  };
}
