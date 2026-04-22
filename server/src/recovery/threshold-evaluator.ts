/**
 * Recovery Cascade -- threshold evaluator.
 *
 * M-of-N approval aggregation, signature verification, quorum proof.
 *
 * Acceptance criterion 1: below M signed approvals, no recovery action
 * executes. Unit + integration tested.
 *
 * Acceptance criterion 4 (partial): deterministic given same inputs.
 *
 * Acceptance criterion 8: real-crypto tests. Signatures use real
 * @noble/curves Ed25519.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";
import type { GuardianRoster } from "../mesh/guardian/types.js";
import {
  RosterStaleError,
  ThresholdNotMetError,
} from "./errors.js";
import type { GuardianApproval } from "./types.js";

/**
 * The canonical body a guardian signs when approving a recovery action.
 * This shape is deterministic under canonical-JSON so all nodes compute
 * the same hash.
 */
export interface ApprovalSigningInput {
  cascade_id: string;
  recovery_action: string;
  fortress_id: string;
  roster_version: number;
}

/**
 * Build the canonical signing input for a guardian approval.
 */
export function buildApprovalSigningInput(params: {
  cascade_id: string;
  recovery_action: string;
  fortress_id: string;
  roster_version: number;
}): ApprovalSigningInput {
  return {
    cascade_id: params.cascade_id,
    recovery_action: params.recovery_action,
    fortress_id: params.fortress_id,
    roster_version: params.roster_version,
  };
}

/**
 * Result of threshold evaluation.
 */
export interface ThresholdEvaluationResult {
  /** Whether the threshold has been met. */
  threshold_met: boolean;
  /** Number of valid, verified approvals. */
  valid_count: number;
  /** Required threshold. */
  threshold_m: number;
  /** Total guardians. */
  total_n: number;
  /** Guardian IDs of valid approvals. */
  valid_guardian_ids: string[];
  /** Guardian IDs that failed verification (if any). */
  invalid_guardian_ids: string[];
}

/**
 * Evaluate whether M-of-N guardian approval threshold is met.
 *
 * Pure function. Deterministic given the same inputs.
 *
 * Verification rules:
 *   1. Each approval's `signature_scheme` must be `ed25519-v1`.
 *   2. Each approval's `guardian_id` must resolve to a guardian in the
 *      pinned roster.
 *   3. No duplicate `guardian_id` across approvals.
 *   4. Each Ed25519 signature must verify against the matching guardian
 *      pubkey over the canonical signing input.
 *   5. At least M valid signatures.
 *
 * Does NOT throw on insufficient threshold. Returns the evaluation result
 * so the caller can decide whether to throw or surface to operator.
 */
export function evaluateThreshold(params: {
  approvals: GuardianApproval[];
  roster: GuardianRoster;
  signing_input: ApprovalSigningInput;
}): ThresholdEvaluationResult {
  const { approvals, roster, signing_input } = params;

  const guardianMap = new Map(
    roster.guardians.map((g) => [g.guardian_id, g])
  );

  const seen = new Set<string>();
  const validIds: string[] = [];
  const invalidIds: string[] = [];
  const signedBytes = canonicalizeToBytes(signing_input);

  for (const approval of approvals) {
    // Skip duplicates.
    if (seen.has(approval.guardian_id)) {
      invalidIds.push(approval.guardian_id);
      continue;
    }
    seen.add(approval.guardian_id);

    // Scheme check.
    if (approval.signature_scheme !== SIGNATURE_SCHEME_V1) {
      invalidIds.push(approval.guardian_id);
      continue;
    }

    // Roster lookup.
    const guardian = guardianMap.get(approval.guardian_id);
    if (!guardian) {
      invalidIds.push(approval.guardian_id);
      continue;
    }

    // Signature verification.
    try {
      const ok = ed25519.verify(
        fromBase64url(approval.signature),
        signedBytes,
        fromBase64url(guardian.public_key)
      );
      if (ok) {
        validIds.push(approval.guardian_id);
      } else {
        invalidIds.push(approval.guardian_id);
      }
    } catch {
      invalidIds.push(approval.guardian_id);
    }
  }

  return {
    threshold_met: validIds.length >= roster.m,
    valid_count: validIds.length,
    threshold_m: roster.m,
    total_n: roster.n,
    valid_guardian_ids: validIds,
    invalid_guardian_ids: invalidIds,
  };
}

/**
 * Enforce that the M-of-N threshold is met. Throws if not.
 *
 * Acceptance criterion 1: below M signed approvals, no recovery action
 * executes.
 */
export function enforceThreshold(params: {
  approvals: GuardianApproval[];
  roster: GuardianRoster;
  signing_input: ApprovalSigningInput;
  expected_roster_version?: number;
}): ThresholdEvaluationResult {
  // Roster version check (failure mode d).
  if (
    params.expected_roster_version !== undefined &&
    params.roster.version !== params.expected_roster_version
  ) {
    throw new RosterStaleError({
      expected_version: params.roster.version,
      actual_version: params.expected_roster_version,
    });
  }

  const result = evaluateThreshold({
    approvals: params.approvals,
    roster: params.roster,
    signing_input: params.signing_input,
  });

  if (!result.threshold_met) {
    throw new ThresholdNotMetError({
      valid_count: result.valid_count,
      threshold_m: result.threshold_m,
    });
  }

  return result;
}

/**
 * Sign an approval as a guardian. Helper for test fixtures and the
 * guardian signing endpoint.
 */
export function signApproval(params: {
  signing_input: ApprovalSigningInput;
  guardian_id: string;
  guardian_private_key: Uint8Array;
  recovery_action: string;
  cascade_id: string;
}): GuardianApproval {
  const signedBytes = canonicalizeToBytes(params.signing_input);
  const sig = ed25519.sign(signedBytes, params.guardian_private_key);

  return {
    guardian_id: params.guardian_id,
    recovery_action: params.recovery_action as GuardianApproval["recovery_action"],
    cascade_id: params.cascade_id,
    approved_at: new Date().toISOString(),
    signature: toBase64url(sig),
    signature_scheme: SIGNATURE_SCHEME_V1,
  };
}

