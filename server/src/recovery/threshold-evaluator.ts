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
import { canonicalGuardianKey } from "../mesh/guardian/guardian-roster.js";
import type { GuardianRoster } from "../mesh/guardian/types.js";
import {
  RosterStaleError,
  ThresholdNotMetError,
} from "./errors.js";
import type { GuardianApproval } from "./types.js";

/**
 * Bind check: the signing input a quorum is verified against MUST describe the
 * same roster version as the roster whose public keys are used to verify it.
 *
 * Without this bind, a quorum of signatures produced under an earlier roster
 * version (for example one that still counted a now-revoked guardian) would
 * verify byte-for-byte against a later roster as long as the overlapping
 * guardian keys are unchanged. The signature payload carries roster_version,
 * but the verifier previously never compared it to the roster it trusted. This
 * closes that specific cross-version signature-reuse path, fail closed: on any
 * mismatch every approval is treated as invalid so the threshold cannot be met.
 */
function rosterVersionBinds(
  signing_input: ApprovalSigningInput,
  roster: GuardianRoster
): boolean {
  return signing_input.roster_version === roster.version;
}

/**
 * Bind check: an approval object's self-declared cascade_id and recovery_action
 * are unauthenticated metadata (the Ed25519 signature covers only the canonical
 * signing input, not these envelope fields). A caller or audit reader that
 * trusts approval.recovery_action / approval.cascade_id must not be handed an
 * approval whose declared target disagrees with the input it was actually
 * signed over. Any disagreement is treated as invalid, fail closed.
 */
function approvalDeclaresSameTarget(
  approval: GuardianApproval,
  signing_input: ApprovalSigningInput
): boolean {
  return (
    approval.cascade_id === signing_input.cascade_id &&
    approval.recovery_action === signing_input.recovery_action
  );
}

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

  // Fail-closed bind: the roster the quorum is verified against MUST be the
  // same version the approvals were signed over. On a version mismatch no
  // approval can be valid, so the threshold cannot be met (quorum bypass via
  // cross-version signature reuse is closed here).
  if (!rosterVersionBinds(signing_input, roster)) {
    return {
      threshold_met: false,
      valid_count: 0,
      threshold_m: roster.m,
      total_n: roster.n,
      valid_guardian_ids: [],
      invalid_guardian_ids: approvals.map((a) => a.guardian_id),
    };
  }

  const guardianMap = new Map(
    roster.guardians.map((g) => [g.guardian_id, g])
  );

  const seen = new Set<string>();
  const seenKeys = new Set<string>();
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

    // Fail-closed bind: the approval's self-declared target (cascade_id +
    // recovery_action) must match the input it is being verified against.
    // These envelope fields are not covered by the signature, so an approval
    // that declares a different target is rejected rather than counted.
    if (!approvalDeclaresSameTarget(approval, signing_input)) {
      invalidIds.push(approval.guardian_id);
      continue;
    }

    // Roster lookup.
    const guardian = guardianMap.get(approval.guardian_id);
    if (!guardian) {
      invalidIds.push(approval.guardian_id);
      continue;
    }

    // Fail-closed bind: a guardian public key must not be counted toward the
    // threshold more than once. verifyGuardianRoster already rejects a roster
    // that assigns one key to multiple guardian_ids, but this is defense in
    // depth for an evaluation run against a roster that skipped that check: one
    // key holder occupying multiple slots under distinct ids must not satisfy
    // M-of-N alone. The approval signature binds the signing input and the key,
    // not the guardian_id, so distinct-id + shared-key approvals all verify;
    // counting only the first per key preserves quorum independence. The
    // uniqueness key is the CANONICAL decoded form so a non-canonical spelling
    // of one roster key cannot be counted as a second, independent slot; a
    // malformed/non-canonical roster key fails closed (approval discarded).
    let canonicalKey: string;
    try {
      canonicalKey = canonicalGuardianKey(guardian.public_key);
    } catch {
      invalidIds.push(approval.guardian_id);
      continue;
    }
    if (seenKeys.has(canonicalKey)) {
      invalidIds.push(approval.guardian_id);
      continue;
    }
    seenKeys.add(canonicalKey);

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

  // Fail-closed bind (failure mode d, unconditional): the signing input the
  // quorum was produced against must describe the roster we are verifying
  // with. This holds even when the caller does not pass expected_roster_version,
  // so a quorum signed under an older roster cannot authorize against a newer
  // one. Surfaced as RosterStaleError for a precise operator signal.
  if (params.roster.version !== params.signing_input.roster_version) {
    throw new RosterStaleError({
      expected_version: params.roster.version,
      actual_version: params.signing_input.roster_version,
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

