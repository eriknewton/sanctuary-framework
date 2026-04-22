/**
 * Sanctuary Policy Engine — Sentinel-role enforcement.
 *
 * Walkthrough Key 11 LOCKED: "Sentinels are inward-facing only — narrower
 * attack surface than ordinary agents. ... no external network access, no
 * outbound tool-calling to third-party APIs, no credential-broker access
 * beyond their own identity key."
 *
 * This module is a READ-ONLY consumer of the is_sentinel flag compiled into
 * the policy. Authoring / management of the sentinel role is scope for a
 * separate surface (the policy authoring console). What we enforce here:
 *
 *   - Sentinel may not access any slot on any counterparty other than itself
 *     (inward-facing only). Any outbound grant attempt is denied with
 *     reason_code = sentinel_inward_restriction.
 *
 *   - Sentinel may not carry any concordia_commitment_classes capability
 *     (sentinels are passive observers at v1.0; commitments are for
 *     contract-bearing agents).
 *
 * The restriction is applied BEFORE slot-rule evaluation, so even an
 * operator who mistakenly granted a sentinel some outbound capability cannot
 * punch through. Defense-in-depth.
 */

import { GATE_REASON_CODES } from "./constants.js";
import type { CompiledPolicy } from "./types.js";

export interface SentinelCheckResult {
  allowed: boolean;
  reason_code?: string;
  explanation?: string;
}

/**
 * Decide whether a sentinel-flagged agent may access the given counterparty.
 *
 * Return `allowed: true` if the policy does not carry the sentinel flag.
 * Return `allowed: true` if the access is self-targeted (sentinel reading
 * its own state; e.g. audit log reads). Otherwise deny.
 */
export function checkSentinelRestriction(
  policy: CompiledPolicy,
  counterparty: string
): SentinelCheckResult {
  if (!policy.capabilities.is_sentinel) {
    return { allowed: true };
  }
  if (counterparty === policy.agent_id) {
    return { allowed: true };
  }
  return {
    allowed: false,
    reason_code: GATE_REASON_CODES.SENTINEL_INWARD_RESTRICTION,
    explanation: `sentinel agents are inward-facing only; access to ${counterparty} is not permitted`,
  };
}

/**
 * Structural check: a sentinel-flagged compiled policy MUST NOT declare
 * any commitment classes. Run at envelope-receive time so operators see an
 * authoring error early rather than at runtime.
 */
export function sentinelPolicyIsValid(policy: CompiledPolicy): {
  valid: boolean;
  reason?: string;
} {
  if (!policy.capabilities.is_sentinel) return { valid: true };
  if (policy.capabilities.concordia_commitment_classes.length > 0) {
    return {
      valid: false,
      reason:
        "sentinel-flagged policy declares concordia_commitment_classes; sentinels are passive observers at v1.0",
    };
  }
  return { valid: true };
}
