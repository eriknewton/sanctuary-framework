/**
 * Agent-visible deny/approval-required vocabulary.
 *
 * These are the ONLY strings an agent should ever see on a deny or
 * approval-required path. Rich details (tier, slot, operation, policy_match)
 * flow exclusively to the encrypted audit log.
 *
 * Rationale: a compromised agent can fingerprint the operator's policy by
 * submitting probe operations and observing which return-strings reveal
 * structure. Generic vocabulary closes that side-channel (full-sweep #48).
 */

export const AGENT_VISIBLE_DENY_REASONS = {
  REQUIRES_APPROVAL: "operation requires operator approval",
  NOT_PERMITTED: "operation not permitted",
  REQUIRES_OPERATOR: "operation requires operator action",
} as const;

export type AgentVisibleDenyReason =
  typeof AGENT_VISIBLE_DENY_REASONS[keyof typeof AGENT_VISIBLE_DENY_REASONS];
