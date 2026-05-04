/**
 * Egress-decision domain types.
 *
 * The filter daemon evaluates each outbound flow against the loaded ruleset
 * and produces an EgressDecision. The decision is a tagged union; subsequent
 * PRs implement the evaluator. PR 4 wires the prompt-required path into the
 * dashboard surface; PR 5 wires the audit emission.
 *
 * Source: Castle Wall Phase 1 Scope Lock 2026-05-03 section 6.
 */

import type { LearnedGranularity } from "../ipc/messages.js";

/** Reason an outbound flow was blocked. */
export type BlockReason =
  | "no_matching_rule"
  | "explicit_deny_rule"
  | "operator_denied_now"
  | "operator_denied_historically"
  | "policy_validation_failed"
  | "filter_in_no_wall_mode_but_explicit_deny"
  | "prompt_flood_blocked"
  | "queue_saturated";

/** Tagged union of decisions the daemon can return for a single outbound flow. */
export type EgressDecision =
  | { kind: "allow"; rule_id: string }
  | { kind: "block"; reason: BlockReason }
  | { kind: "prompt"; request_id: string };

/**
 * Persistent record of an operator's "always" choice. Subsequent flows that
 * match the granularity key are auto-decided without re-prompting until the
 * record is removed via dashboard.
 */
export interface LearnedDecision {
  granularity: LearnedGranularity;
  template: string;
  agent_id?: string;
  domain_or_etld1: string;
  decision: "allow" | "deny";
  learned_at: string;
  last_applied_at: string;
}

/** Helper exhaustiveness check usable by the evaluator implementations in later PRs. */
export function decisionIsTerminal(decision: EgressDecision): decision is
  | { kind: "allow"; rule_id: string }
  | { kind: "block"; reason: BlockReason } {
  return decision.kind === "allow" || decision.kind === "block";
}
