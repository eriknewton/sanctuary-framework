/**
 * Sanctuary Fortress Modes -- State Machine
 *
 * Transition logic, guards, and legal-path enforcement.
 * All transitions are pure-logic; no LLM, no network at the gate.
 *
 * Legal paths:
 *   1->2  (join federation)
 *   2->1  (leave federation)
 *   2->3  (register external adapter)
 *   3->2  (deregister all external adapters)
 *   3->1  (full withdrawal)
 *   1->3  ILLEGAL (must pass through 2)
 */

import type { ModeTier } from "./constants.js";
import { LEGAL_TRANSITIONS, isModeTier } from "./constants.js";
import type {
  TransitionPrecondition,
  PreconditionContext,
  PreconditionResult,
} from "./types.js";
import {
  IllegalTransitionError,
  AlreadyInTierError,
  InvalidTierError,
} from "./errors.js";

// ---------------------------------------------------------------------------
// Transition validation (pure logic, no side effects)
// ---------------------------------------------------------------------------

/**
 * Validate that a transition from one tier to another is legal.
 * Throws on any illegal transition.
 */
export function validateTransition(from: ModeTier, to: ModeTier): void {
  if (!isModeTier(from)) {
    throw new InvalidTierError(from);
  }
  if (!isModeTier(to)) {
    throw new InvalidTierError(to);
  }
  if (from === to) {
    throw new AlreadyInTierError(from);
  }
  if (!LEGAL_TRANSITIONS[from].has(to)) {
    throw new IllegalTransitionError(from, to);
  }
}

/**
 * Check whether a transition is legal without throwing.
 */
export function isLegalTransition(from: ModeTier, to: ModeTier): boolean {
  if (!isModeTier(from) || !isModeTier(to)) return false;
  if (from === to) return false;
  return LEGAL_TRANSITIONS[from].has(to);
}

/**
 * Get all legal target tiers from the given tier.
 */
export function getLegalTargets(from: ModeTier): ModeTier[] {
  return Array.from(LEGAL_TRANSITIONS[from]);
}

// ---------------------------------------------------------------------------
// Precondition definitions
// ---------------------------------------------------------------------------

/**
 * Tier 2 entry: the fortress must have a valid node identity certificate
 * and at least one reachable bootstrap peer.
 */
const PRECONDITION_FEDERATION_JOIN: TransitionPrecondition = {
  id: "federation_join",
  description: "Valid node identity certificate and at least one reachable bootstrap peer",
  check: async (ctx: PreconditionContext): Promise<PreconditionResult> => {
    if (!ctx.has_node_identity_cert) {
      return {
        passed: false,
        reason: "No valid node identity certificate found for this fortress",
      };
    }
    if (!ctx.has_reachable_peer) {
      return {
        passed: false,
        reason: "No reachable bootstrap peer found",
      };
    }
    return { passed: true, reason: "Federation join preconditions met" };
  },
};

/**
 * Tier 3 entry: at least one external-protocol adapter must be registered.
 * At v1.0 a stub adapter satisfies this precondition.
 */
const PRECONDITION_EXTERNAL_ADAPTER: TransitionPrecondition = {
  id: "external_adapter_registered",
  description: "At least one external-protocol adapter is registered (stub accepted at v1.0)",
  check: async (ctx: PreconditionContext): Promise<PreconditionResult> => {
    if (ctx.registered_adapter_count < 1) {
      return {
        passed: false,
        reason: "No external-protocol adapter registered. Register at least one adapter (stub accepted at v1.0).",
      };
    }
    return { passed: true, reason: "External adapter precondition met" };
  },
};

// ---------------------------------------------------------------------------
// Precondition registry
// ---------------------------------------------------------------------------

/**
 * Map of (from, to) -> preconditions to check.
 * Transitions not in this map have no preconditions (always allowed
 * if the transition is legal).
 */
const TRANSITION_PRECONDITIONS: Map<
  string,
  TransitionPrecondition[]
> = new Map([
  // 1 -> 2: requires federation join
  [
    transitionKey("tier_1_private", "tier_2_federated"),
    [PRECONDITION_FEDERATION_JOIN],
  ],
  // 2 -> 3: requires external adapter
  [
    transitionKey("tier_2_federated", "tier_3_interop"),
    [PRECONDITION_EXTERNAL_ADAPTER],
  ],
]);

function transitionKey(from: ModeTier, to: ModeTier): string {
  return `${from}->${to}`;
}

/**
 * Get preconditions for a specific transition. Returns empty array
 * if no preconditions are defined (e.g., downgrades).
 */
export function getPreconditions(
  from: ModeTier,
  to: ModeTier
): TransitionPrecondition[] {
  return TRANSITION_PRECONDITIONS.get(transitionKey(from, to)) ?? [];
}

/**
 * Run all preconditions for a transition and return failures.
 * Returns an empty array if all preconditions pass.
 */
export async function checkPreconditions(
  ctx: PreconditionContext
): Promise<Array<{ id: string; reason: string }>> {
  const preconditions = getPreconditions(ctx.current_tier, ctx.target_tier);
  const failures: Array<{ id: string; reason: string }> = [];

  for (const precondition of preconditions) {
    const result = await precondition.check(ctx);
    if (!result.passed) {
      failures.push({ id: precondition.id, reason: result.reason });
    }
  }

  return failures;
}
