/**
 * Sanctuary Handshake -- Subscriber pre-handshake registration gate.
 *
 * Every cross-identity subscriber registration (policy engine `subscribe`
 * grants, federation event subscriptions, etc.) must pass through this
 * gate. The gate consults the sovereignty handshake results and refuses
 * registration for any peer whose handshake has not completed or has
 * expired.
 *
 * Behavior contract:
 *   - verified_sovereign: permitted, tagged on subscription record.
 *   - verified_degraded: permitted, tagged on subscription record.
 *   - unverified / not_started / in_progress / failed / expired: refused.
 *   - self (local Sanctuary instance): always permitted.
 *
 * Denial messages are generic per policy-non-leakage discipline.
 */

import type { HandshakeResult, TrustTier } from "./types.js";

/**
 * The state a subscriber's handshake is observed to be in. Maps from the
 * codebase's HandshakeResult (or absence thereof) to the spawn prompt's
 * state taxonomy.
 */
export type SubscriberHandshakeState =
  | "not_started"
  | "in_progress"
  | "failed"
  | "expired"
  | "verified_sovereign"
  | "verified_degraded";

/**
 * Gate decision for a subscriber registration attempt.
 */
export interface SubscriberGateResult {
  permitted: boolean;
  state: SubscriberHandshakeState;
  trust_tier?: TrustTier;
  /** True when the caller is the local Sanctuary instance. */
  is_self: boolean;
}

/** Generic denial message. Does not leak which state caused the refusal. */
export const SUBSCRIBER_DENIED_MESSAGE =
  "subscriber registration denied: operation not permitted";

/**
 * Lookup function type for dependency injection into the slot gate
 * evaluator. Avoids coupling the policy engine to the handshake module
 * at the import level.
 */
export type HandshakeStateLookup = (
  counterpartyId: string
) => HandshakeResult | undefined;

/**
 * Check whether a counterparty is permitted to register as a subscriber.
 *
 * @param counterpartyId  The identity of the subscribing peer.
 * @param selfId          The local Sanctuary instance's identity.
 * @param lookup          Function that retrieves the HandshakeResult for a
 *                        given counterparty ID, or undefined if none exists.
 */
export function checkSubscriberHandshakeState(
  counterpartyId: string,
  selfId: string,
  lookup: HandshakeStateLookup
): SubscriberGateResult {
  // Self-subscriptions are always permitted.
  if (counterpartyId === selfId) {
    return { permitted: true, state: "verified_sovereign", is_self: true };
  }

  const result = lookup(counterpartyId);

  // No handshake result: not started, in progress, or failed.
  if (!result) {
    return { permitted: false, state: "not_started", is_self: false };
  }

  // Handshake completed but not verified.
  if (!result.verified) {
    return {
      permitted: false,
      state: "failed",
      trust_tier: result.trust_tier,
      is_self: false,
    };
  }

  // Check expiry.
  if (new Date(result.expires_at) <= new Date()) {
    return {
      permitted: false,
      state: "expired",
      trust_tier: result.trust_tier,
      is_self: false,
    };
  }

  // Map trust tier to subscriber state.
  switch (result.trust_tier) {
    case "verified-sovereign":
      return {
        permitted: true,
        state: "verified_sovereign",
        trust_tier: "verified-sovereign",
        is_self: false,
      };
    case "verified-degraded":
      return {
        permitted: true,
        state: "verified_degraded",
        trust_tier: "verified-degraded",
        is_self: false,
      };
    case "unverified":
    default:
      return {
        permitted: false,
        state: "failed",
        trust_tier: result.trust_tier,
        is_self: false,
      };
  }
}

/**
 * Critical audit entry details for a denied subscriber registration.
 * The caller is responsible for writing this to the audit log via
 * `auditLog.appendCritical(...)`.
 */
export interface SubscriberDeniedAuditDetails {
  attempting_peer_identity: string;
  subscriber_surface: string;
  handshake_state_observed: SubscriberHandshakeState;
  timestamp: string;
}

/**
 * Build the audit details for a denied subscriber registration.
 */
export function buildDeniedAuditDetails(
  counterpartyId: string,
  subscriberSurface: string,
  gateResult: SubscriberGateResult
): SubscriberDeniedAuditDetails {
  return {
    attempting_peer_identity: counterpartyId,
    subscriber_surface: subscriberSurface,
    handshake_state_observed: gateResult.state,
    timestamp: new Date().toISOString(),
  };
}
