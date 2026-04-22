/**
 * Sanctuary Fortress Modes -- Mode Transition Event
 *
 * Creates signed transition envelopes using the federation v0.1 SignedEvent shape.
 * Event type: fortress_mode_transition (in the fortress_* reserved namespace).
 * signature_scheme = "ed25519-v1" mandatory per crypto-agility spec SS5.3.
 */

import { packSignedEvent } from "../mesh/envelope.js";
import type { SignedEvent } from "../mesh/types.js";
import { FORTRESS_EVENT_TYPES } from "./constants.js";
import type { ModeTransitionPayload } from "./types.js";
import type { ModeTier } from "./constants.js";

// ---------------------------------------------------------------------------
// Pack params
// ---------------------------------------------------------------------------

export interface PackModeTransitionParams {
  from_tier: ModeTier;
  to_tier: ModeTier;
  fortress_id: string;
  reason: string;
  preconditions_checked: string[];
  emitter_node: string;
  emitter_principal: string;
  monotonic_seq: number;
  node_private_key: Uint8Array;
  principal_private_key?: Uint8Array;
  causal_parents?: string[];
}

// ---------------------------------------------------------------------------
// Pack
// ---------------------------------------------------------------------------

/**
 * Create a signed mode transition event.
 *
 * Uses packSignedEvent from the mesh envelope module, producing a
 * federation v0.1-compatible SignedEvent with:
 *   event_type = "fortress_mode_transition"
 *   signature_scheme = "ed25519-v1" (mandatory, set by packSignedEvent)
 *   payload = ModeTransitionPayload
 */
export function packModeTransitionEvent(
  params: PackModeTransitionParams
): SignedEvent<ModeTransitionPayload> {
  const now = new Date().toISOString();

  const payload: ModeTransitionPayload = {
    from_tier: params.from_tier,
    to_tier: params.to_tier,
    fortress_id: params.fortress_id,
    reason: params.reason,
    preconditions_checked: params.preconditions_checked,
    transitioned_at: now,
  };

  return packSignedEvent<ModeTransitionPayload>({
    event_type: FORTRESS_EVENT_TYPES.MODE_TRANSITION,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    causal_parents: params.causal_parents,
    payload,
    monotonic_seq: params.monotonic_seq,
    node_private_key: params.node_private_key,
    principal_private_key: params.principal_private_key,
  });
}
