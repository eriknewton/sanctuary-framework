/**
 * Sanctuary Agent Contract v0.1 — Lifecycle Event Emission (§2.8).
 *
 * Agents transition through six states: launched → paused → checkpointed →
 * resumed → retired / revoked. Each transition emits a signed lifecycle
 * event on the mesh envelope under event_type `agent_lifecycle_event`.
 *
 * Transition rules enforced here:
 * - uninstantiated → launched: the only inbound transition. Repeating it
 *   for a bound agent throws LifecycleTransitionError.
 * - launched → paused | checkpointed | retired | revoked.
 * - paused → resumed | retired | revoked.
 * - checkpointed → resumed | retired | revoked. Resumed REQUIRES
 *   checkpoint_hash; other transitions accept it optionally.
 * - resumed → paused | checkpointed | retired | revoked.
 * - retired / revoked are terminal. Any further transition throws.
 *
 * `revoked` is guardian-initiated (§2.8, Walkthrough Key 13). The caller
 * MUST provide a guardian_quorum; absent quorum is a transition error.
 *
 * The audit-log seal on `retired` is NOT implemented here — it is a
 * downstream consumer concern (the audit log subsystem watches for the
 * event). This module only emits.
 */

import {
  packSignedEvent,
  verifySignedEvent,
  type VerifyContext,
} from "../mesh/envelope.js";
import type { SignedEvent } from "../mesh/types.js";
import {
  AGENT_CONTRACT_VERSION,
  LIFECYCLE_STATES,
  SIGNATURE_SCHEME_V1,
  type AgentContractEventType,
  type LifecycleState,
} from "./constants.js";
import { LifecycleTransitionError } from "./errors.js";
import { validateLifecycleEvent } from "./schema.js";
import type { LifecycleEvent } from "./types.js";

export const AGENT_LIFECYCLE_EVENT_TYPE: AgentContractEventType =
  "agent_lifecycle_event";

type FromState = LifecycleState | "uninstantiated";

/**
 * Allowed transitions map. Any `from` not in keys is rejected. Any `to` not
 * in `allowed[from]` is rejected.
 */
const ALLOWED_TRANSITIONS: Record<FromState, readonly LifecycleState[]> = {
  uninstantiated: ["launched"],
  launched: ["paused", "checkpointed", "retired", "revoked"],
  paused: ["resumed", "retired", "revoked"],
  checkpointed: ["resumed", "retired", "revoked"],
  resumed: ["paused", "checkpointed", "retired", "revoked"],
  retired: [],
  revoked: [],
};

/** Terminal states — no outbound transitions permitted. */
export const TERMINAL_LIFECYCLE_STATES: readonly LifecycleState[] = [
  "retired",
  "revoked",
];

/** Return the set of transitions legal from `from`. */
export function allowedTransitions(from: FromState): readonly LifecycleState[] {
  return ALLOWED_TRANSITIONS[from] ?? [];
}

export interface EmitLifecycleParams {
  agent_id: string;
  fortress_id: string;
  from_state: FromState;
  to_state: LifecycleState;
  reason: string;
  /** Required on `resumed`; optional on `checkpointed`, `retired`, `revoked`. */
  checkpoint_hash?: string;
  /** Required on `revoked`. */
  guardian_quorum?: Array<{ guardian_pubkey: string; signature: string }>;
  emitter_node: string;
  emitter_principal: string;
  node_private_key: Uint8Array;
  principal_private_key?: Uint8Array;
  monotonic_seq: number;
  emitted_at?: string;
}

/**
 * Validate the transition is legal, build the event, pack it into a mesh
 * envelope, return both.
 */
export function emitLifecycleEvent(
  params: EmitLifecycleParams
): { signed_event: SignedEvent<LifecycleEvent>; event: LifecycleEvent } {
  if (!(LIFECYCLE_STATES as readonly string[]).includes(params.to_state)) {
    throw new LifecycleTransitionError(
      params.agent_id,
      params.from_state,
      params.to_state
    );
  }
  const legal = ALLOWED_TRANSITIONS[params.from_state] ?? [];
  if (!legal.includes(params.to_state)) {
    throw new LifecycleTransitionError(
      params.agent_id,
      params.from_state,
      params.to_state
    );
  }
  if (params.to_state === "resumed" && !params.checkpoint_hash) {
    throw new LifecycleTransitionError(
      params.agent_id,
      params.from_state,
      `${params.to_state} (checkpoint_hash required)`
    );
  }
  if (params.to_state === "revoked") {
    if (!params.guardian_quorum || params.guardian_quorum.length === 0) {
      throw new LifecycleTransitionError(
        params.agent_id,
        params.from_state,
        `${params.to_state} (guardian_quorum required — revocation is guardian-initiated per Walkthrough Key 13)`
      );
    }
  }
  const emitted_at = params.emitted_at ?? new Date().toISOString();
  const event: LifecycleEvent = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
    from_state: params.from_state,
    to_state: params.to_state,
    reason: params.reason,
    emitted_at,
    ...(params.checkpoint_hash ? { checkpoint_hash: params.checkpoint_hash } : {}),
    ...(params.guardian_quorum ? { guardian_quorum: params.guardian_quorum } : {}),
  };
  validateLifecycleEvent(event);
  const signed_event = packSignedEvent<LifecycleEvent>({
    event_type: AGENT_LIFECYCLE_EVENT_TYPE,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    payload: event,
    monotonic_seq: params.monotonic_seq,
    node_private_key: params.node_private_key,
    principal_private_key: params.principal_private_key,
  });
  return { signed_event, event };
}

/** Verify a lifecycle event envelope + body. Mirror of verifyAgentCard. */
export function verifyLifecycleEvent(
  evt: SignedEvent<unknown>,
  ctx: VerifyContext
): { event: LifecycleEvent; signed_event: SignedEvent<LifecycleEvent> } {
  if (evt.event_type !== AGENT_LIFECYCLE_EVENT_TYPE) {
    throw new LifecycleTransitionError(
      "<unknown>",
      "<unknown>",
      `wrong event_type "${evt.event_type}"`
    );
  }
  const verifyResult = verifySignedEvent(evt as SignedEvent, ctx);
  const event = validateLifecycleEvent(verifyResult.event.payload);
  if (event.fortress_id !== verifyResult.event.fortress_id) {
    throw new LifecycleTransitionError(
      event.agent_id,
      event.from_state,
      "fortress_id mismatch between envelope and payload"
    );
  }
  return {
    event,
    signed_event: verifyResult.event as SignedEvent<LifecycleEvent>,
  };
}
