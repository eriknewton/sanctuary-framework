/**
 * DMswitch trigger broadcast + receiver path.
 *
 * Spec §9.2: when the DMswitch fires (operator absence beyond threshold), the
 * canonical audit node generates a `dmswitch_triggered` audit event and
 * broadcasts it. Every node receives, surfaces it locally, and unlocks the
 * guardian-revocation path (§3.6.1).
 *
 * `dmswitch_triggered` is in V01_EVENT_TYPES (mesh/constants.ts) so the
 * envelope packer accepts it as a v0.1 event.
 *
 * v1.0 ships defaults only (90-day absence + 30-day grace). Multi-condition
 * trigger grammar is a v1.x research ticket.
 */

import { packSignedEvent } from "../envelope.js";
import type { CounterStore } from "../lifecycle/types.js";
import type { SignedEvent } from "../types.js";
import {
  DEFAULT_DMSWITCH_ABSENCE_MS,
  DEFAULT_DMSWITCH_GRACE_MS,
} from "../guardian/constants.js";

/**
 * Wire-form dmswitch payload. Embedded in a v0.1 SignedEvent envelope on the
 * broadcast pubsub topic.
 */
export interface DmswitchTriggeredPayload {
  /** ISO8601 — last operator activity observed. */
  last_operator_activity_at: string;
  /** ISO8601 — when the DMswitch fired. */
  triggered_at: string;
  /** absence + grace thresholds in effect at trigger. */
  absence_ms: number;
  grace_ms: number;
  /** Free-form reason — operator-set on manual trigger; "automatic" otherwise. */
  reason: string;
}

/**
 * Decide whether the DMswitch should fire given the operator's last
 * observed activity and the configured thresholds.
 *
 * Pure function — caller (the canonical audit node) ticks this and emits on
 * `true`. Idempotent: caller MUST track whether it has already emitted to
 * avoid spamming.
 */
export function shouldTriggerDmswitch(params: {
  last_operator_activity_at: number;
  now_ms: number;
  absence_ms?: number;
  grace_ms?: number;
}): boolean {
  const absence = params.absence_ms ?? DEFAULT_DMSWITCH_ABSENCE_MS;
  const grace = params.grace_ms ?? DEFAULT_DMSWITCH_GRACE_MS;
  return params.now_ms - params.last_operator_activity_at >= absence + grace;
}

/**
 * Build a signed `dmswitch_triggered` envelope ready for broadcast.
 *
 * Caller (the canonical audit node) calls this once when `shouldTriggerDmswitch`
 * crosses the threshold, broadcasts via the mesh transport, and persists the
 * event so it can be replayed to nodes that come online subsequently.
 */
export function packDmswitchTriggeredEvent(params: {
  emitter_node: string;
  emitter_principal: string;
  fortress_id: string;
  last_operator_activity_at: string;
  triggered_at: string;
  reason: string;
  absence_ms?: number;
  grace_ms?: number;
  node_private_key: Uint8Array;
  counters: CounterStore;
}): SignedEvent<DmswitchTriggeredPayload> {
  const payload: DmswitchTriggeredPayload = {
    last_operator_activity_at: params.last_operator_activity_at,
    triggered_at: params.triggered_at,
    absence_ms: params.absence_ms ?? DEFAULT_DMSWITCH_ABSENCE_MS,
    grace_ms: params.grace_ms ?? DEFAULT_DMSWITCH_GRACE_MS,
    reason: params.reason,
  };
  return packSignedEvent<DmswitchTriggeredPayload>({
    event_type: "dmswitch_triggered",
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    payload,
    monotonic_seq: params.counters.next("envelope_monotonic_seq"),
    node_private_key: params.node_private_key,
  });
}
