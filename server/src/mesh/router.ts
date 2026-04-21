/**
 * Sanctuary Federation Protocol v0.1 — Router
 *
 * v0.1 dispatcher: routes known event_types to registered handlers; silently drops
 * unknown / reserved-namespace event_types (forward-compat per §10.3).
 *
 * Verification happens BEFORE dispatch (see envelope.verifySignedEvent). The router
 * is not the trust boundary — it is the routing layer. Events that pass verification
 * but are of an unknown type are "we trust this came from a valid peer but we don't
 * know how to handle it" — the right action at v0.1 is to drop them with a log line,
 * not to error.
 *
 * This makes v0.1 forward-compatible: when v1.x emits a `cross_fortress_read_query`
 * and a v0.1 node happens to receive it, the v0.1 node (a) verifies the signature
 * succeeds or fails per the cross-operator isolation invariant (§10.5 — it will
 * normally fail because the stated fortress_id is foreign), (b) if it somehow
 * passes verification, drops at dispatch because the event_type is unknown. No
 * crash. No misrouting.
 */

import { isReservedEventType, isV01EventType } from "./constants.js";
import type { SignedEvent } from "./types.js";

export type V01Handler<Payload = unknown> = (
  evt: SignedEvent<Payload>
) => void | Promise<void>;

export class MeshRouter {
  private handlers = new Map<string, V01Handler>();
  /**
   * Counters for audit / operator-surface observability. Bumped for every dispatch
   * decision, readable via `stats()`. v0.1 enforces nothing on these; v1.x may
   * alarm on growth of `dropped_reserved` or `dropped_unknown`.
   */
  private counters = {
    dispatched: 0,
    dropped_reserved: 0,
    dropped_unknown: 0,
  };

  register<Payload>(eventType: string, handler: V01Handler<Payload>): void {
    if (!isV01EventType(eventType)) {
      throw new Error(
        `MeshRouter.register: ${eventType} is not a v0.1 event type`
      );
    }
    this.handlers.set(eventType, handler as V01Handler);
  }

  /** Route a verified event. Returns true if a handler was invoked, false if dropped. */
  dispatch(evt: SignedEvent): boolean {
    if (isReservedEventType(evt.event_type)) {
      this.counters.dropped_reserved++;
      return false;
    }
    const h = this.handlers.get(evt.event_type);
    if (!h) {
      this.counters.dropped_unknown++;
      return false;
    }
    void h(evt);
    this.counters.dispatched++;
    return true;
  }

  stats(): Readonly<typeof this.counters> {
    return { ...this.counters };
  }
}
