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

/**
 * A registered handler for one v0.1 event type.
 *
 * MAY BE ASYNC, AND THAT IS THE WHOLE REASON THE CONTAINMENT BELOW EXISTS.
 * This signature admits `Promise<void>`, so a handler can fail in two
 * structurally different ways — a synchronous `throw`, and a rejected promise
 * the caller never sees — and a guard that catches only the first is scoped to
 * whichever handlers happen to be synchronous on the day it was written.
 * Adding the single word `async` to a registered handler is typecheck-clean
 * and would silently move it from the guarded shape to the unguarded one.
 *
 * CROSS-FILE PIN: must match the containment note at `dispatch` below, and the
 * one at `MeshNode.handleIncomingBroadcast`'s `router.dispatch` call in
 * `lifecycle/mesh-node.ts`. All three describe one invariant: NO handler fault
 * of EITHER shape reaches the `void` the transport subscription invokes the
 * receive path with. Change one, change all three.
 */
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
    // COUNTED BEFORE INVOCATION, DELIBERATELY. These three counters record the
    // ROUTING DECISION this method made — reserved, unknown, or handed to a
    // handler — not whether the handler then succeeded. Incrementing after the
    // call made the number mean "dispatched AND returned synchronously without
    // throwing", which is a fourth thing nobody asked for and which an async
    // handler cannot report anyway: its outcome is not known when this method
    // returns. So the sync and async shapes now agree, and a contained fault
    // does not silently vanish from the routing counters. `stats()` is
    // observability, never a trust input; no accept/deny decision reads it.
    this.counters.dispatched++;
    // CONTAINMENT (must match the note on `V01Handler` above, and the one at
    // `MeshNode.handleIncomingBroadcast`'s call site). A SYNC throw from
    // `h(evt)` happens before this line's `Promise.resolve` and propagates out
    // of `dispatch` unchanged — that is deliberate, the caller contains it and
    // this method must not start swallowing what the caller already handles.
    // An ASYNC rejection has no such caller: the receive path has already
    // returned by the time it settles, so nothing is left to catch it and
    // Node's default for an unhandled rejection is to terminate the process.
    // Attaching the handler here is what makes the guarantee hold for BOTH
    // shapes rather than for whichever handlers are synchronous today.
    //
    // The `.catch` is a no-op with the same rationale as the sync side: the
    // envelope was verified and the receive recorded before dispatch, so a
    // contained fault loses that handler's own delivery and nothing else, and
    // there is no surface left to escalate to — the operator surfaces ARE the
    // hooks a handler reaches.
    void Promise.resolve(h(evt)).catch(() => {});
    return true;
  }

  stats(): Readonly<typeof this.counters> {
    return { ...this.counters };
  }
}
