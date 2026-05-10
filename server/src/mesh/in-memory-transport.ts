/**
 * Sanctuary Federation Protocol v0.1 — In-Memory Transport
 *
 * Real-shape transport for tests. No libp2p, no network — a straight in-process
 * fan-out that exercises:
 *   packSignedEvent → canonical-JSON → signature → canonical bytes on the wire →
 *   signature verify → cert-chain walk → ignore-unknown-extension-keys → dispatch.
 *
 * The libp2p adapter is a separate module (deferred; see handoff). Both
 * transports implement the same MeshTransport interface, so tests that work here
 * are contract-level tests that will hold for the libp2p transport too.
 *
 * Real-shape requirement (CLAUDE.md commit-discipline + v0.10.4→v0.10.6 lesson):
 * this transport serializes to bytes, transmits bytes, deserializes on the other
 * side, and runs signature verification end-to-end. It does NOT bypass crypto
 * or mock the route table. A signature that fails here fails identically over
 * libp2p.
 */

import type { AuditBatch, SignedEvent } from "./types.js";
import { verifyAuditBatch, type VerifyBatchContext } from "./audit-batch.js";
import { verifySignedEvent, type VerifyContext } from "./envelope.js";

export type MessageSerialized = string;

export interface MeshTransport {
  broadcast(evt: SignedEvent): Promise<void>;
  unicast(toNodeId: string, message: MessageSerialized): Promise<void>;
  subscribe(handler: EventHandler): () => void;
  subscribeUnicast(handler: UnicastHandler): () => void;
}

export type EventHandler = (evt: SignedEvent, wireBytes: string) => void;
export type UnicastHandler = (toNodeId: string, message: string) => void;

/**
 * In-memory fan-out: each attached peer sees every broadcast; unicast delivers to
 * exactly the addressed peer. Messages are serialized to JSON strings to ensure
 * the receive path parses canonical wire bytes, not shared object references.
 *
 * Handler ordering guarantees (full-sweep #94)
 * --------------------------------------------
 * Tests sometimes need to reason about the relative order in which two
 * subscribed handlers on the same peer observe a single broadcast, or about
 * the relative order in which two attached peers observe the same broadcast.
 * The dispatch loop below makes the following guarantees explicit so callers
 * do not have to read the implementation to know what is contract and what
 * is incidental:
 *
 *   1. **Per-peer handler order = subscription order.** `subscribe` appends
 *      to a `Set`; iteration over a JavaScript `Set` is insertion-ordered
 *      (ECMAScript spec). For a given broadcast, the first-subscribed handler
 *      on a given peer runs strictly before the second-subscribed handler on
 *      that same peer. Tests may rely on this.
 *   2. **Cross-peer handler order = attach order.** `attach` populates an
 *      internal `Map`; iteration over a JavaScript `Map` is also
 *      insertion-ordered. The first peer attached observes a broadcast
 *      before the second peer attached observes the same broadcast. Tests
 *      may rely on this.
 *   3. **Self-suppression is unconditional.** A peer never receives its own
 *      broadcast, regardless of subscription order. The `if (peer.nodeId
 *      === nodeId) continue` guard fires before any handler is invoked.
 *   4. **Handler invocation is synchronous within `broadcast()`.** Although
 *      `broadcast` is `async`, the dispatch loop awaits nothing internally;
 *      every handler runs to completion before the returned promise
 *      resolves. A handler that throws synchronously will surface that
 *      error from the `broadcast()` call site.
 *   5. **Each handler sees a freshly-parsed event object.** The transport
 *      `JSON.parse`s the wire string per delivery, so two handlers on
 *      different peers observe distinct object references for the same
 *      logical event. Mutations made by one handler are not visible to
 *      another.
 *   6. **Unsubscribe takes effect on the next broadcast, not mid-broadcast.**
 *      Calling the unsubscribe function returned by `subscribe` removes the
 *      handler from the `Set` immediately, but the in-flight `broadcast()`
 *      call has already snapshotted the iteration target by virtue of
 *      synchronous iteration. A handler MAY observe one final delivery if
 *      it unsubscribes itself during dispatch.
 *
 * These guarantees are contract for the in-memory transport. The libp2p
 * adapter does NOT preserve cross-peer attach-order (network delivery is
 * best-effort and concurrent), so cross-peer tests that depend on (2) will
 * not port verbatim. Per-peer subscription-order (1) does carry over.
 */
export class InMemoryTransport {
  private peers = new Map<string, PeerEndpoint>();

  /** Attach a peer, get back its local transport handle. */
  attach(nodeId: string): MeshTransport {
    const endpoint: PeerEndpoint = {
      nodeId,
      broadcastHandlers: new Set(),
      unicastHandlers: new Set(),
    };
    this.peers.set(nodeId, endpoint);
    const transport: MeshTransport = {
      broadcast: async (evt: SignedEvent) => {
        const wire = JSON.stringify(evt);
        for (const peer of this.peers.values()) {
          if (peer.nodeId === nodeId) continue; // don't deliver to self
          for (const h of peer.broadcastHandlers) {
            const parsed = JSON.parse(wire) as SignedEvent;
            h(parsed, wire);
          }
        }
      },
      unicast: async (toNodeId: string, message: MessageSerialized) => {
        const peer = this.peers.get(toNodeId);
        if (!peer) {
          throw new Error(
            `InMemoryTransport: unknown unicast target ${toNodeId}`
          );
        }
        for (const h of peer.unicastHandlers) {
          h(toNodeId, message);
        }
      },
      subscribe: (h) => {
        endpoint.broadcastHandlers.add(h);
        return () => endpoint.broadcastHandlers.delete(h);
      },
      subscribeUnicast: (h) => {
        endpoint.unicastHandlers.add(h);
        return () => endpoint.unicastHandlers.delete(h);
      },
    };
    return transport;
  }

  detach(nodeId: string): void {
    this.peers.delete(nodeId);
  }

  nodeCount(): number {
    return this.peers.size;
  }
}

interface PeerEndpoint {
  nodeId: string;
  broadcastHandlers: Set<EventHandler>;
  unicastHandlers: Set<UnicastHandler>;
}

// ═══════════════════════════════════════════════════════════════════════
// Convenience: verify-and-route helpers
// ═══════════════════════════════════════════════════════════════════════

/**
 * Receive and verify a broadcast event. On success, returns the verified event
 * plus any reserved-extension-keys observed (forward-compat log). On unknown
 * event_type, the event is dropped silently and the caller sees `dispatched: false`.
 */
export function receiveBroadcast(
  evt: SignedEvent,
  ctx: VerifyContext,
  dispatcher: (evt: SignedEvent) => boolean
): {
  verified: boolean;
  dispatched: boolean;
  recognized_reserved_extension_keys: string[];
  drop_reason?: string;
} {
  const res = verifySignedEvent(evt, ctx);
  const dispatched = dispatcher(res.event);
  return {
    verified: true,
    dispatched,
    recognized_reserved_extension_keys: res.recognized_reserved_extension_keys,
    drop_reason: dispatched ? undefined : "unknown_or_reserved_event_type",
  };
}

/**
 * Receive and verify an audit batch (unicast, canonical audit node side).
 * See spec §5.2 — verifier chains rollback-detection + hkdf-proof + per-entry sigs.
 */
export function receiveAuditBatch(
  batch: AuditBatch,
  ctx: VerifyBatchContext
): void {
  verifyAuditBatch(batch, ctx);
}
