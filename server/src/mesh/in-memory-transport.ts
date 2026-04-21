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
 * plus any unknown-extension-keys (forward-compat log). On unknown event_type,
 * the event is dropped silently — caller sees `dispatched: false`.
 */
export function receiveBroadcast(
  evt: SignedEvent,
  ctx: VerifyContext,
  dispatcher: (evt: SignedEvent) => boolean
): {
  verified: boolean;
  dispatched: boolean;
  unknown_extension_keys: string[];
  drop_reason?: string;
} {
  const res = verifySignedEvent(evt, ctx);
  const dispatched = dispatcher(res.event);
  return {
    verified: true,
    dispatched,
    unknown_extension_keys: res.unknown_extension_keys,
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
