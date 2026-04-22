/**
 * Sanctuary Operator Console v1.0 -- Signed Event Stream (SSE)
 *
 * SSE endpoint at /api/console/events streaming signed events to the
 * browser for live audit-log view. Reuses existing SSE pattern from
 * the dashboard.
 *
 * Events are tagged by their reserved namespace prefix
 * (policy_*, chat_*, mesh_*, recovery_*, fortress_*, attestation_*, identity_*).
 */

import type { ServerResponse } from "node:http";
import { SSE_KEEPALIVE_MS } from "./constants.js";
import type { ConsoleSSEEnvelope } from "./types.js";

export type SSEClient = ServerResponse;

export interface SignedEventStreamOptions {
  /** Keepalive interval in ms. Default SSE_KEEPALIVE_MS. */
  keepaliveMs?: number;
}

/**
 * Manages SSE client connections and broadcasts signed events.
 */
export class SignedEventStream {
  private clients = new Set<SSEClient>();
  private keepaliveMs: number;

  constructor(opts?: SignedEventStreamOptions) {
    this.keepaliveMs = opts?.keepaliveMs ?? SSE_KEEPALIVE_MS;
  }

  /**
   * Register a new SSE client. Sets headers, starts keepalive,
   * and returns a cleanup function.
   */
  addClient(res: SSEClient): () => void {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });

    this.clients.add(res);

    // Keepalive timer
    const keepAlive = setInterval(() => {
      try {
        res.write(": keepalive\n\n");
      } catch {
        /* socket gone */
      }
    }, this.keepaliveMs);

    const cleanup = () => {
      clearInterval(keepAlive);
      this.clients.delete(res);
    };

    res.on("close", cleanup);
    res.on("error", cleanup);

    return cleanup;
  }

  /**
   * Send an initial hydration payload to a newly connected client.
   */
  sendHydration(res: SSEClient, data: unknown): void {
    try {
      res.write(`event: hydrate\ndata: ${JSON.stringify(data)}\n\n`);
    } catch {
      /* socket gone */
    }
  }

  /**
   * Broadcast an SSE event to all connected clients.
   */
  broadcast(envelope: ConsoleSSEEnvelope): void {
    const payload = `data: ${JSON.stringify(envelope)}\n\n`;
    for (const client of this.clients) {
      try {
        client.write(payload);
      } catch {
        /* socket gone; cleanup fires via close event */
      }
    }
  }

  /**
   * Broadcast a named event (e.g., "audit_event", "header_update").
   */
  broadcastNamed(eventName: string, data: unknown): void {
    const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of this.clients) {
      try {
        client.write(payload);
      } catch {
        /* socket gone */
      }
    }
  }

  /**
   * Number of connected SSE clients.
   */
  get clientCount(): number {
    return this.clients.size;
  }

  /**
   * Close all SSE connections.
   */
  closeAll(): void {
    for (const client of this.clients) {
      try {
        client.end();
      } catch {
        /* ignore */
      }
    }
    this.clients.clear();
  }
}
