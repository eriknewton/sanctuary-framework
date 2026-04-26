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
  /**
   * Number of consecutive failed keepalive writes before the reaper
   * forcibly closes a client. Default 3 (so a partitioned client is
   * cleaned up after 3 × keepaliveMs of write failures rather than
   * lingering forever if the underlying socket never fires `close`).
   */
  maxMissedKeepalives?: number;
}

interface ClientState {
  keepaliveTimer: ReturnType<typeof setInterval>;
  cleanup: () => void;
  missedKeepalives: number;
}

/**
 * Manages SSE client connections and broadcasts signed events.
 */
export class SignedEventStream {
  private clients = new Map<SSEClient, ClientState>();
  private keepaliveMs: number;
  private maxMissedKeepalives: number;

  constructor(opts?: SignedEventStreamOptions) {
    this.keepaliveMs = opts?.keepaliveMs ?? SSE_KEEPALIVE_MS;
    this.maxMissedKeepalives = opts?.maxMissedKeepalives ?? 3;
  }

  /**
   * Register a new SSE client. Sets headers, starts keepalive,
   * and returns a cleanup function.
   *
   * The keepalive timer doubles as a heartbeat reaper: if write() throws
   * for `maxMissedKeepalives` consecutive intervals, the client is
   * forcibly closed even if its underlying socket never emitted "close"
   * (some proxy / NAT scenarios silently drop connections).
   */
  addClient(res: SSEClient): () => void {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });

    const cleanup = () => {
      const state = this.clients.get(res);
      if (state) {
        clearInterval(state.keepaliveTimer);
        this.clients.delete(res);
      }
    };

    const keepaliveTimer = setInterval(() => {
      const state = this.clients.get(res);
      if (!state) return;
      try {
        res.write(": keepalive\n\n");
        state.missedKeepalives = 0;
      } catch {
        state.missedKeepalives += 1;
        if (state.missedKeepalives >= this.maxMissedKeepalives) {
          // Reap a stuck client whose socket never fired "close"
          try {
            res.end();
          } catch {
            /* ignore */
          }
          cleanup();
        }
      }
    }, this.keepaliveMs);

    this.clients.set(res, { keepaliveTimer, cleanup, missedKeepalives: 0 });

    res.on("close", cleanup);
    res.on("error", cleanup);

    return cleanup;
  }

  /**
   * Explicitly close a single client connection, clearing its keepalive
   * timer and removing it from the broadcast set. Idempotent.
   */
  close(client: SSEClient): void {
    const state = this.clients.get(client);
    if (!state) return;
    try {
      client.end();
    } catch {
      /* ignore */
    }
    state.cleanup();
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
    for (const client of this.clients.keys()) {
      try {
        client.write(payload);
      } catch {
        /* socket gone; cleanup fires via close event or reaper */
      }
    }
  }

  /**
   * Broadcast a named event (e.g., "audit_event", "header_update").
   */
  broadcastNamed(eventName: string, data: unknown): void {
    const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of this.clients.keys()) {
      try {
        client.write(payload);
      } catch {
        /* socket gone; cleanup fires via close event or reaper */
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
   * Close all SSE connections, clearing every keepalive timer.
   */
  closeAll(): void {
    for (const [client, state] of this.clients) {
      clearInterval(state.keepaliveTimer);
      try {
        client.end();
      } catch {
        /* ignore */
      }
    }
    this.clients.clear();
  }
}
