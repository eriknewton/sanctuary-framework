/**
 * Sanctuary Dashboard — HTTP Server
 *
 * Thin wrapper around node:http that wires the request handler
 * from api.ts. No Express. Listens on 127.0.0.1 by default.
 *
 * Exposes a minimal event emitter (publish / subscribe) so callers
 * can push live activity + approval events to SSE clients without
 * the server layer needing to know about aggregator internals.
 */

import { createServer, type Server } from "node:http";
import type {
  AggregatorSources,
  ActivityEntry,
  PendingApproval,
} from "./aggregator.js";
import { handleRequest, type ApprovalHandlers, type StreamEvent } from "./api.js";

export interface DashboardServerOptions {
  port?: number;
  host?: string;
  authToken?: string;
  mode: "co-located" | "standalone";
  sources: AggregatorSources;
  approvals?: ApprovalHandlers;
}

export interface DashboardHandle {
  url: string;
  port: number;
  host: string;
  stop: () => Promise<void>;
  /** Push an event to all connected SSE clients. */
  publish: (event: StreamEvent) => void;
  /**
   * Push a fresh activity entry. Exposes a simple shortcut so callers
   * (e.g. the Sanctuary proxy / upstream clients) can report tool calls
   * without constructing a StreamEvent themselves.
   */
  publishActivity: (entry: ActivityEntry) => void;
  /** Push a new pending approval (already added by the approval channel). */
  publishApproval: (approval: PendingApproval) => void;
  /**
   * Push a v1.1 hub inbox item update. Producers (HubService) call this
   * on inbox writes (Tier 1 enqueue, Tier 1 resolve, source-pulled item
   * surfaced). Consumers replace-or-prepend by `item_id`.
   */
  publishInbox: (item: unknown) => void;
  /**
   * Push a v1.1 per-agent status update. Producers call this when the
   * agent registry's `updateStatus` transitions. Consumers replace by
   * `agent_id`.
   */
  publishAgentStatus: (snapshot: unknown) => void;
}

const DEFAULT_PORT = 3501;
const DEFAULT_HOST = "127.0.0.1";

export async function startDashboardServer(
  options: DashboardServerOptions
): Promise<DashboardHandle> {
  const port = options.port ?? DEFAULT_PORT;
  const host = options.host ?? DEFAULT_HOST;

  const listeners = new Set<(event: StreamEvent) => void>();
  const onEvent = (listener: (event: StreamEvent) => void): (() => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  };
  const publish = (event: StreamEvent): void => {
    for (const listener of listeners) {
      try {
        listener(event);
      } catch {
        // listener failures shouldn't break others
      }
    }
  };

  const deps = {
    sources: options.sources,
    authToken: options.authToken,
    approvals: options.approvals,
    onEvent,
  };

  const server: Server = createServer(async (req, res) => {
    try {
      const served = await handleRequest(deps, req, res);
      if (!served) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "not_found", path: req.url }));
      }
    } catch (err) {
      try {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal", message: (err as Error).message }));
      } catch {
        // already partially written
      }
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const actualPort = (() => {
    const addr = server.address();
    if (addr && typeof addr === "object") return addr.port;
    return port;
  })();

  const url = `http://${host}:${actualPort}`;

  return {
    url,
    port: actualPort,
    host,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
    publish,
    publishActivity: (entry: ActivityEntry) =>
      publish({ type: "activity", data: entry }),
    publishApproval: (approval: PendingApproval) =>
      publish({ type: "approval", data: approval }),
    publishInbox: (item: unknown) => publish({ type: "inbox", data: item }),
    publishAgentStatus: (snapshot: unknown) =>
      publish({ type: "agent_status", data: snapshot }),
  };
}
