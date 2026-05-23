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
import type { V11Bindings } from "./v1_1/wiring.js";

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
  /**
   * v1.1.2 hotfix (Finding V): bind v1.1 hub bindings to this dashboard
   * instance so /v1.1, /api/hub/*, and /api/identities serve the v1.1
   * surface. Pass null to detach. PR #82 wired these routes only on the
   * principal-policy DashboardApprovalChannel; the wrap-auto operator
   * dashboard (this server) needed the same wiring for the wrap-emitted
   * URL to expose the v1.1 surfaces the v1.1.1 release notes claim.
   */
  setV11Bindings: (bindings: V11Bindings | null) => void;
  /**
   * v1.1.2: enable loopback auto-auth for /api/hub/* + /api/identities.
   * When true, requests from 127.0.0.1 / ::1 bypass the bearer-token
   * check (mirrors the principal-policy dashboard's _autoAuthLocalhost
   * flag). Set true when the dashboard binds to a loopback host and the
   * caller has independently authenticated the operator.
   */
  setV11LoopbackAutoAuth: (enabled: boolean) => void;
  /**
   * Merge newly-available live sources into the snapshot aggregator.
   * Wrap-auto starts HTTP before the fortress key is resolved, then
   * supplies the loaded identity manager and audit log through this hook.
   */
  updateSources: (sources: Partial<AggregatorSources>) => void;
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
  const updateSources = (sources: Partial<AggregatorSources>): void => {
    Object.assign(options.sources, sources);
  };

  // v1.1.2 hotfix (Finding V): mutable per-server state for the v1.1
  // bindings + loopback auto-auth flag. handleRequest sees the latest
  // values on every call because we re-build the deps object per request.
  let v11Bindings: V11Bindings | null = null;
  let v11LoopbackAutoAuth = false;

  const server: Server = createServer(async (req, res) => {
    try {
      const deps = {
        sources: options.sources,
        authToken: options.authToken,
        approvals: options.approvals,
        onEvent,
        v11Bindings,
        loopbackAutoAuth: v11LoopbackAutoAuth,
      };
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
    setV11Bindings: (bindings: V11Bindings | null) => {
      v11Bindings = bindings;
    },
    setV11LoopbackAutoAuth: (enabled: boolean) => {
      v11LoopbackAutoAuth = enabled;
    },
    updateSources,
  };
}
