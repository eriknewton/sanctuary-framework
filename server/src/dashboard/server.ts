/**
 * Sanctuary Dashboard — HTTP Server
 *
 * Thin wrapper around node:http that wires the request handler
 * from api.ts. No Express. Listens on 127.0.0.1 by default.
 *
 * Exposes a minimal event emitter (publish / subscribe) so callers
 * can push live activity + approval events to SSE clients without
 * the server layer needing to know about aggregator internals.
 *
 * RETIRED FROM PRODUCTION SPAWNING (dashboard one-surface fold, 2026-08-02):
 * see the module-surface note in ./index.ts — the ONE production dashboard
 * is the principal-policy DashboardApprovalChannel. `startDashboardServer`
 * stays exported (pinned public surface + test anchors).
 */

import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type {
  AggregatorSources,
  ActivityEntry,
  PendingApproval,
} from "./aggregator.js";
import { handleRequest, type ApprovalHandlers, type StreamEvent } from "./api.js";
import { sendCaughtError } from "../http/error-envelope.js";
import {
  attachPostListenHttpServerErrorLogger,
  cleanupFailedHttpServer,
  closeHttpServer,
  DEFAULT_HTTP_SHUTDOWN_GRACE_MS,
} from "../http/server-lifecycle.js";
import type { V11Bindings } from "./v1_1/wiring.js";
import type { FleetRoster } from "../principal-policy/fleet-roster.js";

export interface DashboardServerOptions {
  port?: number;
  host?: string;
  authToken?: string;
  mode: "co-located" | "standalone";
  sources: AggregatorSources;
  approvals?: ApprovalHandlers;
  /**
   * Read-only fleet-roster provider for the wrap dashboard's fleet-roster
   * panel. Forwarded verbatim onto the per-request `APIDeps`, where it feeds
   * BOTH `GET /api/fleet/roster` and the posture-route `GET /api/posture/fleet`
   * that the posture-home fleet panel fetches. MAY be async (the wrap process
   * reads the roster from disk). When omitted the routes serve the honest absent
   * roster / 404 (no fabricated fleet). See `APIDeps.fleetRoster`.
   */
  fleetRoster?: () => FleetRoster | Promise<FleetRoster>;
  /** Shutdown grace before active connections are force-closed. Default: 5000ms. */
  shutdownGraceMs?: number;
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
  /**
   * Create a one-click URL carrying a short-lived dashboard session.
   * This replaces legacy `?token=` URLs; the long-lived bearer token is
   * never emitted into the URL.
   */
  createSessionUrl?: () => string;
}

const DEFAULT_PORT = 3501;
const DEFAULT_HOST = "127.0.0.1";
const SESSION_TTL_MS = 5 * 60 * 1000;
const MAX_SESSIONS = 256;

interface StoredDashboardSession {
  id: string;
  createdAt: number;
  expiresAt: number;
}

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
  const sessions = new Map<string, StoredDashboardSession>();
  const cleanupSessions = (): void => {
    const now = Date.now();
    for (const [id, session] of sessions) {
      if (now > session.expiresAt) sessions.delete(id);
    }
  };
  const sessionStore = {
    create: () => {
      cleanupSessions();
      if (sessions.size >= MAX_SESSIONS) {
        const oldest = [...sessions.entries()].sort(
          (a, b) => a[1].createdAt - b[1].createdAt,
        )[0];
        if (oldest) sessions.delete(oldest[0]);
      }
      const now = Date.now();
      const id = randomBytes(32).toString("hex");
      sessions.set(id, {
        id,
        createdAt: now,
        expiresAt: now + SESSION_TTL_MS,
      });
      return {
        id,
        expiresInSeconds: Math.floor(SESSION_TTL_MS / 1000),
      };
    },
    validate: (id: string) => {
      const session = sessions.get(id);
      if (!session) return false;
      if (Date.now() > session.expiresAt) {
        sessions.delete(id);
        return false;
      }
      return true;
    },
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
        sessions: sessionStore,
        approvals: options.approvals,
        onEvent,
        v11Bindings,
        loopbackAutoAuth: v11LoopbackAutoAuth,
        fleetRoster: options.fleetRoster,
      };
      const served = await handleRequest(deps, req, res);
      if (!served) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "not_found", path: req.url }));
      }
    } catch (err) {
      try {
        sendCaughtError(res, 500, "internal_error", err, {
          route: req.url ?? undefined,
        });
      } catch {
        // already partially written
      }
    }
  });

  await new Promise<void>((resolve, reject) => {
    const onStartupError = (err: Error) => {
      void cleanupFailedHttpServer(server).finally(() => reject(err));
    };
    server.once("error", onStartupError);
    server.listen(port, host, () => {
      server.off("error", onStartupError);
      attachPostListenHttpServerErrorLogger(
        server,
        "Sanctuary Dashboard HTTP server",
      );
      resolve();
    });
  });

  const actualPort = (() => {
    const addr = server.address();
    if (addr && typeof addr === "object") return addr.port;
    return port;
  })();

  const url = `http://${host}:${actualPort}`;
  const createSessionUrl = (): string => {
    if (!options.authToken) return url;
    const session = sessionStore.create();
    return `${url}?session=${encodeURIComponent(session.id)}`;
  };
  let stopped = false;
  let stopPromise: Promise<void> | null = null;
  const stop = (): Promise<void> => {
    if (stopped) return Promise.resolve();
    if (stopPromise) return stopPromise;
    stopPromise = closeHttpServer(server, {
      label: "Sanctuary Dashboard HTTP server",
      graceMs: options.shutdownGraceMs ?? DEFAULT_HTTP_SHUTDOWN_GRACE_MS,
    }).finally(() => {
      stopped = true;
      stopPromise = null;
      listeners.clear();
      sessions.clear();
    });
    return stopPromise;
  };

  return {
    url,
    port: actualPort,
    host,
    stop,
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
    createSessionUrl,
  };
}
