/**
 * Sanctuary Dashboard — Multi-tenant HTTP server
 *
 * Standalone HTTP service that shows every tenant discovered on the host
 * and deep-links into each one's per-tenant dashboard. It does not decrypt
 * any tenant state; it scans the filesystem + reads plaintext
 * `runtime.json` hints + probes each per-tenant `/api/health` endpoint.
 *
 * Launched by `sanctuary dashboard --multi`. The single-tenant dashboard
 * remains the default path, so users with one wrapped agent are unaffected.
 */

import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import { getMultiTenantSnapshot } from "./multi-aggregator.js";
import { renderMultiAgentHTML } from "./multi-html.js";
import { getProcessInstance, getProcessSince } from "./process-identity.js";
import { isRemoteDashboardBinding } from "./remote-binding.js";
import { sendCaughtError } from "../http/error-envelope.js";
import {
  attachPostListenHttpServerErrorLogger,
  cleanupFailedHttpServer,
  closeHttpServer,
  DEFAULT_HTTP_SHUTDOWN_GRACE_MS,
} from "../http/server-lifecycle.js";

export interface MultiDashboardOptions {
  /** HTTP port. Default 3500 (distinct from single-tenant default 3501). */
  port?: number;
  /** Bind host. Default 127.0.0.1. */
  host?: string;
  /** Optional bearer token (checked on every route). */
  authToken?: string;
  /**
   * Permit non-loopback plaintext HTTP when the network layer already encrypts.
   * Defaults to false.
   */
  allowPlaintextRemote?: boolean;
  /**
   * Override HOME for tenant discovery. Primarily for tests.
   */
  home?: string;
  /**
   * Override discovery root (tests). Normally derived from HOME.
   */
  discoveryRoot?: string;
  /** Shutdown grace before active connections are force-closed. Default: 5000ms. */
  shutdownGraceMs?: number;
}

export interface MultiDashboardHandle {
  url: string;
  port: number;
  host: string;
  stop: () => Promise<void>;
}

const DEFAULT_PORT = 3500;
const DEFAULT_HOST = "127.0.0.1";

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function extractToken(
  req: import("node:http").IncomingMessage,
  url: URL
): string | null {
  const header = req.headers.authorization;
  if (header && header.startsWith("Bearer ")) {
    return header.slice(7).trim();
  }
  void url;
  return null;
}

export async function startMultiDashboardServer(
  options: MultiDashboardOptions = {}
): Promise<MultiDashboardHandle> {
  const port = options.port ?? DEFAULT_PORT;
  const host = options.host ?? DEFAULT_HOST;
  let authToken = options.authToken;

  // A non-loopback plaintext multi-tenant bind exposes every tenant
  // unauthenticated; refuse it, matching the single-tenant path in
  // principal-policy/dashboard.ts.
  if (isRemoteDashboardBinding(host) && !options.allowPlaintextRemote) {
    throw new Error(
      `Sanctuary Multi Dashboard: refusing to start on non-loopback interface ` +
        `${host} over plaintext HTTP.\n\n` +
        `  The multi-agent dashboard exposes every tenant's metadata.\n\n` +
        `  Options:\n` +
        `    1. Configure TLS or a TLS-terminating reverse proxy\n` +
        `    2. Set dashboard.allow_plaintext_remote: true if the network\n` +
        `       layer already encrypts (e.g. Tailscale, WireGuard)\n` +
        `    3. Bind to 127.0.0.1 (localhost only)\n`,
    );
  }

  // Must match DashboardApprovalChannel.isRemoteBinding in
  // principal-policy/dashboard.ts: remote binds never start tokenless.
  if (isRemoteDashboardBinding(host) && !authToken) {
    authToken = randomBytes(32).toString("hex");
    process.stderr.write(
      `\n  C1: Non-loopback multi-dashboard binding requires authentication.\n` +
        `  Auto-generated auth token (use this to connect from remote machines).\n` +
        `  Operator token: ${authToken}\n\n`,
    );
  }

  const discovery: { home?: string; root?: string } = {};
  if (options.home !== undefined) discovery.home = options.home;
  if (options.discoveryRoot !== undefined) discovery.root = options.discoveryRoot;

  const server: Server = createServer(async (req, res) => {
    try {
      const hostHeader = req.headers.host || `${host}:${port}`;
      const url = new URL(req.url ?? "/", `http://${hostHeader}`);
      const method = (req.method ?? "GET").toUpperCase();
      const path = url.pathname;

      // Token gate (when enabled).
      if (authToken) {
        const token = extractToken(req, url);
        if (!token || !constantTimeEquals(token, authToken)) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "unauthorized" }));
          return;
        }
      }

      if (method === "GET" && path === "/api/health") {
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        // brief D3: `{ ok, mode }` plus the opaque per-process `instance` +
        // `since`. The `instance` is per-process, so a per-tenant dashboard
        // and this multi-tenant aggregator each mint their own id; it CANNOT
        // be used to correlate tenants. The multi-tenant aggregator holds no
        // single-tenant unlock state, so it has NO /api/readiness route
        // (brief D3 / sec invariant 6.4): readiness is reported only by each
        // per-tenant dashboard about itself, never aggregated here.
        res.end(
          JSON.stringify({
            ok: true,
            mode: "multi",
            instance: getProcessInstance(),
            since: getProcessSince(),
          }),
        );
        return;
      }

      if (
        method === "GET" &&
        (path === "/" || path === "/agents" || path === "/index.html")
      ) {
        const snapshot = await getMultiTenantSnapshot({ discovery });
        const html = renderMultiAgentHTML({ snapshot, host, port });
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
        });
        res.end(html);
        return;
      }

      if (method === "GET" && path === "/api/agents") {
        const snapshot = await getMultiTenantSnapshot({ discovery });
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        res.end(JSON.stringify(snapshot));
        return;
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not_found", path }));
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
        "Sanctuary Multi Dashboard HTTP server",
      );
      resolve();
    });
  });

  const addr = server.address();
  const actualPort =
    addr && typeof addr === "object" && addr.port ? addr.port : port;
  let stopped = false;
  let stopPromise: Promise<void> | null = null;
  const stop = (): Promise<void> => {
    if (stopped) return Promise.resolve();
    if (stopPromise) return stopPromise;
    stopPromise = closeHttpServer(server, {
      label: "Sanctuary Multi Dashboard HTTP server",
      graceMs: options.shutdownGraceMs ?? DEFAULT_HTTP_SHUTDOWN_GRACE_MS,
    }).finally(() => {
      stopped = true;
      stopPromise = null;
    });
    return stopPromise;
  };

  return {
    url: `http://${host}:${actualPort}`,
    port: actualPort,
    host,
    stop,
  };
}
