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
import { getMultiTenantSnapshot } from "./multi-aggregator.js";
import { renderMultiAgentHTML } from "./multi-html.js";
import { sendCaughtError } from "../http/error-envelope.js";

export interface MultiDashboardOptions {
  /** HTTP port. Default 3500 (distinct from single-tenant default 3501). */
  port?: number;
  /** Bind host. Default 127.0.0.1. */
  host?: string;
  /** Optional bearer token (checked on every route). */
  authToken?: string;
  /**
   * Override HOME for tenant discovery. Primarily for tests.
   */
  home?: string;
  /**
   * Override discovery root (tests). Normally derived from HOME.
   */
  discoveryRoot?: string;
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
  const authToken = options.authToken;

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
        res.end(JSON.stringify({ ok: true, mode: "multi" }));
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
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const addr = server.address();
  const actualPort =
    addr && typeof addr === "object" && addr.port ? addr.port : port;

  return {
    url: `http://${host}:${actualPort}`,
    port: actualPort,
    host,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
