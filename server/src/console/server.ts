/**
 * Sanctuary Operator Console v1.0 — Standalone HTTP server.
 *
 * Starts an HTTP server that serves the console HTML + API on a loopback
 * address. Auth model mirrors the Sovereignty Dashboard:
 *   - Default bind 127.0.0.1.
 *   - Bearer token required unless `loopbackAutoAuth` is set.
 *
 * Mount pattern: production deployments typically mount the console routes
 * alongside the principal-policy dashboard (`handleConsoleRequest` called
 * from that server's dispatcher). This module is the standalone boot path
 * used by the Electron shell and by integration tests.
 */

import { createServer as createHttpServer, type Server } from "node:http";
import { handleConsoleRequest, type ConsoleAPIDeps } from "./api.js";

export interface ConsoleServerOptions {
  port?: number;
  host?: string;
  authToken?: string;
  loopbackAutoAuth?: boolean;
  client: ConsoleAPIDeps["client"];
}

export interface ConsoleServerHandle {
  url: string;
  port: number;
  host: string;
  stop(): Promise<void>;
}

export async function startConsoleServer(
  opts: ConsoleServerOptions
): Promise<ConsoleServerHandle> {
  const host = opts.host ?? "127.0.0.1";
  const port = opts.port ?? 0; // 0 = random free port; good default for tests.

  const deps: ConsoleAPIDeps = {
    client: opts.client,
    ...(opts.authToken ? { authToken: opts.authToken } : {}),
    loopbackAutoAuth: opts.loopbackAutoAuth ?? true,
  };

  const server: Server = createHttpServer(async (req, res) => {
    try {
      const handled = await handleConsoleRequest(deps, req, res);
      if (!handled) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "not_found", path: req.url }));
      }
    } catch (err) {
      try {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "internal",
            message: err instanceof Error ? err.message : String(err),
          })
        );
      } catch {
        /* headers already sent */
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
    addr && typeof addr === "object" ? addr.port : port;
  const url = `http://${host}:${actualPort}/console`;

  return {
    url,
    port: actualPort,
    host,
    stop: () =>
      new Promise((resolve, reject) => {
        server.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      }),
  };
}
