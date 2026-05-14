/**
 * Sanctuary Operator Console v1.0 -- Auth Middleware
 *
 * Loopback auto-auth mirroring v0.10.6 pattern + token gating for
 * non-loopback. No external identity provider at v1.0.
 *
 * Auth gate is the FIRST middleware. Every /api/console/* route passes
 * through this before any handler runs.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import {
  constantTimeEquals,
  extractToken,
} from "../dashboard/api.js";
import { AuthGateError } from "./errors.js";

export interface AuthConfig {
  /** When true, loopback (127.0.0.1 / ::1) requests bypass auth. */
  loopbackAutoAuth: boolean;
  /** Bearer token for non-loopback. If undefined, non-loopback fails closed. */
  authToken?: string;
}

/**
 * Check whether a request originates from loopback.
 */
export function isLoopback(req: IncomingMessage): boolean {
  const addr = req.socket.remoteAddress ?? "";
  return (
    addr === "127.0.0.1" ||
    addr === "::1" ||
    addr === "::ffff:127.0.0.1"
  );
}

/**
 * Evaluate auth for an incoming request.
 * Returns true if authorized. Throws AuthGateError if not.
 */
export function enforceAuth(
  config: AuthConfig,
  req: IncomingMessage,
  url: URL
): true {
  // Loopback auto-auth: localhost connections skip token check
  if (config.loopbackAutoAuth && isLoopback(req)) {
    return true;
  }

  if (!config.authToken) {
    throw new AuthGateError("missing configured authentication token");
  }

  // Extract token from Authorization header or ?token= query param
  const token = extractToken(req, url);
  if (!token) {
    throw new AuthGateError("missing authentication token");
  }

  if (!constantTimeEquals(token, config.authToken)) {
    throw new AuthGateError("invalid authentication token");
  }

  return true;
}

/**
 * Express-style middleware wrapper. Attaches to every /api/console/* route.
 */
export function authMiddleware(
  config: AuthConfig
): (req: IncomingMessage, res: ServerResponse, url: URL) => boolean {
  return (req, res, url) => {
    try {
      enforceAuth(config, req, url);
      return true;
    } catch (err) {
      if (err instanceof AuthGateError) {
        res.writeHead(err.statusCode, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        res.end(JSON.stringify({ error: "unauthorized" }));
        return false;
      }
      throw err;
    }
  };
}
