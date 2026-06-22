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
 * Per-invocation auth options.
 *
 * `requireToken` forces the operator bearer token to be presented and
 * validated REGARDLESS of origin, suppressing the `loopbackAutoAuth`
 * shortcut for this request. Use it for routes whose effect must always
 * trace to the operator's credential and never to mere network position.
 *
 * Rationale (MCP threat model): in Sanctuary the wrapped AI agent is
 * co-resident with the operator and shares loopback. Treating
 * loopback-origin as operator identity is therefore unsafe for any
 * route that releases a human-approval decision (a Tier-1 gate). Such a
 * route must require the operator token even on loopback, even with
 * `--auto-auth-localhost` enabled, so a co-resident agent holding only a
 * loopback-HTTP primitive cannot self-approve its own Tier-1 operation.
 * Read-only/dashboard routes may keep loopback auto-auth for local
 * convenience.
 */
export interface AuthOptions {
  /**
   * When true, the loopback auto-auth shortcut is suppressed for this
   * request: a valid operator bearer token is required regardless of
   * origin. Token-validation logic is otherwise unchanged.
   */
  requireToken?: boolean;
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
  url: URL,
  options?: AuthOptions
): true {
  // Loopback auto-auth: localhost connections skip token check.
  // Suppressed when the route opts in to `requireToken` - a decision
  // that releases a Tier-1 op must trace to the operator's credential,
  // not to loopback network position (the co-resident agent shares it).
  if (
    !options?.requireToken &&
    config.loopbackAutoAuth &&
    isLoopback(req)
  ) {
    return true;
  }

  if (!config.authToken) {
    throw new AuthGateError("missing configured authentication token");
  }

  // Extract token from Authorization header only; long-lived URL tokens are rejected.
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
  config: AuthConfig,
  options?: AuthOptions
): (req: IncomingMessage, res: ServerResponse, url: URL) => boolean {
  return (req, res, url) => {
    try {
      enforceAuth(config, req, url, options);
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
