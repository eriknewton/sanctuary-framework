/**
 * /v1 HTTP router skeleton (PR-A1).
 *
 * Mounted additively in DashboardApprovalChannel ahead of the legacy
 * `/api/*` tables. Owns every path at `/v1` and below (`/v1.0` and
 * `/v1.1`, the legacy dashboard HTML routes, do NOT match this prefix).
 *
 * Auth model (fail closed):
 * - POST /v1/session/init + POST /v1/session/complete are the ceremony
 *   itself (auth class CHALLENGE_RESPONSE).
 * - GET /v1/status with no Authorization header serves the PUBLIC minimal
 *   variant: `{ ok, version }` and nothing else — no policy, identity,
 *   or listener detail leaks to an unauthenticated probe.
 * - Everything else under /v1 — including unknown paths — requires a
 *   valid SESSION_TOKEN bearer. Unauthenticated callers get one generic
 *   401 whether or not the path exists, so the route map is not
 *   enumerable without a session. Only an authenticated caller can
 *   distinguish "not found" from "denied".
 * - Capability checks run after token validation; a valid session
 *   without the required capability gets a generic 403.
 *
 * All denials are generic (CLAUDE.md constraint 7): the body never says
 * which check failed. No key material is ever written to a response or
 * log from this module (constraint 6).
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { V1SessionService, V1SessionClaims } from "./session-service.js";
import { V1_CAPABILITY_STATUS_READ } from "./session-service.js";

/** Request bodies above this size are rejected before parsing. */
const MAX_BODY_BYTES = 16 * 1024;

export interface V1RouterContext {
  sessions: V1SessionService;
  /** Loopback check shared with the dashboard's auth paths. */
  isLoopbackRequest(req: IncomingMessage): boolean;
  /** Full (SESSION_TOKEN) status document. Must contain no key material. */
  buildFullStatus(): Record<string, unknown>;
  /** Server version string for the PUBLIC minimal status variant. */
  version: string;
}

function writeJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

/** One generic denial for every authentication failure (constraint 7). */
function denyUnauthorized(res: ServerResponse): void {
  writeJson(res, 401, { error: "unauthorized" });
}

/** One generic denial for every capability failure. */
function denyForbidden(res: ServerResponse): void {
  writeJson(res, 403, { error: "forbidden" });
}

/** Generic malformed-request rejection. Never issues credentials. */
function denyBadRequest(res: ServerResponse): void {
  writeJson(res, 400, { error: "bad request" });
}

async function readJsonBody(req: IncomingMessage): Promise<unknown | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) return undefined;
    chunks.push(buf);
  }
  const text = Buffer.concat(chunks).toString("utf-8");
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Extract and validate the bearer session token. Returns claims or null.
 * The long-lived dashboard auth token is NOT accepted here — /v1 routes
 * are session-token only, by design.
 */
function sessionClaims(
  ctx: V1RouterContext,
  req: IncomingMessage,
): V1SessionClaims | null {
  const header = req.headers.authorization;
  if (!header) return null;
  const parts = header.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer" || !parts[1]) return null;
  return ctx.sessions.validateToken(parts[1]);
}

/**
 * Handle a request under the /v1 prefix. Returns true when the request
 * was served (always, for matching prefixes — /v1 never falls through to
 * legacy routing).
 */
export async function handleV1Request(
  ctx: V1RouterContext,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
): Promise<boolean> {
  if (url.pathname !== "/v1" && !url.pathname.startsWith("/v1/")) {
    return false;
  }

  // ── Ceremony endpoints (CHALLENGE_RESPONSE) ─────────────────────────
  if (method === "POST" && url.pathname === "/v1/session/init") {
    const body = await readJsonBody(req);
    if (body === undefined) {
      denyBadRequest(res);
      return true;
    }
    const result = ctx.sessions.init(body, ctx.isLoopbackRequest(req));
    if (!result.ok) {
      denyUnauthorized(res);
      return true;
    }
    writeJson(res, 200, {
      challenge: result.challenge,
      challenge_id: result.challenge_id,
      expires_at: result.expires_at,
    });
    return true;
  }

  if (method === "POST" && url.pathname === "/v1/session/complete") {
    const body = await readJsonBody(req);
    if (body === undefined) {
      denyBadRequest(res);
      return true;
    }
    const result = ctx.sessions.complete(body);
    if (!result.ok) {
      denyUnauthorized(res);
      return true;
    }
    writeJson(res, 200, {
      session_token: result.session_token,
      expires_at: result.expires_at,
      capabilities: result.capabilities,
    });
    return true;
  }

  // ── GET /v1/status: PUBLIC minimal without credentials ──────────────
  if (method === "GET" && url.pathname === "/v1/status") {
    if (!req.headers.authorization) {
      // Minimal health variant: must not leak policy, identity, or
      // listener detail (catalog: "Minimal response must not leak
      // policy").
      writeJson(res, 200, { ok: true, version: ctx.version });
      return true;
    }
    const claims = sessionClaims(ctx, req);
    if (!claims) {
      denyUnauthorized(res);
      return true;
    }
    if (!claims.capabilities.includes(V1_CAPABILITY_STATUS_READ)) {
      denyForbidden(res);
      return true;
    }
    writeJson(res, 200, ctx.buildFullStatus());
    return true;
  }

  // ── Everything else under /v1: fail closed ─────────────────────────
  const claims = sessionClaims(ctx, req);
  if (!claims) {
    denyUnauthorized(res);
    return true;
  }
  writeJson(res, 404, { error: "not found" });
  return true;
}
