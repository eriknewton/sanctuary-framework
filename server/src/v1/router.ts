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
import {
  writeJson,
  denyUnauthorized,
  denyForbidden,
  denyNotFound,
  readJsonBody,
} from "./http.js";
import {
  handleAgentsRequest,
  isAgentsPath,
  type V1AgentsDeps,
} from "./agents.js";
import {
  handleFederationRequest,
  handleFederationCeremony,
  isFederationPath,
  isFederationCeremonyPath,
  type V1FederationDeps,
} from "./federation.js";

export interface V1RouterContext {
  sessions: V1SessionService;
  /** Loopback check shared with the dashboard's auth paths. */
  isLoopbackRequest(req: IncomingMessage): boolean;
  /** Full (SESSION_TOKEN) status document. Must contain no key material. */
  buildFullStatus(): Record<string, unknown>;
  /** Server version string for the PUBLIC minimal status variant. */
  version: string;
  /**
   * PR-A2 agent endpoints (GET /v1/agents, POST /v1/agents/protect,
   * POST /v1/agents/unprotect). Always wired in production; when the hub
   * is unbound the deps degrade gracefully (empty roster, writes fail
   * closed). Optional so PR-A1's minimal test rigs still construct.
   */
  agents?: V1AgentsDeps;
  /**
   * PR-A3 federation endpoints (enable/disable/status, authorize ceremony).
   * Always wired in production; fail closed when no fortress context is
   * provisioned. Optional so earlier minimal test rigs still construct.
   */
  federation?: V1FederationDeps;
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
  // Every rejection on the ceremony endpoints — parse failure, body-size
  // limit, semantic denial — collapses to the SAME generic denial (codex
  // review finding 2). A malformed ceremony body is still a denied
  // unauthenticated ceremony attempt; a distinguishable 400 would give
  // an unauthenticated caller an oracle for which check failed.
  if (method === "POST" && url.pathname === "/v1/session/init") {
    const body = await readJsonBody(req);
    if (body === undefined) {
      denyUnauthorized(res);
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
      // Echo the bound ref so the client signs the challenge over the exact
      // attestation ref the daemon recorded (PR-A3: the ref now varies by
      // auth path — durable operator vs loopback vs auth-disabled).
      attestation_ref: result.attestation_ref,
    });
    return true;
  }

  if (method === "POST" && url.pathname === "/v1/session/complete") {
    const body = await readJsonBody(req);
    if (body === undefined) {
      denyUnauthorized(res);
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

  // ── Federation join-submission ceremony (BOOTSTRAP_TOKEN class) ─────
  // The joining node has no /v1 session on this fortress; its credential is
  // the operator-signed bootstrap token inside the JoinRequest. Handled here,
  // before the session gate, like session/init — every failure collapses to
  // the same uniform 401, so a probing joiner cannot tell federation-off from
  // a bad token from an unknown node. Only POST is the ceremony; a non-POST on
  // this path falls through to the session gate (404 to an authed caller, 401
  // otherwise) exactly like a non-POST on the session ceremony endpoints — it
  // must never fall through to legacy /api routing.
  if (ctx.federation && method === "POST" && isFederationCeremonyPath(url.pathname)) {
    return handleFederationCeremony(ctx.federation, req, res, url, method);
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
  // A valid SESSION_TOKEN is required for every remaining path. Only an
  // authenticated caller can distinguish a real route from a 404, so the
  // route map stays opaque to unauthenticated probes.
  const claims = sessionClaims(ctx, req);
  if (!claims) {
    denyUnauthorized(res);
    return true;
  }

  // PR-A2 agent endpoints. Writes (protect/unprotect) layer OPERATOR_SIGNED
  // verification on top of the session inside the handler.
  if (ctx.agents && isAgentsPath(url.pathname)) {
    return handleAgentsRequest(ctx.agents, req, res, url, method, claims);
  }

  // PR-A3 federation admin endpoints (enable/disable/status, authorize/init).
  // The write paths layer OPERATOR_SIGNED on top of the session in the handler.
  if (ctx.federation && isFederationPath(url.pathname)) {
    return handleFederationRequest(ctx.federation, req, res, url, method, claims);
  }

  denyNotFound(res);
  return true;
}
