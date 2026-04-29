/**
 * v1.1 Shared Dispatch Helper (v1.1.2 hotfix)
 *
 * v1.1.1 (PR #82) wired v1.1 routes only into the principal-policy
 * `DashboardApprovalChannel` server. The wrap-auto operator dashboard
 * (`dashboard/server.ts` + `dashboard/api.ts`) is a separate HTTP server
 * shipped without any v1.1 routing — operators following the wrap-emitted
 * URL hit 404 on `/v1.1`, `/api/hub/*`, and the `/api/identities` alias.
 *
 * This module is a single source of truth for the v1.1 dispatch logic so
 * the two dashboard servers stay in lock-step. Both call `dispatchV11Request`
 * before their legacy route tables; the request-handler signatures of the
 * two servers diverge but the dispatch contract does not.
 *
 * Auth contract (mirrors PR #82's principal-policy implementation):
 *   - `/v1.1` HTML is served unauthenticated; the inline client negotiates
 *     bearer-token / loopback auto-auth on its own.
 *   - `/api/hub/*` and `/api/identities` route through the same `AuthConfig`
 *     contract as the legacy `/api/*` routes.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import { handleHubRoute } from "../../hub/api-router.js";
import { handleDashboardV11Route } from "./index.js";
import {
  handleIntelligenceRoute,
  INTELLIGENCE_API_PREFIX,
} from "./intelligence-api-router.js";
import type { V11Bindings } from "./wiring.js";
import type { AuthConfig } from "../../console/auth-middleware.js";

export interface DispatchV11RequestInputs {
  bindings: V11Bindings;
  /**
   * Bearer token for non-loopback callers. When undefined, the dashboard
   * runs without bearer-token gating (matches v1.0 unauthenticated mode).
   */
  authToken?: string;
  /** When true, loopback (127.0.0.1 / ::1) requests bypass token check. */
  loopbackAutoAuth: boolean;
}

/**
 * Try to handle the request as a v1.1 route. Returns true when the route
 * matched and was served; false to fall through to the legacy route table.
 *
 * The v1.1 HTML at `/v1.1` is intentionally served before the legacy auth
 * gate so the operator can land on the page; the inline client handles its
 * own auth dance via fetch + sessionStorage.
 */
export async function dispatchV11Request(
  inputs: DispatchV11RequestInputs,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
): Promise<boolean> {
  const { bindings, authToken, loopbackAutoAuth } = inputs;

  // v1.1 dashboard HTML at /, /dashboard, /v1.1 (and trailing slash).
  // v1.1.7: root and /dashboard route to the v1.1 SPA so wrap-printed URLs
  // land operators on the current surface. Legacy v1.0 dashboard is preserved
  // at /v1.0 by the legacy route tables in principal-policy/dashboard.ts and
  // dashboard/api.ts; /v1.1 continues to serve for back-compat with operator
  // bookmarks.
  if (
    method === "GET" &&
    (url.pathname === "/" ||
      url.pathname === "/dashboard" ||
      url.pathname === "/v1.1" ||
      url.pathname === "/v1.1/")
  ) {
    return handleDashboardV11Route(
      {
        identityId: bindings.identityId,
        fortressId: bindings.fortressId,
        ...(authToken !== undefined ? { authToken } : {}),
      },
      req,
      res,
    );
  }

  // Intelligence API at /api/hub/intelligence/*. Mounted BEFORE the
  // generic /api/hub/* dispatch so the more specific prefix wins. Same
  // auth contract as the rest of /api/hub/*; selector-bearing bindings
  // serve operator config, selector-less bindings respond 503 with a
  // documented "selector not configured" body.
  if (
    url.pathname === INTELLIGENCE_API_PREFIX ||
    url.pathname.startsWith(`${INTELLIGENCE_API_PREFIX}/`)
  ) {
    const authConfig: AuthConfig = {
      loopbackAutoAuth,
      ...(authToken !== undefined ? { authToken } : {}),
    };
    if (!bindings.intelligenceSelector) {
      res.writeHead(503, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(
        JSON.stringify({
          ok: false,
          error: "selector_not_configured",
          detail: "Intelligence substrate selector is not wired into this dashboard binding.",
        }),
      );
      return true;
    }
    return handleIntelligenceRoute(
      { authConfig, selector: bindings.intelligenceSelector },
      req,
      res,
    );
  }

  // Hub API at /api/hub/*. Same auth contract as legacy /api/*.
  if (url.pathname.startsWith("/api/hub/")) {
    const authConfig: AuthConfig = {
      loopbackAutoAuth,
      ...(authToken !== undefined ? { authToken } : {}),
    };
    return handleHubRoute(
      { authConfig, service: bindings.hubService },
      req,
      res,
    );
  }

  // Finding E alias: /api/identities → /api/hub/agents (back-compat for
  // pre-v1.1 operator scripts). Same auth, same response shape.
  if (method === "GET" && url.pathname === "/api/identities") {
    const authConfig: AuthConfig = {
      loopbackAutoAuth,
      ...(authToken !== undefined ? { authToken } : {}),
    };
    const aliasReq = Object.create(req) as IncomingMessage;
    aliasReq.url = "/api/hub/agents" + url.search;
    return handleHubRoute(
      { authConfig, service: bindings.hubService },
      aliasReq,
      res,
    );
  }

  return false;
}
