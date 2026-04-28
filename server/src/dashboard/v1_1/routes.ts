/**
 * Sanctuary v1.1 Dashboard — HTTP Route
 *
 * Renders the v1.1 SPA HTML at any GET path the caller decides to mount
 * it on. v1.1.7 routes the SPA at /, /dashboard, and /v1.1; the path
 * matching lives in the caller (`dispatch.ts`), so this module only
 * needs to confirm the request is a GET and emit the response.
 *
 * The hub API (PR #73 surface) is the only data plane the dashboard
 * consumes; this module does NOT proxy hub routes. Callers wire
 * `handleHubRoute` from `server/src/hub/api-router.ts` separately.
 *
 * SSE pass-through: the dashboard binds to the existing `/api/stream`
 * producer at `server/src/dashboard/api.ts`. The hub service wires
 * inbox+activity+agent-status broadcast through `publishV11Event` from
 * the SSE producer extension below.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { renderDashboardV11Html, type DashboardV11HtmlOptions } from "./html.js";

export interface DashboardV11RouteDeps extends DashboardV11HtmlOptions {}

/**
 * Render the v1.1 SPA HTML for the current request. Returns true when
 * served; false on non-GET so the caller stack can continue routing.
 *
 * Path matching is the caller's responsibility — at v1.1.7 the SPA is
 * mounted at /, /dashboard, /v1.1 (and trailing slash) by
 * `dispatch.ts`.
 */
export function handleDashboardV11Route(
  deps: DashboardV11RouteDeps,
  req: IncomingMessage,
  res: ServerResponse,
): boolean {
  const method = (req.method ?? "GET").toUpperCase();
  if (method !== "GET") return false;
  const html = renderDashboardV11Html(deps);
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(html);
  return true;
}
