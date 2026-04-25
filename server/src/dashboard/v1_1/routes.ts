/**
 * Sanctuary v1.1 Dashboard — HTTP Route
 *
 * Mounts a single GET route serving the v1.1 HTML shell. The hub API
 * (PR #73 surface) is the only data plane the dashboard consumes; this
 * module does NOT proxy hub routes. Callers wire `handleHubRoute` from
 * `server/src/hub/api-router.ts` separately.
 *
 * SSE pass-through: the dashboard binds to the existing `/api/stream`
 * producer at `server/src/dashboard/api.ts`. The hub service wires
 * inbox+activity+agent-status broadcast through `publishV11Event` from
 * the SSE producer extension below.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { renderDashboardV11Html, type DashboardV11HtmlOptions } from "./html.js";

export interface DashboardV11RouteDeps extends DashboardV11HtmlOptions {
  /** Path the dashboard is served from. Defaults to `/v1.1`. */
  routePath?: string;
}

/**
 * Handle a single request against the v1.1 dashboard route. Returns true
 * if the route matched and was served; false otherwise so the caller
 * stack can continue routing.
 */
export function handleDashboardV11Route(
  deps: DashboardV11RouteDeps,
  req: IncomingMessage,
  res: ServerResponse,
): boolean {
  const routePath = deps.routePath ?? "/v1.1";
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  if (method !== "GET") return false;
  if (url.pathname !== routePath && url.pathname !== `${routePath}/`) return false;
  const html = renderDashboardV11Html(deps);
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(html);
  return true;
}
