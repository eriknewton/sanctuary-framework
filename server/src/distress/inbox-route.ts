/**
 * HABEAS PORT — distress inbox HTTP route (read-only).
 *
 * Mounted under `/api/distress/*` on the dashboard. Surfaces the distress
 * envelopes the local listener received so the operator can see them in the
 * dashboard UI. The caller (`dashboard.dispatchDistress`) runs the dashboard's
 * own `checkAuth` gate BEFORE invoking this router — the same gate the
 * `/api/audit-log` route uses (bearer token + login session cookie + loopback
 * posture) — so there is no second, weaker auth path. The listener itself never
 * serves content to a connecting peer; reading happens only here, behind that
 * dashboard auth.
 *
 * Routes:
 *   GET /api/distress/inbox            newest-first list of received signals
 *   GET /api/distress/inbox?limit=N    bounded list (N capped at the ring size)
 *
 * Read-only: there is no write/delete surface. Writes happen only on the
 * listener's verified-delivery path; the audit log is the system of record.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import type { DistressInbox } from "./inbox.js";

export const DISTRESS_API_PREFIX = "/api/distress";

const INBOX_DEFAULT_LIMIT = 100;

/**
 * Deps for the distress inbox router.
 *
 * NOTE: this router does NOT authenticate. The caller (the dashboard's
 * `dispatchDistress`) MUST run its `checkAuth` gate before invoking this — the
 * same gate the audit-log route uses, which honors bearer token + login
 * session cookie. Keeping auth in the caller (rather than a local
 * authMiddleware) ensures the distress inbox shares one auth posture with the
 * rest of the dashboard instead of a second, cookie-blind one.
 */
export interface DistressRouterDeps {
  inbox: DistressInbox;
}

function writeJSON(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function parseLimit(raw: string | null, fallback: number): number {
  if (raw === null || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) return fallback;
  return parsed;
}

/**
 * Handle a request against the distress inbox surface. Returns true when
 * served (including 4xx/5xx); false to let the caller keep routing.
 */
export async function handleDistressRoute(
  deps: DistressRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (path !== DISTRESS_API_PREFIX && !path.startsWith(`${DISTRESS_API_PREFIX}/`)) {
    return false;
  }

  // Auth is enforced by the caller (dashboard checkAuth) before we are invoked.
  try {
    if (method === "GET" && path === `${DISTRESS_API_PREFIX}/inbox`) {
      const limit = parseLimit(url.searchParams.get("limit"), INBOX_DEFAULT_LIMIT);
      const entries = await deps.inbox.list(limit);
      writeJSON(res, 200, { ok: true, data: { entries, count: entries.length } });
      return true;
    }

    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    writeJSON(res, 500, { ok: false, error: "internal", detail: msg });
    return true;
  }
}
