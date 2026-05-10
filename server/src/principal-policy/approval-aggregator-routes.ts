/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-1
 *
 * HTTP route surface for the unified approval inbox. Mirrors the hub
 * api-router shape so dashboard glue can wire the aggregator alongside
 * the v1.1 hub routes through one auth pipeline.
 *
 * Mounted under `/api/approval-inbox/*`. Every route runs through the
 * existing `authMiddleware` from `server/src/console/auth-middleware.ts`
 * so loopback auto-auth + bearer-token gating come from one shared
 * implementation. No new auth path is introduced.
 *
 * Routes:
 *   GET    /api/approval-inbox                       (list pending entries)
 *   GET    /api/approval-inbox/:aggregator_id        (full detail incl. payload)
 *   POST   /api/approval-inbox/:aggregator_id/approve
 *   POST   /api/approval-inbox/:aggregator_id/deny
 *   GET    /api/approval-inbox/stream                (SSE stream of new entries)
 *
 * No new outbound network surface. All routes are operator-local; the
 * Castle Wall egress filter (Layer 1) still binds. The aggregator is a
 * Layer 3 cooperative-MCP surface; this Upsilon-1 PR ships the routing
 * substrate; per-harness adapter approval-redirect mode is Upsilon-2.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import type { AggregatedApprovalStatus, ApprovalAggregator } from "./approval-aggregator.js";

/** URL prefix for the cross-harness approval inbox surface. */
export const APPROVAL_INBOX_API_PREFIX = "/api/approval-inbox";

/** Operator identity attribution when the HTTP route resolves an entry. */
export const APPROVAL_INBOX_OPERATOR_DEFAULT = "operator_dashboard";

/**
 * Default and maximum result count for the list route. Mirrors the hub
 * inbox limits at v1.1 so dashboard pagination stays consistent.
 */
const APPROVAL_INBOX_DEFAULT_LIMIT = 50;
const APPROVAL_INBOX_MAX_LIMIT = 200;

export interface ApprovalInboxRouterDeps {
  authConfig: AuthConfig;
  aggregator: ApprovalAggregator;
  /**
   * Optional override for the operator id attributed on HTTP-driven
   * resolutions. Defaults to APPROVAL_INBOX_OPERATOR_DEFAULT. Tests pass
   * the operator's identity id so audit events carry the same attribution
   * as gate-driven resolutions.
   */
  operatorId?: string;
}

function writeJSON(
  res: ServerResponse,
  status: number,
  payload: unknown,
): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function parseLimit(
  raw: string | null,
  defaultValue: number,
  max: number,
): number {
  if (raw === null || raw === "") return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    return defaultValue;
  }
  return Math.min(parsed, max);
}

function isStatusFilter(value: string): value is AggregatedApprovalStatus {
  return (
    value === "pending" ||
    value === "approved" ||
    value === "denied" ||
    value === "timeout" ||
    value === "expired"
  );
}

/**
 * Match `/api/approval-inbox/:id` and `/api/approval-inbox/:id/<action>`.
 */
function matchEntryRoute(path: string): {
  aggregatorId: string;
  action: string | null;
} | null {
  const prefix = `${APPROVAL_INBOX_API_PREFIX}/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0) return null;
  const slash = rest.indexOf("/");
  if (slash === -1) {
    return { aggregatorId: decodeURIComponent(rest), action: null };
  }
  return {
    aggregatorId: decodeURIComponent(rest.slice(0, slash)),
    action: rest.slice(slash + 1),
  };
}

async function handleStream(
  deps: ApprovalInboxRouterDeps,
  res: ServerResponse,
): Promise<void> {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });

  const initial = await deps.aggregator.list({ status: "pending" });
  res.write(
    `event: approval_inbox_snapshot\ndata: ${JSON.stringify({ entries: initial })}\n\n`,
  );

  const unsubscribe = deps.aggregator.onEvent((event) => {
    try {
      res.write(
        `event: approval_inbox_${event.type}\ndata: ${JSON.stringify(event.entry)}\n\n`,
      );
    } catch {
      // socket gone; cleanup runs on close
    }
  });

  const keepAlive = setInterval(() => {
    try {
      res.write(": keepalive\n\n");
    } catch {
      // ignore
    }
  }, 25_000);

  const cleanup = (): void => {
    clearInterval(keepAlive);
    unsubscribe();
  };
  res.on("close", cleanup);
  res.on("error", cleanup);
}

/**
 * Handle a request against the approval-inbox surface. Returns true when
 * served (including 4xx/5xx); returns false to let the caller continue
 * routing.
 */
export async function handleApprovalInboxRoute(
  deps: ApprovalInboxRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== APPROVAL_INBOX_API_PREFIX &&
    !path.startsWith(`${APPROVAL_INBOX_API_PREFIX}/`)
  ) {
    return false;
  }

  // Auth gate: shared with the hub + console surfaces.
  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  try {
    // GET /api/approval-inbox/stream
    if (
      method === "GET" &&
      path === `${APPROVAL_INBOX_API_PREFIX}/stream`
    ) {
      await handleStream(deps, res);
      return true;
    }

    // GET /api/approval-inbox
    if (method === "GET" && path === APPROVAL_INBOX_API_PREFIX) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        APPROVAL_INBOX_DEFAULT_LIMIT,
        APPROVAL_INBOX_MAX_LIMIT,
      );
      const statusRaw = url.searchParams.get("status");
      const status =
        statusRaw && isStatusFilter(statusRaw) ? statusRaw : "pending";
      const sinceTs = url.searchParams.get("since") ?? undefined;
      const entries = await deps.aggregator.list({
        status,
        limit,
        ...(sinceTs !== undefined ? { sinceTs } : {}),
      });
      writeJSON(res, 200, { ok: true, data: { entries } });
      return true;
    }

    const entryMatch = matchEntryRoute(path);
    if (entryMatch === null) {
      writeJSON(res, 404, { ok: false, error: "not_found", path });
      return true;
    }

    // GET /api/approval-inbox/:id
    if (method === "GET" && entryMatch.action === null) {
      const entries = await deps.aggregator.list({ limit: APPROVAL_INBOX_MAX_LIMIT });
      const entry = entries.find(
        (e) => e.aggregator_id === entryMatch.aggregatorId,
      );
      if (!entry) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      const payload = await deps.aggregator.getFullPayload(
        entryMatch.aggregatorId,
      );
      writeJSON(res, 200, { ok: true, data: { entry, request_payload: payload } });
      return true;
    }

    // POST /api/approval-inbox/:id/approve
    // POST /api/approval-inbox/:id/deny
    if (
      method === "POST" &&
      (entryMatch.action === "approve" || entryMatch.action === "deny")
    ) {
      const decision: "approved" | "denied" =
        entryMatch.action === "approve" ? "approved" : "denied";
      const operatorId = deps.operatorId ?? APPROVAL_INBOX_OPERATOR_DEFAULT;
      try {
        const entry = await deps.aggregator.resolve(
          entryMatch.aggregatorId,
          decision,
          operatorId,
        );
        writeJSON(res, 200, { ok: true, data: { entry } });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === "approval-aggregator: not_found") {
          writeJSON(res, 404, { ok: false, error: "not_found" });
        } else {
          writeJSON(res, 500, { ok: false, error: "internal", detail: msg });
        }
      }
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
