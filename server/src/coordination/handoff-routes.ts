/**
 * Sanctuary v1.3 WP-V1.3-3 Omega-1 Coordination handoff HTTP routes.
 *
 * Mounted under `/api/coordination/*`. Mirrors the Phi-1 sentinel
 * route module shape (Standing CTO call: follow Phi-1 sibling-view
 * pattern; spawn-prompt's `dashboard-handoff-view.ts` filename did
 * not exist on main, so the routes live under the
 * `coordination/` subsystem with the rest of the handoff machinery).
 *
 * Routes:
 *   GET    /api/coordination/handoffs              (chronological list, filtered)
 *   GET    /api/coordination/handoffs/stream       (SSE stream of new entries)
 *   GET    /api/coordination/handoffs/:entry_id    (full detail incl. source audit entry)
 *
 * Auth-gated via existing operator middleware. Multi-fortress
 * isolation enforced at the audit-log encryption boundary the
 * underlying HandoffLog reads through.
 *
 * Two new operator-action audit events fire on these routes:
 *  - `operator_coordination_view_opened` on the list route.
 *  - `operator_handoff_entry_drilled` on the detail route.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import {
  COORDINATION_VIEW_AUDIT_OPS,
  type HandoffLog,
  type HandoffEntry,
} from "./handoff-log.js";

export const COORDINATION_API_PREFIX = "/api/coordination";
export const COORDINATION_HANDOFFS_PREFIX = "/api/coordination/handoffs";

const COORDINATION_LIST_DEFAULT_LIMIT = 50;
const COORDINATION_LIST_MAX_LIMIT = 500;

export interface HandoffRouterDeps {
  authConfig: AuthConfig;
  handoffLog: HandoffLog;
  auditLog: AuditLog;
  /** Operator identity attribution for audit events emitted by these routes. */
  operatorId: string;
  /** In-process SSE event bridge; the route subscribes for fanout. */
  events: HandoffEventBridge;
}

/**
 * In-process bridge that lets the dispatcher (or any other in-process
 * source) push handoff events to live SSE subscribers without
 * coupling the HandoffLog to a transport. The list route reads
 * historical state via HandoffLog.query(); the stream route subscribes
 * here for new entries.
 */
export class HandoffEventBridge {
  private readonly listeners = new Set<(entry: HandoffEntry) => void>();

  subscribe(listener: (entry: HandoffEntry) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(entry: HandoffEntry): void {
    for (const listener of this.listeners) {
      try {
        listener(entry);
      } catch {
        // Listener exceptions never fail the bridge.
      }
    }
  }
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
  if (Number.isNaN(parsed) || parsed < 0) return defaultValue;
  return Math.min(parsed, max);
}

function matchEntryRoute(path: string): { entryId: string } | null {
  const prefix = `${COORDINATION_HANDOFFS_PREFIX}/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0 || rest === "stream") return null;
  if (rest.includes("/")) return null;
  return { entryId: decodeURIComponent(rest) };
}

async function handleStream(
  deps: HandoffRouterDeps,
  res: ServerResponse,
): Promise<void> {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  // Send a snapshot of recent handoffs so the operator UI shows
  // historical context as soon as the stream connects.
  const snapshot = await deps.handoffLog.query({ limit: 50 });
  res.write(
    `event: handoff_snapshot\ndata: ${JSON.stringify({ entries: snapshot })}\n\n`,
  );
  const unsubscribe = deps.events.subscribe((entry) => {
    try {
      res.write(
        `event: handoff_added\ndata: ${JSON.stringify(entry)}\n\n`,
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
 * Handle a request against the coordination surface. Returns true
 * when served (including 4xx/5xx); returns false to let the caller
 * continue routing.
 */
export async function handleCoordinationRoute(
  deps: HandoffRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== COORDINATION_API_PREFIX &&
    !path.startsWith(`${COORDINATION_API_PREFIX}/`)
  ) {
    return false;
  }
  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  try {
    if (
      method === "GET" &&
      path === `${COORDINATION_HANDOFFS_PREFIX}/stream`
    ) {
      await handleStream(deps, res);
      return true;
    }

    if (method === "GET" && path === COORDINATION_HANDOFFS_PREFIX) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        COORDINATION_LIST_DEFAULT_LIMIT,
        COORDINATION_LIST_MAX_LIMIT,
      );
      const since = url.searchParams.get("since") ?? undefined;
      const until = url.searchParams.get("until") ?? undefined;
      const agentId = url.searchParams.get("agent_id") ?? undefined;
      const entries = await deps.handoffLog.query({
        limit,
        ...(since !== undefined ? { since } : {}),
        ...(until !== undefined ? { until } : {}),
        ...(agentId !== undefined ? { agent_id: agentId } : {}),
      });
      deps.auditLog.append(
        "l2",
        COORDINATION_VIEW_AUDIT_OPS.VIEW_OPENED,
        deps.operatorId,
        {
          fortress_id: deps.handoffLog.getFortressId(),
          result_count: entries.length,
          ...(since !== undefined ? { since } : {}),
          ...(until !== undefined ? { until } : {}),
          ...(agentId !== undefined ? { agent_id: agentId } : {}),
        },
      );
      writeJSON(res, 200, { ok: true, data: { entries } });
      return true;
    }

    const entryMatch = matchEntryRoute(path);
    if (method === "GET" && entryMatch) {
      const detail = await deps.handoffLog.getEntry(entryMatch.entryId);
      if (!detail) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      deps.auditLog.append(
        "l2",
        COORDINATION_VIEW_AUDIT_OPS.ENTRY_DRILLED,
        deps.operatorId,
        {
          fortress_id: deps.handoffLog.getFortressId(),
          entry_id: detail.entry.entry_id,
          event_class: detail.entry.event_class,
          source_agent_id: detail.entry.source_agent_id,
          target_agent_id: detail.entry.target_agent_id,
        },
      );
      writeJSON(res, 200, { ok: true, data: detail });
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
