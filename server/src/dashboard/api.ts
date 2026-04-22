/**
 * Sanctuary Dashboard — HTTP API + SSE
 *
 * Request router for the unified dashboard. Pure functions that
 * take a request + sources and produce a response so the transport
 * layer (node:http) and tests can exercise the same code paths.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type {
  AggregatorSources,
  ProtectionSnapshot,
  PendingApproval,
  ActivityEntry,
} from "./aggregator.js";
import { getProtectionSnapshot } from "./aggregator.js";
import { renderDashboardHTML } from "./html.js";
import { listTemplates, getTemplateEntry } from "../templates/registry.js";

export interface ApprovalHandlers {
  allow: (id: string) => Promise<boolean>;
  deny: (id: string) => Promise<boolean>;
}

export interface APIDeps {
  sources: AggregatorSources;
  authToken?: string;
  approvals?: ApprovalHandlers;
  /** Register a listener; returns an unsubscribe fn. */
  onEvent?: (listener: (event: StreamEvent) => void) => () => void;
}

export interface StreamEvent {
  type: "snapshot" | "activity" | "approval";
  data: unknown;
}

/**
 * Constant-time token comparison to avoid trivial timing attacks.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Pull the bearer token from Authorization header or ?token= query.
 */
export function extractToken(req: IncomingMessage, url: URL): string | null {
  const header = req.headers.authorization;
  if (header && header.startsWith("Bearer ")) {
    return header.slice(7).trim();
  }
  const q = url.searchParams.get("token");
  return q ?? null;
}

export function isAuthorized(deps: APIDeps, req: IncomingMessage, url: URL): boolean {
  if (!deps.authToken) return true;
  const token = extractToken(req, url);
  if (!token) return false;
  return constantTimeEquals(token, deps.authToken);
}

function writeJSON(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function writeText(res: ServerResponse, status: number, body: string, contentType = "text/plain"): void {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

/**
 * Handle a single incoming HTTP request. Returns true if the route
 * matched and was served; false to allow the caller to 404.
 */
export async function handleRequest(
  deps: APIDeps,
  req: IncomingMessage,
  res: ServerResponse
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  // ── Auth (all routes) ───────────────────────────────────────────────
  if (!isAuthorized(deps, req, url)) {
    writeJSON(res, 401, { error: "unauthorized" });
    return true;
  }

  // ── Health (unauthenticated-safe, but we still require auth above) ──
  if (method === "GET" && path === "/api/health") {
    writeJSON(res, 200, { ok: true, mode: deps.sources.mode });
    return true;
  }

  // ── Root HTML ───────────────────────────────────────────────────────
  if (method === "GET" && (path === "/" || path === "/index.html")) {
    const snapshot = await getProtectionSnapshot(deps.sources);
    const html = renderDashboardHTML({ snapshot, authToken: deps.authToken });
    writeText(res, 200, html, "text/html; charset=utf-8");
    return true;
  }

  // ── Snapshot JSON ───────────────────────────────────────────────────
  if (method === "GET" && path === "/api/snapshot") {
    const snapshot = await getProtectionSnapshot(deps.sources);
    writeJSON(res, 200, snapshot);
    return true;
  }

  // ── Approval decisions ──────────────────────────────────────────────
  const approvalMatch = /^\/api\/approvals\/([^/]+)\/(allow|deny)$/.exec(path);
  if (method === "POST" && approvalMatch) {
    const id = decodeURIComponent(approvalMatch[1]!);
    const action = approvalMatch[2] as "allow" | "deny";
    if (!deps.approvals) {
      writeJSON(res, 503, { error: "approvals_unavailable" });
      return true;
    }
    const handler = action === "allow" ? deps.approvals.allow : deps.approvals.deny;
    try {
      const ok = await handler(id);
      writeJSON(res, ok ? 200 : 404, { id, action, ok });
    } catch (err) {
      writeJSON(res, 500, { error: "approval_failed", message: (err as Error).message });
    }
    return true;
  }

  // ── SSE stream ──────────────────────────────────────────────────────
  if (method === "GET" && path === "/api/stream") {
    await handleStream(deps, res);
    return true;
  }

  // ── Template registry (read-only) ─────────────────────────────────
  if (method === "GET" && path === "/api/templates") {
    try {
      const templates = listTemplates();
      writeJSON(res, 200, { templates });
    } catch (err) {
      writeJSON(res, 500, {
        error: "template_load_failed",
        message: (err as Error).message,
      });
    }
    return true;
  }

  const templateMatch = /^\/api\/templates\/([^/]+)$/.exec(path);
  if (method === "GET" && templateMatch) {
    const name = decodeURIComponent(templateMatch[1]!);
    try {
      const entry = getTemplateEntry(name);
      if (!entry) {
        writeJSON(res, 404, { error: "template_not_found", name });
        return true;
      }
      writeJSON(res, 200, entry);
    } catch (err) {
      writeJSON(res, 500, {
        error: "template_load_failed",
        message: (err as Error).message,
      });
    }
    return true;
  }

  return false;
}

async function handleStream(deps: APIDeps, res: ServerResponse): Promise<void> {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });

  // Initial snapshot
  const snapshot = await getProtectionSnapshot(deps.sources);
  res.write(`event: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n`);

  const unsubscribe = deps.onEvent
    ? deps.onEvent((event) => {
        try {
          res.write(`event: ${event.type}\ndata: ${JSON.stringify(event.data)}\n\n`);
        } catch {
          // socket gone — cleanup happens in 'close'
        }
      })
    : () => {};

  const keepAlive = setInterval(() => {
    try {
      res.write(": keepalive\n\n");
    } catch {
      // ignore
    }
  }, 25_000);

  const cleanup = () => {
    clearInterval(keepAlive);
    unsubscribe();
  };

  res.on("close", cleanup);
  res.on("error", cleanup);
}

// Re-export helpers used by tests
export type { ProtectionSnapshot, PendingApproval, ActivityEntry };
