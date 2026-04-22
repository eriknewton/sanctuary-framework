/**
 * Sanctuary Operator Console v1.0 — HTTP API.
 *
 * Routes served under `/api/console/*` and the console HTML at `/console`.
 * Auth model mirrors the existing dashboard: Bearer token header or
 * `?token=` query string, constant-time compared; loopback auto-auth is
 * inherited from the host `principal-policy/dashboard.ts` server when
 * mounted there.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import {
  constantTimeEquals,
  extractToken,
} from "../dashboard/api.js";
import type { MeshConsoleClient } from "./client.js";
import { renderConsoleHTML } from "./html.js";
import {
  MeshConsoleError,
  MeshConsoleJoinDecisionError,
  MeshConsoleReservedSurfaceError,
  MeshConsoleUnknownEventTypeError,
} from "./errors.js";
import type {
  AlertAckInput,
  ConsoleSSEEvent,
  JoinDecisionInput,
  PolicyComposeInput,
  RevokeInput,
} from "./types.js";

export interface ConsoleAPIDeps {
  client: MeshConsoleClient;
  authToken?: string;
  /** When true, loopback (127.0.0.1 / ::1) requests bypass auth. */
  loopbackAutoAuth?: boolean;
}

function writeJSON(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function writeText(
  res: ServerResponse,
  status: number,
  body: string,
  contentType = "text/plain"
): void {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function isLoopback(req: IncomingMessage): boolean {
  const addr = req.socket.remoteAddress ?? "";
  return (
    addr === "127.0.0.1" ||
    addr === "::1" ||
    addr === "::ffff:127.0.0.1"
  );
}

function isAuthorized(deps: ConsoleAPIDeps, req: IncomingMessage, url: URL): boolean {
  if (deps.loopbackAutoAuth && isLoopback(req)) return true;
  if (!deps.authToken) return true;
  const token = extractToken(req, url);
  if (!token) return false;
  return constantTimeEquals(token, deps.authToken);
}

async function readJSONBody<T = unknown>(req: IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  let size = 0;
  const MAX = 256 * 1024; // 256 KB cap
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX) {
      throw new Error("request body too large");
    }
    chunks.push(chunk as Buffer);
  }
  const body = Buffer.concat(chunks).toString("utf-8");
  if (!body) return {} as T;
  return JSON.parse(body) as T;
}

function mapConsoleError(err: unknown): { status: number; payload: { error: string; detail?: string } } {
  if (err instanceof MeshConsoleReservedSurfaceError) {
    return { status: 400, payload: { error: "reserved_surface", detail: err.message } };
  }
  if (err instanceof MeshConsoleUnknownEventTypeError) {
    return { status: 400, payload: { error: "unknown_event_type", detail: err.message } };
  }
  if (err instanceof MeshConsoleJoinDecisionError) {
    return { status: 404, payload: { error: "join_not_found", detail: err.message } };
  }
  if (err instanceof MeshConsoleError) {
    return { status: 400, payload: { error: "console_error", detail: err.message } };
  }
  const msg = err instanceof Error ? err.message : String(err);
  return { status: 500, payload: { error: "internal", detail: msg } };
}

/**
 * Route console requests. Returns true if matched + handled; false if the
 * path didn't match so the caller can fall through to other routers (the
 * principal-policy dashboard mounts this alongside its own routes).
 */
export async function handleConsoleRequest(
  deps: ConsoleAPIDeps,
  req: IncomingMessage,
  res: ServerResponse
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  // Gate every console route behind auth BEFORE deciding route matching — we
  // still want a 401 if someone hits `/console` without auth, not a 404.
  const routeMatches =
    path === "/console" ||
    path === "/console/" ||
    path.startsWith("/api/console/");
  if (!routeMatches) return false;

  if (!isAuthorized(deps, req, url)) {
    writeJSON(res, 401, { error: "unauthorized" });
    return true;
  }

  // ── GET /console — HTML ─────────────────────────────────────────────
  if (method === "GET" && (path === "/console" || path === "/console/")) {
    const html = renderConsoleHTML(deps.client);
    writeText(res, 200, html, "text/html; charset=utf-8");
    return true;
  }

  // ── GET /api/console/state — full snapshot JSON ─────────────────────
  if (method === "GET" && path === "/api/console/state") {
    writeJSON(res, 200, deps.client.snapshot());
    return true;
  }

  // ── GET /api/console/navigation ─────────────────────────────────────
  if (method === "GET" && path === "/api/console/navigation") {
    writeJSON(res, 200, { items: deps.client.listNavigation() });
    return true;
  }

  // ── GET /api/console/fortress / agents / alerts / joins / recovery ──
  if (method === "GET" && path === "/api/console/fortress") {
    writeJSON(res, 200, deps.client.fortressOverview());
    return true;
  }
  if (method === "GET" && path === "/api/console/agents") {
    writeJSON(res, 200, deps.client.agentsPanel());
    return true;
  }
  if (method === "GET" && path === "/api/console/alerts") {
    writeJSON(res, 200, deps.client.alertInbox());
    return true;
  }
  if (method === "GET" && path === "/api/console/joins") {
    writeJSON(res, 200, { pending: deps.client.pendingJoinsSnapshot() });
    return true;
  }
  if (method === "GET" && path === "/api/console/recovery") {
    writeJSON(res, 200, deps.client.recoveryEntry());
    return true;
  }
  if (method === "GET" && path === "/api/console/policies") {
    writeJSON(res, 200, { pinned: deps.client.getPinnedPolicies() });
    return true;
  }
  if (method === "GET" && path === "/api/console/templates") {
    writeJSON(res, 200, {
      templates: deps.client.listChannelTemplates().map((t) => ({
        id: t.id,
        label: t.label,
        description: t.description,
      })),
    });
    return true;
  }

  // ── POST /api/console/policy/compose ────────────────────────────────
  if (method === "POST" && path === "/api/console/policy/compose") {
    try {
      const body = await readJSONBody<PolicyComposeInput>(req);
      const result = await deps.client.composePolicy(body);
      writeJSON(res, 200, result);
    } catch (err) {
      const { status, payload } = mapConsoleError(err);
      writeJSON(res, status, payload);
    }
    return true;
  }

  // ── POST /api/console/join/decide ───────────────────────────────────
  if (method === "POST" && path === "/api/console/join/decide") {
    try {
      const body = await readJSONBody<JoinDecisionInput>(req);
      deps.client.resolveJoinDecision(body);
      writeJSON(res, 200, { ok: true, request_id: body.request_id });
    } catch (err) {
      const { status, payload } = mapConsoleError(err);
      writeJSON(res, status, payload);
    }
    return true;
  }

  // ── POST /api/console/alerts/ack ────────────────────────────────────
  if (method === "POST" && path === "/api/console/alerts/ack") {
    try {
      const body = await readJSONBody<AlertAckInput>(req);
      const row = deps.client.acknowledgeAlert(body);
      writeJSON(res, 200, row);
    } catch (err) {
      const { status, payload } = mapConsoleError(err);
      writeJSON(res, status, payload);
    }
    return true;
  }

  // ── POST /api/console/nodes/revoke ──────────────────────────────────
  if (method === "POST" && path === "/api/console/nodes/revoke") {
    try {
      const body = await readJSONBody<RevokeInput>(req);
      const event = await deps.client.revokeNode(body);
      writeJSON(res, 200, {
        signed_event_id: event.event_id,
        signature_scheme: "ed25519-v1",
      });
    } catch (err) {
      const { status, payload } = mapConsoleError(err);
      writeJSON(res, status, payload);
    }
    return true;
  }

  // ── GET /api/console/stream — SSE ───────────────────────────────────
  if (method === "GET" && path === "/api/console/stream") {
    await handleStream(deps, res);
    return true;
  }

  writeJSON(res, 404, { error: "not_found", path });
  return true;
}

async function handleStream(
  deps: ConsoleAPIDeps,
  res: ServerResponse
): Promise<void> {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });

  // Initial hydration: send the full client state so the browser can bootstrap.
  try {
    res.write(
      `event: hydrate\ndata: ${JSON.stringify(deps.client.snapshot())}\n\n`
    );
  } catch {
    // socket gone
    return;
  }

  const unsubscribe = deps.client.onEvent((evt: ConsoleSSEEvent) => {
    try {
      res.write(`data: ${JSON.stringify(evt)}\n\n`);
    } catch {
      // socket gone — cleanup fires via `close`
    }
  });

  const keepAlive = setInterval(() => {
    try {
      res.write(": keepalive\n\n");
    } catch {
      /* ignore */
    }
  }, 25_000);

  const cleanup = () => {
    clearInterval(keepAlive);
    unsubscribe();
  };
  res.on("close", cleanup);
  res.on("error", cleanup);
}
