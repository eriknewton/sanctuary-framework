/**
 * Sanctuary Operator Console v1.0 -- API Router
 *
 * Routes for /api/console/* wiring to fortress-service, agent-contract-service,
 * policy-engine, chat-service, recovery-service, attestation-service.
 * Delegates only; owns no domain logic.
 *
 * Auth gate is the FIRST middleware on every route.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { AuthConfig } from "./auth-middleware.js";
import { authMiddleware } from "./auth-middleware.js";
import { CONSOLE_API_PREFIX, CONSOLE_HTML_PATH, API_ROUTES } from "./constants.js";
import type { ConsoleService } from "./console-service.js";
import { ConsoleError } from "./errors.js";
import { serveStaticFile } from "./serve-static.js";
import type { FortressTransitionRequest, PolicyCompileRequest, ChatSendRequest } from "./types.js";

// -----------------------------------------------------------------------
// JSON helpers
// -----------------------------------------------------------------------

function writeJSON(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

async function readJSONBody<T = unknown>(req: IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  let size = 0;
  const MAX = 256 * 1024;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  const body = Buffer.concat(chunks).toString("utf-8");
  if (!body) return {} as T;
  return JSON.parse(body) as T;
}

// -----------------------------------------------------------------------
// Router
// -----------------------------------------------------------------------

export interface ConsoleRouterDeps {
  authConfig: AuthConfig;
  service: ConsoleService;
  publicDir?: string;
}

/**
 * Handle a console request. Returns true if matched + handled.
 * Auth gate runs first on every matched route.
 */
export async function handleConsoleRoute(
  deps: ConsoleRouterDeps,
  req: IncomingMessage,
  res: ServerResponse
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  // Match console routes
  const isConsoleRoute =
    path === CONSOLE_HTML_PATH ||
    path === CONSOLE_HTML_PATH + "/" ||
    path.startsWith(CONSOLE_API_PREFIX + "/") ||
    path.startsWith("/console/");

  if (!isConsoleRoute) return false;

  // Auth gate: first middleware on every matched route
  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true; // 401 already sent

  // ── Static files: /console/*, /console ────────────────────────────
  if (method === "GET" && (path === CONSOLE_HTML_PATH || path === CONSOLE_HTML_PATH + "/" || path.startsWith("/console/"))) {
    const served = await serveStaticFile(res, path, deps.publicDir);
    if (served) return true;
    // Fall through to 404 if file not found
  }

  // ── Header badge ──────────────────────────────────────────────────
  if (method === "GET" && path === API_ROUTES.HEADER_BADGE) {
    try {
      const header = await deps.service.getHeader();
      writeJSON(res, 200, { ok: true, data: header });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  // ── Fortress mode ─────────────────────────────────────────────────
  if (method === "GET" && path === API_ROUTES.FORTRESS_MODE) {
    try {
      const view = await deps.service.getFortressView();
      writeJSON(res, 200, { ok: true, data: view });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  if (method === "POST" && path === API_ROUTES.FORTRESS_TRANSITION) {
    try {
      const body = await readJSONBody<FortressTransitionRequest>(req);
      const result = await deps.service.proposeTransition(body);
      writeJSON(res, 200, { ok: true, data: result });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  // ── Agent roster ──────────────────────────────────────────────────
  if (method === "GET" && path === API_ROUTES.AGENT_LIST) {
    try {
      const view = deps.service.getAgentRosterView();
      writeJSON(res, 200, { ok: true, data: view });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  if (method === "GET" && path === API_ROUTES.AGENT_BADGE) {
    try {
      const agentId = url.searchParams.get("agent_id") ?? "";
      const badge = deps.service.getAgentBadge(agentId);
      writeJSON(res, 200, { ok: true, data: badge });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  // Operator-triggered retry-state reset for a stuck red badge. Body:
  // `{ "agent_id": "<id>" }`. Returns the reset result so the dashboard
  // can flip the local UI immediately; the broadcast SSE event covers
  // any other connected dashboard tabs.
  if (method === "POST" && path === API_ROUTES.AGENT_RETRY_RESET) {
    try {
      const body = await readJSONBody<{ agent_id?: string }>(req);
      const result = deps.service.resetAgentRetryState(body.agent_id ?? "");
      writeJSON(res, 200, { ok: true, data: result });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  // ── Policy editor ─────────────────────────────────────────────────
  if (method === "GET" && path === API_ROUTES.POLICY_TEMPLATES) {
    try {
      const view = deps.service.getPolicyEditorView();
      writeJSON(res, 200, { ok: true, data: { templates: view.templates } });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  if (method === "POST" && path === API_ROUTES.POLICY_COMPILE) {
    try {
      const body = await readJSONBody<PolicyCompileRequest>(req);
      const result = await deps.service.compilePolicy(body);
      writeJSON(res, 200, { ok: true, data: result });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  // ── Chat ──────────────────────────────────────────────────────────
  if (method === "GET" && path === API_ROUTES.CHAT_GROUPS) {
    try {
      const view = deps.service.getChatView();
      writeJSON(res, 200, { ok: true, data: { groups: view.groups } });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  if (method === "GET" && path === API_ROUTES.CHAT_PRESENCE) {
    try {
      const view = deps.service.getChatView();
      writeJSON(res, 200, { ok: true, data: { presence: view.presence } });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  if (method === "GET" && path === API_ROUTES.CHAT_MESSAGES) {
    try {
      const groupId = url.searchParams.get("group_id") ?? "";
      const limit = parseInt(url.searchParams.get("limit") ?? "50", 10);
      const messages = await deps.service.getChatMessages(groupId, limit);
      writeJSON(res, 200, { ok: true, data: { messages } });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  if (method === "POST" && path === API_ROUTES.CHAT_SEND) {
    try {
      const body = await readJSONBody<ChatSendRequest>(req);
      const result = deps.service.sendChatMessage(body);
      writeJSON(res, 200, { ok: true, data: result });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  // ── Recovery ──────────────────────────────────────────────────────
  if (method === "GET" && path === API_ROUTES.RECOVERY_STATUS) {
    try {
      const view = deps.service.getRecoveryView();
      writeJSON(res, 200, { ok: true, data: view });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  if (method === "GET" && path === API_ROUTES.RECOVERY_GUARDIANS) {
    try {
      const view = deps.service.getRecoveryView();
      writeJSON(res, 200, { ok: true, data: { roster: view.roster, threshold_m: view.threshold_m, threshold_n: view.threshold_n } });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  if (method === "GET" && path === API_ROUTES.RECOVERY_DMSWITCH) {
    try {
      const view = deps.service.getRecoveryView();
      writeJSON(res, 200, { ok: true, data: { dmswitch: view.dmswitch } });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  // ── Audit log ─────────────────────────────────────────────────────
  if (method === "GET" && path === API_ROUTES.AUDIT_EVENTS) {
    try {
      const filtersParam = url.searchParams.get("filters");
      const filters = filtersParam ? filtersParam.split(",") : undefined;
      const limit = parseInt(url.searchParams.get("limit") ?? "100", 10);
      const view = deps.service.getAuditLogView(filters, limit);
      writeJSON(res, 200, { ok: true, data: view });
    } catch (err) {
      handleError(res, err);
    }
    return true;
  }

  // ── SSE events stream ─────────────────────────────────────────────
  if (method === "GET" && path === API_ROUTES.EVENTS) {
    deps.service.handleSSEConnection(res);
    return true;
  }

  // ── 404 ───────────────────────────────────────────────────────────
  writeJSON(res, 404, { ok: false, error: "not_found", path });
  return true;
}

function handleError(res: ServerResponse, err: unknown): void {
  if (err instanceof ConsoleError) {
    writeJSON(res, err.statusCode, {
      ok: false,
      error: err.name,
      detail: err.message,
    });
  } else {
    const msg = err instanceof Error ? err.message : String(err);
    writeJSON(res, 500, { ok: false, error: "internal", detail: msg });
  }
}
