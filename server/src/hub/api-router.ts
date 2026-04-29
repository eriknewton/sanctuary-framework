/**
 * Sanctuary v1.1. Operator Hub API Router
 *
 * HTTP route surface for the v1.1 operator hub. Mirrors the v1.0 console
 * router shape so dashboard glue (Prompt 8) can wire either endpoint set
 * with the same machinery.
 *
 * Auth invariant:
 * Every route runs through the existing `authMiddleware` from
 * `server/src/console/auth-middleware.ts`. No new auth path is introduced
 * here. Loopback auto-auth + bearer-token gating come from the same
 * implementation as the v1.0 console.
 *
 * Local-only invariant:
 * Routes reject query parameters and body fields that would extend hub
 * behavior across fortress boundaries (e.g., `fortress_id`, `peer_id`).
 * v1.3 federation introduces a separate surface.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";

import type { LocalHarnessKind } from "../contracts/v1.1/local-agent-records.js";
import {
  HUB_AGENT_CONTROL_ACTIONS,
  HUB_API_PREFIX,
  HUB_AGENTS_DEFAULT_LIMIT,
  HUB_AGENTS_MAX_LIMIT,
  HUB_CHAT_MESSAGE_MAX_CHARS,
  HUB_FORTRESS_AGENT_ID_SENTINEL,
  HUB_INBOX_ACTIONS,
  HUB_INBOX_DEFAULT_LIMIT,
  HUB_INBOX_MAX_LIMIT,
  HUB_MAX_REQUEST_BODY_BYTES,
  HUB_ROUTES,
  type HubAgentControlAction,
  type HubInboxAction,
} from "./constants.js";
import {
  HubError,
  HubLocalOnlyError,
  HubValidationError,
} from "./errors.js";
import type { HubService } from "./hub-service.js";

export interface HubRouterDeps {
  authConfig: AuthConfig;
  service: HubService;
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

async function readJSONBody<T = Record<string, unknown>>(
  req: IncomingMessage,
): Promise<T> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > HUB_MAX_REQUEST_BODY_BYTES) {
      throw new HubValidationError("request body too large");
    }
    chunks.push(buf);
  }
  const body = Buffer.concat(chunks).toString("utf-8");
  if (!body) return {} as T;
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new HubValidationError("request body is not valid JSON");
  }
}

function parseLimit(
  raw: string | null,
  defaultValue: number,
  max: number,
): number {
  if (raw === null || raw === "") return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    throw new HubValidationError("limit must be a non-negative integer");
  }
  return Math.min(parsed, max);
}

function rejectCrossFortressParams(url: URL): void {
  for (const reserved of ["fortress_id", "peer_id", "remote_fortress_id"]) {
    if (url.searchParams.has(reserved)) {
      throw new HubLocalOnlyError(
        `query parameter '${reserved}' is not supported at v1.1 (cross-fortress reach)`,
      );
    }
  }
}

function handleError(res: ServerResponse, err: unknown): void {
  if (err instanceof HubError) {
    writeJSON(res, err.statusCode, {
      ok: false,
      error: err.name,
      detail: err.message,
    });
    return;
  }
  const msg = err instanceof Error ? err.message : String(err);
  writeJSON(res, 500, { ok: false, error: "internal", detail: msg });
}

/**
 * Match `/api/hub/agents/<id>/<action>` and `/api/hub/agents/<id>` patterns.
 * Returns null if no match.
 */
function matchAgentRoute(path: string): {
  agentId: string;
  remainder: string | null;
} | null {
  const prefix = `${HUB_API_PREFIX}/agents/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0) return null;
  const slash = rest.indexOf("/");
  if (slash === -1) {
    return { agentId: decodeURIComponent(rest), remainder: null };
  }
  return {
    agentId: decodeURIComponent(rest.slice(0, slash)),
    remainder: rest.slice(slash + 1),
  };
}

/**
 * Match `/api/hub/chat/agents/<id>/<remainder>` and
 * `/api/hub/chat/agents/<id>` patterns. Returns null if the path is
 * not under the chat-agents prefix.
 */
function matchChatAgentRoute(path: string): {
  agentId: string;
  remainder: string | null;
} | null {
  const prefix = `${HUB_API_PREFIX}/chat/agents/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0) return null;
  const slash = rest.indexOf("/");
  if (slash === -1) {
    return { agentId: decodeURIComponent(rest), remainder: null };
  }
  return {
    agentId: decodeURIComponent(rest.slice(0, slash)),
    remainder: rest.slice(slash + 1),
  };
}

/**
 * Pull a non-empty chat message body out of a request body. Throws
 * HubValidationError when the body is missing, the wrong type, or
 * exceeds the per-message length cap.
 */
function checkChatMessage(value: unknown): string {
  if (typeof value !== "string") {
    throw new HubValidationError("message must be a string");
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw new HubValidationError("message must not be empty");
  }
  if (trimmed.length > HUB_CHAT_MESSAGE_MAX_CHARS) {
    throw new HubValidationError(
      `message exceeds ${HUB_CHAT_MESSAGE_MAX_CHARS}-character cap`,
    );
  }
  return trimmed;
}

/**
 * Match `/api/hub/inbox/<id>/<action>` pattern.
 */
function matchInboxRoute(path: string): {
  itemId: string;
  action: string;
} | null {
  const prefix = `${HUB_API_PREFIX}/inbox/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  const parts = rest.split("/");
  if (parts.length !== 2) return null;
  const [itemId, action] = parts;
  if (!itemId || !action) return null;
  return { itemId: decodeURIComponent(itemId), action };
}

function isHubInboxAction(value: string): value is HubInboxAction {
  return (HUB_INBOX_ACTIONS as readonly string[]).includes(value);
}

function isHubAgentControlAction(
  value: string,
): value is HubAgentControlAction {
  return (HUB_AGENT_CONTROL_ACTIONS as readonly string[]).includes(value);
}

function parseHarnessFilter(
  raw: string | null,
): LocalHarnessKind[] | undefined {
  if (!raw) return undefined;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s): s is LocalHarnessKind => s.length > 0) as LocalHarnessKind[];
}

/**
 * Handle a hub request. Returns true if the route matched and was served.
 * Returns false to allow the caller to 404.
 */
export async function handleHubRoute(
  deps: HubRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (!path.startsWith(`${HUB_API_PREFIX}/`)) return false;

  // Auth gate: first middleware on every matched route. Reuses console
  // auth middleware verbatim. No new auth path.
  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  try {
    rejectCrossFortressParams(url);

    // ── GET /api/hub/inbox ──────────────────────────────────────────
    if (method === "GET" && path === `${HUB_API_PREFIX}/inbox`) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        HUB_INBOX_DEFAULT_LIMIT,
        HUB_INBOX_MAX_LIMIT,
      );
      const items = deps.service.listInbox().slice(0, limit);
      writeJSON(res, 200, { ok: true, data: { items } });
      return true;
    }

    // ── POST /api/hub/inbox/:id/:action ─────────────────────────────
    const inboxMatch = matchInboxRoute(path);
    if (method === "POST" && inboxMatch) {
      if (!isHubInboxAction(inboxMatch.action)) {
        throw new HubValidationError(
          `unknown inbox action: ${inboxMatch.action}`,
        );
      }
      const item = await deps.service.resolveInboxItem(
        inboxMatch.itemId,
        inboxMatch.action,
      );
      writeJSON(res, 200, { ok: true, data: { item } });
      return true;
    }

    // ── POST /api/hub/fortress/lockdown ─────────────────────────────
    if (
      method === "POST" &&
      path === HUB_ROUTES.FORTRESS_LOCKDOWN
    ) {
      const result = deps.service.enqueueFortressLockdown();
      writeJSON(res, 202, { ok: true, data: result });
      return true;
    }

    // ── POST /api/hub/fortress/exit-bundle/export ───────────────────
    if (
      method === "POST" &&
      path === HUB_ROUTES.FORTRESS_EXIT_BUNDLE_EXPORT
    ) {
      const result = deps.service.enqueueFortressExportBundle();
      writeJSON(res, 202, { ok: true, data: result });
      return true;
    }

    // ── GET /api/hub/agents (+ filters) ─────────────────────────────
    if (method === "GET" && path === `${HUB_API_PREFIX}/agents`) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        HUB_AGENTS_DEFAULT_LIMIT,
        HUB_AGENTS_MAX_LIMIT,
      );
      const cursor = url.searchParams.get("cursor") ?? undefined;
      const harnessesRaw = url.searchParams.get("harnesses");
      const filter = {
        ...(cursor !== undefined ? { cursor } : {}),
        limit,
        ...(harnessesRaw !== null && harnessesRaw !== ""
          ? { harnesses: parseHarnessFilter(harnessesRaw) }
          : {}),
      };
      const records = deps.service.listAgents(filter);
      writeJSON(res, 200, { ok: true, data: { agents: records } });
      return true;
    }

    // ── /api/hub/agents/:id and /api/hub/agents/:id/<remainder> ─────
    const agentMatch = matchAgentRoute(path);
    if (agentMatch) {
      const { agentId, remainder } = agentMatch;

      // Routing-layer alias for the v1.1 dashboard's existing call paths.
      // The dashboard sends `/api/hub/agents/all/lockdown` and
      // `/api/hub/agents/all/exit-bundle/export` as fortress-scope. The
      // canonical paths are HUB_ROUTES.FORTRESS_*; this branch keeps the
      // dashboard's 404 toast workaround retired without touching the
      // dashboard. Cross-fortress params already rejected above.
      if (
        method === "POST" &&
        agentId === HUB_FORTRESS_AGENT_ID_SENTINEL
      ) {
        if (remainder === "lockdown") {
          const result = deps.service.enqueueFortressLockdown();
          writeJSON(res, 202, { ok: true, data: result });
          return true;
        }
        if (remainder === "exit-bundle/export") {
          const result = deps.service.enqueueFortressExportBundle();
          writeJSON(res, 202, { ok: true, data: result });
          return true;
        }
        // Other remainders fall through and 404 below; the sentinel is
        // only an alias for the two fortress-scope Tier 1 actions.
      }

      // GET /api/hub/agents/:id
      if (method === "GET" && remainder === null) {
        const record = deps.service.getAgent(agentId);
        const snapshot = deps.service.getAgentStatusSnapshot(agentId);
        writeJSON(res, 200, {
          ok: true,
          data: { agent: record, snapshot },
        });
        return true;
      }

      // POST /api/hub/agents/:id/policy
      if (method === "POST" && remainder === "policy") {
        const body = await readJSONBody<{ policy_id?: unknown }>(req);
        if (typeof body.policy_id !== "string" || !body.policy_id) {
          throw new HubValidationError("policy_id required (string)");
        }
        const result = deps.service.bindAgentPolicy(agentId, body.policy_id);
        writeJSON(res, 202, { ok: true, data: result });
        return true;
      }

      // POST /api/hub/agents/:id/template
      if (method === "POST" && remainder === "template") {
        const body = await readJSONBody<{
          template_id?: unknown;
          channel_template_id?: unknown;
        }>(req);
        const result = deps.service.bindAgentChannelTemplate(
          agentId,
          body.template_id ?? body.channel_template_id,
        );
        writeJSON(res, 202, { ok: true, data: result });
        return true;
      }

      // POST /api/hub/agents/:id/<control-action>
      if (method === "POST" && remainder !== null) {
        if (!isHubAgentControlAction(remainder)) {
          throw new HubValidationError(
            `unknown agent control action: ${remainder}`,
          );
        }
        const result = await deps.service.controlAgent(agentId, remainder);
        // Tier 1 deferrals return 202 Accepted; immediate transitions 200.
        const status =
          "status" in result && result.status === "approval_pending"
            ? 202
            : 200;
        writeJSON(res, status, { ok: true, data: result });
        return true;
      }
    }

    // ── GET /api/hub/activity ───────────────────────────────────────
    if (method === "GET" && path === `${HUB_API_PREFIX}/activity`) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        50,
        500,
      );
      const since = url.searchParams.get("since") ?? undefined;
      const agentId = url.searchParams.get("agent_id") ?? undefined;
      const categoryRaw = url.searchParams.get("category") ?? undefined;
      const filter = {
        limit,
        ...(since !== undefined ? { since } : {}),
        ...(agentId !== undefined ? { agent_id: agentId } : {}),
        ...(categoryRaw !== undefined
          ? {
              category:
                categoryRaw as Parameters<
                  HubService["listActivity"]
                >[0]["category"],
            }
          : {}),
      };
      const entries = await deps.service.listActivity(filter);
      writeJSON(res, 200, { ok: true, data: { entries } });
      return true;
    }

    // ── GET /api/hub/policies ───────────────────────────────────────
    if (method === "GET" && path === `${HUB_API_PREFIX}/policies`) {
      const policies = deps.service.listPolicySummaries();
      writeJSON(res, 200, { ok: true, data: { policies } });
      return true;
    }

    // ── GET /api/hub/budgets ────────────────────────────────────────
    if (method === "GET" && path === `${HUB_API_PREFIX}/budgets`) {
      const budgets = deps.service.listBudgetSummaries();
      writeJSON(res, 200, { ok: true, data: { budgets } });
      return true;
    }

    // ── POST /api/hub/chat/concierge ─────────────────────────────
    if (
      method === "POST" &&
      path === HUB_ROUTES.CHAT_CONCIERGE_SEND
    ) {
      const body = await readJSONBody<{ message?: unknown }>(req);
      const message = checkChatMessage(body.message);
      const result = await deps.service.sendConcierge(message);
      writeJSON(res, 200, { ok: true, data: result });
      return true;
    }

    // ── GET /api/hub/chat/concierge/history ──────────────────────
    if (
      method === "GET" &&
      path === HUB_ROUTES.CHAT_CONCIERGE_HISTORY
    ) {
      const messages = await deps.service.getConciergeHistory();
      writeJSON(res, 200, { ok: true, data: { messages } });
      return true;
    }

    // ── GET /api/hub/chat/sessions ───────────────────────────────
    if (
      method === "GET" &&
      path === HUB_ROUTES.CHAT_SESSIONS_LIST
    ) {
      const sessions = deps.service.listActiveDirectAgentSessions();
      writeJSON(res, 200, { ok: true, data: { sessions } });
      return true;
    }

    // ── /api/hub/chat/agents/:id/* ───────────────────────────────
    const chatAgentMatch = matchChatAgentRoute(path);
    if (chatAgentMatch) {
      const { agentId, remainder } = chatAgentMatch;

      // GET /api/hub/chat/agents/:id/history
      if (method === "GET" && remainder === "history") {
        const messages = await deps.service.getDirectAgentHistory(agentId);
        writeJSON(res, 200, { ok: true, data: { messages } });
        return true;
      }

      // POST /api/hub/chat/agents/:id/session/start
      if (method === "POST" && remainder === "session/start") {
        const body = await readJSONBody<{ expires_at?: unknown }>(req);
        let expiresAtIso: string | undefined;
        if (body.expires_at !== undefined) {
          if (typeof body.expires_at !== "string") {
            throw new HubValidationError(
              "expires_at must be an ISO8601 string",
            );
          }
          if (Number.isNaN(Date.parse(body.expires_at))) {
            throw new HubValidationError(
              "expires_at must be a parseable ISO8601 timestamp",
            );
          }
          expiresAtIso = body.expires_at;
        }
        const result = deps.service.requestDirectAgentSession(
          agentId,
          expiresAtIso,
        );
        writeJSON(res, 202, { ok: true, data: result });
        return true;
      }

      // POST /api/hub/chat/agents/:id/session/end
      if (method === "POST" && remainder === "session/end") {
        const body = await readJSONBody<{ session_id?: unknown }>(req);
        if (
          typeof body.session_id !== "string" ||
          body.session_id.length === 0
        ) {
          throw new HubValidationError("session_id required");
        }
        const session = await deps.service.closeDirectAgentSession(
          body.session_id,
        );
        writeJSON(res, 200, { ok: true, data: { session } });
        return true;
      }

      // POST /api/hub/chat/agents/:id/message
      if (method === "POST" && remainder === "message") {
        const body = await readJSONBody<{
          message?: unknown;
          session_id?: unknown;
        }>(req);
        const message = checkChatMessage(body.message);
        if (
          typeof body.session_id !== "string" ||
          body.session_id.length === 0
        ) {
          throw new HubValidationError("session_id required");
        }
        const result = await deps.service.sendDirectAgentMessage(
          body.session_id,
          message,
        );
        // The session bound by `body.session_id` MUST belong to
        // `agentId`; the chat-service throws HubNotFoundError if not.
        // Defense in depth: validate the session.agent_id matches the
        // url path explicitly here.
        if (result.session.agent_id !== agentId) {
          throw new HubValidationError(
            "session_id does not belong to this agent",
          );
        }
        writeJSON(res, 200, { ok: true, data: result });
        return true;
      }
    }

    // No hub route matched.
    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    handleError(res, err);
    return true;
  }
}
