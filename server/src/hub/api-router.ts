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
  HUB_INBOX_ACTIONS,
  HUB_INBOX_DEFAULT_LIMIT,
  HUB_INBOX_MAX_LIMIT,
  HUB_MAX_REQUEST_BODY_BYTES,
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
          channel_template_id?: unknown;
        }>(req);
        const record = await deps.service.bindAgentChannelTemplate(
          agentId,
          body.channel_template_id,
        );
        writeJSON(res, 200, { ok: true, data: { agent: record } });
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

    // No hub route matched.
    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    handleError(res, err);
    return true;
  }
}
