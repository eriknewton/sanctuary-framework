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
import {
  publicCodeForStatus,
  sendCaughtError,
} from "../http/error-envelope.js";

import type { LocalHarnessKind } from "../contracts/v1.1/local-agent-records.js";
import { effectiveLivenessStatus } from "../contracts/v1.1/liveness.js";
import {
  HUB_AGENT_CONTROL_ACTIONS,
  HUB_API_PREFIX,
  HUB_AGENTS_DEFAULT_LIMIT,
  HUB_AGENTS_MAX_LIMIT,
  HUB_CHAT_MESSAGE_MAX_CHARS,
  HUB_CHAT_THREADS_DEFAULT_LIMIT,
  HUB_CHAT_THREADS_MAX_LIMIT,
  HUB_CHAT_TURNS_DEFAULT_LIMIT,
  HUB_CHAT_TURNS_MAX_LIMIT,
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
import {
  TASK_STATUSES,
  type TaskStatus,
} from "../operational/task-coordination/index.js";

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

function handleError(
  res: ServerResponse,
  err: unknown,
  opts: { operation: string; suppressPublicDetail?: boolean },
): void {
  if (err instanceof HubError) {
    if (opts.suppressPublicDetail === true) {
      sendCaughtError(res, err.statusCode, publicCodeForStatus(err.statusCode), err, {
        route: "hub",
        operation: opts.operation,
      });
      return;
    }
    writeJSON(res, err.statusCode, {
      ok: false,
      error: err.name,
      detail: err.publicDetail,
    });
    return;
  }
  sendCaughtError(res, 500, "internal_error", err, {
    route: "hub",
    operation: opts.operation,
  });
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
 * Match `/api/hub/chat/concierge/threads/<thread_id>` (WP-V1.3-9 Tau-1).
 * Returns null if the path does not match the expected shape, including
 * a missing or empty thread_id.
 */
function matchConciergeThreadRoute(
  path: string,
): { threadId: string } | null {
  const prefix = `${HUB_API_PREFIX}/chat/concierge/threads/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0 || rest.includes("/")) return null;
  const decoded = decodeURIComponent(rest);
  if (decoded.length === 0) return null;
  return { threadId: decoded };
}

/**
 * Parse the optional `?since=N` query param for the concierge memory
 * read route. Throws HubValidationError on a non-integer / negative
 * value; returns undefined when absent.
 */
function parseSince(raw: string | null): number | undefined {
  if (raw === null || raw === "") return undefined;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    throw new HubValidationError("since must be a non-negative integer");
  }
  return parsed;
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

function matchTaskRoute(path: string): {
  taskId: string;
  action: string | null;
} | null {
  const prefix = `${HUB_API_PREFIX}/tasks/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0) return null;
  const parts = rest.split("/");
  if (parts.length > 2) return null;
  const [taskId, action] = parts;
  if (!taskId) return null;
  return {
    taskId: decodeURIComponent(taskId),
    action: action ?? null,
  };
}

function isHubInboxAction(value: string): value is HubInboxAction {
  return (HUB_INBOX_ACTIONS as readonly string[]).includes(value);
}

/**
 * State-changing approval DECISIONS on the hub inbox: approve / deny
 * resolve a pending Tier-1 approval. `dismiss` is housekeeping, not a
 * release, so it is excluded. Kept in lockstep with the dispatch table's
 * `matchInboxRoute` so the auth gate cannot drift from routing.
 */
const HUB_APPROVAL_DECISION_ACTIONS = new Set(["approve", "deny"]);

function isHubApprovalDecisionPath(path: string): boolean {
  const match = matchInboxRoute(path);
  return match !== null && HUB_APPROVAL_DECISION_ACTIONS.has(match.action);
}

function isHubCustodyMutationPath(method: string, path: string): boolean {
  if (method !== "POST") return false;
  if (isHubApprovalDecisionPath(path)) return true;
  if (
    path === HUB_ROUTES.FORTRESS_LOCKDOWN ||
    path === HUB_ROUTES.FORTRESS_EXIT_BUNDLE_EXPORT
  ) {
    return true;
  }

  const agentMatch = matchAgentRoute(path);
  if (!agentMatch || agentMatch.remainder === null) return false;

  if (
    agentMatch.agentId === HUB_FORTRESS_AGENT_ID_SENTINEL &&
    (agentMatch.remainder === "lockdown" ||
      agentMatch.remainder === "exit-bundle/export")
  ) {
    return true;
  }

  // Tier-1 `policy_change` custody mutations: binding an agent's policy or
  // channel template enqueues a Tier-1 approval (operation_category
  // "policy_change" in hub-service `bindAgentPolicy`/`bindAgentChannelTemplate`).
  // A co-resident loopback caller must not enqueue these without the operator
  // bearer, so they ride the strict chokepoint alongside the control actions.
  if (agentMatch.remainder === "policy" || agentMatch.remainder === "template") {
    return true;
  }

  return isHubAgentControlAction(agentMatch.remainder);
}

/**
 * Operational (fleet-state) mutations on the hub that are NOT custody
 * decisions but still change persisted operator-visible state: task
 * control (create/update/assign/cancel) and inbox housekeeping
 * (dismiss). They were previously left on loopback auto-auth, so a
 * co-resident agent sharing the loopback interface could create or
 * re-route tasks, or dismiss inbox items, without the operator bearer.
 * They now ride the SAME strict chokepoint as the custody mutations:
 * the operator bearer is required even on loopback. This is the #800
 * follow-on for operational-mutation routes.
 *
 * Kept in lockstep with the dispatch table below (`matchTaskRoute`,
 * `matchInboxRoute`) so the auth gate cannot drift from routing.
 * Reads (GET list/detail) and the read-style concierge query keep
 * loopback auto-auth. Approval DECISIONS (approve/deny) and the fortress
 * custody routes are classified by `isHubCustodyMutationPath`, not here.
 */
function isHubOperationalMutationPath(method: string, path: string): boolean {
  // All inbox mutations are POSTs (`approve` / `deny` / `dismiss`). The
  // approval decisions are already strict via `isHubCustodyMutationPath`;
  // gating the whole inbox-action surface here adds `dismiss` (and fails
  // closed for any future action) without weakening the decision gate.
  if (method === "POST" && matchInboxRoute(path) !== null) {
    return true;
  }

  // Task control. `POST /tasks` creates; `PATCH /tasks/:id` changes
  // status; `POST /tasks/:id/assign` re-routes; `POST /tasks/:id/cancel`
  // cancels. All mutate fleet task state.
  if (method === "POST" && path === `${HUB_API_PREFIX}/tasks`) {
    return true;
  }
  const taskMatch = matchTaskRoute(path);
  if (taskMatch) {
    if (method === "PATCH" && taskMatch.action === null) return true;
    if (
      method === "POST" &&
      (taskMatch.action === "assign" || taskMatch.action === "cancel")
    ) {
      return true;
    }
  }

  return false;
}

function isHubAgentControlAction(
  value: string,
): value is HubAgentControlAction {
  return (HUB_AGENT_CONTROL_ACTIONS as readonly string[]).includes(value);
}

function isTaskStatus(value: string): value is TaskStatus {
  return (TASK_STATUSES as readonly string[]).includes(value);
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
  //
  // SECURITY (loopback-no-autoauth-for-custody): custody mutations must
  // ALWAYS require the operator bearer token, even on loopback with auto-auth
  // on, so a co-resident agent sharing loopback cannot trigger its own
  // custody-changing route. The strict subset is hub approval decisions,
  // fortress lockdown/export, and agent-control POSTs. Other hub routes
  // (read-only lists, read-style concierge query, policy/template binds)
  // keep the existing loopback auto-auth contract. `requireToken` only
  // suppresses the loopback shortcut; token validation is unchanged.
  //
  // SECURITY (#800 follow-on, operational mutations): operational
  // fleet-state mutations (task control, inbox dismiss) ALSO require the
  // operator bearer even on loopback, so a co-resident agent cannot
  // create/re-route tasks or dismiss inbox items tokenless. They ride the
  // same strict gate but are NOT custody decisions, so they do NOT
  // suppress public error detail (that suppression stays scoped to the
  // approval-decision custody routes below).
  const requiresOperatorBearer =
    isHubCustodyMutationPath(method, path) ||
    isHubOperationalMutationPath(method, path);
  const checkAuth = authMiddleware(
    deps.authConfig,
    requiresOperatorBearer ? { requireToken: true } : undefined,
  );
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

    // ── GET /api/hub/tasks ──────────────────────────────────────────
    if (method === "GET" && path === `${HUB_API_PREFIX}/tasks`) {
      const rawStatus = url.searchParams.get("status");
      if (rawStatus !== null && !isTaskStatus(rawStatus)) {
        throw new HubValidationError(
          `status must be one of: ${TASK_STATUSES.join(", ")}`,
        );
      }
      const tasks = await deps.service.listTasks({
        ...(rawStatus ? { status: rawStatus } : {}),
        ...(url.searchParams.get("assignee")
          ? { assignee: url.searchParams.get("assignee")! }
          : {}),
        ...(url.searchParams.get("creator")
          ? { creator: url.searchParams.get("creator")! }
          : {}),
      });
      writeJSON(res, 200, { ok: true, data: { tasks } });
      return true;
    }

    // ── POST /api/hub/tasks ─────────────────────────────────────────
    if (method === "POST" && path === `${HUB_API_PREFIX}/tasks`) {
      const body = await readJSONBody<{
        title?: unknown;
        description?: unknown;
        creator?: unknown;
        assignee?: unknown;
        parent_task_id?: unknown;
        metadata?: unknown;
      }>(req);
      if (typeof body.title !== "string") {
        throw new HubValidationError("title required");
      }
      if (typeof body.creator !== "string") {
        throw new HubValidationError("creator required");
      }
      const task = await deps.service.createTask({
        title: body.title,
        creator: body.creator,
        ...(typeof body.description === "string"
          ? { description: body.description }
          : {}),
        ...(typeof body.assignee === "string" ? { assignee: body.assignee } : {}),
        ...(typeof body.parent_task_id === "string"
          ? { parent_task_id: body.parent_task_id }
          : {}),
        ...(body.metadata &&
        typeof body.metadata === "object" &&
        !Array.isArray(body.metadata)
          ? { metadata: body.metadata as Record<string, unknown> }
          : {}),
      });
      writeJSON(res, 201, { ok: true, data: { task } });
      return true;
    }

    // ── POST /api/hub/concierge/ask ────────────────────────────────
    if (method === "POST" && path === `${HUB_API_PREFIX}/concierge/ask`) {
      const body = await readJSONBody<{
        question?: unknown;
        stream?: unknown;
        includePayloads?: unknown;
      }>(req);
      const question = checkChatMessage(body.question);
      const response = await deps.service.askConcierge({
        question,
        stream: body.stream === true,
        includePayloads: body.includePayloads === true,
      });
      writeJSON(res, 200, { ok: true, data: { response } });
      return true;
    }

    // ── GET /api/hub/concierge/status ──────────────────────────────
    if (method === "GET" && path === `${HUB_API_PREFIX}/concierge/status`) {
      const status = await deps.service.getConciergeStatus();
      writeJSON(res, 200, { ok: true, data: { status } });
      return true;
    }

    // ── /api/hub/tasks/:id and /api/hub/tasks/:id/<action> ──────────
    const taskMatch = matchTaskRoute(path);
    if (taskMatch) {
      if (method === "GET" && taskMatch.action === null) {
        const task = await deps.service.getTask(taskMatch.taskId);
        writeJSON(res, 200, { ok: true, data: { task } });
        return true;
      }

      if (method === "PATCH" && taskMatch.action === null) {
        const body = await readJSONBody<{
          status?: unknown;
          actor?: unknown;
        }>(req);
        if (typeof body.status !== "string" || !isTaskStatus(body.status)) {
          throw new HubValidationError(
            `status must be one of: ${TASK_STATUSES.join(", ")}`,
          );
        }
        if (typeof body.actor !== "string") {
          throw new HubValidationError("actor required");
        }
        const task = await deps.service.updateTaskStatus(taskMatch.taskId, {
          status: body.status,
          actor: body.actor,
        });
        writeJSON(res, 200, { ok: true, data: { task } });
        return true;
      }

      if (method === "POST" && taskMatch.action === "assign") {
        const body = await readJSONBody<{
          assignee?: unknown;
          actor?: unknown;
        }>(req);
        if (typeof body.assignee !== "string") {
          throw new HubValidationError("assignee required");
        }
        if (typeof body.actor !== "string") {
          throw new HubValidationError("actor required");
        }
        const task = await deps.service.assignTask(taskMatch.taskId, {
          assignee: body.assignee,
          actor: body.actor,
        });
        writeJSON(res, 200, { ok: true, data: { task } });
        return true;
      }

      if (method === "POST" && taskMatch.action === "cancel") {
        const body = await readJSONBody<{
          reason?: unknown;
          actor?: unknown;
        }>(req);
        if (typeof body.actor !== "string") {
          throw new HubValidationError("actor required");
        }
        const task = await deps.service.cancelTask(taskMatch.taskId, {
          actor: body.actor,
          ...(typeof body.reason === "string" ? { reason: body.reason } : {}),
        });
        writeJSON(res, 200, { ok: true, data: { task } });
        return true;
      }
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
      // Liveness aging: a stored `active` status is the last value written and
      // is never aged by the registry, so a crashed/dead agent would keep
      // reading "Running / online / protected / verified" on the fleet view.
      // Age a stale `active` (last_activity_at older than the window) down to
      // `unknown` before serving the read-projection, so the dashboard renders
      // unknown/away and drops the verified badge instead of a false-live state.
      const now = Date.now();
      const aged = records.map((r) => {
        const effective = effectiveLivenessStatus(r.status, r.last_activity_at, now);
        return effective === r.status ? r : { ...r, status: effective };
      });
      writeJSON(res, 200, { ok: true, data: { agents: aged } });
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

      // POST /api/hub/agents/:id/inspect/open
      // Click-to-inspect (WP-V1.2 reshape). Repurposes the click-to-chat
      // wire-up from PR #98 + PR #100; the panel returns recent activity,
      // pending Tier 1 approvals, and policy summary instead of opening
      // a chat session. Synchronous open shape preserved.
      if (method === "POST" && remainder === "inspect/open") {
        const panel = await deps.service.openAgentInspectPanel(agentId);
        writeJSON(res, 200, { ok: true, data: { panel } });
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

    // ── GET /api/hub/chat/concierge/threads ──────────────────────
    if (
      method === "GET" &&
      path === HUB_ROUTES.CHAT_CONCIERGE_THREADS_LIST
    ) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        HUB_CHAT_THREADS_DEFAULT_LIMIT,
        HUB_CHAT_THREADS_MAX_LIMIT,
      );
      const threads = await deps.service.listConciergeMemoryThreads({ limit });
      writeJSON(res, 200, { ok: true, data: { threads } });
      return true;
    }

    // ── GET / DELETE /api/hub/chat/concierge/threads/:thread_id ──
    {
      const threadMatch = matchConciergeThreadRoute(path);
      if (threadMatch) {
        if (method === "GET") {
          const since = parseSince(url.searchParams.get("since"));
          const limit = parseLimit(
            url.searchParams.get("limit"),
            HUB_CHAT_TURNS_DEFAULT_LIMIT,
            HUB_CHAT_TURNS_MAX_LIMIT,
          );
          const readOpts: { sinceTurnId?: number; limit: number } = { limit };
          if (since !== undefined) readOpts.sinceTurnId = since;
          const turns = await deps.service.readConciergeMemoryThread(
            threadMatch.threadId,
            readOpts,
          );
          writeJSON(res, 200, { ok: true, data: { turns } });
          return true;
        }
        if (method === "DELETE") {
          const removed = await deps.service.deleteConciergeMemoryThread(
            threadMatch.threadId,
          );
          writeJSON(res, removed ? 200 : 404, {
            ok: removed,
            data: { thread_id: threadMatch.threadId, removed },
          });
          return true;
        }
      }
    }

    // No hub route matched.
    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    handleError(res, err, {
      operation: `${method} ${path}`,
      suppressPublicDetail:
        method === "POST" && isHubApprovalDecisionPath(path),
    });
    return true;
  }
}
