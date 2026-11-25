/**
 * Operator dashboard routes for local tasks. principal-policy/dashboard.ts
 * authenticates every route here in `dispatchLocal` before this file runs,
 * with loopback auto-auth denied: only the operator bearer, or a session or
 * cookie minted from it, is admitted. Nothing here is reachable from an
 * agent-facing path.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { LocalOperatorStores, neutralizeControlText } from "./operator-surface.js";
import { OPLOG_MAX_ROWS } from "./oplog.js";
import { isRequestId } from "./store-record.js";

export const LOCAL_API_PREFIX = "/api/local/";
export const LOCAL_PAGE_PATH = "/local";

/**
 * The operator-auth route table for local tasks. Must match the dispatch in
 * handleLocalRoute below and the `/api/local/` gate in principal-policy/dashboard.ts.
 */
export const LOCAL_DASHBOARD_ROUTES = [
  { method: "GET", path: LOCAL_PAGE_PATH },
  { method: "GET", path: "/api/local/status" },
  { method: "GET", path: "/api/local/results" },
  { method: "GET", path: "/api/local/results/:id" },
  { method: "POST", path: "/api/local/results/:id/delete" },
  { method: "GET", path: "/api/local/log" },
] as const;

/**
 * Shown on the status route when the authority holds no armed binding. Must match the status
 * assertions in test/local-recompile/dashboard-local.test.ts.
 */
export const LOCAL_AUTHORITY_NOTICE =
  "Local tasks are not ready: the local model binding did not verify. A binding set up or changed after the server started needs a server restart.";

/** One page of log rows for the dashboard view. */
export const LOCAL_LOG_VIEW_ROWS = 200;

/** Fixed text above every summary; must match the page script below. */
export const LOCAL_SUMMARY_NOTICE =
  "This was written by your local model from your stored records. Check it before pasting it anywhere, including back to an agent.";

/** The arming state the status route reports; compose.ts's LocalTaskStatus satisfies it. */
export interface LocalSurfaceStatus {
  readonly armed: boolean;
  readonly cause: string | null;
  /** Null when the authority would grant a valid job now; otherwise why every job is refused. */
  authorityCause(): string | null;
  workerPid(): number | undefined;
  queueDepth(): number;
}

export interface LocalDashboardSurface {
  status: LocalSurfaceStatus;
  /** The model tag of the verified local binding, or null when there is none. */
  modelTag(): string | null;
  /** Null when the stores could not be opened; result and log routes then answer 503. */
  stores: LocalOperatorStores | null;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

export function isPidAlive(pid: number | undefined): boolean {
  // Only a real process id is signalled: 0 and negative ids name process groups, and signal 0 to
  // them would report a group alive.
  if (pid === undefined || !Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Serve one local-task route; returns false when the path is not one of LOCAL_DASHBOARD_ROUTES. */
export async function handleLocalRoute(surface: LocalDashboardSurface, req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const method = req.method ?? "GET";
  const path = url.pathname;

  if (method === "GET" && path === LOCAL_PAGE_PATH) {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      // The page runs only its own inline script and fetches only this origin.
      "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
    });
    res.end(LOCAL_PAGE_HTML);
    return true;
  }
  if (method === "GET" && path === "/api/local/status") {
    const pid = surface.status.workerPid();
    const authorityCause = surface.status.authorityCause();
    // Ready only when the tool is armed and the authority would grant a valid job; otherwise the cause.
    json(res, 200, {
      armed: surface.status.armed,
      ready: surface.status.armed && authorityCause === null,
      cause: surface.status.cause,
      authority_cause: authorityCause,
      ...(authorityCause === null ? {} : { notice: LOCAL_AUTHORITY_NOTICE }),
      queue_depth: surface.status.queueDepth(),
      worker_alive: isPidAlive(pid),
      model_tag: surface.modelTag(),
    });
    return true;
  }

  const stores = surface.stores;
  const isResultsRoute = path === "/api/local/results" || path.startsWith("/api/local/results/");
  if (!isResultsRoute && path !== "/api/local/log") return false;
  if (stores === null) {
    json(res, 503, { error: "local stores unavailable" });
    return true;
  }

  if (method === "GET" && path === "/api/local/results") {
    json(res, 200, { results: await stores.listResults() });
    return true;
  }
  if (method === "GET" && path === "/api/local/log") {
    const since = Number(url.searchParams.get("since") ?? "0");
    if (!Number.isSafeInteger(since) || since < 0) {
      json(res, 400, { error: "invalid since" });
      return true;
    }
    const read = await stores.readLog(since, Math.min(LOCAL_LOG_VIEW_ROWS, OPLOG_MAX_ROWS));
    if (!read.ok) json(res, 409, { error: "log chain broken", seq: read.break.seq, reason: read.break.reason });
    else json(res, 200, { head_seq: read.status.head_seq, rows: read.rows });
    return true;
  }

  const parts = path.slice("/api/local/results/".length).split("/");
  const id = parts[0] ?? "";
  if (!isRequestId(id)) return false;
  if (method === "GET" && parts.length === 1) {
    // Opening a detail view writes the render row before the result is read out.
    const object = await stores.viewResult(id);
    if (object === null) json(res, 404, { error: "not found" });
    else json(res, 200, { result: { ...object, body: object.body ? neutralizedBody(object.body) : null } });
    return true;
  }
  if (method === "POST" && parts.length === 2 && parts[1] === "delete") {
    // The store writes the delete row before removing the object.
    const deleted = await stores.deleteResult(id);
    json(res, deleted ? 200 : 404, deleted ? { deleted: id } : { error: "not found" });
    return true;
  }
  return false;
}

function neutralizedBody(body: Record<string, string | string[]>): Record<string, string | string[]> {
  return Object.fromEntries(
    Object.entries(body).map(([key, value]) => [key, Array.isArray(value) ? value.map(neutralizeControlText) : neutralizeControlText(value)]),
  );
}

/**
 * The "Local tasks" page. Every value from a result is set with textContent,
 * never as markup, and no link in model text is made clickable.
 */
export const LOCAL_PAGE_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sanctuary: Local tasks</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:60rem}li{cursor:pointer;margin:.25rem 0}
#summary{white-space:pre-wrap;border:1px solid #888;padding:1rem}#notice{font-weight:600}</style></head>
<body><h1>Local tasks</h1>
<p id="status"></p>
<ul id="list"></ul>
<section id="detail" hidden>
<p id="notice"></p>
<pre id="summary"></pre>
<ul id="sources"></ul>
<button id="delete" type="button">Delete this result</button>
</section>
<script>
const NOTICE = ${JSON.stringify(LOCAL_SUMMARY_NOTICE)};
const el = (id) => document.getElementById(id);
// The routes refuse loopback position alone, so the page passes on the session it was opened with.
const SESSION = new URLSearchParams(location.search).get("session");
function withSession(path) { return SESSION ? path + (path.includes("?") ? "&" : "?") + "session=" + encodeURIComponent(SESSION) : path; }
async function get(path, init) {
  const res = await fetch(withSession(path), { credentials: "same-origin", ...init });
  if (res.status === 401) { el("status").textContent = "Sign in to the Sanctuary dashboard to see local tasks."; throw new Error("unauthenticated"); }
  return res.json();
}
async function refresh() {
  const status = await get("/api/local/status");
  el("status").textContent = status.armed ? "Local tasks are on." : "Local tasks are off (" + status.cause + ").";
  const data = await get("/api/local/results");
  const list = el("list");
  list.replaceChildren();
  for (const item of data.results || []) {
    const li = document.createElement("li");
    li.textContent = item.request_id + "  " + item.state + "  " + new Date(item.created_at).toISOString();
    li.addEventListener("click", () => show(item.request_id));
    list.append(li);
  }
}
async function show(id) {
  const data = await get("/api/local/results/" + encodeURIComponent(id));
  const body = (data.result && data.result.body) || {};
  el("notice").textContent = NOTICE;
  el("summary").textContent = typeof body.summary === "string" ? body.summary : "";
  const sources = el("sources");
  sources.replaceChildren();
  for (const ref of body.refs || []) { const li = document.createElement("li"); li.textContent = ref; sources.append(li); }
  el("delete").onclick = async () => { await get("/api/local/results/" + encodeURIComponent(id) + "/delete", { method: "POST" }); el("detail").hidden = true; refresh(); };
  el("detail").hidden = false;
}
refresh();
</script></body></html>
`;
