/**
 * Sanctuary Dashboard — HTTP API + SSE
 *
 * Request router for the unified dashboard. Pure functions that
 * take a request + sources and produce a response so the transport
 * layer (node:http) and tests can exercise the same code paths.
 */

import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type {
  AggregatorSources,
  ProtectionSnapshot,
  PendingApproval,
  ActivityEntry,
} from "./aggregator.js";
import { getProtectionSnapshot } from "./aggregator.js";
import { renderDashboardHTML } from "./html.js";
import { listTemplates, getTemplateEntry, getTemplate } from "../templates/registry.js";
import { initTemplate } from "../templates/init.js";
import type { TemplateName } from "../templates/registry.js";
import { findTenant } from "../cli/agents/discovery.js";
import { dispatchV11Request } from "./v1_1/dispatch.js";
import type { V11Bindings } from "./v1_1/wiring.js";
import { constantTimeEquals } from "../http/auth.js";
import { getProcessInstance, getProcessSince } from "./process-identity.js";
import { logCaughtError } from "../http/error-envelope.js";
import { renderPostureHomeHTML } from "../principal-policy/posture-home-html.js";
import {
  renderMobileCompanionHTML,
  MOBILE_COMPANION_WEBMANIFEST,
  MOBILE_COMPANION_SERVICE_WORKER_JS,
  MOBILE_COMPANION_CSP,
  MOBILE_COMPANION_ROUTE_PREFIX,
} from "./mobile.js";
import {
  handlePostureRoute,
  POSTURE_AGENT_PATH_PREFIX,
  POSTURE_API_PREFIX,
  POSTURE_EVIDENCE_PATH,
  POSTURE_HOME_PATH,
} from "../principal-policy/posture-routes.js";
import { absentFleetRoster } from "../principal-policy/fleet-roster.js";
import type { FleetRoster } from "../principal-policy/fleet-roster.js";

export { constantTimeEquals };

export interface ApprovalHandlers {
  allow: (id: string) => Promise<boolean>;
  deny: (id: string) => Promise<boolean>;
}

export interface APIDeps {
  sources: AggregatorSources;
  authToken?: string;
  sessions?: DashboardSessionStore;
  approvals?: ApprovalHandlers;
  /** Register a listener; returns an unsubscribe fn. */
  onEvent?: (listener: (event: StreamEvent) => void) => () => void;
  /** Node ID for signed-event emissions (template init). */
  nodeId?: string;
  /** Node's Ed25519 private key for signing (template init). */
  nodePrivateKey?: Uint8Array;
  /** Principal ID for signed-event emissions (template init). */
  principalId?: string;
  /** Fortress ID for template init. */
  fortressId?: string;
  /**
   * Override the orphan-check for template init. Returns true when a
   * fortress is bound to the given agent_id. Default: resolves against
   * tenant discovery (`findTenant`).
   */
  isAgentWrapped?: (agentId: string) => Promise<boolean>;
  /**
   * v1.1.2 hotfix (Finding V): bound v1.1 hub bindings. When set, requests
   * to `/v1.1`, `/api/hub/*`, and `/api/identities` route through the
   * shared v1.1 dispatch helper before the legacy auth gate. When null
   * or undefined, the legacy route table handles the request and those
   * paths 404 (matches the pre-v1.1.2 behavior of this server).
   */
  v11Bindings?: V11Bindings | null;
  /**
   * v1.1.2 hotfix: when true, loopback requests bypass the bearer-token
   * check on /api/hub/* + /api/identities (mirrors PR #82's
   * `_autoAuthLocalhost` flag on the principal-policy dashboard).
   * Defaults to false; the wrap-auto dashboard sets true to keep the
   * operator UX one-click from the wrap-emitted URL.
   */
  loopbackAutoAuth?: boolean;
  /**
   * Honest readiness provider for the auth-gated `/api/readiness` endpoint
   * (Dashboard Server Lifecycle Hardening brief D3). Returns:
   *   - "serving": the fortress is unlocked and the read surface is live.
   *   - "locked": the process is up but not yet unlocked.
   * It must report real server state, never a guess. When omitted, the
   * endpoint derives an honest fallback from whether the identity manager
   * is wired (the read surface is supplied post-unlock via
   * `updateSources`, so its presence is a truthful "serving" proxy and its
   * absence is a truthful "locked"). NEVER exposed on `/api/health`.
   */
  readiness?: () => "locked" | "serving";
  /**
   * Honest Consumer-A agent-supervisor bridge readiness for
   * `/api/readiness`. Returns "wired" / "unwired" / "n/a". When a provider
   * is supplied it reports the REAL bridge state ("wired"/"unwired"). When
   * omitted, the honest default is "n/a" - and that is truthful here because
   * this api.ts dashboard is a read-only aggregator with NO Protect launch
   * route, so an absent bridge does NOT guarantee a 503 in this mode. (The
   * principal-policy dashboard, by contrast, DOES route Protect through its
   * bridge, so there an absent bridge => 503 and the honest value is
   * "unwired", never "n/a".) NEVER exposed on `/api/health`.
   */
  supervisorStatus?: () => "wired" | "unwired" | "n/a";
  /**
   * Read-only fleet-roster provider for the wrap ("Protect") dashboard's
   * fleet-roster panel. Returns the presenter output of `buildFleetRoster` over
   * this process's federation read-seam. Wired by the wrap CLI to a REAL,
   * disk-backed provider (`buildWrapFleetRosterProvider`) that reads the at-rest
   * fortress records; MAY be async because the wrap process runs no live
   * federation daemon and resolves the roster by reading disk per request.
   *
   * The SAME provider feeds two consumers on this server: the standalone-parity
   * `GET /api/fleet/roster` route AND the posture-route `GET /api/posture/fleet`
   * that the already-served posture-home fleet panel fetches. Passing one
   * provider to both keeps a single source of truth (no second trust path).
   *
   * Strictly read-only: there is no admit/revoke/rotate route here (those are a
   * later, deliberately separate slice), so the panel SEES and monitors the
   * fleet, it never manages trust. No key material crosses this seam - the
   * roster shape carries only public identifiers and posture metadata.
   *
   * When omitted (the common single-machine wrap install with no federation
   * wired), the route serves `absentFleetRoster()` - the honest "no fleet
   * configured" shape - never a fabricated roster or a greyed-green "all
   * admitted" shell. It must report REAL federation state, never a guess.
   */
  fleetRoster?: () => FleetRoster | Promise<FleetRoster>;
}

export interface DashboardSession {
  id: string;
  expiresInSeconds: number;
}

export interface DashboardSessionStore {
  create: () => DashboardSession;
  validate: (id: string) => boolean;
}

/**
 * SSE event taxonomy.
 *
 * v1.0 event names: `snapshot` (initial hydration), `activity` (audit feed
 * append), `approval` (pending approval surfaced).
 *
 * v1.1 added: `inbox` (HubInboxItem replace-or-prepend by item_id) and
 * `agent_status` (HubAgentStatusSnapshot replace by agent_id). The hub
 * service emits these via the existing `publish` interface; the producer
 * wires every name verbatim through `event: <type>` SSE frames.
 */
export interface StreamEvent {
  type: "snapshot" | "activity" | "approval" | "inbox" | "agent_status";
  data: unknown;
}

/**
 * Pull the bearer token from Authorization header only. Long-lived URL
 * query tokens are deliberately ignored; SSE uses short-lived sessions.
 */
export function extractToken(req: IncomingMessage, url: URL): string | null {
  const header = req.headers.authorization;
  if (header && header.startsWith("Bearer ")) {
    return header.slice(7).trim();
  }
  void url;
  return null;
}

export function isAuthorized(deps: APIDeps, req: IncomingMessage, url: URL): boolean {
  if (!deps.authToken) return true;
  const token = extractToken(req, url);
  if (token && constantTimeEquals(token, deps.authToken)) return true;

  const sessionId = url.searchParams.get("session");
  if (sessionId && deps.sessions?.validate(sessionId)) return true;

  return false;
}

function isAuthorizedWithBearerToken(deps: APIDeps, req: IncomingMessage, url: URL): boolean {
  if (!deps.authToken) return false;
  const token = extractToken(req, url);
  return token !== null && constantTimeEquals(token, deps.authToken);
}

function isLoopbackRequest(req: IncomingMessage): boolean {
  const addr = req.socket.remoteAddress;
  return addr === "127.0.0.1" || addr === "::1" || addr === "localhost";
}

function isAuthorizedForRead(deps: APIDeps, req: IncomingMessage, url: URL): boolean {
  return isAuthorized(deps, req, url) || (deps.loopbackAutoAuth === true && isLoopbackRequest(req));
}

function writeJSON(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

async function readJSONBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  const MAX = 256 * 1024;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  const body = Buffer.concat(chunks).toString("utf-8");
  if (!body) return {};
  return JSON.parse(body) as Record<string, unknown>;
}

/**
 * Generate an ephemeral 32-byte key for dashboard-initiated signing
 * when no persistent node key is configured.
 */
function generateEphemeralKey(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

function writeText(
  res: ServerResponse,
  status: number,
  body: string,
  contentType = "text/plain",
  extraHeaders?: Record<string, string>,
): void {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    ...(extraHeaders ?? {}),
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

  // ── Posture board shell (folded INTO the concierge default) ─────────
  // Default-flip (2026-06-30): `/` now serves the v1.1 concierge as the single
  // default surface (handled by the v1.1 dispatch below), and the posture board
  // is preserved at `/posture` AND folded into the concierge (the seal expands
  // to full posture detail; a Posture entry lives in the Verify group). This
  // block now owns ONLY `/posture`. `/api/status` keeps decision_capable false
  // below so the approval area stays read-only on this process.
  //
  // NOTE: `/posture` keeps its prior read-auth gate in this router (unchanged
  // by the default-flip). `/` falls through to the v1.1 dispatch, which serves
  // the concierge SPA tokenless and runs its own client-side auth dance,
  // exactly as `/dashboard` and `/v1.1` already do.
  if (method === "GET" && path === POSTURE_HOME_PATH) {
    if (!isAuthorizedForRead(deps, req, url)) {
      writeJSON(res, 401, { error: "unauthorized" });
      return true;
    }
    writeText(res, 200, renderPostureHomeHTML(), "text/html; charset=utf-8");
    return true;
  }

  // ── Mobile companion (PWA) -- slice 1: phone-as-approval ─────────────
  // Served TOKENLESS, exactly like the v1.1 concierge SPA: the shell carries
  // NO operator data and runs its own client-side auth (the operator's token
  // is sent only as a bearer header to the EXISTING gated /api routes -- see
  // ./mobile.ts for the full security posture). The service worker is
  // scope-limited to /m/ and never caches /api traffic.
  if (
    method === "GET" &&
    (path === MOBILE_COMPANION_ROUTE_PREFIX || path === `${MOBILE_COMPANION_ROUTE_PREFIX}/`)
  ) {
    writeText(res, 200, renderMobileCompanionHTML(), "text/html; charset=utf-8", {
      "Content-Security-Policy": MOBILE_COMPANION_CSP,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    });
    return true;
  }
  if (method === "GET" && path === `${MOBILE_COMPANION_ROUTE_PREFIX}/manifest.webmanifest`) {
    writeText(res, 200, MOBILE_COMPANION_WEBMANIFEST, "application/manifest+json; charset=utf-8", {
      "X-Content-Type-Options": "nosniff",
    });
    return true;
  }
  if (method === "GET" && path === `${MOBILE_COMPANION_ROUTE_PREFIX}/sw.js`) {
    writeText(res, 200, MOBILE_COMPANION_SERVICE_WORKER_JS, "text/javascript; charset=utf-8", {
      "X-Content-Type-Options": "nosniff",
      "Service-Worker-Allowed": "/m/",
    });
    return true;
  }

  if (
    path === POSTURE_API_PREFIX ||
    path.startsWith(`${POSTURE_API_PREFIX}/`) ||
    path === POSTURE_EVIDENCE_PATH ||
    path.startsWith(POSTURE_AGENT_PATH_PREFIX)
  ) {
    if (!isAuthorizedForRead(deps, req, url)) {
      writeJSON(res, 401, { error: "unauthorized" });
      return true;
    }
    const handled = await handlePostureRoute(
      {
        auditLog: deps.sources.auditLog ?? null,
        originMachine:
          deps.sources.identityManager?.getPrimaryIdentityId() ?? "local",
        listAgents: () => deps.v11Bindings?.hubService.listAgents() ?? [],
        resolvePinnedProducerKey: deps.sources.resolvePinnedProducerKey,
        producerKeyExpectedButUnavailable:
          deps.sources.producerKeyExpectedButUnavailable === true,
        resolveBrokerPinnedProducerKey:
          deps.sources.resolveBrokerPinnedProducerKey,
        brokerProducerKeyExpectedButUnavailable:
          deps.sources.brokerProducerKeyExpectedButUnavailable === true,
        resolveProtectionClaimSubject:
          deps.sources.resolveProtectionClaimSubject,
        resolveEnforcementAvailabilityStatus:
          deps.sources.resolveEnforcementAvailabilityStatus,
        // Fleet Console: pass the SAME read-only fleet-roster provider the
        // `/api/fleet/roster` route uses to the posture routes, so the already-
        // served posture-home fleet panel (`GET /api/posture/fleet`) lights up
        // on this wrap dashboard instead of 404ing. One provider, one trust
        // path. Absent -> the posture route 404s and the panel stays hidden
        // (honest "no fleet"), exactly as on an unfederated fortress.
        ...(deps.fleetRoster ? { fleetRoster: deps.fleetRoster } : {}),
      },
      req,
      res,
      url,
      method,
    );
    if (handled) return true;
  }

  // ── Session exchange ───────────────────────────────────────────────
  // Header-only by design: this is the only route that mints URL-carryable
  // short-lived sessions for EventSource and one-click operator URLs.
  if (method === "POST" && path === "/auth/session") {
    if (!deps.authToken) {
      writeJSON(res, 200, { session_id: "no-auth", expires_in_seconds: 0 });
      return true;
    }
    const token = extractToken(req, url);
    if (!token || !constantTimeEquals(token, deps.authToken)) {
      writeJSON(res, 401, { error: "unauthorized" });
      return true;
    }
    if (!deps.sessions) {
      writeJSON(res, 503, { error: "sessions_unavailable" });
      return true;
    }
    const session = deps.sessions.create();
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Set-Cookie": `sanctuary_session=${session.id}; Path=/; SameSite=Strict; Max-Age=${session.expiresInSeconds}`,
    });
    res.end(JSON.stringify({
      session_id: session.id,
      expires_in_seconds: session.expiresInSeconds,
    }));
    return true;
  }

  // ── v1.1 dispatch (v1.1.2 hotfix, Finding V) ────────────────────────
  // Try v1.1 compatibility routes first when bindings are set. Mounted at
  // /dashboard + /v1.1 (HTML) and /api/hub/* (API). After the default-flip
  // (2026-06-30) `/` falls THROUGH to this dispatch and is served by the
  // v1.1 concierge as the single default surface; `/posture` is the posture
  // shell handled above.
  //
  // Auth gating is intentionally inside the shared helper so the v1.1
  // HTML at /v1.1 can serve unauthenticated (the inline client handles
  // its own auth dance) while /api/hub/* and /api/identities honor the
  // same bearer-token + loopback-auto-auth contract as legacy /api/*.
  if (deps.v11Bindings) {
    const handled = await dispatchV11Request(
      {
        bindings: deps.v11Bindings,
        ...(deps.authToken !== undefined ? { authToken: deps.authToken } : {}),
        loopbackAutoAuth: deps.loopbackAutoAuth ?? false,
      },
      req,
      res,
      url,
      method,
    );
    if (handled) return true;
  }

  // ── `/` posture-shell fallback when v1.1 bindings are absent ─────────
  // Default-flip (2026-06-30): `/` normally serves the v1.1 concierge via the
  // dispatch above. But that dispatch is gated on `deps.v11Bindings`, which is
  // null in two reachable windows: (a) the startup race between listen() and
  // setV11Bindings(), and (b) the permanent degraded path where buildV11Bindings
  // throws and setV11Bindings is therefore never called (wrap/cli.ts swallows the
  // throw and prints a note). Without this fallback `/` would skip both the
  // posture block above (now `/posture`-only) and the v1.1 dispatch, fall through
  // to `return false`, and 404 - a regression from the pre-flip behavior where
  // `/` always served the posture shell. This mirrors the principal-policy
  // router's `isRootServedAsShell` fallback (principal-policy/dashboard.ts): when
  // there is no concierge to fall through to, `/` keeps serving the posture board
  // shell as the honest degraded surface rather than 404ing. Same read-auth gate
  // the posture block above and the pre-flip `/` used.
  if (method === "GET" && path === "/" && !deps.v11Bindings) {
    if (!isAuthorizedForRead(deps, req, url)) {
      writeJSON(res, 401, { error: "unauthorized" });
      return true;
    }
    writeText(res, 200, renderPostureHomeHTML(), "text/html; charset=utf-8");
    return true;
  }

  // ── Health (unauthenticated liveness only) ───────────────────────────
  // Mirrors the principal-policy dashboard contract exactly: `{ ok, mode }`
  // plus the opaque per-process `instance` + `since` (restart-detection
  // signal, brief D3). No state, config, posture, agent, token, count, or
  // readiness data: `ready`/`supervisor` are auth-gated on /api/readiness
  // because an unauthenticated `ready: locked` would be a co-resident-agent
  // oracle for fortress-unlock state (brief HIGH-1).
  if (method === "GET" && path === "/api/health") {
    writeJSON(res, 200, {
      ok: true,
      mode: deps.sources.mode,
      instance: getProcessInstance(),
      since: getProcessSince(),
    });
    return true;
  }

  // ── Readiness (AUTH-GATED, brief D3) ─────────────────────────────────
  // Separate from /api/health precisely because `ready`/`supervisor` would
  // be a co-resident-agent oracle if unauthenticated (brief HIGH-1). Uses
  // the SAME read-auth as the other authenticated read routes
  // (bearer token, session, or loopback auto-auth). Reports readiness, never
  // posture: "serving" means "unlocked and the read surface is live", NOT
  // "your agents are protected" - protection truth stays exclusively on
  // /api/posture/castle-wall (evidence-gated). No state/config/agent/tenant
  // /token/count data leaks here either.
  if (method === "GET" && path === "/api/readiness") {
    if (!isAuthorizedForRead(deps, req, url)) {
      writeJSON(res, 401, { error: "unauthorized" });
      return true;
    }
    const ready = deps.readiness
      ? deps.readiness()
      : deps.sources.identityManager
        ? "serving"
        : "locked";
    // `supervisor` reports the REAL bridge state when a provider is supplied
    // ("wired"/"unwired"). "n/a" is honest ONLY here because this co-located /
    // unified read-aggregator dashboard has NO Protect launch route at all
    // (no launchProtect; getProtectionSnapshot is the read-only posture view,
    // not Protect execution). A missing bridge therefore does NOT guarantee a
    // 503 in this mode, so "not applicable" is the truthful default - unlike
    // the principal-policy dashboard, where an absent bridge guarantees a
    // Protect 503 and the honest value is "unwired".
    const supervisor = deps.supervisorStatus ? deps.supervisorStatus() : "n/a";
    writeJSON(res, 200, { ready, supervisor });
    return true;
  }

  // ── Auth (all routes) ───────────────────────────────────────────────
  const isFoldedReadAuxiliary =
    method === "GET" &&
    (path === "/api/status" ||
      path === "/api/pending" ||
      path === "/api/stream");
  const authorized = isFoldedReadAuxiliary
    ? isAuthorizedForRead(deps, req, url)
    : isAuthorized(deps, req, url);
  if (!authorized) {
    writeJSON(res, 401, { error: "unauthorized" });
    return true;
  }

  // ── Folded posture-page auxiliaries ─────────────────────────────────
  if (method === "GET" && path === "/api/status") {
    writeJSON(res, 200, {
      pending_count: deps.sources.pendingApprovals?.length ?? 0,
      connected_clients: 0,
      standalone_mode: false,
      decision_capable: false,
      policy: deps.sources.policy
        ? {
            version: deps.sources.policy.version,
            tier1_always_approve: deps.sources.policy.tier1_always_approve,
            tier2_anomaly: deps.sources.policy.tier2_anomaly,
            tier3_always_allow: deps.sources.policy.tier3_always_allow,
            approval_channel: {
              type: deps.sources.policy.approval_channel.type,
              timeout_seconds: deps.sources.policy.approval_channel.timeout_seconds,
              auto_deny: true,
            },
            approval_redirect: {
              enabled: deps.sources.policy.approval_redirect?.enabled === true,
              mode:
                deps.sources.policy.approval_redirect?.mode === "notify"
                  ? "notify"
                  : "replace",
            },
          }
        : {
            approval_redirect: { enabled: false, mode: "replace" },
          },
    });
    return true;
  }

  if (method === "GET" && path === "/api/pending") {
    writeJSON(res, 200, deps.sources.pendingApprovals ?? []);
    return true;
  }

  // ── Fleet roster (read-only; SEE-not-manage) ────────────────────────
  // The wrap ("Protect") dashboard's fleet-roster panel. This is the auth-gated
  // (the shared gate above already ran and 401'd an unauthenticated caller
  // before reaching here), STRICTLY read-only view of the fleet: it SEES and
  // monitors the machines the federation layer knows, and never manages trust
  // (there is no admit/revoke/rotate route here - that is a later slice). It
  // carries no key material.
  //
  // When no federation read-seam is wired on this process (the common
  // single-machine install), it serves the honest `absentFleetRoster()` shape -
  // `available: false`, empty nodes, all-zero summaries - never a fabricated
  // roster or a greyed-green "all admitted" shell over a fortress with no fleet.
  if (method === "GET" && path === "/api/fleet/roster") {
    const roster = deps.fleetRoster
      ? await deps.fleetRoster()
      : absentFleetRoster();
    writeJSON(res, 200, roster);
    return true;
  }

  // ── Legacy v1.0 HTML (preserved at /v1.0) ───────────────────────────
  // Default-flip: root serves the v1.1 concierge (via dispatchV11 above);
  // /dashboard and /v1.1 remain compatibility aliases; /posture serves the
  // posture shell above. The legacy four-panel dashboard moved to /v1.0 so
  // operators who explicitly want the prior surface can reach it; /index.html
  // alias preserved on the legacy path.
  if (
    method === "GET" &&
    (path === "/v1.0" || path === "/v1.0/" || path === "/v1.0/index.html")
  ) {
    const snapshot = await getProtectionSnapshot(deps.sources);
    const html = renderDashboardHTML({ snapshot });
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
    if (!isAuthorizedWithBearerToken(deps, req, url)) {
      writeJSON(res, 401, { error: "unauthorized" });
      return true;
    }
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
      logCaughtError(
        err,
        { route: "/api/approvals/:id/:action", operation: action },
        { status: 500 },
      );
      writeJSON(res, 500, { error: "approval_failed" });
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
      logCaughtError(
        err,
        { route: "/api/templates", operation: "list_templates" },
        { status: 500 },
      );
      writeJSON(res, 500, { error: "template_load_failed" });
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
      logCaughtError(
        err,
        { route: "/api/templates/:name", operation: "get_template" },
        { status: 500 },
      );
      writeJSON(res, 500, { error: "template_load_failed" });
    }
    return true;
  }

  // ── Template init (POST) ───────────────────────────────────────────
  // SECURITY (templates-init-operator-bearer): template init AUTHORS and
  // Ed25519-SIGNS a governance policy event for an agent, a custody-class
  // mutation, the same trust level as an approval decision. It MUST require
  // the operator bearer token (fail-closed: no token configured => reject),
  // matching the `/api/approvals/:id/:action` gate above. The shared
  // `isAuthorized` gate at the top of this handler fail-OPENS when no token
  // is configured and honors loopback auto-auth, neither of which is
  // acceptable for a mutation: a co-resident wrapped agent shares loopback
  // with the operator, so loopback origin is NOT operator identity.
  const initMatch = /^\/api\/templates\/([^/]+)\/init$/.exec(path);
  if (method === "POST" && initMatch) {
    if (!isAuthorizedWithBearerToken(deps, req, url)) {
      writeJSON(res, 401, { error: "unauthorized" });
      return true;
    }
    const name = decodeURIComponent(initMatch[1]!);
    try {
      // Validate template exists
      const bundle = getTemplate(name);
      if (!bundle) {
        writeJSON(res, 404, { error: "template_not_found", name });
        return true;
      }

      // Read request body
      const body = await readJSONBody(req);

      // Validate required fields
      if (!body.agent_name || typeof body.agent_name !== "string") {
        writeJSON(res, 400, {
          error: "validation_error",
          message: "agent_name is required and must be a string",
        });
        return true;
      }

      // Validate agent_name format (alphanumeric, hyphens, underscores)
      if (!/^[a-zA-Z0-9_-]+$/.test(body.agent_name)) {
        writeJSON(res, 400, {
          error: "validation_error",
          message: "agent_name must contain only alphanumeric characters, hyphens, and underscores",
        });
        return true;
      }

      // Orphan-reject: a channel-shape template binds to an already-wrapped
      // harness. A template init against an agent_id with no fortress behind
      // it would author a policy artifact bound to nothing, which is the
      // runtime-drift surface the v1.0.0-rc.2 back-out closed. Sanctuary
      // ships channel-shape governance templates, not named-agent runtimes.
      const isAgentWrapped =
        deps.isAgentWrapped ?? (async (agentId: string) => {
          const tenant = await findTenant(agentId);
          if (!tenant) return false;
          return tenant.initialized || tenant.has_profile;
        });
      if (!(await isAgentWrapped(body.agent_name))) {
        writeJSON(res, 400, {
          error: "orphan_agent_id",
          message:
            `No wrapped harness found for agent_id "${body.agent_name}". ` +
            `Run \`sanctuary wrap\` to wrap the harness first, then retry template init.`,
        });
        return true;
      }

      // Build init params, routing through the same code path as CLI
      const nodeId = deps.nodeId ?? "dashboard-node";
      const nodePrivateKey = deps.nodePrivateKey ?? generateEphemeralKey();
      const principalId = deps.principalId ?? "dashboard-principal";
      const fortressId = deps.fortressId ?? "default";

      const result = initTemplate({
        template_name: name as TemplateName,
        agent_id: body.agent_name,
        fortress_id: fortressId,
        counterparty: "*",
        policy_version: 1,
        emitter_node: nodeId,
        emitter_principal: principalId,
        monotonic_seq: 1,
        node_private_key: nodePrivateKey,
      });

      writeJSON(res, 200, {
        agent_id: body.agent_name,
        signed_event_id: result.signed_event.event_id,
        policy_version: result.compiled.policy_version,
        template_name: name,
        attestation_panel_url: `/console#agent_roster`,
      });
    } catch (err) {
      logCaughtError(
        err,
        { route: "/api/templates/:name/init", operation: "init_template" },
        { status: 500 },
      );
      writeJSON(res, 500, { error: "template_init_failed" });
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
