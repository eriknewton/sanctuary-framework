/**
 * Sanctuary MCP Server — Principal Dashboard
 *
 * HTTP-based approval channel that serves a real-time web dashboard
 * for human principals to approve/deny agent operations.
 *
 * Architecture:
 * - Node.js built-in `http`/`https` modules (no Express or external deps)
 * - SSE (Server-Sent Events) for real-time push to browser
 * - Pending approval requests block the MCP tool call via Promise
 * - Human clicks approve/deny in browser → POST /api/approve/:id → Promise resolves
 * - Timeout fallback: auto-deny (or auto-approve) if no response
 *
 * Security invariants:
 * - Binds to 127.0.0.1 by default (localhost only)
 * - Optional bearer token authentication for non-localhost deployments
 * - Optional TLS (HTTPS) via cert/key paths
 * - All decisions are audit-logged
 * - Agent cannot access the dashboard (it runs outside MCP stdin/stdout)
 */

import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { exec } from "node:child_process";
import { platform } from "node:os";
import { SANCTUARY_VERSION as PKG_VERSION } from "../config.js";
import type { SanctuaryConfig } from "../config.js";
import type { ApprovalChannel } from "./approval-channel.js";
import type { ApprovalRequest, ApprovalResponse, PrincipalPolicy } from "./types.js";
import type { BaselineTracker } from "./baseline.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type { HandshakeResult } from "../handshake/types.js";
// SignedSHR type available via shr/types if needed in future
import { generateSHR, type SHRGeneratorOptions } from "../shr/generator.js";
import { generateDashboardHTML, generateLoginHTML } from "./dashboard-html.js";
import { generateFortressViewHTML } from "../cocoon/fortress-view.js";
import type { SovereigntyProfileStore, SovereigntyProfileUpdate, UpstreamServer } from "../sovereignty-profile.js";
import { generateSystemPrompt } from "../system-prompt-generator.js";
import type { ClientManager } from "../proxy/client-manager.js";
import { dispatchV11Request } from "../dashboard/v1_1/dispatch.js";
import type { V11Bindings } from "../dashboard/v1_1/wiring.js";
import type { ApprovalAggregator } from "./approval-aggregator.js";
import {
  APPROVAL_INBOX_API_PREFIX,
  handleApprovalInboxRoute,
} from "./approval-aggregator-routes.js";
import type { SentinelDispatcher } from "../sentinel/sentinel-dispatcher.js";
import {
  SENTINEL_API_PREFIX,
  handleSentinelRoute,
} from "../sentinel/sentinel-routes.js";
import type { HandoffLog } from "../coordination/handoff-log.js";
import {
  COORDINATION_API_PREFIX,
  type HandoffEventBridge,
  handleCoordinationRoute,
} from "../coordination/handoff-routes.js";

// ── Types ───────────────────────────────────────────────────────────────

export interface DashboardConfig {
  port: number;
  host: string;
  timeout_seconds: number;
  /** SEC-002: auto_deny is always true. Field retained for interface compat but ignored. */
  auto_deny?: boolean;
  /** Bearer token for API authentication. If omitted, auth is disabled. */
  auth_token?: string;
  /** TLS configuration for HTTPS. If omitted, plain HTTP is used. */
  tls?: {
    cert_path: string;
    key_path: string;
  };
  /** Auto-open the dashboard in the default browser on startup. Default: true for localhost. */
  auto_open?: boolean;
}

interface PendingRequest {
  id: string;
  request: ApprovalRequest;
  resolve: (response: ApprovalResponse) => void;
  timer: ReturnType<typeof setTimeout>;
  created_at: string;
}

type SSEClient = ServerResponse;

// ── Dashboard Approval Channel ──────────────────────────────────────────

// ── Session Store ────────────────────────────────────────────────────
// Short-lived sessions replace the long-lived auth token in URLs (SEC-012).

interface DashboardSession {
  id: string;
  created_at: number;
  expires_at: number;
}

const SESSION_TTL_REMOTE_MS = 5 * 60 * 1000;  // 5 minutes for remote/TLS
const SESSION_TTL_LOCAL_MS = 24 * 60 * 60 * 1000; // 24 hours for localhost
const MAX_SESSIONS = 1000;

// ── Rate Limiting ───────────────────────────────────────────────────
// Sliding-window rate limiting per remote address.
// Decision endpoints (approve/deny) have a tighter limit than general API.

const RATE_LIMIT_WINDOW_MS = 60_000; // 1-minute window
const RATE_LIMIT_GENERAL = 120;       // max general API requests per window
const RATE_LIMIT_DECISIONS = 20;      // max approve/deny decisions per window
const MAX_RATE_LIMIT_ENTRIES = 10_000; // cap the tracking map to prevent memory exhaustion

interface RateLimitEntry {
  general: number[];   // timestamps of general requests
  decisions: number[]; // timestamps of decision requests
}

/**
 * Classify a request as an HTML/SSE "view" route that must remain unthrottled.
 * Operator page loads, refreshes, and the single long-lived SSE stream are
 * exempt from the general rate limit so the dashboard never 429s the user out
 * of their own UI. API endpoints still hit the rate limiter so loops or scrapes
 * are throttled.
 */
export function isDashboardViewRoute(method: string, path: string): boolean {
  if (method !== "GET") return false;
  return (
    path === "/" ||
    path === "/dashboard" ||
    path === "/v1.0" ||
    path === "/fortress" ||
    path === "/events"
  );
}

export class DashboardApprovalChannel implements ApprovalChannel {
  private config: DashboardConfig;
  private pending: Map<string, PendingRequest> = new Map();
  private sseClients: Set<SSEClient> = new Set();
  private httpServer: ReturnType<typeof createHttpServer> | null = null;
  private policy: PrincipalPolicy | null = null;
  private baseline: BaselineTracker | null = null;
  private auditLog: AuditLog | null = null;
  private identityManager: IdentityManager | null = null;
  private handshakeResults: Map<string, HandshakeResult> | null = null;
  private shrOpts: SHRGeneratorOptions | null = null;
  private _sanctuaryConfig: SanctuaryConfig | null = null;
  private profileStore: SovereigntyProfileStore | null = null;
  private clientManager: ClientManager | null = null;
  private dashboardHTML: string;
  private fortressHTML: string | null = null;
  private loginHTML: string;
  private authToken: string | undefined;
  private useTLS: boolean;
  /** Session TTL: longer for localhost, shorter for remote */
  private sessionTTLMs: number;
  /** SEC-012: Short-lived session store. Sessions replace URL query tokens. */
  private sessions: Map<string, DashboardSession> = new Map();
  private sessionCleanupTimer: ReturnType<typeof setInterval> | null = null;
  /** Rate limiting: per-IP request tracking */
  private rateLimits: Map<string, RateLimitEntry> = new Map();
  /** Whether the dashboard is running in standalone mode (no MCP server) */
  private _standaloneMode = false;
  /**
   * v0.10.2: when set, requests from loopback addresses (127.0.0.1 / ::1)
   * are treated as authenticated without requiring a Bearer token or
   * dashboard session cookie. Only the `startStandaloneDashboard` boot
   * path enables this, and ONLY after the supplied passphrase successfully
   * decrypts at least one stored identity — proving the caller already
   * holds the primary secret that protects every piece of Sanctuary state.
   *
   * Rationale: the dashboard auth token is a dashboard-access credential
   * layered on top of the master-key unlock. Once the operator has already
   * presented the passphrase on the command line (terminal-side auth), a
   * second login prompt in the auto-opened browser just trains users to
   * paste secrets into web forms — the exact habit Sanctuary exists to
   * discourage. Remote (non-loopback) callers still require the bearer
   * token, so this is a localhost-only ergonomics unlock, not a network
   * policy change.
   */
  private _autoAuthLocalhost = false;
  /**
   * v1.1 routes (dashboard HTML at /v1.1, hub API at /api/hub/*) are
   * mounted additively when set. Legacy routes at / continue to serve
   * regardless. Default route flip is deferred to v1.2.
   */
  private v11Bindings: V11Bindings | null = null;

  /**
   * v1.3 WP-V1.3-10 Cross-Harness Approval Inbox aggregator. Mounted
   * additively at `/api/approval-inbox/*` when set. Legacy approval
   * routes at `/api/approvals/:id/(allow|deny)` continue to serve. The
   * aggregator is a passive subscriber to the gate; the routes here are
   * the operator-facing query / decision surface.
   */
  private approvalAggregator: ApprovalAggregator | null = null;

  /**
   * v1.3 WP-V1.3-1 Phi-1 Sentinel dispatcher. Mounted additively at
   * `/api/sentinels/*` when set. Sentinel surface is read-only against
   * the audit log; subscribe/unsubscribe writes flow through the
   * dispatcher's audited paths.
   */
  private sentinelDispatcher: SentinelDispatcher | null = null;

  /**
   * v1.3 WP-V1.3-3 Omega-1 Coordination Handoff Visualization.
   * Mounted additively at `/api/coordination/*` when set. Read-only
   * against the audit log; the only writes are operator-action audit
   * events (operator_coordination_view_opened,
   * operator_handoff_entry_drilled).
   */
  private handoffLog: HandoffLog | null = null;
  private handoffEventBridge: HandoffEventBridge | null = null;
  private handoffAuditLog:
    | import("../l2-operational/audit-log.js").AuditLog
    | null = null;
  private handoffOperatorId: string | null = null;

  constructor(config: DashboardConfig) {
    this.config = config;
    this.authToken = config.auth_token;
    this.useTLS = !!(config.tls?.cert_path && config.tls?.key_path);
    // Localhost gets 24h sessions; remote/TLS gets 5min
    const isLocalhost = config.host === "127.0.0.1" || config.host === "localhost" || config.host === "::1";
    this.sessionTTLMs = isLocalhost ? SESSION_TTL_LOCAL_MS : SESSION_TTL_REMOTE_MS;
    this.dashboardHTML = generateDashboardHTML({
      timeoutSeconds: config.timeout_seconds,
      serverVersion: PKG_VERSION,
      // Construction-time default; real value is set by setAutoAuthLocalhost()
      // below (which regenerates this HTML). Default false preserves the
      // pre-v0.10.6 remote-deployment behavior when auto-auth is not enabled.
      loopbackAutoAuth: this._autoAuthLocalhost,
    });
    this.loginHTML = generateLoginHTML({ serverVersion: PKG_VERSION });
    // SEC-012: Periodic cleanup of expired sessions (every 60s)
    this.sessionCleanupTimer = setInterval(() => this.cleanupSessions(), 60_000);
  }

  /**
   * Inject dependencies after construction.
   * Called from index.ts after all components are initialized.
   */
  setDependencies(deps: {
    policy: PrincipalPolicy;
    baseline: BaselineTracker;
    auditLog: AuditLog;
    identityManager?: IdentityManager;
    handshakeResults?: Map<string, HandshakeResult>;
    shrOpts?: SHRGeneratorOptions;
    sanctuaryConfig?: SanctuaryConfig;
    profileStore?: SovereigntyProfileStore;
    clientManager?: ClientManager;
  }): void {
    this.policy = deps.policy;
    this.baseline = deps.baseline;
    this.auditLog = deps.auditLog;
    if (deps.identityManager) this.identityManager = deps.identityManager;
    if (deps.handshakeResults) this.handshakeResults = deps.handshakeResults;
    if (deps.shrOpts) this.shrOpts = deps.shrOpts;
    if (deps.sanctuaryConfig) this._sanctuaryConfig = deps.sanctuaryConfig;
    if (deps.profileStore) this.profileStore = deps.profileStore;
    if (deps.clientManager) this.clientManager = deps.clientManager;
  }

  /**
   * Mark this dashboard as running in standalone mode.
   * Exposed via /api/status so the frontend can show an appropriate banner.
   */
  setStandaloneMode(standalone: boolean): void {
    this._standaloneMode = standalone;
  }

  /**
   * v1.1.1 hotfix: bind the v1.1 dashboard + hub API to this dashboard
   * instance. After binding, requests to `/v1.1` serve the v1.1 HTML and
   * requests under `/api/hub/*` route through the hub API. Legacy routes
   * at `/` and `/api/*` keep their pre-v1.1 behavior (additive mount).
   *
   * Pass `null` to detach the bindings (used by tests and during shutdown).
   */
  setV11Bindings(bindings: V11Bindings | null): void {
    this.v11Bindings = bindings;
  }

  /**
   * v1.3 WP-V1.3-10 Upsilon-1: bind the cross-harness approval inbox
   * aggregator. Once set, requests to `/api/approval-inbox/*` route
   * through `handleApprovalInboxRoute`. Pass `null` to detach (used by
   * tests + during shutdown).
   */
  setApprovalAggregator(aggregator: ApprovalAggregator | null): void {
    this.approvalAggregator = aggregator;
  }

  /**
   * v1.3 WP-V1.3-1 Phi-1: bind the Sentinel dispatcher. Once set,
   * requests to `/api/sentinels/*` route through `handleSentinelRoute`.
   * Pass `null` to detach (used by tests + during shutdown).
   */
  setSentinelDispatcher(dispatcher: SentinelDispatcher | null): void {
    this.sentinelDispatcher = dispatcher;
  }

  /**
   * v1.3 WP-V1.3-3 Omega-1: bind the Coordination handoff log +
   * event bridge + audit log + operator id. Once set, requests to
   * `/api/coordination/*` route through `handleCoordinationRoute`.
   * Pass `null` for any field to detach.
   */
  setHandoffLog(opts: {
    handoffLog: HandoffLog | null;
    eventBridge?: HandoffEventBridge | null;
    auditLog?: import("../l2-operational/audit-log.js").AuditLog | null;
    operatorId?: string | null;
  }): void {
    this.handoffLog = opts.handoffLog;
    this.handoffEventBridge = opts.eventBridge ?? null;
    this.handoffAuditLog = opts.auditLog ?? null;
    this.handoffOperatorId = opts.operatorId ?? null;
  }

  /**
   * v1.3 WP-V1.3-10 dispatch entry point. Called from `handleRequest`
   * before the legacy approval route table. Returns true when served.
   */
  private async dispatchApprovalInbox(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (!this.approvalAggregator) return false;
    return handleApprovalInboxRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        aggregator: this.approvalAggregator,
        operatorId: this.identityManager?.getPrimaryIdentityId() ?? undefined,
      },
      req,
      res,
    );
  }

  /**
   * v1.3 WP-V1.3-1 Phi-1 dispatch entry point. Routes `/api/sentinels/*`
   * requests through the sentinel router when a dispatcher has been
   * bound. Returns true when served.
   */
  private async dispatchSentinel(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (!this.sentinelDispatcher) return false;
    return handleSentinelRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        dispatcher: this.sentinelDispatcher,
      },
      req,
      res,
    );
  }

  /**
   * v1.3 WP-V1.3-3 Omega-1 dispatch entry point. Routes
   * `/api/coordination/*` requests through the coordination router
   * when a HandoffLog has been bound. Returns true when served.
   */
  private async dispatchCoordination(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (
      !this.handoffLog ||
      !this.handoffEventBridge ||
      !this.handoffAuditLog
    ) {
      return false;
    }
    return handleCoordinationRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        handoffLog: this.handoffLog,
        auditLog: this.handoffAuditLog,
        operatorId:
          this.handoffOperatorId ??
          this.identityManager?.getPrimaryIdentityId() ??
          "operator_dashboard",
        events: this.handoffEventBridge,
      },
      req,
      res,
    );
  }

  /**
   * v1.1 dispatch entry point. Called from `handleRequest` before the
   * legacy route table. Returns true when the request was served by v1.1
   * routes; false to fall through to legacy routing.
   *
   * Auth gating: the v1.1 dashboard HTML is served unconditionally (the
   * client script handles its own auth dance). Hub API routes run through
   * the same auth contract as legacy `/api/*` routes via the AuthConfig
   * passed to `handleHubRoute`.
   */
  private async dispatchV11(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
  ): Promise<boolean> {
    if (!this.v11Bindings) return false;
    return dispatchV11Request(
      {
        bindings: this.v11Bindings,
        ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        loopbackAutoAuth: this._autoAuthLocalhost,
      },
      req,
      res,
      url,
      method,
    );
  }

  /**
   * v0.10.2: enable (or disable) the loopback auto-auth fast path. See
   * {@link _autoAuthLocalhost} for the rationale and threat model. Callers
   * should gate this on both (a) the dashboard host being a loopback
   * interface and (b) the master-key unlock having succeeded against
   * on-disk state.
   */
  setAutoAuthLocalhost(enabled: boolean): void {
    this._autoAuthLocalhost = enabled;
    // v0.10.6: the dashboard HTML embeds a LOOPBACK_AUTH constant that mirrors
    // this flag so the client-side init gate knows not to redirect-loop when
    // sessionStorage is empty. Regenerate the HTML here because construction
    // happens before the caller decides whether to enable auto-auth.
    this.dashboardHTML = generateDashboardHTML({
      timeoutSeconds: this.config.timeout_seconds,
      serverVersion: PKG_VERSION,
      loopbackAutoAuth: this._autoAuthLocalhost,
    });
  }

  /**
   * v0.10.2: is this request from a loopback interface? We treat the
   * standard IPv4/IPv6 loopback addresses plus the IPv4-mapped IPv6 form
   * as loopback so LAN clients never accidentally hit the unauthenticated
   * fast path even on hosts where the HTTP server binds 0.0.0.0.
   */
  private isLoopbackRequest(req: IncomingMessage): boolean {
    const addr = this.getRemoteAddr(req);
    return addr === "127.0.0.1" || addr === "::1" || addr === "localhost";
  }

  /**
   * Start the HTTP(S) server for the dashboard.
   */
  async start(): Promise<void> {
    const handler = (req: IncomingMessage, res: ServerResponse) => this.handleRequest(req, res);

    let server;
    if (this.useTLS && this.config.tls) {
      const tlsOpts = {
        cert: await readFile(this.config.tls.cert_path),
        key: await readFile(this.config.tls.key_path),
      };
      server = createHttpsServer(tlsOpts, handler);
    } else {
      server = createHttpServer(handler);
    }
    this.httpServer = server;

    return new Promise((resolve, reject) => {

      const protocol = this.useTLS ? "https" : "http";
      const baseUrl = `${protocol}://${this.config.host}:${this.config.port}`;

      server.listen(this.config.port, this.config.host, () => {
        // Generate a pre-authenticated one-click URL
        const sessionUrl = this.authToken ? this.createSessionUrl() : baseUrl;

        // Print dashboard URL
        process.stderr.write(
          `\n  Sanctuary Principal Dashboard: ${baseUrl}\n`
        );
        if (this.authToken) {
          const hint = this.authToken.slice(0, 4) + "..." + this.authToken.slice(-4);
          process.stderr.write(
            `  Auth token: ${hint}\n`
          );
        }
        process.stderr.write(`\n`);

        // Auto-open in default browser (default: true for localhost)
        // Skip in test environments to avoid spawning browsers during CI/test runs
        const isTest = !!(process.env.VITEST || process.env.NODE_ENV === "test" || process.env.CI);
        const isLocalhost = this.config.host === "127.0.0.1" || this.config.host === "localhost" || this.config.host === "::1";
        const shouldAutoOpen = !isTest && (this.config.auto_open ?? isLocalhost);
        if (shouldAutoOpen) {
          this.openInBrowser(sessionUrl);
        }

        resolve();
      });
      server.on("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "EADDRINUSE") {
          const port = this.config.port;
          process.stderr.write(
            `\n  ╔══════════════════════════════════════════════════════════════╗\n` +
            `  ║  Port ${port} is already in use.                              ║\n` +
            `  ║                                                              ║\n` +
            `  ║  Another Sanctuary Dashboard may still be running.           ║\n` +
            `  ║  To fix: lsof -ti:${port} | xargs kill                        ║\n` +
            `  ║  Then restart the dashboard.                                 ║\n` +
            `  ╚══════════════════════════════════════════════════════════════╝\n\n`
          );
        }
        reject(err);
      });
    });
  }

  /**
   * Stop the HTTP server and clean up.
   */
  async stop(): Promise<void> {
    // Clear all pending requests
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.resolve({
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "auto",
      });
    }
    this.pending.clear();

    // Close SSE connections
    for (const client of this.sseClients) {
      client.end();
    }
    this.sseClients.clear();

    // SEC-012: Clean up session state
    this.sessions.clear();
    if (this.sessionCleanupTimer) {
      clearInterval(this.sessionCleanupTimer);
      this.sessionCleanupTimer = null;
    }

    // Clean up rate limit tracking
    this.rateLimits.clear();

    // Close HTTP server
    if (this.httpServer) {
      return new Promise((resolve) => {
        this.httpServer!.close(() => resolve());
      });
    }
  }

  /**
   * Request approval from the human via the dashboard.
   * Blocks until the human approves/denies or timeout occurs.
   */
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    const id = randomBytes(8).toString("hex");

    // Also write to stderr as a fallback notification
    process.stderr.write(
      `[Sanctuary] Approval required: ${request.operation} (Tier ${request.tier}) — open dashboard to respond\n`
    );

    return new Promise<ApprovalResponse>((resolve) => {
      // Set up timeout
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const response: ApprovalResponse = {
          // SEC-002: Timeout ALWAYS denies. No configuration can change this.
          decision: "deny",
          decided_at: new Date().toISOString(),
          decided_by: "timeout",
        };
        this.broadcastSSE("request-resolved", {
          request_id: id,
          decision: response.decision,
          decided_by: "timeout",
        });
        resolve(response);
      }, this.config.timeout_seconds * 1000);

      // Store the pending request
      const pending: PendingRequest = {
        id,
        request,
        resolve,
        timer,
        created_at: new Date().toISOString(),
      };
      this.pending.set(id, pending);

      // Broadcast to all connected dashboards
      this.broadcastSSE("pending-request", {
        request_id: id,
        operation: request.operation,
        tier: request.tier,
        reason: request.reason,
        context: request.context,
        timestamp: request.timestamp,
      });
    });
  }

  // ── Authentication ──────────────────────────────────────────────────

  /**
   * Verify bearer token authentication.
   *
   * SEC-012: The long-lived auth token is ONLY accepted via the Authorization
   * header — never in URL query strings. For SSE and page loads that cannot
   * set headers, a short-lived session token (obtained via POST /auth/session)
   * is accepted via ?session= query parameter.
   *
   * Returns true if auth passes, false if blocked (response already sent).
   */
  private checkAuth(req: IncomingMessage, url: URL, res: ServerResponse): boolean {
    if (!this.authToken) return true; // Auth disabled

    // v0.10.2: loopback auto-auth — see _autoAuthLocalhost comment.
    if (this._autoAuthLocalhost && this.isLoopbackRequest(req)) {
      return true;
    }

    // Check Authorization: Bearer <token> header (primary auth method)
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const parts = authHeader.split(" ");
      if (parts.length === 2 && parts[0] === "Bearer" && parts[1] === this.authToken) {
        return true;
      }
    }

    // SEC-012: Check ?session= query parameter for short-lived session tokens
    // This replaces the old ?token= query parameter that exposed the long-lived token
    const sessionId = url.searchParams.get("session");
    if (sessionId && this.validateSession(sessionId)) {
      return true;
    }

    // Check sanctuary_session cookie (set by login page flow)
    const cookieSession = this.parseCookie(req, "sanctuary_session");
    if (cookieSession && this.validateSession(cookieSession)) {
      return true;
    }

    // SEC-012: Long-lived token in ?token= query parameter is explicitly REJECTED.
    // This was the vulnerability — tokens in URLs leak to logs, history, and Referer headers.

    // For GET / requests from browsers, serve login page instead of JSON 401
    // (checked in handleRequest before checkAuth is called for this path)
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized — use Authorization: Bearer header or a valid session" }));
    return false;
  }

  /**
   * Check if a request is authenticated WITHOUT sending a response.
   * Used to decide between login page vs dashboard for GET /.
   */
  private isAuthenticated(req: IncomingMessage, url: URL): boolean {
    if (!this.authToken) return true;

    // v0.10.2: loopback auto-auth mirrors checkAuth so GET / serves the
    // dashboard HTML instead of the login page for localhost callers.
    if (this._autoAuthLocalhost && this.isLoopbackRequest(req)) {
      return true;
    }

    const authHeader = req.headers.authorization;
    if (authHeader) {
      const parts = authHeader.split(" ");
      if (parts.length === 2 && parts[0] === "Bearer" && parts[1] === this.authToken) {
        return true;
      }
    }

    const sessionId = url.searchParams.get("session");
    if (sessionId && this.validateSession(sessionId)) return true;

    const cookieSession = this.parseCookie(req, "sanctuary_session");
    if (cookieSession && this.validateSession(cookieSession)) return true;

    return false;
  }

  /**
   * Parse a specific cookie value from the request.
   */
  private parseCookie(req: IncomingMessage, name: string): string | null {
    const header = req.headers.cookie;
    if (!header) return null;
    for (const part of header.split(";")) {
      const [key, ...rest] = part.split("=");
      if (key?.trim() === name) {
        return rest.join("=").trim();
      }
    }
    return null;
  }

  // ── Session Management (SEC-012) ──────────────────────────────────

  /**
   * Create a short-lived session by exchanging the long-lived auth token
   * (provided in the Authorization header) for a session ID.
   */
  private createSession(): string {
    // Enforce max sessions to prevent memory exhaustion
    if (this.sessions.size >= MAX_SESSIONS) {
      this.cleanupSessions();
      // If still at limit after cleanup, evict the oldest session
      if (this.sessions.size >= MAX_SESSIONS) {
        const oldest = [...this.sessions.entries()].sort(
          (a, b) => a[1].created_at - b[1].created_at
        )[0];
        if (oldest) this.sessions.delete(oldest[0]);
      }
    }

    const id = randomBytes(32).toString("hex");
    const now = Date.now();
    this.sessions.set(id, {
      id,
      created_at: now,
      expires_at: now + this.sessionTTLMs,
    });
    return id;
  }

  /**
   * Validate a session ID — must exist and not be expired.
   */
  private validateSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    if (Date.now() > session.expires_at) {
      this.sessions.delete(sessionId);
      return false;
    }
    return true;
  }

  /**
   * Remove all expired sessions.
   */
  private cleanupSessions(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now > session.expires_at) {
        this.sessions.delete(id);
      }
    }
  }

  // ── Rate Limiting ─────────────────────────────────────────────────

  /**
   * Get the remote address from a request, normalizing IPv6-mapped IPv4.
   */
  private getRemoteAddr(req: IncomingMessage): string {
    const addr = req.socket.remoteAddress ?? "unknown";
    // Normalize ::ffff:127.0.0.1 → 127.0.0.1
    return addr.startsWith("::ffff:") ? addr.slice(7) : addr;
  }

  /**
   * Check rate limit for a request. Returns true if allowed, false if rate-limited.
   * When rate-limited, sends a 429 response.
   */
  private checkRateLimit(
    req: IncomingMessage,
    res: ServerResponse,
    type: "general" | "decisions"
  ): boolean {
    const addr = this.getRemoteAddr(req);
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;

    // Get or create entry for this address
    let entry = this.rateLimits.get(addr);
    if (!entry) {
      // Cap the tracking map to prevent memory exhaustion
      if (this.rateLimits.size >= MAX_RATE_LIMIT_ENTRIES) {
        this.pruneRateLimits(now);
      }
      entry = { general: [], decisions: [] };
      this.rateLimits.set(addr, entry);
    }

    // Prune old timestamps from the window
    entry.general = entry.general.filter(t => t > windowStart);
    entry.decisions = entry.decisions.filter(t => t > windowStart);

    const limit = type === "decisions" ? RATE_LIMIT_DECISIONS : RATE_LIMIT_GENERAL;
    const timestamps = entry[type];

    if (timestamps.length >= limit) {
      const retryAfter = Math.ceil((timestamps[0]! + RATE_LIMIT_WINDOW_MS - now) / 1000);
      res.writeHead(429, {
        "Content-Type": "application/json",
        "Retry-After": String(Math.max(1, retryAfter)),
      });
      res.end(JSON.stringify({
        error: "Rate limit exceeded",
        retry_after_seconds: Math.max(1, retryAfter),
      }));
      return false;
    }

    timestamps.push(now);
    return true;
  }

  /**
   * Remove stale entries from the rate limit map.
   */
  private pruneRateLimits(now: number): void {
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    for (const [addr, entry] of this.rateLimits) {
      const hasRecent =
        entry.general.some(t => t > windowStart) ||
        entry.decisions.some(t => t > windowStart);
      if (!hasRecent) {
        this.rateLimits.delete(addr);
      }
    }
  }

  // ── HTTP Request Handler ────────────────────────────────────────────

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const method = req.method ?? "GET";

    // CORS headers — restrict to same-origin; the dashboard is served by this server
    const origin = req.headers.origin;
    const protocol = this.useTLS ? "https" : "http";
    const selfOrigin = `${protocol}://${this.config.host}:${this.config.port}`;
    if (origin === selfOrigin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
    // When no origin header (same-origin requests), no CORS header needed
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // v1.3 WP-V1.3-10 Upsilon-1: cross-harness approval inbox routes at
    // `/api/approval-inbox/*`. Mounted additively in front of the v1.1
    // hub + legacy v1.0 surfaces; legacy `/api/approvals/:id/...` paths
    // stay live for the v1.0 dashboard.
    if (
      this.approvalAggregator &&
      url.pathname.startsWith(APPROVAL_INBOX_API_PREFIX)
    ) {
      this.dispatchApprovalInbox(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // v1.3 WP-V1.3-1 Phi-1: Sentinel surface at `/api/sentinels/*`.
    // Read-only against the audit log; subscribe/unsubscribe writes
    // flow through the dispatcher's audited paths.
    if (
      this.sentinelDispatcher &&
      url.pathname.startsWith(SENTINEL_API_PREFIX)
    ) {
      this.dispatchSentinel(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // v1.3 WP-V1.3-3 Omega-1: Coordination handoff surface at
    // `/api/coordination/*`. Read-only against the audit log; only
    // writes are operator-action audit events.
    if (
      this.handoffLog &&
      url.pathname.startsWith(COORDINATION_API_PREFIX)
    ) {
      this.dispatchCoordination(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // v1.1.1 hotfix: try v1.1 dispatch first. dispatchV11 returns true when
    // the request matched a v1.1 route (dashboard HTML at /v1.1, hub API
    // at /api/hub/*). When false, fall through to the legacy route table
    // below so v1.0 surfaces stay live (additive mount, default route flip
    // deferred to v1.2).
    if (this.v11Bindings) {
      this.dispatchV11(req, res, url, method)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    this.handleLegacyRequest(req, res, url, method);
  }

  private handleLegacyRequest(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
  ): void {
    // SEC-012: Session exchange does its own auth (header-only) — let it through before checkAuth
    if (method === "POST" && url.pathname === "/auth/session") {
      if (!this.checkRateLimit(req, res, "general")) return;
      try {
        this.handleSessionExchange(req, res);
      } catch {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
      return;
    }

    // For GET /v1.0: serve login page if not authenticated (instead of JSON 401).
    // v1.1.7: root path now serves the v1.1 SPA (handled by dispatchV11
    // above). The legacy four-panel dashboard moved to /v1.0; the login
    // page mirrors that move so unauthenticated requests at /v1.0 still
    // hit the legacy login flow.
    if (method === "GET" && url.pathname === "/v1.0" && this.authToken) {
      if (!this.isAuthenticated(req, url)) {
        // Login page is a view — no rate limit (auth brute force is gated on /auth/session).
        this.serveLoginPage(res);
        return;
      }
    }

    // Authenticate all other non-OPTIONS requests
    if (!this.checkAuth(req, url, res)) return;

    // Rate limiting: apply general limit to authenticated API requests only.
    // HTML view routes (`/`, `/dashboard`, `/fortress`) and the long-lived SSE
    // stream (`/events`) are exempt — operator page loads and browser
    // refreshes must never 429. Decision endpoints (approve/deny) and the
    // session-exchange endpoint keep their own stricter limits below.
    if (!isDashboardViewRoute(method, url.pathname)) {
      if (!this.checkRateLimit(req, res, "general")) return;
    }

    try {
      if (method === "GET" && url.pathname === "/fortress") {
        this.serveFortressView(res);
      } else if (method === "GET" && url.pathname === "/v1.0") {
        // v1.1.7: legacy v1.0 dashboard preserved at /v1.0. Root and
        // /dashboard now route to the v1.1 SPA via dispatchV11 above.
        if (this.fortressHTML) {
          this.serveFortressView(res);
        } else {
          this.serveDashboard(res);
        }
      } else if (method === "GET" && url.pathname === "/events") {
        this.handleSSE(req, res);
      } else if (method === "GET" && url.pathname === "/api/status") {
        this.handleStatus(res);
      } else if (method === "GET" && url.pathname === "/api/pending") {
        this.handlePendingList(res);
      } else if (method === "GET" && url.pathname === "/api/audit-log") {
        this.handleAuditLog(url, res);
      } else if (method === "GET" && url.pathname === "/api/sovereignty") {
        this.handleSovereignty(res);
      } else if (method === "GET" && url.pathname === "/api/identity") {
        this.handleIdentity(res);
      } else if (method === "GET" && url.pathname === "/api/handshakes") {
        this.handleHandshakes(res);
      } else if (method === "GET" && url.pathname === "/api/shr") {
        this.handleSHR(res);
      } else if (method === "GET" && url.pathname === "/api/sovereignty-profile") {
        this.handleSovereigntyProfileGet(res);
      } else if (method === "POST" && url.pathname === "/api/sovereignty-profile") {
        this.handleSovereigntyProfileUpdate(req, res);
      } else if (method === "GET" && url.pathname === "/api/proxy/servers") {
        this.handleProxyServers(res);
      } else if (method === "POST" && url.pathname === "/api/proxy/servers") {
        this.handleProxyServersUpdate(req, res);
      } else if (method === "POST" && url.pathname.startsWith("/api/approve/")) {
        // Decision endpoints get an additional tighter rate limit
        if (!this.checkRateLimit(req, res, "decisions")) return;
        const id = url.pathname.slice("/api/approve/".length);
        this.handleDecision(id, "approve", res);
      } else if (method === "POST" && url.pathname.startsWith("/api/deny/")) {
        // Decision endpoints get an additional tighter rate limit
        if (!this.checkRateLimit(req, res, "decisions")) return;
        const id = url.pathname.slice("/api/deny/".length);
        this.handleDecision(id, "deny", res);
      } else {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
      }
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }

  // ── Route Handlers ──────────────────────────────────────────────────

  /**
   * SEC-012: Exchange a long-lived auth token (in Authorization header)
   * for a short-lived session ID. The session ID can be used in URL
   * query parameters without exposing the long-lived credential.
   *
   * This endpoint performs its OWN auth check (header-only) because it
   * must reject query-parameter tokens and is called before the
   * normal checkAuth flow.
   */
  private handleSessionExchange(req: IncomingMessage, res: ServerResponse): void {
    if (!this.authToken) {
      // Auth disabled — sessions not needed
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ session_id: "no-auth" }));
      return;
    }

    // Only accept the long-lived token via Authorization header — NEVER from URL
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Authorization header required" }));
      return;
    }

    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer" || parts[1] !== this.authToken) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid bearer token" }));
      return;
    }

    const sessionId = this.createSession();
    const ttlSeconds = Math.floor(this.sessionTTLMs / 1000);
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Set-Cookie": `sanctuary_session=${sessionId}; Path=/; SameSite=Strict; Max-Age=${ttlSeconds}`,
    });
    res.end(JSON.stringify({
      session_id: sessionId,
      expires_in_seconds: ttlSeconds,
    }));
  }

  private serveLoginPage(res: ServerResponse): void {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache, no-store",
    });
    res.end(this.loginHTML);
  }

  private serveDashboard(res: ServerResponse): void {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(this.dashboardHTML);
  }

  private serveFortressView(res: ServerResponse): void {
    if (!this.fortressHTML) {
      // Fallback to standard dashboard
      this.serveDashboard(res);
      return;
    }
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(this.fortressHTML);
  }

  /**
   * Enable Fortress View (Cocoon mode) with the given upstream server count.
   * Once enabled, the root path `/` serves the Fortress View instead of the
   * standard dashboard. The standard dashboard remains available at `/dashboard`.
   */
  enableFortressView(upstreamServerCount: number): void {
    this.fortressHTML = generateFortressViewHTML({
      serverVersion: PKG_VERSION,
      authToken: this.authToken,
      upstreamServerCount,
    });
  }

  /**
   * Broadcast a proxy call event to connected dashboards (Fortress View feed).
   */
  broadcastProxyCall(data: {
    tool: string;
    server: string;
    decision: string;
    reason?: string;
    tier?: number;
    timestamp: string;
  }): void {
    this.broadcastSSE("proxy-call", data);
  }

  private handleSSE(req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });

    // Send initial state
    const initData: Record<string, unknown> = {};

    if (this.baseline) {
      initData.baseline = this.baseline.getProfile();
    }
    if (this.policy) {
      initData.policy = {
        tier1_always_approve: this.policy.tier1_always_approve,
        tier2_anomaly: this.policy.tier2_anomaly,
        tier3_always_allow: this.policy.tier3_always_allow,
        approval_channel: {
          type: this.policy.approval_channel.type,
          timeout_seconds: this.policy.approval_channel.timeout_seconds,
          auto_deny: true, // SEC-002: hardcoded, not configurable
        },
      };
    }

    // Send any current pending requests
    const pendingList = Array.from(this.pending.values()).map((p) => ({
      request_id: p.id,
      operation: p.request.operation,
      tier: p.request.tier,
      reason: p.request.reason,
      context: p.request.context,
      timestamp: p.request.timestamp,
    }));
    if (pendingList.length > 0) {
      initData.pending = pendingList;
    }

    res.write(`event: init\ndata: ${JSON.stringify(initData)}\n\n`);

    this.sseClients.add(res);

    req.on("close", () => {
      this.sseClients.delete(res);
    });
  }

  private handleStatus(res: ServerResponse): void {
    const status: Record<string, unknown> = {
      pending_count: this.pending.size,
      connected_clients: this.sseClients.size,
      standalone_mode: this._standaloneMode,
    };

    if (this.baseline) {
      status.baseline = this.baseline.getProfile();
    }
    if (this.policy) {
      status.policy = {
        version: this.policy.version,
        tier1_always_approve: this.policy.tier1_always_approve,
        tier2_anomaly: this.policy.tier2_anomaly,
        tier3_always_allow: this.policy.tier3_always_allow,
        approval_channel: {
          type: this.policy.approval_channel.type,
          timeout_seconds: this.policy.approval_channel.timeout_seconds,
          auto_deny: true, // SEC-002: hardcoded, not configurable
        },
      };
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(status));
  }

  private handlePendingList(res: ServerResponse): void {
    const list = Array.from(this.pending.values()).map((p) => ({
      id: p.id,
      operation: p.request.operation,
      tier: p.request.tier,
      reason: p.request.reason,
      context: p.request.context,
      timestamp: p.request.timestamp,
      created_at: p.created_at,
    }));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(list));
  }

  private handleAuditLog(url: URL, res: ServerResponse): void {
    const limit = parseInt(url.searchParams.get("limit") ?? "50", 10);

    // AuditLog.query is async, but for the dashboard we return what we can
    if (this.auditLog) {
      this.auditLog.query({ limit }).then((entries) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(entries));
      }).catch(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify([]));
      });
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([]));
    }
  }

  private handleDecision(id: string, decision: "approve" | "deny", res: ServerResponse): void {
    const pending = this.pending.get(id);
    if (!pending) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Request not found or already resolved" }));
      return;
    }

    // Clear timeout
    clearTimeout(pending.timer);

    // Remove from pending
    this.pending.delete(id);

    // Create response
    const response: ApprovalResponse = {
      decision,
      decided_at: new Date().toISOString(),
      decided_by: "human",
    };

    // Broadcast resolution to all dashboards
    this.broadcastSSE("request-resolved", {
      request_id: id,
      decision,
      decided_by: "human",
    });

    // Resolve the waiting promise (unblocks the tool call)
    pending.resolve(response);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, decision }));
  }

  // ── Sovereignty Data Routes ─────────────────────────────────────────

  private handleSovereignty(res: ServerResponse): void {
    if (!this.shrOpts) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "SHR generator not available" }));
      return;
    }

    const shr = generateSHR(undefined, this.shrOpts);
    if (typeof shr === "string") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: shr }));
      return;
    }

    const layers = shr.body.layers;
    // Compute sovereignty score: 25 points per layer, deductions for degraded/inactive
    let score = 0;
    for (const layer of [layers.l1, layers.l2, layers.l3, layers.l4]) {
      if (layer.status === "active") score += 25;
      else if (layer.status === "degraded") score += 15;
      // inactive = 0
    }

    const overallLevel = score === 100 ? "full"
      : score >= 65 ? "degraded"
      : score >= 25 ? "minimal"
      : "unverified";

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      score,
      overall_level: overallLevel,
      layers: {
        l1: { status: layers.l1.status, detail: layers.l1.encryption, key_custody: layers.l1.key_custody },
        l2: { status: layers.l2.status, detail: layers.l2.isolation_type, attestation: layers.l2.attestation_available },
        l3: { status: layers.l3.status, detail: layers.l3.proof_system, selective_disclosure: layers.l3.selective_disclosure },
        l4: { status: layers.l4.status, detail: layers.l4.attestation_format, reputation_portable: layers.l4.reputation_portable },
      },
      degradations: shr.body.degradations,
      capabilities: shr.body.capabilities,
      config_loaded: this._sanctuaryConfig != null,
    }));
  }

  private handleIdentity(res: ServerResponse): void {
    if (!this.identityManager) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ identities: [], count: 0 }));
      return;
    }

    const identities = this.identityManager.listWithRotationCount();

    const primary = this.identityManager.getDefault();

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      identities,
      count: identities.length,
      primary_id: primary?.identity_id ?? null,
    }));
  }

  private handleHandshakes(res: ServerResponse): void {
    if (!this.handshakeResults) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ handshakes: [], count: 0 }));
      return;
    }

    const handshakes = Array.from(this.handshakeResults.values()).map(h => ({
      counterparty_id: h.counterparty_id,
      verified: h.verified,
      sovereignty_level: h.sovereignty_level,
      trust_tier: h.trust_tier,
      completed_at: h.completed_at,
      expires_at: h.expires_at,
      errors: h.errors,
    }));

    // Sort by completed_at descending (most recent first)
    handshakes.sort((a, b) => new Date(b.completed_at).getTime() - new Date(a.completed_at).getTime());

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      handshakes,
      count: handshakes.length,
      tier_distribution: {
        verified_sovereign: handshakes.filter(h => h.trust_tier === "verified-sovereign").length,
        verified_degraded: handshakes.filter(h => h.trust_tier === "verified-degraded").length,
        unverified: handshakes.filter(h => h.trust_tier === "unverified").length,
      },
    }));
  }

  private handleSHR(res: ServerResponse): void {
    if (!this.shrOpts) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "SHR generator not available" }));
      return;
    }

    const shr = generateSHR(undefined, this.shrOpts);
    if (typeof shr === "string") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: shr }));
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(shr));
  }

  // ── Sovereignty Profile API ─────────────────────────────────────────

  private handleSovereigntyProfileGet(res: ServerResponse): void {
    if (!this.profileStore) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Sovereignty Profile not available" }));
      return;
    }

    try {
      const profile = this.profileStore.get();
      const prompt = generateSystemPrompt(profile);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ profile, system_prompt: prompt }));
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to read sovereignty profile" }));
    }
  }

  private handleSovereigntyProfileUpdate(req: IncomingMessage, res: ServerResponse): void {
    if (!this.profileStore) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Sovereignty Profile not available" }));
      return;
    }

    let body = "";
    let destroyed = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      // Size limit: 16KB for profile updates
      if (body.length > 16384) {
        destroyed = true;
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        req.destroy();
      }
    });
    req.on("end", async () => {
      if (destroyed) return;
      try {
        const updates: SovereigntyProfileUpdate = JSON.parse(body);
        const updated = await this.profileStore!.update(updates);
        const prompt = generateSystemPrompt(updated);

        // Audit log the dashboard-initiated change
        if (this.auditLog) {
          this.auditLog.append("l2", "sovereignty_profile_update_dashboard", "dashboard", {
            changes: updates,
            features_enabled: Object.entries(updated.features)
              .filter(([, v]) => v.enabled)
              .map(([k]) => k),
          });
        }

        // Broadcast to SSE clients
        this.broadcastSSE("sovereignty-profile-update", { profile: updated, system_prompt: prompt });

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ profile: updated, system_prompt: prompt }));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON body" }));
      }
    });
  }

  // ── Proxy Server Handlers ───────────────────────────────────────────

  /**
   * GET /api/proxy/servers — list upstream proxy servers and their status.
   */
  private handleProxyServers(res: ServerResponse): void {
    const profile = this.profileStore?.get();
    const upstreamServers = profile?.upstream_servers ?? [];
    const clientStatus = this.clientManager?.getStatus() ?? [];

    // Merge config with live status
    const servers = upstreamServers.map(server => {
      const status = clientStatus.find(s => s.name === server.name);
      return {
        name: server.name,
        transport_type: server.transport.type,
        enabled: server.enabled,
        default_tier: server.default_tier,
        state: status?.state ?? "disconnected",
        tool_count: status?.tool_count ?? 0,
        error: status?.error,
        tool_overrides: server.tool_overrides ?? {},
      };
    });

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ servers }));
  }

  /**
   * POST /api/proxy/servers — update upstream server configuration.
   * This is a dashboard action (human-initiated), so it's allowed with audit logging
   * rather than requiring Tier 1 approval.
   */
  private handleProxyServersUpdate(req: IncomingMessage, res: ServerResponse): void {
    if (!this.profileStore) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Profile store not available" }));
      return;
    }

    let body = "";
    let destroyed = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      if (body.length > 16384) {
        destroyed = true;
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        req.destroy();
      }
    });
    req.on("end", async () => {
      if (destroyed) return;
      try {
        const { upstream_servers } = JSON.parse(body) as { upstream_servers: UpstreamServer[] };

        // Update profile with new server config
        const updated = await this.profileStore!.update({ upstream_servers });

        // Audit log the dashboard-initiated change
        if (this.auditLog) {
          this.auditLog.append("l2", "proxy_servers_update_dashboard", "dashboard", {
            server_count: upstream_servers.length,
            servers: upstream_servers.map(s => ({
              name: s.name,
              type: s.transport.type,
              enabled: s.enabled,
              tier: s.default_tier,
            })),
          });
        }

        // Reconfigure client manager if available
        if (this.clientManager && updated.upstream_servers) {
          this.clientManager.configure(updated.upstream_servers).catch(() => {
            // Connection errors handled by client manager
          });
        }

        // Broadcast to SSE clients
        this.broadcastSSE("proxy-servers-update", {
          servers: updated.upstream_servers ?? [],
          timestamp: new Date().toISOString(),
        });

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ upstream_servers: updated.upstream_servers ?? [] }));
      } catch (err) {
        const message = err instanceof Error ? err.message : "Invalid request";
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: message }));
      }
    });
  }

  // ── SSE Broadcasting ────────────────────────────────────────────────

  broadcastSSE(event: string, data: unknown): void {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(message);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  /**
   * Broadcast an audit entry to connected dashboards.
   * Called externally when audit events happen.
   */
  broadcastAuditEntry(entry: {
    timestamp: string;
    layer: string;
    operation: string;
    identity_id: string;
  }): void {
    this.broadcastSSE("audit-entry", entry);
  }

  /**
   * Broadcast a baseline update to connected dashboards.
   * Called externally after baseline changes.
   */
  broadcastBaselineUpdate(): void {
    if (this.baseline) {
      this.broadcastSSE("baseline-update", this.baseline.getProfile());
    }
  }

  /**
   * Broadcast a tool call event to connected dashboards.
   * Called from the gate or router when a tool is invoked.
   */
  broadcastToolCall(data: {
    tool: string;
    tier: number;
    allowed: boolean;
    timestamp: string;
  }): void {
    this.broadcastSSE("tool-call", data);
  }

  /**
   * Broadcast a context gate decision to connected dashboards.
   */
  broadcastContextGateDecision(data: {
    tool: string;
    fields_filtered: number;
    fields_total: number;
    action: string;
    timestamp: string;
  }): void {
    this.broadcastSSE("context-gate-decision", data);
  }

  /**
   * Broadcast current protection status to connected dashboards.
   */
  broadcastProtectionStatus(data: Record<string, unknown>): void {
    this.broadcastSSE("protection-status", data);
  }

  // ── Mesh-health surface (WP-MVP-3 Follow-up #3) ─────────────────────
  //
  // The federation FailureModeDetector pushes per-tick health snapshots and
  // per-detection alerts here; the existing /events SSE channel transports
  // them to the browser. No new transport.
  //
  // Spec §8 + §9. Spawn-prompt acceptance criterion 7: "Mesh Health dashboard
  // panel renders via existing SSE /events channel — no new transport. Every
  // state transition produces an observable SSE event."

  /** Push a Mesh Health snapshot (full re-render trigger on the client). */
  broadcastMeshHealth(snapshot: Record<string, unknown>): void {
    this.broadcastSSE("mesh-health", snapshot);
  }

  /** Push a single failure-mode alert (incremental client update). */
  broadcastMeshFailureModeAlert(alert: Record<string, unknown>): void {
    this.broadcastSSE("mesh-failure-mode-alert", alert);
  }

  /** Push a post-recovery prompt update (master rotation hygiene flow). */
  broadcastMeshPostRecoveryPrompt(prompt: Record<string, unknown>): void {
    this.broadcastSSE("mesh-post-recovery-prompt", prompt);
  }

  /**
   * Open a URL in the system's default browser.
   * Cross-platform: macOS (open), Linux (xdg-open), Windows (start).
   * Fails silently — dashboard still works via terminal URL.
   */
  private openInBrowser(url: string): void {
    const os = platform();
    let cmd: string;
    if (os === "darwin") {
      cmd = `open "${url}"`;
    } else if (os === "win32") {
      cmd = `start "" "${url}"`;
    } else {
      cmd = `xdg-open "${url}"`;
    }
    exec(cmd, (err) => {
      if (err) {
        process.stderr.write(
          `  (Could not auto-open browser. Open the URL above manually.)\n\n`
        );
      }
    });
  }

  /**
   * Create a pre-authenticated URL for the dashboard.
   * Used by the sanctuary_dashboard_open tool and at startup.
   */
  createSessionUrl(): string {
    const sessionId = this.createSession();
    const protocol = this.useTLS ? "https" : "http";
    return `${protocol}://${this.config.host}:${this.config.port}/?session=${sessionId}`;
  }

  /**
   * Get the base URL for the dashboard.
   */
  getBaseUrl(): string {
    const protocol = this.useTLS ? "https" : "http";
    return `${protocol}://${this.config.host}:${this.config.port}`;
  }

  /** Get the number of pending requests */
  get pendingCount(): number {
    return this.pending.size;
  }

  /** Get the number of connected SSE clients */
  get clientCount(): number {
    return this.sseClients.size;
  }
}
