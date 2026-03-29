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
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import type { ApprovalChannel } from "./approval-channel.js";
import type { ApprovalRequest, ApprovalResponse, PrincipalPolicy } from "./types.js";
import type { BaselineTracker } from "./baseline.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import { generateDashboardHTML } from "./dashboard-html.js";

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

const SESSION_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_SESSIONS = 1000;

export class DashboardApprovalChannel implements ApprovalChannel {
  private config: DashboardConfig;
  private pending: Map<string, PendingRequest> = new Map();
  private sseClients: Set<SSEClient> = new Set();
  private httpServer: ReturnType<typeof createHttpServer> | null = null;
  private policy: PrincipalPolicy | null = null;
  private baseline: BaselineTracker | null = null;
  private auditLog: AuditLog | null = null;
  private dashboardHTML: string;
  private authToken: string | undefined;
  private useTLS: boolean;
  /** SEC-012: Short-lived session store. Sessions replace URL query tokens. */
  private sessions: Map<string, DashboardSession> = new Map();
  private sessionCleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: DashboardConfig) {
    this.config = config;
    this.authToken = config.auth_token;
    this.useTLS = !!(config.tls?.cert_path && config.tls?.key_path);
    this.dashboardHTML = generateDashboardHTML({
      timeoutSeconds: config.timeout_seconds,
      serverVersion: "0.3.0",
      authToken: this.authToken,
    });
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
  }): void {
    this.policy = deps.policy;
    this.baseline = deps.baseline;
    this.auditLog = deps.auditLog;
  }

  /**
   * Start the HTTP(S) server for the dashboard.
   */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const handler = (req: IncomingMessage, res: ServerResponse) => this.handleRequest(req, res);

      if (this.useTLS && this.config.tls) {
        const tlsOpts = {
          cert: readFileSync(this.config.tls.cert_path),
          key: readFileSync(this.config.tls.key_path),
        };
        this.httpServer = createHttpsServer(tlsOpts, handler);
      } else {
        this.httpServer = createHttpServer(handler);
      }

      const protocol = this.useTLS ? "https" : "http";
      const baseUrl = `${protocol}://${this.config.host}:${this.config.port}`;

      this.httpServer.listen(this.config.port, this.config.host, () => {
        if (this.authToken) {
          // Show only a hint of the token in stderr to avoid log exposure
          const hint = this.authToken.slice(0, 4) + "..." + this.authToken.slice(-4);
          process.stderr.write(
            `\n  Sanctuary Principal Dashboard: ${baseUrl}\n`
          );
          // SEC-012: Never suggest putting the token in the URL
          process.stderr.write(
            `  Auth required (token: ${hint}). Use Authorization: Bearer <TOKEN> header.\n\n`
          );
        } else {
          process.stderr.write(
            `\n  Sanctuary Principal Dashboard: ${baseUrl}\n\n`
          );
        }
        resolve();
      });
      this.httpServer.on("error", reject);
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

    // SEC-012: Long-lived token in ?token= query parameter is explicitly REJECTED.
    // This was the vulnerability — tokens in URLs leak to logs, history, and Referer headers.

    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized — use Authorization: Bearer header or a valid session" }));
    return false;
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
      expires_at: now + SESSION_TTL_MS,
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

    // Authenticate all non-OPTIONS requests
    if (!this.checkAuth(req, url, res)) return;

    try {
      // SEC-012: Session exchange endpoint — must be authenticated via header
      if (method === "POST" && url.pathname === "/auth/session") {
        this.handleSessionExchange(req, res);
        return;
      }

      if (method === "GET" && url.pathname === "/") {
        this.serveDashboard(res);
      } else if (method === "GET" && url.pathname === "/events") {
        this.handleSSE(req, res);
      } else if (method === "GET" && url.pathname === "/api/status") {
        this.handleStatus(res);
      } else if (method === "GET" && url.pathname === "/api/pending") {
        this.handlePendingList(res);
      } else if (method === "GET" && url.pathname === "/api/audit-log") {
        this.handleAuditLog(url, res);
      } else if (method === "POST" && url.pathname.startsWith("/api/approve/")) {
        const id = url.pathname.slice("/api/approve/".length);
        this.handleDecision(id, "approve", res);
      } else if (method === "POST" && url.pathname.startsWith("/api/deny/")) {
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
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      session_id: sessionId,
      expires_in_seconds: SESSION_TTL_MS / 1000,
    }));
  }

  private serveDashboard(res: ServerResponse): void {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(this.dashboardHTML);
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

  // ── SSE Broadcasting ────────────────────────────────────────────────

  private broadcastSSE(event: string, data: unknown): void {
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

  /** Get the number of pending requests */
  get pendingCount(): number {
    return this.pending.size;
  }

  /** Get the number of connected SSE clients */
  get clientCount(): number {
    return this.sseClients.size;
  }
}
