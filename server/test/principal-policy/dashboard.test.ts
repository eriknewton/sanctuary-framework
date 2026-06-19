/**
 * Sanctuary MCP Server — Principal Dashboard Tests
 *
 * Tests the DashboardApprovalChannel: HTTP server, SSE, approval flow,
 * and timeout behavior.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import type { ApprovalRequest, ApprovalResponse } from "../../src/principal-policy/types.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

async function requestNoKeepAlive(
  url: string,
  options: { method?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  const target = new URL(url);

  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: options.method ?? "GET",
        headers: {
          ...options.headers,
          Connection: "close",
        },
        agent: false,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body,
          });
        });
      },
    );

    req.setTimeout(5000, () => {
      req.destroy(new Error(`Timed out requesting ${target.href}`));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("Principal Dashboard", () => {
  let dashboard: DashboardApprovalChannel;
  let port: number;

  beforeEach(async () => {
    // Sigma-6: bindWithRetry retries on EADDRINUSE so this suite stops
    // being the recurring port-collision flake offender (9-10 incidents
    // across iterations 2-6). The retry helper picks a fresh random
    // port each attempt; the DashboardApprovalChannel.start() surfaces
    // EADDRINUSE which the helper catches and retries.
    await bindWithRetry(async () => {
      port = randomTestPort();
      dashboard = new DashboardApprovalChannel({
        port,
        host: "127.0.0.1",
        timeout_seconds: 2, // Short timeout for tests
        auto_deny: true,
      });
      await dashboard.start();
    });
  });

  afterEach(async () => {
    await dashboard.stop();
  });

  // ── HTTP Server ──────────────────────────────────────────────────────

  describe("HTTP Server", () => {
    it("serves the legacy dashboard HTML at /v1.0", async () => {
      // v1.1.7: legacy four-panel dashboard moved to /v1.0; root + /dashboard
      // route to the v1.1 SPA via dispatchV11 when v11Bindings are wired
      // (not in this rig). This rig boots a bare DashboardApprovalChannel,
      // so the v1.1 dispatch is dormant and the legacy route is the active
      // surface — pinned at the new /v1.0 URL.
      const res = await fetch(`http://127.0.0.1:${port}/v1.0`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/html");
      const text = await res.text();
      expect(text).toContain("Sanctuary");
      expect(text).toContain("Principal Dashboard");
    });

    it("returns 404 for unknown routes", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/nonexistent`);
      expect(res.status).toBe(404);
    });

    it("returns status at /api/status", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/api/status`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.pending_count).toBe(0);
      expect(data.connected_clients).toBe(0);
    });

    it("returns empty pending list at /api/pending", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/api/pending`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data).toEqual([]);
    });
  });

  // ── Approval Flow ────────────────────────────────────────────────────

  describe("Approval Flow", () => {
    const makeRequest = (): ApprovalRequest => ({
      operation: "state_export",
      tier: 1,
      reason: "Tier 1 operation",
      context: { namespace: "test" },
      timestamp: new Date().toISOString(),
    });

    it("creates pending request and resolves on approve", async () => {
      const request = makeRequest();

      // Start approval (don't await — it blocks)
      const approvalPromise = dashboard.requestApproval(request);
      expect(dashboard.pendingCount).toBe(1);

      // Get the pending list to find the ID
      const listRes = await fetch(`http://127.0.0.1:${port}/api/pending`);
      const pending = await listRes.json();
      expect(pending).toHaveLength(1);
      expect(pending[0].operation).toBe("state_export");

      // Approve
      const approveRes = await fetch(
        `http://127.0.0.1:${port}/api/approve/${pending[0].id}`,
        { method: "POST" }
      );
      expect(approveRes.status).toBe(200);

      // The approval promise should resolve
      const response = await approvalPromise;
      expect(response.decision).toBe("approve");
      expect(response.decided_by).toBe("human");
      expect(dashboard.pendingCount).toBe(0);
    });

    it("creates pending request and resolves on deny", async () => {
      const request = makeRequest();
      const approvalPromise = dashboard.requestApproval(request);

      const listRes = await fetch(`http://127.0.0.1:${port}/api/pending`);
      const pending = await listRes.json();

      const denyRes = await fetch(
        `http://127.0.0.1:${port}/api/deny/${pending[0].id}`,
        { method: "POST" }
      );
      expect(denyRes.status).toBe(200);

      const response = await approvalPromise;
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("human");
    });

    it("returns 404 for non-existent request ID", async () => {
      const res = await requestNoKeepAlive(
        `http://127.0.0.1:${port}/api/approve/nonexistent`,
        { method: "POST" }
      );
      expect(res.status).toBe(404);
    });

    it("auto-denies on timeout when auto_deny is true", async () => {
      const request = makeRequest();
      const response = await dashboard.requestApproval(request);
      // With 2-second timeout, this should auto-deny
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
      expect(dashboard.pendingCount).toBe(0);
    }, 5000);

    it("handles multiple concurrent pending requests", async () => {
      const req1 = { ...makeRequest(), operation: "state_export" };
      const req2 = { ...makeRequest(), operation: "identity_rotate" };

      const p1 = dashboard.requestApproval(req1);
      const p2 = dashboard.requestApproval(req2);
      expect(dashboard.pendingCount).toBe(2);

      // Get pending list
      const listRes = await fetch(`http://127.0.0.1:${port}/api/pending`);
      const pending = await listRes.json();
      expect(pending).toHaveLength(2);

      // Approve first, deny second
      await fetch(`http://127.0.0.1:${port}/api/approve/${pending[0].id}`, { method: "POST" });
      await fetch(`http://127.0.0.1:${port}/api/deny/${pending[1].id}`, { method: "POST" });

      const [r1, r2] = await Promise.all([p1, p2]);
      // Order depends on which ID maps to which request
      const decisions = [r1.decision, r2.decision].sort();
      expect(decisions).toEqual(["approve", "deny"]);
      expect(dashboard.pendingCount).toBe(0);
    });
  });

  // ── SEC-002: auto_deny false is ignored ─────────────────────────────

  describe("SEC-002: auto_deny false is ignored", () => {
    let approvalDashboard: DashboardApprovalChannel;
    let approvePort: number;

    beforeEach(async () => {
      // Sigma-6: bindWithRetry — see top-level beforeEach for rationale.
      await bindWithRetry(async () => {
        approvePort = randomTestPort();
        approvalDashboard = new DashboardApprovalChannel({
          port: approvePort,
          host: "127.0.0.1",
          timeout_seconds: 1,
          auto_deny: false, // SEC-002: this is now ignored
        });
        await approvalDashboard.start();
      });
    });

    afterEach(async () => {
      await approvalDashboard.stop();
    });

    it("denies on timeout even when auto_deny is false (SEC-002)", async () => {
      const request: ApprovalRequest = {
        operation: "state_export",
        tier: 1,
        reason: "Test",
        context: {},
        timestamp: new Date().toISOString(),
      };
      const response = await approvalDashboard.requestApproval(request);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
    }, 5000);
  });

  // ── SSE (Server-Sent Events) ─────────────────────────────────────────

  describe("SSE", () => {
    it("connects to /events and receives init message", async () => {
      const response = await fetch(`http://127.0.0.1:${port}/events`);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("text/event-stream");

      // Read a chunk of the SSE stream
      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      const { value } = await reader.read();
      const text = decoder.decode(value);
      expect(text).toContain("event: init");

      await reader.cancel();
    });

    it("tracks connected clients", async () => {
      expect(dashboard.clientCount).toBe(0);

      const response = await fetch(`http://127.0.0.1:${port}/events`);
      const reader = response.body!.getReader();
      await reader.read(); // Wait for init message

      // Give the server a moment to register the client
      await new Promise((r) => setTimeout(r, 50));
      expect(dashboard.clientCount).toBe(1);

      await reader.cancel();
    });
  });

  // ── Broadcast Methods ────────────────────────────────────────────────

  describe("Broadcasting", () => {
    it("broadcastAuditEntry sends to SSE clients", async () => {
      const response = await fetch(`http://127.0.0.1:${port}/events`);
      const reader = response.body!.getReader();
      const decoder = new TextDecoder();

      // Read init message
      await reader.read();

      // Broadcast an audit entry
      dashboard.broadcastAuditEntry({
        timestamp: new Date().toISOString(),
        layer: "l1",
        operation: "state_write",
        identity_id: "test-id",
      });

      // Read the audit event
      const { value } = await reader.read();
      const text = decoder.decode(value);
      expect(text).toContain("event: audit-entry");
      expect(text).toContain("state_write");

      await reader.cancel();
    });
  });

  // ── Authentication ──────────────────────────────────────────────────

  describe("Authentication", () => {
    const AUTH_TOKEN = "test-secret-token-12345";
    let authDashboard: DashboardApprovalChannel;
    let authPort: number;

    beforeEach(async () => {
      // Sigma-6: bindWithRetry — see top-level beforeEach for rationale.
      await bindWithRetry(async () => {
        authPort = randomTestPort();
        authDashboard = new DashboardApprovalChannel({
          port: authPort,
          host: "127.0.0.1",
          timeout_seconds: 2,
          auto_deny: true,
          auth_token: AUTH_TOKEN,
        });
        await authDashboard.start();
      });
    });

    afterEach(async () => {
      await authDashboard.stop();
    });

    it("rejects requests without auth token", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/api/status`);
      expect(res.status).toBe(401);
      const data = await res.json();
      expect(data.error).toContain("Unauthorized");
    });

    it("rejects requests with same-length wrong bearer token", async () => {
      const wrongToken = AUTH_TOKEN.replace("12345", "54321");
      const res = await fetch(`http://127.0.0.1:${authPort}/api/status`, {
        headers: { Authorization: `Bearer ${wrongToken}` },
      });
      expect(res.status).toBe(401);
    });

    it("accepts requests with correct bearer token in header", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/api/status`, {
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.pending_count).toBe(0);
    });

    it("gates GET /api/posture/composition behind the SAME checkAuth gate", async () => {
      // Recognition precursor: the composition gate endpoint must sit behind the
      // same bearer gate as the rest of /api/posture/*, never a weaker path.
      const noAuth = await fetch(
        `http://127.0.0.1:${authPort}/api/posture/composition`,
      );
      expect(noAuth.status).toBe(401);

      const wrongToken = AUTH_TOKEN.replace("12345", "54321");
      const badAuth = await fetch(
        `http://127.0.0.1:${authPort}/api/posture/composition`,
        { headers: { Authorization: `Bearer ${wrongToken}` } },
      );
      expect(badAuth.status).toBe(401);
    });

    it("GET /api/posture/composition returns ONLY the gate flag (off, no Concordia/Verascore data)", async () => {
      const res = await fetch(
        `http://127.0.0.1:${authPort}/api/posture/composition`,
        { headers: { Authorization: `Bearer ${AUTH_TOKEN}` } },
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      // Honest default-off: composition is disabled by default, so the gate
      // reports false (config, not absence-of-evidence).
      expect(body.composition_enabled).toBe(false);
      expect(typeof body.origin_machine).toBe("string");
      // The payload carries ONLY the gate flag + origin_machine - never a score,
      // a fetch result, or any Concordia/Verascore field.
      expect(Object.keys(body).sort()).toEqual(
        ["composition_enabled", "origin_machine"].sort(),
      );
    });

    it("rejects session exchange with same-length wrong bearer token", async () => {
      const wrongToken = AUTH_TOKEN.replace("12345", "54321");
      const res = await fetch(`http://127.0.0.1:${authPort}/auth/session`, {
        method: "POST",
        headers: { Authorization: `Bearer ${wrongToken}` },
      });
      expect(res.status).toBe(401);
    });

    it("rejects long-lived token in query parameter (SEC-012)", async () => {
      // SEC-012: The long-lived auth token must NOT be accepted via URL query string.
      // Before the SEC-012 fix, this returned 200. Now it must return 401.
      const res = await fetch(`http://127.0.0.1:${authPort}/api/status?token=${AUTH_TOKEN}`);
      expect(res.status).toBe(401);
    });

    it("accepts session token in query parameter (SEC-012)", async () => {
      // SEC-012: Exchange the long-lived token for a short-lived session
      const exchangeRes = await fetch(`http://127.0.0.1:${authPort}/auth/session`, {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(exchangeRes.status).toBe(200);
      const { session_id } = await exchangeRes.json();

      // Use the session token in the URL — this is the safe replacement
      const res = await fetch(`http://127.0.0.1:${authPort}/api/status?session=${session_id}`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.pending_count).toBe(0);
    });

    it("serves legacy dashboard HTML at /v1.0 with bearer header (SEC-012)", async () => {
      // SEC-012: Dashboard is accessed via Authorization header, not ?token= in URL.
      // v1.1.7: legacy four-panel dashboard moved to /v1.0. This rig has no
      // v11Bindings, so the v1.1 dispatch is dormant and we test legacy.
      const res = await fetch(`http://127.0.0.1:${authPort}/v1.0`, {
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).toContain("Sanctuary");
      expect(text).toContain("Principal Dashboard");
    });

    it("serves login page instead of legacy dashboard at /v1.0 when unauthenticated", async () => {
      // v1.1.7: legacy login flow moved with the legacy dashboard to /v1.0.
      const res = await fetch(`http://127.0.0.1:${authPort}/v1.0`);
      expect(res.status).toBe(200);
      const body = await res.text();
      // Should be the login page, not the full dashboard
      expect(body).toContain("login");
      expect(body).toContain("Auth Token");
      // Dashboard content should NOT be present
      expect(body).not.toContain("Live Activity");
    });

    it("allows OPTIONS requests without auth (CORS preflight)", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/api/status`, {
        method: "OPTIONS",
      });
      expect(res.status).toBe(204);
    });

    it("auth protects approve/deny endpoints", async () => {
      // Start a pending request
      const request: ApprovalRequest = {
        operation: "state_export",
        tier: 1,
        reason: "Test",
        context: {},
        timestamp: new Date().toISOString(),
      };
      const approvalPromise = authDashboard.requestApproval(request);

      // Get the pending ID (with auth)
      const listRes = await fetch(`http://127.0.0.1:${authPort}/api/pending`, {
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      const pending = await listRes.json();
      expect(pending).toHaveLength(1);

      // Try to approve without auth — should fail
      const noAuthRes = await fetch(
        `http://127.0.0.1:${authPort}/api/approve/${pending[0].id}`,
        { method: "POST" }
      );
      expect(noAuthRes.status).toBe(401);

      // Approve with auth — should succeed
      const authRes = await fetch(
        `http://127.0.0.1:${authPort}/api/approve/${pending[0].id}`,
        { method: "POST", headers: { Authorization: `Bearer ${AUTH_TOKEN}` } }
      );
      expect(authRes.status).toBe(200);

      const response = await approvalPromise;
      expect(response.decision).toBe("approve");
      expect(response.decided_by).toBe("human");
    });

    it("SSE requires auth via session query param (SEC-012)", async () => {
      // Without any auth — should be 401
      const noAuth = await fetch(`http://127.0.0.1:${authPort}/events`);
      expect(noAuth.status).toBe(401);

      // With long-lived token in URL — should be 401 (SEC-012 fix)
      const tokenInUrl = await fetch(`http://127.0.0.1:${authPort}/events?token=${AUTH_TOKEN}`);
      expect(tokenInUrl.status).toBe(401);

      // Exchange token for session first
      const exchangeRes = await fetch(`http://127.0.0.1:${authPort}/auth/session`, {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      const { session_id } = await exchangeRes.json();

      // With session — should connect
      const withSession = await fetch(`http://127.0.0.1:${authPort}/events?session=${session_id}`);
      expect(withSession.status).toBe(200);
      expect(withSession.headers.get("content-type")).toBe("text/event-stream");

      const reader = withSession.body!.getReader();
      const decoder = new TextDecoder();
      const { value } = await reader.read();
      const text = decoder.decode(value);
      expect(text).toContain("event: init");

      await reader.cancel();
    });
  });

  // ── Loopback auto-auth carve-out for approval decisions ────────────
  //
  // SECURITY (loopback-no-autoauth-for-approvals): with auth_token set AND
  // loopback auto-auth ON, the legacy approve/deny DECISION must still
  // require the operator token, because the co-resident agent shares the
  // loopback interface. Read-only routes keep the auto-auth convenience.
  describe("Loopback auto-auth does not gate the approve/deny decision", () => {
    const AUTH_TOKEN = "operator-loopback-token";
    let autoDashboard: DashboardApprovalChannel;
    let autoPort: number;

    beforeEach(async () => {
      await bindWithRetry(async () => {
        autoPort = randomTestPort();
        autoDashboard = new DashboardApprovalChannel({
          port: autoPort,
          host: "127.0.0.1",
          timeout_seconds: 2,
          auto_deny: true,
          auth_token: AUTH_TOKEN,
        });
        await autoDashboard.start();
        // Enable loopback auto-auth: the vulnerability precondition.
        autoDashboard.setAutoAuthLocalhost(true);
      });
    });

    afterEach(async () => {
      await autoDashboard.stop();
    });

    const makeReq = (): ApprovalRequest => ({
      operation: "state_export",
      tier: 1,
      reason: "Tier 1 operation",
      context: {},
      timestamp: new Date().toISOString(),
    });

    it("rejects a tokenless loopback POST /api/approve/:id (401) even with auto-auth on", async () => {
      const approvalPromise = autoDashboard.requestApproval(makeReq());
      // Read-only pending list still works under auto-auth, no token.
      const listRes = await fetch(`http://127.0.0.1:${autoPort}/api/pending`);
      expect(listRes.status).toBe(200);
      const pending = await listRes.json();
      expect(pending).toHaveLength(1);

      const res = await fetch(
        `http://127.0.0.1:${autoPort}/api/approve/${pending[0].id}`,
        { method: "POST" },
      );
      expect(res.status).toBe(401);
      // The Tier-1 op must remain pending: the gate held.
      expect(autoDashboard.pendingCount).toBe(1);

      // Clean up the still-pending promise (auto_deny resolves on timeout).
      void approvalPromise.catch(() => undefined);
    });

    it("rejects a tokenless loopback POST /api/deny/:id (401) even with auto-auth on", async () => {
      const approvalPromise = autoDashboard.requestApproval(makeReq());
      const pending = await (
        await fetch(`http://127.0.0.1:${autoPort}/api/pending`)
      ).json();
      const res = await fetch(
        `http://127.0.0.1:${autoPort}/api/deny/${pending[0].id}`,
        { method: "POST" },
      );
      expect(res.status).toBe(401);
      expect(autoDashboard.pendingCount).toBe(1);
      void approvalPromise.catch(() => undefined);
    });

    it("accepts POST /api/approve/:id WITH the operator token (200) under auto-auth", async () => {
      const approvalPromise = autoDashboard.requestApproval(makeReq());
      const pending = await (
        await fetch(`http://127.0.0.1:${autoPort}/api/pending`)
      ).json();
      const res = await fetch(
        `http://127.0.0.1:${autoPort}/api/approve/${pending[0].id}`,
        { method: "POST", headers: { Authorization: `Bearer ${AUTH_TOKEN}` } },
      );
      expect(res.status).toBe(200);
      const response = await approvalPromise;
      expect(response.decision).toBe("approve");
      expect(response.decided_by).toBe("human");
    });

    it("read-only status still served under loopback auto-auth without a token", async () => {
      const res = await fetch(`http://127.0.0.1:${autoPort}/api/status`);
      expect(res.status).toBe(200);
    });

    // legacy-dashboard-approval-route: the approval DECISION routes are
    // dispatched POST-only. There is no live GET handler, so a GET can never
    // release a Tier-1 op — closing any residual "self-approve via GET"
    // door that the POST-only requireToken gate would not cover. This locks
    // the absence in: a GET to /api/approve/:id (even WITH the operator token)
    // must not approve, and the op must stay pending.
    it("a GET to /api/approve/:id never approves (POST-only decision surface, no GET door)", async () => {
      const approvalPromise = autoDashboard.requestApproval(makeReq());
      const pending = await (
        await fetch(`http://127.0.0.1:${autoPort}/api/pending`)
      ).json();
      expect(pending).toHaveLength(1);

      // GET — the legacy buttons USED to emit this (via the GET-only
      // fetchAPI helper). It must NOT resolve the decision. Even with the
      // operator token attached, there is no GET handler to honor it.
      const getRes = await fetch(
        `http://127.0.0.1:${autoPort}/api/approve/${pending[0].id}`,
        { method: "GET", headers: { Authorization: `Bearer ${AUTH_TOKEN}` } },
      );
      expect(getRes.status).toBe(404);
      // The Tier-1 op must remain pending: no GET self-approval occurred.
      expect(autoDashboard.pendingCount).toBe(1);

      void approvalPromise.catch(() => undefined);
    });

    it("a GET to /api/deny/:id never denies (POST-only decision surface, no GET door)", async () => {
      const approvalPromise = autoDashboard.requestApproval(makeReq());
      const pending = await (
        await fetch(`http://127.0.0.1:${autoPort}/api/pending`)
      ).json();
      const getRes = await fetch(
        `http://127.0.0.1:${autoPort}/api/deny/${pending[0].id}`,
        { method: "GET", headers: { Authorization: `Bearer ${AUTH_TOKEN}` } },
      );
      expect(getRes.status).toBe(404);
      expect(autoDashboard.pendingCount).toBe(1);
      void approvalPromise.catch(() => undefined);
    });
  });

  // ── No-auth mode (backward compatibility) ──────────────────────────

  describe("No-auth mode", () => {
    it("allows all requests when auth_token is not configured", async () => {
      // The default dashboard in beforeEach has no auth_token
      const res = await fetch(`http://127.0.0.1:${port}/api/status`);
      expect(res.status).toBe(200);
    });
  });

  // ── Rate Limiting ────────────────────────────────────────────────────
  //
  // v1.3.0 (XXXXX): loopback addresses (127.0.0.1, ::1) are now exempt
  // from rate limiting. Since these tests run against 127.0.0.1, they
  // verify the EXEMPTION — rapid loopback bursts must never 429.
  // Rate limiting for non-loopback addresses is structurally preserved
  // in the code path but cannot be integration-tested without a
  // non-loopback bind address.

  describe("Rate Limiting", () => {
    it("loopback is exempt: 125 rapid API requests never return 429 (XXXXX)", async () => {
      // v1.3.0 (XXXXX): loopback exemption. Previously this test expected
      // 429 after 120 requests. Now loopback is always allowed.
      const results: number[] = [];
      for (let i = 0; i < 125; i++) {
        const res = await fetch(`http://127.0.0.1:${port}/api/status`);
        results.push(res.status);
      }
      expect(results).not.toContain(429);
      expect(results.every((s) => s === 200)).toBe(true);
    });

    // v0.10.0-rc.2 regression guard: exempt HTML/SSE view routes from the
    // general rate limit so the operator can never 429 themselves out of
    // their own dashboard on a normal browser refresh. These tests still
    // hold under the XXXXX loopback exemption.
    it("does NOT rate-limit HTML view route `/v1.0` (rc.2 regression, v1.1.7 path-flip)", { retry: 2 }, async () => {
      const results: number[] = [];
      for (let i = 0; i < 125; i++) {
        const res = await fetch(`http://127.0.0.1:${port}/v1.0`);
        results.push(res.status);
      }
      expect(results).not.toContain(429);
      for (const s of results) expect(s).toBe(200);
    });

    it("does NOT rate-limit /dashboard (rc.2 regression)", { retry: 2 }, async () => {
      const results: number[] = [];
      for (let i = 0; i < 125; i++) {
        const res = await fetch(`http://127.0.0.1:${port}/dashboard`);
        results.push(res.status);
      }
      expect(results).not.toContain(429);
    });

    it("loopback is exempt: rapid API requests stay 200 while views also stay 200 (XXXXX, rc.2 update)", { retry: 2 }, async () => {
      // Previously this test expected API routes to 429 while view routes
      // stayed green, proving scoped exemption. With XXXXX loopback
      // exemption, both stay green from loopback. The rate limiter's
      // view/API distinction is preserved for non-loopback addresses.
      const viewResults: number[] = [];
      const apiResults: number[] = [];
      for (let i = 0; i < 125; i++) {
        const r = await fetch(`http://127.0.0.1:${port}/`);
        viewResults.push(r.status);
      }
      for (let i = 0; i < 125; i++) {
        const r = await fetch(`http://127.0.0.1:${port}/api/status`);
        apiResults.push(r.status);
      }
      expect(viewResults).not.toContain(429);
      expect(apiResults).not.toContain(429);
    });

    it("loopback is exempt: rapid decision approvals never return 429 (XXXXX)", async () => {
      // Previously tested tight rate limit on decisions (20/min). With
      // XXXXX loopback exemption, decisions from loopback are always allowed.
      const promises: Promise<unknown>[] = [];
      for (let i = 0; i < 25; i++) {
        promises.push(
          dashboard.requestApproval({
            operation: "state_export",
            tier: 1,
            reason: "Rate limit test",
            context: {},
            timestamp: new Date().toISOString(),
          })
        );
      }

      const listRes = await fetch(`http://127.0.0.1:${port}/api/pending`);
      const pending = await listRes.json();
      expect(pending.length).toBeGreaterThan(20);

      const results: number[] = [];
      for (const p of pending) {
        const res = await fetch(
          `http://127.0.0.1:${port}/api/approve/${p.id}`,
          { method: "POST" }
        );
        results.push(res.status);
      }
      expect(results).not.toContain(429);
    });
  });

  // ── Cleanup ──────────────────────────────────────────────────────────

  describe("Cleanup", () => {
    it("stop() resolves all pending requests as deny", async () => {
      const request: ApprovalRequest = {
        operation: "state_export",
        tier: 1,
        reason: "Test",
        context: {},
        timestamp: new Date().toISOString(),
      };

      const approvalPromise = dashboard.requestApproval(request);
      expect(dashboard.pendingCount).toBe(1);

      // Stop the dashboard — should resolve all pending as deny
      await dashboard.stop();

      const response = await approvalPromise;
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("auto");
    });
  });

  // ── XXXXX: Rate limit loopback exemption + /api/health ──────────────

  describe("XXXXX: rate limit + health endpoint", () => {
    it("/api/health returns 200 without auth (XXXXX)", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/api/health`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.ok).toBe(true);
      expect(data.mode).toBe("principal-policy");
    });

    it("/api/health has no-store cache header (XXXXX)", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/api/health`);
      expect(res.headers.get("cache-control")).toBe("no-store");
    });

    it("60 rapid loopback requests to /api/health never return 429 (XXXXX)", async () => {
      // All requests come from 127.0.0.1 (loopback). With XXXXX fix,
      // loopback is exempt from rate limiting, so this must never 429.
      const results = await Promise.all(
        Array.from({ length: 60 }, () =>
          fetch(`http://127.0.0.1:${port}/api/health`).then((r) => r.status),
        ),
      );
      expect(results.every((s) => s === 200)).toBe(true);
    });

    it("rapid loopback requests to /api/status never return 429 (XXXXX)", async () => {
      // Loopback exemption applies to all API endpoints, not just health.
      const results = await Promise.all(
        Array.from({ length: 60 }, () =>
          fetch(`http://127.0.0.1:${port}/api/status`).then((r) => r.status),
        ),
      );
      expect(results.every((s) => s === 200)).toBe(true);
    });
  });
});
