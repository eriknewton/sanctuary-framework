/**
 * Sanctuary MCP Server — Principal Dashboard Tests
 *
 * Tests the DashboardApprovalChannel: HTTP server, SSE, approval flow,
 * and timeout behavior.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import type { ApprovalRequest, ApprovalResponse } from "../../src/principal-policy/types.js";

// Use a random port to avoid conflicts in parallel test runs
function randomPort(): number {
  return 10000 + Math.floor(Math.random() * 50000);
}

describe("Principal Dashboard", () => {
  let dashboard: DashboardApprovalChannel;
  let port: number;

  beforeEach(async () => {
    port = randomPort();
    dashboard = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 2, // Short timeout for tests
      auto_deny: true,
    });
    await dashboard.start();
  });

  afterEach(async () => {
    await dashboard.stop();
  });

  // ── HTTP Server ──────────────────────────────────────────────────────

  describe("HTTP Server", () => {
    it("serves the dashboard HTML at /", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/`);
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
      const res = await fetch(
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
      approvePort = randomPort();
      approvalDashboard = new DashboardApprovalChannel({
        port: approvePort,
        host: "127.0.0.1",
        timeout_seconds: 1,
        auto_deny: false, // SEC-002: this is now ignored
      });
      await approvalDashboard.start();
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

      reader.cancel();
    });

    it("tracks connected clients", async () => {
      expect(dashboard.clientCount).toBe(0);

      const response = await fetch(`http://127.0.0.1:${port}/events`);
      const reader = response.body!.getReader();
      await reader.read(); // Wait for init message

      // Give the server a moment to register the client
      await new Promise((r) => setTimeout(r, 50));
      expect(dashboard.clientCount).toBe(1);

      reader.cancel();
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

      reader.cancel();
    });
  });

  // ── Authentication ──────────────────────────────────────────────────

  describe("Authentication", () => {
    const AUTH_TOKEN = "test-secret-token-12345";
    let authDashboard: DashboardApprovalChannel;
    let authPort: number;

    beforeEach(async () => {
      authPort = randomPort();
      authDashboard = new DashboardApprovalChannel({
        port: authPort,
        host: "127.0.0.1",
        timeout_seconds: 2,
        auto_deny: true,
        auth_token: AUTH_TOKEN,
      });
      await authDashboard.start();
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

    it("rejects requests with wrong bearer token", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/api/status`, {
        headers: { Authorization: "Bearer wrong-token" },
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

    it("accepts requests with correct token in query parameter", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/api/status?token=${AUTH_TOKEN}`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.pending_count).toBe(0);
    });

    it("serves dashboard HTML with correct query token", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/?token=${AUTH_TOKEN}`);
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).toContain("Sanctuary");
      expect(text).toContain("Principal Dashboard");
    });

    it("rejects dashboard HTML without token", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/`);
      expect(res.status).toBe(401);
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

    it("SSE requires auth via query param", async () => {
      // Without token — should be 401
      const noAuth = await fetch(`http://127.0.0.1:${authPort}/events`);
      expect(noAuth.status).toBe(401);

      // With token — should connect
      const withAuth = await fetch(`http://127.0.0.1:${authPort}/events?token=${AUTH_TOKEN}`);
      expect(withAuth.status).toBe(200);
      expect(withAuth.headers.get("content-type")).toBe("text/event-stream");

      const reader = withAuth.body!.getReader();
      const decoder = new TextDecoder();
      const { value } = await reader.read();
      const text = decoder.decode(value);
      expect(text).toContain("event: init");

      reader.cancel();
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
});
