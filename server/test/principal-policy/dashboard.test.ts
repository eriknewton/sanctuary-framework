/**
 * Sanctuary MCP Server — Principal Dashboard Tests
 *
 * Tests the DashboardApprovalChannel: HTTP server, SSE, approval flow,
 * and timeout behavior.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import {
  DashboardApprovalChannel,
  ipv6Slash64Prefix,
} from "../../src/principal-policy/dashboard.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
  PrincipalPolicy,
} from "../../src/principal-policy/types.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

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

  const DECISION_TEST_TOKEN = "decision-test-token-12345";

  async function withDecisionDashboard<T>(
    run: (rig: {
      channel: DashboardApprovalChannel;
      port: number;
      authHeaders: Record<string, string>;
    }) => Promise<T>,
  ): Promise<T> {
    let channel: DashboardApprovalChannel | undefined;
    let decisionPort = 0;
    await bindWithRetry(async () => {
      decisionPort = randomTestPort();
      channel = new DashboardApprovalChannel({
        port: decisionPort,
        host: "127.0.0.1",
        timeout_seconds: 30,
        auto_deny: true,
        auth_token: DECISION_TEST_TOKEN,
      });
      await channel.start();
    });

    try {
      return await run({
        channel: channel!,
        port: decisionPort,
        authHeaders: { Authorization: `Bearer ${DECISION_TEST_TOKEN}` },
      });
    } finally {
      await channel?.stop();
    }
  }

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
        // Generous timeout: the human-decision tests (approve/deny/concurrent)
        // must never race the production auto-deny timer under a >2s event-loop
        // stall during full-suite CI load. The genuine timeout-behavior test
        // ("auto-denies on timeout when auto_deny is true") builds its OWN
        // short-timeout dashboard so this value does not affect it.
        timeout_seconds: 30,
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

  // ── /api/readiness supervisor bridge (brief D3, Fix 1) ───────────────
  // The principal-policy dashboard CAN run Protect: it routes through the
  // supervisor bridge, and an absent bridge means Protect fails closed with
  // 503. So `supervisor` must report the REAL bridge state - "unwired" when
  // null (the production reality today, since setSupervisorBridge is not yet
  // called in production), "wired" once a bridge is bound. It must never mask
  // an absent bridge as "n/a" here, because absence guarantees a 503.
  describe("/api/readiness supervisor signal", () => {
    it("reports supervisor=unwired when no bridge is bound (Protect would 503)", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/api/readiness`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.supervisor).toBe("unwired");
      // It must NOT mask the absent bridge as "n/a": absence => 503.
      expect(body.supervisor).not.toBe("n/a");
    });

    it("reports supervisor=wired once a bridge is bound via setSupervisorBridge", async () => {
      // The readiness handler only checks the bridge for presence (truthiness);
      // it never calls into it for the readiness value, so a bare stub is
      // sufficient ground truth for "a bridge is bound".
      const stubBridge = {
        launchProtect: async () => ({ ok: false }),
      } as unknown as Parameters<typeof dashboard.setSupervisorBridge>[0];
      dashboard.setSupervisorBridge(stubBridge);
      try {
        const res = await fetch(`http://127.0.0.1:${port}/api/readiness`);
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.supervisor).toBe("wired");
      } finally {
        // Detach so we don't leak the stub into sibling tests.
        dashboard.setSupervisorBridge(null);
      }
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
      await withDecisionDashboard(async ({ channel, port, authHeaders }) => {
        const request = makeRequest();

        // Start approval (don't await — it blocks)
        const approvalPromise = channel.requestApproval(request);
        expect(channel.pendingCount).toBe(1);

        // Get the pending list to find the ID
        const listRes = await fetch(`http://127.0.0.1:${port}/api/pending`, {
          headers: authHeaders,
        });
        const pending = await listRes.json();
        expect(pending).toHaveLength(1);
        expect(pending[0].operation).toBe("state_export");

        // Approve
        const approveRes = await fetch(
          `http://127.0.0.1:${port}/api/approve/${pending[0].id}`,
          { method: "POST", headers: authHeaders },
        );
        expect(approveRes.status).toBe(200);

        // The approval promise should resolve
        const response = await approvalPromise;
        expect(response.decision).toBe("approve");
        expect(response.decided_by).toBe("human");
        expect(channel.pendingCount).toBe(0);
      });
    });

    it("creates pending request and resolves on deny", async () => {
      await withDecisionDashboard(async ({ channel, port, authHeaders }) => {
        const request = makeRequest();
        const approvalPromise = channel.requestApproval(request);

        const listRes = await fetch(`http://127.0.0.1:${port}/api/pending`, {
          headers: authHeaders,
        });
        const pending = await listRes.json();
        expect(pending).toHaveLength(1);

        const denyRes = await fetch(
          `http://127.0.0.1:${port}/api/deny/${pending[0].id}`,
          { method: "POST", headers: authHeaders },
        );
        expect(denyRes.status).toBe(200);

        const response = await approvalPromise;
        expect(response.decision).toBe("deny");
        expect(response.decided_by).toBe("human");
      });
    });

    it("returns 404 for non-existent request ID", async () => {
      await withDecisionDashboard(async ({ port, authHeaders }) => {
        const res = await requestNoKeepAlive(
          `http://127.0.0.1:${port}/api/approve/nonexistent`,
          { method: "POST", headers: authHeaders },
        );
        expect(res.status).toBe(404);
      });
    });

    it("auto-denies on timeout when auto_deny is true", async () => {
      // The top-level dashboard runs a generous 30s timeout so the
      // human-decision tests never race the auto-deny under load. This test
      // genuinely needs a SHORT timeout to observe the auto-deny within the
      // 5000ms budget, so it builds its own short-timeout dashboard (mirroring
      // the SEC-002 rig below) and tears it down in a finally.
      let timeoutDashboard: DashboardApprovalChannel | undefined;
      let timeoutPort: number;
      await bindWithRetry(async () => {
        timeoutPort = randomTestPort();
        timeoutDashboard = new DashboardApprovalChannel({
          port: timeoutPort,
          host: "127.0.0.1",
          timeout_seconds: 2,
          auto_deny: true,
        });
        await timeoutDashboard.start();
      });
      try {
        const request = makeRequest();
        const response = await timeoutDashboard!.requestApproval(request);
        // With 2-second timeout, this should auto-deny
        expect(response.decision).toBe("deny");
        expect(response.decided_by).toBe("timeout");
        expect(timeoutDashboard!.pendingCount).toBe(0);
      } finally {
        await timeoutDashboard?.stop();
      }
    }, 5000);

    it("handles multiple concurrent pending requests", async () => {
      await withDecisionDashboard(async ({ channel, port, authHeaders }) => {
        const req1 = { ...makeRequest(), operation: "state_export" };
        const req2 = { ...makeRequest(), operation: "identity_rotate" };

        const p1 = channel.requestApproval(req1);
        const p2 = channel.requestApproval(req2);
        expect(channel.pendingCount).toBe(2);

        // Get pending list
        const listRes = await fetch(`http://127.0.0.1:${port}/api/pending`, {
          headers: authHeaders,
        });
        const pending = await listRes.json();
        expect(pending).toHaveLength(2);

        // Approve first, deny second
        await fetch(`http://127.0.0.1:${port}/api/approve/${pending[0].id}`, {
          method: "POST",
          headers: authHeaders,
        });
        await fetch(`http://127.0.0.1:${port}/api/deny/${pending[1].id}`, {
          method: "POST",
          headers: authHeaders,
        });

        const [r1, r2] = await Promise.all([p1, p2]);
        // Order depends on which ID maps to which request
        const decisions = [r1.decision, r2.decision].sort();
        expect(decisions).toEqual(["approve", "deny"]);
        expect(channel.pendingCount).toBe(0);
      });
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
      expect(data.error).toContain("unauthorized");
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

    // ── /api/readiness (auth-gated, brief D3) ─────────────────────────
    it("rejects /api/readiness without an auth token", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/api/readiness`);
      expect(res.status).toBe(401);
      const data = await res.json();
      // It must not leak readiness in the unauthorized body.
      expect(data.ready).toBeUndefined();
      expect(data.supervisor).toBeUndefined();
    });

    it("rejects /api/readiness with a same-length wrong bearer token", async () => {
      const wrongToken = AUTH_TOKEN.replace("12345", "54321");
      const res = await fetch(`http://127.0.0.1:${authPort}/api/readiness`, {
        headers: { Authorization: `Bearer ${wrongToken}` },
      });
      expect(res.status).toBe(401);
    });

    it("returns { ready, supervisor } with a valid bearer token (locked by default)", async () => {
      const res = await fetch(`http://127.0.0.1:${authPort}/api/readiness`, {
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(Object.keys(data).sort()).toEqual(["ready", "supervisor"]);
      // No identity manager wired on this rig -> honest "locked". No supervisor
      // bridge bound on this rig -> honest "unwired" (the principal-policy
      // dashboard CAN run Protect, so an absent bridge guarantees a Protect 503;
      // masking that as "n/a" would be dishonest, brief Fix 1).
      expect(data.ready).toBe("locked");
      expect(data.supervisor).toBe("unwired");
    });

    it("reports ready=serving once an identity manager is wired (unlocked)", async () => {
      authDashboard.setDependencies({
        policy: {} as never,
        baseline: { getProfile: () => ({}) } as never,
        auditLog: {} as never,
        identityManager: {} as never,
      });
      const res = await fetch(`http://127.0.0.1:${authPort}/api/readiness`, {
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.ready).toBe("serving");
      // Still no supervisor bridge bound -> honest "unwired" (see above).
      expect(data.supervisor).toBe("unwired");
    });

    it("includes approval_redirect mode in /api/status for folded approval routing", async () => {
      const policy: PrincipalPolicy = {
        version: 1,
        tier1_always_approve: ["state_export"],
        tier2_anomaly: {
          new_namespace_access: "approve",
          new_counterparty: "approve",
          frequency_spike_multiplier: 3,
          max_signs_per_minute: 10,
          bulk_read_threshold: 20,
          first_session_policy: "approve",
        },
        tier3_always_allow: [],
        approval_channel: {
          type: "callback",
          timeout_seconds: 2,
          auto_deny: true,
        },
        approval_redirect: {
          enabled: true,
          mode: "replace",
        },
      };
      authDashboard.setDependencies({
        policy,
        baseline: { getProfile: () => ({}) } as never,
        auditLog: {} as never,
      });

      const res = await fetch(`http://127.0.0.1:${authPort}/api/status`, {
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.policy.approval_redirect).toEqual({
        enabled: true,
        mode: "replace",
      });
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

    it("sets the dashboard login cookie SameSite=Lax", async () => {
      // C1 re-auth fix: Lax (not Strict) so a cross-host Fleet "Open Console"
      // top-level navigation carries a still-valid session and does NOT
      // re-prompt. Lax still withholds the cookie on cross-site POSTs, so the
      // approval-decision routes stay CSRF-safe.
      const res = await fetch(`http://127.0.0.1:${authPort}/auth/session`, {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const cookie = res.headers.get("set-cookie") ?? "";
      expect(cookie).toContain("sanctuary_session=");
      expect(cookie).toContain("SameSite=Lax");
      expect(cookie).not.toContain("SameSite=Strict");
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

    it("one-click session authenticates posture reads but not approval decisions, while invalid sessions stay 401", async () => {
      const policy: PrincipalPolicy = {
        version: 1,
        tier1_always_approve: ["state_export"],
        tier2_anomaly: {
          new_namespace_access: "approve",
          new_counterparty: "approve",
          frequency_spike_multiplier: 3,
          max_signs_per_minute: 10,
          bulk_read_threshold: 20,
          first_session_policy: "approve",
        },
        tier3_always_allow: [],
        approval_channel: {
          type: "dashboard",
          timeout_seconds: 2,
          auto_deny: true,
        },
      };
      authDashboard.setDependencies({
        policy,
        baseline: { getProfile: () => ({}) } as never,
        auditLog: new AuditLog(new MemoryStorage(), generateRandomKey()),
      });

      const exchangeRes = await fetch(`http://127.0.0.1:${authPort}/auth/session`, {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(exchangeRes.status).toBe(200);
      expect(exchangeRes.headers.get("set-cookie") ?? "").toContain("SameSite=Lax");
      const { session_id } = await exchangeRes.json();
      const session = encodeURIComponent(session_id);

      const postureRes = await fetch(
        `http://127.0.0.1:${authPort}/api/posture/home?session=${session}`,
      );
      expect(postureRes.status).toBe(200);
      const posture = await postureRes.json();
      expect(posture.stream_available).toBe(true);

      const request: ApprovalRequest = {
        operation: "state_export",
        tier: 1,
        reason: "One-click session decision",
        context: {},
        timestamp: new Date().toISOString(),
      };
      const approvalPromise = authDashboard.requestApproval(request);
      const pendingRes = await fetch(
        `http://127.0.0.1:${authPort}/api/pending?session=${session}`,
      );
      expect(pendingRes.status).toBe(200);
      const pending = await pendingRes.json();
      expect(pending).toHaveLength(1);

      const badRead = await fetch(
        `http://127.0.0.1:${authPort}/api/posture/home?session=not-a-valid-session`,
      );
      expect(badRead.status).toBe(401);
      const badDecision = await fetch(
        `http://127.0.0.1:${authPort}/api/approve/${pending[0].id}?session=not-a-valid-session`,
        { method: "POST" },
      );
      expect(badDecision.status).toBe(401);
      expect(authDashboard.pendingCount).toBe(1);

      const sessionDecisionRes = await fetch(
        `http://127.0.0.1:${authPort}/api/approve/${pending[0].id}?session=${session}`,
        { method: "POST" },
      );
      expect(sessionDecisionRes.status).toBe(401);
      expect(authDashboard.pendingCount).toBe(1);

      const cookieDecisionRes = await fetch(
        `http://127.0.0.1:${authPort}/api/deny/${pending[0].id}`,
        {
          method: "POST",
          headers: { Cookie: `sanctuary_session=${session_id}` },
        },
      );
      expect(cookieDecisionRes.status).toBe(401);
      expect(authDashboard.pendingCount).toBe(1);

      const decisionRes = await fetch(
        `http://127.0.0.1:${authPort}/api/approve/${pending[0].id}`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
        },
      );
      expect(decisionRes.status).toBe(200);
      const decision = await approvalPromise;
      expect(decision.decision).toBe("approve");
      expect(decision.decided_by).toBe("human");
    });

    it("strict legacy mutations fail closed when no operator token is configured", async () => {
      let noTokenDashboard: DashboardApprovalChannel | undefined;
      let noTokenPort = 0;
      try {
        await bindWithRetry(async () => {
          noTokenPort = randomTestPort();
          noTokenDashboard = new DashboardApprovalChannel({
            port: noTokenPort,
            host: "127.0.0.1",
            timeout_seconds: 2,
            auto_deny: true,
          });
          await noTokenDashboard.start();
        });
        noTokenDashboard!.setAutoAuthLocalhost(true);
        noTokenDashboard!.setUnlockHandler(async () => true);

        const approvalPromise = noTokenDashboard!.requestApproval({
          operation: "state_export",
          tier: 1,
          reason: "No configured token must not fail open",
          context: {},
          timestamp: new Date().toISOString(),
        });
        void approvalPromise.catch(() => undefined);
        const pending = await (
          await fetch(`http://127.0.0.1:${noTokenPort}/api/pending`)
        ).json();
        const id = pending[0].id;
        const cases = [
          [`/api/unlock`, { passphrase: "irrelevant" }],
          [`/api/approve/${id}`, null],
          [`/api/deny/${id}`, null],
          [`/api/sovereignty-profile`, {}],
          [`/api/proxy/servers`, { upstream_servers: [] }],
        ] as const;

        for (const [path, body] of cases) {
          const res = await fetch(`http://127.0.0.1:${noTokenPort}${path}`, {
            method: "POST",
            headers: body === null ? undefined : { "Content-Type": "application/json" },
            body: body === null ? undefined : JSON.stringify(body),
          });
          expect(res.status, path).toBe(401);
        }
      } finally {
        await noTokenDashboard?.stop();
      }
    });

    it("strict legacy config mutations reject loopback/session auth and accept a valid bearer", async () => {
      authDashboard.setAutoAuthLocalhost(true);
      const exchangeRes = await fetch(`http://127.0.0.1:${authPort}/auth/session`, {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(exchangeRes.status).toBe(200);
      const { session_id } = await exchangeRes.json();
      const routes = [
        [`/api/sovereignty-profile`, {}],
        [`/api/proxy/servers`, { upstream_servers: [] }],
      ] as const;

      for (const [path, body] of routes) {
        const tokenless = await fetch(`http://127.0.0.1:${authPort}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        expect(tokenless.status, `${path} tokenless`).toBe(401);

        const session = await fetch(
          `http://127.0.0.1:${authPort}${path}?session=${encodeURIComponent(session_id)}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          },
        );
        expect(session.status, `${path} session`).toBe(401);

        const cookie = await fetch(`http://127.0.0.1:${authPort}${path}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Cookie: `sanctuary_session=${session_id}`,
          },
          body: JSON.stringify(body),
        });
        expect(cookie.status, `${path} cookie`).toBe(401);

        const bearer = await fetch(`http://127.0.0.1:${authPort}${path}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${AUTH_TOKEN}`,
          },
          body: JSON.stringify(body),
        });
        expect(bearer.status, `${path} bearer reached handler`).not.toBe(401);
      }
    });

    it("strict unlock rejects loopback/session auth and accepts a valid bearer", async () => {
      await withDecisionDashboard(async ({ channel, port, authHeaders }) => {
        channel.setAutoAuthLocalhost(true);
        let calls = 0;
        channel.setUnlockHandler(async () => {
          calls += 1;
          return true;
        });
        (channel as unknown as { _parked: boolean })._parked = true;
        const exchangeRes = await fetch(`http://127.0.0.1:${port}/auth/session`, {
          method: "POST",
          headers: authHeaders,
        });
        expect(exchangeRes.status).toBe(200);
        const { session_id } = await exchangeRes.json();
        const body = JSON.stringify({ passphrase: "secret" });

        const tokenless = await fetch(`http://127.0.0.1:${port}/api/unlock`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
        });
        expect(tokenless.status).toBe(401);

        const session = await fetch(
          `http://127.0.0.1:${port}/api/unlock?session=${encodeURIComponent(session_id)}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
          },
        );
        expect(session.status).toBe(401);

        const cookie = await fetch(`http://127.0.0.1:${port}/api/unlock`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Cookie: `sanctuary_session=${session_id}`,
          },
          body,
        });
        expect(cookie.status).toBe(401);

        const bearer = await fetch(`http://127.0.0.1:${port}/api/unlock`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...authHeaders,
          },
          body,
        });
        expect(bearer.status).toBe(200);
        expect(calls).toBe(1);
      });
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

  // ── C1 Finding 5: remote console reuses a valid session, no re-prompt ──
  //
  // The Open Console fix navigates the SAME TAB to a remote host's posture
  // root. On a REMOTE bind (non-loopback host) `dispatchRootPosture` serves the
  // login page when the caller is unauthenticated, so an operator gets a token
  // box instead of a blank shell. The defect this group pins: a return visit
  // bearing a STILL-VALID `sanctuary_session` cookie must NOT re-prompt — the
  // session must be reused. The HARD constraint: a caller with NO token AND no
  // valid session must STILL get the login page. Auth is never weakened.
  describe("Remote console reuses a valid session cookie (Finding 5)", () => {
    const AUTH_TOKEN = "remote-operator-token-9876";
    let remoteDashboard: DashboardApprovalChannel;
    let remotePort: number;

    beforeEach(async () => {
      await bindWithRetry(async () => {
        remotePort = randomTestPort();
        // host "0.0.0.0" -> isRemoteBinding() true (non-loopback), so the
        // dispatchRootPosture login-gate path is exercised. 0.0.0.0 still
        // listens on loopback, so the test fetches via 127.0.0.1. Plaintext
        // is allowed for the test (the network-layer encryption carve-out).
        remoteDashboard = new DashboardApprovalChannel({
          port: remotePort,
          host: "0.0.0.0",
          timeout_seconds: 2,
          auto_deny: true,
          auth_token: AUTH_TOKEN,
          allow_plaintext_remote: true,
        });
        await remoteDashboard.start();
      });
    });

    afterEach(async () => {
      await remoteDashboard.stop();
    });

    it("serves the LOGIN page at / when no token and no session are present", async () => {
      const res = await requestNoKeepAlive(`http://127.0.0.1:${remotePort}/`);
      expect(res.status).toBe(200);
      // Login page markers (token box + Open Dashboard button), NOT the shell.
      expect(res.body).toContain('id="auth-token"');
      expect(res.body).toContain("Open Dashboard");
      // S2 (2026-07-18): posture page identity renamed "Sovereignty Posture"
      // -> "Security Posture" (copy rule: sovereignty never on screen). The
      // login page is not the posture shell, so it carries neither string.
      expect(res.body).not.toContain("Security Posture");
    });

    it("serves the DASHBOARD shell at / when a VALID session cookie is presented (no re-prompt)", async () => {
      // Mint a real session the same way the login flow does.
      const exchange = await fetch(`http://127.0.0.1:${remotePort}/auth/session`, {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(exchange.status).toBe(200);
      const setCookie = exchange.headers.get("set-cookie") ?? "";
      expect(setCookie).toContain("sanctuary_session=");
      // Lax (the Finding 5 fix) so the cross-host top-level navigation carries it.
      expect(setCookie).toContain("SameSite=Lax");
      const sessionId = (await exchange.json()).session_id as string;

      // Return visit on a fresh load: the browser sends only the cookie.
      const res = await requestNoKeepAlive(`http://127.0.0.1:${remotePort}/`, {
        headers: { Cookie: `sanctuary_session=${sessionId}` },
      });
      expect(res.status).toBe(200);
      // The posture shell, NOT the login page: no re-prompt.
      // S2: page identity renamed "Sovereignty Posture" -> "Security Posture".
      expect(res.body).toContain("Security Posture");
      expect(res.body).not.toContain('id="auth-token"');
    });

    it("still serves the LOGIN page at / for an INVALID/expired session cookie (auth not weakened)", async () => {
      const res = await requestNoKeepAlive(`http://127.0.0.1:${remotePort}/`, {
        headers: { Cookie: "sanctuary_session=not-a-real-session-id" },
      });
      expect(res.status).toBe(200);
      expect(res.body).toContain('id="auth-token"');
      // S2: page identity renamed "Sovereignty Posture" -> "Security Posture".
      expect(res.body).not.toContain("Security Posture");
    });

    it("still 401s the data routes without a token or valid session (auth not weakened)", async () => {
      const res = await fetch(`http://127.0.0.1:${remotePort}/api/status`);
      expect(res.status).toBe(401);
    });
  });

  // ── C1 Finding 5: loopback root behavior is unchanged ──────────────
  describe("Loopback posture root is unchanged by the Finding 5 fix", () => {
    const AUTH_TOKEN = "loopback-operator-token-5555";
    let loopbackDashboard: DashboardApprovalChannel;
    let loopbackPort: number;

    beforeEach(async () => {
      await bindWithRetry(async () => {
        loopbackPort = randomTestPort();
        loopbackDashboard = new DashboardApprovalChannel({
          port: loopbackPort,
          host: "127.0.0.1",
          timeout_seconds: 2,
          auto_deny: true,
          auth_token: AUTH_TOKEN,
        });
        // Loopback auto-auth ON (the local-operator-after-terminal-unlock case).
        loopbackDashboard.setAutoAuthLocalhost(true);
        await loopbackDashboard.start();
      });
    });

    afterEach(async () => {
      await loopbackDashboard.stop();
    });

    it("serves the posture shell tokenless on loopback (no login gate, no re-prompt)", async () => {
      const res = await requestNoKeepAlive(`http://127.0.0.1:${loopbackPort}/`);
      expect(res.status).toBe(200);
      // The one-surface contract: loopback root is the shell, never the login
      // page. The Finding 5 cookie change must not regress this.
      // S2: page identity renamed "Sovereignty Posture" -> "Security Posture".
      expect(res.body).toContain("Security Posture");
      expect(res.body).not.toContain('id="auth-token"');
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

    // dashboard-native-embed-loopback-read: the castle-wall-macos native app
    // embeds the posture board and reads `/api/posture/castle-wall` for the arm
    // badge over a TOKENLESS loopback request (no bearer token, no session,
    // see PostureWebView/SanctuaryServerBridge). That read MUST clear the auth
    // gate under loopback auto-auth, otherwise the badge sticks on "Checking
    // enforcement…" and the embed renders a raw 401 page. This locks the
    // posture-read route as a read-only route the auto-auth fast path covers
    // (NOT a `requireToken` approval-decision route). Its companion above
    // (`rejects a tokenless loopback POST /api/approve/:id (401)`) locks the
    // opposite half: the approval-decision surface stays 401 even with auto-auth
    // on. Scope note: this `beforeEach` toggles the flag directly via
    // `setAutoAuthLocalhost(true)`, so what is locked here is the routing-layer
    // (`checkAuth`) carve-out (posture reads pass, approve/deny stay 401), NOT
    // the wiring that turns the flag on. The `sanctuary --dashboard` boot path
    // (`createSanctuaryServer` in index.ts) enables this fast path the same way
    // `sanctuary dashboard` does, but that boot wiring is a 1:1 copy of the
    // proven dashboard-standalone guard and is not directly exercised by this
    // test; reverting the index.ts change would not fail these cases.
    it("tokenless loopback GET /api/posture/castle-wall is NOT 401 under auto-auth (native embed read)", async () => {
      const res = await fetch(
        `http://127.0.0.1:${autoPort}/api/posture/castle-wall`,
      );
      // The contract the native embed needs is the AUTH boundary: a tokenless
      // loopback read must clear `checkAuth` (never 401). This bare test channel
      // has no posture dependencies wired, so the handler itself may 404/503;
      // what matters here is that auto-auth let the request THROUGH the auth
      // gate (in contrast to the approve/deny routes, which stay 401).
      expect(res.status).not.toBe(401);
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

    // Federation P1 DoS hardening: the federation peer rate-limit bucket keys
    // IPv6 to its /64 prefix so an attacker rotating addresses within one /64
    // shares one bucket. The helper is pure; test it directly.
    describe("ipv6Slash64Prefix (Federation P1 /64 aggregation)", () => {
      it("aggregates distinct addresses in the same /64 to the same key", () => {
        const a = ipv6Slash64Prefix("2001:db8:abcd:1234:0:0:0:1");
        const b = ipv6Slash64Prefix("2001:db8:abcd:1234:ffff:ffff:ffff:ffff");
        expect(a).toBe("2001:db8:abcd:1234::/64");
        expect(a).toBe(b);
      });

      it("keeps addresses in DIFFERENT /64s on distinct keys", () => {
        const a = ipv6Slash64Prefix("2001:db8:abcd:1234::1");
        const b = ipv6Slash64Prefix("2001:db8:abcd:9999::1");
        expect(a).not.toBe(b);
      });

      it("expands a single `::` zero-run before taking the prefix", () => {
        // ::1 -> 0:0:0:0:0:0:0:1 -> first four hextets all zero.
        expect(ipv6Slash64Prefix("::1")).toBe("0:0:0:0::/64");
        // fe80::1 -> fe80:0:0:0:...
        expect(ipv6Slash64Prefix("fe80::1")).toBe("fe80:0:0:0::/64");
      });

      it("returns null for IPv4, mapped-IPv4, and malformed inputs (caller keys verbatim)", () => {
        expect(ipv6Slash64Prefix("127.0.0.1")).toBeNull();
        expect(ipv6Slash64Prefix("203.0.113.7")).toBeNull();
        expect(ipv6Slash64Prefix("::ffff:1.2.3.4")).toBeNull(); // mapped IPv4
        expect(ipv6Slash64Prefix("unknown")).toBeNull();
        expect(ipv6Slash64Prefix("2001:db8::1::2")).toBeNull(); // two "::"
        expect(ipv6Slash64Prefix("fe80::1%eth0")).toBeNull(); // zone id
        expect(ipv6Slash64Prefix("gggg::1")).toBeNull(); // non-hex
      });
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
      // brief D3: opaque restart-detection signal is present.
      expect(typeof data.instance).toBe("string");
      expect(typeof data.since).toBe("number");
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

  // ── One-surface default-flip fallback (Piece C) ─────────────────────
  //
  // Default-flip (2026-06-30): when v1.1 bindings are wired (the production
  // standalone dashboard ALWAYS wires them), `/` serves the v1.1 concierge as
  // the single default surface (proven in test/dashboard/v1_1-routing.test.ts).
  // This rig boots a bare DashboardApprovalChannel with NO v1.1 bindings, so
  // there is no concierge to serve and `/` keeps serving the posture board as
  // the honest fallback rather than 404ing. These tests pin THAT fallback.
  describe("Default-flip fallback: posture board served at / without v1.1 bindings", () => {
    it("GET / serves the posture board HTML (no-bindings fallback)", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/html");
      const body = await res.text();
      // The posture-home shell fetches the posture API client-side; that string
      // is the durable signature of the posture board (not the legacy/v1.1 SPA).
      expect(body).toContain("/api/posture/home");
    });

    it("GET / and GET /posture serve byte-for-byte the same posture board", async () => {
      const [rootRes, postureRes] = await Promise.all([
        fetch(`http://127.0.0.1:${port}/`),
        fetch(`http://127.0.0.1:${port}/posture`),
      ]);
      expect(rootRes.status).toBe(200);
      expect(postureRes.status).toBe(200);
      const [rootBody, postureBody] = await Promise.all([
        rootRes.text(),
        postureRes.text(),
      ]);
      // /posture remains a working alias of the same one surface.
      expect(rootBody).toBe(postureBody);
    });

    it("root-flip does NOT regress the approval-channel routes", async () => {
      await withDecisionDashboard(async ({ channel, port, authHeaders }) => {
        // /api/pending still answers (the pending-approvals inbox source).
        const pendingRes = await fetch(`http://127.0.0.1:${port}/api/pending`, {
          headers: authHeaders,
        });
        expect(pendingRes.status).toBe(200);
        expect(await pendingRes.json()).toEqual([]);

        // An Approve still round-trips through /api/approve/:id and resolves the
        // blocked Tier-1 call (the same approval behavior, reached via the board).
        const approvePromise = channel.requestApproval({
          operation: "state_export",
          tier: 1,
          reason: "root-flip approval round-trip",
          context: { namespace: "test" },
          timestamp: new Date().toISOString(),
        });
        const approveList = await (
          await fetch(`http://127.0.0.1:${port}/api/pending`, {
            headers: authHeaders,
          })
        ).json();
        expect(approveList).toHaveLength(1);
        const approveRes = await fetch(
          `http://127.0.0.1:${port}/api/approve/${approveList[0].id}`,
          { method: "POST", headers: authHeaders },
        );
        expect(approveRes.status).toBe(200);
        expect((await approvePromise).decision).toBe("approve");

        // A Deny still round-trips through /api/deny/:id.
        const denyPromise = channel.requestApproval({
          operation: "identity_rotate",
          tier: 1,
          reason: "root-flip deny round-trip",
          context: { namespace: "test" },
          timestamp: new Date().toISOString(),
        });
        const denyList = await (
          await fetch(`http://127.0.0.1:${port}/api/pending`, {
            headers: authHeaders,
          })
        ).json();
        expect(denyList).toHaveLength(1);
        const denyRes = await fetch(
          `http://127.0.0.1:${port}/api/deny/${denyList[0].id}`,
          { method: "POST", headers: authHeaders },
        );
        expect(denyRes.status).toBe(200);
        expect((await denyPromise).decision).toBe("deny");
      });
    });

    it("root-flip leaves /v1.0 and unknown routes intact", async () => {
      // The legacy four-panel dashboard is still reachable at its own URL.
      const v10 = await fetch(`http://127.0.0.1:${port}/v1.0`);
      expect(v10.status).toBe(200);
      expect(await v10.text()).toContain("Principal Dashboard");
      // The flip matches ONLY the bare root path; unknown routes still 404.
      const unknown = await fetch(`http://127.0.0.1:${port}/nonexistent`);
      expect(unknown.status).toBe(404);
    });
  });

  // ── /api/health stays a cheap, non-sensitive liveness probe (A3 remediation) ──

  describe("/api/health does NOT leak the Castle Wall posture", () => {
    // SECURITY regression guard (Delta Review A3 remediation): a prior revision
    // attached the full evidence-based Castle Wall posture (origin/operator id,
    // verdict counts, enforcement timestamps) to this UNAUTHENTICATED probe and
    // ran an unbounded audit scan + per-entry Ed25519 re-verify per call. That
    // is reverted: `/api/health` is a cheap O(1) `{ ok, mode }` liveness answer
    // ONLY. The honest arm-state lives behind auth (`/api/posture/castle-wall`,
    // `/v1/status`), never here.
    it("returns ONLY { ok, mode, instance, since } — no castle_wall, no posture, no readiness", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/api/health`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.ok).toBe(true);
      expect(data.mode).toBe("principal-policy");
      // brief D3: the opaque restart-detection signal is allowed (instance is a
      // per-boot id, since is the process start time - neither is state).
      expect(typeof data.instance).toBe("string");
      expect(typeof data.since).toBe("number");
      // The detailed posture (and the fields that would leak operator identity
      // or enforcement telemetry) must NOT be on the unauthenticated probe.
      expect(data.castle_wall).toBeUndefined();
      expect(data.arm_state).toBeUndefined();
      expect(data.origin_machine).toBeUndefined();
      expect(data.verdict_counts).toBeUndefined();
      // brief HIGH-1: readiness/supervisor MUST NOT appear on the unauthenticated
      // probe - those are a co-resident-agent oracle and live only behind auth.
      expect(data.ready).toBeUndefined();
      expect(data.supervisor).toBeUndefined();
      expect(Object.keys(data).sort()).toEqual(["instance", "mode", "ok", "since"]);
    });

    it("/api/health keeps its no-store cache header", async () => {
      const res = await fetch(`http://127.0.0.1:${port}/api/health`);
      expect(res.headers.get("cache-control")).toBe("no-store");
    });
  });
});
