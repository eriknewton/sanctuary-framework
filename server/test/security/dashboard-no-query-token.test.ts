/**
 * Sanctuary MCP Server — SEC-012 Regression Test
 *
 * SEC-012: Dashboard auth token transmitted in URL query strings.
 *
 * This test verifies that the long-lived auth token is NEVER accepted via
 * query string parameters. Instead, a session exchange flow is required:
 *   1. POST /auth/session with Authorization: Bearer <TOKEN> header
 *   2. Receive a short-lived session_id
 *   3. Use ?session=<SESSION_ID> for SSE and URL-based requests
 *
 * These tests would have FAILED before the SEC-012 fix was applied:
 * the old code accepted ?token=<AUTH_TOKEN> in the URL.
 */

import { describe, it, expect, afterEach } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { bindWithRetry, randomTestPort } from "../util/port-collision-retry.js";

const AUTH_TOKEN = "test-auth-token-sec012-regression";

describe("SEC-012: Dashboard auth token never in URL query string", () => {
  let dashboard: DashboardApprovalChannel;
  let port: number;
  let baseUrl: string;

  afterEach(async () => {
    if (dashboard) await dashboard.stop();
  });

  // Sigma-7: DashboardApprovalChannel embeds the port in selfOrigin and
  // one-click session URLs, so the port must be known before bind. Wrap
  // construction + start in bindWithRetry so EADDRINUSE collisions under
  // parallel vitest workers re-pick a fresh port and retry.
  async function createDashboard(): Promise<void> {
    await bindWithRetry(async () => {
      port = randomTestPort();
      baseUrl = `http://127.0.0.1:${port}`;
      dashboard = new DashboardApprovalChannel({
        port,
        host: "127.0.0.1",
        timeout_seconds: 30,
        auth_token: AUTH_TOKEN,
      });
      await dashboard.start();
    });
  }

  // ── Test 1: Long-lived token in query string is REJECTED ────────────

  it("rejects long-lived auth token in ?token= query string (401)", async () => {
    await createDashboard();

    // SEC-012 forbids the long-lived token in URL. v1.1.7: legacy login
    // page is reached at /v1.0 (root and /dashboard now route to the v1.1
    // SPA via dispatchV11 in production wiring; this rig boots without
    // v11Bindings so /v1.0 is the active legacy surface). The token in
    // the query string must NOT promote the request to authenticated;
    // unauth still serves the login page.
    const res = await fetch(`${baseUrl}/v1.0?token=${AUTH_TOKEN}`);
    expect(res.status).toBe(200);

    const body = await res.text();
    // Login page should be served, not the full dashboard
    expect(body).toContain("login");
    // Dashboard-specific content should NOT be present
    expect(body).not.toContain("Live Activity");
  });

  // ── Test 2: Long-lived token in Authorization header is accepted ────

  it("accepts long-lived auth token in Authorization: Bearer header", async () => {
    await createDashboard();

    const res = await fetch(`${baseUrl}/v1.0`, {
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  // ── Test 3: Session exchange works ──────────────────────────────────

  it("exchanges auth token for short-lived session via POST /auth/session", async () => {
    await createDashboard();

    const res = await fetch(`${baseUrl}/auth/session`, {
      method: "POST",
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.session_id).toBeDefined();
    expect(typeof body.session_id).toBe("string");
    expect(body.session_id.length).toBe(64); // 32 bytes hex
    expect(body.expires_in_seconds).toBeGreaterThan(0);
  });

  // ── Test 4: Session token in query string is accepted ───────────────

  it("accepts short-lived session token in ?session= query string", async () => {
    await createDashboard();

    // First, exchange token for session
    const exchangeRes = await fetch(`${baseUrl}/auth/session`, {
      method: "POST",
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    const { session_id } = await exchangeRes.json();

    // Now use the session token in URL — this is the safe replacement
    const res = await fetch(`${baseUrl}/api/status?session=${session_id}`);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.pending_count).toBeDefined();
  });

  // ── Test 5: Expired session is rejected ─────────────────────────────

  it("rejects expired session tokens (401)", async () => {
    // Create a dashboard and manually test expiry by accessing internal state.
    // We create a session, then manipulate its expiry to simulate time passing.
    await createDashboard();

    // Exchange for session
    const exchangeRes = await fetch(`${baseUrl}/auth/session`, {
      method: "POST",
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    const { session_id } = await exchangeRes.json();

    // Verify session works first
    const validRes = await fetch(`${baseUrl}/api/status?session=${session_id}`);
    expect(validRes.status).toBe(200);

    // Access the sessions map via the dashboard instance to expire the session.
    // This is a white-box test — we're directly manipulating internal state
    // to simulate the passage of time without actually waiting 5 minutes.
    const sessions = (dashboard as any).sessions as Map<string, { expires_at: number }>;
    const session = sessions.get(session_id);
    expect(session).toBeDefined();
    session!.expires_at = Date.now() - 1000; // Expired 1 second ago

    // Now the session should be rejected
    const expiredRes = await fetch(`${baseUrl}/api/status?session=${session_id}`);
    expect(expiredRes.status).toBe(401);
  });

  // ── Test 6: Invalid/random session is rejected ──────────────────────

  it("rejects invalid/random session tokens (401)", async () => {
    await createDashboard();

    const fakeSession = "a".repeat(64); // Looks like a session ID but was never issued
    const res = await fetch(`${baseUrl}/api/status?session=${fakeSession}`);
    expect(res.status).toBe(401);
  });

  // ── Test 7: Session exchange rejects invalid auth token ─────────────

  it("rejects session exchange with wrong auth token", async () => {
    await createDashboard();

    const res = await fetch(`${baseUrl}/auth/session`, {
      method: "POST",
      headers: { Authorization: "Bearer wrong-token" },
    });
    expect(res.status).toBe(401);
  });

  // ── Test 8: Session exchange rejects missing Authorization header ───

  it("rejects session exchange without Authorization header", async () => {
    await createDashboard();

    const res = await fetch(`${baseUrl}/auth/session`, {
      method: "POST",
    });
    expect(res.status).toBe(401);
  });
});
