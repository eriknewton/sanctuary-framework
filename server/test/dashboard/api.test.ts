/**
 * Dashboard API tests: SSE emission, REST snapshot JSON, and auth-token
 * enforcement. Uses the startDashboardServer helper.
 *
 * Sigma-7: ports are OS-assigned via port: 0. `startDashboardServer`
 * reads actualPort back via server.address() and constructs the handle
 * URL from it, so the SUT does not bake the port in. This is Sigma-6
 * rule option 1 (ephemeral), structurally collision-proof. Replaces a
 * randomPort() helper that flaked EADDRINUSE on Omega-1 CI.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server.js";
import type { DashboardHandle } from "../../src/dashboard/server.js";
import type { ActivityEntry, PendingApproval, AggregatorSources } from "../../src/dashboard/aggregator.js";

async function startForTest(overrides: {
  authToken?: string;
  approvals?: { allow: (id: string) => Promise<boolean>; deny: (id: string) => Promise<boolean> };
  activity?: ActivityEntry[];
  pendingApprovals?: PendingApproval[];
} = {}): Promise<DashboardHandle> {
  const sources: AggregatorSources = {
    mode: "co-located",
    server_version: "0.9.0-test",
    activity: overrides.activity ?? [],
    pendingApprovals: overrides.pendingApprovals ?? [],
  };
  return startDashboardServer({
    mode: "co-located",
    port: 0,
    sources,
    ...(overrides.authToken ? { authToken: overrides.authToken } : {}),
    ...(overrides.approvals ? { approvals: overrides.approvals } : {}),
  });
}

describe("Dashboard HTTP API", () => {
  let handle: DashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.stop();
      handle = null;
    }
  });

  it("serves /api/snapshot as JSON with the ProtectionSnapshot shape", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/api/snapshot`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.layers).toBeDefined();
    expect(body.layers.l1.label).toBe("L1 Cognitive");
    expect(body.overall.light).toMatch(/^(green|yellow|red)$/);
    expect(body.server_version).toBe("0.9.0-test");
  });

  it("serves the legacy hero HTML at /v1.0 (v1.1.7 path-flip)", async () => {
    // v1.1.7: legacy four-panel hero dashboard moved from `/` to `/v1.0`.
    // Root serves the posture shell; /dashboard and /v1.1 are v1.1 SPA
    // compatibility aliases when production wiring provides v11Bindings. This
    // rig boots without v11Bindings, so legacy serves at the new /v1.0 URL.
    handle = await startForTest();
    const res = await fetch(`${handle.url}/v1.0`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("L1 Cognitive");
    expect(html).toContain("L2 Operational");
    expect(html).toContain("L3 Disclosure");
    expect(html).toContain("L4 Reputation");
    expect(html).toContain("id=\"shield\"");
  });

  it("returns 401 when auth token is required and missing", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/snapshot`);
    expect(res.status).toBe(401);
  });

  it("serves /api/health without auth when auth token is configured and exposes only liveness fields", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/health`);
    expect(res.status).toBe(200);
    const body = await res.json();
    // brief D3: `{ ok, mode }` plus the opaque restart-detection signal
    // (`instance` per-boot id + `since` start time). NO readiness/posture.
    expect(Object.keys(body).sort()).toEqual(["instance", "mode", "ok", "since"]);
    expect(body.ok).toBe(true);
    expect(body.mode).toBe("co-located");
    expect(typeof body.instance).toBe("string");
    expect(typeof body.since).toBe("number");
    // brief HIGH-1: these stay OFF the unauthenticated probe.
    expect(body.ready).toBeUndefined();
    expect(body.supervisor).toBeUndefined();
  });

  it("keeps /api/snapshot auth-gated without auth when auth token is configured", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/snapshot`);
    expect(res.status).toBe(401);
  });

  it("returns 200 when auth token is provided via Authorization header", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/snapshot`, {
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(res.status).toBe(200);
  });

  it("rejects auth token provided via ?token= query param", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/snapshot?token=secret-xyz`);
    expect(res.status).toBe(401);
  });

  it("rejects approve/deny when no approval handler is configured", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/api/approvals/abc/allow`, { method: "POST" });
    expect(res.status).toBe(503);
  });

  it("delegates POST /api/approvals/:id/:action to approval handlers", async () => {
    const allowed: string[] = [];
    const denied: string[] = [];
    handle = await startForTest({
      approvals: {
        allow: async (id: string) => { allowed.push(id); return true; },
        deny: async (id: string) => { denied.push(id); return true; },
      },
    });
    const a = await fetch(`${handle.url}/api/approvals/abc/allow`, { method: "POST" });
    const d = await fetch(`${handle.url}/api/approvals/xyz/deny`, { method: "POST" });
    expect(a.status).toBe(200);
    expect(d.status).toBe(200);
    expect(allowed).toEqual(["abc"]);
    expect(denied).toEqual(["xyz"]);
  });

  it("rejects approval mutation auth via long-lived ?token= query param", async () => {
    const allowed: string[] = [];
    handle = await startForTest({
      authToken: "secret-xyz",
      approvals: {
        allow: async (id: string) => { allowed.push(id); return true; },
        deny: async () => true,
      },
    });
    const res = await fetch(`${handle.url}/api/approvals/abc/allow?token=secret-xyz`, {
      method: "POST",
    });
    expect(res.status).toBe(401);
    expect(allowed).toEqual([]);
  });

  it("accepts approval mutation auth via Authorization header", async () => {
    const allowed: string[] = [];
    handle = await startForTest({
      authToken: "secret-xyz",
      approvals: {
        allow: async (id: string) => { allowed.push(id); return true; },
        deny: async () => true,
      },
    });
    const res = await fetch(`${handle.url}/api/approvals/abc/allow`, {
      method: "POST",
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(res.status).toBe(200);
    expect(allowed).toEqual(["abc"]);
  });

  it("rejects approval mutations with a valid short-lived session but still accepts SSE", async () => {
    const allowed: string[] = [];
    const denied: string[] = [];
    handle = await startForTest({
      authToken: "secret-xyz",
      approvals: {
        allow: async (id: string) => { allowed.push(id); return true; },
        deny: async (id: string) => { denied.push(id); return true; },
      },
    });
    const sessionRes = await fetch(`${handle.url}/auth/session`, {
      method: "POST",
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(sessionRes.status).toBe(200);
    const session = await sessionRes.json() as { session_id: string };
    const allowRes = await fetch(
      `${handle.url}/api/approvals/abc/allow?session=${encodeURIComponent(session.session_id)}`,
      { method: "POST" },
    );
    const denyRes = await fetch(
      `${handle.url}/api/approvals/xyz/deny?session=${encodeURIComponent(session.session_id)}`,
      { method: "POST" },
    );
    expect(allowRes.status).toBe(401);
    expect(denyRes.status).toBe(401);
    expect(allowed).toEqual([]);
    expect(denied).toEqual([]);

    const streamRes = await fetch(
      `${handle.url}/api/stream?session=${encodeURIComponent(session.session_id)}`,
    );
    expect(streamRes.status).toBe(200);
    await streamRes.body?.cancel();
  });

  it("emits an initial 'snapshot' event on SSE connect", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/api/stream`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") || "").toContain("text/event-stream");
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    for (let i = 0; i < 6 && !buf.includes("event: snapshot"); i++) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    expect(buf).toContain("event: snapshot");
    expect(buf).toContain("\"layers\"");
    await reader.cancel();
  });

  it("authenticates SSE with a short-lived session URL", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const sessionRes = await fetch(`${handle.url}/auth/session`, {
      method: "POST",
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(sessionRes.status).toBe(200);
    const session = await sessionRes.json() as { session_id: string };
    const res = await fetch(
      `${handle.url}/api/stream?session=${encodeURIComponent(session.session_id)}`,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") || "").toContain("text/event-stream");
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    for (let i = 0; i < 6 && !buf.includes("event: snapshot"); i++) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    expect(buf).toContain("event: snapshot");
    await reader.cancel();
  });

  it("pushes activity events to connected SSE clients", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/api/stream`);
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();

    let buf = "";
    // Drain the initial snapshot
    while (!buf.includes("event: snapshot")) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }

    handle.publishActivity({
      timestamp: new Date().toISOString(),
      tool: "state_write",
      server: "sanctuary",
      tier: 3,
      result: "allowed",
    });

    buf = "";
    for (let i = 0; i < 8 && !buf.includes("event: activity"); i++) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    expect(buf).toContain("event: activity");
    expect(buf).toContain("state_write");
    await reader.cancel();
  });

  it("returns /api/health unauthenticated shape", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/api/health`);
    expect(res.status).toBe(200);
    const body = await res.json();
    // brief D3: `{ ok, mode }` plus the opaque `instance`/`since` restart
    // signal; NO readiness/posture (brief HIGH-1).
    expect(Object.keys(body).sort()).toEqual(["instance", "mode", "ok", "since"]);
    expect(body.ok).toBe(true);
    expect(body.mode).toBe("co-located");
    expect(typeof body.instance).toBe("string");
    expect(typeof body.since).toBe("number");
  });

  it("404s unknown paths", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/does-not-exist`);
    expect(res.status).toBe(404);
  });

  // ERROR-DETAIL-001: completes the #604 error-envelope sweep. The legacy
  // dashboard 500-paths used to serialize `(err as Error).message` to the
  // client. The fix keeps the specific public error code but emits no
  // exception message, stack, or internal path. Operators still get the
  // redacted detail via logCaughtError (server-side only).
  it("does not leak the caught-exception message on a 500 approval failure", async () => {
    const leakyMessage =
      "ENOENT: /Users/eriknewton/secret/path/.sanctuary/state at innerHandler";
    handle = await startForTest({
      approvals: {
        allow: async () => {
          throw new Error(leakyMessage);
        },
        deny: async () => true,
      },
    });
    const res = await fetch(`${handle.url}/api/approvals/abc/allow`, {
      method: "POST",
    });
    expect(res.status).toBe(500);
    const raw = await res.text();
    const body = JSON.parse(raw) as Record<string, unknown>;
    // Specific public code is preserved.
    expect(body.error).toBe("approval_failed");
    // No exception detail field, and nothing from the raw error reaches the wire.
    expect(body).not.toHaveProperty("message");
    expect(raw).not.toContain(leakyMessage);
    expect(raw).not.toContain("ENOENT");
    expect(raw).not.toContain("/Users/eriknewton/secret/path");
    expect(raw).not.toContain("innerHandler");
  });
});
