/**
 * Dashboard API tests — SSE emission, REST snapshot JSON, and auth-token
 * enforcement. Uses the startDashboardServer helper on a random port.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server.js";
import type { DashboardHandle } from "../../src/dashboard/server.js";
import type { ActivityEntry, PendingApproval, AggregatorSources } from "../../src/dashboard/aggregator.js";

function randomPort(): number {
  return 20000 + Math.floor(Math.random() * 40000);
}

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
    port: randomPort(),
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
    // Root and /dashboard now route to the v1.1 SPA via dispatchV11 in
    // production wiring (this rig boots without v11Bindings, so the
    // dispatch is dormant and legacy serves at the new /v1.0 URL).
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

  it("returns 200 when auth token is provided via Authorization header", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/snapshot`, {
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(res.status).toBe(200);
  });

  it("returns 200 when auth token is provided via ?token= query param", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/snapshot?token=secret-xyz`);
    expect(res.status).toBe(200);
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
    expect(body.ok).toBe(true);
    expect(body.mode).toBe("co-located");
  });

  it("404s unknown paths", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/does-not-exist`);
    expect(res.status).toBe(404);
  });
});
