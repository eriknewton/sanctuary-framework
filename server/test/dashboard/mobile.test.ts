/**
 * Mobile companion (PWA) slice-1 route tests.
 *
 * The companion is a phone-as-approval surface served by the SAME dashboard
 * router as every other route. These tests pin the slice-1 security posture:
 *   - the shell + manifest + service worker serve TOKENLESS (a static app
 *     shell like the concierge SPA), even when an operator token is configured;
 *   - the shell carries NO server-side operator data (byte-identical whether
 *     or not approvals are pending -- all data is fetched client-side from the
 *     already-gated /api routes);
 *   - the service worker NEVER caches /api traffic;
 *   - the shell is served under a strict same-origin CSP.
 *
 * Ports are OS-assigned (port: 0) via startDashboardServer, matching api.test.ts.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server.js";
import type { DashboardHandle } from "../../src/dashboard/server.js";
import type { PendingApproval, AggregatorSources } from "../../src/dashboard/aggregator.js";

async function startForTest(
  overrides: { authToken?: string; pendingApprovals?: PendingApproval[] } = {},
): Promise<DashboardHandle> {
  const sources: AggregatorSources = {
    mode: "co-located",
    server_version: "0.9.0-test",
    activity: [],
    pendingApprovals: overrides.pendingApprovals ?? [],
  };
  return startDashboardServer({
    mode: "co-located",
    port: 0,
    sources,
    ...(overrides.authToken ? { authToken: overrides.authToken } : {}),
  });
}

describe("Mobile companion (PWA) slice 1", () => {
  let handle: DashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.stop();
      handle = null;
    }
  });

  it("serves the shell at /m and /m/ as HTML under a strict same-origin CSP", async () => {
    handle = await startForTest();
    for (const path of ["/m", "/m/"]) {
      const res = await fetch(`${handle.url}${path}`);
      expect(res.status, path).toBe(200);
      expect(res.headers.get("content-type")).toMatch(/text\/html/);
      const csp = res.headers.get("content-security-policy") ?? "";
      expect(csp, path).toContain("default-src 'self'");
      expect(csp, path).toContain("connect-src 'self'");
      // No external origin may ever be needed; frame-ancestors locked down.
      expect(csp, path).toContain("frame-ancestors 'none'");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      const html = await res.text();
      expect(html).toContain("<!DOCTYPE html>");
      expect(html).toContain("Sanctuary");
      expect(html).toContain('rel="manifest"');
      // Transport-safety: the shell warns on a non-secure context (a token
      // pasted over plain HTTP is interceptable) rather than assuming HTTPS.
      expect(html).toContain("isSecureContext");
      expect(html).toContain("insecure-warn");
    }
  });

  it("serves the shell TOKENLESS even when an operator token is configured", async () => {
    // The shell is public like the concierge SPA; the DATA behind /api stays
    // gated. A phone can load the app without pre-auth, then unlock in-page.
    handle = await startForTest({ authToken: "s3cr3t-operator-token" });
    const res = await fetch(`${handle.url}/m`);
    expect(res.status).toBe(200);
  });

  it("the shell carries NO server-side operator data (byte-identical with and without pending approvals)", async () => {
    const withNone = await startForTest({ pendingApprovals: [] });
    const emptyHtml = await (await fetch(`${withNone.url}/m`)).text();
    await withNone.stop();

    const pending: PendingApproval[] = [
      {
        id: "req-super-secret-1",
        operation: "delete_all_state",
        agent_id: "hermes",
        summary: "SECRET operation the shell must not leak",
      } as unknown as PendingApproval,
    ];
    handle = await startForTest({ pendingApprovals: pending });
    const pendingHtml = await (await fetch(`${handle.url}/m`)).text();

    // The static shell must not embed any pending-approval data server-side.
    expect(pendingHtml).not.toContain("req-super-secret-1");
    expect(pendingHtml).not.toContain("SECRET operation");
    // And it is the exact same shell regardless of server state.
    expect(pendingHtml).toBe(emptyHtml);
  });

  it("serves a valid web manifest scoped to /m/", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/m/manifest.webmanifest`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/application\/manifest\+json/);
    const m = JSON.parse(await res.text());
    expect(m.start_url).toBe("/m/");
    expect(m.scope).toBe("/m/");
    expect(m.display).toBe("standalone");
    expect(Array.isArray(m.icons)).toBe(true);
    expect(m.icons.length).toBeGreaterThan(0);
  });

  it("serves a service worker that NEVER caches /api traffic", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/m/sw.js`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/javascript/);
    expect(res.headers.get("service-worker-allowed")).toBe("/m/");
    const sw = await res.text();
    // The /api bypass is the security-critical guard: a cached approval list
    // would be stale, and a cached auth response would persist a secret.
    expect(sw).toContain("/api/");
    expect(sw).toMatch(/indexOf\('\/api\/'\)\s*===\s*0/);
    // The shell cache must not blanket-cache POSTs (approvals are POSTs).
    expect(sw).toContain("req.method !== 'GET'");
  });
});
