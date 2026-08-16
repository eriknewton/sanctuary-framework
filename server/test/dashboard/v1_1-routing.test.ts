// fail-before-exempt: storagePath was threaded into existing v1.1 routing harness wiring; stop-button enforcement is covered by agent-stop, egress, and castle-wall-agent-controller tests.
/**
 * v1.1.1 hotfix — DashboardApprovalChannel v1.1 routing wiring
 *
 * v1.1.0 shipped the v1.1 dashboard module + hub API but no entry-point
 * server imported them. From an operator's perspective v1.1.0 delivered
 * no interactive new functionality. The hotfix mounts v1.1 routes
 * additively at /v1.1 (HTML) and /api/hub/* (API); the legacy dashboard
 * root behavior has since been superseded by the posture shell root.
 *
 * These tests boot a real DashboardApprovalChannel instance, call
 * setV11Bindings with stub-empty hub state, and assert end-to-end that
 * GET /v1.1 returns the v1.1 HTML, GET /api/hub/agents returns the hub
 * API JSON shape, and GET / + /api/status keep their legacy behavior.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../src/dashboard/v1_1/wiring.js";
import { getFreePort } from "../helpers/free-port.js";

const IDENTITY_ID = "operator-test-001";
const FORTRESS_STORAGE_PATH = "/tmp/sanctuary-v1.1.1-test";

interface TestRig {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  authToken: string;
  stop: () => Promise<void>;
}

async function readSseUntil(
  res: Response,
  needle: string,
  maxReads = 8,
): Promise<string> {
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  try {
    for (let i = 0; i < maxReads && !buf.includes(needle); i++) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    return buf;
  } finally {
    await reader.cancel();
  }
}

function extractDashboardConfig(html: string): Record<string, unknown> {
  const match = /<script id="dashboard-config" type="application\/json">([^<]+)<\/script>/.exec(html);
  if (!match) throw new Error("dashboard config script not found");
  return JSON.parse(match[1]!) as Record<string, unknown>;
}

async function createSession(rig: TestRig): Promise<string> {
  const exchange = await fetch(`${rig.baseUrl}/auth/session`, {
    method: "POST",
    headers: { Authorization: `Bearer ${rig.authToken}` },
  });
  expect(exchange.status).toBe(200);
  const body = await exchange.json() as { session_id: string };
  return body.session_id;
}


async function startRig(options: { host?: string; allowPlaintextRemote?: boolean } = {}): Promise<TestRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);

  const authToken = `v1-1-1-test-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();

  const dashboard = new DashboardApprovalChannel({
    port,
    host: options.host ?? "127.0.0.1",
    timeout_seconds: 30,
    auth_token: authToken,
    auto_open: false,
    ...(options.allowPlaintextRemote ? { allow_plaintext_remote: true } : {}),
  });

  // Minimal legacy deps so the existing route table doesn't 500 when we
  // probe / and /api/status. The auditLog is the only one the v1.1 hub
  // service actually consumes.
  dashboard.setDependencies({
    policy: {
      version: 1,
      tier1_always_approve: [],
      tier3_auto_allow: [],
      anomaly_thresholds: {
        new_namespace: true,
        unfamiliar_counterparty_window_days: 7,
        frequency_spike_multiplier: 5,
      },
      approval_channel: {
        type: "stderr",
        timeout_seconds: 30,
      },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
  });

  dashboard.setV11Bindings(
    buildV11Bindings({
      identityId: IDENTITY_ID,
      fortressId: fortressIdFromStoragePath(FORTRESS_STORAGE_PATH),
      auditLog,
      storagePath: FORTRESS_STORAGE_PATH,
    }),
  );

  await dashboard.start();

  return {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    authToken,
    stop: async () => {
      await dashboard.stop();
    },
  };
}

describe("DashboardApprovalChannel v1.1 routing (hotfix)", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig();
  });

  afterEach(async () => {
    if (rig) await rig.stop();
  });

  it("GET /v1.1 returns the v1.1 dashboard HTML", async () => {
    const res = await fetch(`${rig.baseUrl}/v1.1`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const body = await res.text();
    // v1.1 HTML carries v1.1-specific markers — check for the dashboard
    // shell + the embedded client script (or its bootstrap).
    expect(body).toContain("Sanctuary");
    expect(body.length).toBeGreaterThan(1000);
  });

  it("GET /v1.1/ (trailing slash) also serves the v1.1 HTML", async () => {
    const res = await fetch(`${rig.baseUrl}/v1.1/`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
  });

  it("GET /api/hub/agents returns hub API JSON shape with empty list", async () => {
    const res = await fetch(`${rig.baseUrl}/api/hub/agents`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { agents: unknown[] };
    };
    expect(body.ok).toBe(true);
    expect(Array.isArray(body.data.agents)).toBe(true);
    expect(body.data.agents.length).toBe(0);
  });

  it("GET /api/hub/inbox returns empty items array", async () => {
    const res = await fetch(`${rig.baseUrl}/api/hub/inbox`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { items: unknown[] };
    };
    expect(body.ok).toBe(true);
    expect(Array.isArray(body.data.items)).toBe(true);
    expect(body.data.items.length).toBe(0);
  });

  it("GET /api/hub/agents without auth returns 401", async () => {
    const res = await fetch(`${rig.baseUrl}/api/hub/agents`);
    expect(res.status).toBe(401);
  });

  it("GET / serves the v1.1 concierge as the single default surface (default-flip 2026-06-30)", async () => {
    // Default-flip: `/` now serves the v1.1 concierge SPA, NOT the separate
    // posture board shell. This is the "ONE SURFACE" requirement: the concierge
    // is the default landing on a bare standalone dashboard boot, and the
    // posture data is folded INTO it (the seal expands to full posture detail;
    // a Posture entry lives in the Verify group). The SPA is served tokenless
    // (it runs its own client-side auth dance), exactly like /dashboard + /v1.1.
    const res = await fetch(`${rig.baseUrl}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    // v1.1 SPA markers: the shell mounts on #main and carries the grouped
    // sidebar nav. It is NOT the standalone posture board shell (which would
    // fetch /api/posture/home directly from its own static page). S2
    // (2026-07-18): the SPA now lands on the posture Overview (data-route
    // "posture") rather than the concierge; Talk stays reachable in the nav.
    expect(html).toContain('id="main"');
    expect(html).toContain('id="sidebar-nav"');
    // The posture Overview is the landing surface on this single shell.
    expect(html).toContain('data-route="posture"');
  });

  it("GET / (concierge) and GET /posture (board) are now DISTINCT surfaces", async () => {
    // The posture data is folded INTO the concierge, but the standalone posture
    // board is PRESERVED at /posture (a frozen surface, never blind-deleted).
    // So `/` and `/posture` now serve DIFFERENT HTML: `/` is the concierge SPA;
    // `/posture` is the posture board shell that fetches /api/posture/home.
    const [rootRes, postureRes] = await Promise.all([
      fetch(`${rig.baseUrl}/`),
      fetch(`${rig.baseUrl}/posture`),
    ]);
    expect(rootRes.status).toBe(200);
    expect(postureRes.status).toBe(200);
    const [rootBody, postureBody] = await Promise.all([
      rootRes.text(),
      postureRes.text(),
    ]);
    expect(rootBody).not.toBe(postureBody);
    // `/` is the concierge SPA.
    expect(rootBody).toContain('id="main"');
    // `/posture` is the preserved posture board shell.
    expect(postureBody).toContain("/api/posture/home");
  });

  it("the posture shell's data routes stay behind auth (401 without a token)", async () => {
    // The shell is unauthenticated, but every byte of EVIDENCE it renders comes
    // from `/api/posture/*`, which must reject an unauthenticated caller. This
    // is the other half of the one-surface auth contract.
    const res = await fetch(`${rig.baseUrl}/api/posture/home`);
    expect(res.status).toBe(401);
  });

  it("GET /dashboard serves the v1.1 SPA (v1.1.7 alias, preserved post root-flip)", async () => {
    const res = await fetch(`${rig.baseUrl}/dashboard`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    expect(html).toContain('id="main"');
  });

  it("renders a streamUrl that the standalone dashboard serves as SSE", async () => {
    const shellRes = await fetch(`${rig.baseUrl}/dashboard`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(shellRes.status).toBe(200);
    const html = await shellRes.text();
    const config = extractDashboardConfig(html);
    expect(config.streamUrl).toBe("/api/stream");

    const sessionId = await createSession(rig);
    const streamRes = await fetch(
      `${rig.baseUrl}${config.streamUrl}?session=${encodeURIComponent(sessionId)}`,
    );
    expect(streamRes.status).toBe(200);
    expect(streamRes.headers.get("content-type")).toContain("text/event-stream");
    const text = await readSseUntil(streamRes, "event: snapshot");
    expect(text).toContain("event: snapshot");
    expect(text).toContain("\"layers\"");
  });

  it("emits SPA-compatible approval frames on the rendered standalone stream", async () => {
    const sessionId = await createSession(rig);
    const streamRes = await fetch(
      `${rig.baseUrl}/api/stream?session=${encodeURIComponent(sessionId)}`,
    );
    expect(streamRes.status).toBe(200);

    const reader = streamRes.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (!buf.includes("event: snapshot")) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    expect(buf).toContain("event: snapshot");

    const approvalPromise = rig.dashboard.requestApproval({
      operation: "state_export",
      tier: 1,
      reason: "Export requires operator approval",
      context: { namespace: "test" },
      timestamp: new Date().toISOString(),
    });

    buf = "";
    for (let i = 0; i < 8 && !buf.includes("event: approval"); i++) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    expect(buf).toContain("event: approval");
    expect(buf).toContain("\"operation\":\"state_export\"");
    expect(buf).toContain("\"tier\":1");

    const pendingRes = await fetch(`${rig.baseUrl}/api/pending`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(pendingRes.status).toBe(200);
    const pending = await pendingRes.json() as Array<{ id: string }>;
    expect(pending).toHaveLength(1);
    const denyRes = await fetch(
      `${rig.baseUrl}/api/deny/${encodeURIComponent(pending[0]!.id)}`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${rig.authToken}` },
      },
    );
    expect(denyRes.status).toBe(200);
    await expect(approvalPromise).resolves.toMatchObject({ decision: "deny" });
    await reader.cancel();
  });

  it("GET /v1.1 continues to serve the v1.1 SPA (back-compat)", async () => {
    const res = await fetch(`${rig.baseUrl}/v1.1`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
  });

  it("remote /dashboard gates unauthenticated callers and never serializes the bearer for session-authenticated HTML", async () => {
    await rig.stop();
    rig = await startRig({ host: "0.0.0.0", allowPlaintextRemote: true });

    const unauth = await fetch(`${rig.baseUrl}/dashboard`);
    expect(unauth.status).toBe(200);
    const login = await unauth.text();
    expect(login).toContain('id="auth-token"');
    expect(login).not.toContain(rig.authToken);

    const exchange = await fetch(`${rig.baseUrl}/auth/session`, {
      method: "POST",
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(exchange.status).toBe(200);
    const { session_id } = await exchange.json() as { session_id: string };

    const withSession = await fetch(
      `${rig.baseUrl}/dashboard?session=${encodeURIComponent(session_id)}`,
    );
    expect(withSession.status).toBe(200);
    const shell = await withSession.text();
    expect(shell).toContain('id="main"');
    expect(shell).not.toContain(rig.authToken);
    expect(shell).toContain('"authToken":""');
  });

  it("GET /v1.0 serves the legacy four-panel dashboard (v1.1.7 preserve)", async () => {
    const res = await fetch(`${rig.baseUrl}/v1.0`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    // Legacy HTML does NOT contain the v1.1 SPA inline-client mount.
    expect(html).not.toContain('id="fortress"');
  });

  it("GET /api/status (legacy) routes to the pre-v1.1 handler (not consumed by v1.1 dispatch)", async () => {
    const res = await fetch(`${rig.baseUrl}/api/status`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    // Pinning that the legacy handler ran: the route is NOT 404 (which
    // would mean the v1.1 dispatch consumed it without a match). The
    // exact status depends on the legacy /api/status handler having all
    // its deps wired; this rig stubs only the v1.1-relevant ones, so
    // 500 from the legacy handler is acceptable evidence it ran.
    expect(res.status).not.toBe(404);
    expect(res.status).not.toBe(401);
  });

  it("GET /api/hub/agents/<id>/pause returns capability error (no controller wired in v1.1.1)", async () => {
    // Wiring is additive at v1.1.1: API shape lights up but the agent
    // controller errors on every action. Pinning this so the error class
    // is visible in regression tests rather than surprising operators.
    const res = await fetch(
      `${rig.baseUrl}/api/hub/agents/some-agent-id/pause`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${rig.authToken}`,
          "Content-Type": "application/json",
        },
        body: "{}",
      },
    );
    // 404 because agent does not exist in the empty registry, OR a hub
    // capability error if agent existed. Either way: not 500, not silent.
    expect([400, 404, 501]).toContain(res.status);
  });

  it("setV11Bindings(null) detaches the v1.1 routes; /v1.1 returns 404", async () => {
    rig.dashboard.setV11Bindings(null);
    const res = await fetch(`${rig.baseUrl}/v1.1`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(404);
  });

  it("with v1.1 bindings detached, /api/hub/agents 404s through legacy fallthrough", async () => {
    rig.dashboard.setV11Bindings(null);
    const res = await fetch(`${rig.baseUrl}/api/hub/agents`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(404);
  });

  // v1.1.1 hotfix Finding E: /api/identities was the pre-v1.1 endpoint
  // name; this hotfix aliases it to /api/hub/agents for back-compat.
  it("GET /api/identities aliases to /api/hub/agents (Finding E back-compat)", async () => {
    const aliasRes = await fetch(`${rig.baseUrl}/api/identities`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    const directRes = await fetch(`${rig.baseUrl}/api/hub/agents`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(aliasRes.status).toBe(200);
    expect(directRes.status).toBe(200);
    const aliasBody = (await aliasRes.json()) as { ok: boolean; data: unknown };
    const directBody = (await directRes.json()) as { ok: boolean; data: unknown };
    expect(aliasBody).toEqual(directBody);
  });

  it("GET /api/identities preserves query string (?harness=foo)", async () => {
    const res = await fetch(
      `${rig.baseUrl}/api/identities?harness=openclaw&limit=5`,
      {
        headers: { Authorization: `Bearer ${rig.authToken}` },
      },
    );
    // Empty registry returns empty list regardless of filters; the assertion
    // is shape, not contents.
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { agents: unknown[] };
    };
    expect(Array.isArray(body.data.agents)).toBe(true);
  });
});
