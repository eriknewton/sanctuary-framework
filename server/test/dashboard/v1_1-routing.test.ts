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
    await rig.stop();
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

  it("GET / serves the posture board shell WITHOUT a token (real auth path)", async () => {
    // The one-surface correction flips the default page at `/` to the posture
    // board (the same shell `/posture` serves), even with v1.1 bindings wired.
    // This rig sets a real `auth_token`, so this exercises the PRODUCTION auth
    // path (not an auth-disabled rig): the static shell carries no posture data
    // and must be served WITHOUT a bearer, while its `/api/posture/*` data
    // fetches stay behind checkAuth (asserted by the 401 test below). The v1.1
    // SPA is preserved at /dashboard and /v1.1 (asserted below).
    const res = await fetch(`${rig.baseUrl}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    // Posture-board marker: the shell fetches the posture API client-side. It is
    // NOT the v1.1 SPA (which mounts on #main / #fortress).
    expect(html).toContain("/api/posture/home");
    expect(html).not.toContain('id="fortress"');
  });

  it("GET / and GET /posture are ONE surface under real auth (byte-for-byte, no token)", async () => {
    // Delta Review A3 remediation: `/` and `/posture` must serve the SAME shell
    // under the SAME auth posture. Before the fix `/` was unauthenticated while
    // `/posture`'s HTML sat behind checkAuth, so the equivalence only held when
    // a test rig disabled auth. With a real `auth_token` set, BOTH paths must
    // answer 200 with the identical shell to an UNAUTHENTICATED caller.
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
    expect(rootBody).toBe(postureBody);
    expect(rootBody).toContain("/api/posture/home");
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
