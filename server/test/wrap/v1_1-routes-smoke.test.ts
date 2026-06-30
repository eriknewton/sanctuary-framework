/**
 * v1.1.2 hotfix (Finding V) — wrap-auto dashboard exposes v1.1 surfaces
 *
 * v1.1.1 release notes claim the v1.1 dashboard, hub API, and
 * `/api/identities` alias are wired into the running server (mounted at
 * `/v1.1` and `/api/hub/*`; legacy v1.0 stays at `/`). In the published
 * v1.1.1 binary, none of those routes are mounted on the dashboard the
 * operator actually hits during `sanctuary wrap` — only the legacy v1.0
 * dashboard at `/` exists. PR #82 (v1.1.1) only wired the routes into
 * the principal-policy `DashboardApprovalChannel` server (used by the
 * MCP server boot path and `sanctuary dashboard` standalone). The
 * wrap-auto operator dashboard is a separate HTTP server.
 *
 * These tests boot the wrap-auto dashboard via `startDashboard` from
 * `dashboard/index.ts` (the same entry point `runWrap` uses), then
 * exercise the binding contract `runWrap` now establishes after Commit
 * 2: `setV11Bindings` + `setV11LoopbackAutoAuth(true)` against the
 * returned handle. Asserts /v1.1, /api/hub/*, and /api/identities all
 * serve content; root serves the folded posture board shell.
 *
 * Critical: this exercises the dashboard server `runWrap` actually
 * starts (server/src/dashboard/{server,api}.ts), NOT the standalone
 * dashboard that already had v1.1 routes via PR #82. If you accidentally
 * test the standalone path, the test passes today on cbf6d99 (v1.1.1
 * release commit) and proves nothing about Finding V.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { startDashboard, type DashboardHandle } from "../../src/dashboard/index.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { getFreePort } from "../helpers/free-port.js";

const IDENTITY_ID = "wrap-smoke-operator";

interface WrapAutoTestRig {
  handle: DashboardHandle;
  baseUrl: string;
  authToken: string;
  tmpFortress: string;
  stop: () => Promise<void>;
}

async function startWrapAutoRigWithRetry(): Promise<WrapAutoTestRig> {
  // Mirrors PR #27's EADDRINUSE retry helper. The wrap-auto dashboard
  // shares the host's port space with concurrent vitest workers; retry
  // on EADDRINUSE only — any other failure is a real bug.
  for (let attempt = 0; attempt < 6; attempt++) {
    const port = await getFreePort();
    const authToken = `wrap-smoke-${randomBytes(8).toString("hex")}`;
    try {
      const tmpFortress = await mkdtemp(join(tmpdir(), "sanctuary-v1_1-smoke-"));
      const handle = await startDashboard({
        port,
        host: "127.0.0.1",
        mode: "co-located",
        authToken,
        serverVersion: "1.1.2-test",
      });

      // Mirror runWrap Commit 2: bind v1.1 + enable loopback auto-auth.
      // Use MemoryStorage + a fresh master key here rather than running
      // the full wrap path (which does keychain reads, harness config
      // rewrites, browser opens). The contract we're pinning is "the
      // wrap-auto dashboard server accepts setV11Bindings and dispatches
      // /v1.1, /api/hub/*, and /api/identities through it."
      const storage = new MemoryStorage();
      const masterKey = randomBytes(32);
      const auditLog = new AuditLog(storage, masterKey);
      handle.updateSources({ auditLog });
      handle.setV11Bindings(
        buildV11Bindings({
          identityId: IDENTITY_ID,
          fortressId: fortressIdFromStoragePath(tmpFortress),
          auditLog,
        }),
      );
      handle.setV11LoopbackAutoAuth(true);

      return {
        handle,
        baseUrl: `http://127.0.0.1:${handle.port}`,
        authToken,
        tmpFortress,
        stop: async () => {
          await handle.stop();
          await rm(tmpFortress, { recursive: true, force: true });
        },
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EADDRINUSE") continue;
      throw err;
    }
  }
  throw new Error("startWrapAutoRig: no free port after 6 attempts");
}

describe("wrap-auto dashboard exposes v1.1 surfaces (Finding V)", () => {
  let rig: WrapAutoTestRig;

  beforeEach(async () => {
    rig = await startWrapAutoRigWithRetry();
  });

  afterEach(async () => {
    await rig.stop();
  });

  it("GET /v1.1 returns the v1.1 dashboard HTML (was 404 pre-fix)", async () => {
    // No auth header: /v1.1 HTML is served unauthenticated so the operator
    // can land on the page; the inline client handles its own auth dance.
    const res = await fetch(`${rig.baseUrl}/v1.1`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const body = await res.text();
    expect(body).toContain("Sanctuary");
    expect(body.length).toBeGreaterThan(1000);
  });

  it("GET /v1.1/ (trailing slash) also serves the v1.1 HTML", async () => {
    const res = await fetch(`${rig.baseUrl}/v1.1/`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
  });

  it("GET /api/hub/agents returns hub API JSON shape (loopback auto-auth)", async () => {
    // Loopback auto-auth is enabled by runWrap; localhost requests pass
    // without a bearer token. This pins both that the route is mounted
    // AND that loopback auto-auth fires through the legacy server's
    // shared dispatch path.
    const res = await fetch(`${rig.baseUrl}/api/hub/agents`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { agents: unknown[] };
    };
    expect(body.ok).toBe(true);
    expect(Array.isArray(body.data.agents)).toBe(true);
  });

  it("GET /api/hub/agents with bearer token also passes (token path still works)", async () => {
    const res = await fetch(`${rig.baseUrl}/api/hub/agents`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
  });

  it("GET /api/identities aliases to /api/hub/agents (Finding E back-compat)", async () => {
    const aliasRes = await fetch(`${rig.baseUrl}/api/identities`);
    const directRes = await fetch(`${rig.baseUrl}/api/hub/agents`);
    expect(aliasRes.status).toBe(200);
    expect(directRes.status).toBe(200);
    expect(await aliasRes.json()).toEqual(await directRes.json());
  });

  it("GET / with a short-lived session URL serves the v1.1 concierge (default surface)", async () => {
    // Default-flip (2026-06-30): `/` serves the v1.1 concierge as the single
    // default surface, even in the wrap-auto path. The posture board is folded
    // into the concierge (a Posture entry in the Verify group; the seal expands
    // to full detail) and preserved standalone at /posture (asserted below).
    const sessionUrl = rig.handle.createSessionUrl?.() ?? rig.baseUrl;
    expect(sessionUrl).not.toContain("?token=");
    const res = await fetch(sessionUrl);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    expect(html).toContain('id="main"');
    expect(html).toContain('data-route="posture"');
  });

  it("GET / serves the concierge; GET /posture serves the posture board (distinct surfaces)", async () => {
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
    expect(rootBody).toContain('id="main"');
    expect(postureBody).toContain("/api/posture/home");
  });

  it("wrap-auto posture auxiliaries are read-only and not decision-capable", async () => {
    const statusRes = await fetch(`${rig.baseUrl}/api/status`);
    expect(statusRes.status).toBe(200);
    const status = (await statusRes.json()) as {
      standalone_mode: boolean;
      decision_capable: boolean;
      policy: { approval_redirect: { enabled: boolean; mode: string } };
    };
    expect(status.standalone_mode).toBe(false);
    expect(status.decision_capable).toBe(false);
    expect(status.policy.approval_redirect).toEqual({
      enabled: false,
      mode: "replace",
    });

    const pendingRes = await fetch(`${rig.baseUrl}/api/pending`);
    expect(pendingRes.status).toBe(200);
    expect(await pendingRes.json()).toEqual([]);
  });

  it("wrap-auto posture data route is mounted behind loopback read auth", async () => {
    const res = await fetch(`${rig.baseUrl}/api/posture/home`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { origin_machine: string };
    expect(typeof body.origin_machine).toBe("string");
  });

  it("did:web compromised rotation requires bearer despite loopback auto-auth", async () => {
    const tokenless = await fetch(
      `${rig.baseUrl}/api/hub/recognition/did-web/rotate-compromised`,
      { method: "POST" },
    );
    expect(tokenless.status).toBe(401);

    const sessionOnly = await fetch(
      `${rig.baseUrl}/api/hub/recognition/did-web/rotate-compromised?session=short-lived`,
      {
        method: "POST",
        headers: { Cookie: "sanctuary_session=short-lived" },
      },
    );
    expect(sessionOnly.status).toBe(401);

    const bearer = await fetch(
      `${rig.baseUrl}/api/hub/recognition/did-web/rotate-compromised`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${rig.authToken}` },
      },
    );
    expect(bearer.status).toBe(200);
    const body = (await bearer.json()) as {
      ok: boolean;
      data: { configured: boolean };
    };
    expect(body.ok).toBe(true);
    expect(body.data.configured).toBe(false);
  });

  it("setV11Bindings(null) detaches the v1.1 routes; /v1.1 falls through legacy gate", async () => {
    // The wrap-auto dashboard's legacy api.ts:handleRequest auth-gates
    // every path that isn't a v1.1 dispatch hit. Detaching the v1.1
    // bindings means /v1.1 falls through to the auth gate, producing 401
    // for an unauthenticated request. With a valid token we get 404
    // (the legacy v1.0 route table has no /v1.1 entry). Either response
    // proves v1.1 dispatch is detached; 200 would be the regression.
    rig.handle.setV11Bindings(null);
    const unauthRes = await fetch(`${rig.baseUrl}/v1.1`);
    expect(unauthRes.status).toBe(401);
    const authedRes = await fetch(`${rig.baseUrl}/v1.1`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(authedRes.status).toBe(404);
  });
});
