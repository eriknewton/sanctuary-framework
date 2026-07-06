/**
 * Fleet control plane PR-2: `POST /api/fleet/activate` route tests.
 *
 * Definition-of-Done for the activation route seam:
 *  1. AUTH (fail-closed): the route requires the operator BEARER TOKEN - a
 *     boundary-changing mutation, exactly like template-init. Missing/wrong token
 *     → 401; the shared fail-open-when-no-token gate is NOT the gate here.
 *  2. UNAVAILABLE: when no handler is wired (no unlocked fortress in-process), the
 *     route serves the honest `activation_unavailable` 503 - it never pretends to
 *     activate.
 *  3. SUCCESS: a valid paste → 200 with the resolved tier + node cap.
 *  4. REJECTED PASTE: a handler `ok:false` → 400 with the reason (bad license is a
 *     client error, never a 500 leak, never a silent grant).
 *  5. VALIDATION: a missing/empty license body → 400.
 *
 * The handler is stubbed here (the real handler is unit-tested in
 * activation.test.ts); these tests pin the ROUTE contract + its fail-closed auth.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server.js";
import type { DashboardHandle } from "../../src/dashboard/server.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import type { FleetActivationResult } from "../../src/dashboard/api.js";

const AUTH = "operator-secret-token";

async function startForTest(overrides: {
  authToken?: string;
  activateFleetLicense?: (pasted: string) => Promise<FleetActivationResult>;
} = {}): Promise<DashboardHandle> {
  const sources: AggregatorSources = {
    mode: "co-located",
    server_version: "0.9.0-test",
    activity: [],
    pendingApprovals: [],
  };
  return startDashboardServer({
    mode: "co-located",
    port: 0,
    sources,
    ...(overrides.authToken ? { authToken: overrides.authToken } : {}),
    ...(overrides.activateFleetLicense
      ? { activateFleetLicense: overrides.activateFleetLicense }
      : {}),
  });
}

async function post(
  handle: DashboardHandle,
  body: unknown,
  token?: string,
): Promise<Response> {
  return fetch(`${handle.url}/api/fleet/activate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

describe("POST /api/fleet/activate", () => {
  let handle: DashboardHandle | null = null;
  afterEach(async () => {
    if (handle) {
      await handle.stop();
      handle = null;
    }
  });

  it("401s without the operator bearer token (fail-closed auth)", async () => {
    handle = await startForTest({
      authToken: AUTH,
      activateFleetLicense: async () => ({ ok: true, tier: "team", max_nodes: 25 }),
    });
    const res = await post(handle, { license: "x" }); // no token
    expect(res.status).toBe(401);
  });

  it("401s with the WRONG bearer token", async () => {
    handle = await startForTest({
      authToken: AUTH,
      activateFleetLicense: async () => ({ ok: true, tier: "team", max_nodes: 25 }),
    });
    const res = await post(handle, { license: "x" }, "wrong-token");
    expect(res.status).toBe(401);
  });

  it("503 activation_unavailable when no handler is wired", async () => {
    handle = await startForTest({ authToken: AUTH }); // no activateFleetLicense
    const res = await post(handle, { license: "x" }, AUTH);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toBe("activation_unavailable");
  });

  it("200 with the resolved tier + cap on a valid paste", async () => {
    handle = await startForTest({
      authToken: AUTH,
      activateFleetLicense: async (pasted) => {
        expect(pasted).toBe("valid-license-blob");
        return { ok: true, tier: "team", max_nodes: 25 };
      },
    });
    const res = await post(handle, { license: "valid-license-blob" }, AUTH);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ ok: true, tier: "team", max_nodes: 25 });
  });

  it("surfaces an unlimited (Team+) grant as max_nodes null", async () => {
    handle = await startForTest({
      authToken: AUTH,
      activateFleetLicense: async () => ({ ok: true, tier: "fleet", max_nodes: null }),
    });
    const res = await post(handle, { license: "x" }, AUTH);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.max_nodes).toBeNull();
  });

  it("400 with the reason on a rejected (verify_failed) paste", async () => {
    handle = await startForTest({
      authToken: AUTH,
      activateFleetLicense: async () => ({ ok: false, reason: "verify_failed" }),
    });
    const res = await post(handle, { license: "expired-blob" }, AUTH);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body).toEqual({ ok: false, reason: "verify_failed" });
  });

  it("400 on a malformed_token paste", async () => {
    handle = await startForTest({
      authToken: AUTH,
      activateFleetLicense: async () => ({ ok: false, reason: "malformed_token" }),
    });
    const res = await post(handle, { license: "garbage" }, AUTH);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.reason).toBe("malformed_token");
  });

  it("400 validation_error when the license field is missing or empty", async () => {
    handle = await startForTest({
      authToken: AUTH,
      activateFleetLicense: async () => ({ ok: true, tier: "team", max_nodes: 25 }),
    });
    const missing = await post(handle, {}, AUTH);
    expect(missing.status).toBe(400);
    const empty = await post(handle, { license: "   " }, AUTH);
    expect(empty.status).toBe(400);
  });

  it("500 (no silent grant) when the handler throws unexpectedly", async () => {
    handle = await startForTest({
      authToken: AUTH,
      activateFleetLicense: async () => {
        throw new Error("boom");
      },
    });
    const res = await post(handle, { license: "x" }, AUTH);
    expect(res.status).toBe(500);
    const body = await res.json();
    // No grant leaked, no stack: just an internal_error envelope.
    expect(body.ok).toBeUndefined();
    expect(body.error).toBe("internal_error");
  });
});
