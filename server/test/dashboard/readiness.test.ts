/**
 * /api/readiness contract tests (Dashboard Server Lifecycle Hardening, brief D3).
 *
 * The readiness/supervisor signal is AUTH-GATED on a SEPARATE endpoint
 * precisely because an unauthenticated `ready: "locked"` field would be a
 * co-resident-agent oracle for whether the fortress is unlocked (brief
 * HIGH-1). These tests pin:
 *   - /api/readiness requires read-auth (401 without a token when auth is on)
 *   - /api/readiness returns { ready, supervisor } WITH valid auth
 *   - ready honestly reflects locked (no identity manager) vs serving (wired)
 *   - /api/health carries instance + since, and does NOT carry ready/supervisor
 *   - instance is stable within a process and changes across a restart
 *   - the multi-tenant dashboard is EXCLUDED from /api/readiness (no cross-
 *     tenant readiness aggregation), while still emitting instance/since on
 *     its own /api/health
 *
 * Ports are OS-assigned via port: 0 (Sigma rule option 1, collision-proof).
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server.js";
import type { DashboardHandle } from "../../src/dashboard/server.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import type { IdentityManager } from "../../src/cognitive/tools.js";
import {
  startMultiDashboardServer,
  type MultiDashboardHandle,
} from "../../src/dashboard/multi-server.js";
import { getProcessInstance, getProcessSince } from "../../src/dashboard/process-identity.js";

/**
 * Minimal IdentityManager stand-in. The /api/readiness fallback only checks
 * for the PRESENCE of an identity manager on the sources (its presence is the
 * honest "unlocked + read surface live" proxy; the server wires it post-unlock
 * via updateSources). The endpoint never calls into it for the readiness value,
 * so a bare object is sufficient ground truth for "serving".
 */
const STUB_IDENTITY_MANAGER = {} as unknown as IdentityManager;

async function startForTest(overrides: {
  authToken?: string;
  identityManager?: IdentityManager;
} = {}): Promise<DashboardHandle> {
  const sources: AggregatorSources = {
    mode: "co-located",
    server_version: "0.9.0-test",
    activity: [],
    pendingApprovals: [],
    ...(overrides.identityManager
      ? { identityManager: overrides.identityManager }
      : {}),
  };
  return startDashboardServer({
    mode: "co-located",
    port: 0,
    sources,
    ...(overrides.authToken ? { authToken: overrides.authToken } : {}),
  });
}

describe("/api/readiness (auth-gated, brief D3)", () => {
  let handle: DashboardHandle | null = null;
  let multi: MultiDashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.stop();
      handle = null;
    }
    if (multi) {
      await multi.stop();
      multi = null;
    }
  });

  it("returns 401 WITHOUT auth when an auth token is configured", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/readiness`);
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe("unauthorized");
    // It must not leak readiness in the unauthorized body.
    expect(body.ready).toBeUndefined();
    expect(body.supervisor).toBeUndefined();
  });

  it("rejects readiness for a same-length wrong bearer token", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/readiness`, {
      headers: { Authorization: "Bearer secret-zyx" },
    });
    expect(res.status).toBe(401);
  });

  it("rejects readiness when the token is supplied via ?token= query param", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/readiness?token=secret-xyz`);
    expect(res.status).toBe(401);
  });

  it("returns { ready, supervisor } WITH a valid bearer token", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/readiness`, {
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["ready", "supervisor"]);
    expect(["locked", "serving"]).toContain(body.ready);
    expect(["wired", "unwired", "n/a"]).toContain(body.supervisor);
  });

  it("reports ready=locked when the read surface is not yet unlocked", async () => {
    // No identity manager wired -> the fortress is up but not unlocked.
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/readiness`, {
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ready).toBe("locked");
    // "n/a" is honest in THIS mode: the co-located/unified read-aggregator
    // dashboard has NO Protect launch route at all, so an absent supervisor
    // bridge does NOT guarantee a 503 here (unlike the principal-policy
    // dashboard, where absence => 503 and the honest value is "unwired" -
    // covered in test/principal-policy/dashboard.test.ts). No supervisorStatus
    // provider is supplied to this rig, so the truthful default is "n/a".
    expect(body.supervisor).toBe("n/a");
  });

  it("reports ready=serving when the read surface is live (unlocked)", async () => {
    handle = await startForTest({
      authToken: "secret-xyz",
      identityManager: STUB_IDENTITY_MANAGER,
    });
    const res = await fetch(`${handle.url}/api/readiness`, {
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ready).toBe("serving");
    // Honest "n/a" for the read-aggregator mode (no Protect launch route);
    // see the locked-case comment above.
    expect(body.supervisor).toBe("n/a");
  });

  it("serves readiness on loopback auto-auth when no auth token is set", async () => {
    // With no auth token configured, the read surface is open on loopback
    // exactly like the other read routes; the endpoint must still answer.
    handle = await startForTest();
    const res = await fetch(`${handle.url}/api/readiness`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["ready", "supervisor"]);
  });

  it("/api/health carries instance + since and NOT ready/supervisor (brief HIGH-1)", async () => {
    handle = await startForTest({ authToken: "secret-xyz" });
    const res = await fetch(`${handle.url}/api/health`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["instance", "mode", "ok", "since"]);
    expect(typeof body.instance).toBe("string");
    expect(body.instance.length).toBeGreaterThan(0);
    expect(typeof body.since).toBe("number");
    // The oracle fields are auth-gated on /api/readiness; never here.
    expect(body.ready).toBeUndefined();
    expect(body.supervisor).toBeUndefined();
  });

  it("instance is STABLE across polls within one process and matches the shared source", async () => {
    handle = await startForTest();
    const [a, b] = await Promise.all([
      fetch(`${handle.url}/api/health`).then((r) => r.json()),
      fetch(`${handle.url}/api/health`).then((r) => r.json()),
    ]);
    expect(a.instance).toBe(b.instance);
    // The handler reads the single shared module-level source, not a per-call
    // value, so the wire id equals the in-process accessor.
    expect(a.instance).toBe(getProcessInstance());
    expect(a.since).toBe(getProcessSince());
  });

  it("instance CHANGES across a restart (the whole point of restart detection)", async () => {
    // A restart loads process-identity fresh in a NEW process, minting a NEW
    // boot id. vi.resetModules() drops the module cache so a re-import re-runs
    // module init - the closest in-test simulation of a process relaunch. If
    // the id did NOT change here, restart detection (the host app's
    // Reconnecting -> Live transition) would be silently broken.
    const first = getProcessInstance();

    vi.resetModules();
    const reloaded = await import("../../src/dashboard/process-identity.js");
    const second = reloaded.getProcessInstance();

    expect(second).not.toBe(first);
    // Both are still well-formed opaque ids (not empty / degenerate).
    expect(typeof second).toBe("string");
    expect(second.length).toBe(first.length);
    expect(second.length).toBeGreaterThan(0);

    // Restore the module registry so sibling suites see the original module.
    vi.resetModules();
  });

  it("multi-tenant dashboard is EXCLUDED from /api/readiness but still emits instance/since on /api/health", async () => {
    multi = await startMultiDashboardServer({ port: 0 });
    // No readiness aggregation across tenants (brief sec invariant 6.4): the
    // multi server holds no single-tenant unlock state, so /api/readiness 404s.
    const readiness = await fetch(`${multi.url}/api/readiness`);
    expect(readiness.status).toBe(404);
    // Its own /api/health still carries the per-process restart signal.
    const health = await fetch(`${multi.url}/api/health`);
    expect(health.status).toBe(200);
    const body = await health.json();
    expect(body.ok).toBe(true);
    expect(body.mode).toBe("multi");
    expect(typeof body.instance).toBe("string");
    expect(typeof body.since).toBe("number");
    // Readiness/posture never appear on the multi health probe either.
    expect(body.ready).toBeUndefined();
    expect(body.supervisor).toBeUndefined();
  });
});
