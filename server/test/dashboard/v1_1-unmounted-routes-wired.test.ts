/**
 * Wire-unmounted-routes (2026-06-29) — auth-gate regression suite.
 *
 * Three frozen-surface route prefixes shipped router code but were never
 * mounted in the production dispatch chokepoint
 * (`dashboard/v1_1/dispatch.ts`), which previously mounted only the hub:
 *
 *   /api/console   (console/api-router.ts  handleConsoleRoute)
 *   /api/anomaly   (anomaly-detection/anomaly-routes.ts)
 *   /api/policy    (policy-engine/english-policy-routes.ts)
 *
 * This PR mounts all three behind the SAME auth chokepoint the hub uses
 * (`enforceAuth` / `authMiddleware` over the dashboard `AuthConfig`). The
 * load-bearing property these tests pin is the gate, not the feature:
 *
 *   (a) an unauthenticated request to each newly-wired prefix is REJECTED
 *       (401) — a co-resident agent with only a loopback-HTTP primitive
 *       cannot reach the handler; AND
 *   (b) an operator-bearer-authenticated request REACHES the handler
 *       (a real 2xx domain response, NOT a 404 that would mean the prefix
 *       is still unmounted / fell through to the legacy table).
 *
 * The rig boots a real `DashboardApprovalChannel` (loopback-auto-auth OFF
 * by default, so the bearer is required even from 127.0.0.1 — identical to
 * the hub's existing "401 without auth" test) and wires the three bindings
 * through `buildV11Bindings`. The console domain service is constructed
 * here (entry-point-owned, like production) and threaded in via the
 * `consoleService` input; anomaly + policy bindings auto-construct from
 * `storage` + `masterKey`.
 *
 * A fourth prefix — `/api/query-anonymity/pii` — is NOW WIRED (Rho-2.5):
 * mounted behind the same auth chokepoint, with the consent-gated Tier B
 * redactor installed on the production selector. The tests below pin the
 * same gate property for it (401 without bearer; reaches handler with
 * bearer), and the absent-binding rig pins match-then-auth-then-503.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../src/dashboard/v1_1/wiring.js";
import { ConsoleService } from "../../src/console/console-service.js";
import { FortressService } from "../../src/fortress/index.js";
import { CONSOLE_API_PREFIX } from "../../src/console/constants.js";
import { ANOMALY_API_PREFIX } from "../../src/anomaly-detection/anomaly-routes.js";
import { ENGLISH_POLICY_API_PREFIX } from "../../src/policy-engine/english-policy-routes.js";
import { PII_REWRITE_API_PREFIX } from "../../src/query-anonymity/pii-rewrite-routes.js";
import { getFreePort } from "../helpers/free-port.js";

const IDENTITY_ID = "operator-test-routes";
const FORTRESS_STORAGE_PATH = "/tmp/sanctuary-wire-routes-test";

interface TestRig {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  authToken: string;
  stop: () => Promise<void>;
}

async function buildConsoleService(opts: {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  fortressId: string;
}): Promise<ConsoleService> {
  const nodePriv = ed25519.utils.randomPrivateKey();
  let seq = 0;
  const fortressService = new FortressService({
    storage: opts.storage,
    masterKey: opts.masterKey,
    fortressId: opts.fortressId,
    nodeId: "test-node-routes",
    principalId: "test-principal-routes",
    nodePrivateKey: nodePriv,
    nextMonotonicSeq: () => ++seq,
  });
  await fortressService.initialize();
  return new ConsoleService({
    fortressService,
    fortressId: opts.fortressId,
    getAgentIds: () => [],
  });
}

async function startRig(): Promise<TestRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const fortressId = fortressIdFromStoragePath(FORTRESS_STORAGE_PATH);

  const authToken = `wire-routes-test-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();

  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: authToken,
    auto_open: false,
  });

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
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
  });

  const consoleService = await buildConsoleService({
    storage,
    masterKey,
    fortressId,
  });

  dashboard.setV11Bindings(
    buildV11Bindings({
      identityId: IDENTITY_ID,
      fortressId,
      auditLog,
      // storage + masterKey trigger the anomaly + english-policy bindings.
      storage,
      masterKey,
      // console domain service is entry-point-constructed and threaded in.
      consoleService,
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

describe("wire-unmounted-routes — auth gate holds on every newly-wired prefix", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig();
  });

  afterEach(async () => {
    await rig.stop();
  });

  // ── /api/console ─────────────────────────────────────────────────────

  it("GET /api/console/* without a bearer is REJECTED (401)", async () => {
    const res = await fetch(`${rig.baseUrl}${CONSOLE_API_PREFIX}/header/badge`);
    expect(res.status).toBe(401);
  });

  it("GET /api/console/* WITH the operator bearer REACHES the handler (not 404/401)", async () => {
    const res = await fetch(
      `${rig.baseUrl}${CONSOLE_API_PREFIX}/header/badge`,
      { headers: { Authorization: `Bearer ${rig.authToken}` } },
    );
    // Reaches the console handler: a real domain response, not the auth
    // 401 and not a 404 (which would mean the prefix is still unmounted).
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(404);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  // ── /api/anomaly ─────────────────────────────────────────────────────

  it("GET /api/anomaly/* without a bearer is REJECTED (401)", async () => {
    const res = await fetch(`${rig.baseUrl}${ANOMALY_API_PREFIX}/detectors`);
    expect(res.status).toBe(401);
  });

  it("GET /api/anomaly/* WITH the operator bearer REACHES the handler (not 404/401)", async () => {
    const res = await fetch(
      `${rig.baseUrl}${ANOMALY_API_PREFIX}/detectors`,
      { headers: { Authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(404);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { catalog: unknown[] };
    };
    expect(body.ok).toBe(true);
    expect(Array.isArray(body.data.catalog)).toBe(true);
  });

  // ── /api/policy ──────────────────────────────────────────────────────

  it("GET /api/policy/* without a bearer is REJECTED (401)", async () => {
    const res = await fetch(`${rig.baseUrl}${ENGLISH_POLICY_API_PREFIX}/drafts`);
    expect(res.status).toBe(401);
  });

  it("GET /api/policy/* WITH the operator bearer REACHES the handler (not 404/401)", async () => {
    const res = await fetch(
      `${rig.baseUrl}${ENGLISH_POLICY_API_PREFIX}/drafts`,
      { headers: { Authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(404);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { drafts: unknown[] };
    };
    expect(body.ok).toBe(true);
    expect(Array.isArray(body.data.drafts)).toBe(true);
  });

  it("POST /api/policy/compile without a bearer is REJECTED (401) — write path also gated", async () => {
    const res = await fetch(`${rig.baseUrl}${ENGLISH_POLICY_API_PREFIX}/compile`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ english_text: "block all egress" }),
    });
    expect(res.status).toBe(401);
  });

  // ── /api/query-anonymity/pii is NOW WIRED (Rho-2.5) ──────────────────

  it("GET /api/query-anonymity/pii/config without a bearer is REJECTED (401)", async () => {
    const res = await fetch(`${rig.baseUrl}/api/query-anonymity/pii/config`);
    expect(res.status).toBe(401);
  });

  it("GET /api/query-anonymity/pii/config WITH the operator bearer REACHES the handler (not 404/401)", async () => {
    const res = await fetch(
      `${rig.baseUrl}/api/query-anonymity/pii/config`,
      { headers: { Authorization: `Bearer ${rig.authToken}` } },
    );
    // Reaches the wired handler: a real domain response, not the auth 401
    // and not a 404 (which would mean the prefix is still unmounted).
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(404);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { effective_tier_b_enabled: boolean };
    };
    expect(body.ok).toBe(true);
    // The route reports the truthful effective state (default off ->
    // false here; the redactorInstalled flag is not threaded by this rig).
    expect(typeof body.data.effective_tier_b_enabled).toBe("boolean");
  });

  // ── Hub behavior unchanged (regression guard) ────────────────────────

  it("hub behavior is UNCHANGED: /api/hub/agents still 401s without auth and 200s with it", async () => {
    const noAuth = await fetch(`${rig.baseUrl}/api/hub/agents`);
    expect(noAuth.status).toBe(401);
    const withAuth = await fetch(`${rig.baseUrl}/api/hub/agents`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(withAuth.status).toBe(200);
    const body = (await withAuth.json()) as {
      ok: boolean;
      data: { agents: unknown[] };
    };
    expect(body.ok).toBe(true);
    expect(Array.isArray(body.data.agents)).toBe(true);
  });
});

describe("wire-unmounted-routes — bindings absent: match-then-auth-then-503 (never a bypass)", () => {
  // A second rig that wires ONLY the hub (no storage/masterKey, no console
  // service). The three new prefixes must still run auth FIRST: an
  // unauthenticated caller gets 401, never a 503 that would leak the
  // unmounted state before the gate. This pins that the absence path does
  // not introduce a bypass.
  let dashboard: DashboardApprovalChannel;
  let baseUrl: string;
  let authToken: string;

  beforeEach(async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const auditLog = new AuditLog(storage, masterKey);
    authToken = `wire-routes-absent-${randomBytes(8).toString("hex")}`;
    const port = await getFreePort();
    dashboard = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auth_token: authToken,
      auto_open: false,
    });
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
        approval_channel: { type: "stderr", timeout_seconds: 30 },
      } as never,
      baseline: { load: async () => {}, save: async () => {} } as never,
      auditLog,
    });
    // No storage/masterKey -> no anomaly binding; no consoleService.
    dashboard.setV11Bindings(
      buildV11Bindings({
        identityId: IDENTITY_ID,
        fortressId: fortressIdFromStoragePath(FORTRESS_STORAGE_PATH),
        auditLog,
      }),
    );
    await dashboard.start();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(async () => {
    await dashboard.stop();
  });

  it("console binding absent: no bearer -> 401 (auth runs before the 503)", async () => {
    const res = await fetch(`${baseUrl}${CONSOLE_API_PREFIX}/header/badge`);
    expect(res.status).toBe(401);
  });

  it("console binding absent: WITH bearer -> 503 not_configured (gate passed, honestly unconfigured)", async () => {
    const res = await fetch(`${baseUrl}${CONSOLE_API_PREFIX}/header/badge`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("console_not_configured");
  });

  it("anomaly binding absent: no bearer -> 401 (auth runs before the 503)", async () => {
    const res = await fetch(`${baseUrl}${ANOMALY_API_PREFIX}/detectors`);
    expect(res.status).toBe(401);
  });

  it("pii binding absent: no bearer -> 401 (auth runs before the 503)", async () => {
    const res = await fetch(`${baseUrl}${PII_REWRITE_API_PREFIX}/config`);
    expect(res.status).toBe(401);
  });

  it("pii binding absent: WITH bearer -> 503 not_configured (gate passed, honestly unconfigured)", async () => {
    const res = await fetch(`${baseUrl}${PII_REWRITE_API_PREFIX}/config`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("pii_rewrite_not_configured");
  });
});

describe("PII-rewrite v1.1 router — default-deny on non-GET mutation (co-resident threat)", () => {
  // PRODUCTION path: when v1.1 bindings are wired, the PII Tier-B surface is
  // served by `handlePiiRewriteRoute` (via dispatchV11), which used a FLAT
  // `authMiddleware(authConfig)` for ALL methods. That let LOOPBACK auto-auth
  // release the `PATCH /config` MUTATION without the operator bearer — a
  // co-resident agent sharing loopback could flip operator PII config + consent
  // by network position alone. These tests pin the inversion to DEFAULT-DENY:
  // with loopback auto-auth ENABLED, a no-bearer loopback caller can still hit
  // the GET read and the stateless POST /rewrite preview, but the PATCH /config
  // mutation now REQUIRES the operator bearer.
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig();
    // Simulate the native-app deployment: loopback auto-auth ON. This is the
    // exact configuration under which the old flat gate leaked the mutation.
    rig.dashboard.setAutoAuthLocalhost(true);
  });

  afterEach(async () => {
    await rig.stop();
  });

  // ── GET read on loopback: auto-auth is sufficient (regression guard) ─────
  it("GET pii/config on loopback with NO bearer REACHES the handler (auto-auth read still works)", async () => {
    const res = await fetch(`${rig.baseUrl}${PII_REWRITE_API_PREFIX}/config`);
    expect(res.status).not.toBe(401);
    expect(res.status).toBe(200);
  });

  // ── POST /rewrite on loopback: the read-style EXEMPTION holds ────────────
  it("POST pii/rewrite on loopback with NO bearer REACHES the handler (stateless preview exempt)", async () => {
    const res = await fetch(`${rig.baseUrl}${PII_REWRITE_API_PREFIX}/rewrite`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: "contact me at jane@example.com" }),
    });
    expect(res.status).not.toBe(401);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  // ── PATCH /config on loopback: the MUTATION now requires the bearer ──────
  it("PATCH pii/config on loopback with NO bearer is REJECTED (401) — default-deny closes the co-resident hole", async () => {
    const res = await fetch(`${rig.baseUrl}${PII_REWRITE_API_PREFIX}/config`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: true }),
    });
    // Was 200 under the flat gate (loopback auto-auth released the mutation);
    // now 401 because requireToken suppresses the loopback shortcut.
    expect(res.status).toBe(401);
  });

  it("PATCH pii/config WITH the operator bearer REACHES the handler (not 401/404)", async () => {
    const res = await fetch(`${rig.baseUrl}${PII_REWRITE_API_PREFIX}/config`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${rig.authToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ enabled: true }),
    });
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(404);
  });
});

describe("legacy dispatcher — default-deny on non-GET mutation (allowlist inversion)", () => {
  // NON-v1.1 path (dashboard-standalone / SEC-012 rig): with NO v1.1 bindings,
  // the legacy dispatcher's gate is the active chokepoint. It used a 4-entry
  // allowlist (`/api/approve/`, `/api/deny/`, `/api/sovereignty-profile`,
  // `/api/proxy/servers`) and fell through to `{ allowSession: true }` for
  // every OTHER non-GET route. These tests pin the inversion to DEFAULT-DENY: a
  // valid SESSION is NOT sufficient for ANY non-GET mutation; the operator
  // bearer is required; reads still work with a session.
  const AUTH_TOKEN = `legacy-default-deny-${randomBytes(8).toString("hex")}`;
  let dashboard: DashboardApprovalChannel;
  let baseUrl: string;

  // A minimal rig with NO v11Bindings so the legacy gate is the active path.
  async function exchangeSession(): Promise<string> {
    const res = await fetch(`${baseUrl}/auth/session`, {
      method: "POST",
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { session_id: string };
    return body.session_id;
  }

  beforeEach(async () => {
    const port = await getFreePort();
    dashboard = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auth_token: AUTH_TOKEN,
      auto_open: false,
    });
    await dashboard.start();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(async () => {
    await dashboard.stop();
  });

  // ── The 4 originally-allowlisted mutations stay gated against a session ──
  it("POST /api/sovereignty-profile with a valid SESSION is REJECTED (401)", async () => {
    const session = await exchangeSession();
    const res = await fetch(
      `${baseUrl}/api/sovereignty-profile?session=${session}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      },
    );
    expect(res.status).toBe(401);
  });

  it("POST /api/proxy/servers with a valid SESSION is REJECTED (401)", async () => {
    const session = await exchangeSession();
    const res = await fetch(`${baseUrl}/api/proxy/servers?session=${session}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ servers: [] }),
    });
    expect(res.status).toBe(401);
  });

  it("POST /api/approve/:id with a valid SESSION is REJECTED (401)", async () => {
    const session = await exchangeSession();
    const res = await fetch(`${baseUrl}/api/approve/some-id?session=${session}`, {
      method: "POST",
    });
    expect(res.status).toBe(401);
  });

  it("POST /api/deny/:id with a valid SESSION is REJECTED (401)", async () => {
    const session = await exchangeSession();
    const res = await fetch(`${baseUrl}/api/deny/some-id?session=${session}`, {
      method: "POST",
    });
    expect(res.status).toBe(401);
  });

  // ── A novel non-GET path (no allowlist entry) is gated by DEFAULT ───────
  it("an arbitrary non-GET path with a SESSION is REJECTED (401) — default-deny, no allowlist edit needed", async () => {
    const session = await exchangeSession();
    const res = await fetch(
      `${baseUrl}/api/some-future-mutation?session=${session}`,
      { method: "POST" },
    );
    // The OLD allowlist fell through to `{ allowSession: true }` here, so a
    // session would have authenticated this un-listed mutation. Default-deny
    // requires the bearer: 401 before any route match.
    expect(res.status).toBe(401);
  });

  // ── GET read with a session still works (regression guard) ──────────────
  it("GET /api/pending with a valid SESSION is authenticated (read routes unaffected)", async () => {
    const session = await exchangeSession();
    const res = await fetch(`${baseUrl}/api/pending?session=${session}`);
    // Reaches the read handler (not the auth 401). The legacy /api/pending
    // route serves with deps unset here, returning its empty-list shape.
    expect(res.status).not.toBe(401);
  });
});
