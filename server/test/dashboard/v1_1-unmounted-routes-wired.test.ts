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
 * A fourth prefix — `/api/query-anonymity/pii` — is deliberately PARKED
 * (not mounted; redactor not wired in this build). The final test pins
 * that it does NOT reach a wired handler.
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

  // ── /api/query-anonymity/pii is PARKED (not wired) ───────────────────

  it("PARKED: /api/query-anonymity/pii does NOT reach a wired handler", async () => {
    // The pii-rewrite prefix is explicitly NOT mounted in this PR (the
    // redactor is not wired in this build; Erik-confirmed next build).
    // With a valid bearer it must NOT produce a wired-handler 200; it
    // falls through to the legacy table (404). This pins that we did not
    // accidentally light it up.
    const res = await fetch(
      `${rig.baseUrl}/api/query-anonymity/pii`,
      { headers: { Authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(404);
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
});
