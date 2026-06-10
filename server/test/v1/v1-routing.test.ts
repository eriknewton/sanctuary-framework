/**
 * Federation PR-A1 — /v1 HTTP surface end-to-end on loopback.
 *
 * Boots a real DashboardApprovalChannel and proves the RFC v7 session
 * ceremony over actual HTTP: init → complete → session-token-gated
 * GET /v1/status. Also proves the fail-closed perimeter: every /v1 route
 * (known or unknown) denies unauthenticated callers with ONE generic 401
 * body, the PUBLIC minimal status leaks nothing, and the legacy /api/* +
 * /v1.0 + /v1.1 surfaces are untouched by the additive mount.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  buildChallengeMessage,
  LOCAL_OPERATOR_ATTESTATION_REF,
} from "../../src/v1/ceremony.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";

interface TestRig {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  authToken: string;
  stop: () => Promise<void>;
}

function pickPort(): number {
  return 17000 + Math.floor(Math.random() * 20000);
}

async function startRig(): Promise<TestRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);

  const authToken = `v1-pr-a1-test-${randomBytes(8).toString("hex")}`;
  const port = pickPort();

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
      approval_channel: {
        type: "stderr",
        timeout_seconds: 30,
      },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
  });

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

function makeClient() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

async function ceremonyInit(
  rig: TestRig,
  publicKey: Uint8Array,
  attestationToken: string | undefined,
): Promise<Response> {
  return fetch(`${rig.baseUrl}/v1/session/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_pubkey: toBase64url(publicKey),
      operator_attestation: {
        type: "local_operator",
        ...(attestationToken !== undefined ? { token: attestationToken } : {}),
      },
    }),
  });
}

async function openSessionOverHttp(rig: TestRig): Promise<string> {
  const { privateKey, publicKey } = makeClient();
  const initRes = await ceremonyInit(rig, publicKey, rig.authToken);
  expect(initRes.status).toBe(200);
  const init = (await initRes.json()) as {
    challenge: string;
    challenge_id: string;
    expires_at: number;
  };
  expect(typeof init.challenge).toBe("string");
  expect(typeof init.challenge_id).toBe("string");

  const message = buildChallengeMessage(
    publicKey,
    fromBase64url(init.challenge),
    LOCAL_OPERATOR_ATTESTATION_REF,
  );
  const completeRes = await fetch(`${rig.baseUrl}/v1/session/complete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: init.challenge_id,
      client_signature: toBase64url(ed25519.sign(message, privateKey)),
    }),
  });
  expect(completeRes.status).toBe(200);
  const complete = (await completeRes.json()) as { session_token: string };
  expect(typeof complete.session_token).toBe("string");
  return complete.session_token;
}

describe("/v1 session ceremony over HTTP (loopback)", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig();
  });

  afterEach(async () => {
    await rig.stop();
  });

  it("happy path: init → complete → full GET /v1/status", async () => {
    const token = await openSessionOverHttp(rig);
    const res = await fetch(`${rig.baseUrl}/v1/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(typeof body.version).toBe("string");
    expect(body.daemon).toBeDefined();
    expect(body.listener).toBeDefined();
    expect(body.federation).toEqual({ enabled: false });
    expect(body).toHaveProperty("identity");
    expect(body).toHaveProperty("castle_wall");
  });

  it("never leaks key material in any /v1 response", async () => {
    const token = await openSessionOverHttp(rig);
    const res = await fetch(`${rig.baseUrl}/v1/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const text = await res.text();
    expect(text).not.toContain("encrypted_private_key");
    expect(text).not.toContain("private_key");
    expect(text).not.toContain(rig.authToken);
  });

  it("rejects a replayed ceremony completion with the generic denial", async () => {
    const { privateKey, publicKey } = makeClient();
    const initRes = await ceremonyInit(rig, publicKey, rig.authToken);
    const init = (await initRes.json()) as { challenge: string; challenge_id: string };
    const message = buildChallengeMessage(
      publicKey,
      fromBase64url(init.challenge),
      LOCAL_OPERATOR_ATTESTATION_REF,
    );
    const body = JSON.stringify({
      challenge_id: init.challenge_id,
      client_signature: toBase64url(ed25519.sign(message, privateKey)),
    });
    const first = await fetch(`${rig.baseUrl}/v1/session/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    expect(first.status).toBe(200);
    const replay = await fetch(`${rig.baseUrl}/v1/session/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({ error: "unauthorized" });
  });

  it("denies init with a wrong operator attestation token — generic, no challenge", async () => {
    const { publicKey } = makeClient();
    const res = await ceremonyInit(rig, publicKey, "wrong-token");
    expect(res.status).toBe(401);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ error: "unauthorized" });
    expect(body.challenge).toBeUndefined();
  });

  it("denies tokenless loopback init when auto-auth is off, allows when on", async () => {
    const { publicKey } = makeClient();
    const denied = await ceremonyInit(rig, publicKey, undefined);
    expect(denied.status).toBe(401);

    rig.dashboard.setAutoAuthLocalhost(true);
    const allowed = await ceremonyInit(rig, publicKey, undefined);
    expect(allowed.status).toBe(200);
  });

  it("failure responses are indistinguishable across denial reasons", async () => {
    // Bad attestation vs replayed challenge vs unknown challenge id must
    // produce byte-identical bodies (CLAUDE.md constraint 7).
    const { publicKey } = makeClient();
    const badAttestation = await ceremonyInit(rig, publicKey, "wrong");
    const unknownChallenge = await fetch(`${rig.baseUrl}/v1/session/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge_id: "no-such-id", client_signature: "AAAA" }),
    });
    const a = await badAttestation.text();
    const b = await unknownChallenge.text();
    expect(badAttestation.status).toBe(401);
    expect(unknownChallenge.status).toBe(401);
    expect(a).toBe(b);
  });

  it("rejects malformed and oversize ceremony bodies without issuing anything", async () => {
    const malformed = await fetch(`${rig.baseUrl}/v1/session/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not json",
    });
    expect(malformed.status).toBe(400);
    const oversize = await fetch(`${rig.baseUrl}/v1/session/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pad: "x".repeat(20 * 1024) }),
    });
    expect(oversize.status).toBe(400);
  });
});

describe("/v1 fail-closed perimeter", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig();
  });

  afterEach(async () => {
    await rig.stop();
  });

  it("GET /v1/status without credentials serves ONLY the minimal document", async () => {
    const res = await fetch(`${rig.baseUrl}/v1/status`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["ok", "version"]);
  });

  it("GET /v1/status with an invalid bearer is denied (not served minimal)", async () => {
    const res = await fetch(`${rig.baseUrl}/v1/status`, {
      headers: { Authorization: "Bearer forged-token" },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("the long-lived dashboard auth token is NOT accepted on /v1 routes", async () => {
    // The legacy bearer works on /api/*; /v1 is session-token only.
    const res = await fetch(`${rig.baseUrl}/v1/status`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated requests on every /v1 route, known or future", async () => {
    const probes: Array<[string, string]> = [
      ["GET", "/v1/agents"],
      ["GET", "/v1/federation/status"],
      ["GET", "/v1/nodes"],
      ["GET", "/v1/audit-log"],
      ["GET", "/v1/identity"],
      ["GET", "/v1/settings"],
      ["GET", "/v1/policy/current"],
      ["POST", "/v1/agents/protect"],
      ["POST", "/v1/federation/enable"],
      ["POST", "/v1/identity/rotate"],
      ["DELETE", "/v1/anything-at-all"],
      ["GET", "/v1"],
      ["GET", "/v1/"],
    ];
    for (const [method, path] of probes) {
      const res = await fetch(`${rig.baseUrl}${path}`, { method });
      expect(res.status, `${method} ${path}`).toBe(401);
      expect(await res.json(), `${method} ${path}`).toEqual({ error: "unauthorized" });
    }
  });

  it("authenticated callers get 404 on unknown /v1 paths (and only they can tell)", async () => {
    const token = await openSessionOverHttp(rig);
    const res = await fetch(`${rig.baseUrl}/v1/no-such-endpoint`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not found" });
  });

  it("does not shadow the legacy surfaces: /api/health, /api/status, /v1.0", async () => {
    const health = await fetch(`${rig.baseUrl}/api/health`);
    expect(health.status).toBe(200);

    const legacyStatus = await fetch(`${rig.baseUrl}/api/status`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    // This rig stubs only the deps the /v1 surface needs; the legacy
    // handler may 500 on missing optional deps (same allowance as
    // test/dashboard/v1_1-routing.test.ts). What matters here is that
    // the /v1 mount did not capture or auth-block the legacy route.
    expect(legacyStatus.status).not.toBe(404);
    expect(legacyStatus.status).not.toBe(401);

    // /v1.0 (legacy dashboard HTML) must NOT be captured by the /v1 router.
    const v10 = await fetch(`${rig.baseUrl}/v1.0`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(v10.status).toBe(200);
    expect(v10.headers.get("content-type")).toMatch(/text\/html/);
  });
});
