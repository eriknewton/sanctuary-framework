/**
 * Federation PR-A1/A3 — /v1 HTTP surface end-to-end on loopback.
 *
 * Boots a real DashboardApprovalChannel and proves the RFC v7 session
 * ceremony over actual HTTP using the PR-A3 durable Ed25519 operator
 * attestation: init → complete → session-token-gated GET /v1/status. Also
 * proves the fail-closed perimeter: every /v1 route (known or unknown) denies
 * unauthenticated callers with ONE generic 401 body, the PUBLIC minimal
 * status leaks nothing, and the legacy /api/* + /v1.0 + /v1.1 surfaces are
 * untouched by the additive mount.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import { signOperatorAttestation } from "../../src/v1/operator-attestation.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { OPERATOR, startRig, openDurableSession, type TestRig } from "./rig.js";

function makeClient() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** A durable operator attestation bound to `clientPubkey`. */
function durableAttestation(clientPubkey: Uint8Array) {
  return signOperatorAttestation({
    operatorPublicKey: OPERATOR.publicKey,
    operatorPrivateKey: OPERATOR.privateKey,
    clientPubkey,
    issuedAtMs: Date.now(),
  });
}

/** POST /v1/session/init with an arbitrary operator_attestation body (or none). */
async function ceremonyInit(
  rig: TestRig,
  publicKey: Uint8Array,
  attestation: unknown | undefined,
): Promise<Response> {
  return fetch(`${rig.baseUrl}/v1/session/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_pubkey: toBase64url(publicKey),
      ...(attestation !== undefined ? { operator_attestation: attestation } : {}),
    }),
  });
}

// retry:2 - this loopback /v1 rig races port/session setup under full-suite
// parallel load (a recurring non-hermetic CI flake class for the /v1 rigs).
describe("/v1 session ceremony over HTTP (durable operator attestation)", { retry: 2 }, () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig({ withOperatorIdentity: true });
  });
  afterEach(async () => {
    await rig.stop();
  });

  it("happy path: init → complete → full GET /v1/status", async () => {
    const token = await openDurableSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(typeof body.version).toBe("string");
    expect(body.daemon).toBeDefined();
    expect(body.listener).toBeDefined();
    expect(body.federation).toMatchObject({ enabled: false, provisioned: false });
    expect(body).toHaveProperty("identity");
    expect(body).toHaveProperty("castle_wall");
  });

  it("never leaks key material in any /v1 response", async () => {
    const token = await openDurableSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const text = await res.text();
    expect(text).not.toContain("encrypted_private_key");
    expect(text).not.toContain("private_key");
    expect(text).not.toContain(rig.authToken);
    expect(text).not.toContain(toBase64url(OPERATOR.privateKey));
  });

  it("rejects a replayed ceremony completion with the generic denial", async () => {
    const { privateKey, publicKey } = makeClient();
    const initRes = await ceremonyInit(rig, publicKey, durableAttestation(publicKey));
    const init = (await initRes.json()) as {
      challenge: string;
      challenge_id: string;
      attestation_ref: string;
    };
    const message = buildChallengeMessage(
      publicKey,
      fromBase64url(init.challenge),
      init.attestation_ref,
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

  it("REPLACE-NOT-EXTEND: a bearer-token attestation no longer opens a session", async () => {
    // What PR-A1's temporary validator accepted (proof of the dashboard token)
    // is now rejected over HTTP — the durable path replaced it.
    const { publicKey } = makeClient();
    const res = await ceremonyInit(rig, publicKey, {
      type: "local_operator",
      token: rig.authToken,
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("denies init with an attestation signed by a NON-operator key", async () => {
    const { publicKey } = makeClient();
    const impostorPriv = randomBytes(32);
    const impostorPub = ed25519.getPublicKey(impostorPriv);
    const forged = signOperatorAttestation({
      operatorPublicKey: impostorPub,
      operatorPrivateKey: impostorPriv,
      clientPubkey: publicKey,
      issuedAtMs: Date.now(),
    });
    const res = await ceremonyInit(rig, publicKey, forged);
    expect(res.status).toBe(401);
    expect((await res.json())).toEqual({ error: "unauthorized" });
  });

  it("denies tokenless loopback init when auto-auth is off, allows when on", async () => {
    const { publicKey } = makeClient();
    const denied = await ceremonyInit(rig, publicKey, undefined);
    expect(denied.status).toBe(401);

    rig.dashboard.setAutoAuthLocalhost(true);
    const allowed = await ceremonyInit(rig, publicKey, undefined);
    expect(allowed.status).toBe(200);
  });

  it("ceremony denials are byte-identical across EVERY rejection path", async () => {
    const { publicKey } = makeClient();
    const impostorPriv = randomBytes(32);
    const forgedAttestation = signOperatorAttestation({
      operatorPublicKey: ed25519.getPublicKey(impostorPriv),
      operatorPrivateKey: impostorPriv,
      clientPubkey: publicKey,
      issuedAtMs: Date.now(),
    });
    const post = (path: string, body: string) =>
      fetch(`${rig.baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });

    const responses = await Promise.all([
      post("/v1/session/init", "{not json"),
      post("/v1/session/init", JSON.stringify({ pad: "x".repeat(20 * 1024) })),
      post("/v1/session/init", JSON.stringify({})),
      post(
        "/v1/session/init",
        JSON.stringify({
          client_pubkey: toBase64url(publicKey),
          operator_attestation: forgedAttestation,
        }),
      ),
      post(
        "/v1/session/init",
        JSON.stringify({
          client_pubkey: toBase64url(publicKey),
          operator_attestation: { type: "local_operator", token: "wrong-token" },
        }),
      ),
      post(
        "/v1/session/complete",
        JSON.stringify({ challenge_id: "no-such-id", client_signature: "AAAA" }),
      ),
    ]);

    const statuses = responses.map((r) => r.status);
    const bodies = await Promise.all(responses.map((r) => r.text()));
    for (let i = 0; i < responses.length; i++) {
      expect(statuses[i], `rejection path ${i}`).toBe(statuses[0]);
      expect(bodies[i], `rejection path ${i}`).toBe(bodies[0]);
    }
    expect(statuses[0]).toBe(401);
  });
});

// retry:2 - loopback /v1 rig; same non-hermetic flake class as above.
describe("/v1 fail-closed perimeter", { retry: 2 }, () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig({ withOperatorIdentity: true });
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
      ["POST", "/v1/federation/authorize/init"],
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

  it("the federation join-submission ceremony denies a bad request with the uniform 401", async () => {
    // Pre-session class (bootstrap-token auth). Federation is unprovisioned in
    // this rig, so even a structurally-plausible body is denied — and the body
    // is byte-identical to every other unauthenticated denial (no oracle).
    const res = await fetch(`${rig.baseUrl}/v1/federation/authorize/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bootstrap_token: { intended_node_id: "n" }, node_pubkey: "x" }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("authenticated callers get 404 on unknown /v1 paths (and only they can tell)", async () => {
    const token = await openDurableSession(rig);
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
    expect(legacyStatus.status).not.toBe(404);
    expect(legacyStatus.status).not.toBe(401);

    const v10 = await fetch(`${rig.baseUrl}/v1.0`, {
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(v10.status).toBe(200);
    expect(v10.headers.get("content-type")).toMatch(/text\/html/);
  });
});
