/**
 * Federation PR-A2 — /v1/agents over real HTTP through DashboardApprovalChannel.
 *
 * Proves the additive routes are reachable and wired correctly through the
 * REAL channel (not a mock of the handler):
 *   - unauthenticated callers get the uniform 401 on every agents path
 *     (route map stays opaque — these paths existed only as 401/404 in
 *     PR-A1; a regression that bypassed session auth would surface here);
 *   - an authenticated session reads GET /v1/agents (empty roster with no
 *     hub bound) instead of the PR-A1 404;
 *   - writes are OPERATOR_SIGNED and fail closed: a real Ed25519 operator
 *     signature passes the channel's signature gate (and then 503s because
 *     no hub is bound in this rig), while an unsigned/wrongly-signed write
 *     collapses to the generic 403. This exercises the dashboard adapter's
 *     `resolveOperatorPublicKey` against a real operator identity.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { IdentityManager } from "../../src/l1-cognitive/tools.js";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import { signOperatorPayload } from "../../src/v1/operator-signed.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";

const operator = (() => {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
})();

interface TestRig {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  authToken: string;
  stop: () => Promise<void>;
}

function pickPort(): number {
  return 17000 + Math.floor(Math.random() * 20000);
}

/** A minimal IdentityManager exposing only what the /v1 agent routes read. */
function stubIdentityManager(publicKey: Uint8Array): IdentityManager {
  return {
    getDefault: () => ({
      identity_id: "op-1",
      label: "operator",
      did: "did:key:test",
      public_key: toBase64url(publicKey),
      created_at: "2026-06-01T00:00:00.000Z",
      key_type: "ed25519",
      key_protection: "passphrase",
    }),
    getPrimaryIdentityId: () => "op-1",
  } as unknown as IdentityManager;
}

async function startRig(opts?: { withOperatorIdentity?: boolean }): Promise<TestRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const authToken = `v1-pr-a2-test-${randomBytes(8).toString("hex")}`;
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
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
    ...(opts?.withOperatorIdentity
      ? { identityManager: stubIdentityManager(operator.publicKey) }
      : {}),
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

/**
 * Open a session for the agents tests via post-unlock loopback auto-auth. The
 * session attestation type is orthogonal to the agents endpoints under test
 * (which gate writes on the independent OPERATOR_SIGNED signature); the
 * durable-attestation path itself is covered in session-service.test.ts and
 * v1-routing.test.ts. Auto-auth does NOT bypass the per-write operator
 * signature, so the fail-closed write assertions still hold.
 */
async function openSession(rig: TestRig): Promise<string> {
  rig.dashboard.setAutoAuthLocalhost(true);
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  const initRes = await fetch(`${rig.baseUrl}/v1/session/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_pubkey: toBase64url(publicKey) }),
  });
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
  const completeRes = await fetch(`${rig.baseUrl}/v1/session/complete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: init.challenge_id,
      client_signature: toBase64url(ed25519.sign(message, privateKey)),
    }),
  });
  const complete = (await completeRes.json()) as { session_token: string };
  return complete.session_token;
}

describe("/v1/agents over HTTP — perimeter + wiring", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig();
  });
  afterEach(async () => {
    await rig.stop();
  });

  it("denies every agents path to unauthenticated callers with the uniform 401", async () => {
    const probes: Array<[string, string]> = [
      ["GET", "/v1/agents"],
      ["POST", "/v1/agents/protect"],
      ["POST", "/v1/agents/unprotect"],
    ];
    for (const [method, path] of probes) {
      const res = await fetch(`${rig.baseUrl}${path}`, { method });
      expect(res.status, `${method} ${path}`).toBe(401);
      expect(await res.json(), `${method} ${path}`).toEqual({ error: "unauthorized" });
    }
  });

  it("serves GET /v1/agents to an authenticated session (empty roster, no hub bound)", async () => {
    const token = await openSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/agents`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ agents: [] });
  });

  it("fails writes closed when no operator identity is configured (generic 403)", async () => {
    const token = await openSession(rig);
    // Even a well-formed, signed payload is denied: this rig has no operator
    // identity, so resolveOperatorPublicKey returns null → 403.
    const payload = { agent_id: "agent-x", idempotency_key: "k1" };
    const res = await fetch(`${rig.baseUrl}/v1/agents/unprotect`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        ...payload,
        operator_signature: toBase64url(
          signOperatorPayload("/v1/agents/unprotect", payload, operator.privateKey),
        ),
      }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });
});

describe("/v1/agents over HTTP — operator-signed writes with an operator identity", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({ withOperatorIdentity: true });
  });
  afterEach(async () => {
    await rig.stop();
  });

  it("passes the signature gate then 503s (no hub bound) for a valid operator signature", async () => {
    const token = await openSession(rig);
    const payload = { agent_id: "agent-x", idempotency_key: "k1" };
    const res = await fetch(`${rig.baseUrl}/v1/agents/unprotect`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        ...payload,
        operator_signature: toBase64url(
          signOperatorPayload("/v1/agents/unprotect", payload, operator.privateKey),
        ),
      }),
    });
    // Signature verified against the real operator identity ⇒ past the gate;
    // 503 because this rig binds no hub. (A 403 here would mean the gate
    // wrongly rejected a valid operator signature.)
    expect(res.status).toBe(503);
  });

  it("denies an unsigned write even with an operator identity present", async () => {
    const token = await openSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/agents/unprotect`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: "agent-x", idempotency_key: "k1" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });

  it("a valid signed protect reaches the supervisor path and fails closed 503 when no supervisor is wired (Phase S1; NOT a 501 oracle)", async () => {
    const token = await openSession(rig);
    // Phase S1 protect requires a config_path + agent_id (it launches a
    // supervised process). This rig binds no supervisor bridge, so a fully
    // formed, validly-signed protect lands on the fail-closed 503 path —
    // never a silent success, and never the old 501 not_implemented oracle.
    const payload = {
      harness: "claude_code",
      agent_id: "agent-x",
      config_path: "/conf/agent-x.json",
      idempotency_key: "k1",
    };
    const res = await fetch(`${rig.baseUrl}/v1/agents/protect`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        ...payload,
        operator_signature: toBase64url(
          signOperatorPayload("/v1/agents/protect", payload, operator.privateKey),
        ),
      }),
    });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "unavailable" });
  });

  it("denies an unsigned protect with 403 (no execution oracle without a signature)", async () => {
    const token = await openSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/agents/protect`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        harness: "claude_code",
        agent_id: "agent-x",
        config_path: "/conf/agent-x.json",
        idempotency_key: "k1",
      }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });
});
