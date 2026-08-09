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
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { IdentityManager } from "../../src/cognitive/tools.js";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import {
  addOperatorAuthorizationFields,
  signOperatorPayload,
} from "../../src/v1/operator-signed.js";
import { signOperatorAttestation } from "../../src/v1/operator-attestation.js";
import {
  OPERATOR_AUTHORIZATION_SPENT_STORE_KEY,
  OPERATOR_AUTHORIZATION_SPENT_STORE_NAMESPACE,
  OperatorAuthorizationSpentStore,
} from "../../src/v1/operator-authorization-spent-store.js";
import { buildV11Bindings } from "../../src/dashboard/v1_1/wiring.js";
import { writePersistedLocalAgents } from "../../src/hub/agent-registry-persistence.js";
import type { HubTier1ApprovalEnqueuedResult } from "../../src/hub/types.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { ProtectLaunchOutcome } from "../../src/v1/agents.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { getFreePort } from "../helpers/free-port.js";

const operator = (() => {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
})();

interface TestRig {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  authToken: string;
  storagePath?: string;
  hasOperatorIdentity: boolean;
  stop: () => Promise<void>;
}

class ArmedFailingOperatorSpentStorage extends MemoryStorage {
  armed = false;

  override async write(
    namespace: string,
    key: string,
    data: Uint8Array,
  ): Promise<void> {
    if (
      this.armed &&
      namespace === OPERATOR_AUTHORIZATION_SPENT_STORE_NAMESPACE &&
      key === OPERATOR_AUTHORIZATION_SPENT_STORE_KEY
    ) {
      throw new Error("operator spent-set write failed");
    }
    await super.write(namespace, key, data);
  }
}

/** A minimal IdentityManager exposing only what the /v1 agent routes read. */
function stubIdentityManager(publicKey: Uint8Array): IdentityManager {
  const identity = {
    identity_id: "op-1",
    label: "operator",
    did: "did:key:test",
    public_key: toBase64url(publicKey),
    created_at: "2026-06-01T00:00:00.000Z",
    key_type: "ed25519",
    key_protection: "passphrase",
  };
  return {
    get: (id: string) => (id === "op-1" ? identity : undefined),
    getDefault: () => identity,
    getPrimaryIdentityId: () => "op-1",
  } as unknown as IdentityManager;
}

async function startRig(opts?: {
  withOperatorIdentity?: boolean;
  spentSetStorage?: MemoryStorage;
  withV11Bindings?: boolean;
  withSupervisor?: boolean;
}): Promise<TestRig> {
  const storage = opts?.spentSetStorage ?? new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const authToken = `v1-pr-a2-test-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();
  const storagePath = opts?.withV11Bindings
    ? await mkdtemp(join(tmpdir(), "sanctuary-agents-http-"))
    : undefined;

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
  await dashboard.setOperatorAuthorizationSpentStore(
    OperatorAuthorizationSpentStore.durableFromBoot(storage, masterKey),
  );
  if (storagePath) {
    writePersistedLocalAgents(storagePath, [agentRecord()]);
    const bindings = buildV11Bindings({
      identityId: "op-1",
      fortressId: "fortress-http-test",
      auditLog,
      storagePath,
      stopAgentEgress: async () => ({
        outcome: "engaged",
        agent_uid: 501,
        revoked_rule_ids: ["agent-x"],
        residual_allow_count: 0,
        reload_confirmed: true,
        snapshot_path: "/tmp/sanctuary-agent-stop-test",
      }),
      warnProducerKeyUnavailable: () => {},
    });
    bindings.hubService.controlAgent = async (
      agentId,
      action,
    ): Promise<HubTier1ApprovalEnqueuedResult> => {
      if (action !== "unwrap" && action !== "lockdown") {
        throw new Error("test hub only stubs Tier 1 actions");
      }
      return {
        agent_id: agentId,
        inbox_item_id: `tier1.${action}.${agentId}.http-test`,
        status: "approval_pending",
        operation_category: action,
      };
    };
    dashboard.setV11Bindings(bindings);
  }
  if (opts?.withSupervisor) {
    dashboard.setSupervisorBridge({
      launchProtect: async (spec: {
        agentId: string;
        harness: string;
        configPath: string;
      }): Promise<ProtectLaunchOutcome> => ({
        ok: true,
        status: "protecting",
        agent_id: spec.agentId,
        launch_id: "launch-http-test",
      }),
    } as unknown as Parameters<typeof dashboard.setSupervisorBridge>[0]);
  }

  await dashboard.start();
  return {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    authToken,
    storagePath,
    hasOperatorIdentity: opts?.withOperatorIdentity === true,
    stop: async () => {
      await dashboard.stop();
      if (storagePath) {
        await rm(storagePath, { recursive: true, force: true });
      }
    },
  };
}

function agentRecord(): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: "agent-x",
    identity_id: "op-1",
    harness: "claude_code",
    model_provider: {
      vendor: "anthropic",
      model_id: "claude-test",
      runs_locally: false,
    },
    policy_id: "policy-test",
    status: "active",
    budget_summary: {
      daily: { unit: "tokens", cap: 1000, used: 1 },
      last_refreshed_at: "2026-08-09T00:00:00.000Z",
    },
    last_activity_at: "2026-08-09T00:00:00.000Z",
    wrapped_at: "2026-08-09T00:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: false,
      can_change_template: false,
    },
  };
}

function operatorSigned(action: string, payload: Record<string, unknown>) {
  const signedPayload = addOperatorAuthorizationFields(payload);
  return {
    ...signedPayload,
    operator_signature: toBase64url(
      signOperatorPayload(action, signedPayload, operator.privateKey),
    ),
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
  const operator_attestation = rig.hasOperatorIdentity
    ? signOperatorAttestation({
        operatorPublicKey: operator.publicKey,
        operatorPrivateKey: operator.privateKey,
        clientPubkey: publicKey,
        issuedAtMs: Date.now(),
      })
    : undefined;
  const initRes = await fetch(`${rig.baseUrl}/v1/session/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_pubkey: toBase64url(publicKey),
      ...(operator_attestation ? { operator_attestation } : {}),
    }),
  });
  expect(initRes.status).toBe(200);
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
  expect(completeRes.status).toBe(200);
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
      body: JSON.stringify(operatorSigned("/v1/agents/unprotect", payload)),
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
      body: JSON.stringify(operatorSigned("/v1/agents/unprotect", payload)),
    });
    // Signature verified against the real operator identity ⇒ past the gate;
    // 503 because this rig binds no hub. (A 403 here would mean the gate
    // wrongly rejected a valid operator signature.)
    expect(res.status).toBe(503);
  });

  it("refuses replay of the same operator-signed unprotect over the real channel", async () => {
    const token = await openSession(rig);
    const body = operatorSigned("/v1/agents/unprotect", {
      agent_id: "agent-x",
      idempotency_key: "replay-k1",
    });
    const send = () =>
      fetch(`${rig.baseUrl}/v1/agents/unprotect`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    const first = await send();
    expect(first.status).toBe(503); // spent first, then no hub bound.
    const replay = await send();
    expect(replay.status).toBe(403);
    expect(await replay.json()).toEqual({ error: "forbidden" });
  });

  it("lets non-federated production-graph protect and unprotect succeed once, then refuses replay", async () => {
    await rig.stop();
    rig = await startRig({
      withOperatorIdentity: true,
      withV11Bindings: true,
      withSupervisor: true,
    });
    expect(rig.dashboard.isFederationProvisioned()).toBe(false);
    const token = await openSession(rig);

    const protectBody = operatorSigned("/v1/agents/protect", {
      harness: "claude_code",
      agent_id: "agent-x",
      config_path: "/conf/agent-x.json",
      idempotency_key: "nonfed-protect",
    });
    const sendProtect = () =>
      fetch(`${rig.baseUrl}/v1/agents/protect`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(protectBody),
      });
    const firstProtect = await sendProtect();
    expect(firstProtect.status).toBe(202);
    expect(await firstProtect.json()).toEqual({
      status: "protecting",
      agent_id: "agent-x",
      launch_id: "launch-http-test",
    });
    const replayProtect = await sendProtect();
    expect(replayProtect.status).toBe(403);
    expect(await replayProtect.json()).toEqual({ error: "forbidden" });

    const unprotectBody = operatorSigned("/v1/agents/unprotect", {
      agent_id: "agent-x",
      idempotency_key: "nonfed-unprotect",
    });
    const sendUnprotect = () =>
      fetch(`${rig.baseUrl}/v1/agents/unprotect`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(unprotectBody),
      });
    const firstUnprotect = await sendUnprotect();
    expect(firstUnprotect.status).toBe(202);
    const firstUnprotectBody = (await firstUnprotect.json()) as {
      status: string;
      agent_id: string;
      audit_event_id: string;
    };
    expect(firstUnprotectBody.status).toBe("approval_pending");
    expect(firstUnprotectBody.agent_id).toBe("agent-x");
    expect(firstUnprotectBody.audit_event_id).toMatch(/^tier1\.unwrap\.agent-x\./);
    const replayUnprotect = await sendUnprotect();
    expect(replayUnprotect.status).toBe(403);
    expect(await replayUnprotect.json()).toEqual({ error: "forbidden" });
  });

  it("refuses a legacy no-freshness operator-signed unprotect over the real channel", async () => {
    const token = await openSession(rig);
    const payload = { agent_id: "agent-x", idempotency_key: "legacy-k1" };
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

  it("fails closed when the durable spent-set write fails over the real channel", async () => {
    await rig.stop();
    const storage = new ArmedFailingOperatorSpentStorage();
    rig = await startRig({ withOperatorIdentity: true, spentSetStorage: storage });
    storage.armed = true;
    const token = await openSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/agents/unprotect`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/agents/unprotect", {
          agent_id: "agent-x",
          idempotency_key: "unwritable-spent-set",
        }),
      ),
    });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "unavailable" });
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
      body: JSON.stringify(operatorSigned("/v1/agents/protect", payload)),
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
