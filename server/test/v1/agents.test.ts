// fail-before-exempt: /v1/agents test adds unsupported-unprotect ordering coverage before Tier 1 enqueue, not stop-button enforcement; real coverage is in agent-stop, egress, and controller tests.
/**
 * Federation PR-A2 — /v1/agents handler logic.
 *
 * Drives `handleAgentsRequest` directly with mock request/response objects
 * and an injectable {@link V1AgentsDeps}. The router has already validated
 * the SESSION_TOKEN before this code runs, so these tests assume a valid
 * session and focus on what PR-A2 adds: the AgentSummary mapping +
 * pagination, the OPERATOR_SIGNED write gate (fail closed), the Tier 1
 * unwrap enqueue, idempotent replay, and the protect execution stub.
 *
 * Each write test signs with a real Ed25519 operator key via PR-A1's
 * `signOperatorPayload`, so a regression that drops or weakens signature
 * verification fails these tests rather than passing silently.
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import {
  handleAgentsRequest,
  toAgentSummary,
  V1IdempotencyStore,
  idempotencyKeyFor,
  type V1AgentsDeps,
  type UnprotectOutcome,
} from "../../src/v1/agents.js";
import { signOperatorPayload } from "../../src/v1/operator-signed.js";
import { toBase64url } from "../../src/core/encoding.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { V1SessionClaims } from "../../src/v1/session-service.js";

// ── mocks ─────────────────────────────────────────────────────────────────

interface CapturedResponse {
  status: number;
  body: unknown;
  text: string;
}

function mockRes(): { res: import("node:http").ServerResponse; captured: CapturedResponse } {
  const captured: CapturedResponse = { status: 0, body: undefined, text: "" };
  const res = {
    writeHead(status: number) {
      captured.status = status;
      return this;
    },
    end(payload?: string) {
      captured.text = payload ?? "";
      captured.body = payload ? JSON.parse(payload) : undefined;
    },
  } as unknown as import("node:http").ServerResponse;
  return { res, captured };
}

function mockReq(body?: unknown): import("node:http").IncomingMessage {
  const chunks =
    body === undefined ? [] : [Buffer.from(JSON.stringify(body), "utf-8")];
  return {
    headers: {},
    async *[Symbol.asyncIterator]() {
      for (const c of chunks) yield c;
    },
  } as unknown as import("node:http").IncomingMessage;
}

function makeRecord(over: Partial<LocalAgentRecord>): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: "agent-x",
    identity_id: "op-1",
    harness: "claude_code",
    model_provider: { provider: "anthropic", model: "claude" } as never,
    policy_id: "policy-1",
    status: "active",
    budget_summary: {} as never,
    last_activity_at: "2026-06-10T00:00:00.000Z",
    wrapped_at: "2026-06-01T00:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: false,
      can_change_template: false,
    },
    ...over,
  };
}

const CLAIMS: V1SessionClaims = {
  client_pubkey: "client-pubkey-b64u",
  attestation_ref: "local-operator",
  session_generation: 1,
  issued_at: 0,
  expires_at: 9_999_999_999,
  capabilities: ["status_read"],
};

/** An operator keypair + a deps factory wired to it. */
function makeOperator() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

function baseDeps(over: Partial<V1AgentsDeps>): V1AgentsDeps {
  return {
    nodeId: "node-1",
    listAgents: () => [],
    resolveOperatorPublicKey: () => null,
    enqueueUnprotect: async () => ({ ok: false, reason: "unavailable" }),
    ...over,
  };
}

function signUnprotect(
  privateKey: Uint8Array,
  payload: Record<string, unknown>,
): string {
  return toBase64url(signOperatorPayload("/v1/agents/unprotect", payload, privateKey));
}

// ── GET /v1/agents ─────────────────────────────────────────────────────────

describe("GET /v1/agents", () => {
  it("maps hub records to the catalog AgentSummary shape", async () => {
    const deps = baseDeps({
      nodeId: "node-1",
      listAgents: () => [makeRecord({ agent_id: "a1", policy_id: "p9" })],
    });
    const { res, captured } = mockRes();
    await handleAgentsRequest(deps, mockReq(), res, new URL("http://x/v1/agents"), "GET", CLAIMS);
    expect(captured.status).toBe(200);
    expect(captured.body).toEqual({
      agents: [
        {
          agent_id: "a1",
          node_id: "node-1",
          label: "a1",
          harness: "claude_code",
          policy_protected: true,
          enforcement_active: "unknown",
          protected: true,
          policy_id: "p9",
          last_activity_at: "2026-06-10T00:00:00.000Z",
        },
      ],
    });
  });

  it("reports an unwrapping agent as not policy_protected", () => {
    const summary = toAgentSummary(makeRecord({ status: "unwrapping" }), "node-1");
    expect(summary.policy_protected).toBe(false);
    // Deprecated alias tracks policy_protected exactly.
    expect(summary.protected).toBe(false);
  });

  // ── Honesty split: policy_protected vs enforcement_active ────────────────
  //
  // The old single `protected` boolean over-claimed: it was `true` for any
  // status except "unwrapping", so a DEAD ("error") or indeterminate
  // ("unknown") agent still read protected:true, and a federation peer would read
  // that as "alive and actively guarded". These cases pin the honest split:
  // policy_protected stays true (operator intent / present in the roster), but
  // enforcement_active is "unknown" because no live liveness/enforcement signal
  // exists yet. Each asserts the deprecated alias equals policy_protected.
  //
  // REGRESSION GUARD: under the old single-boolean behavior there was no
  // enforcement_active field at all, so these `enforcement_active === "unknown"`
  // assertions FAIL against it, exactly the honesty carve-out required.

  it("reports a DEAD (error) agent as policy_protected but enforcement_active unknown", () => {
    const summary = toAgentSummary(makeRecord({ status: "error" }), "node-1");
    expect(summary.policy_protected).toBe(true);
    expect(summary.enforcement_active).toBe("unknown");
    expect(summary.protected).toBe(summary.policy_protected);
  });

  it("reports an UNKNOWN-status agent as policy_protected but enforcement_active unknown", () => {
    const summary = toAgentSummary(makeRecord({ status: "unknown" }), "node-1");
    expect(summary.policy_protected).toBe(true);
    expect(summary.enforcement_active).toBe("unknown");
    expect(summary.protected).toBe(summary.policy_protected);
  });

  it("never fabricates a live enforcement_active for an active agent (always unknown today)", () => {
    const summary = toAgentSummary(makeRecord({ status: "active" }), "node-1");
    expect(summary.policy_protected).toBe(true);
    // Honesty: presence in the roster is NOT proof of live enforcement.
    expect(summary.enforcement_active).toBe("unknown");
  });

  it("filters by harness", async () => {
    const deps = baseDeps({
      listAgents: () => [
        makeRecord({ agent_id: "a1", harness: "claude_code" }),
        makeRecord({ agent_id: "a2", harness: "openclaw" }),
      ],
    });
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq(),
      res,
      new URL("http://x/v1/agents?harness=openclaw"),
      "GET",
      CLAIMS,
    );
    const body = captured.body as { agents: Array<{ agent_id: string }> };
    expect(body.agents.map((a) => a.agent_id)).toEqual(["a2"]);
  });

  it("paginates with an opaque cursor and stable order", async () => {
    const deps = baseDeps({
      listAgents: () =>
        ["a3", "a1", "a2"].map((id) => makeRecord({ agent_id: id })),
    });
    const first = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq(),
      first.res,
      new URL("http://x/v1/agents?limit=2"),
      "GET",
      CLAIMS,
    );
    const firstBody = first.captured.body as {
      agents: Array<{ agent_id: string }>;
      next_cursor?: string;
    };
    expect(firstBody.agents.map((a) => a.agent_id)).toEqual(["a1", "a2"]);
    expect(firstBody.next_cursor).toBeDefined();

    const second = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq(),
      second.res,
      new URL(`http://x/v1/agents?limit=2&cursor=${firstBody.next_cursor}`),
      "GET",
      CLAIMS,
    );
    const secondBody = second.captured.body as {
      agents: Array<{ agent_id: string }>;
      next_cursor?: string;
    };
    expect(secondBody.agents.map((a) => a.agent_id)).toEqual(["a3"]);
    expect(secondBody.next_cursor).toBeUndefined();
  });

  it("returns an empty page for a non-local node_id (single-node in PR-A2)", async () => {
    const deps = baseDeps({
      nodeId: "node-1",
      listAgents: () => [makeRecord({ agent_id: "a1" })],
    });
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq(),
      res,
      new URL("http://x/v1/agents?node_id=other-node"),
      "GET",
      CLAIMS,
    );
    expect(captured.body).toEqual({ agents: [] });
  });
});

// ── POST /v1/agents/unprotect ───────────────────────────────────────────────

describe("POST /v1/agents/unprotect", () => {
  it("enqueues a Tier 1 unwrap for a validly-signed request", async () => {
    const op = makeOperator();
    let enqueued: string | null = null;
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      enqueueUnprotect: async (agentId): Promise<UnprotectOutcome> => {
        enqueued = agentId;
        return {
          ok: true,
          result: {
            agent_id: agentId,
            inbox_item_id: "tier1.unwrap.agent-x.abc",
            status: "approval_pending",
            operation_category: "unwrap",
          },
        };
      },
    });
    const payload = { agent_id: "agent-x", idempotency_key: "k1" };
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signUnprotect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/unprotect"),
      "POST",
      CLAIMS,
    );
    expect(enqueued).toBe("agent-x");
    // 202 Accepted: the Tier 1 unwrap is enqueued for approval, not done.
    expect(captured.status).toBe(202);
    expect(captured.body).toEqual({
      status: "approval_pending",
      agent_id: "agent-x",
      audit_event_id: "tier1.unwrap.agent-x.abc",
    });
  });

  it("denies an unsigned request with the generic 403 and never enqueues", async () => {
    const op = makeOperator();
    let called = false;
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      enqueueUnprotect: async () => {
        called = true;
        return { ok: false, reason: "unavailable" };
      },
    });
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ agent_id: "agent-x", idempotency_key: "k1" }),
      res,
      new URL("http://x/v1/agents/unprotect"),
      "POST",
      CLAIMS,
    );
    expect(called).toBe(false);
    expect(captured.status).toBe(403);
    expect(captured.body).toEqual({ error: "forbidden" });
  });

  it("denies a request signed by the WRONG key", async () => {
    const op = makeOperator();
    const attacker = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      enqueueUnprotect: async () => {
        throw new Error("must not be reached");
      },
    });
    const payload = { agent_id: "agent-x", idempotency_key: "k1" };
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signUnprotect(attacker.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/unprotect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(403);
    expect(captured.body).toEqual({ error: "forbidden" });
  });

  it("fails closed when no operator identity is configured (same 403, no oracle)", async () => {
    const op = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => null, // no operator identity
    });
    const payload = { agent_id: "agent-x", idempotency_key: "k1" };
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signUnprotect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/unprotect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(403);
    expect(captured.body).toEqual({ error: "forbidden" });
  });

  it("maps a not-found agent to 404 (only after a valid signature)", async () => {
    const op = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      enqueueUnprotect: async () => ({ ok: false, reason: "not_found" }),
    });
    const payload = { agent_id: "ghost", idempotency_key: "k1" };
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signUnprotect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/unprotect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(404);
    expect(captured.body).toEqual({ error: "not found" });
  });

  it("refuses unsupported unwrap before returning a Tier 1 approval handle", async () => {
    const op = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      enqueueUnprotect: async () => ({ ok: false, reason: "unsupported" }),
    });
    const payload = { agent_id: "agent-x", idempotency_key: "k1" };
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signUnprotect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/unprotect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(403);
    expect(captured.body).toEqual({ error: "forbidden" });
  });

  it("returns 503 when the hub is unbound", async () => {
    const op = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      enqueueUnprotect: async () => ({ ok: false, reason: "unavailable" }),
    });
    const payload = { agent_id: "agent-x", idempotency_key: "k1" };
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signUnprotect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/unprotect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(503);
  });

  it("is idempotent: a replayed signed request enqueues exactly once", async () => {
    const op = makeOperator();
    let enqueueCount = 0;
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      idempotency: new V1IdempotencyStore(),
      enqueueUnprotect: async (agentId): Promise<UnprotectOutcome> => {
        enqueueCount += 1;
        return {
          ok: true,
          result: {
            agent_id: agentId,
            inbox_item_id: `tier1.unwrap.${agentId}.${enqueueCount}`,
            status: "approval_pending",
            operation_category: "unwrap",
          },
        };
      },
    });
    const payload = { agent_id: "agent-x", idempotency_key: "same-key" };
    const sig = signUnprotect(op.privateKey, payload);
    const run = async () => {
      const { res, captured } = mockRes();
      await handleAgentsRequest(
        deps,
        mockReq({ ...payload, operator_signature: sig }),
        res,
        new URL("http://x/v1/agents/unprotect"),
        "POST",
        CLAIMS,
      );
      return captured;
    };
    const first = await run();
    const second = await run();
    expect(enqueueCount).toBe(1);
    expect(second.body).toEqual(first.body);
  });

  it("dedups across DIFFERENT sessions (retry that re-opens a session)", async () => {
    // Regression for the codex PR-A2 finding: a retry after token expiry
    // opens a fresh /v1 session with a NEW ephemeral client key. Keyed on
    // the session it would double-enqueue; keyed on the operator identity it
    // must still replay.
    const op = makeOperator();
    let enqueueCount = 0;
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      idempotency: new V1IdempotencyStore(),
      enqueueUnprotect: async (agentId): Promise<UnprotectOutcome> => {
        enqueueCount += 1;
        return {
          ok: true,
          result: {
            agent_id: agentId,
            inbox_item_id: `tier1.unwrap.${agentId}.${enqueueCount}`,
            status: "approval_pending",
            operation_category: "unwrap",
          },
        };
      },
    });
    const payload = { agent_id: "agent-x", idempotency_key: "retry-key" };
    const sig = signUnprotect(op.privateKey, payload);
    const runWith = async (clientPubkey: string) => {
      const { res, captured } = mockRes();
      await handleAgentsRequest(
        deps,
        mockReq({ ...payload, operator_signature: sig }),
        res,
        new URL("http://x/v1/agents/unprotect"),
        "POST",
        { ...CLAIMS, client_pubkey: clientPubkey },
      );
      return captured;
    };
    const first = await runWith("ephemeral-session-1");
    const second = await runWith("ephemeral-session-2");
    expect(enqueueCount).toBe(1);
    expect(second.body).toEqual(first.body);
  });

  it("coalesces CONCURRENT duplicate requests onto a single enqueue", async () => {
    // Regression for codex finding 2: two identical signed requests racing
    // both miss the durable cache; the in-flight reservation must collapse
    // them to one Tier 1 enqueue.
    const op = makeOperator();
    let enqueueCount = 0;
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      idempotency: new V1IdempotencyStore(),
      enqueueUnprotect: async (agentId): Promise<UnprotectOutcome> => {
        // Yield so both requests are in-flight before either resolves.
        await new Promise((r) => setTimeout(r, 5));
        enqueueCount += 1;
        return {
          ok: true,
          result: {
            agent_id: agentId,
            inbox_item_id: `tier1.unwrap.${agentId}.${enqueueCount}`,
            status: "approval_pending",
            operation_category: "unwrap",
          },
        };
      },
    });
    const payload = { agent_id: "agent-x", idempotency_key: "race-key" };
    const sig = signUnprotect(op.privateKey, payload);
    const fire = async () => {
      const { res, captured } = mockRes();
      await handleAgentsRequest(
        deps,
        mockReq({ ...payload, operator_signature: sig }),
        res,
        new URL("http://x/v1/agents/unprotect"),
        "POST",
        CLAIMS,
      );
      return captured;
    };
    const [a, b] = await Promise.all([fire(), fire()]);
    expect(enqueueCount).toBe(1);
    expect(a.status).toBe(202);
    expect(b.status).toBe(202);
    expect(a.body).toEqual(b.body);
  });

  it("rejects a missing agent_id with 400 before any auth work", async () => {
    const deps = baseDeps({ resolveOperatorPublicKey: () => makeOperator().publicKey });
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ idempotency_key: "k1", operator_signature: "x" }),
      res,
      new URL("http://x/v1/agents/unprotect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(400);
  });
});

// ── POST /v1/agents/protect (Phase S1: split-process supervised launch) ─────

describe("POST /v1/agents/protect", () => {
  function protectPayload(over?: Record<string, unknown>) {
    return {
      harness: "claude_code",
      agent_id: "agent-1",
      config_path: "/conf/a.json",
      idempotency_key: "k1",
      ...over,
    };
  }
  function signProtect(privateKey: Uint8Array, payload: Record<string, unknown>): string {
    return toBase64url(signOperatorPayload("/v1/agents/protect", payload, privateKey));
  }

  it("launches via the supervisor and returns 202 protecting for a signed request", async () => {
    const op = makeOperator();
    const calls: Array<{ agentId: string; harness: string; configPath: string }> = [];
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      launchProtect: async (spec) => {
        calls.push(spec);
        return { ok: true, status: "protecting", agent_id: spec.agentId, launch_id: "L1" };
      },
    });
    const payload = protectPayload();
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signProtect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/protect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(202);
    expect(captured.body).toEqual({ status: "protecting", agent_id: "agent-1", launch_id: "L1" });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ agentId: "agent-1", harness: "claude_code", configPath: "/conf/a.json" });
  });

  it("returns 200 no-op when the agent is already protected (resource-level idempotent)", async () => {
    const op = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      launchProtect: async (spec) => ({ ok: true, status: "protected", agent_id: spec.agentId }),
    });
    const payload = protectPayload();
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signProtect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/protect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(200);
    expect(captured.body).toEqual({ status: "protected", agent_id: "agent-1" });
  });

  it("collapses a rotation-in-progress refusal into the generic 403 (no oracle)", async () => {
    const op = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      launchProtect: async () => ({ ok: false, reason: "rotation_in_progress" }),
    });
    const payload = protectPayload();
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signProtect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/protect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(403);
    expect(captured.body).toEqual({ error: "forbidden" });
  });

  it("collapses a locked-fortress (forbidden) refusal into the generic 403", async () => {
    const op = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      launchProtect: async () => ({ ok: false, reason: "forbidden" }),
    });
    const payload = protectPayload();
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signProtect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/protect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(403);
    expect(captured.body).toEqual({ error: "forbidden" });
  });

  it("returns a retryable 503 when no supervisor is wired (fail-closed, NOT a 501 oracle)", async () => {
    const op = makeOperator();
    // No launchProtect dep ⇒ supervisor subsystem absent.
    const deps = baseDeps({ resolveOperatorPublicKey: () => op.publicKey });
    const payload = protectPayload();
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signProtect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/protect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(503);
    expect(captured.body).toEqual({ error: "unavailable" });
  });

  it("denies an unsigned protect with 403 (no execution oracle without a signature)", async () => {
    const op = makeOperator();
    let launched = false;
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      launchProtect: async () => {
        launched = true;
        return { ok: true, status: "protecting", agent_id: "a", launch_id: "L" };
      },
    });
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq(protectPayload()),
      res,
      new URL("http://x/v1/agents/protect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(403);
    expect(captured.body).toEqual({ error: "forbidden" });
    expect(launched).toBe(false); // never reaches execution
  });

  it("rejects a missing harness with 400", async () => {
    const deps = baseDeps({ resolveOperatorPublicKey: () => makeOperator().publicKey });
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ idempotency_key: "k1", operator_signature: "x" }),
      res,
      new URL("http://x/v1/agents/protect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(400);
  });

  it("rejects a missing config_path with 400 (after the signature verifies)", async () => {
    const op = makeOperator();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      launchProtect: async () => ({ ok: true, status: "protecting", agent_id: "a", launch_id: "L" }),
    });
    const payload = { harness: "claude_code", agent_id: "agent-1", idempotency_key: "k1" };
    const { res, captured } = mockRes();
    await handleAgentsRequest(
      deps,
      mockReq({ ...payload, operator_signature: signProtect(op.privateKey, payload) }),
      res,
      new URL("http://x/v1/agents/protect"),
      "POST",
      CLAIMS,
    );
    expect(captured.status).toBe(400);
  });

  it("replays a retried protect from the idempotency cache — launches EXACTLY once (M2)", async () => {
    const op = makeOperator();
    let launchCount = 0;
    const store = new V1IdempotencyStore();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      idempotency: store,
      launchProtect: async (spec) => {
        launchCount++;
        return { ok: true, status: "protecting", agent_id: spec.agentId, launch_id: `L${launchCount}` };
      },
    });
    const payload = protectPayload();
    const sig = signProtect(op.privateKey, payload);
    const run = async () => {
      const { res, captured } = mockRes();
      await handleAgentsRequest(
        deps,
        mockReq({ ...payload, operator_signature: sig }),
        res,
        new URL("http://x/v1/agents/protect"),
        "POST",
        CLAIMS,
      );
      return captured;
    };
    const first = await run();
    const second = await run();
    expect(launchCount).toBe(1); // double-click does NOT double-launch
    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    expect(second.body).toEqual(first.body); // same launch_id replayed
  });

  it("coalesces CONCURRENT duplicate protects onto one launch (M2 race)", async () => {
    const op = makeOperator();
    let launchCount = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const store = new V1IdempotencyStore();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      idempotency: store,
      launchProtect: async (spec) => {
        launchCount++;
        await gate; // hold the first launch in-flight
        return { ok: true, status: "protecting", agent_id: spec.agentId, launch_id: "L1" };
      },
    });
    const payload = protectPayload();
    const sig = signProtect(op.privateKey, payload);
    const fire = () => {
      const { res, captured } = mockRes();
      return handleAgentsRequest(
        deps,
        mockReq({ ...payload, operator_signature: sig }),
        res,
        new URL("http://x/v1/agents/protect"),
        "POST",
        CLAIMS,
      ).then(() => captured);
    };
    const p1 = fire();
    const p2 = fire();
    await Promise.resolve();
    release();
    const [c1, c2] = await Promise.all([p1, p2]);
    expect(launchCount).toBe(1); // concurrent duplicates coalesce
    expect(c1.status).toBe(202);
    expect(c2.status).toBe(202);
  });

  it("does NOT cache a transient unavailable launch failure (retryable)", async () => {
    const op = makeOperator();
    let attempts = 0;
    const store = new V1IdempotencyStore();
    const deps = baseDeps({
      resolveOperatorPublicKey: () => op.publicKey,
      idempotency: store,
      launchProtect: async (spec) => {
        attempts++;
        if (attempts === 1) return { ok: false, reason: "unavailable" };
        return { ok: true, status: "protecting", agent_id: spec.agentId, launch_id: "L2" };
      },
    });
    const payload = protectPayload();
    const sig = signProtect(op.privateKey, payload);
    const run = async () => {
      const { res, captured } = mockRes();
      await handleAgentsRequest(
        deps,
        mockReq({ ...payload, operator_signature: sig }),
        res,
        new URL("http://x/v1/agents/protect"),
        "POST",
        CLAIMS,
      );
      return captured;
    };
    const first = await run();
    const second = await run();
    expect(first.status).toBe(503); // transient failure
    expect(second.status).toBe(202); // retry is not blocked by a cached failure
    expect(attempts).toBe(2);
  });
});

// ── idempotency store ───────────────────────────────────────────────────────

describe("V1IdempotencyStore", () => {
  it("returns a stored record for the same composite key", () => {
    const store = new V1IdempotencyStore();
    store.set("key-a", 0, { status: 200, body: { a: 1 } });
    expect(store.get("key-b", 0)).toBeUndefined();
    expect(store.get("key-a", 0)?.body).toEqual({ a: 1 });
  });

  it("expires records past the TTL", () => {
    const store = new V1IdempotencyStore({ ttlMs: 1000 });
    store.set("k", 0, { status: 200, body: 1 });
    expect(store.get("k", 999)).toBeDefined();
    expect(store.get("k", 1001)).toBeUndefined();
  });

  it("evicts the oldest entry past the bound", () => {
    const store = new V1IdempotencyStore({ maxEntries: 2 });
    store.set("k1", 0, { status: 200, body: 1 });
    store.set("k2", 0, { status: 200, body: 2 });
    store.set("k3", 0, { status: 200, body: 3 });
    expect(store.get("k1", 0)).toBeUndefined();
    expect(store.get("k2", 0)).toBeDefined();
    expect(store.get("k3", 0)).toBeDefined();
  });
});

describe("idempotencyKeyFor", () => {
  it("is session-independent: stable for the same operator/action/key/payload", () => {
    const op = makeOperator();
    const payload = { agent_id: "a", idempotency_key: "k" };
    const k1 = idempotencyKeyFor(op.publicKey, "/v1/agents/unprotect", "k", payload);
    const k2 = idempotencyKeyFor(op.publicKey, "/v1/agents/unprotect", "k", payload);
    expect(k1).toBe(k2);
  });

  it("differs when the signed payload differs (no wrong replay on key reuse)", () => {
    const op = makeOperator();
    const k1 = idempotencyKeyFor(op.publicKey, "/v1/agents/unprotect", "k", { agent_id: "a", idempotency_key: "k" });
    const k2 = idempotencyKeyFor(op.publicKey, "/v1/agents/unprotect", "k", { agent_id: "b", idempotency_key: "k" });
    expect(k1).not.toBe(k2);
  });
});
