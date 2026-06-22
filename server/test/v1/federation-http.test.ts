/**
 * Federation PR-A3 — /v1/federation endpoints over real HTTP.
 *
 * Proves, through the REAL DashboardApprovalChannel:
 *   - session-gating + the uniform 401 perimeter on every federation path;
 *   - enable/disable are OPERATOR_SIGNED (unsigned → generic 403);
 *   - the end-to-end join ceremony: operator mints a bootstrap token via
 *     authorize/init, a joining node submits a JoinRequest to authorize/
 *     complete and receives a chain-valid certificate (happy path), and an
 *     unverifiable peer is denied with the uniform 401 (fail closed);
 *   - every ceremony step writes an audit entry on success AND denial
 *     (design note 5 audit-write-completeness).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { signOperatorPayload } from "../../src/v1/operator-signed.js";
import { verifyCertChain } from "../../src/mesh/trust-root.js";
import type { BootstrapToken, NodeIdentityCertificate, PrincipalCertificate } from "../../src/mesh/types.js";
import { toBase64url } from "../../src/core/encoding.js";
import { OPERATOR, startRig, openDurableSession, type TestRig } from "./rig.js";
import { makeFederationMaterials, assembleJoinRequest, type FedMaterials } from "./fed-materials.js";

let rig: TestRig;
let materials: FedMaterials;

beforeEach(async () => {
  rig = await startRig({ withOperatorIdentity: true });
  materials = makeFederationMaterials();
  rig.dashboard.setFederationContext(materials.context);
});
afterEach(async () => {
  await rig.stop();
});

function operatorSigned(action: string, payload: Record<string, unknown>) {
  return {
    ...payload,
    operator_signature: toBase64url(signOperatorPayload(action, payload, OPERATOR.privateKey)),
  };
}

async function auditOps(): Promise<Array<{ operation: string; result: string }>> {
  const { entries } = await rig.auditLog.query({ layer: "l2", limit: 1000 });
  return entries
    .filter((e) => e.operation.startsWith("v1_federation_"))
    .map((e) => ({ operation: e.operation, result: e.result }));
}

describe("/v1/federation perimeter + session gating", () => {
  it("denies every federation path to unauthenticated callers with the uniform 401", async () => {
    const probes: Array<[string, string]> = [
      ["GET", "/v1/federation/status"],
      ["POST", "/v1/federation/enable"],
      ["POST", "/v1/federation/disable"],
      ["POST", "/v1/federation/authorize/init"],
    ];
    for (const [method, path] of probes) {
      const res = await fetch(`${rig.baseUrl}${path}`, { method });
      expect(res.status, `${method} ${path}`).toBe(401);
      expect(await res.json(), `${method} ${path}`).toEqual({ error: "unauthorized" });
    }
  });

  it("serves GET /v1/federation/status to an authenticated session", async () => {
    const token = await openDurableSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/federation/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.provisioned).toBe(true);
    expect(body.enabled).toBe(false); // not enabled yet
    expect(body.fortress_id).toBe(materials.fortressId);
    expect(body.roster).toEqual({ size: 0 });
  });
});

describe("/v1/federation enable/disable — OPERATOR_SIGNED", () => {
  it("denies enable without an operator signature (generic 403)", async () => {
    const token = await openDurableSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/federation/enable`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ idempotency_key: "k1" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    expect(await auditOps()).toContainEqual({ operation: "v1_federation_enable", result: "failure" });
  });

  it("enables with a valid operator signature, and status reflects it", async () => {
    const token = await openDurableSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/federation/enable`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(operatorSigned("/v1/federation/enable", { idempotency_key: "k1" })),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ enabled: true });

    const statusRes = await fetch(`${rig.baseUrl}/v1/federation/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(((await statusRes.json()) as Record<string, unknown>).enabled).toBe(true);
    expect(await auditOps()).toContainEqual({ operation: "v1_federation_enable", result: "success" });
  });

  it("disable is honored and audited", async () => {
    const token = await openDurableSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/federation/disable`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(operatorSigned("/v1/federation/disable", { idempotency_key: "k1" })),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ enabled: false });
    expect(await auditOps()).toContainEqual({ operation: "v1_federation_disable", result: "success" });
  });
});

describe("/v1/federation join ceremony end-to-end over HTTP", () => {
  async function enableFederation(token: string) {
    const res = await fetch(`${rig.baseUrl}/v1/federation/enable`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(operatorSigned("/v1/federation/enable", { idempotency_key: "k1" })),
    });
    expect(res.status).toBe(200);
  }

  it("authorize/init mints a token; authorize/complete issues a chain-valid certificate", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);

    // 1. Operator authorizes a node to join → bootstrap token.
    const initBody = operatorSigned("/v1/federation/authorize/init", {
      intended_node_id: "edge-node-1",
      intended_node_mode: "local",
    });
    const initRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(initBody),
    });
    expect(initRes.status).toBe(200);
    const { bootstrap_token } = (await initRes.json()) as { bootstrap_token: BootstrapToken };
    expect(bootstrap_token.intended_node_id).toBe("edge-node-1");

    // 2. Joining node assembles a JoinRequest (using the out-of-band master
    //    secret) and submits it WITHOUT any /v1 session — bootstrap-token auth.
    const assembled = assembleJoinRequest({
      bootstrapToken: bootstrap_token,
      fortressMasterSecret: materials.masterSecret,
    });
    const completeRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(assembled.joinRequest),
    });
    expect(completeRes.status).toBe(200);
    const body = (await completeRes.json()) as {
      certificate: NodeIdentityCertificate;
      issuing_principal_cert: PrincipalCertificate;
    };
    expect(body.certificate.node_id).toBe("edge-node-1");
    expect(() =>
      verifyCertChain(body.certificate, body.issuing_principal_cert, materials.context.pinnedMasterPubkey),
    ).not.toThrow();

    // 3. Roster reflects the join; audit recorded both ceremony steps.
    const statusRes = await fetch(`${rig.baseUrl}/v1/federation/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(((await statusRes.json()) as { roster: { size: number } }).roster.size).toBe(1);
    const ops = await auditOps();
    expect(ops).toContainEqual({ operation: "v1_federation_authorize_init", result: "success" });
    expect(ops).toContainEqual({ operation: "v1_federation_authorize_complete", result: "success" });
  });

  it("denies an unverifiable JoinRequest with the uniform 401 and audits the denial", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);
    const initRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/authorize/init", {
          intended_node_id: "edge-node-2",
          intended_node_mode: "local",
        }),
      ),
    });
    const { bootstrap_token } = (await initRes.json()) as { bootstrap_token: BootstrapToken };

    // Joining node lacks the real master secret → bad HKDF proof → denied.
    const assembled = assembleJoinRequest({
      bootstrapToken: bootstrap_token,
      fortressMasterSecret: new Uint8Array(32),
    });
    const res = await fetch(`${rig.baseUrl}/v1/federation/authorize/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(assembled.joinRequest),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect(await auditOps()).toContainEqual({
      operation: "v1_federation_authorize_complete",
      result: "failure",
    });
  });

  it("denies a revoked node at authorize/complete through the HTTP ceremony path", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);
    const initRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/authorize/init", {
          intended_node_id: "revoked-edge-node",
          intended_node_mode: "local",
        }),
      ),
    });
    expect(initRes.status).toBe(200);
    const { bootstrap_token } = (await initRes.json()) as { bootstrap_token: BootstrapToken };
    materials.context.isNodeRevoked = (nodeId) => nodeId === "revoked-edge-node";

    const assembled = assembleJoinRequest({
      bootstrapToken: bootstrap_token,
      fortressMasterSecret: materials.masterSecret,
    });
    const res = await fetch(`${rig.baseUrl}/v1/federation/authorize/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(assembled.joinRequest),
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    const statusRes = await fetch(`${rig.baseUrl}/v1/federation/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(((await statusRes.json()) as { roster: { size: number } }).roster.size).toBe(0);
    expect(await auditOps()).toContainEqual({
      operation: "v1_federation_authorize_complete",
      result: "failure",
    });
  });

  it("authorize/complete denies when federation is disabled (uniform 401, no oracle)", async () => {
    // Federation provisioned but NOT enabled: a probing joiner gets the same
    // 401 as a bad token — no signal that federation exists here.
    const res = await fetch(`${rig.baseUrl}/v1/federation/authorize/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        bootstrap_token: { intended_node_id: "x", issuing_principal: "p", signature: "s" },
        node_pubkey: "AAAA",
        node_mode: "local",
        hkdf_salt_proof: "AAAA",
      }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });
});
