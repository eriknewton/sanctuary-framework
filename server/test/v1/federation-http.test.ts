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
import { generateKeypair } from "../../src/core/identity.js";
import { issueGuardianRoster } from "../../src/mesh/guardian/guardian-roster.js";
import type { GuardianIdentity } from "../../src/mesh/guardian/types.js";
import {
  buildApprovalSigningInput,
  signApproval,
  type GuardianApproval,
} from "../../src/recovery/index.js";
import {
  revocationCascadeId,
  GUARDIAN_SIGN_OFF_ACTION,
} from "../../src/v1/federation-revocation-guardian-gate.js";

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

// retry:2 - loopback /v1 federation rig races port/session setup under full-
// suite parallel load (recurring non-hermetic CI flake class).
describe("/v1/federation perimeter + session gating", { retry: 2 }, () => {
  it("denies every federation path to unauthenticated callers with the uniform 401", async () => {
    const probes: Array<[string, string]> = [
      ["GET", "/v1/federation/status"],
      ["POST", "/v1/federation/enable"],
      ["POST", "/v1/federation/disable"],
      ["POST", "/v1/federation/authorize/init"],
      ["POST", "/v1/federation/revoke"],
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

// retry:2 - loopback /v1 federation rig; same non-hermetic flake class.
describe("/v1/federation enable/disable — OPERATOR_SIGNED", { retry: 2 }, () => {
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

  it("denies revoke without an operator signature (generic 403)", async () => {
    const token = await openDurableSession(rig);
    const res = await fetch(`${rig.baseUrl}/v1/federation/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ node_id: "edge-node-1", reason: "operator_removed" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    expect(await auditOps()).toContainEqual({ operation: "v1_federation_revoke", result: "failure" });
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

// retry:2 - loopback /v1 federation rig; same non-hermetic flake class.
describe("/v1/federation join ceremony end-to-end over HTTP", { retry: 2 }, () => {
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

  it("surfaces operator-cloud node mode and trust-boundary disclosure additively", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);

    const initBody = operatorSigned("/v1/federation/authorize/init", {
      intended_node_id: "cloud-node-1",
      intended_node_mode: "operator_cloud",
    });
    const initRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(initBody),
    });
    expect(initRes.status).toBe(200);
    const { bootstrap_token } = (await initRes.json()) as { bootstrap_token: BootstrapToken };
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

    const nodesRes = await fetch(`${rig.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(nodesRes.status).toBe(200);
    const nodesBody = (await nodesRes.json()) as { nodes: Array<Record<string, any>> };
    expect(nodesBody.nodes).toHaveLength(1);
    expect(nodesBody.nodes[0]).toEqual(
      expect.objectContaining({
        node_id: "cloud-node-1",
        node_mode: "operator_cloud",
        host_provider: "provider",
        tee_attested: false,
        disclosure_acknowledged_at: null,
        drill_status: "unproven",
      }),
    );
    expect(nodesBody.nodes[0].trust_boundary).toEqual(
      expect.objectContaining({
        version: "operator-cloud-trust-boundary-v1",
        label: "provider in trust boundary, not TEE",
        provider_in_trust_boundary: true,
        tee_attested: false,
      }),
    );

    const fedStatusRes = await fetch(`${rig.baseUrl}/v1/federation/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const fedStatus = (await fedStatusRes.json()) as Record<string, any>;
    expect(fedStatus).toEqual(
      expect.objectContaining({
        enabled: true,
        provisioned: true,
        operator_cloud_nodes: 1,
        provider_in_trust_boundary: true,
        tee_attested: false,
      }),
    );
    expect(fedStatus.trust_boundary.disclosure).toContain("provider is in this node's trust boundary");

    const v1StatusRes = await fetch(`${rig.baseUrl}/v1/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const v1Status = (await v1StatusRes.json()) as Record<string, any>;
    expect(v1Status.federation).toEqual(
      expect.objectContaining({
        roster_size: 1,
        operator_cloud_nodes: 1,
        provider_in_trust_boundary: true,
        tee_attested: false,
      }),
    );
  });

  it("rejects operator-cloud join requests that self-report TEE attestation", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);
    const initRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/authorize/init", {
          intended_node_id: "cloud-node-fake-tee",
          intended_node_mode: "operator_cloud",
        }),
      ),
    });
    const { bootstrap_token } = (await initRes.json()) as { bootstrap_token: BootstrapToken };
    const assembled = assembleJoinRequest({
      bootstrapToken: bootstrap_token,
      fortressMasterSecret: materials.masterSecret,
    });
    const res = await fetch(`${rig.baseUrl}/v1/federation/authorize/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...assembled.joinRequest,
        attestation: "fake-self-report",
      }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
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

  it("revoke emits a durable operator-authority eviction and future joins fail closed", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);

    const initRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/authorize/init", {
          intended_node_id: "edge-node-1",
          intended_node_mode: "local",
        }),
      ),
    });
    expect(initRes.status).toBe(200);
    const { bootstrap_token } = (await initRes.json()) as { bootstrap_token: BootstrapToken };
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

    const revokeRes = await fetch(`${rig.baseUrl}/v1/federation/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/revoke", {
          node_id: "edge-node-1",
          reason: "operator_removed",
        }),
      ),
    });
    expect(revokeRes.status).toBe(200);
    expect(await revokeRes.json()).toEqual({
      revoked: true,
      node_id: "edge-node-1",
      event_id: expect.any(String),
      eviction_serial: 1,
    });
    expect(materials.context.isNodeRevoked("edge-node-1")).toBe(true);

    const reauthRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/authorize/init", {
          intended_node_id: "edge-node-1",
          intended_node_mode: "local",
        }),
      ),
    });
    expect(reauthRes.status).toBe(200);
    const { bootstrap_token: retryToken } = (await reauthRes.json()) as {
      bootstrap_token: BootstrapToken;
    };
    const retry = assembleJoinRequest({
      bootstrapToken: retryToken,
      fortressMasterSecret: materials.masterSecret,
    });
    const retryCompleteRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(retry.joinRequest),
    });
    expect(retryCompleteRes.status).toBe(401);
    expect(await retryCompleteRes.json()).toEqual({ error: "unauthorized" });

    const ops = await auditOps();
    expect(ops).toContainEqual({ operation: "v1_federation_revoke", result: "success" });
    expect(ops).toContainEqual({
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

// retry:2 - same loopback /v1 rig flake class as the perimeter suites above.
describe("/v1/federation/revoke: optional M-of-N guardian sign-off", { retry: 2 }, () => {
  async function enableFederation(token: string) {
    const res = await fetch(`${rig.baseUrl}/v1/federation/enable`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(operatorSigned("/v1/federation/enable", { idempotency_key: "k1" })),
    });
    expect(res.status).toBe(200);
  }

  function buildGuardians(count: number): Array<{
    identity: GuardianIdentity;
    kp: ReturnType<typeof generateKeypair>;
  }> {
    const out: Array<{
      identity: GuardianIdentity;
      kp: ReturnType<typeof generateKeypair>;
    }> = [];
    for (let i = 0; i < count; i++) {
      const kp = generateKeypair();
      out.push({
        identity: {
          guardian_id: `guardian-${i}`,
          public_key: toBase64url(kp.publicKey),
          kind: "human",
          invited_at: new Date().toISOString(),
        },
        kp,
      });
    }
    return out;
  }

  function signApprovals(
    guardians: Array<{
      identity: GuardianIdentity;
      kp: ReturnType<typeof generateKeypair>;
    }>,
    count: number,
    nodeId: string,
    rosterVersion: number,
  ): GuardianApproval[] {
    const cascadeId = revocationCascadeId(materials.fortressId, nodeId);
    const signingInput = buildApprovalSigningInput({
      cascade_id: cascadeId,
      recovery_action: GUARDIAN_SIGN_OFF_ACTION,
      fortress_id: materials.fortressId,
      roster_version: rosterVersion,
    });
    return guardians.slice(0, count).map((g) =>
      signApproval({
        signing_input: signingInput,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.kp.privateKey,
        recovery_action: GUARDIAN_SIGN_OFF_ACTION,
        cascade_id: cascadeId,
      }),
    );
  }

  async function joinNode(token: string, nodeId: string): Promise<void> {
    const initRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/authorize/init", {
          intended_node_id: nodeId,
          intended_node_mode: "local",
        }),
      ),
    });
    expect(initRes.status).toBe(200);
    const { bootstrap_token } = (await initRes.json()) as { bootstrap_token: BootstrapToken };
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
  }

  it("default-off: revoke succeeds with no guardian approvals (legacy path unchanged)", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);
    await joinNode(token, "edge-default-off");

    // No requirement configured (the default). Revoke with NO guardian field.
    const res = await fetch(`${rig.baseUrl}/v1/federation/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/revoke", {
          node_id: "edge-default-off",
          reason: "operator_removed",
        }),
      ),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ revoked: true, node_id: "edge-default-off" });
    expect(materials.context.isNodeRevoked("edge-default-off")).toBe(true);
  });

  it("enabled + exactly-threshold valid quorum: revoke is accepted", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);
    await joinNode(token, "edge-quorum-ok");

    const guardians = buildGuardians(5);
    const roster = issueGuardianRoster({
      m: 3,
      n: 5,
      guardians: guardians.map((g) => g.identity),
      fortress_id: materials.fortressId,
      version: 1,
      master_private_key: materials.masterSecret,
    });
    rig.dashboard.setFederationGuardianRevocationRequirement({ roster });

    const approvals = signApprovals(guardians, 3, "edge-quorum-ok", roster.version);
    const res = await fetch(`${rig.baseUrl}/v1/federation/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        ...operatorSigned("/v1/federation/revoke", {
          node_id: "edge-quorum-ok",
          reason: "operator_removed",
        }),
        guardian_approvals: approvals,
      }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ revoked: true, node_id: "edge-quorum-ok" });
    expect(materials.context.isNodeRevoked("edge-quorum-ok")).toBe(true);
  });

  it("enabled + under-threshold quorum: revoke is REFUSED (403, fail-closed)", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);
    await joinNode(token, "edge-under-threshold");

    const guardians = buildGuardians(5);
    const roster = issueGuardianRoster({
      m: 3,
      n: 5,
      guardians: guardians.map((g) => g.identity),
      fortress_id: materials.fortressId,
      version: 1,
      master_private_key: materials.masterSecret,
    });
    rig.dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Only 2 valid approvals against an M=3 roster.
    const approvals = signApprovals(guardians, 2, "edge-under-threshold", roster.version);
    const res = await fetch(`${rig.baseUrl}/v1/federation/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        ...operatorSigned("/v1/federation/revoke", {
          node_id: "edge-under-threshold",
          reason: "operator_removed",
        }),
        guardian_approvals: approvals,
      }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    // Fail-closed: the node was NOT revoked.
    expect(materials.context.isNodeRevoked("edge-under-threshold")).toBe(false);
    expect(await auditOps()).toContainEqual({
      operation: "v1_federation_revoke",
      result: "failure",
    });
  });

  it("enabled + missing guardian approvals: revoke is REFUSED (403)", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);
    await joinNode(token, "edge-no-approvals");

    const guardians = buildGuardians(5);
    const roster = issueGuardianRoster({
      m: 3,
      n: 5,
      guardians: guardians.map((g) => g.identity),
      fortress_id: materials.fortressId,
      version: 1,
      master_private_key: materials.masterSecret,
    });
    rig.dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Requirement is on but the operator omits the guardian_approvals field.
    const res = await fetch(`${rig.baseUrl}/v1/federation/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(
        operatorSigned("/v1/federation/revoke", {
          node_id: "edge-no-approvals",
          reason: "operator_removed",
        }),
      ),
    });
    expect(res.status).toBe(403);
    expect(materials.context.isNodeRevoked("edge-no-approvals")).toBe(false);
  });
});
