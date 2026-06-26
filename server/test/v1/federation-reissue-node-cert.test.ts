/**
 * Federation 3c-2: pre-session node-cert reissue after signing-master rotation.
 *
 * A joiner that still holds a K1-issued node cert may adopt the current K2 root
 * only by proving possession of the old node key over a server-issued challenge,
 * presenting the old cert chain, and presenting the K1->K2 rotation cert.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  signFederationRootRotationCertificate,
  verifyCertChain,
} from "../../src/mesh/trust-root.js";
import { createAutoApproveJoinApprover, generateNodeKeypair } from "../../src/mesh/lifecycle/join-approver.js";
import type {
  FederationRootRotationCertificate,
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../src/mesh/types.js";
import { signOperatorPayload } from "../../src/v1/operator-signed.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  buildFederationReissueNodeCertProofMessage,
  FEDERATION_REISSUE_NODE_CERT_REQUEST_VERSION,
  type FederationIssuerContext,
} from "../../src/v1/federation.js";
import { OPERATOR, openDurableSession, startRig, type TestRig } from "./rig.js";

interface ReissueMaterials {
  fortressId: string;
  k2Public: FortressMasterPublicKey;
  context: FederationIssuerContext;
  nodeId: string;
  currentNodeCert: NodeIdentityCertificate;
  currentIssuingPrincipalCert: PrincipalCertificate;
  rotationCert: FederationRootRotationCertificate;
  nodePrivateKey: Uint8Array;
}

let rig: TestRig;
let materials: ReissueMaterials;

beforeEach(async () => {
  rig = await startRig({ withOperatorIdentity: true });
  materials = makeReissueMaterials();
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

async function enableFederation(): Promise<void> {
  const token = await openDurableSession(rig);
  const res = await fetch(`${rig.baseUrl}/v1/federation/enable`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(operatorSigned("/v1/federation/enable", { idempotency_key: "k1" })),
  });
  expect(res.status).toBe(200);
}

async function issueChallenge(): Promise<{ challenge_id: string; challenge: string }> {
  const res = await fetch(`${rig.baseUrl}/v1/federation/rotate/reissue-node-cert`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "challenge", node_id: materials.nodeId }),
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    request_version: string;
    challenge_id: string;
    challenge: string;
    expires_at: string;
  };
  expect(body.request_version).toBe(FEDERATION_REISSUE_NODE_CERT_REQUEST_VERSION);
  expect(body.challenge_id).toMatch(/[0-9a-f-]{36}/);
  expect(body.challenge.length).toBeGreaterThan(20);
  return { challenge_id: body.challenge_id, challenge: body.challenge };
}

function signedCompleteBody(
  challenge: { challenge_id: string; challenge: string },
  rotationCert = materials.rotationCert,
): Record<string, unknown> {
  const message = buildFederationReissueNodeCertProofMessage({
    fortressId: materials.fortressId,
    nodeId: materials.nodeId,
    challengeId: challenge.challenge_id,
    challenge: challenge.challenge,
    currentNodeCert: materials.currentNodeCert,
    currentIssuingPrincipalCert: materials.currentIssuingPrincipalCert,
    rotationCert,
  });
  return {
    action: "complete",
    node_id: materials.nodeId,
    challenge_id: challenge.challenge_id,
    challenge: challenge.challenge,
    current_node_cert: materials.currentNodeCert,
    current_issuing_principal_cert: materials.currentIssuingPrincipalCert,
    rotation_cert: rotationCert,
    node_signature: toBase64url(ed25519.sign(message, materials.nodePrivateKey)),
  };
}

async function completeReissue(body: Record<string, unknown>): Promise<Response> {
  return fetch(`${rig.baseUrl}/v1/federation/rotate/reissue-node-cert`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// retry:2 - loopback /v1 rigs can race random local ports under full-suite load.
describe("/v1/federation/rotate/reissue-node-cert", { retry: 2 }, () => {
  it("returns a same-shaped challenge while disabled, then fails closed on completion", async () => {
    const challenge = await issueChallenge();

    const res = await completeReissue(signedCompleteBody(challenge));
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });

  it("reissues a K2-chained node cert after challenge POP against the old K1 cert", async () => {
    await enableFederation();
    const challenge = await issueChallenge();

    const res = await completeReissue(signedCompleteBody(challenge));
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      reissued: boolean;
      request_version: string;
      node_id: string;
      certificate: NodeIdentityCertificate;
      issuing_principal_cert: PrincipalCertificate;
      pinned_master: FortressMasterPublicKey;
    };
    expect(body.reissued).toBe(true);
    expect(body.request_version).toBe(FEDERATION_REISSUE_NODE_CERT_REQUEST_VERSION);
    expect(body.node_id).toBe(materials.nodeId);
    expect(body.certificate.node_pubkey).toBe(materials.currentNodeCert.node_pubkey);
    expect(body.certificate.parent_chain.fortress_master_pubkey).toBe(
      materials.k2Public.public_key,
    );
    verifyCertChain(body.certificate, body.issuing_principal_cert, body.pinned_master);
  });

  it("rejects replay of an already-consumed challenge", async () => {
    await enableFederation();
    const challenge = await issueChallenge();
    const body = signedCompleteBody(challenge);
    expect((await completeReissue(body)).status).toBe(200);

    const replay = await completeReissue(body);
    expect(replay.status).toBe(403);
    expect(await replay.json()).toEqual({ error: "forbidden" });
  });

  it("denies a node that becomes revoked before completion", async () => {
    await enableFederation();
    const challenge = await issueChallenge();
    const dashboardState = (rig.dashboard as unknown as {
      _federationState: { revoked: Set<string> };
    })._federationState;
    dashboardState.revoked.add(materials.nodeId);

    const res = await completeReissue(signedCompleteBody(challenge));
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });

  it("fails closed on a hybrid rotation cert instead of verifying only the classical half", async () => {
    await enableFederation();
    const challenge = await issueChallenge();
    const hybridRotationCert = {
      ...materials.rotationCert,
      hybrid_rotation: { present: true },
    } as unknown as FederationRootRotationCertificate;

    const res = await completeReissue(signedCompleteBody(challenge, hybridRotationCert));
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });
});

function makeReissueMaterials(): ReissueMaterials {
  const k1 = generateFortressMaster();
  const k2 = generateFortressMaster();
  const fortressId = k1.public.fortress_id;
  const k2Public: FortressMasterPublicKey = {
    ...k2.public,
    fortress_id: fortressId,
  };

  const oldPrincipalPrivate = randomBytes(32);
  const oldPrincipalPublic = ed25519.getPublicKey(oldPrincipalPrivate);
  const oldPrincipalCert = issuePrincipalCertificate({
    principal_id: "principal-k1",
    principal_pubkey: oldPrincipalPublic,
    role: "root",
    fortress_id: fortressId,
    master_private_key: k1.private_key,
  });

  const newPrincipalPrivate = randomBytes(32);
  const newPrincipalPublic = ed25519.getPublicKey(newPrincipalPrivate);
  const newPrincipalCert = issuePrincipalCertificate({
    principal_id: "principal-k2",
    principal_pubkey: newPrincipalPublic,
    role: "root",
    fortress_id: fortressId,
    master_private_key: k2.private_key,
  });

  const { publicKey: nodePublicKey, privateKey: nodePrivateKey } =
    generateNodeKeypair();
  const nodeId = "joiner-k1-node";
  const currentNodeCert = issueNodeIdentityCertificate({
    node_id: nodeId,
    node_pubkey: nodePublicKey,
    node_mode: "local",
    fortress_id: fortressId,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: k1.public.public_key,
      principal_id: oldPrincipalCert.principal_id,
      principal_pubkey: oldPrincipalCert.principal_pubkey,
    },
    principal_private_key: oldPrincipalPrivate,
    master_private_key: k1.private_key,
  });

  const rotationCert = signFederationRootRotationCertificate({
    fortress_id: fortressId,
    old_master_pubkey: k1.public.public_key,
    new_master: k2Public,
    old_master_private_key: k1.private_key,
    rotation_serial: 1,
    rotated_at: "2026-06-26T00:00:00.000Z",
  });
  const masterSecret = randomBytes(32);
  const context: FederationIssuerContext = {
    fortressId,
    nodeId: "home-k2-node",
    nodeMode: "local",
    pinnedMasterPubkey: k2Public,
    issuingPrincipalCert: newPrincipalCert,
    getIssuingPrincipalPrivateKey: () => newPrincipalPrivate,
    getFortressMasterSecret: () => masterSecret,
    getMasterPrivateKey: () => k2.private_key,
    isNodeRevoked: () => false,
    approver: createAutoApproveJoinApprover({
      pinned_master_pubkey: k2Public,
      issuing_principal_cert: newPrincipalCert,
      issuing_principal_private_key: newPrincipalPrivate,
      master_private_key: k2.private_key,
    }),
  };

  return {
    fortressId,
    k2Public,
    context,
    nodeId,
    currentNodeCert,
    currentIssuingPrincipalCert: oldPrincipalCert,
    rotationCert,
    nodePrivateKey,
  };
}
