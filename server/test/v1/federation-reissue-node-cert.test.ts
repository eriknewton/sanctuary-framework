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
import {
  addOperatorAuthorizationFields,
  signOperatorPayload,
} from "../../src/v1/operator-signed.js";
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
  /** Genuine predecessor (K1) private key, for forging higher-serial lineage in tests. */
  k1PrivateKey: Uint8Array;
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
  const signedPayload = addOperatorAuthorizationFields(payload);
  return {
    ...signedPayload,
    operator_signature: toBase64url(
      signOperatorPayload(action, signedPayload, OPERATOR.privateKey),
    ),
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
  expect(String((body as unknown as { request_id?: unknown }).request_id)).toMatch(
    UUID_RE,
  );
  return { challenge_id: body.challenge_id, challenge: body.challenge };
}

/** POST the challenge action and hand back the RAW body, decoy or real. */
async function rawChallengeBody(
  nodeId = materials.nodeId,
): Promise<Record<string, unknown>> {
  const res = await fetch(`${rig.baseUrl}/v1/federation/rotate/reissue-node-cert`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "challenge", node_id: nodeId }),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

/** Every issuer audit entry for this route, newest last. */
async function reissueAuditEntries(): Promise<
  { operation: string; result: string; details?: Record<string, unknown> }[]
> {
  const { entries } = await rig.auditLog.query({ limit: Number.MAX_SAFE_INTEGER });
  return entries.filter((entry) =>
    entry.operation.startsWith("v1_federation_reissue_node_cert"),
  );
}

/** The single audit entry the caller's `request_id` resolves to. */
async function auditEntryForRequestId(
  requestId: string,
): Promise<{ operation: string; result: string; details?: Record<string, unknown> }> {
  const matches = (await reissueAuditEntries()).filter(
    (entry) => entry.details?.request_id === requestId,
  );
  expect(matches).toHaveLength(1);
  return matches[0]!;
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

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * THE denial-shape assertion for this route. Every refusal, whatever the cause,
 * must be `{ error, request_id }` and NOTHING else: the id is uniform random
 * noise (F-FED-OPAQUEDENY), so the body still distinguishes nothing, and the
 * exact-key check is what catches a future edit that "helpfully" adds a reason
 * field to one branch. Returns the id so a caller can additionally assert that
 * two denials do not share one.
 */
async function expectUniformForbidden(res: Response): Promise<string> {
  expect(res.status).toBe(403);
  const body = (await res.json()) as Record<string, unknown>;
  expect(Object.keys(body).sort()).toEqual(["error", "request_id"]);
  expect(body.error).toBe("forbidden");
  expect(String(body.request_id)).toMatch(UUID_RE);
  return String(body.request_id);
}

// retry:2 - loopback /v1 rigs can race random local ports under full-suite load.
describe("/v1/federation/rotate/reissue-node-cert", { retry: 2 }, () => {
  it("returns a same-shaped challenge while disabled, then fails closed on completion", async () => {
    const challenge = await issueChallenge();

    const res = await completeReissue(signedCompleteBody(challenge));
    expect(res.status).toBe(403);
    await expectUniformForbidden(res);
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
    await expectUniformForbidden(replay);
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
    await expectUniformForbidden(res);
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
    await expectUniformForbidden(res);
  });

  // HOLE 1: a forged predecessor master cannot mint a real current-root cert.
  // The attacker controls M_attacker, crafts a rotation cert claiming M_attacker
  // is the "old" master rotating into the REAL current root, self-signs a node
  // chain under M_attacker, and holds the node key for the PoP. The server must
  // pin the predecessor from its OWN recorded lineage and reject this cert
  // because it is not byte-identical to the one the fortress adopted.
  it("rejects a forged-old-master rotation cert (attacker's own keypair as old_master)", async () => {
    await enableFederation();
    const forged = makeForgedOldMasterMaterials(materials);
    const challenge = await issueChallenge();

    const res = await completeReissue(forged.signedBody(challenge));
    expect(res.status).toBe(403);
    await expectUniformForbidden(res);
  });

  // HOLE 1 (replay/rollback): a genuine-lineage rotation cert with a rolled-back
  // serial is rejected. Here the fortress has adopted serial 2, but the submitted
  // cert (and the recorded one in this rig) carry serial 1: the submitted cert is
  // not byte-identical to the recorded serial-2 cert, so it is rejected.
  it("rejects a genuine-lineage rotation cert with a rolled-back / replayed serial", async () => {
    // Re-pin the context's recorded lineage to a serial-2 cert (as if the
    // fortress rotated twice), while the client still presents the serial-1 cert.
    const advanced = makeAdvancedSerialMaterials(materials);
    rig.dashboard.setFederationContext(advanced.context);
    await enableFederation();
    const challenge = await issueChallenge();

    // Client submits the OLD serial-1 cert; server adopted serial 2.
    const res = await completeReissue(signedCompleteBody(challenge, materials.rotationCert));
    expect(res.status).toBe(403);
    await expectUniformForbidden(res);
  });

  // HOLE 2: on a hybrid (PQC) fortress the reissue endpoint refuses entirely, so
  // a classical-only rotation cert can never silently downgrade the post-quantum
  // root. The submitted cert here is the genuine recorded one; the deny comes
  // purely from the fortress being hybrid.
  it("fails closed on a hybrid fortress even for a genuine classical rotation cert", async () => {
    rig.dashboard.setFederationContext({ ...materials.context, isHybrid: true });
    await enableFederation();
    const challenge = await issueChallenge();

    const res = await completeReissue(signedCompleteBody(challenge));
    expect(res.status).toBe(403);
    await expectUniformForbidden(res);
  });
});

/**
 * F-FED-OPAQUEDENY: the joiner-visible refusal maps at least five distinct
 * server-side causes onto one message, the issuer audits the precise one, and
 * the joiner's operator never sees it. Two separate two-machine drills
 * (2026-07-30, 2026-07-31) lost real time to exactly this, and both only moved
 * because the operator already knew to go read the issuer's audit log.
 *
 * The fix has to buy diagnosability WITHOUT selling the no-membership-oracle
 * property, so these tests are written adversarially against the fix itself: the
 * first two prove the wire still tells an unauthenticated caller nothing, and
 * only then do the rest prove the reason is recoverable by someone who can open
 * the issuer's fortress.
 */
// retry:2 - loopback /v1 rigs can race random local ports under full-suite load.
describe("reissue denials are diagnosable without becoming an oracle", { retry: 2 }, () => {
  it("gives every response on the route a distinct request id, denial or not", async () => {
    // A decoy challenge (federation OFF) and a real one (federation ON) must be
    // indistinguishable, so the id has to be on BOTH -- if it rode only on real
    // ones its mere presence would answer "is federation enabled?".
    const decoy = await rawChallengeBody();
    const denial = await expectUniformForbidden(
      await completeReissue(signedCompleteBody({
        challenge_id: String(decoy.challenge_id),
        challenge: String(decoy.challenge),
      })),
    );

    await enableFederation();
    const real = await rawChallengeBody();
    const success = await completeReissue(
      signedCompleteBody({
        challenge_id: String(real.challenge_id),
        challenge: String(real.challenge),
      }),
    );
    expect(success.status).toBe(200);
    const successBody = (await success.json()) as { request_id?: unknown };

    for (const id of [decoy.request_id, real.request_id, successBody.request_id]) {
      expect(String(id)).toMatch(UUID_RE);
    }
    const ids = [decoy.request_id, denial, real.request_id, successBody.request_id];
    expect(new Set(ids.map(String)).size).toBe(4);
  });

  it("returns the SAME denial body shape for three different causes", async () => {
    // federation_disabled: never enabled.
    const disabledChallenge = await rawChallengeBody();
    const disabledDenial = await completeReissue(
      signedCompleteBody({
        challenge_id: String(disabledChallenge.challenge_id),
        challenge: String(disabledChallenge.challenge),
      }),
    );

    // challenge_invalid: enable, then present a challenge that was never issued.
    await enableFederation();
    const challengeInvalidDenial = await completeReissue(
      signedCompleteBody({
        challenge_id: "00000000-0000-4000-8000-000000000000",
        challenge: "not-a-real-challenge",
      }),
    );

    // no_recorded_rotation_lineage: a fortress that never rotated.
    const noLineage = { ...materials.context };
    delete noLineage.recordedRotationCert;
    delete noLineage.recordedRotationSerial;
    rig.dashboard.setFederationContext(noLineage);
    await enableFederation();
    const lineageChallenge = await issueChallenge();
    const lineageDenial = await completeReissue(signedCompleteBody(lineageChallenge));

    const bodies = await Promise.all(
      [disabledDenial, challengeInvalidDenial, lineageDenial].map(async (res) => {
        expect(res.status).toBe(403);
        return (await res.json()) as Record<string, unknown>;
      }),
    );
    // Identical once the uniform-random id is removed: nothing in the body
    // separates "federation is off" from "no lineage" from "bad challenge".
    for (const body of bodies) {
      const { request_id, ...rest } = body;
      expect(String(request_id)).toMatch(UUID_RE);
      expect(rest).toEqual({ error: "forbidden" });
    }
    expect(new Set(bodies.map((b) => String(b.request_id))).size).toBe(3);
  });

  it("resolves a denial's request id to the precise reason in the ISSUER audit", async () => {
    await enableFederation();
    const challenge = await issueChallenge();
    const body = signedCompleteBody(challenge);
    expect((await completeReissue(body)).status).toBe(200);

    // Replay the spent challenge: the wire says only "forbidden".
    const requestId = await expectUniformForbidden(await completeReissue(body));

    const entry = await auditEntryForRequestId(requestId);
    expect(entry.result).toBe("failure");
    expect(entry.details?.reason).toBe("challenge_invalid");
    // And the remediation, so the lookup ends in an action rather than a code.
    expect(String(entry.details?.operator_next_step)).toContain("fresh challenge");
  });

  it("audits the lineage reason with BOTH serials and the restart instruction", async () => {
    // The exact condition Leg A hit: a rotate-root the running endpoint never
    // picked up. The two serials are what separate that from "never rotated".
    const noLineage = { ...materials.context };
    delete noLineage.recordedRotationCert;
    delete noLineage.recordedRotationSerial;
    rig.dashboard.setFederationContext(noLineage);
    await enableFederation();
    const challenge = await issueChallenge();

    const requestId = await expectUniformForbidden(
      await completeReissue(signedCompleteBody(challenge)),
    );

    const entry = await auditEntryForRequestId(requestId);
    expect(entry.details?.reason).toBe("no_recorded_rotation_lineage");
    expect(entry.details?.recorded_rotation_serial).toBeNull();
    expect(entry.details?.presented_rotation_serial).toBe(
      materials.rotationCert.rotation_serial,
    );
    expect(String(entry.details?.operator_next_step)).toContain("Restart the fortress endpoint");
  });

  it("audits the disabled reason with status and re-enable instructions", async () => {
    const challenge = await rawChallengeBody();
    const requestId = await expectUniformForbidden(
      await completeReissue(
        signedCompleteBody({
          challenge_id: String(challenge.challenge_id),
          challenge: String(challenge.challenge),
        }),
      ),
    );

    const entry = await auditEntryForRequestId(requestId);
    expect(entry.details?.reason).toBe("federation_disabled");
    expect(String(entry.details?.operator_next_step)).toContain(
      "sanctuary federation status",
    );
    expect(String(entry.details?.operator_next_step)).toContain(
      "sanctuary federation enable",
    );
  });

  it("carries a remediation for a deep issuance reason too, not just the shallow ones", async () => {
    // The remediation map has to cover the reasons thrown from inside the
    // issuance path as well, or the CLI sends the operator to read a field that
    // is not there. proof_invalid is one of those deep ones.
    await enableFederation();
    const challenge = await issueChallenge();
    const body = signedCompleteBody(challenge);
    body.node_signature = toBase64url(randomBytes(64));

    const requestId = await expectUniformForbidden(await completeReissue(body));
    const entry = await auditEntryForRequestId(requestId);
    expect(entry.details?.reason).toBe("proof_invalid");
    expect(String(entry.details?.operator_next_step)).toContain("fresh challenge");
  });

  it("keeps the reason and the remediation OFF the wire entirely", async () => {
    const challenge = await rawChallengeBody();
    const res = await completeReissue(
      signedCompleteBody({
        challenge_id: String(challenge.challenge_id),
        challenge: String(challenge.challenge),
      }),
    );
    const raw = await res.text();
    // The literal audit strings must never appear in a response body.
    expect(raw).not.toContain("federation_disabled");
    expect(raw).not.toContain("operator_next_step");
    expect(raw).not.toContain("reason");
  });
});

/**
 * Build a self-consistent attacker chain: a rotation cert claiming the attacker's
 * OWN master rotated into the REAL current root, plus an old node-cert chain that
 * verifies under the attacker's master, plus the node key for the PoP. Every
 * signature is internally valid; the ONLY thing wrong is that the "old" master is
 * the attacker's, not the fortress's recorded predecessor.
 */
function makeForgedOldMasterMaterials(genuine: ReissueMaterials): {
  signedBody: (challenge: { challenge_id: string; challenge: string }) => Record<string, unknown>;
} {
  const attackerMaster = generateFortressMaster();
  const fortressId = genuine.fortressId;

  const attackerPrincipalPrivate = randomBytes(32);
  const attackerPrincipalPublic = ed25519.getPublicKey(attackerPrincipalPrivate);
  const attackerPrincipalCert = issuePrincipalCertificate({
    principal_id: "principal-attacker",
    principal_pubkey: attackerPrincipalPublic,
    role: "root",
    fortress_id: fortressId,
    master_private_key: attackerMaster.private_key,
  });

  const { publicKey: nodePublicKey, privateKey: nodePrivateKey } = generateNodeKeypair();
  const forgedNodeCert = issueNodeIdentityCertificate({
    node_id: genuine.nodeId,
    node_pubkey: nodePublicKey,
    node_mode: "local",
    fortress_id: fortressId,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: attackerMaster.public.public_key,
      principal_id: attackerPrincipalCert.principal_id,
      principal_pubkey: attackerPrincipalCert.principal_pubkey,
    },
    principal_private_key: attackerPrincipalPrivate,
    master_private_key: attackerMaster.private_key,
  });

  // The forged rotation cert: attacker's master "rotates" into the REAL current
  // root (k2Public is public), signed by the attacker's master.
  const forgedRotationCert = signFederationRootRotationCertificate({
    fortress_id: fortressId,
    old_master_pubkey: attackerMaster.public.public_key,
    new_master: genuine.k2Public,
    old_master_private_key: attackerMaster.private_key,
    rotation_serial: 1,
    rotated_at: "2026-06-26T00:00:00.000Z",
  });

  return {
    signedBody: (challenge) => {
      const message = buildFederationReissueNodeCertProofMessage({
        fortressId,
        nodeId: genuine.nodeId,
        challengeId: challenge.challenge_id,
        challenge: challenge.challenge,
        currentNodeCert: forgedNodeCert,
        currentIssuingPrincipalCert: attackerPrincipalCert,
        rotationCert: forgedRotationCert,
      });
      return {
        action: "complete",
        node_id: genuine.nodeId,
        challenge_id: challenge.challenge_id,
        challenge: challenge.challenge,
        current_node_cert: forgedNodeCert,
        current_issuing_principal_cert: attackerPrincipalCert,
        rotation_cert: forgedRotationCert,
        node_signature: toBase64url(ed25519.sign(message, nodePrivateKey)),
      };
    },
  };
}

/**
 * A context whose RECORDED lineage is at serial 2 (a genuine, internally-valid
 * serial-2 rotation cert from the same K1->K2 link), used to prove that a client
 * presenting the older serial-1 cert is rejected (it is not byte-identical to the
 * adopted serial-2 cert).
 */
function makeAdvancedSerialMaterials(genuine: ReissueMaterials): {
  context: FederationIssuerContext;
} {
  const serial2Cert = signFederationRootRotationCertificate({
    fortress_id: genuine.fortressId,
    old_master_pubkey: genuine.rotationCert.old_master_pubkey,
    new_master: genuine.k2Public,
    old_master_private_key: genuine.k1PrivateKey,
    rotation_serial: 2,
    rotated_at: "2026-06-27T00:00:00.000Z",
  });
  return {
    context: {
      ...genuine.context,
      recordedRotationCert: serial2Cert,
      recordedRotationSerial: 2,
    },
  };
}

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
    // The fortress's OWN adopted rotation lineage (as the durable trust-root
    // record would surface it). The reissue endpoint pins the predecessor master
    // from THIS, not from the request body.
    recordedRotationCert: rotationCert,
    recordedRotationSerial: 1,
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
    k1PrivateKey: k1.private_key,
    context,
    nodeId,
    currentNodeCert,
    currentIssuingPrincipalCert: oldPrincipalCert,
    rotationCert,
    nodePrivateKey,
  };
}
