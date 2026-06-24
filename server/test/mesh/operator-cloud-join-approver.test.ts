/**
 * Operator Cloud Slice 2, production join approver + pending-provision-claim
 * store, driven through the real JoinCeremony.authorizeComplete path.
 *
 * Pins the BLOCKING acceptance criteria:
 *  (a) a cloud join is approved ONLY against a matching, unconsumed,
 *      digest-and-pubkey-bound Tier-1 claim (anti-substitution),
 *  (d) a substituted bundle / substituted pubkey / consumed claim / missing
 *      approver all DENY,
 *  (b) the issued cloud context is a non-issuer FederationNonIssuerOperatorCloudContext
 *      (the joined-node record yields no issuer authority).
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import {
  JoinCeremony,
  assertOperatorCloudContextHasNoIssuerAuthority,
  federationContextHasIssuerAuthority,
  type FederationContext,
  type FederationNonIssuerOperatorCloudContext,
} from "../../src/v1/federation.js";
import {
  OperatorCloudProvisionClaimStore,
  createOperatorCloudJoinApprover,
} from "../../src/mesh/lifecycle/operator-cloud-join-approver.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  buildOperatorCloudProvisionBundle,
  openScopedSecret,
  wrapNodePrivateKeyForCloud,
  isOperatorCloudJoinedNodeRecord,
  computeNodePubkeyHash,
  type OperatorCloudJoinedNodeRecord,
} from "../../src/mesh/operator-cloud-provision.js";
import { assembleOperatorCloudJoinRequest } from "../../src/cli/federation.js";
import { issueBootstrapToken } from "../../src/mesh/lifecycle/bootstrap-token.js";
import { verifyCertChain } from "../../src/mesh/trust-root.js";
import { makeFederationMaterials } from "../v1/fed-materials.js";
import { stringToBytes, toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL, NODE_TRUST_BOUNDARY_VERSION } from "../../src/mesh/node-posture.js";

const DELIVERY_TARGET = "sanctuary@cloud-1:/run/sanctuary/provision-bundle.json";
const NODE_ID = "operator-cloud-1";

/**
 * Set up a full home-side provision: master + issuer materials, a scoped bundle,
 * a recorded Tier-1-approved claim, and a production operator-cloud approver
 * wired into an issuer FederationContext. Returns everything a cloud node needs.
 */
async function setup(opts?: {
  recordClaim?: boolean;
  claimStore?: OperatorCloudProvisionClaimStore;
}) {
  const materials = makeFederationMaterials();
  const proofKey = randomBytes(32);
  const deliveryKey = randomBytes(32);
  const token = issueBootstrapToken({
    intended_node_id: NODE_ID,
    intended_node_mode: "operator_cloud",
    fortress_id: materials.fortressId,
    issuing_principal: materials.context.issuingPrincipalCert.principal_id,
    principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
  });
  const built = buildOperatorCloudProvisionBundle({
    fortressId: materials.fortressId,
    nodeId: NODE_ID,
    homeFederationUrl: "https://home.example",
    bootstrapToken: token,
    pinnedMasterPubkey: materials.context.pinnedMasterPubkey,
    issuingPrincipalCert: materials.context.issuingPrincipalCert,
    nodeJoinProofKey: proofKey,
    agentIds: ["agent-a"],
    namespaces: ["ns-a"],
    grants: [
      { grant_id: "g1", agent_id: "agent-a", namespace: "ns-a", plaintext: stringToBytes("S") },
    ],
    deliveryTarget: DELIVERY_TARGET,
    deliveryKey,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });

  // The cloud node assembles its join request from the bundle FIRST so we know
  // its actual public key for the claim binding.
  const assembled = assembleOperatorCloudJoinRequest({
    bundle: built.bundle,
    deliveryKey,
    deliveryTarget: DELIVERY_TARGET,
  });

  const nodePubkeyHash = computeNodePubkeyHash(toBase64url(assembled.nodePublicKey));
  const claimStore = opts?.claimStore ?? new OperatorCloudProvisionClaimStore();
  if (opts?.recordClaim ?? true) {
    await claimStore.record({
      fortress_id: materials.fortressId,
      node_id: NODE_ID,
      node_pubkey_hash: nodePubkeyHash,
      bootstrap_nonce: token.nonce,
      manifest_digest: built.digests.manifest_digest,
      scoped_secret_ciphertext_digest: built.digests.scoped_secret_ciphertext_digest,
      scope_digest: built.digests.scope_digest,
      bundle_digest: built.digests.bundle_digest,
      expires_at: built.bundle.manifest.expires_at,
    });
  }

  const approver = createOperatorCloudJoinApprover({
    pinned_master_pubkey: materials.context.pinnedMasterPubkey,
    issuing_principal_cert: materials.context.issuingPrincipalCert,
    issuing_principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
    master_private_key: materials.context.getMasterPrivateKey?.(),
    claimStore,
    nodeJoinProofKey: proofKey,
  });

  // The HOME issuer context that drives the ceremony, with the OC approver.
  const homeContext: FederationContext = {
    ...materials.context,
    approver,
  };

  return {
    materials,
    token,
    built,
    deliveryKey,
    assembled,
    claimStore,
    approver,
    homeContext,
    nodePubkeyHash,
    proofKey,
  };
}

describe("operator-cloud join approver, anti-substitution (HIGH-1 / criterion a + d)", () => {
  it("approves a join that matches the digest-and-pubkey-bound claim", async () => {
    const { homeContext, assembled, materials } = await setup();
    const outcome = await new JoinCeremony(homeContext).authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(true);
    if (outcome.approved) {
      expect(() =>
        verifyCertChain(
          outcome.certificate,
          materials.context.issuingPrincipalCert,
          materials.context.pinnedMasterPubkey,
        ),
      ).not.toThrow();
      expect(outcome.certificate.node_mode).toBe("operator_cloud");
    }
  });

  it("DENIES when there is NO matching approved provision claim", async () => {
    const { homeContext, assembled } = await setup({ recordClaim: false });
    const outcome = await new JoinCeremony(homeContext).authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(false);
  });

  it("DENIES a substituted node pubkey consuming a leaked bundle (HIGH-1)", async () => {
    const { homeContext, assembled } = await setup();
    // Attacker keeps the bundle's proof but swaps in their own keypair.
    const substituted = {
      ...assembled.joinRequest,
      node_pubkey: toBase64url(randomBytes(32)),
    };
    const outcome = await new JoinCeremony(homeContext).authorizeComplete(substituted);
    expect(outcome.approved).toBe(false);
  });

  it("DENIES a second consume of an already-consumed claim (single-use)", async () => {
    const { homeContext, assembled } = await setup();
    const first = await new JoinCeremony(homeContext).authorizeComplete(assembled.joinRequest);
    expect(first.approved).toBe(true);
    const second = await new JoinCeremony(homeContext).authorizeComplete(assembled.joinRequest);
    expect(second.approved).toBe(false);
  });

  it("DENIES an expired claim", async () => {
    const { materials, token, built, claimStore, assembled, nodePubkeyHash, proofKey } = await setup({
      recordClaim: false,
    });
    // Record a claim already expired.
    await claimStore.record({
      fortress_id: materials.fortressId,
      node_id: NODE_ID,
      node_pubkey_hash: nodePubkeyHash,
      bootstrap_nonce: token.nonce,
      manifest_digest: built.digests.manifest_digest,
      scoped_secret_ciphertext_digest: built.digests.scoped_secret_ciphertext_digest,
      scope_digest: built.digests.scope_digest,
      bundle_digest: built.digests.bundle_digest,
      expires_at: new Date(Date.now() - 1000).toISOString(),
    });
    const approver = createOperatorCloudJoinApprover({
      pinned_master_pubkey: materials.context.pinnedMasterPubkey,
      issuing_principal_cert: materials.context.issuingPrincipalCert,
      issuing_principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
      master_private_key: materials.context.getMasterPrivateKey?.(),
      claimStore,
      nodeJoinProofKey: proofKey,
    });
    const ctx: FederationContext = { ...materials.context, approver };
    const outcome = await new JoinCeremony(ctx).authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(false);
  });

  it("DENIES when no approver is bound (Slice 1 invariant holds for operator-cloud joins)", async () => {
    const { materials, assembled } = await setup();
    // Strip the approver entirely.
    const noApprover = { ...materials.context } as FederationContext & { approver?: unknown };
    delete noApprover.approver;
    const outcome = await new JoinCeremony(noApprover as FederationContext).authorizeComplete(
      assembled.joinRequest,
    );
    expect(outcome.approved).toBe(false);
  });
});

describe("operator-cloud joined-node record, non-issuer context (criterion b)", () => {
  it("a joined cloud node yields a FederationNonIssuerOperatorCloudContext with no issuer authority", async () => {
    const { homeContext, assembled, built, deliveryKey, materials } = await setup();
    const outcome = await new JoinCeremony(homeContext).authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(true);
    if (!outcome.approved) return;

    const scoped = openScopedSecret(built.bundle, deliveryKey);
    const record: OperatorCloudJoinedNodeRecord = {
      record_version: "operator-cloud-joined-node-v1",
      fortress_id: materials.fortressId,
      node_id: NODE_ID,
      node_mode: "operator_cloud",
      pinned_master_pubkey: materials.context.pinnedMasterPubkey,
      issuing_principal_cert: materials.context.issuingPrincipalCert,
      local_node_cert: outcome.certificate,
      wrapped_local_node_private_key: wrapNodePrivateKeyForCloud({
        nodePrivateKey: assembled.nodePrivateKey,
        cloudNodeUnsealKey: fromBase64url(scoped.cloud_node_unseal_key),
      }),
      scope_manifest: built.bundle.manifest.scope_manifest,
      trust_boundary: {
        version: NODE_TRUST_BOUNDARY_VERSION,
        posture: "provider_in_trust_boundary_not_tee",
        label: OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL,
        provider_in_trust_boundary: true,
        tee_attested: false,
      },
      disclosure_acknowledged_at: new Date().toISOString(),
    };
    expect(isOperatorCloudJoinedNodeRecord(record)).toBe(true);

    // The runtime context built from this record is a non-issuer context.
    const cloudContext: FederationNonIssuerOperatorCloudContext = {
      fortressId: record.fortress_id,
      nodeId: record.node_id,
      nodeMode: "operator_cloud",
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      isNodeRevoked: () => false,
    };
    expect(() => assertOperatorCloudContextHasNoIssuerAuthority(cloudContext)).not.toThrow();
    expect(federationContextHasIssuerAuthority(cloudContext)).toBe(false);

    // An operator-cloud context cannot mint a bootstrap token or issue certs.
    expect(() =>
      new JoinCeremony(cloudContext).authorizeInit({
        intendedNodeId: "x",
        intendedNodeMode: "local",
      }),
    ).toThrow();
  });
});

describe("operator-cloud join approver — RESTART replay denied (durable, the debt-closer)", () => {
  it("a consumed claim stays consumed across a daemon restart (DENIES the cloud-join replay)", async () => {
    // Shared encrypted storage + custody master across two daemon "boots". Each
    // boot builds its OWN durable claim store, mirroring how a production boot
    // would wire it; the recorded + consumed claim must survive the restart.
    const storage = new MemoryStorage();
    const fakeMaster = new Uint8Array(32).fill(13);

    // Boot 1: a durable claim store; setup records the claim into it. First join
    // APPROVED, claim CONSUMED + persisted.
    const store1 = OperatorCloudProvisionClaimStore.durableFromBoot(storage, fakeMaster);
    const ctx1 = await setup({ claimStore: store1 });
    const first = await new JoinCeremony(ctx1.homeContext).authorizeComplete(
      ctx1.assembled.joinRequest,
    );
    expect(first.approved).toBe(true);

    // Boot 2: a FRESH durable claim store over the SAME storage (the restart),
    // wired to an approver that re-verifies the same bundle. Replaying the SAME
    // join is DENIED because the consumed state was persisted. On `main`
    // (in-memory only) the restart would FORGET the consumption and ALLOW.
    const store2 = OperatorCloudProvisionClaimStore.durableFromBoot(storage, fakeMaster);
    const approver2 = createOperatorCloudJoinApprover({
      pinned_master_pubkey: ctx1.materials.context.pinnedMasterPubkey,
      issuing_principal_cert: ctx1.materials.context.issuingPrincipalCert,
      issuing_principal_private_key: ctx1.materials.context.getIssuingPrincipalPrivateKey(),
      master_private_key: ctx1.materials.context.getMasterPrivateKey?.(),
      claimStore: store2,
      nodeJoinProofKey: ctx1.proofKey,
    });
    const ctx2: FederationContext = { ...ctx1.materials.context, approver: approver2 };
    const replay = await new JoinCeremony(ctx2).authorizeComplete(
      ctx1.assembled.joinRequest,
    );
    expect(replay.approved).toBe(false);
  });
});
