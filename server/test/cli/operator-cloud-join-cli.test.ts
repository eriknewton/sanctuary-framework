/**
 * Operator Cloud Slice 2, CLI join-via-bundle + secret-free delivery skeleton.
 *
 * Pins: the operator-cloud join uses --provision-bundle (NOT the raw fortress
 * master secret); the assembled request's proof binds the cloud-generated
 * keypair; and the delivery skeleton emits NO secret material and forbids
 * cloud-init embedding.
 */

import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { randomBytes } from "node:crypto";

import { runFederationJoin } from "../../src/cli/federation.js";
import {
  renderOperatorCloudDeliveryPlan,
  runDeployCommand,
} from "../../src/cli/deploy.js";
import {
  buildOperatorCloudProvisionBundle,
  computeNodePubkeyHash,
} from "../../src/mesh/operator-cloud-provision.js";
import {
  OperatorCloudProvisionClaimStore,
  createOperatorCloudJoinApprover,
} from "../../src/mesh/lifecycle/operator-cloud-join-approver.js";
import { JoinCeremony, type FederationContext } from "../../src/v1/federation.js";
import { issueBootstrapToken } from "../../src/mesh/lifecycle/bootstrap-token.js";
import { makeFederationMaterials } from "../v1/fed-materials.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const DELIVERY_TARGET = "sanctuary@cloud-1:/run/sanctuary/bundle.json";
const NODE_ID = "operator-cloud-1";

function homeProvision() {
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
    grants: [{ grant_id: "g1", agent_id: "agent-a", namespace: "ns-a", plaintext: stringToBytes("S") }],
    deliveryTarget: DELIVERY_TARGET,
    deliveryKey,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  return { materials, proofKey, deliveryKey, token, built };
}

describe("sanctuary federation join, operator-cloud bundle path", () => {
  it("joins via --provision-bundle and never requires the fortress master secret", async () => {
    const { materials, proofKey, deliveryKey, token, built } = homeProvision();

    // The fortress side: a production OC approver. In the real flow the VM runs
    // `prepare` (exposing its node pubkey) BEFORE the operator approves, so the
    // claim binds the pubkey the CLI will present. We mirror that by recording
    // the claim from the incoming request's pubkey, then running the ceremony.
    const claimStore = new OperatorCloudProvisionClaimStore();
    const ctx: FederationContext = {
      ...materials.context,
      approver: createOperatorCloudJoinApprover({
        pinned_master_pubkey: materials.context.pinnedMasterPubkey,
        issuing_principal_cert: materials.context.issuingPrincipalCert,
        issuing_principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
        master_private_key: materials.context.getMasterPrivateKey?.(),
        claimStore,
        nodeJoinProofKey: proofKey,
      }),
    };

    // Mock dashboardRequest: route /authorize/complete through the real ceremony.
    const mockRequest = (async (path: string, init: { body?: string }) => {
      expect(path).toBe("/v1/federation/authorize/complete");
      const join = JSON.parse(init.body as string);
      await claimStore.record({
        fortress_id: materials.fortressId,
        node_id: NODE_ID,
        node_pubkey_hash: computeNodePubkeyHash(join.node_pubkey),
        bootstrap_nonce: token.nonce,
        manifest_digest: built.digests.manifest_digest,
        scoped_secret_ciphertext_digest: built.digests.scoped_secret_ciphertext_digest,
        scope_digest: built.digests.scope_digest,
        bundle_digest: built.digests.bundle_digest,
        expires_at: built.bundle.manifest.expires_at,
      });
      const outcome = await new JoinCeremony(ctx).authorizeComplete(join);
      if (!outcome.approved) throw new DashboardRequestErrorStub();
      return { certificate: outcome.certificate, issuing_principal_cert: outcome.issuingPrincipalCert };
    }) as never;

    const out = new Capture();
    const err = new Capture();
    const code = await runFederationJoin({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9999",
        "--provision-bundle",
        JSON.stringify(built.bundle),
        "--delivery-key",
        toBase64url(deliveryKey),
        "--delivery-target",
        DELIVERY_TARGET,
      ],
      out,
      err,
      request: mockRequest,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain('"joined": true');
    expect(out.text()).toContain('"node_id"');
  });

  it("rejects --provision-bundle combined with --master-secret (mutually exclusive)", async () => {
    const err = new Capture();
    const code = await runFederationJoin({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9999",
        "--provision-bundle",
        "{}",
        "--master-secret",
        toBase64url(randomBytes(32)),
      ],
      err,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("mutually exclusive");
  });

  it("rejects a local-mode join whose token mode is operator_cloud (must use a bundle)", async () => {
    const { materials } = homeProvision();
    const ocToken = issueBootstrapToken({
      intended_node_id: NODE_ID,
      intended_node_mode: "operator_cloud",
      fortress_id: materials.fortressId,
      issuing_principal: materials.context.issuingPrincipalCert.principal_id,
      principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
    });
    const err = new Capture();
    const code = await runFederationJoin({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9999",
        "--bootstrap-token",
        JSON.stringify(ocToken),
        "--master-secret",
        toBase64url(randomBytes(32)),
      ],
      err,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("must join with --provision-bundle");
  });
});

class DashboardRequestErrorStub extends Error {
  kind = "auth" as const;
  constructor() {
    super("denied");
    this.name = "DashboardRequestError";
  }
}

describe("sanctuary deploy operator-cloud delivery, secret-free skeleton", () => {
  const FORBIDDEN = [
    /master_secret/i,
    /private_key/i,
    /delivery_key/i,
    /node_join_proof_key/i,
    /unseal_key/i,
    /data_key/i,
    /passphrase/i,
  ];

  it("emits an SSH/pull delivery plan that forbids cloud-init embedding and carries no secrets", () => {
    const plan = renderOperatorCloudDeliveryPlan({
      host: "cloud-1.example",
      user: "svc",
      bundlePath: "/run/sanctuary/bundle.json",
    });
    expect(plan).toContain("schema_version: operator-cloud-delivery-plan-v1");
    expect(plan).toContain("delivery_channel: ssh-pull");
    expect(plan).toContain("cloud_init_embedding: forbidden");
    for (const pattern of FORBIDDEN) {
      expect(plan).not.toMatch(pattern);
    }
  });

  it("is reachable via the deploy CLI as `operator-cloud delivery`", async () => {
    const out = new Capture();
    const code = await runDeployCommand({
      argv: ["operator-cloud", "delivery", "--host", "h", "--user", "u"],
      out,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("delivery_channel: ssh-pull");
  });
});
