/**
 * Operator Cloud Slice 2, issuer-side provision service.
 *
 * Pins HIGH-2: the EXTERNAL approval context (what would travel to a
 * webhook/dashboard inbox before approval) carries NO raw scope identifiers and
 * NO secret bytes, only opaque digests, counts, and non-sensitive labels. The
 * full scope manifest is available LOCALLY only.
 *
 * Also pins the HIGH-1 ordering + claim binding: prepare digests in memory, then
 * record the claim only after approval, bound to exactly those digests.
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import {
  prepareOperatorCloudProvision,
  recordApprovedProvisionClaim,
  assertNoScopeLeakInExternalContext,
} from "../../src/mesh/operator-cloud-provision-service.js";
import { OperatorCloudProvisionClaimStore } from "../../src/mesh/lifecycle/operator-cloud-join-approver.js";
import { issueBootstrapToken } from "../../src/mesh/lifecycle/bootstrap-token.js";
import { makeFederationMaterials } from "../v1/fed-materials.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";

const SENSITIVE_NS = "very-secret-namespace-do-not-leak";
const SENSITIVE_AGENT = "agent-confidential-project-x";
const DELIVERY_TARGET = "sanctuary@cloud-1:/run/sanctuary/bundle.json";

function prepare() {
  const materials = makeFederationMaterials();
  const nodeId = "operator-cloud-1";
  const proofKey = randomBytes(32);
  const deliveryKey = randomBytes(32);
  const nodePubkey = toBase64url(randomBytes(32));
  const token = issueBootstrapToken({
    intended_node_id: nodeId,
    intended_node_mode: "operator_cloud",
    fortress_id: materials.fortressId,
    issuing_principal: materials.context.issuingPrincipalCert.principal_id,
    principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
  });
  return prepareOperatorCloudProvision({
    provider: "generic-ssh",
    nodePubkeyB64: nodePubkey,
    fortressId: materials.fortressId,
    nodeId,
    homeFederationUrl: "https://home.example",
    bootstrapToken: token,
    pinnedMasterPubkey: materials.context.pinnedMasterPubkey,
    issuingPrincipalCert: materials.context.issuingPrincipalCert,
    nodeJoinProofKey: proofKey,
    agentIds: [SENSITIVE_AGENT],
    namespaces: [SENSITIVE_NS],
    grants: [
      {
        grant_id: "grant-secret-1",
        agent_id: SENSITIVE_AGENT,
        namespace: SENSITIVE_NS,
        plaintext: stringToBytes("S"),
      },
    ],
    deliveryTarget: DELIVERY_TARGET,
    deliveryKey,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
}

describe("operator-cloud provision approval context, external redaction (HIGH-2)", () => {
  it("the external context carries counts + digests, never raw agent/namespace/grant ids", () => {
    const prepared = prepare();
    const serialized = JSON.stringify(prepared.externalContext);
    expect(serialized).not.toContain(SENSITIVE_NS);
    expect(serialized).not.toContain(SENSITIVE_AGENT);
    expect(serialized).not.toContain("grant-secret-1");
    expect(prepared.externalContext.agent_count).toBe(1);
    expect(prepared.externalContext.namespace_count).toBe(1);
    expect(prepared.externalContext.grant_count).toBe(1);
    expect(prepared.externalContext.bundle_digest).toBeTruthy();
    expect(prepared.externalContext.scope_digest).toBeTruthy();
  });

  it("the external context carries no secret bytes (proof key / unseal key / DEK / private key)", () => {
    const prepared = prepare();
    const serialized = JSON.stringify(prepared.externalContext);
    expect(serialized).not.toMatch(/data_key|node_join_proof_key|unseal_key|private_key|master_secret/i);
    expect(() => assertNoScopeLeakInExternalContext(prepared.externalContext)).not.toThrow();
  });

  it("the LOCAL context DOES carry the full scope manifest (operator inspects it locally)", () => {
    const prepared = prepare();
    expect(prepared.localContext.agent_ids).toContain(SENSITIVE_AGENT);
    expect(prepared.localContext.namespaces).toContain(SENSITIVE_NS);
    expect(prepared.localContext.grant_ids).toContain("grant-secret-1");
  });

  it("the guard REJECTS an object that leaks raw scope identifiers externally", () => {
    expect(() =>
      assertNoScopeLeakInExternalContext({ agent_ids: [SENSITIVE_AGENT] }),
    ).toThrow(/scope identifiers/);
  });
});

describe("operator-cloud provision claim, bound to the prepared digests (HIGH-1)", () => {
  it("records a claim that matches the prepared bundle digests + node pubkey", () => {
    const prepared = prepare();
    const store = new OperatorCloudProvisionClaimStore();
    const claim = recordApprovedProvisionClaim({ claimStore: store, prepared });
    expect(claim.manifest_digest).toBe(prepared.built.digests.manifest_digest);
    expect(claim.bundle_digest).toBe(prepared.built.digests.bundle_digest);
    expect(claim.scope_digest).toBe(prepared.built.digests.scope_digest);
    expect(claim.node_pubkey_hash).toBe(prepared.nodePubkeyHash);
    expect(claim.consumed).toBe(false);
  });
});
