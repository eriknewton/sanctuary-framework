/**
 * Operator Cloud Slice 2, scoped provision bundle + per-grant key schedule.
 *
 * These tests pin the CORE SECURITY PROPERTY (HIGH-3 of the design review): a
 * cloud node holding the bundle's scoped keys can decrypt ONLY its assigned
 * grants, and a COMPROMISED cloud node running attacker code still cannot
 * decrypt out-of-scope state because it literally lacks the per-grant key.
 *
 * They also pin: no root/issuer material in the serialized bundle, the
 * anti-substitution digest/proof binding, and the provider-in-trust-boundary
 * disclosure carried through the bundle manifest.
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import {
  buildOperatorCloudProvisionBundle,
  decryptAssignedGrant,
  openScopedSecret,
  assertBundleHasNoRootMaterial,
  computeBundleDigest,
  computeManifestDigest,
  computeScopedSecretCiphertextDigest,
  computeOperatorCloudJoinProof,
  verifyOperatorCloudJoinProof,
  OPERATOR_CLOUD_BUNDLE_VERSION,
  type OperatorCloudGrantInput,
} from "../../src/mesh/operator-cloud-provision.js";
import { decrypt, encrypt } from "../../src/core/encryption.js";
import { issueBootstrapToken } from "../../src/mesh/lifecycle/bootstrap-token.js";
import { makeFederationMaterials } from "../v1/fed-materials.js";
import { stringToBytes, bytesToString, fromBase64url } from "../../src/core/encoding.js";

const DELIVERY_TARGET = "sanctuary@cloud-1:/run/sanctuary/provision-bundle.json";

function buildScopedBundle(opts?: {
  nodeId?: string;
  agentIds?: string[];
  namespaces?: string[];
  grants?: OperatorCloudGrantInput[];
  deliveryKey?: Uint8Array;
}) {
  const materials = makeFederationMaterials();
  const nodeId = opts?.nodeId ?? "operator-cloud-1";
  const proofKey = randomBytes(32);
  const deliveryKey = opts?.deliveryKey ?? randomBytes(32);
  const token = issueBootstrapToken({
    intended_node_id: nodeId,
    intended_node_mode: "operator_cloud",
    fortress_id: materials.fortressId,
    issuing_principal: materials.context.issuingPrincipalCert.principal_id,
    principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
  });
  const agentIds = opts?.agentIds ?? ["agent-a"];
  const namespaces = opts?.namespaces ?? ["ns-a"];
  const grants: OperatorCloudGrantInput[] =
    opts?.grants ?? [
      {
        grant_id: "grant-1",
        agent_id: "agent-a",
        namespace: "ns-a",
        plaintext: stringToBytes("ASSIGNED SECRET STATE"),
      },
    ];
  const built = buildOperatorCloudProvisionBundle({
    fortressId: materials.fortressId,
    nodeId,
    homeFederationUrl: "https://home.example",
    bootstrapToken: token,
    pinnedMasterPubkey: materials.context.pinnedMasterPubkey,
    issuingPrincipalCert: materials.context.issuingPrincipalCert,
    nodeJoinProofKey: proofKey,
    agentIds,
    namespaces,
    grants,
    deliveryTarget: DELIVERY_TARGET,
    deliveryKey,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  return { materials, nodeId, proofKey, deliveryKey, token, built };
}

describe("operator-cloud provision bundle, happy path", () => {
  it("a cloud node CAN decrypt its assigned grant with the bundle's scoped keys", () => {
    const { deliveryKey, built, nodeId, materials } = buildScopedBundle();
    const scoped = openScopedSecret(built.bundle, deliveryKey);
    expect(scoped.assigned_grants).toHaveLength(1);
    const plaintext = decryptAssignedGrant({
      grant: scoped.assigned_grants[0]!,
      fortressId: materials.fortressId,
      nodeId,
      scopeDigest: built.digests.scope_digest,
    });
    expect(bytesToString(plaintext)).toBe("ASSIGNED SECRET STATE");
  });

  it("carries the provider-in-trust-boundary disclosure, never TEE, in the manifest", () => {
    const { built } = buildScopedBundle();
    const tb = built.bundle.manifest.trust_boundary;
    expect(built.bundle.manifest.bundle_version).toBe(OPERATOR_CLOUD_BUNDLE_VERSION);
    expect(tb.posture).toBe("provider_in_trust_boundary_not_tee");
    expect(tb.provider_in_trust_boundary).toBe(true);
    expect(tb.tee_attested).toBe(false);
    expect(tb.label).toContain("not TEE");
  });
});

describe("operator-cloud provision bundle, negative decrypt (HIGH-3 core property)", () => {
  it("the per-grant DEK fails to decrypt the same grant under a DIFFERENT node id (AAD substitution)", () => {
    const { deliveryKey, built, materials } = buildScopedBundle({ nodeId: "operator-cloud-1" });
    const scoped = openScopedSecret(built.bundle, deliveryKey);
    // A compromised node tries to re-attribute its OWN grant to another node id.
    expect(() =>
      decryptAssignedGrant({
        grant: scoped.assigned_grants[0]!,
        fortressId: materials.fortressId,
        nodeId: "operator-cloud-2", // wrong node id => AAD mismatch
        scopeDigest: built.digests.scope_digest,
      }),
    ).toThrow();
  });

  it("the per-grant DEK fails to decrypt under a DIFFERENT scope digest", () => {
    const { deliveryKey, built, materials, nodeId } = buildScopedBundle();
    const scoped = openScopedSecret(built.bundle, deliveryKey);
    expect(() =>
      decryptAssignedGrant({
        grant: scoped.assigned_grants[0]!,
        fortressId: materials.fortressId,
        nodeId,
        scopeDigest: "sha256:WRONG-SCOPE-DIGEST",
      }),
    ).toThrow();
  });

  it("the per-grant DEK fails to decrypt under a DIFFERENT agent/namespace claim (cross-grant)", () => {
    const grants: OperatorCloudGrantInput[] = [
      { grant_id: "g1", agent_id: "agent-a", namespace: "ns-a", plaintext: stringToBytes("A") },
      { grant_id: "g2", agent_id: "agent-b", namespace: "ns-b", plaintext: stringToBytes("B") },
    ];
    const { deliveryKey, built, materials, nodeId } = buildScopedBundle({
      agentIds: ["agent-a", "agent-b"],
      namespaces: ["ns-a", "ns-b"],
      grants,
    });
    const scoped = openScopedSecret(built.bundle, deliveryKey);
    const g1 = scoped.assigned_grants.find((g) => g.grant_id === "g1")!;
    // Try to decrypt g1's ciphertext while claiming it is g2 (cross-grant AAD).
    expect(() =>
      decryptAssignedGrant({
        grant: { ...g1, grant_id: "g2", agent_id: "agent-b", namespace: "ns-b" },
        fortressId: materials.fortressId,
        nodeId,
        scopeDigest: built.digests.scope_digest,
      }),
    ).toThrow();
  });

  it("each grant uses a DISTINCT random DEK, so one grant's key cannot open another", () => {
    const grants: OperatorCloudGrantInput[] = [
      { grant_id: "g1", agent_id: "agent-a", namespace: "ns-a", plaintext: stringToBytes("ONE") },
      { grant_id: "g2", agent_id: "agent-a", namespace: "ns-a", plaintext: stringToBytes("TWO") },
    ];
    const { deliveryKey, built } = buildScopedBundle({ grants });
    const scoped = openScopedSecret(built.bundle, deliveryKey);
    const g1 = scoped.assigned_grants.find((g) => g.grant_id === "g1")!;
    const g2 = scoped.assigned_grants.find((g) => g.grant_id === "g2")!;
    expect(g1.data_key).not.toBe(g2.data_key);
    // g1's DEK cannot decrypt g2's ciphertext (different key AND different AAD).
    const g1Dek = fromBase64url(g1.data_key);
    expect(() => decrypt(g2.ciphertext, g1Dek)).toThrow();
  });

  it("a cloud node provisioned for node A cannot decrypt a grant wrapped for node B (cross-node bundle)", () => {
    const a = buildScopedBundle({ nodeId: "node-A" });
    const b = buildScopedBundle({ nodeId: "node-B" });
    // The node-A cloud node opens its OWN scoped secret; it never receives
    // node-B's delivery key, so it cannot even open node-B's scoped section.
    expect(() => openScopedSecret(b.built.bundle, a.deliveryKey)).toThrow();
  });

  it("UNASSIGNED home state encrypted under a home-only key the bundle never carries cannot be decrypted", () => {
    const { deliveryKey, built } = buildScopedBundle();
    const scoped = openScopedSecret(built.bundle, deliveryKey);
    // Whole-home / unassigned state is encrypted under a home-only DEK that is
    // NEVER placed in any bundle. The cloud node holds only its assigned DEKs.
    const homeOnlyDek = randomBytes(32);
    const unassigned = encrypt(stringToBytes("WHOLE HOME STATE"), homeOnlyDek);
    // The cloud node has no DEK for this ciphertext; every key it holds fails.
    for (const grant of scoped.assigned_grants) {
      const dek = fromBase64url(grant.data_key);
      expect(() => decrypt(unassigned, dek)).toThrow();
    }
    const unsealKey = fromBase64url(scoped.cloud_node_unseal_key);
    expect(() => decrypt(unassigned, unsealKey)).toThrow();
  });
});

describe("operator-cloud provision bundle, no root/issuer material", () => {
  it("the serialized bundle contains no master secret, master private key, or issuer private key", () => {
    const { built } = buildScopedBundle();
    expect(() => assertBundleHasNoRootMaterial(built.bundle)).not.toThrow();
    const serialized = JSON.stringify(built.bundle).toLowerCase();
    expect(serialized).not.toContain("master_secret");
    expect(serialized).not.toContain("master_private_key");
    expect(serialized).not.toContain("issuing_principal_private_key");
    expect(serialized).not.toContain("recovery_key");
    expect(serialized).not.toContain("guardian_share");
  });

  it("refuses a grant whose agent_id or namespace is outside the declared scope", () => {
    expect(() =>
      buildScopedBundle({
        agentIds: ["agent-a"],
        namespaces: ["ns-a"],
        grants: [
          { grant_id: "g1", agent_id: "agent-evil", namespace: "ns-a", plaintext: stringToBytes("x") },
        ],
      }),
    ).toThrow(/not in declared scope/);
  });
});

describe("operator-cloud join proof, anti-substitution binding (HIGH-1)", () => {
  it("the proof verifies for the exact nonce + pubkey + bundle digest", () => {
    const { proofKey, built } = buildScopedBundle();
    const nodePubkey = "AAAA".padEnd(43, "A"); // placeholder 32-byte-ish b64url
    const proof = computeOperatorCloudJoinProof({
      nodeJoinProofKey: proofKey,
      fortressId: built.bundle.manifest.fortress_id,
      nodeId: built.bundle.manifest.node_id,
      bootstrapNonce: built.bundle.manifest.bootstrap_token.nonce,
      nodePubkeyB64: nodePubkey,
      bundleDigest: built.digests.bundle_digest,
    });
    expect(
      verifyOperatorCloudJoinProof({
        nodeJoinProofKey: proofKey,
        fortressId: built.bundle.manifest.fortress_id,
        nodeId: built.bundle.manifest.node_id,
        bootstrapNonce: built.bundle.manifest.bootstrap_token.nonce,
        nodePubkeyB64: nodePubkey,
        bundleDigest: built.digests.bundle_digest,
        proof,
      }),
    ).toBe(true);
  });

  it("the proof FAILS under a substituted node pubkey (leaked-bundle defense)", () => {
    const { proofKey, built } = buildScopedBundle();
    const proof = computeOperatorCloudJoinProof({
      nodeJoinProofKey: proofKey,
      fortressId: built.bundle.manifest.fortress_id,
      nodeId: built.bundle.manifest.node_id,
      bootstrapNonce: built.bundle.manifest.bootstrap_token.nonce,
      nodePubkeyB64: "AAAA".padEnd(43, "A"),
      bundleDigest: built.digests.bundle_digest,
    });
    expect(
      verifyOperatorCloudJoinProof({
        nodeJoinProofKey: proofKey,
        fortressId: built.bundle.manifest.fortress_id,
        nodeId: built.bundle.manifest.node_id,
        bootstrapNonce: built.bundle.manifest.bootstrap_token.nonce,
        nodePubkeyB64: "BBBB".padEnd(43, "B"), // substituted pubkey
        bundleDigest: built.digests.bundle_digest,
        proof,
      }),
    ).toBe(false);
  });

  it("the proof FAILS under a substituted bundle digest", () => {
    const { proofKey, built } = buildScopedBundle();
    const pubkey = "AAAA".padEnd(43, "A");
    const proof = computeOperatorCloudJoinProof({
      nodeJoinProofKey: proofKey,
      fortressId: built.bundle.manifest.fortress_id,
      nodeId: built.bundle.manifest.node_id,
      bootstrapNonce: built.bundle.manifest.bootstrap_token.nonce,
      nodePubkeyB64: pubkey,
      bundleDigest: built.digests.bundle_digest,
    });
    expect(
      verifyOperatorCloudJoinProof({
        nodeJoinProofKey: proofKey,
        fortressId: built.bundle.manifest.fortress_id,
        nodeId: built.bundle.manifest.node_id,
        bootstrapNonce: built.bundle.manifest.bootstrap_token.nonce,
        nodePubkeyB64: pubkey,
        bundleDigest: "sha256:SUBSTITUTED",
        proof,
      }),
    ).toBe(false);
  });

  it("the bundle digest is reproducible from manifest + ciphertext + delivery target", () => {
    const { built } = buildScopedBundle();
    const recomputed = computeBundleDigest({
      manifestDigest: computeManifestDigest(built.bundle.manifest),
      scopedSecretCiphertextDigest: computeScopedSecretCiphertextDigest(built.bundle.scoped_secret),
      deliveryTarget: DELIVERY_TARGET,
    });
    expect(recomputed).toBe(built.digests.bundle_digest);
  });
});
