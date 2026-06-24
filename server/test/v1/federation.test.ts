/**
 * Federation PR-A3 — JoinCeremony unit tests.
 *
 * The join ceremony is the operator-authorized membership flow built on the
 * mesh lifecycle primitives. These tests pin: the bootstrap token it mints is
 * verifiable; the happy path issues a chain-valid node certificate; and every
 * unverifiable peer is DENIED (bad token signature, wrong fortress, bad HKDF
 * proof, node_mode mismatch, malformed key, operator-gate refusal) — fail
 * closed, signature/proof based, never shape based (CLAUDE.md constraint 4).
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "node:crypto";

import {
  assertNonIssuerContextHasNoIssuerAuthority,
  assertOperatorCloudContextHasNoIssuerAuthority,
  federationContextHasIssuerAuthority,
  JoinCeremony,
  type FederationContext,
} from "../../src/v1/federation.js";
import { verifyBootstrapToken } from "../../src/mesh/lifecycle/bootstrap-token.js";
import {
  issueNodeIdentityCertificate,
  verifyCertChain,
} from "../../src/mesh/trust-root.js";
import { createAutoDenyJoinApprover } from "../../src/mesh/lifecycle/join-approver.js";
import { generateKeypair } from "../../src/core/identity.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import {
  mintFederationTrustRootRecord,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  joinerContextFromRecord,
  type FederationJoinerTrustRootRecord,
} from "../../src/mesh/federation-joiner-trust-root-store.js";
import { makeFederationMaterials, assembleJoinRequest } from "./fed-materials.js";

const NODE_ID = "joining-node-7";

/** Build a real NON-ISSUER joiner record off a freshly minted issuer fortress. */
function buildJoinerRecord(): { record: FederationJoinerTrustRootRecord } {
  const home = mintFederationTrustRootRecord({ nodeId: "home-mac" });
  const node = generateKeypair();
  const principalPrivate = Uint8Array.from(home.issuing_principal_private_key);
  const masterPrivate = home.master_private_key
    ? Uint8Array.from(home.master_private_key)
    : undefined;
  if (!masterPrivate) throw new Error("home record must hold master private key");
  try {
    const issued = issueNodeIdentityCertificate({
      node_id: "joiner-linux",
      node_pubkey: node.publicKey,
      node_mode: "local",
      fortress_id: home.pinned_master_pubkey.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: home.pinned_master_pubkey.public_key,
        principal_id: home.issuing_principal_cert.principal_id,
        principal_pubkey: home.issuing_principal_cert.principal_pubkey,
      },
      principal_private_key: principalPrivate,
      master_private_key: masterPrivate,
    });
    return {
      record: {
        fortress_id: home.pinned_master_pubkey.fortress_id,
        node_id: "joiner-linux",
        pinned_master_pubkey: { ...home.pinned_master_pubkey },
        issuing_principal_cert: { ...home.issuing_principal_cert },
        local_node_cert: issued,
        local_node_private_key: Uint8Array.from(node.privateKey),
      },
    };
  } finally {
    node.privateKey.fill(0);
    principalPrivate.fill(0);
    masterPrivate.fill(0);
  }
}

function mintAndAssemble(materials = makeFederationMaterials()) {
  const ceremony = new JoinCeremony(materials.context);
  const token = ceremony.authorizeInit({
    intendedNodeId: NODE_ID,
    intendedNodeMode: "local",
  });
  const assembled = assembleJoinRequest({
    bootstrapToken: token,
    fortressMasterSecret: materials.masterSecret,
  });
  return { materials, ceremony, token, assembled };
}

describe("JoinCeremony.authorizeInit", () => {
  it("mints a bootstrap token that verifies against the issuing principal", () => {
    const { materials, token } = mintAndAssemble();
    expect(token.intended_node_id).toBe(NODE_ID);
    expect(token.fortress_id).toBe(materials.fortressId);
    expect(() =>
      verifyBootstrapToken({
        token,
        expected_fortress_id: materials.fortressId,
        issuing_principal_cert: materials.context.issuingPrincipalCert,
      }),
    ).not.toThrow();
  });
});

describe("JoinCeremony.authorizeComplete — happy path", () => {
  it("approves a well-formed JoinRequest and issues a chain-valid certificate", async () => {
    const { materials, ceremony, assembled } = mintAndAssemble();
    const outcome = await ceremony.authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(true);
    if (!outcome.approved) throw new Error("unreachable");
    expect(outcome.nodeId).toBe(NODE_ID);
    expect(outcome.certificate.node_id).toBe(NODE_ID);
    // The issued cert chains to the pinned fortress master via the principal.
    expect(() =>
      verifyCertChain(
        outcome.certificate,
        outcome.issuingPrincipalCert,
        materials.context.pinnedMasterPubkey,
      ),
    ).not.toThrow();
  });
});

describe("JoinCeremony.authorizeComplete — fail closed on unverifiable peers", () => {
  it("denies a tampered bootstrap-token signature", async () => {
    const { ceremony, assembled } = mintAndAssemble();
    const tampered = {
      ...assembled.joinRequest,
      bootstrap_token: {
        ...assembled.joinRequest.bootstrap_token,
        signature: assembled.joinRequest.bootstrap_token.signature.slice(0, -4) + "AAAA",
      },
    };
    const outcome = await ceremony.authorizeComplete(tampered);
    expect(outcome.approved).toBe(false);
  });

  it("denies a token whose fortress_id does not match this fortress", async () => {
    // A token minted by a DIFFERENT fortress, submitted here.
    const other = makeFederationMaterials();
    const otherCeremony = new JoinCeremony(other.context);
    const otherToken = otherCeremony.authorizeInit({
      intendedNodeId: NODE_ID,
      intendedNodeMode: "local",
    });
    const assembled = assembleJoinRequest({
      bootstrapToken: otherToken,
      fortressMasterSecret: other.masterSecret,
    });
    const ours = makeFederationMaterials();
    const outcome = await new JoinCeremony(ours.context).authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(false);
  });

  it("denies a request whose HKDF salt proof was computed under the wrong master secret", async () => {
    const { ceremony, token } = mintAndAssemble();
    // Joining node holds the bootstrap token but NOT the real master secret.
    const wrongSecret = randomBytes(32);
    const assembled = assembleJoinRequest({
      bootstrapToken: token,
      fortressMasterSecret: wrongSecret,
    });
    const outcome = await ceremony.authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(false);
    if (!outcome.approved) expect(outcome.denialReason).toMatch(/hkdf/i);
  });

  it("denies a node_mode that does not match the bootstrap token", async () => {
    const { ceremony, assembled } = mintAndAssemble();
    const mismatched = { ...assembled.joinRequest, node_mode: "operator_cloud" as const };
    const outcome = await ceremony.authorizeComplete(mismatched);
    expect(outcome.approved).toBe(false);
  });

  it("denies a malformed node_pubkey", async () => {
    const { ceremony, assembled } = mintAndAssemble();
    const bad = { ...assembled.joinRequest, node_pubkey: "!!not-base64url!!" };
    const outcome = await ceremony.authorizeComplete(bad);
    expect(outcome.approved).toBe(false);
  });

  it("respects an operator gate denial even when the request is crypto-valid", async () => {
    const materials = makeFederationMaterials({
      approver: createAutoDenyJoinApprover("policy refusal"),
    });
    const { ceremony, assembled } = mintAndAssemble(materials);
    const outcome = await ceremony.authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(false);
    if (!outcome.approved) expect(outcome.denialReason).toContain("policy refusal");
  });

  it("denies issuance when no operator approval gate is injected", async () => {
    const { materials, assembled } = mintAndAssemble();
    const { approver: _approver, ...withoutApprover } = materials.context;
    const outcome = await new JoinCeremony(
      withoutApprover as unknown as FederationContext,
    ).authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(false);
    if (!outcome.approved) expect(outcome.denialReason).toContain("approval gate unavailable");
  });

  it("operator-cloud non-issuer contexts cannot mint tokens or issue certs", async () => {
    const materials = makeFederationMaterials();
    const homeCeremony = new JoinCeremony(materials.context);
    const token = homeCeremony.authorizeInit({
      intendedNodeId: "another-node",
      intendedNodeMode: "local",
    });
    const assembled = assembleJoinRequest({
      bootstrapToken: token,
      fortressMasterSecret: materials.masterSecret,
    });
    const cloudContext: FederationContext = {
      fortressId: materials.fortressId,
      nodeId: "cloud-node-issuer-test",
      nodeMode: "operator_cloud",
      pinnedMasterPubkey: materials.context.pinnedMasterPubkey,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      isNodeRevoked: () => false,
    };

    expect(() => assertOperatorCloudContextHasNoIssuerAuthority(cloudContext)).not.toThrow();
    expect(() =>
      new JoinCeremony(cloudContext).authorizeInit({
        intendedNodeId: "forbidden-node",
        intendedNodeMode: "local",
      }),
    ).toThrow(/issuer authority unavailable/);

    const outcome = await new JoinCeremony(cloudContext).authorizeComplete(
      assembled.joinRequest,
    );
    expect(outcome.approved).toBe(false);
    if (!outcome.approved) expect(outcome.denialReason).toContain("issuer authority unavailable");
  });

  it("rejects operator-cloud contexts that carry issuer authority", () => {
    const materials = makeFederationMaterials();
    const invalidCloudContext = {
      ...materials.context,
      nodeMode: "operator_cloud",
    } as unknown as FederationContext;
    expect(() => assertOperatorCloudContextHasNoIssuerAuthority(invalidCloudContext)).toThrow(
      /must not carry issuer authority/,
    );
  });

  it("denies a wholly forged token (random signature, no real principal)", async () => {
    const { ceremony, assembled } = mintAndAssemble();
    const forged = {
      ...assembled.joinRequest,
      bootstrap_token: {
        ...assembled.joinRequest.bootstrap_token,
        signature: Buffer.from(randomBytes(64)).toString("base64url"),
      },
    };
    const outcome = await ceremony.authorizeComplete(forged);
    expect(outcome.approved).toBe(false);
  });
});

// Federation Slice 3a: the non-issuer guard generalizes from operator_cloud-only
// to ALL non-issuer node modes (a LOCAL joiner is non-issuer too). These pin
// that (b) a local-mode joiner context cannot mint/issue, and the generalized
// guard catches issuer-material leakage for a local node, while a legitimate
// local ISSUER context still passes untouched.
describe("Slice 3a — non-issuer guard generalization (local joiner)", () => {
  function localJoinerContext(): FederationContext {
    const { record } = buildJoinerRecord();
    return joinerContextFromRecord(record) as unknown as FederationContext;
  }

  it("a LOCAL joiner context (b): no issuer accessors, cannot authorizeInit", () => {
    const ctx = localJoinerContext();
    expect(ctx.nodeMode).toBe("local");
    const candidate = ctx as unknown as Record<string, unknown>;
    expect("getIssuingPrincipalPrivateKey" in candidate).toBe(false);
    expect("getFortressMasterSecret" in candidate).toBe(false);
    expect("approver" in candidate).toBe(false);
    expect(federationContextHasIssuerAuthority(ctx)).toBe(false);
    expect(() =>
      new JoinCeremony(ctx).authorizeInit({
        intendedNodeId: "x",
        intendedNodeMode: "local",
      }),
    ).toThrow(/issuer authority unavailable/);
  });

  it("a LOCAL joiner driving authorizeComplete is denied: issuer authority unavailable", async () => {
    const ctx = localJoinerContext();
    // Assemble a request against a separate real issuer; the local-joiner
    // daemon has no issuer authority to mint the transport key / run the gate.
    const issuer = makeFederationMaterials();
    const token = new JoinCeremony(issuer.context).authorizeInit({
      intendedNodeId: "n",
      intendedNodeMode: "local",
    });
    const assembled = assembleJoinRequest({
      bootstrapToken: token,
      fortressMasterSecret: issuer.masterSecret,
    });
    const outcome = await new JoinCeremony(ctx).authorizeComplete(
      assembled.joinRequest,
    );
    expect(outcome.approved).toBe(false);
  });

  it("the generalized guard PASSES a clean local joiner context", () => {
    expect(() =>
      assertNonIssuerContextHasNoIssuerAuthority(localJoinerContext()),
    ).not.toThrow();
  });

  it("the generalized guard REJECTS a local context carrying issuer authority", () => {
    const ctx = localJoinerContext() as unknown as Record<string, unknown>;
    ctx.getFortressMasterSecret = () => new Uint8Array(32);
    expect(() =>
      assertNonIssuerContextHasNoIssuerAuthority(
        ctx as unknown as FederationContext,
      ),
    ).toThrow(/non-issuer federation context must not carry issuer authority/);
  });

  it("the generalized guard leaves a legitimate local ISSUER context untouched", () => {
    const materials = makeFederationMaterials();
    // materials.context is a complete local issuer context (all accessors).
    expect(materials.context.nodeMode === "operator_cloud").toBe(false);
    expect(() =>
      assertNonIssuerContextHasNoIssuerAuthority(materials.context),
    ).not.toThrow();
    expect(federationContextHasIssuerAuthority(materials.context)).toBe(true);
  });
});
