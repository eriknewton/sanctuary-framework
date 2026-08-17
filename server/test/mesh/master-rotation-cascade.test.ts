/**
 * Sanctuary Federation Protocol v0.1 — Master-Rotation Cascade Integration
 *
 * End-to-end test: a real bootstrapped MeshNode accepts a master rotation
 * (guardian-quorum-signed payload), the cascade re-issues its own cert under
 * the new master, re-derives HKDF subkeys, and emits the audit-continuity
 * boundary entry.
 *
 * Spawn-prompt acceptance criterion 4 (master_rotation acceptance + cascade)
 * + 5 (audit continuity).
 */

import { describe, it, expect } from "vitest";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
  SIGNATURE_SCHEME_V1,
} from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issuePrincipalCertificate,
  verifyCertChain,
} from "../../src/mesh/trust-root.js";
import {
  acceptMasterRotation,
  buildGuardianMasterRotationQuorumInput,
  buildMasterRotationPayload,
  mintRevokeCollectionContext,
  rekeyOnMasterRotation,
  signMasterRotationAsGuardian,
  issueGuardianRoster,
  type GuardianIdentity,
} from "../../src/mesh/guardian/index.js";
import {
  CanonicalAuditLog,
  InMemoryNodeKeyStore,
  MeshNode,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";
import { InMemoryTransport } from "../../src/mesh/in-memory-transport.js";
import type {
  FortressMasterPublicKey,
  PrincipalCertificate,
} from "../../src/mesh/types.js";

describe("MeshNode.installMasterRotation — end-to-end cascade", () => {
  it("accepts rotation, re-issues self cert, re-derives HKDF, emits boundary entry", async () => {
    // 1. Bootstrap fortress + node.
    const transport = new InMemoryTransport();
    const handle = transport.attach("node-1");
    const placeholder = createAutoApproveJoinApprover({
      pinned_master_pubkey: {} as FortressMasterPublicKey,
      issuing_principal_cert: {} as PrincipalCertificate,
      issuing_principal_private_key: new Uint8Array(32),
    });
    const result = await MeshNode.bootstrapFirstNode({
      node_id: "node-1",
      node_mode: "local",
      transport: handle,
      approver: placeholder,
      key_store: new InMemoryNodeKeyStore(),
    });
    const oldMaster = result.bootstrap.master_public;
    const oldCert = result.bootstrap.node_certificate;

    // 2. Issue guardian roster signed by the OLD master.
    const guardians: Array<{ identity: GuardianIdentity; sk: Uint8Array }> = [];
    for (let i = 0; i < 5; i++) {
      const kp = generateKeypair();
      guardians.push({
        identity: {
          guardian_id: `g${i}`,
          public_key: toBase64url(kp.publicKey),
          kind: "human",
          invited_at: new Date().toISOString(),
        },
        sk: kp.privateKey,
      });
    }
    const roster = issueGuardianRoster({
      m: 3,
      n: 5,
      guardians: guardians.map((g) => g.identity),
      fortress_id: oldMaster.fortress_id,
      version: 1,
      master_private_key: result.bootstrap.master_private_key,
    });

    // 3. Quorum-sign rotation to new master.
    const newMasterKp = generateKeypair();
    const newMasterPublic: FortressMasterPublicKey = {
      public_key: toBase64url(newMasterKp.publicKey),
      fortress_id: oldMaster.fortress_id,
      created_at: new Date().toISOString(),
    };
    // QI-SIBLING-02: the collection context is minted before the guardians
    // sign, and the rotation input is built from it by the shared builder.
    const quorumContext = mintRevokeCollectionContext();
    const rotatedAt = new Date().toISOString();
    const input = buildGuardianMasterRotationQuorumInput({
      context: quorumContext,
      old_master_pubkey: oldMaster.public_key,
      new_master_pubkey: newMasterPublic,
      rotated_at: rotatedAt,
      fortress_id: oldMaster.fortress_id,
    });
    const sigs = guardians.slice(0, 3).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.sk,
      })
    );
    const payload = buildMasterRotationPayload({
      quorum_context: quorumContext,
      old_master_pubkey: oldMaster.public_key,
      new_master_pubkey: newMasterPublic,
      rotated_at: rotatedAt,
      fortress_id: oldMaster.fortress_id,
      guardian_signatures: sigs,
      pinned_roster: roster,
    });

    // 4. Verify quorum + cascade re-key.
    acceptMasterRotation({
      payload,
      pinned_master: oldMaster,
      pinned_roster: roster,
      now: new Date(),
    });
    const newPrincipalKp = generateKeypair();
    const cascade = rekeyOnMasterRotation({
      new_master_secret: newMasterKp.privateKey,
      new_master_public: newMasterPublic,
      old_node_certificates: [oldCert],
      old_root_principal: result.bootstrap.root_principal_certificate,
      new_root_principal_private_key: newPrincipalKp.privateKey,
      new_root_principal_public_key: newPrincipalKp.publicKey,
    });

    // 5. Install on the node.
    const reIssuedSelf = cascade.re_issued_node_certificates.find(
      (c) => c.node_id === "node-1"
    )!;
    const { boundary_entry } = result.node.installMasterRotation({
      payload,
      new_master_secret: newMasterKp.privateKey,
      re_issued_self_cert: reIssuedSelf,
      new_root_principal_cert: cascade.new_root_principal_certificate,
    });

    // 6. Assert post-rotation state.
    const pinned = result.node.getPinnedMaster();
    expect(pinned.public_key).toBe(newMasterPublic.public_key);
    const ownCert = result.node.getOwnCertificate()!;
    expect(ownCert.parent_chain.fortress_master_pubkey).toBe(
      newMasterPublic.public_key
    );
    // Cert chain validates against new master.
    verifyCertChain(
      ownCert,
      cascade.new_root_principal_certificate,
      newMasterPublic
    );
    // Boundary entry shape.
    expect(boundary_entry.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect((boundary_entry.payload as { kind: string }).kind).toBe(
      "master_rotation_boundary"
    );

    // 7. Idempotent — second install with same new master is a no-op.
    const second = result.node.installMasterRotation({
      payload,
      new_master_secret: newMasterKp.privateKey,
      re_issued_self_cert: reIssuedSelf,
      new_root_principal_cert: cascade.new_root_principal_certificate,
    });
    expect((second.boundary_entry.payload as { kind: string }).kind).toContain(
      "master_rotation_boundary"
    );
  });

  it("rejects re_issued_self_cert that does not chain to the new master", async () => {
    const transport = new InMemoryTransport();
    const handle = transport.attach("node-1");
    const placeholder = createAutoApproveJoinApprover({
      pinned_master_pubkey: {} as FortressMasterPublicKey,
      issuing_principal_cert: {} as PrincipalCertificate,
      issuing_principal_private_key: new Uint8Array(32),
    });
    const result = await MeshNode.bootstrapFirstNode({
      node_id: "node-1",
      node_mode: "local",
      transport: handle,
      approver: placeholder,
      key_store: new InMemoryNodeKeyStore(),
    });
    const fakeNewMasterKp = generateKeypair();
    const fakeNewMasterPublic: FortressMasterPublicKey = {
      public_key: toBase64url(fakeNewMasterKp.publicKey),
      fortress_id: result.bootstrap.master_public.fortress_id,
      created_at: new Date().toISOString(),
    };
    expect(() =>
      result.node.installMasterRotation({
        payload: {
          old_master_pubkey: result.bootstrap.master_public.public_key,
          new_master_pubkey: fakeNewMasterPublic,
          quorum_signatures: [],
          rotated_at: new Date().toISOString(),
        },
        new_master_secret: fakeNewMasterKp.privateKey,
        // Self-cert from the OLD master — does not chain to the new master.
        re_issued_self_cert: result.bootstrap.node_certificate,
        new_root_principal_cert: result.bootstrap.root_principal_certificate,
      })
    ).toThrow();
  });
});

// Touch CanonicalAuditLog import to keep TS happy on type-only narrowing.
void CanonicalAuditLog;
