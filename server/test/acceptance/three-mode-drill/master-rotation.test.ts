/**
 * §12.9 — Guardian-quorum master rotation preserves audit continuity
 * through the three-mode drill.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md §12.9,
 *       §9.3 (guardian-quorum reconstitution), §9.4 (cascade implications),
 *       §9.5 (audit continuity), Key 13 (recovery cascade integration).
 *
 * End-to-end flow exercised:
 *   1. Boot the real three-mode mesh (libp2p + Noise + gossipsub).
 *   2. Push + flush a pre-rotation audit batch per emitter (B, C) so the
 *      canonical log is non-empty.
 *   3. Issue a 3-of-5 GuardianRoster signed by the OLD fortress-master.
 *   4. Build + sign a master_rotation payload via the FU #3 primitives
 *      (buildMasterRotationPayload over a guardian-quorum signed input).
 *   5. Drive rotation: call MeshNode.installMasterRotation on all three
 *      nodes, and admit each peer's re-issued certificate.
 *   6. Assert cascade acceptance: every node pins the new master; per-node
 *      certs re-anchor under the new fortress-master; HKDF per-node audit-
 *      chain keys and transport keys re-derive.
 *   7. Push + flush a post-rotation audit batch per emitter (B, C).
 *   8. Walk the canonical log end-to-end with verifyAuditBatch, routing each
 *      batch to the correct fortress-master era (pre- or post-rotation) via
 *      batch_seq — the pre-rotation master verifies batches sealed before
 *      rotation; the post-rotation master verifies batches sealed after.
 *      Every batch in the walk must verify.
 */

import { afterEach, describe, expect, it } from "vitest";

import { generateKeypair } from "../../../src/core/identity.js";
import { toBase64url } from "../../../src/core/encoding.js";
import { verifyAuditBatch } from "../../../src/mesh/audit-batch.js";
import {
  deriveNodeAuditChainKey,
  deriveNodeTransportKey,
  verifyCertChain,
} from "../../../src/mesh/trust-root.js";
import {
  acceptMasterRotation,
  buildGuardianMasterRotationQuorumInput,
  buildMasterRotationPayload,
  mintRevokeCollectionContext,
  issueGuardianRoster,
  rekeyOnMasterRotation,
  signMasterRotationAsGuardian,
  type GuardianIdentity,
} from "../../../src/mesh/guardian/index.js";
import type {
  AuditBatch,
  FortressMasterPublicKey,
  NodeIdentityCertificate,
} from "../../../src/mesh/types.js";

import {
  bootThreeModeDrill,
  type ThreeModeDrillHandle,
  waitFor,
} from "./harness.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

describe("three-mode-drill §12.9 — master rotation preserves audit continuity", () => {
  it(
    "drives a 3-of-5 guardian quorum rotation through all three nodes; cert chain, HKDF subkeys, and audit log all re-verify end-to-end",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      // ── 1. Pre-rotation audit batches from B and C ────────────────────
      drill.nodeB.pushAuditEntry({
        emitter_agent: "drill-agent-b",
        emitter_principal: drill.root_principal_cert.principal_id,
        policy_version: 0,
        attestation_state: "verified",
        payload: { era: "pre", from: "B", drill: "§12.9" },
      });
      await drill.nodeB.flushAuditBuffer(drill.nodeIdA);
      drill.nodeC.pushAuditEntry({
        emitter_agent: "drill-agent-c",
        emitter_principal: drill.root_principal_cert.principal_id,
        policy_version: 0,
        attestation_state: "verified",
        payload: { era: "pre", from: "C", drill: "§12.9" },
      });
      await drill.nodeC.flushAuditBuffer(drill.nodeIdA);
      await waitFor(
        () => drill.nodeA.getCanonicalAuditSize() >= 2,
        15_000,
        50,
        "canonical log ingests the two pre-rotation batches"
      );

      // ── 2. Issue a 3-of-5 guardian roster under the OLD master ────────
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
        fortress_id: drill.master_public.fortress_id,
        version: 1,
        master_private_key: drill.master_private_key,
      });

      // ── 3. Build + sign the master_rotation payload ───────────────────
      const newMasterKp = generateKeypair();
      const newMasterPublic: FortressMasterPublicKey = {
        public_key: toBase64url(newMasterKp.publicKey),
        fortress_id: drill.master_public.fortress_id,
        created_at: new Date().toISOString(),
      };
      // QI-SIBLING-02: collection window minted before signing; every relying
      // site re-checks it with its own clock.
      const quorumContext = mintRevokeCollectionContext();
      const rotatedAt = new Date().toISOString();
      const rotationInput = buildGuardianMasterRotationQuorumInput({
        context: quorumContext,
        old_master_pubkey: drill.master_public.public_key,
        new_master_pubkey: newMasterPublic,
        rotated_at: rotatedAt,
        fortress_id: drill.master_public.fortress_id,
      });
      const quorumSigs = guardians.slice(0, 3).map((g) =>
        signMasterRotationAsGuardian({
          input: rotationInput,
          guardian_id: g.identity.guardian_id,
          guardian_private_key: g.sk,
        })
      );
      const payload = buildMasterRotationPayload({
        quorum_context: quorumContext,
        old_master_pubkey: drill.master_public.public_key,
        new_master_pubkey: newMasterPublic,
        rotated_at: rotatedAt,
        fortress_id: drill.master_public.fortress_id,
        guardian_signatures: quorumSigs,
        pinned_roster: roster,
      });

      // Sanity: quorum itself verifies before we drive it through the cascade.
      acceptMasterRotation({
        payload,
        pinned_master: drill.master_public,
        pinned_roster: roster,
        now: new Date(),
      });

      // ── 4. Cascade re-key: re-issue all three certs + new root principal
      const newRootPrincipalKp = generateKeypair();
      const cascade = rekeyOnMasterRotation({
        new_master_secret: newMasterKp.privateKey,
        new_master_public: newMasterPublic,
        old_node_certificates: [
          drill.nodeCertA,
          drill.nodeCertB,
          drill.nodeCertC,
        ],
        old_root_principal: drill.root_principal_cert,
        new_root_principal_private_key: newRootPrincipalKp.privateKey,
        new_root_principal_public_key: newRootPrincipalKp.publicKey,
      });

      const newCertOf = (
        id: string
      ): NodeIdentityCertificate => {
        const c = cascade.re_issued_node_certificates.find(
          (x) => x.node_id === id
        );
        if (!c) throw new Error(`no re-issued cert for ${id}`);
        return c;
      };

      // ── 5. Install rotation on every node ─────────────────────────────
      const installResults = [
        {
          id: drill.nodeIdA,
          node: drill.nodeA,
          boundary: drill.nodeA.installMasterRotation({
            payload,
            new_master_secret: newMasterKp.privateKey,
            re_issued_self_cert: newCertOf(drill.nodeIdA),
            new_root_principal_cert: cascade.new_root_principal_certificate,
          }),
        },
        {
          id: drill.nodeIdB,
          node: drill.nodeB,
          boundary: drill.nodeB.installMasterRotation({
            payload,
            new_master_secret: newMasterKp.privateKey,
            re_issued_self_cert: newCertOf(drill.nodeIdB),
            new_root_principal_cert: cascade.new_root_principal_certificate,
          }),
        },
        {
          id: drill.nodeIdC,
          node: drill.nodeC,
          boundary: drill.nodeC.installMasterRotation({
            payload,
            new_master_secret: newMasterKp.privateKey,
            re_issued_self_cert: newCertOf(drill.nodeIdC),
            new_root_principal_cert: cascade.new_root_principal_certificate,
          }),
        },
      ];

      // Every install emits a master_rotation_boundary audit entry signed
      // with ed25519-v1 — the operator-visible record of the rotation point.
      for (const r of installResults) {
        expect(r.boundary.boundary_entry.signature_scheme).toBe(
          "ed25519-v1"
        );
        expect(
          (r.boundary.boundary_entry.payload as { kind: string }).kind
        ).toBe("master_rotation_boundary");
      }

      // Each node must admit every peer's re-issued certificate so post-
      // rotation envelope verification resolves to the new-master-anchored
      // cert chain. `admitPeerCertificate` re-runs verifyCertChain against
      // the node's newly-pinned master. v0.1 API: one call per peer per node.
      for (const node of [drill.nodeA, drill.nodeB, drill.nodeC]) {
        for (const peerId of [drill.nodeIdA, drill.nodeIdB, drill.nodeIdC]) {
          if (peerId === (node === drill.nodeA ? drill.nodeIdA : node === drill.nodeB ? drill.nodeIdB : drill.nodeIdC)) {
            continue; // self already swapped by installMasterRotation
          }
          node.admitPeerCertificate({
            certificate: newCertOf(peerId),
            issuing_principal_cert: cascade.new_root_principal_certificate,
          });
        }
      }

      // ── 6. Cascade assertions ─────────────────────────────────────────
      // (a) Every node pins the new master.
      for (const node of [drill.nodeA, drill.nodeB, drill.nodeC]) {
        expect(node.getPinnedMaster().public_key).toBe(
          newMasterPublic.public_key
        );
      }
      // (b) Every node's own cert re-anchors under the new master.
      for (const { node, id } of [
        { node: drill.nodeA, id: drill.nodeIdA },
        { node: drill.nodeB, id: drill.nodeIdB },
        { node: drill.nodeC, id: drill.nodeIdC },
      ]) {
        const ownCert = node.getOwnCertificate()!;
        expect(ownCert.node_id).toBe(id);
        expect(ownCert.parent_chain.fortress_master_pubkey).toBe(
          newMasterPublic.public_key
        );
        expect(() =>
          verifyCertChain(
            ownCert,
            cascade.new_root_principal_certificate,
            newMasterPublic
          )
        ).not.toThrow();
      }
      // (c) Per-node audit-chain + transport keys re-derive under the new
      //     master. The cascade map records the re-derivation; asserting
      //     that `deriveNodeAuditChainKey` + `deriveNodeTransportKey` with
      //     the new master secret yield byte-identical material confirms
      //     every node re-keys deterministically from the new secret.
      for (const id of [drill.nodeIdA, drill.nodeIdB, drill.nodeIdC]) {
        const cascadeAuditKey = cascade.re_derived_audit_chain_keys.get(id)!;
        const freshAuditKey = deriveNodeAuditChainKey({
          fortress_master_secret: newMasterKp.privateKey,
          node_id: id,
        });
        expect(Buffer.from(cascadeAuditKey)).toEqual(
          Buffer.from(freshAuditKey)
        );
        const cascadeTransportKey =
          cascade.re_derived_transport_keys.get(id)!;
        const peerCert = newCertOf(id);
        const freshTransportKey = deriveNodeTransportKey({
          fortress_master_secret: newMasterKp.privateKey,
          node_id: id,
          node_mode: peerCert.node_mode,
        });
        expect(Buffer.from(cascadeTransportKey)).toEqual(
          Buffer.from(freshTransportKey)
        );
      }

      // ── 7. Post-rotation audit batches from B and C ───────────────────
      // B and C push + flush. Each flush will include the master_rotation
      // boundary entry (pushed into the buffer by installMasterRotation)
      // plus the new user entry — all sealed under the NEW chain key.
      drill.nodeB.pushAuditEntry({
        emitter_agent: "drill-agent-b",
        emitter_principal: drill.root_principal_cert.principal_id,
        policy_version: 0,
        attestation_state: "verified",
        payload: { era: "post", from: "B", drill: "§12.9" },
      });
      await drill.nodeB.flushAuditBuffer(drill.nodeIdA);
      drill.nodeC.pushAuditEntry({
        emitter_agent: "drill-agent-c",
        emitter_principal: drill.root_principal_cert.principal_id,
        policy_version: 0,
        attestation_state: "verified",
        payload: { era: "post", from: "C", drill: "§12.9" },
      });
      await drill.nodeC.flushAuditBuffer(drill.nodeIdA);
      await waitFor(
        () => drill.nodeA.getCanonicalAuditSize() >= 4,
        15_000,
        50,
        "canonical log ingests the two post-rotation batches"
      );

      // ── 8. Audit-continuity walk ──────────────────────────────────────
      // Walk every batch the canonical log holds, routing each to the
      // fortress-master era that sealed it. Pre-rotation batches (batch_seq
      // === 0 per emitter) verify under the OLD master + OLD per-node audit
      // chain key + old node + old root-principal certs. Post-rotation
      // batches (batch_seq >= 1) verify under the new material. Every batch
      // must verify end-to-end. A single `verifyAuditBatch` throw fails the
      // assertion.
      const batches = drill.nodeA.getCanonicalAuditLog()!.snapshot();
      expect(batches.length).toBeGreaterThanOrEqual(4);

      const oldMaster = drill.master_public;
      const oldMasterSecret = drill.master_private_key;
      const oldRootPrincipal = drill.root_principal_cert;
      const oldCertByNode = new Map<string, NodeIdentityCertificate>([
        [drill.nodeIdA, drill.nodeCertA],
        [drill.nodeIdB, drill.nodeCertB],
        [drill.nodeIdC, drill.nodeCertC],
      ]);
      const newRootPrincipal = cascade.new_root_principal_certificate;

      const previousByEmitter = new Map<string, AuditBatch>();
      let preVerified = 0;
      let postVerified = 0;
      for (const batch of batches) {
        const isPre = batch.batch_seq === 0;
        const masterPublic = isPre ? oldMaster : newMasterPublic;
        const masterSecret = isPre ? oldMasterSecret : newMasterKp.privateKey;
        const rootPrincipal = isPre ? oldRootPrincipal : newRootPrincipal;
        const auditChainKey = deriveNodeAuditChainKey({
          fortress_master_secret: masterSecret,
          node_id: batch.emitter_node,
        });
        const nodeCert = isPre
          ? oldCertByNode.get(batch.emitter_node)
          : newCertOf(batch.emitter_node);
        expect(nodeCert).toBeDefined();

        verifyAuditBatch(batch, {
          pinnedMasterPubkey: masterPublic,
          lookupNodeCert: (id) =>
            id === batch.emitter_node ? nodeCert : undefined,
          lookupPrincipalCert: (id) =>
            id === rootPrincipal.principal_id ? rootPrincipal : undefined,
          lookupAuditChainKey: () => auditChainKey,
          lookupPreviousBatch: (id) =>
            previousByEmitter.get(id) ?? null,
        });
        previousByEmitter.set(batch.emitter_node, batch);
        if (isPre) preVerified += 1;
        else postVerified += 1;
      }
      // Two pre-rotation + two post-rotation batches must each have
      // verified — criterion §12.9 "audit continuity holds across the
      // rotation boundary."
      expect(preVerified).toBe(2);
      expect(postVerified).toBe(2);

      // Every entry across the walk declares ed25519-v1 — the crypto-
      // agility single-source-of-truth invariant.
      for (const batch of batches) {
        for (const entry of batch.entries) {
          expect(entry.signature_scheme).toBe("ed25519-v1");
        }
      }

      // The post-rotation batches must include the master_rotation boundary
      // entry that installMasterRotation pushed into each emitter's buffer
      // — the operator-visible rotation marker that audit-walkers use to
      // pivot between eras.
      const postBatches = batches.filter((b) => b.batch_seq >= 1);
      const boundaryCount = postBatches.reduce(
        (acc, b) =>
          acc +
          b.entries.filter(
            (e) =>
              (e.payload as { kind?: string } | null)?.kind ===
              "master_rotation_boundary"
          ).length,
        0
      );
      expect(boundaryCount).toBeGreaterThanOrEqual(2);
    },
    180_000
  );
});
