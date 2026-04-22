/**
 * §12.4 — Audit continuity across emitters in the canonical log.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md §12.4,
 *       §5.2 (audit batch cadence), §5.3 (crypto-agility).
 *
 * Emitter nodes seal local audit batches periodically and unicast them to the
 * canonical audit node (node A in this drill). The canonical node runs
 * `verifyAuditBatch` on each one — which enforces HKDF chain proof (each
 * emitter's per-node audit-chain key HKDF-derived from the fortress-master),
 * per-emitter prev-batch-hash continuity, strict-monotonic `batch_seq`, and
 * Ed25519 signature on the batch body.
 *
 * This test drives real audit batches from nodes B and C (both non-canonical)
 * through the real libp2p wire to node A. It covers ≥ 3 batch intervals
 * across at least 2 emitters (per spec §5.2 / acceptance §12 criterion 5).
 *
 * A's own audit entries are not exercised here: the canonical node's
 * `flushAuditBuffer(self_id)` relies on transport self-unicast, which is a
 * v0.1 API shape the harness deliberately does not drive (Follow-up #3 scope
 * — see §8 operator-surface work). Flagged in the handoff as a carry-forward
 * observation.
 */

import { afterEach, describe, expect, it } from "vitest";

import { deriveNodeAuditChainKey } from "../../../src/mesh/trust-root.js";
import { verifyAuditBatch } from "../../../src/mesh/audit-batch.js";

import { bootThreeModeDrill, type ThreeModeDrillHandle, waitFor } from "./harness.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

describe("three-mode-drill §12.4 — audit batches from B and C verify on A's canonical log", () => {
  it(
    "drives ≥ 3 batches across 2 emitters; every batch verifies end-to-end with chain continuity",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      // ── Push entries + flush on B three times (three batches) ─────────
      for (let round = 0; round < 3; round++) {
        for (let j = 0; j < 2; j++) {
          drill.nodeB.pushAuditEntry({
            emitter_agent: "drill-agent-b",
            emitter_principal: drill.root_principal_cert.principal_id,
            policy_version: 0,
            attestation_state: "verified",
            payload: { round, j, from: "B", drill: "§12.4" },
          });
        }
        await drill.nodeB.flushAuditBuffer(drill.nodeIdA);
      }

      // ── Push entries + flush on C twice (two batches) ─────────────────
      for (let round = 0; round < 2; round++) {
        drill.nodeC.pushAuditEntry({
          emitter_agent: "drill-agent-c",
          emitter_principal: drill.root_principal_cert.principal_id,
          policy_version: 0,
          attestation_state: "verified",
          payload: { round, from: "C", drill: "§12.4" },
        });
        await drill.nodeC.flushAuditBuffer(drill.nodeIdA);
      }

      // ── Wait until A's canonical log has every expected batch ─────────
      await waitFor(
        () => {
          return drill.nodeA.getCanonicalAuditSize() >= 5;
        },
        15_000,
        50,
        "canonical audit log ingests 5 batches"
      );

      // ── Walk the canonical log; verify each batch end-to-end ──────────
      const log = drill.nodeA.getCanonicalAuditLog();
      expect(log).toBeDefined();
      const batches = log!.snapshot();
      expect(batches.length).toBeGreaterThanOrEqual(5);

      // Per-emitter chain state — `verifyAuditBatch` needs the previous
      // batch in emitter-order to verify prev_batch_hash continuity.
      const previousByEmitter = new Map<string, typeof batches[number]>();
      for (const batch of batches) {
        const auditChainKey = deriveNodeAuditChainKey({
          fortress_master_secret: drill.master_private_key,
          node_id: batch.emitter_node,
        });
        const emitterCert = drill.nodeA
          .getRoster()
          .lookupNodeCert(batch.emitter_node);
        expect(emitterCert).toBeDefined();

        // Throws on signature / HKDF-proof / rollback / chain-discontinuity.
        verifyAuditBatch(batch, {
          pinnedMasterPubkey: drill.master_public,
          lookupNodeCert: (id: string) =>
            drill.nodeA.getRoster().lookupNodeCert(id),
          lookupPrincipalCert: (id: string) =>
            id === drill.root_principal_cert.principal_id
              ? drill.root_principal_cert
              : undefined,
          lookupAuditChainKey: () => auditChainKey,
          lookupPreviousBatch: (id: string) =>
            previousByEmitter.get(id) ?? null,
        });
        previousByEmitter.set(batch.emitter_node, batch);
      }

      // Per-emitter `batch_seq` is strictly monotonic — B has 3, C has 2.
      const bBatches = batches.filter((b) => b.emitter_node === drill.nodeIdB);
      const cBatches = batches.filter((b) => b.emitter_node === drill.nodeIdC);
      expect(bBatches).toHaveLength(3);
      expect(cBatches).toHaveLength(2);
      for (let i = 1; i < bBatches.length; i++) {
        expect(bBatches[i].batch_seq).toBe(bBatches[i - 1].batch_seq + 1);
      }
      for (let i = 1; i < cBatches.length; i++) {
        expect(cBatches[i].batch_seq).toBe(cBatches[i - 1].batch_seq + 1);
      }

      // Every batch carries the crypto-agility-bearing signature_scheme on
      // its entries — the single-source-of-truth `signature_scheme:
      // "ed25519-v1"` field.
      for (const batch of batches) {
        for (const entry of batch.entries) {
          expect(entry.signature_scheme).toBe("ed25519-v1");
        }
      }
    },
    90_000
  );
});
