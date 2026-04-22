/**
 * §12.2 — Per-node certificate chain anchoring.
 * §12.7 — `node_revoke` propagation within one heartbeat cycle.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md §12.2, §12.7
 *
 * §12.2 asserts every node's cert verifies against the pinned fortress-
 * master, chaining through the signing principal, using the same
 * `verifyCertChain` that the mesh uses internally. §12.7 asserts a signed
 * `node_revoke` event propagates over gossipsub to every non-revoked node's
 * roster within a heartbeat interval + grace, not just on the emitter.
 *
 * The spec's acceptance ceiling for revoke propagation is one heartbeat cycle
 * (`DEFAULTS.HEARTBEAT_INTERVAL_MS` = 30s on v0.1) plus a grace margin;
 * observed time on loopback is well under 1s, but the ceiling is the
 * contract.
 */

import { afterEach, describe, expect, it } from "vitest";

import { DEFAULTS } from "../../../src/mesh/constants.js";
import { verifyCertChain } from "../../../src/mesh/trust-root.js";

import { bootThreeModeDrill, type ThreeModeDrillHandle, waitFor } from "./harness.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

describe("three-mode-drill §12.2 — per-node cert chain anchors to fortress-master", () => {
  it(
    "every node cert on every roster verifies through the issuing principal back to the pinned master",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      // A principal lookup map so the test can locate each cert's issuer.
      // v0.1 fortress uses a single root principal; future v1.x partner
      // principals would mean a larger table here.
      const principalByCert = (_cert: {
        parent_chain: { principal_id: string };
      }) => drill.root_principal_cert;

      for (const node of [drill.nodeA, drill.nodeB, drill.nodeC]) {
        const entries = node.getRoster().listAll();
        expect(entries).toHaveLength(3);
        for (const entry of entries) {
          // verifyCertChain throws on any mismatch in signature, fortress-id,
          // or master-pubkey pin. The positive assertion is "did not throw."
          expect(() =>
            verifyCertChain(
              entry.certificate,
              principalByCert(entry.certificate),
              drill.master_public
            )
          ).not.toThrow();
        }
      }

      // Sovereign-TEE cert carries a mock attestation hash; `tee_attestation_hash`
      // is required for node_mode === "sovereign_tee" and MUST be absent for
      // the other two modes.
      expect(drill.nodeCertA.tee_attestation_hash).toBeUndefined();
      expect(drill.nodeCertB.tee_attestation_hash).toBeUndefined();
      expect(drill.nodeCertC.tee_attestation_hash).toBeDefined();
    },
    90_000
  );
});

describe("three-mode-drill §12.7 — node_revoke propagates within one heartbeat cycle", () => {
  it(
    "node A revokes node B; nodes A and C exclude B from their rosters within the heartbeat ceiling",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      // Revoke propagation timer starts at `revokePeer` — the method
      // simultaneously broadcasts `node_revoke` on gossipsub and marks the
      // local roster revoked.
      const started = Date.now();
      await drill.nodeA.revokePeer({
        target_node_id: drill.nodeIdB,
        reason: "drill: §12.7 revoke test",
      });
      expect(drill.nodeA.getRoster().presenceOf(drill.nodeIdB)).toBe("revoked");

      // Node C receives the revoke event via gossipsub, runs
      // `router.register("node_revoke", …)` which calls
      // `roster.markRevoked(nodeIdB)`. Wait until C's roster excludes B.
      await waitFor(
        () => drill.nodeC.getRoster().presenceOf(drill.nodeIdB) === "revoked",
        DEFAULTS.HEARTBEAT_INTERVAL_MS + 5_000,
        50,
        "node C's roster marks B revoked"
      );
      const elapsed = Date.now() - started;

      // Contract: within one heartbeat cycle + grace.
      expect(elapsed).toBeLessThanOrEqual(
        DEFAULTS.HEARTBEAT_INTERVAL_MS + 5_000
      );
      expect(drill.nodeC.getRoster().presenceOf(drill.nodeIdB)).toBe("revoked");

      // `lookupActiveNodeCert(B)` returns undefined post-revoke on both
      // non-B nodes — which is what makes envelope-verification for any
      // future B-emitted event fail at dispatch.
      expect(drill.nodeA.getRoster().lookupActiveNodeCert(drill.nodeIdB)).toBeUndefined();
      expect(drill.nodeC.getRoster().lookupActiveNodeCert(drill.nodeIdB)).toBeUndefined();
    },
    90_000
  );
});
