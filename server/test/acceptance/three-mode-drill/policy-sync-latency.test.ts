/**
 * §12.3 - Policy-update fan-out within 5 seconds of the authoring emit.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md §12.3
 *
 *   "A policy edit is authored and signed on one node. Within 5 seconds on
 *    a healthy mesh, every other node has applied the policy-version update
 *    to its PolicyBundleStore."
 *
 * The test emits a real signed `policy_update` event via
 * `MeshNode.publishPolicyUpdate` on node A, starting a wall-clock timer at
 * emit. It waits until nodes B and C both have the new version in their
 * version vector, then asserts the elapsed is strictly less than the §12.3
 * 5-second budget. `DEFAULTS.POLICY_DISTRIBUTION_DEADLINE_MS` is the single
 * source of truth for the deadline - the constant is what the spec binds.
 */

import { afterEach, describe, expect, it } from "vitest";

import { DEFAULTS } from "../../../src/mesh/constants.js";

import { bootThreeModeDrill, type ThreeModeDrillHandle, waitFor } from "./harness.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

describe("three-mode-drill §12.3 - policy update fan-out ≤ 5s on loopback", () => {
  it(
    "policy emitted on node A applies on B and C within POLICY_DISTRIBUTION_DEADLINE_MS",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      const agentId = "drill-agent-policy-1";
      const policyBlob = Buffer.from(
        JSON.stringify({ drill: "§12.3", rule: "allow_memory_read" })
      ).toString("base64");

      const started = Date.now();
      const evt = await drill.nodeA.publishPolicyUpdate({
        payload: {
          agent_id: agentId,
          policy_version: 1,
          valid_from: "2026-06-01T00:00:00.000Z",
          valid_until: "2099-01-01T00:00:00.000Z",
          policy_blob: policyBlob,
        },
        principal_private_key: drill.root_principal_keypair.privateKey,
        emitter_principal: drill.root_principal_cert.principal_id,
      });
      expect(evt.event_type).toBe("policy_update");

      await waitFor(
        () => {
          const bSeesIt =
            drill.nodeB.getPolicyBundle().versionOf(agentId) === 1;
          const cSeesIt =
            drill.nodeC.getPolicyBundle().versionOf(agentId) === 1;
          return bSeesIt && cSeesIt;
        },
        DEFAULTS.POLICY_DISTRIBUTION_DEADLINE_MS,
        25,
        "policy update distributes to B and C"
      );

      const elapsed = Date.now() - started;
      // Contract: must hold strictly under the §12.3 5-second deadline.
      expect(elapsed).toBeLessThan(DEFAULTS.POLICY_DISTRIBUTION_DEADLINE_MS);

      // Every node's policy bundle agrees on the version vector now.
      expect(drill.nodeA.getPolicyBundle().versionVector()[agentId]).toBe(1);
      expect(drill.nodeB.getPolicyBundle().versionVector()[agentId]).toBe(1);
      expect(drill.nodeC.getPolicyBundle().versionVector()[agentId]).toBe(1);
    },
    60_000
  );
});
