/**
 * Tier 1 policy-config registration for `federation_node_join`.
 *
 * Satisfies the PR #30 review backlog item and the WP-MVP-2 spawn prompt's
 * AC4 requirement: join-approval MUST require operator-in-the-loop per Key 8.
 */

import { describe, expect, it } from "vitest";

import {
  DEFAULT_POLICY,
  parsePolicy,
} from "../../src/principal-policy/loader.js";
import {
  MeshConsoleClient,
  FEDERATION_NODE_JOIN_OPERATION,
} from "../../src/console/index.js";

describe("federation_node_join Tier 1 registration", () => {
  it("DEFAULT_POLICY.tier1_always_approve contains federation_node_join", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).toContain(
      FEDERATION_NODE_JOIN_OPERATION
    );
  });

  it("the console's operation name matches the Tier 1 entry", () => {
    expect(MeshConsoleClient.federationJoinOperation()).toBe(
      FEDERATION_NODE_JOIN_OPERATION
    );
  });

  it("parsePolicy round-trips the Tier 1 entry through JSON", () => {
    const json = JSON.stringify({
      version: 2,
      tier1_always_approve: ["state_export", FEDERATION_NODE_JOIN_OPERATION],
      tier2_anomaly: { new_counterparty: "approve" },
      tier3_always_allow: ["state_read"],
    });
    const parsed = parsePolicy(json);
    expect(parsed.tier1_always_approve).toContain(FEDERATION_NODE_JOIN_OPERATION);
  });

  it("the Tier 1 entry is NOT in Tier 3 (defense against drift)", () => {
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain(
      FEDERATION_NODE_JOIN_OPERATION
    );
  });
});
