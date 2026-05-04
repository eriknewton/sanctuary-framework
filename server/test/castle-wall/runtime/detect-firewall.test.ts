/**
 * Castle Wall E7.2 detect-and-namespace tests.
 *
 * Verifies the recommendation logic against fixture system states + the
 * detect-and-recommend round trip with a fake probe (PR 2b will swap the
 * fake for real subprocess calls).
 */

import { describe, it, expect } from "vitest";

import {
  CASTLE_TABLE_NAME,
  detectAndRecommend,
  recommendNamespace,
  type FirewallEnvironment,
  type FirewallProbe,
} from "../../../src/castle-wall/runtime/detect-firewall.js";

describe("castle-wall/runtime/detect-firewall : recommendNamespace", () => {
  const baseline: FirewallEnvironment = {
    ufwActive: false,
    firewalldActive: false,
    otherNftablesTables: [],
  };

  it("clean host gets the no-existing-firewall classification", () => {
    const r = recommendNamespace(baseline);
    expect(r.castleTableName).toBe(CASTLE_TABLE_NAME);
    expect(r.conflictClass).toBe("no_existing_firewall");
  });

  it("ufw active is namespace-safe", () => {
    const r = recommendNamespace({ ...baseline, ufwActive: true });
    expect(r.conflictClass).toBe("ufw_present_namespace_safe");
  });

  it("firewalld active is namespace-safe", () => {
    const r = recommendNamespace({ ...baseline, firewalldActive: true });
    expect(r.conflictClass).toBe("firewalld_present_namespace_safe");
  });

  it("existing nftables tables are namespace-safe when not colliding", () => {
    const r = recommendNamespace({
      ...baseline,
      otherNftablesTables: ["docker", "user-defined"],
    });
    expect(r.conflictClass).toBe("existing_nftables_present_namespace_safe");
    expect(r.note).toContain("docker");
  });

  it("name collision flagged when sanctuary-castle already exists", () => {
    const r = recommendNamespace({
      ...baseline,
      otherNftablesTables: [CASTLE_TABLE_NAME],
    });
    expect(r.conflictClass).toBe("name_collision");
  });

  it("collision precedence beats firewalld+ufw signals", () => {
    const r = recommendNamespace({
      ufwActive: true,
      firewalldActive: true,
      otherNftablesTables: [CASTLE_TABLE_NAME, "docker"],
    });
    expect(r.conflictClass).toBe("name_collision");
  });
});

describe("castle-wall/runtime/detect-firewall : detectAndRecommend", () => {
  const fakeProbe: FirewallProbe = {
    isUfwActive: async () => false,
    isFirewalldActive: async () => true,
    listNftablesTables: async () => ["firewalld"],
  };

  it("filters out the sanctuary-castle table from otherNftablesTables", async () => {
    const probe: FirewallProbe = {
      isUfwActive: async () => false,
      isFirewalldActive: async () => false,
      listNftablesTables: async () => [CASTLE_TABLE_NAME, "user"],
    };
    const result = await detectAndRecommend(probe);
    expect(result.environment.otherNftablesTables).toEqual(["user"]);
    expect(result.recommendation.conflictClass).toBe(
      "existing_nftables_present_namespace_safe"
    );
  });

  it("propagates probe results to the environment shape", async () => {
    const result = await detectAndRecommend(fakeProbe);
    expect(result.environment.firewalldActive).toBe(true);
    expect(result.environment.ufwActive).toBe(false);
  });

  it("wraps probe errors in RuntimeFirewallDetectError", async () => {
    const erroring: FirewallProbe = {
      isUfwActive: async () => false,
      isFirewalldActive: async () => {
        throw new Error("systemctl not found");
      },
      listNftablesTables: async () => [],
    };
    await expect(detectAndRecommend(erroring)).rejects.toThrow(/firewall probe failed/);
  });
});
