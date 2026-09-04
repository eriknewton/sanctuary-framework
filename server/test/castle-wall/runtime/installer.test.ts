/**
 * Castle Wall installer plan tests.
 *
 * Verifies the plan-shape determinism, curated-rule selection echo, and the
 * audit-event details surface.
 */

import { describe, it, expect } from "vitest";

import {
  describeCurated,
  planAsAuditDetails,
  planInstall,
} from "../../../src/castle-wall/runtime/installer.js";
import { recommendNamespace } from "../../../src/castle-wall/runtime/detect-firewall.js";
import { CURATED_ALLOWLIST } from "../../../src/castle-wall/runtime/curated-allowlist.js";

describe("castle-wall/runtime/installer : planInstall", () => {
  const firewall = recommendNamespace({
    ufwActive: false,
    firewalldActive: false,
    otherNftablesTables: [],
  });

  it("emits the canonical server-profile plan for a clean host", () => {
    const plan = planInstall({
      fortress_id: "abc12345",
      firewall,
      curated_selections: [],
    });
    expect(plan.steps.length).toBe(9);
    expect(plan.runtime_dir).toBe("/run/sanctuary/abc12345");
    expect(plan.state_dir).toBe("/var/lib/sanctuary/abc12345");
    expect(plan.socket_path).toBe("/run/sanctuary/abc12345/filter.sock");
    expect(plan.systemd_unit_path).toBe(
      "/etc/systemd/system/sanctuary-castle-wall.service"
    );
  });

  it("classifies known curated selections as enabled", () => {
    const ruleId = CURATED_ALLOWLIST[0]!.rule_id;
    const plan = planInstall({
      fortress_id: "abcdef01",
      firewall,
      curated_selections: [{ rule_id: ruleId }],
    });
    expect(plan.curated_rules_enabled).toEqual([ruleId]);
    expect(plan.curated_rules_skipped).toEqual([]);
  });

  it("classifies unknown curated selections as skipped", () => {
    const plan = planInstall({
      fortress_id: "abcdef01",
      firewall,
      curated_selections: [{ rule_id: "no-such-rule" }],
    });
    expect(plan.curated_rules_enabled).toEqual([]);
    expect(plan.curated_rules_skipped).toEqual(["no-such-rule"]);
  });

  it("steps reference the libexec daemon binary path", () => {
    const plan = planInstall({
      fortress_id: "abcdef01",
      firewall,
      curated_selections: [],
      libexec_dir: "/opt/sanctuary/libexec",
    });
    const placeUnit = plan.steps.find((s) => s.kind === "place_systemd_unit");
    expect(placeUnit?.description).toContain("/opt/sanctuary/libexec/castle-wall-daemon");
  });

  it("refuses a fortress id that could escape the fixed root-owned layout", () => {
    expect(() =>
      planInstall({
        fortress_id: "../../etc",
        firewall,
        curated_selections: [],
      })
    ).toThrow(/8\.\.64 lowercase hexadecimal/);
  });
});

describe("castle-wall/runtime/installer : planAsAuditDetails", () => {
  it("includes castle table name + firewall summary", () => {
    const firewall = recommendNamespace({
      ufwActive: true,
      firewalldActive: false,
      otherNftablesTables: [],
    });
    const plan = planInstall({
      fortress_id: "abcdef01",
      firewall,
      curated_selections: [],
    });
    const details = planAsAuditDetails(plan);
    expect(details.castle_table_name).toBe("sanctuary-castle");
    expect(details.firewall_conflict_class).toBe("ufw_present_namespace_safe");
    expect(details.step_count).toBe(9);
  });
});

describe("castle-wall/runtime/installer : describeCurated", () => {
  it("returns matching entries for known ids", () => {
    const ruleId = CURATED_ALLOWLIST[0]!.rule_id;
    const result = describeCurated([ruleId]);
    expect(result.length).toBe(1);
    expect(result[0]!.rule_id).toBe(ruleId);
  });

  it("filters unknown ids", () => {
    const result = describeCurated(["nope"]);
    expect(result.length).toBe(0);
  });
});
