/**
 * CI parity assertion for the NEFilter-manifest / pf-anchor single-source
 * generation (Unified Protect Slice 8). Acceptance per the design: a
 * deliberately-divergent policy FAILS the check; generated artifacts agree
 * on a fixture corpus.
 */

import { describe, it, expect } from "vitest";

import {
  deriveGateAllowRule,
  type ExclusiveEgressGatePolicy,
} from "../../src/castle-wall/allowlist/gate-derivation.js";
import { composeEffectiveRules } from "../../src/castle-wall/allowlist/habeas-port.js";
import { renderPfAnchorRules } from "../../src/egress-gate/pf-anchor.js";
import {
  checkGatePolicyParity,
  assertGatePolicyParity,
  GatePolicyParityError,
} from "../../src/egress-gate/parity.js";

const CREATED_AT = "2026-07-02T00:00:00Z";

/** Fixture corpus: representative uid/port combinations. */
const CORPUS: ExclusiveEgressGatePolicy[] = [
  { agent_uid: 502, gate_port: 19998 },
  { agent_uid: 503, gate_port: 8443 },
  { agent_uid: 1001, gate_port: 65535 },
  { agent_uid: 601, gate_port: 1 },
];

function artifactsFor(policy: ExclusiveEgressGatePolicy) {
  return {
    policy,
    manifestRules: [deriveGateAllowRule(policy, CREATED_AT)],
    pfAnchorText: renderPfAnchorRules(policy),
  };
}

describe("egress-gate/parity (Slice 8 drift guard)", () => {
  it("passes on every corpus policy when both artifacts come from the single source", () => {
    for (const policy of CORPUS) {
      expect(checkGatePolicyParity(artifactsFor(policy))).toEqual([]);
    }
  });

  it("passes against a FULL composed manifest ruleset (habeas + dns + gate)", () => {
    const policy = CORPUS[0]!;
    const composed = composeEffectiveRules({
      operatorRules: [],
      resolvers: ["9.9.9.9"],
      exclusiveEgressGate: policy,
      createdAt: CREATED_AT,
    });
    expect(
      checkGatePolicyParity({
        policy,
        manifestRules: composed,
        pfAnchorText: renderPfAnchorRules(policy),
      }),
    ).toEqual([]);
  });

  it("FAILS when the pf anchor was generated for a different port (deliberate divergence)", () => {
    const policy = { agent_uid: 502, gate_port: 19998 };
    const divergent = { agent_uid: 502, gate_port: 19999 };
    const issues = checkGatePolicyParity({
      policy,
      manifestRules: [deriveGateAllowRule(policy, CREATED_AT)],
      pfAnchorText: renderPfAnchorRules(divergent),
    });
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.join(" ")).toMatch(/19999|diverges/);
  });

  it("FAILS when the pf anchor was generated for a different uid", () => {
    const policy = { agent_uid: 502, gate_port: 19998 };
    const divergent = { agent_uid: 601, gate_port: 19998 };
    const issues = checkGatePolicyParity({
      policy,
      manifestRules: [deriveGateAllowRule(policy, CREATED_AT)],
      pfAnchorText: renderPfAnchorRules(divergent),
    });
    expect(issues.length).toBeGreaterThan(0);
  });

  it("FAILS when the manifest carries NO gate rule (rule present in pf but not NEFilter)", () => {
    const policy = CORPUS[0]!;
    const issues = checkGatePolicyParity({
      policy,
      manifestRules: [],
      pfAnchorText: renderPfAnchorRules(policy),
    });
    expect(issues.some((i) => i.includes("exactly one is required"))).toBe(true);
  });

  it("FAILS when the manifest gate rule was tampered wider (extra port)", () => {
    const policy = CORPUS[0]!;
    const tampered = deriveGateAllowRule(policy, CREATED_AT);
    tampered.match = { ...tampered.match, port: [policy.gate_port, 443] };
    const issues = checkGatePolicyParity({
      policy,
      manifestRules: [tampered],
      pfAnchorText: renderPfAnchorRules(policy),
    });
    expect(issues.length).toBeGreaterThan(0);
  });

  it("FAILS when the manifest gate rule destination was widened beyond loopback", () => {
    const policy = CORPUS[0]!;
    const tampered = deriveGateAllowRule(policy, CREATED_AT);
    tampered.match = { ...tampered.match, cidr: "0.0.0.0/0" };
    const issues = checkGatePolicyParity({
      policy,
      manifestRules: [tampered],
      pfAnchorText: renderPfAnchorRules(policy),
    });
    expect(issues.length).toBeGreaterThan(0);
  });

  it("FAILS when the pf anchor text was hand-edited (pass rule removed)", () => {
    const policy = CORPUS[0]!;
    const anchor = renderPfAnchorRules(policy)
      .split("\n")
      .filter((l) => !l.startsWith("pass "))
      .join("\n");
    const issues = checkGatePolicyParity({
      policy,
      manifestRules: [deriveGateAllowRule(policy, CREATED_AT)],
      pfAnchorText: anchor,
    });
    expect(issues.some((i) => i.includes("no parseable agent-to-gate pass rule"))).toBe(true);
  });

  it("FAILS on duplicate gate rules in the manifest", () => {
    const policy = CORPUS[0]!;
    const rule = deriveGateAllowRule(policy, CREATED_AT);
    const issues = checkGatePolicyParity({
      policy,
      manifestRules: [rule, rule],
      pfAnchorText: renderPfAnchorRules(policy),
    });
    expect(issues.some((i) => i.includes("exactly one is required"))).toBe(true);
  });

  it("FAILS on a structurally-invalid policy", () => {
    const issues = checkGatePolicyParity({
      policy: { agent_uid: 0, gate_port: 19998 },
      manifestRules: [],
      pfAnchorText: "",
    });
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatch(/structurally invalid/);
  });

  it("assertGatePolicyParity throws a typed error carrying the issues", () => {
    const policy = CORPUS[0]!;
    expect(() =>
      assertGatePolicyParity({
        policy,
        manifestRules: [],
        pfAnchorText: renderPfAnchorRules(policy),
      }),
    ).toThrow(GatePolicyParityError);
  });
});
