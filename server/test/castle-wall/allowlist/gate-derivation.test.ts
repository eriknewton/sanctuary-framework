/**
 * Tests for the exclusive-egress gate rule derivation (Unified Protect
 * Slice 1): fail-closed validation, the pinned loopback-only rule shape,
 * and injection through the signed-manifest generation path
 * (`composeEffectiveRules`) without disturbing the habeas invariants.
 */

import { describe, it, expect } from "vitest";

import {
  DERIVED_GATE_RULE_ID,
  GATE_LOOPBACK_CIDR,
  deriveGateAllowRule,
  validateExclusiveEgressGatePolicy,
} from "../../../src/castle-wall/allowlist/gate-derivation.js";
import { validateRule, type AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import { composeEffectiveRules } from "../../../src/castle-wall/allowlist/habeas-port.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";

const VALID_POLICY = { agent_uid: 502, gate_port: 19998 };
const CREATED_AT = "2026-07-02T00:00:00Z";

describe("castle-wall/allowlist/gate-derivation", () => {
  describe("validateExclusiveEgressGatePolicy (fail-closed)", () => {
    it("accepts a well-formed policy and returns a normalized copy", () => {
      const validated = validateExclusiveEgressGatePolicy({
        ...VALID_POLICY,
        stray_field: "dropped",
      });
      expect(validated).toEqual(VALID_POLICY);
    });

    it.each([
      ["null", null],
      ["a string", "502:19998"],
      ["an array", [502, 19998]],
      ["missing agent_uid", { gate_port: 19998 }],
      ["missing gate_port", { agent_uid: 502 }],
      ["string agent_uid", { agent_uid: "502", gate_port: 19998 }],
      ["negative agent_uid", { agent_uid: -1, gate_port: 19998 }],
      ["fractional agent_uid", { agent_uid: 502.5, gate_port: 19998 }],
      ["root agent_uid (uid 0 defeats confinement)", { agent_uid: 0, gate_port: 19998 }],
      ["port 0", { agent_uid: 502, gate_port: 0 }],
      ["port above 65535", { agent_uid: 502, gate_port: 65536 }],
      ["string port", { agent_uid: 502, gate_port: "19998" }],
    ])("rejects %s", (_label, candidate) => {
      expect(validateExclusiveEgressGatePolicy(candidate)).toBeNull();
    });
  });

  describe("deriveGateAllowRule", () => {
    it("derives the pinned loopback-only allow rule", () => {
      const rule = deriveGateAllowRule(VALID_POLICY, CREATED_AT);
      expect(rule.id).toBe(DERIVED_GATE_RULE_ID);
      expect(rule.disposition).toBe("allow");
      expect(rule.derived).toBe(true);
      expect(rule.match.cidr).toBe(GATE_LOOPBACK_CIDR);
      expect(rule.match.port).toEqual([19998]);
      expect(rule.match.protocol).toBe("tcp");
      // Loopback-only by construction: no host axes that could widen off-box.
      expect(rule.match.host).toBeUndefined();
      expect(rule.match.host_pattern).toBeUndefined();
      expect(rule.match.ip).toBeUndefined();
      // Empty scope = all wrapped agents (never a widened operator posture:
      // the evaluator consults rules for agent-classified flows only).
      expect(rule.scope).toEqual({});
    });

    it("derives a rule that passes the allowlist schema validator", () => {
      const rule = deriveGateAllowRule(VALID_POLICY, CREATED_AT);
      expect(validateRule(rule)).toEqual([]);
    });

    it("throws on a malformed policy instead of emitting a malformed rule", () => {
      expect(() =>
        deriveGateAllowRule({ agent_uid: 0, gate_port: 19998 }, CREATED_AT),
      ).toThrow(/malformed exclusive-egress gate policy/);
    });

    it("never claims the word unbypassable in its user-visible description", () => {
      const rule = deriveGateAllowRule(VALID_POLICY, CREATED_AT);
      expect((rule.description ?? "").toLowerCase()).not.toContain("unbypassable");
    });
  });

  describe("composeEffectiveRules integration (signed-manifest generation path)", () => {
    it("injects exactly one derived gate rule when the policy is present", () => {
      const composed = composeEffectiveRules({
        operatorRules: [],
        resolvers: [],
        exclusiveEgressGate: VALID_POLICY,
        createdAt: CREATED_AT,
      });
      const gateRules = composed.filter((r) => r.id === DERIVED_GATE_RULE_ID);
      expect(gateRules).toHaveLength(1);
      expect(gateRules[0]!.match.port).toEqual([19998]);
      expect(gateRules[0]!.derived).toBe(true);
    });

    it("injects no gate rule when the policy is absent (unchanged composition)", () => {
      const composed = composeEffectiveRules({
        operatorRules: [],
        resolvers: [],
        createdAt: CREATED_AT,
      });
      expect(composed.some((r) => r.id === DERIVED_GATE_RULE_ID)).toBe(false);
    });

    it("keeps the habeas lane intact alongside the gate rule", () => {
      const composed = composeEffectiveRules({
        operatorRules: [],
        resolvers: [],
        exclusiveEgressGate: VALID_POLICY,
        createdAt: CREATED_AT,
      });
      // The always-on local habeas lane must still be present exactly once.
      const habeas = composed.filter((r) => r.id === "reserved_habeas_distress_local");
      expect(habeas).toHaveLength(1);
    });

    it("REJECTS an operator rule claiming the reserved derived gate id (never a duplicate-id signed manifest)", () => {
      // Like the habeas reserved ids: derived, never authored. Pushing a
      // second rule with the same id would wedge the Slice-8 parity gate
      // (which requires EXACTLY one) and break id-keyed introspection.
      const impostor: AllowlistRule = {
        id: DERIVED_GATE_RULE_ID,
        schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
        created_at: CREATED_AT,
        match: { cidr: "0.0.0.0/0", port: [443], protocol: "tcp" },
        scope: {},
        disposition: "allow",
      };
      expect(() =>
        composeEffectiveRules({
          operatorRules: [impostor],
          resolvers: [],
          exclusiveEgressGate: VALID_POLICY,
          createdAt: CREATED_AT,
        }),
      ).toThrow(/reserved for the .*exclusive-egress gate/);
    });

    it("REJECTS the reserved gate id even when no gate policy is configured (a derived-looking rule is never operator-authored)", () => {
      const impostor: AllowlistRule = {
        id: DERIVED_GATE_RULE_ID,
        schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
        created_at: CREATED_AT,
        match: { cidr: "127.0.0.1/32", port: [19998], protocol: "tcp" },
        scope: {},
        disposition: "allow",
      };
      expect(() =>
        composeEffectiveRules({
          operatorRules: [impostor],
          resolvers: [],
          createdAt: CREATED_AT,
        }),
      ).toThrow(/reserved for the .*exclusive-egress gate/);
    });

    it("throws (fail-closed) when handed a malformed policy object", () => {
      expect(() =>
        composeEffectiveRules({
          operatorRules: [],
          resolvers: [],
          exclusiveEgressGate: { agent_uid: 502, gate_port: 0 },
          createdAt: CREATED_AT,
        }),
      ).toThrow(/malformed exclusive-egress gate policy/);
    });
  });
});
