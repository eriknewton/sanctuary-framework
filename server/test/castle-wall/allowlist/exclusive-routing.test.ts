/**
 * Unified Protect Slice 5 S5-4: exclusive routing manifest composition
 * (design rev3 BLOCKER-1). The load-bearing invariants:
 *
 *  - the compose-time assertion FAILS CLOSED on ANY agent-reachable direct
 *    off-box endpoint allow (unscoped, uid-scoped to the agent, or id-scoped
 *    to the agent's identity) - no manifest, no arm;
 *  - the agent's manifest carries exactly the gate channel (bound to the
 *    agent principal) + the genuine habeas reserved lanes; a rule merely
 *    CLAIMING a reserved id is a violation, never a lane;
 *  - the derived DNS rule is checked like any rule: in a clean exclusive
 *    composition its parent-scope union binds to the gate principal + the
 *    habeas emitter, so the agent gets NO direct DNS (the gate resolves);
 *  - coarse-only fallback exists ONLY as an explicit audited mode: it
 *    refuses gate-scoped residue ("never both models at once") and REQUIRES
 *    a successful audit emission with the DISTINCT op string
 *    `exclusive_routing_coarse_fallback` before returning rules;
 *  - the provisioned-rule builder re-scopes to the gate principal in
 *    exclusive routing while the coarse default stays byte-identical.
 */

import { describe, expect, it } from "vitest";

import {
  EXCLUSIVE_ROUTING_COARSE_FALLBACK_AUDIT_OP,
  ExclusiveRoutingViolationError,
  ExclusiveRoutingResidueError,
  allowRuleScopeReachesAgent,
  ruleIsLoopbackOnly,
  assertExclusiveRoutingComposition,
  composeExclusiveRoutingRules,
  type ExclusiveRoutingPrincipals,
  type CoarseFallbackAuditRecord,
} from "../../../src/castle-wall/allowlist/exclusive-routing.js";
import {
  composeEffectiveRules,
} from "../../../src/castle-wall/allowlist/habeas-port.js";
import {
  deriveGateAllowRule,
  DERIVED_GATE_RULE_ID,
} from "../../../src/castle-wall/allowlist/gate-derivation.js";
import { DERIVED_DNS_RULE_ID } from "../../../src/castle-wall/allowlist/dns-derivation.js";
import {
  buildProvisionedEgressRules,
  HERMES_ENDPOINT_SET,
} from "../../../src/castle-wall/provision/egress.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import { checkGatePolicyParity } from "../../../src/egress-gate/parity.js";
import { renderPfAnchorRules } from "../../../src/egress-gate/pf-anchor.js";

const CREATED_AT = "2026-07-16T00:00:00.000Z";
const GATE_POLICY = { agent_uid: 600, gate_port: 49152 };
const PRINCIPALS: ExclusiveRoutingPrincipals = {
  agent_uid: 600,
  gate_uid: 601,
  agent: { agent_id: "hermes-cos-1", agent_template: "ops-runner" },
};
const RESOLVERS = ["9.9.9.9"];

function operatorRule(overrides: Partial<AllowlistRule> & { id: string }): AllowlistRule {
  return {
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: CREATED_AT,
    match: { host: ["api.example.net"], port: [443], protocol: "tcp" },
    scope: {},
    disposition: "allow",
    ...overrides,
  };
}

/** The clean exclusive base: gate-scoped provisioned rules + gate policy. */
function cleanExclusiveBase() {
  return {
    operatorRules: buildProvisionedEgressRules(HERMES_ENDPOINT_SET, CREATED_AT, {
      mode: "exclusive",
      gate_uid: 601,
    }),
    resolvers: RESOLVERS,
    exclusiveEgressGate: GATE_POLICY,
    createdAt: CREATED_AT,
  };
}

describe("S5-4 predicates", () => {
  it("allowRuleScopeReachesAgent: empty scope reaches; gate-uid-only does not; agent uid/id/template do", () => {
    expect(allowRuleScopeReachesAgent({}, PRINCIPALS)).toBe(true);
    expect(allowRuleScopeReachesAgent(undefined, PRINCIPALS)).toBe(true);
    expect(allowRuleScopeReachesAgent({ uids: [601] }, PRINCIPALS)).toBe(false);
    expect(allowRuleScopeReachesAgent({ uids: [600] }, PRINCIPALS)).toBe(true);
    expect(allowRuleScopeReachesAgent({ uids: [601], agent_ids: ["hermes-cos-1"] }, PRINCIPALS)).toBe(true);
    expect(allowRuleScopeReachesAgent({ agent_ids: ["someone-else"] }, PRINCIPALS)).toBe(false);
    expect(allowRuleScopeReachesAgent({ template_ids: ["ops-runner"] }, PRINCIPALS)).toBe(true);
  });

  it("ruleIsLoopbackOnly: loopback ip/cidr yes; hostnames, port-only, and off-box never", () => {
    expect(ruleIsLoopbackOnly(operatorRule({ id: "a", match: { ip: ["127.0.0.1"], port: [8741] } }))).toBe(true);
    expect(ruleIsLoopbackOnly(operatorRule({ id: "b", match: { cidr: "127.0.0.1/32", port: [49152] } }))).toBe(true);
    expect(ruleIsLoopbackOnly(operatorRule({ id: "c", match: { ip: ["127.0.0.1", "::1"], port: [1] } }))).toBe(true);
    expect(ruleIsLoopbackOnly(operatorRule({ id: "d", match: { host: ["localhost"], port: [80] } }))).toBe(false);
    expect(ruleIsLoopbackOnly(operatorRule({ id: "e", match: { port: [443] } }))).toBe(false);
    expect(ruleIsLoopbackOnly(operatorRule({ id: "f", match: { ip: ["127.0.0.1", "8.8.8.8"] } }))).toBe(false);
    expect(ruleIsLoopbackOnly(operatorRule({ id: "g", match: { cidr: "127.0.0.0/4" } }))).toBe(false);
  });
});

describe("S5-4 exclusive composition (the happy path)", () => {
  it("composes: gate-scoped endpoints + agent-scoped gate channel + genuine habeas lanes; agent has NO direct off-box allow and NO direct DNS", async () => {
    const result = await composeExclusiveRoutingRules({
      base: cleanExclusiveBase(),
      routing: { mode: "exclusive", principals: PRINCIPALS },
    });
    expect(result.mode).toBe("exclusive");
    const report = result.report!;
    expect(report.justified_lane_ids).toContain(DERIVED_GATE_RULE_ID);
    expect(report.justified_lane_ids).toContain("reserved_habeas_distress_local");
    // Every provisioned endpoint rule is gate-scoped; the derived DNS rule is
    // gate-scoped too (its parent union is the gate-scoped hostname rules), so
    // the count is endpoints + 1 (DNS).
    expect(report.gate_scoped_rule_ids).toContain(DERIVED_DNS_RULE_ID);
    expect(
      report.gate_scoped_rule_ids.filter((id) => id.startsWith("provisioned-hermes-")).length,
    ).toBe(HERMES_ENDPOINT_SET.endpoints.length);

    // The gate channel binds to the AGENT principal.
    const gateRule = result.rules.find((r) => r.id === DERIVED_GATE_RULE_ID)!;
    expect(gateRule.scope.uids).toEqual([600]);

    // The derived DNS rule exists (gate-scoped hostname parents + habeas
    // emitter) but is NOT agent-reachable: no direct DNS for the agent.
    const dns = result.rules.find((r) => r.id === DERIVED_DNS_RULE_ID);
    expect(dns).toBeDefined();
    expect(allowRuleScopeReachesAgent(dns!.scope, PRINCIPALS)).toBe(false);
    expect(dns!.scope.uids).toEqual([601]);

    // No allow in the whole composition reaches the agent off-box.
    for (const rule of result.rules) {
      if (rule.disposition !== "allow") continue;
      if (report.justified_lane_ids.includes(rule.id)) continue;
      if (ruleIsLoopbackOnly(rule)) continue;
      expect(allowRuleScopeReachesAgent(rule.scope, PRINCIPALS)).toBe(false);
    }
  });

  it("with a distress webhook: the webhook lane is admitted as a DOCUMENTED residual, never silently", async () => {
    const result = await composeExclusiveRoutingRules({
      base: {
        ...cleanExclusiveBase(),
        distressWebhook: { host: "distress.example.org", port: 443 },
      },
      routing: { mode: "exclusive", principals: PRINCIPALS },
    });
    expect(result.report!.documented_residual_ids).toEqual([
      "reserved_habeas_distress_webhook",
    ]);
    // The DNS union now also carries the emitter scope; still not the agent.
    const dns = result.rules.find((r) => r.id === DERIVED_DNS_RULE_ID)!;
    expect(allowRuleScopeReachesAgent(dns.scope, PRINCIPALS)).toBe(false);
  });
});

describe("S5-4 compose-time assertion fails CLOSED", () => {
  it("a LEAKED agent-scope rule (coarse-scoped provisioned rule, scope {}) fails the composition", async () => {
    const leaked = buildProvisionedEgressRules(HERMES_ENDPOINT_SET, CREATED_AT); // coarse: scope {}
    await expect(
      composeExclusiveRoutingRules({
        base: { ...cleanExclusiveBase(), operatorRules: leaked },
        routing: { mode: "exclusive", principals: PRINCIPALS },
      }),
    ).rejects.toThrow(ExclusiveRoutingViolationError);
  });

  it("an unscoped operator allow fails; a deny/prompt never does", async () => {
    await expect(
      composeExclusiveRoutingRules({
        base: {
          ...cleanExclusiveBase(),
          operatorRules: [
            ...cleanExclusiveBase().operatorRules,
            operatorRule({ id: "op-unscoped-allow" }),
          ],
        },
        routing: { mode: "exclusive", principals: PRINCIPALS },
      }),
    ).rejects.toThrow(/op-unscoped-allow/);

    const withDeny = await composeExclusiveRoutingRules({
      base: {
        ...cleanExclusiveBase(),
        operatorRules: [
          ...cleanExclusiveBase().operatorRules,
          operatorRule({ id: "op-deny", disposition: "deny" }),
        ],
      },
      routing: { mode: "exclusive", principals: PRINCIPALS },
    });
    expect(withDeny.mode).toBe("exclusive");
  });

  it("an allow scoped to the agent uid / agent id / template id each fails with a named reason", async () => {
    for (const scope of [
      { uids: [600] },
      { agent_ids: ["hermes-cos-1"] },
      { template_ids: ["ops-runner"] },
    ]) {
      await expect(
        composeExclusiveRoutingRules({
          base: {
            ...cleanExclusiveBase(),
            operatorRules: [
              ...cleanExclusiveBase().operatorRules,
              operatorRule({ id: "op-agent-scoped", scope }),
            ],
          },
          routing: { mode: "exclusive", principals: PRINCIPALS },
        }),
      ).rejects.toThrow(/op-agent-scoped/);
    }
  });

  it("an agent-reachable hostname allow ALSO fails via its own rule (and would widen DNS): direct DNS never leaks silently", () => {
    // Compose manually so the derived-DNS widening is visible: an unscoped
    // hostname allow makes the DNS union {} (agent-reachable). BOTH the
    // parent and the derived DNS rule violate.
    const rules = composeEffectiveRules({
      operatorRules: [operatorRule({ id: "op-unscoped-hostname" })],
      resolvers: RESOLVERS,
      exclusiveEgressGate: GATE_POLICY,
      gateRuleScopeToAgentUid: true,
      createdAt: CREATED_AT,
    });
    let err: ExclusiveRoutingViolationError | null = null;
    try {
      assertExclusiveRoutingComposition(rules, {
        principals: PRINCIPALS,
        gatePolicy: GATE_POLICY,
      });
    } catch (e) {
      err = e as ExclusiveRoutingViolationError;
    }
    expect(err).toBeInstanceOf(ExclusiveRoutingViolationError);
    const ids = err!.violations.map((v) => v.rule_id);
    expect(ids).toContain("op-unscoped-hostname");
    expect(ids).toContain(DERIVED_DNS_RULE_ID);
  });

  it("a rule CLAIMING a reserved habeas id without the genuine shape is a violation, not a lane", () => {
    const rules = [
      ...composeEffectiveRules({
        operatorRules: cleanExclusiveBase().operatorRules,
        resolvers: RESOLVERS,
        exclusiveEgressGate: GATE_POLICY,
        gateRuleScopeToAgentUid: true,
        createdAt: CREATED_AT,
      }),
      // Planted post-compose (composeEffectiveRules itself rejects authored
      // reserved ids; the assertion must still refuse a claimed id in case a
      // future compose path regresses).
      operatorRule({
        id: "reserved_habeas_distress_extra",
        match: { host: ["exfil.example.com"], port: [443], protocol: "tcp" },
      }),
    ];
    expect(() =>
      assertExclusiveRoutingComposition(rules, {
        principals: PRINCIPALS,
        gatePolicy: GATE_POLICY,
      }),
    ).toThrow(/reserved_habeas_distress_extra/);
  });

  it("a gate-channel rule with the WRONG shape (unscoped, wrong port, or off-box) is a violation", () => {
    const base = composeEffectiveRules({
      operatorRules: cleanExclusiveBase().operatorRules,
      resolvers: RESOLVERS,
      exclusiveEgressGate: GATE_POLICY,
      gateRuleScopeToAgentUid: true,
      createdAt: CREATED_AT,
    });
    const tamper = (mutate: (rule: AllowlistRule) => AllowlistRule): AllowlistRule[] =>
      base.map((r) => (r.id === DERIVED_GATE_RULE_ID ? mutate({ ...r }) : r));

    // Unscoped (legacy) gate rule in an exclusive composition: violation.
    expect(() =>
      assertExclusiveRoutingComposition(
        tamper((r) => ({ ...r, scope: {} })),
        { principals: PRINCIPALS, gatePolicy: GATE_POLICY },
      ),
    ).toThrow(ExclusiveRoutingViolationError);
    // Wrong port: violation.
    expect(() =>
      assertExclusiveRoutingComposition(
        tamper((r) => ({ ...r, match: { ...r.match, port: [50000] } })),
        { principals: PRINCIPALS, gatePolicy: GATE_POLICY },
      ),
    ).toThrow(ExclusiveRoutingViolationError);
    // Off-box destination claiming the gate id: violation.
    expect(() =>
      assertExclusiveRoutingComposition(
        tamper((r) => ({ ...r, match: { cidr: "10.0.0.0/8", port: [49152], protocol: "tcp" } })),
        { principals: PRINCIPALS, gatePolicy: GATE_POLICY },
      ),
    ).toThrow(ExclusiveRoutingViolationError);
  });

  it("cross-principal composition is refused: gate policy for a DIFFERENT agent uid", async () => {
    await expect(
      composeExclusiveRoutingRules({
        base: { ...cleanExclusiveBase(), exclusiveEgressGate: { agent_uid: 700, gate_port: 49152 } },
        routing: { mode: "exclusive", principals: PRINCIPALS },
      }),
    ).rejects.toThrow(/cross-principal/);
  });

  it("exclusive routing without a gate policy is refused (no gate, no exclusivity)", async () => {
    const base = cleanExclusiveBase();
    await expect(
      composeExclusiveRoutingRules({
        base: { operatorRules: base.operatorRules, resolvers: RESOLVERS, createdAt: CREATED_AT },
        routing: { mode: "exclusive", principals: PRINCIPALS },
      }),
    ).rejects.toThrow(/gate policy/);
  });

  it("a gate_uid colliding with the agent uid is refused", async () => {
    await expect(
      composeExclusiveRoutingRules({
        base: cleanExclusiveBase(),
        routing: {
          mode: "exclusive",
          principals: { ...PRINCIPALS, gate_uid: 600 },
        },
      }),
    ).rejects.toThrow(/distinct from the agent uid/);
  });
});

describe("S5-4 coarse-only fallback: explicit, residue-free, audited", () => {
  const coarseRules = (): AllowlistRule[] =>
    buildProvisionedEgressRules(HERMES_ENDPOINT_SET, CREATED_AT);

  it("composes coarse scoping WITHOUT a gate channel and EMITS the distinct audit op", async () => {
    const audits: CoarseFallbackAuditRecord[] = [];
    const result = await composeExclusiveRoutingRules({
      base: {
        operatorRules: coarseRules(),
        resolvers: RESOLVERS,
        // A caller may still be holding the gate policy; the fallback must
        // NOT compose a gate channel from it.
        exclusiveEgressGate: GATE_POLICY,
        createdAt: CREATED_AT,
      },
      routing: {
        mode: "coarse-only",
        agent_uid: 600,
        reason: "exclusive-egress generation could not come live at install",
        audit: (record) => {
          audits.push(record);
        },
      },
    });
    expect(result.mode).toBe("coarse-only");
    expect(result.rules.some((r) => r.id === DERIVED_GATE_RULE_ID)).toBe(false);
    expect(audits).toHaveLength(1);
    expect(audits[0]!.operation).toBe(EXCLUSIVE_ROUTING_COARSE_FALLBACK_AUDIT_OP);
    expect(audits[0]!.operation).toBe("exclusive_routing_coarse_fallback");
    expect(audits[0]!.agent_uid).toBe(600);
    expect(audits[0]!.coarse_provisioned_rule_ids.length).toBe(
      HERMES_ENDPOINT_SET.endpoints.length,
    );
  });

  it("REFUSES gate-scoped provisioned residue (never both models at once)", async () => {
    await expect(
      composeExclusiveRoutingRules({
        base: {
          operatorRules: buildProvisionedEgressRules(HERMES_ENDPOINT_SET, CREATED_AT, {
            mode: "exclusive",
            gate_uid: 601,
          }),
          resolvers: RESOLVERS,
          createdAt: CREATED_AT,
        },
        routing: {
          mode: "coarse-only",
          agent_uid: 600,
          reason: "fallback with stale exclusive files",
          audit: () => undefined,
        },
      }),
    ).rejects.toThrow(ExclusiveRoutingResidueError);
  });

  it("an AUDIT FAILURE fails the fallback composition (an unaudited degrade never composes)", async () => {
    await expect(
      composeExclusiveRoutingRules({
        base: { operatorRules: coarseRules(), resolvers: RESOLVERS, createdAt: CREATED_AT },
        routing: {
          mode: "coarse-only",
          agent_uid: 600,
          reason: "audit sink down",
          audit: () => {
            throw new Error("audit sink unavailable");
          },
        },
      }),
    ).rejects.toThrow(/audit sink unavailable/);
  });
});

describe("S5-4 provisioned-rule routing + gate-rule scoping + parity", () => {
  it("coarse default stays byte-identical to the shipped v1 shape", () => {
    const legacy = buildProvisionedEgressRules(HERMES_ENDPOINT_SET, CREATED_AT);
    for (const rule of legacy) {
      expect(rule.scope).toEqual({});
      expect(rule.description).not.toContain("Exclusive routing");
    }
    // Same ids in both modes: a mode switch republishes the same files.
    const exclusive = buildProvisionedEgressRules(HERMES_ENDPOINT_SET, CREATED_AT, {
      mode: "exclusive",
      gate_uid: 601,
    });
    expect(exclusive.map((r) => r.id)).toEqual(legacy.map((r) => r.id));
    for (const rule of exclusive) {
      expect(rule.scope).toEqual({ uids: [601] });
    }
  });

  it("exclusive routing with a bogus gate uid throws", () => {
    expect(() =>
      buildProvisionedEgressRules(HERMES_ENDPOINT_SET, CREATED_AT, {
        mode: "exclusive",
        gate_uid: 0,
      }),
    ).toThrow(/positive integer gate_uid/);
  });

  it("deriveGateAllowRule default is byte-identical; the option binds to the agent principal", () => {
    const legacy = deriveGateAllowRule(GATE_POLICY, CREATED_AT);
    expect(legacy.scope).toEqual({});
    const scoped = deriveGateAllowRule(GATE_POLICY, CREATED_AT, { scope_to_agent_uid: true });
    expect(scoped.scope).toEqual({ uids: [600] });
    expect({ ...scoped, scope: {} }).toEqual(legacy);
  });

  it("the pf/manifest parity guard accepts the agent-scoped gate rule ONLY under the exclusive flag", () => {
    const pfText = renderPfAnchorRules(GATE_POLICY);
    const scopedManifest = [
      deriveGateAllowRule(GATE_POLICY, CREATED_AT, { scope_to_agent_uid: true }),
    ];
    // Exclusive composition + flag: parity holds.
    expect(
      checkGatePolicyParity({
        policy: GATE_POLICY,
        manifestRules: scopedManifest,
        pfAnchorText: pfText,
        gateRuleScopedToAgentUid: true,
      }),
    ).toEqual([]);
    // The scoped rule WITHOUT the flag is drift (and vice versa).
    expect(
      checkGatePolicyParity({
        policy: GATE_POLICY,
        manifestRules: scopedManifest,
        pfAnchorText: pfText,
      }),
    ).not.toEqual([]);
    expect(
      checkGatePolicyParity({
        policy: GATE_POLICY,
        manifestRules: [deriveGateAllowRule(GATE_POLICY, CREATED_AT)],
        pfAnchorText: pfText,
        gateRuleScopedToAgentUid: true,
      }),
    ).not.toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Codex adversarial-gate BLOCKER fixes (2026-07-16). The pre-fix repros are
// encoded here so a regression re-opens exactly the gap the gate caught.
// ---------------------------------------------------------------------------

describe("S5-4 BLOCKER-1: the gate lane is byte-identical to the derivation, or nothing", () => {
  const composedBase = (): AllowlistRule[] =>
    composeEffectiveRules({
      operatorRules: cleanExclusiveBase().operatorRules,
      resolvers: RESOLVERS,
      exclusiveEgressGate: GATE_POLICY,
      gateRuleScopeToAgentUid: true,
      createdAt: CREATED_AT,
    });
  const tamperGate = (
    mutate: (rule: AllowlistRule) => AllowlistRule,
  ): AllowlistRule[] =>
    composedBase().map((r) => (r.id === DERIVED_GATE_RULE_ID ? mutate({ ...r }) : r));
  const assertGate = (rules: AllowlistRule[]) =>
    assertExclusiveRoutingComposition(rules, {
      principals: PRINCIPALS,
      gatePolicy: GATE_POLICY,
    });

  it("admits the EXACT single-source derived gate rule as a justified lane", () => {
    const report = assertGate(composedBase());
    expect(report.justified_lane_ids).toContain(DERIVED_GATE_RULE_ID);
  });

  it("REJECTS a tcp->udp protocol swap with every other field genuine (the field-by-field gap)", () => {
    // Pre-fix, the shape check delegated to `ruleIsLoopbackOnly`, which never
    // inspects `protocol`; a udp rule whose cidr/port/scope all passed was
    // wrongly admitted as the justified gate lane. Byte-identity catches it.
    let err: ExclusiveRoutingViolationError | null = null;
    try {
      assertGate(tamperGate((r) => ({ ...r, match: { ...r.match, protocol: "udp" } })));
    } catch (e) {
      err = e as ExclusiveRoutingViolationError;
    }
    expect(err).toBeInstanceOf(ExclusiveRoutingViolationError);
    expect(err!.violations.map((v) => v.rule_id)).toContain(DERIVED_GATE_RULE_ID);
  });

  it("REJECTS an EXTRA smuggled field on the gate rule (extra fields were not forbidden)", () => {
    expect(() =>
      assertGate(
        tamperGate((r) => ({ ...r, smuggled_extra: "x" }) as unknown as AllowlistRule),
      ),
    ).toThrow(ExclusiveRoutingViolationError);
  });

  it("REJECTS a different gate port claiming the gate id", () => {
    expect(() =>
      assertGate(tamperGate((r) => ({ ...r, match: { ...r.match, port: [40000] } }))),
    ).toThrow(ExclusiveRoutingViolationError);
  });

  it("REJECTS an extra destination axis smuggled into the gate match", () => {
    // A second (off-box) ip alongside the loopback cidr: `ruleIsLoopbackOnly`
    // stayed true (it checks the cidr, not that no other axis widens), but the
    // byte comparison rejects the widened match.
    expect(() =>
      assertGate(
        tamperGate((r) => ({ ...r, match: { ...r.match, ip: ["8.8.8.8"] } })),
      ),
    ).toThrow(ExclusiveRoutingViolationError);
  });
});

describe("S5-4 BLOCKER-2: coarse-only rejects ANY uids-scoped allow residue", () => {
  it("REJECTS a NON-provisioned operator allow scoped to the gate uid (pre-fix: only provisioned-* caught)", async () => {
    // Codex repro: an operator allow with a NON-`provisioned-` id and
    // scope.uids = [gate_uid]. The old residue filter only matched
    // `provisioned-*`, so this survived the coarse compose and the derived-DNS
    // rule inherited the gate-uid parent scope, preserving gate-scoped residue
    // in the composed output. Now it fails closed BEFORE any compose.
    let audited = false;
    await expect(
      composeExclusiveRoutingRules({
        base: {
          operatorRules: [
            operatorRule({
              id: "op-custom-endpoint",
              scope: { uids: [601] }, // gate_uid: exclusive-model residue
              match: { host: ["api.partner.example"], port: [443], protocol: "tcp" },
            }),
          ],
          resolvers: RESOLVERS,
          createdAt: CREATED_AT,
        },
        routing: {
          mode: "coarse-only",
          agent_uid: 600,
          reason: "exclusive bring-up abandoned; residue left on disk",
          audit: () => {
            audited = true;
          },
        },
      }),
    ).rejects.toThrow(ExclusiveRoutingResidueError);
    // Fail-closed BEFORE compose: the audit emitter never ran, so no coarse
    // ruleset (hence no derived DNS) was ever produced from the residue.
    expect(audited).toBe(false);
  });

  it("surfaces the rejected residue rule id in the error (honest, never silent)", async () => {
    let err: ExclusiveRoutingResidueError | null = null;
    try {
      await composeExclusiveRoutingRules({
        base: {
          operatorRules: [
            operatorRule({ id: "op-custom-endpoint", scope: { uids: [601] } }),
          ],
          resolvers: RESOLVERS,
          createdAt: CREATED_AT,
        },
        routing: {
          mode: "coarse-only",
          agent_uid: 600,
          reason: "residue on disk",
          audit: () => undefined,
        },
      });
    } catch (e) {
      err = e as ExclusiveRoutingResidueError;
    }
    expect(err).toBeInstanceOf(ExclusiveRoutingResidueError);
    expect(err!.residueRuleIds).toContain("op-custom-endpoint");
  });

  it("an allow scoped to the AGENT uid is also residue (not only gate-uid)", async () => {
    await expect(
      composeExclusiveRoutingRules({
        base: {
          operatorRules: [operatorRule({ id: "op-agent-scoped", scope: { uids: [600] } })],
          resolvers: RESOLVERS,
          createdAt: CREATED_AT,
        },
        routing: {
          mode: "coarse-only",
          agent_uid: 600,
          reason: "agent-scoped residue",
          audit: () => undefined,
        },
      }),
    ).rejects.toThrow(ExclusiveRoutingResidueError);
  });

  it("a uids-scoped DENY is inert (not residue): coarse-only still composes + audits", async () => {
    const audits: CoarseFallbackAuditRecord[] = [];
    const result = await composeExclusiveRoutingRules({
      base: {
        operatorRules: [
          ...buildProvisionedEgressRules(HERMES_ENDPOINT_SET, CREATED_AT), // coarse scope {}
          operatorRule({ id: "op-uid-deny", disposition: "deny", scope: { uids: [601] } }),
        ],
        resolvers: RESOLVERS,
        createdAt: CREATED_AT,
      },
      routing: {
        mode: "coarse-only",
        agent_uid: 600,
        reason: "a uid-scoped deny grants no off-box reach",
        audit: (record) => {
          audits.push(record);
        },
      },
    });
    expect(result.mode).toBe("coarse-only");
    expect(audits).toHaveLength(1);
  });
});
