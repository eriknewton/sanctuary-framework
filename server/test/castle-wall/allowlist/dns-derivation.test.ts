/**
 * Scoped DNS rule auto-derivation tests (#380).
 *
 * Exercises the security invariants: a derived rule appears ONLY when a
 * hostname allow-rule exists, scopes to the system resolver set only, inherits
 * scope from its parents, and is absent (fail closed) when no resolvers are
 * known.
 */

import { describe, it, expect } from "vitest";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import {
  deriveDnsRuleForHostnameRules,
  normalizeResolvers,
  DERIVED_DNS_RULE_ID,
} from "../../../src/castle-wall/allowlist/dns-derivation.js";

function hostRule(overrides: Partial<AllowlistRule> = {}): AllowlistRule {
  return {
    id: "host-1",
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-06-10T00:00:00.000Z",
    match: { host: "api.anthropic.com", port: 443, protocol: "tcp" },
    scope: {},
    disposition: "allow",
    ...overrides,
  };
}

const CREATED_AT = "2026-06-10T12:00:00.000Z";

describe("castle-wall/allowlist/dns-derivation normalizeResolvers", () => {
  it("keeps valid IPs, strips ports and zone ids, dedupes", () => {
    expect(
      normalizeResolvers([
        "1.1.1.1",
        "8.8.8.8:1053",
        "[2001:4860:4860::8888]:53",
        "fe80::1%en0",
        "2001:4860:4860::8888",
        "1.1.1.1",
        "garbage",
        42,
      ])
    ).toEqual(["1.1.1.1", "8.8.8.8", "2001:4860:4860::8888", "fe80::1"]);
  });
});

describe("castle-wall/allowlist/dns-derivation deriveDnsRuleForHostnameRules", () => {
  it("derives a scoped DNS rule when a hostname allow-rule exists", () => {
    const derived = deriveDnsRuleForHostnameRules({
      rules: [hostRule()],
      resolvers: ["1.1.1.1", "8.8.8.8"],
      createdAt: CREATED_AT,
    });
    expect(derived).not.toBeNull();
    expect(derived?.id).toBe(DERIVED_DNS_RULE_ID);
    expect(derived?.derived).toBe(true);
    expect(derived?.disposition).toBe("allow");
    expect(derived?.match).toEqual({
      ip: ["1.1.1.1", "8.8.8.8"],
      port: [53],
      protocol: "tcp+udp",
    });
  });

  it("returns null when there are NO hostname rules (no standing port-53 grant)", () => {
    const portOnly = hostRule({ id: "p-1", match: { port: 443 } });
    const ipOnly = hostRule({ id: "i-1", match: { ip: "9.9.9.9" } });
    expect(
      deriveDnsRuleForHostnameRules({
        rules: [portOnly, ipOnly],
        resolvers: ["1.1.1.1"],
        createdAt: CREATED_AT,
      })
    ).toBeNull();
  });

  it("ignores hostname rules that are not allow-disposition", () => {
    const denyHost = hostRule({ id: "d-1", disposition: "deny" });
    const promptHost = hostRule({ id: "pr-1", disposition: "prompt" });
    expect(
      deriveDnsRuleForHostnameRules({
        rules: [denyHost, promptHost],
        resolvers: ["1.1.1.1"],
        createdAt: CREATED_AT,
      })
    ).toBeNull();
  });

  it("derives from a host_pattern allow-rule too", () => {
    const derived = deriveDnsRuleForHostnameRules({
      rules: [hostRule({ match: { host_pattern: "*.anthropic.com" } })],
      resolvers: ["1.1.1.1"],
      createdAt: CREATED_AT,
    });
    expect(derived?.match.ip).toEqual(["1.1.1.1"]);
  });

  it("fails closed (returns null) when the resolver set is empty", () => {
    expect(
      deriveDnsRuleForHostnameRules({
        rules: [hostRule()],
        resolvers: ["garbage", ""],
        createdAt: CREATED_AT,
      })
    ).toBeNull();
  });

  it("is unscoped when any parent hostname rule is unscoped (all agents)", () => {
    const derived = deriveDnsRuleForHostnameRules({
      rules: [
        hostRule({ id: "h-1", scope: { agent_ids: ["agent-a"] } }),
        hostRule({ id: "h-2", scope: {} }), // all agents
      ],
      resolvers: ["1.1.1.1"],
      createdAt: CREATED_AT,
    });
    expect(derived?.scope).toEqual({});
  });

  it("unions parent scopes when all parents are scoped", () => {
    const derived = deriveDnsRuleForHostnameRules({
      rules: [
        hostRule({ id: "h-1", scope: { agent_ids: ["agent-b", "agent-a"] } }),
        hostRule({ id: "h-2", scope: { agent_ids: ["agent-a"], template_ids: ["claude-code"] } }),
      ],
      resolvers: ["1.1.1.1"],
      createdAt: CREATED_AT,
    });
    expect(derived?.scope).toEqual({
      agent_ids: ["agent-a", "agent-b"],
      template_ids: ["claude-code"],
    });
  });

  // --- S5-0 (2026-07-14): scope.uids must not silently widen back to "all" ---

  it("a uids-only scoped hostname rule is NOT treated as unscoped (scope-leak regression guard)", () => {
    const derived = deriveDnsRuleForHostnameRules({
      rules: [hostRule({ id: "gate-host", scope: { uids: [601] } })],
      resolvers: ["1.1.1.1"],
      createdAt: CREATED_AT,
    });
    // Before the S5-0 fix, `scopeIsAll` ignored `uids` entirely and this
    // asserted `{}` (unscoped -- reachable by every agent, including the one
    // the gate-only hostname rule was never meant to grant DNS resolution to).
    expect(derived?.scope).toEqual({ uids: [601] });
  });

  it("unions scope.uids across multiple gate-scoped hostname rules", () => {
    const derived = deriveDnsRuleForHostnameRules({
      rules: [
        hostRule({ id: "h-1", scope: { uids: [601] } }),
        hostRule({ id: "h-2", scope: { uids: [601, 602] } }),
      ],
      resolvers: ["1.1.1.1"],
      createdAt: CREATED_AT,
    });
    expect(derived?.scope).toEqual({ uids: [601, 602] });
  });

  it("a mix of agent_ids-scoped and uids-scoped hostname rules unions both axes", () => {
    const derived = deriveDnsRuleForHostnameRules({
      rules: [
        hostRule({ id: "h-1", scope: { agent_ids: ["agent-a"] } }),
        hostRule({ id: "h-2", scope: { uids: [601] } }),
      ],
      resolvers: ["1.1.1.1"],
      createdAt: CREATED_AT,
    });
    expect(derived?.scope).toEqual({ agent_ids: ["agent-a"], uids: [601] });
  });

  it("STILL widens to unscoped when any parent is unscoped, even alongside a uids-scoped parent", () => {
    const derived = deriveDnsRuleForHostnameRules({
      rules: [
        hostRule({ id: "h-1", scope: { uids: [601] } }),
        hostRule({ id: "h-2", scope: {} }), // all agents
      ],
      resolvers: ["1.1.1.1"],
      createdAt: CREATED_AT,
    });
    expect(derived?.scope).toEqual({});
  });

  it("yields to an operator-authored rule that claims the reserved derived id", () => {
    const operatorOverride = hostRule({
      id: DERIVED_DNS_RULE_ID,
      match: { ip: "1.2.3.4", port: 53 },
    });
    expect(
      deriveDnsRuleForHostnameRules({
        rules: [hostRule(), operatorOverride],
        resolvers: ["1.1.1.1"],
        createdAt: CREATED_AT,
      })
    ).toBeNull();
  });
});
