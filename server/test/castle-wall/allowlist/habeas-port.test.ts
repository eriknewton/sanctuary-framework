/**
 * HABEAS PORT — reserved distress lane derivation tests.
 *
 * The sovereignty properties under test:
 *   1. The reserved loopback distress rule is ALWAYS present in the composed
 *      ruleset, with or without operator rules, with or without a webhook.
 *   2. An operator ruleset that claims the reserved id or could shadow the
 *      lane (deny/prompt over loopback:HABEAS_PORT or the webhook target) is
 *      REJECTED with a clear error — never silently accommodated.
 *   3. The lane is narrow: loopback + one fixed port, plus exactly the
 *      configured webhook host:port.
 */

import { describe, it, expect } from "vitest";
import {
  HABEAS_LOCAL_RULE_ID,
  HABEAS_WEBHOOK_RULE_ID,
  HABEAS_RULE_ID_PREFIX,
  HABEAS_DISTRESS_PORT,
  HABEAS_LOOPBACK_IPS,
  HABEAS_EMITTER_AGENT_ID,
  parseHabeasWebhookTarget,
  deriveHabeasDistressRules,
  findHabeasConflicts,
  findHabeasConflictsInComposed,
  isGenuineDerivedHabeasRule,
  composeEffectiveRules,
  HabeasConflictError,
} from "../../../src/castle-wall/allowlist/habeas-port.js";
import { DERIVED_DNS_RULE_ID } from "../../../src/castle-wall/allowlist/dns-derivation.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

const CREATED_AT = "2026-06-12T00:00:00.000Z";

function operatorRule(overrides: Partial<AllowlistRule> & { id: string }): AllowlistRule {
  return {
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: CREATED_AT,
    match: { host: "api.example.com" },
    scope: {},
    disposition: "allow",
    ...overrides,
  };
}

describe("parseHabeasWebhookTarget", () => {
  it("parses https URLs with the scheme default port", () => {
    expect(parseHabeasWebhookTarget("https://ops.example.com/distress")).toEqual({
      host: "ops.example.com",
      port: 443,
    });
  });

  it("parses explicit ports and http loopback", () => {
    expect(parseHabeasWebhookTarget("https://ops.example.com:8443/x")).toEqual({
      host: "ops.example.com",
      port: 8443,
    });
    expect(parseHabeasWebhookTarget("http://127.0.0.1:9000/distress")).toEqual({
      host: "127.0.0.1",
      port: 9000,
    });
  });

  it("rejects non-http(s) schemes and malformed URLs", () => {
    expect(parseHabeasWebhookTarget("ftp://ops.example.com/x")).toBeNull();
    expect(parseHabeasWebhookTarget("file:///etc/passwd")).toBeNull();
    expect(parseHabeasWebhookTarget("not a url")).toBeNull();
    expect(parseHabeasWebhookTarget("")).toBeNull();
  });
});

describe("deriveHabeasDistressRules", () => {
  it("always derives the loopback rule, marked derived, allow, emitter-scoped", () => {
    const rules = deriveHabeasDistressRules({ createdAt: CREATED_AT });
    expect(rules).toHaveLength(1);
    const local = rules[0]!;
    expect(local.id).toBe(HABEAS_LOCAL_RULE_ID);
    expect(local.disposition).toBe("allow");
    expect(local.derived).toBe(true);
    // Anti-exfil: scoped to the reserved emitter id, NEVER all-agents — no
    // wrapped agent's flows may match the lane.
    expect(local.scope).toEqual({ agent_ids: [HABEAS_EMITTER_AGENT_ID] });
    expect(local.match.ip).toEqual([...HABEAS_LOOPBACK_IPS]);
    expect(local.match.port).toEqual([HABEAS_DISTRESS_PORT]);
    expect(local.match.protocol).toBe("tcp");
    // The lane is narrow: no host axes, no broad cidr.
    expect(local.match.host).toBeUndefined();
    expect(local.match.host_pattern).toBeUndefined();
    expect(local.match.cidr).toBeUndefined();
  });

  it("adds exactly the webhook host:port when a webhook is configured", () => {
    const rules = deriveHabeasDistressRules({
      webhook: { host: "ops.example.com", port: 443 },
      createdAt: CREATED_AT,
    });
    expect(rules.map((r) => r.id)).toEqual([
      HABEAS_LOCAL_RULE_ID,
      HABEAS_WEBHOOK_RULE_ID,
    ]);
    const webhook = rules[1]!;
    expect(webhook.match.host).toEqual(["ops.example.com"]);
    expect(webhook.match.port).toEqual([443]);
    expect(webhook.match.protocol).toBe("tcp");
    expect(webhook.derived).toBe(true);
    expect(webhook.disposition).toBe("allow");
    expect(webhook.scope).toEqual({ agent_ids: [HABEAS_EMITTER_AGENT_ID] });
  });

  it("never emits an all-agents scope on any derived habeas rule", () => {
    const rules = deriveHabeasDistressRules({
      webhook: { host: "ops.example.com", port: 443 },
      createdAt: CREATED_AT,
    });
    for (const rule of rules) {
      expect(rule.scope.agent_ids).toEqual([HABEAS_EMITTER_AGENT_ID]);
    }
  });
});

describe("findHabeasConflicts", () => {
  it("returns no issues for an ordinary allow-list", () => {
    const rules = [
      operatorRule({ id: "r1", match: { host: "api.example.com" } }),
      operatorRule({ id: "r2", match: { port: 443 }, disposition: "allow" }),
    ];
    expect(findHabeasConflicts(rules)).toEqual([]);
  });

  it("rejects operator rules claiming the reserved id or prefix", () => {
    for (const id of [
      HABEAS_LOCAL_RULE_ID,
      HABEAS_WEBHOOK_RULE_ID,
      `${HABEAS_RULE_ID_PREFIX}_imposter`,
    ]) {
      const issues = findHabeasConflicts([operatorRule({ id, disposition: "deny" })]);
      expect(issues).toHaveLength(1);
      expect(issues[0]).toContain(HABEAS_RULE_ID_PREFIX);
    }
  });

  it("rejects a deny rule covering loopback at the habeas port", () => {
    const issues = findHabeasConflicts([
      operatorRule({
        id: "block-loopback",
        match: { ip: "127.0.0.1", port: HABEAS_DISTRESS_PORT },
        disposition: "deny",
      }),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]).toContain("habeas");
  });

  it("rejects an any-destination deny whose port set covers the habeas port", () => {
    const issues = findHabeasConflicts([
      operatorRule({
        id: "block-port-range",
        match: { port: [80, HABEAS_DISTRESS_PORT] },
        disposition: "deny",
      }),
    ]);
    expect(issues).toHaveLength(1);
  });

  it("rejects a cidr deny containing loopback with no port axis (match-any port)", () => {
    const issues = findHabeasConflicts([
      operatorRule({
        id: "block-all-v4",
        match: { cidr: "0.0.0.0/0" },
        disposition: "deny",
      }),
    ]);
    expect(issues).toHaveLength(1);
  });

  it("rejects prompt rules the same as deny rules (a prompt can time out into deny)", () => {
    const issues = findHabeasConflicts([
      operatorRule({
        id: "prompt-loopback",
        match: { ip: ["::1"], port: HABEAS_DISTRESS_PORT },
        disposition: "prompt",
      }),
    ]);
    expect(issues).toHaveLength(1);
  });

  it("accepts a deny scoped away from the lane", () => {
    const issues = findHabeasConflicts([
      operatorRule({
        id: "block-other-port",
        match: { ip: "127.0.0.1", port: HABEAS_DISTRESS_PORT + 1 },
        disposition: "deny",
      }),
      operatorRule({
        id: "block-external",
        match: { cidr: "203.0.113.0/24" },
        disposition: "deny",
      }),
    ]);
    expect(issues).toEqual([]);
  });

  it("rejects deny rules covering the configured webhook target", () => {
    const webhook = { host: "ops.example.com", port: 443 };
    const byHost = findHabeasConflicts(
      [operatorRule({ id: "h", match: { host: "OPS.example.com" }, disposition: "deny" })],
      webhook,
    );
    expect(byHost).toHaveLength(1);
    const byPattern = findHabeasConflicts(
      [operatorRule({ id: "p", match: { host_pattern: "*.example.com" }, disposition: "deny" })],
      webhook,
    );
    expect(byPattern).toHaveLength(1);
    const byAnyDestPort = findHabeasConflicts(
      [operatorRule({ id: "q", match: { port: 443 }, disposition: "deny" })],
      webhook,
    );
    expect(byAnyDestPort).toHaveLength(1);
  });

  it("does not flag webhook-host denies when no webhook is configured", () => {
    const issues = findHabeasConflicts([
      operatorRule({ id: "h", match: { host: "ops.example.com", port: 443 }, disposition: "deny" }),
    ]);
    expect(issues).toEqual([]);
  });
});

describe("composeEffectiveRules", () => {
  const RESOLVERS = ["1.1.1.1"];

  it("always injects the loopback habeas rule, even with zero operator rules", () => {
    const rules = composeEffectiveRules({
      operatorRules: [],
      resolvers: RESOLVERS,
      createdAt: CREATED_AT,
    });
    expect(rules.map((r) => r.id)).toContain(HABEAS_LOCAL_RULE_ID);
  });

  it("injects the webhook rule and lets DNS derivation see its hostname", () => {
    const rules = composeEffectiveRules({
      operatorRules: [],
      resolvers: RESOLVERS,
      distressWebhook: { host: "ops.example.com", port: 443 },
      createdAt: CREATED_AT,
    });
    const ids = rules.map((r) => r.id);
    expect(ids).toContain(HABEAS_LOCAL_RULE_ID);
    expect(ids).toContain(HABEAS_WEBHOOK_RULE_ID);
    // The webhook hostname must stay resolvable: the scoped DNS allow (#380)
    // derives from the habeas webhook rule's host axis.
    expect(ids).toContain(DERIVED_DNS_RULE_ID);
  });

  it("derives no DNS rule for a local-only lane with no hostname rules", () => {
    const rules = composeEffectiveRules({
      operatorRules: [],
      resolvers: RESOLVERS,
      createdAt: CREATED_AT,
    });
    expect(rules.map((r) => r.id)).not.toContain(DERIVED_DNS_RULE_ID);
  });

  it("preserves operator rules ahead of the derived rules", () => {
    const op = operatorRule({ id: "r1" });
    const rules = composeEffectiveRules({
      operatorRules: [op],
      resolvers: RESOLVERS,
      createdAt: CREATED_AT,
    });
    expect(rules[0]).toEqual(op);
  });

  it("throws HabeasConflictError (fail closed) on a shadowing ruleset", () => {
    const attempt = () =>
      composeEffectiveRules({
        operatorRules: [
          operatorRule({
            id: "silence-distress",
            match: { port: HABEAS_DISTRESS_PORT },
            disposition: "deny",
          }),
        ],
        resolvers: RESOLVERS,
        createdAt: CREATED_AT,
      });
    expect(attempt).toThrow(HabeasConflictError);
    expect(attempt).toThrow(/habeas distress/);
    expect(attempt).toThrow(/cannot be removed or shadowed/);
  });

  it("throws on an operator rule claiming the reserved id", () => {
    expect(() =>
      composeEffectiveRules({
        operatorRules: [
          operatorRule({ id: HABEAS_LOCAL_RULE_ID, disposition: "deny" }),
        ],
        resolvers: RESOLVERS,
        createdAt: CREATED_AT,
      }),
    ).toThrow(HabeasConflictError);
  });
});

describe("composed-manifest gate (Rust parity mirror)", () => {
  const RESOLVERS = ["1.1.1.1"];
  // Verdict-level parity with the Rust gate is asserted from the shared
  // fixture (habeas-conflict-parity.test.ts); these tests pin the TS-side
  // genuineness recognizer's load-bearing edges.

  function derivedRules(): AllowlistRule[] {
    return deriveHabeasDistressRules({
      webhook: { host: "ops.example.com", port: 443 },
      createdAt: CREATED_AT,
    });
  }

  it("recognizes the composer's own derived rules as genuine", () => {
    for (const rule of derivedRules()) {
      expect(isGenuineDerivedHabeasRule(rule), rule.id).toBe(true);
    }
  });

  it("does not trust the derived flag: a flag-only reserved rule is not genuine", () => {
    const forged = operatorRule({
      id: HABEAS_LOCAL_RULE_ID,
      match: { host: "evil.example.com" },
      derived: true,
    });
    expect(isGenuineDerivedHabeasRule(forged)).toBe(false);
    const issues = findHabeasConflictsInComposed([forged]);
    expect(issues.some((i) => i.includes(HABEAS_RULE_ID_PREFIX))).toBe(true);
  });

  it("a time_window on a reserved-id rule breaks genuineness", () => {
    const [local] = derivedRules();
    const withWindow: AllowlistRule = {
      ...local,
      time_window: { start: "09:00", end: "17:00" },
    };
    expect(isGenuineDerivedHabeasRule(withWindow)).toBe(false);
  });

  it("composeEffectiveRules output always passes the composed gate", () => {
    const composed = composeEffectiveRules({
      operatorRules: [operatorRule({ id: "r1" })],
      resolvers: RESOLVERS,
      distressWebhook: { host: "ops.example.com", port: 443 },
      createdAt: CREATED_AT,
    });
    expect(findHabeasConflictsInComposed(composed)).toEqual([]);
  });

  it("rejects a composed manifest missing the always-on local lane", () => {
    const issues = findHabeasConflictsInComposed([operatorRule({ id: "r1" })]);
    expect(issues.length).toBe(1);
    expect(issues[0]).toContain("exactly one");
    expect(issues[0]).toContain(HABEAS_LOCAL_RULE_ID);
  });

  it("rejects duplicate reserved webhook rules (no target redefinition)", () => {
    const rules = deriveHabeasDistressRules({
      webhook: { host: "ops.example.com", port: 443 },
      createdAt: CREATED_AT,
    });
    const evilTwin = deriveHabeasDistressRules({
      webhook: { host: "evil.example.com", port: 443 },
      createdAt: CREATED_AT,
    }).find((r) => r.id === HABEAS_WEBHOOK_RULE_ID)!;
    const issues = findHabeasConflictsInComposed([...rules, evilTwin]);
    expect(issues.some((i) => i.includes("must be unique"))).toBe(true);
  });
});
