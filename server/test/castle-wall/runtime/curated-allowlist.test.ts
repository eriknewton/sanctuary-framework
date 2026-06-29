/**
 * Castle Wall runtime curated-allowlist tests.
 *
 * Asserts the E6.1 default-not-enabled invariant and the resolveCuratedRules
 * filter; ensures the canonical curated set is frozen and can't be mutated
 * by callers.
 */

import { describe, it, expect } from "vitest";

import {
  CURATED_ALLOWLIST,
  MESSAGING_HOST_DENYLIST,
  resolveCuratedRules,
} from "../../../src/castle-wall/runtime/curated-allowlist.js";
import {
  validateRule,
  type AllowlistRule,
} from "../../../src/castle-wall/allowlist/schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";

/** Every host literal a curated entry would put on the wire. */
function curatedHosts(): string[] {
  const hosts: string[] = [];
  for (const entry of CURATED_ALLOWLIST) {
    const h = entry.rule.match.host;
    if (Array.isArray(h)) hosts.push(...h);
    else if (typeof h === "string") hosts.push(h);
  }
  return hosts;
}

describe("castle-wall/runtime/curated-allowlist : invariants", () => {
  it("ships at least one curated entry", () => {
    expect(CURATED_ALLOWLIST.length).toBeGreaterThan(0);
  });

  it("default_enabled is false on every curated entry (E6.1)", () => {
    for (const entry of CURATED_ALLOWLIST) {
      expect(entry.default_enabled).toBe(false);
    }
  });

  it("every curated rule has disposition 'allow'", () => {
    for (const entry of CURATED_ALLOWLIST) {
      expect(entry.rule.disposition).toBe("allow");
    }
  });

  it("every curated rule_id matches its embedded rule.id", () => {
    for (const entry of CURATED_ALLOWLIST) {
      expect(entry.rule.id).toBe(entry.rule_id);
    }
  });

  it("curated set is frozen", () => {
    expect(Object.isFrozen(CURATED_ALLOWLIST)).toBe(true);
    expect(Object.isFrozen(CURATED_ALLOWLIST[0])).toBe(true);
  });
});

describe("castle-wall/runtime/curated-allowlist : resolveCuratedRules", () => {
  it("returns only the rules whose ids the operator selected", () => {
    const all = CURATED_ALLOWLIST.map((e) => e.rule_id);
    const ids = [all[0]!];
    const rules = resolveCuratedRules(ids);
    expect(rules.length).toBe(1);
    expect(rules[0]!.id).toBe(ids[0]);
  });

  it("returns empty when no ids selected", () => {
    expect(resolveCuratedRules([]).length).toBe(0);
  });

  it("ignores unknown rule ids", () => {
    const rules = resolveCuratedRules(["does-not-exist"]);
    expect(rules.length).toBe(0);
  });
});

describe("castle-wall/runtime/curated-allowlist : exfil-hardening (item 5)", () => {
  it("no curated default host is a messaging-platform host", () => {
    // The DEFAULT suggestion set must never pre-offer a messaging channel
    // (Slack / Discord / Telegram and siblings): those are the lowest-friction
    // exfil lanes. Substring match catches regional/versioned siblings too.
    const offenders: string[] = [];
    for (const host of curatedHosts()) {
      const lower = host.toLowerCase();
      for (const banned of MESSAGING_HOST_DENYLIST) {
        if (lower.includes(banned.toLowerCase())) {
          offenders.push(`${host} (matches ${banned})`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("denylist and curated set are disjoint by exact host as well", () => {
    const curated = new Set(curatedHosts().map((h) => h.toLowerCase()));
    for (const banned of MESSAGING_HOST_DENYLIST) {
      expect(curated.has(banned.toLowerCase())).toBe(false);
    }
  });

  it("the messaging denylist is frozen and non-empty", () => {
    expect(Object.isFrozen(MESSAGING_HOST_DENYLIST)).toBe(true);
    expect(MESSAGING_HOST_DENYLIST.length).toBeGreaterThan(0);
  });

  it("an explicit operator allow of a messaging host is still valid (default-only, not a hard block)", () => {
    // The hardening tightens only the out-of-box DEFAULT. An operator who
    // genuinely needs a messaging channel authors a normal AllowlistRule for
    // that host; nothing in the curated-default change rejects it. Prove the
    // operator-authored rule passes the schema gate that all operator rules
    // pass before signing.
    const operatorSlackRule: AllowlistRule = {
      id: "operator-explicit-slack-webhook",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-06-29T00:00:00Z",
      description: "Operator-authored explicit allow for Slack webhook egress",
      match: { host: ["hooks.slack.com"], port: [443], protocol: "tcp" },
      scope: {},
      disposition: "allow",
    };
    expect(validateRule(operatorSlackRule)).toEqual([]);

    const operatorTelegramRule: AllowlistRule = {
      ...operatorSlackRule,
      id: "operator-explicit-telegram-bot",
      description: "Operator-authored explicit allow for Telegram bot API",
      match: { host: ["api.telegram.org"], port: [443], protocol: "tcp" },
    };
    expect(validateRule(operatorTelegramRule)).toEqual([]);
  });
});
