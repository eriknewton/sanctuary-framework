/**
 * Castle Wall Observe / Learn Allow-List v1 -- promote gating tests.
 *
 * CI DoD test 4: approving with the approval channel DOWN changes nothing;
 * approving with it UP produces exactly the expected new rules plus one
 * audit entry each.
 */

import { describe, it, expect } from "vitest";
import { promoteCandidates } from "../../../src/castle-wall/observe/promote.js";
import { candidateKey, type CandidateObservation } from "../../../src/castle-wall/observe/types.js";
import { validateRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

function candidate(overrides: Partial<CandidateObservation> = {}): CandidateObservation {
  return {
    agent_id: "agent-1",
    agent_template: "claude-code",
    host: "api.example.com",
    ip: "203.0.113.5",
    port: 443,
    protocol: "tcp",
    hostname_source: "sni",
    times_seen: 3,
    first_seen: "2026-07-07T10:00:00.000Z",
    last_seen: "2026-07-07T10:05:00.000Z",
    would_be_disposition: "denied",
    exfil_risk: false,
    ...overrides,
  };
}

function byKeyMap(candidates: CandidateObservation[]): Map<string, CandidateObservation> {
  return new Map(candidates.map((c) => [candidateKey(c), c]));
}

const NOW = new Date("2026-07-07T12:00:00.000Z");

describe("promoteCandidates: approval channel DOWN or denying", () => {
  it("channel unreachable (throws): no manifest mutation, live rules unaffected", async () => {
    const candidates = [candidate()];
    const candidatesByKey = byKeyMap(candidates);
    let publishCalled = false;

    await expect(
      promoteCandidates([{ key: candidateKey(candidates[0]!) }], candidatesByKey, {
        currentRules: [],
        approve: async () => {
          throw new Error("approval channel unreachable");
        },
        publish: async (rules) => {
          publishCalled = true;
          return { written_rule_filenames: rules.map((r) => r.id), removed_rule_filenames: [] };
        },
        now: NOW,
      }),
    ).rejects.toThrow("approval channel unreachable");

    expect(publishCalled).toBe(false);
  });

  it("channel resolves denied: status 'denied', publish never called, no rules added", async () => {
    const candidates = [candidate()];
    const candidatesByKey = byKeyMap(candidates);
    let publishCalled = false;

    const outcome = await promoteCandidates([{ key: candidateKey(candidates[0]!) }], candidatesByKey, {
      currentRules: [],
      approve: async () => ({ allowed: false, reason: "not approved" }),
      publish: async (rules) => {
        publishCalled = true;
        return { written_rule_filenames: rules.map((r) => r.id), removed_rule_filenames: [] };
      },
      now: NOW,
    });

    expect(outcome.status).toBe("denied");
    expect(publishCalled).toBe(false);
  });
});

describe("promoteCandidates: approval channel UP (approved)", () => {
  it("produces exactly the expected new rules and one audit call per promoted candidate", async () => {
    const a = candidate({ host: "api.example.com", port: 443 });
    const b = candidate({ host: "pypi.org", ip: "151.101.0.1", port: 443, agent_id: "agent-2" });
    const candidatesByKey = byKeyMap([a, b]);

    let publishedRules: AllowlistRule[] | null = null;
    const auditedKeys: string[] = [];

    const outcome = await promoteCandidates(
      [{ key: candidateKey(a) }, { key: candidateKey(b) }],
      candidatesByKey,
      {
        currentRules: [],
        approve: async () => ({ allowed: true }),
        publish: async (rules) => {
          publishedRules = rules;
          return { written_rule_filenames: rules.map((r) => r.id), removed_rule_filenames: [] };
        },
        auditPromotedCandidate: async (row) => {
          auditedKeys.push(row.key);
        },
        now: NOW,
      },
    );

    expect(outcome.status).toBe("promoted");
    if (outcome.status !== "promoted") throw new Error("unreachable");
    expect(outcome.addedRules).toHaveLength(2);
    for (const rule of outcome.addedRules) {
      expect(validateRule(rule)).toEqual([]);
    }
    expect(publishedRules).toEqual(outcome.addedRules);
    // Exactly one audit call per promoted candidate.
    expect(auditedKeys.sort()).toEqual([candidateKey(a), candidateKey(b)].sort());
    expect(outcome.promotedKeys.sort()).toEqual([candidateKey(a), candidateKey(b)].sort());
  });

  it("merges new rules alongside the existing live ruleset (never drops what was already there)", async () => {
    const existingRule: AllowlistRule = {
      id: "curated-anthropic-api",
      schema_version: 1,
      created_at: "2026-05-04T00:00:00Z",
      match: { host: ["api.anthropic.com"], port: [443], protocol: "tcp" },
      scope: {},
      disposition: "allow",
    };
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);
    let publishedRules: AllowlistRule[] | null = null;

    await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      currentRules: [existingRule],
      approve: async () => ({ allowed: true }),
      publish: async (rules) => {
        publishedRules = rules;
        return { written_rule_filenames: [], removed_rule_filenames: [] };
      },
      now: NOW,
    });

    expect(publishedRules).toHaveLength(2);
    expect(publishedRules!.map((r) => r.id)).toContain("curated-anthropic-api");
  });

  it("drops a not-found key without calling approve or publish for it, and reports it in `dropped`", async () => {
    const outcome = await promoteCandidates([{ key: "nonexistent-key" }], new Map(), {
      currentRules: [],
      approve: async () => ({ allowed: true }),
      publish: async () => ({ written_rule_filenames: [], removed_rule_filenames: [] }),
      now: NOW,
    });
    expect(outcome.status).toBe("no_candidates");
    if (outcome.status !== "no_candidates") throw new Error("unreachable");
    expect(outcome.dropped).toEqual([{ key: "nonexistent-key", reason: "not_found" }]);
  });

  it("a best-effort audit throw does not change the outcome status (manifest already published)", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);

    const outcome = await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      currentRules: [],
      approve: async () => ({ allowed: true }),
      publish: async (rules) => ({ written_rule_filenames: rules.map((r) => r.id), removed_rule_filenames: [] }),
      auditPromotedCandidate: async () => {
        throw new Error("audit sink down");
      },
      now: NOW,
    });

    expect(outcome.status).toBe("promoted");
  });
});
