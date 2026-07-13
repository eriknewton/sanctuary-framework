/**
 * Castle Wall Observe / Learn Allow-List v1 -- promote gating tests.
 *
 * CI DoD test 4: approving with the approval channel DOWN changes nothing;
 * approving with it UP produces exactly the expected new rules plus one
 * audit entry each.
 *
 * Plus the two-family gate fix-round regressions:
 *   - a promote against a TAMPERED existing manifest ABORTS and changes
 *     nothing (FIX 1);
 *   - a promote where the on-disk manifest digest changed between the
 *     approval basis and publish ABORTS (FIX 2);
 *   - the Tier-1 approval context carries each synthesized rule's EFFECTIVE
 *     match, including the widened `*.<domain>` form (FIX 3).
 */

import { describe, it, expect } from "vitest";
import { promoteCandidates } from "../../../src/castle-wall/observe/promote.js";
import type { VerifiedManifestRead } from "../../../src/castle-wall/observe/promote.js";
import { candidateKey, type CandidateObservation } from "../../../src/castle-wall/observe/types.js";
import { validateRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { AgentOrigin, OperatorBaseline } from "../../../src/castle-wall/allowlist/manifest.js";

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

/** A `readVerifiedManifest` double that always returns the same verified read. */
function manifest(read: VerifiedManifestRead): () => Promise<VerifiedManifestRead> {
  return async () => read;
}

const OK_EMPTY: VerifiedManifestRead = { status: "ok", rules: [], digest: "digest-empty" };
const NOW = new Date("2026-07-07T12:00:00.000Z");

describe("promoteCandidates: approval channel DOWN or denying", () => {
  it("channel unreachable (throws): no manifest mutation, live rules unaffected", async () => {
    const candidates = [candidate()];
    const candidatesByKey = byKeyMap(candidates);
    let publishCalled = false;

    await expect(
      promoteCandidates([{ key: candidateKey(candidates[0]!) }], candidatesByKey, {
        readVerifiedManifest: manifest(OK_EMPTY),
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
      readVerifiedManifest: manifest(OK_EMPTY),
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
        readVerifiedManifest: manifest(OK_EMPTY),
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

  it("merges new rules alongside the verified existing ruleset (never drops what was already there)", async () => {
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
      readVerifiedManifest: manifest({ status: "ok", rules: [existingRule], digest: "digest-one" }),
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
      readVerifiedManifest: manifest(OK_EMPTY),
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
      readVerifiedManifest: manifest(OK_EMPTY),
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

describe("promoteCandidates: FIX 1 -- tampered existing manifest aborts, changes nothing", () => {
  it("a tampered manifest at basis time aborts BEFORE approval, publish never called", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);
    let approveCalled = false;
    let publishCalled = false;

    const outcome = await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: manifest({ status: "tampered", reason: "signature verification failed" }),
      approve: async () => {
        approveCalled = true;
        return { allowed: true };
      },
      publish: async () => {
        publishCalled = true;
        return { written_rule_filenames: [], removed_rule_filenames: [] };
      },
      now: NOW,
    });

    expect(outcome.status).toBe("tampered_manifest");
    if (outcome.status !== "tampered_manifest") throw new Error("unreachable");
    expect(outcome.reason).toContain("signature verification failed");
    // A tampered manifest must never even reach the human approval prompt,
    // and must never be re-signed.
    expect(approveCalled).toBe(false);
    expect(publishCalled).toBe(false);
  });

  it("a manifest that verifies at basis but is tampered at publish time aborts, publish never called", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);
    let call = 0;
    let publishCalled = false;

    const outcome = await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: async (): Promise<VerifiedManifestRead> => {
        call += 1;
        // basis: ok; publish-time re-read: tampered (someone swapped it).
        return call === 1
          ? { status: "ok", rules: [], digest: "digest-basis" }
          : { status: "tampered", reason: "manifest replaced after approval" };
      },
      approve: async () => ({ allowed: true }),
      publish: async () => {
        publishCalled = true;
        return { written_rule_filenames: [], removed_rule_filenames: [] };
      },
      now: NOW,
    });

    expect(outcome.status).toBe("tampered_manifest");
    expect(publishCalled).toBe(false);
  });
});

describe("promoteCandidates: FIX 2 -- lost-update compare-and-set", () => {
  it("aborts when the on-disk manifest digest changed between the approval basis and publish", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);
    let call = 0;
    let publishCalled = false;

    const outcome = await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: async (): Promise<VerifiedManifestRead> => {
        call += 1;
        // basis digest differs from the publish-time digest: a concurrent
        // manifest update landed while the human was approving.
        return call === 1
          ? { status: "ok", rules: [], digest: "digest-basis" }
          : { status: "ok", rules: [], digest: "digest-CHANGED" };
      },
      approve: async () => ({ allowed: true }),
      publish: async () => {
        publishCalled = true;
        return { written_rule_filenames: [], removed_rule_filenames: [] };
      },
      now: NOW,
    });

    expect(outcome.status).toBe("manifest_changed");
    expect(publishCalled).toBe(false);
  });

  it("proceeds when the digest is unchanged between basis and publish", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);
    let publishCalled = false;

    const outcome = await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: manifest({ status: "ok", rules: [], digest: "digest-stable" }),
      approve: async () => ({ allowed: true }),
      publish: async (rules) => {
        publishCalled = true;
        return { written_rule_filenames: rules.map((r) => r.id), removed_rule_filenames: [] };
      },
      now: NOW,
    });

    expect(outcome.status).toBe("promoted");
    expect(publishCalled).toBe(true);
  });

  it("an absent manifest at basis and publish (fresh install) proceeds and publishes the first manifest", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);

    const outcome = await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: manifest({ status: "absent" }),
      approve: async () => ({ allowed: true }),
      publish: async (rules) => ({ written_rule_filenames: rules.map((r) => r.id), removed_rule_filenames: [] }),
      now: NOW,
    });

    expect(outcome.status).toBe("promoted");
    if (outcome.status !== "promoted") throw new Error("unreachable");
    expect(outcome.addedRules).toHaveLength(1);
  });

  it("aborts when a manifest is created (absent -> ok) between basis and publish", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);
    let call = 0;

    const outcome = await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: async (): Promise<VerifiedManifestRead> => {
        call += 1;
        return call === 1 ? { status: "absent" } : { status: "ok", rules: [], digest: "digest-new" };
      },
      approve: async () => ({ allowed: true }),
      publish: async () => ({ written_rule_filenames: [], removed_rule_filenames: [] }),
      now: NOW,
    });

    expect(outcome.status).toBe("manifest_changed");
  });
});

describe("promoteCandidates: FIX 3 -- approval context shows the synthesized effective match", () => {
  it("the Tier-1 approval context carries the exact-host synthesized match, not just the raw destination", async () => {
    const a = candidate({ host: "api.example.com", port: 443 });
    const candidatesByKey = byKeyMap([a]);
    let capturedContext: Record<string, unknown> | null = null;

    await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: manifest(OK_EMPTY),
      approve: async (_operation, context) => {
        capturedContext = context;
        return { allowed: false, reason: "review only" };
      },
      publish: async () => ({ written_rule_filenames: [], removed_rule_filenames: [] }),
      now: NOW,
    });

    expect(capturedContext).not.toBeNull();
    const serialized = JSON.stringify(capturedContext);
    expect(serialized).toContain("host=api.example.com");
    expect(serialized).toContain("scope=template:claude-code");
  });

  it("for per_template_etld1, the approval context shows the WIDENED *.<domain> match the human must see", async () => {
    // A legitimate (non-public-suffix) widening: api.example.com -> *.example.com.
    const a = candidate({ host: "api.example.com", port: 443 });
    const candidatesByKey = byKeyMap([a]);
    let capturedContext: Record<string, unknown> | null = null;

    await promoteCandidates([{ key: candidateKey(a), granularity: "per_template_etld1" }], candidatesByKey, {
      readVerifiedManifest: manifest(OK_EMPTY),
      approve: async (_operation, context) => {
        capturedContext = context;
        return { allowed: false, reason: "review only" };
      },
      publish: async () => ({ written_rule_filenames: [], removed_rule_filenames: [] }),
      now: NOW,
    });

    const serialized = JSON.stringify(capturedContext);
    expect(serialized).toContain("host_pattern=*.example.com");
  });

  it("a per_template_etld1 candidate landing on a public suffix (co.uk) is REFUSED (never offered, never in context)", async () => {
    const a = candidate({ host: "shop.foo.co.uk", port: 443 });
    const candidatesByKey = byKeyMap([a]);
    let approveCalled = false;

    const outcome = await promoteCandidates([{ key: candidateKey(a), granularity: "per_template_etld1" }], candidatesByKey, {
      readVerifiedManifest: manifest(OK_EMPTY),
      approve: async () => {
        approveCalled = true;
        return { allowed: true };
      },
      publish: async () => ({ written_rule_filenames: [], removed_rule_filenames: [] }),
      now: NOW,
    });

    // The only selected candidate refuses to synthesize -> nothing to approve.
    expect(outcome.status).toBe("no_candidates");
    if (outcome.status !== "no_candidates") throw new Error("unreachable");
    expect(outcome.dropped).toEqual([{ key: candidateKey(a), reason: "failed_validation" }]);
    expect(approveCalled).toBe(false);
  });
});

describe("promoteCandidates: #897 P1 -- carries verified manifest-level descriptors into publish", () => {
  const agentOrigin: AgentOrigin = { mode: "uid", agent_uid: 550, system_uid_allow_ceiling: 500 };
  const operatorBaseline: OperatorBaseline = {
    essentials: [{ name: "tailscale", signing_id: "io.tailscale.ipn.macos" }],
  };

  it("passes the verified agent_origin + operator_baseline from the read through to publish", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);
    let capturedRules: AllowlistRule[] | null = null;
    let capturedDescriptors: unknown = "unset";

    const outcome = await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: manifest({
        status: "ok",
        rules: [],
        digest: "digest-with-descriptors",
        agentOrigin,
        operatorBaseline,
      }),
      approve: async () => ({ allowed: true }),
      publish: async (rules, descriptors) => {
        capturedRules = rules;
        capturedDescriptors = descriptors;
        return { written_rule_filenames: rules.map((r) => r.id), removed_rule_filenames: [] };
      },
      now: NOW,
    });

    expect(outcome.status).toBe("promoted");
    // The descriptors reach publish verbatim (they come from the SAME verified
    // read the carry-forward rules come from -- never raw on-disk bytes).
    expect(capturedDescriptors).toEqual({ agentOrigin, operatorBaseline });
    expect(capturedRules).not.toBeNull();
  });

  it("passes an EMPTY descriptor set when the verified manifest carried none (absent stays absent)", async () => {
    const a = candidate();
    const candidatesByKey = byKeyMap([a]);
    let capturedDescriptors: unknown = "unset";

    await promoteCandidates([{ key: candidateKey(a) }], candidatesByKey, {
      readVerifiedManifest: manifest(OK_EMPTY),
      approve: async () => ({ allowed: true }),
      publish: async (rules, descriptors) => {
        capturedDescriptors = descriptors;
        return { written_rule_filenames: rules.map((r) => r.id), removed_rule_filenames: [] };
      },
      now: NOW,
    });

    // No descriptors on the source manifest -> an empty descriptor set, so
    // buildSignedManifest omits both fields and the canonical bytes are
    // unchanged (no accidental null/undefined descriptor injected).
    expect(capturedDescriptors).toEqual({});
  });
});
