/**
 * Tests for the confined-agent egress provisioning module (design doc
 * Confined_Agent_Egress_Design_2026-07-10.md): rule building + provenance
 * ids, the Tier-1 plan render (exfil-risk + broad-authority markings), the
 * static pre-arm verification (same TS matcher the enforcement paths use +
 * #380 derived-DNS presence), publish/scrub against a real disposable
 * tmpdir (never the real ~/.sanctuary), and the as-uid probe helpers.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach } from "vitest";

import {
  HERMES_ENDPOINT_SET,
  AGENT_EGRESS_NEGATIVE_CONTROL_HOST,
  provisionedRuleId,
  provisionedRuleIdPrefix,
  endpointIsMessagingExfilRisk,
  buildProvisionedEgressRules,
  renderEgressPlanLines,
  verifyProvisionedEgressStatically,
  publishProvisionedEgressRules,
  scrubProvisionedEgressRules,
  readEgressRulesFromDisk,
  egressRulesDir,
  buildAgentEgressProbeSpecs,
  buildAgentEgressReport,
  asUidTlsProbeArgv,
  asUidProbeReachableDecision,
  type HarnessEndpointSet,
} from "../../../src/castle-wall/provision/egress.js";
import { validateRule } from "../../../src/castle-wall/allowlist/schema.js";
import { DERIVED_DNS_RULE_ID } from "../../../src/castle-wall/allowlist/dns-derivation.js";

const RESOLVERS = ["1.1.1.1", "8.8.8.8"];
const NOW = "2026-07-10T00:00:00Z";

const tempDirs: string[] = [];
afterEach(async () => {
  for (const dir of tempDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function makeFortress(): Promise<string> {
  const fortress = await mkdtemp(join(tmpdir(), "sanctuary-egress-test-"));
  tempDirs.push(fortress);
  return fortress;
}

describe("castle-wall/provision/egress: endpoint set + rule building", () => {
  it("the Hermes seed set uses PER-SERVICE Google hosts, never the shared www.googleapis.com gateway (MED-1)", () => {
    const hosts = HERMES_ENDPOINT_SET.endpoints.map((e) => e.host);
    expect(hosts).not.toContain("www.googleapis.com");
    expect(hosts).toContain("gmail.googleapis.com");
    expect(hosts).toContain("oauth2.googleapis.com");
    expect(hosts).toContain("accounts.google.com");
    expect(hosts).toContain("api.venice.ai");
    expect(hosts).toContain("api.telegram.org");
    // Every declared endpoint is pinned to 443/tcp (never "any port").
    for (const endpoint of HERMES_ENDPOINT_SET.endpoints) {
      expect(endpoint.port).toBe(443);
      expect(endpoint.protocol).toBe("tcp");
    }
  });

  it("rule ids are provenance-tagged (provisioned-hermes-<digest12>), stable across runs, and distinct per endpoint", () => {
    const ids = HERMES_ENDPOINT_SET.endpoints.map((e) => provisionedRuleId("hermes", e));
    for (const id of ids) {
      expect(id).toMatch(/^provisioned-hermes-[0-9a-f]{12}$/);
    }
    expect(new Set(ids).size).toBe(ids.length);
    // Deterministic (idempotent re-provision writes the same files).
    expect(provisionedRuleId("hermes", HERMES_ENDPOINT_SET.endpoints[0]!)).toBe(ids[0]);
  });

  it("built rules validate against the schema, are UNSCOPED, derived:true, exact host + pinned port/protocol, disposition allow", () => {
    const rules = buildProvisionedEgressRules(HERMES_ENDPOINT_SET, NOW);
    expect(rules).toHaveLength(HERMES_ENDPOINT_SET.endpoints.length);
    for (const rule of rules) {
      expect(validateRule(rule)).toEqual([]);
      expect(rule.disposition).toBe("allow");
      expect(rule.derived).toBe(true);
      expect(rule.scope).toEqual({});
      expect(rule.id.startsWith(provisionedRuleIdPrefix("hermes"))).toBe(true);
      expect(rule.match.port).toEqual([443]);
      expect(rule.match.protocol).toBe("tcp");
      expect(Array.isArray(rule.match.host)).toBe(true);
      expect(rule.description).toContain("hermes");
    }
  });

  it("telegram is flagged messaging-exfil-risk (computed from MESSAGING_HOST_DENYLIST, never hand-declared)", () => {
    const telegram = HERMES_ENDPOINT_SET.endpoints.find((e) => e.host === "api.telegram.org")!;
    const venice = HERMES_ENDPOINT_SET.endpoints.find((e) => e.host === "api.venice.ai")!;
    expect(endpointIsMessagingExfilRisk(telegram)).toBe(true);
    expect(endpointIsMessagingExfilRisk(venice)).toBe(false);
  });

  it("the plan render names every grant, marks messaging hosts EXFIL-RISK, and marks broad gateways BROAD AUTHORITY", () => {
    const set: HarnessEndpointSet = {
      harnessId: "hermes",
      endpoints: [
        ...HERMES_ENDPOINT_SET.endpoints,
        {
          name: "Shared Google gateway (hypothetical fallback)",
          host: "www.googleapis.com",
          port: 443,
          protocol: "tcp",
          riskClass: "broad-authority-gateway",
        },
      ],
    };
    const lines = renderEgressPlanLines(set);
    expect(lines[0]).toContain("default-deny");
    const telegramLine = lines.find((l) => l.includes("api.telegram.org"))!;
    expect(telegramLine).toContain("EXFIL-RISK");
    const gatewayLine = lines.find((l) => l.includes("www.googleapis.com"))!;
    expect(gatewayLine).toContain("BROAD AUTHORITY");
    for (const endpoint of set.endpoints) {
      expect(lines.some((l) => l.includes(`${endpoint.host}:${endpoint.port}`))).toBe(true);
    }
  });
});

describe("castle-wall/provision/egress: static verification", () => {
  it("passes when every endpoint has an allow match and the derived DNS rule is derivable", () => {
    const rules = buildProvisionedEgressRules(HERMES_ENDPOINT_SET, NOW);
    const result = verifyProvisionedEgressStatically(rules, HERMES_ENDPOINT_SET, RESOLVERS, NOW);
    expect(result.ok).toBe(true);
    expect(result.dnsRulePresent).toBe(true);
    expect(result.checks.every((c) => c.allowed)).toBe(true);
    expect(result.checks).toHaveLength(HERMES_ENDPOINT_SET.endpoints.length);
  });

  it("fails closed when one endpoint has no allow match (and names it in the checks table)", () => {
    const rules = buildProvisionedEgressRules(HERMES_ENDPOINT_SET, NOW).filter(
      (rule) => !(rule.match.host as string[]).includes("api.venice.ai"),
    );
    const result = verifyProvisionedEgressStatically(rules, HERMES_ENDPOINT_SET, RESOLVERS, NOW);
    expect(result.ok).toBe(false);
    const venice = result.checks.find((c) => c.host === "api.venice.ai")!;
    expect(venice.allowed).toBe(false);
  });

  it("fails closed when the resolver set is empty (no derived DNS rule = the agent could never resolve the names)", () => {
    const rules = buildProvisionedEgressRules(HERMES_ENDPOINT_SET, NOW);
    const result = verifyProvisionedEgressStatically(rules, HERMES_ENDPOINT_SET, [], NOW);
    expect(result.ok).toBe(false);
    expect(result.dnsRulePresent).toBe(false);
  });

  it("F1 parity: an EMPTY endpoint set fails closed with a synthetic row (nothing verified is never a pass)", () => {
    const result = verifyProvisionedEgressStatically(
      [],
      { harnessId: "hermes", endpoints: [] },
      RESOLVERS,
      NOW,
    );
    expect(result.ok).toBe(false);
    expect(result.checks[0]!.name).toContain("no endpoints declared");
  });

  it("a DENY rule for an endpoint does not satisfy the check (allow-disposition matches only)", () => {
    const rules = buildProvisionedEgressRules(HERMES_ENDPOINT_SET, NOW).map((rule) =>
      (rule.match.host as string[]).includes("api.venice.ai")
        ? { ...rule, disposition: "deny" as const }
        : rule,
    );
    const result = verifyProvisionedEgressStatically(rules, HERMES_ENDPOINT_SET, RESOLVERS, NOW);
    expect(result.ok).toBe(false);
    expect(result.checks.find((c) => c.host === "api.venice.ai")!.allowed).toBe(false);
  });
});

describe("castle-wall/provision/egress: publish + scrub (hermetic tmp fortress)", () => {
  it("publish writes one canonical rule file per endpoint, triggers the reload, and the files read back valid", async () => {
    const fortress = await makeFortress();
    let reloads = 0;
    const result = await publishProvisionedEgressRules({
      fortressPath: fortress,
      endpointSet: HERMES_ENDPOINT_SET,
      reloadPolicy: async () => {
        reloads += 1;
        return { ok: true };
      },
    });
    expect(result.ok).toBe(true);
    expect(reloads).toBe(1);
    if (!result.ok) throw new Error("unreachable");
    expect(result.ruleIds).toHaveLength(HERMES_ENDPOINT_SET.endpoints.length);

    const persisted = await readEgressRulesFromDisk(fortress);
    expect(persisted).toHaveLength(HERMES_ENDPOINT_SET.endpoints.length);
    const staticVerify = verifyProvisionedEgressStatically(persisted, HERMES_ENDPOINT_SET, RESOLVERS, NOW);
    expect(staticVerify.ok).toBe(true);
  });

  it("publish is idempotent AND scrubs a STALE provisioned rule the adapter no longer declares (currency diff: removals revoke)", async () => {
    const fortress = await makeFortress();
    const reload = async () => ({ ok: true });
    // Seed a stale provisioned rule for a host the set does not declare.
    const dir = egressRulesDir(fortress);
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, "provisioned-hermes-000000000000.json"),
      JSON.stringify({
        id: "provisioned-hermes-000000000000",
        schema_version: 1,
        created_at: NOW,
        match: { host: ["removed.example.com"], port: [443], protocol: "tcp" },
        scope: {},
        disposition: "allow",
        derived: true,
      }),
    );
    const result = await publishProvisionedEgressRules({
      fortressPath: fortress,
      endpointSet: HERMES_ENDPOINT_SET,
      reloadPolicy: reload,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.staleRuleIdsRemoved).toEqual(["provisioned-hermes-000000000000"]);
    const filenames = await readdir(dir);
    expect(filenames).not.toContain("provisioned-hermes-000000000000.json");

    // Idempotent second publish: same rule ids, nothing stale.
    const second = await publishProvisionedEgressRules({
      fortressPath: fortress,
      endpointSet: HERMES_ENDPOINT_SET,
      reloadPolicy: reload,
    });
    expect(second.ok).toBe(true);
    if (!second.ok) throw new Error("unreachable");
    expect(second.staleRuleIdsRemoved).toEqual([]);
    expect(second.ruleIds.sort()).toEqual(result.ruleIds.sort());
  });

  it("publish does NOT touch operator-authored or other-harness rules when scrubbing stale entries", async () => {
    const fortress = await makeFortress();
    const dir = egressRulesDir(fortress);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "operator-custom.json"), JSON.stringify({ any: "thing" }));
    await writeFile(join(dir, "provisioned-otherharness-111111111111.json"), "{}");
    const result = await publishProvisionedEgressRules({
      fortressPath: fortress,
      endpointSet: HERMES_ENDPOINT_SET,
      reloadPolicy: async () => ({ ok: true }),
    });
    expect(result.ok).toBe(true);
    const filenames = await readdir(dir);
    expect(filenames).toContain("operator-custom.json");
    expect(filenames).toContain("provisioned-otherharness-111111111111.json");
  });

  it("publish FAILS CLOSED when the reload cannot be confirmed (an unreachable daemon is never a silent pass)", async () => {
    const fortress = await makeFortress();
    const result = await publishProvisionedEgressRules({
      fortressPath: fortress,
      endpointSet: HERMES_ENDPOINT_SET,
      reloadPolicy: async () => ({ ok: false, error: "no Castle Wall daemon reachable" }),
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.error).toMatch(/no Castle Wall daemon reachable/);
  });

  it("scrub removes every provisioned-<harness>-* rule, VERIFIES none survive, and is idempotent", async () => {
    const fortress = await makeFortress();
    await publishProvisionedEgressRules({
      fortressPath: fortress,
      endpointSet: HERMES_ENDPOINT_SET,
      reloadPolicy: async () => ({ ok: true }),
    });
    const first = await scrubProvisionedEgressRules({ fortressPath: fortress, harnessId: "hermes" });
    expect(first.removedRuleIds).toHaveLength(HERMES_ENDPOINT_SET.endpoints.length);
    const filenames = await readdir(egressRulesDir(fortress));
    expect(filenames.filter((f) => f.startsWith("provisioned-hermes-"))).toEqual([]);
    // Idempotent second scrub.
    const second = await scrubProvisionedEgressRules({ fortressPath: fortress, harnessId: "hermes" });
    expect(second.removedRuleIds).toEqual([]);
    // A never-provisioned fortress (no rules dir at all) scrubs cleanly too.
    const fresh = await makeFortress();
    const none = await scrubProvisionedEgressRules({ fortressPath: fresh, harnessId: "hermes" });
    expect(none.removedRuleIds).toEqual([]);
  });

  it("scrub reports a FAILED reload without throwing (the rules are already gone from the signing source)", async () => {
    const fortress = await makeFortress();
    await publishProvisionedEgressRules({
      fortressPath: fortress,
      endpointSet: HERMES_ENDPOINT_SET,
      reloadPolicy: async () => ({ ok: true }),
    });
    const result = await scrubProvisionedEgressRules({
      fortressPath: fortress,
      harnessId: "hermes",
      reloadPolicy: async () => ({ ok: false, error: "daemon gone" }),
    });
    expect(result.removedRuleIds.length).toBeGreaterThan(0);
    expect(result.reloadOk).toBe(false);
  });

  it("readEgressRulesFromDisk throws on an INVALID rule file (fail-closed: verification against a ruleset the daemon would refuse is meaningless)", async () => {
    const fortress = await makeFortress();
    const dir = egressRulesDir(fortress);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "bad.json"), JSON.stringify({ id: "bad", disposition: "allow" }));
    await expect(readEgressRulesFromDisk(fortress)).rejects.toThrow(/invalid/);
  });
});

describe("castle-wall/provision/egress: as-uid probe helpers", () => {
  it("probe specs cover every declared endpoint (expected reachable) PLUS the negative control (expected blocked)", () => {
    const specs = buildAgentEgressProbeSpecs(HERMES_ENDPOINT_SET);
    expect(specs).toHaveLength(HERMES_ENDPOINT_SET.endpoints.length + 1);
    const control = specs[specs.length - 1]!;
    expect(control.host).toBe(AGENT_EGRESS_NEGATIVE_CONTROL_HOST);
    expect(control.expected).toBe("blocked");
    for (const spec of specs.slice(0, -1)) {
      expect(spec.expected).toBe("reachable");
    }
  });

  it("throws when the negative-control host collides with a declared endpoint (the control would be meaningless)", () => {
    const colliding: HarnessEndpointSet = {
      harnessId: "x",
      endpoints: [
        {
          name: "collide",
          host: AGENT_EGRESS_NEGATIVE_CONTROL_HOST,
          port: 443,
          protocol: "tcp",
          riskClass: "standard",
        },
      ],
    };
    expect(() => buildAgentEgressProbeSpecs(colliding)).toThrow(/collides/);
  });

  it("the report passes ONLY when every endpoint is reachable AND the control is blocked", () => {
    const specs = buildAgentEgressProbeSpecs(HERMES_ENDPOINT_SET);
    const allGood = specs.map((s) => s.expected === "reachable");
    expect(buildAgentEgressReport(specs, allGood).ok).toBe(true);

    // One endpoint blocked -> fail (the agent would be confined into silence).
    const oneBlocked = [...allGood];
    oneBlocked[0] = false;
    const blockedReport = buildAgentEgressReport(specs, oneBlocked);
    expect(blockedReport.ok).toBe(false);
    expect(blockedReport.rows[0]!.pass).toBe(false);

    // Negative control REACHABLE -> fail (the wall is not confining the agent).
    const controlOpen = [...allGood];
    controlOpen[controlOpen.length - 1] = true;
    const openReport = buildAgentEgressReport(specs, controlOpen);
    expect(openReport.ok).toBe(false);
    expect(openReport.rows[openReport.rows.length - 1]!.pass).toBe(false);
  });

  it("F1 parity: an empty spec list fails closed", () => {
    const report = buildAgentEgressReport([], []);
    expect(report.ok).toBe(false);
  });

  it("asUidTlsProbeArgv builds a non-interactive sudo -u '#<uid>' curl probe; only exit 0 reads as reachable", () => {
    const { file, args } = asUidTlsProbeArgv(503, "api.venice.ai", 443);
    expect(file).toBe("/usr/bin/sudo");
    expect(args).toContain("-n");
    expect(args).toContain("#503");
    expect(args[args.length - 1]).toBe("https://api.venice.ai:443/");
    expect(args).not.toContain("--fail");
    expect(asUidProbeReachableDecision(0)).toBe(true);
    expect(asUidProbeReachableDecision(7)).toBe(false);
    expect(asUidProbeReachableDecision(28)).toBe(false);
    expect(asUidProbeReachableDecision(null)).toBe(false);
    expect(() => asUidTlsProbeArgv(0, "h", 443)).toThrow(/positive integer uid/);
    expect(() => asUidTlsProbeArgv(-1, "h", 443)).toThrow(/positive integer uid/);
  });
});

describe("castle-wall/provision/egress: derived-DNS interaction", () => {
  it("an operator-authored rule claiming the reserved derived id counts as DNS presence (operator override wins)", () => {
    const rules = [
      ...buildProvisionedEgressRules(HERMES_ENDPOINT_SET, NOW),
      {
        id: DERIVED_DNS_RULE_ID,
        schema_version: 1 as const,
        created_at: NOW,
        match: { ip: ["9.9.9.9"], port: [53], protocol: "tcp+udp" as const },
        scope: {},
        disposition: "allow" as const,
      },
    ];
    // Resolver set empty, but the operator's own DNS rule is present.
    const result = verifyProvisionedEgressStatically(rules, HERMES_ENDPOINT_SET, [], NOW);
    expect(result.dnsRulePresent).toBe(true);
  });
});
