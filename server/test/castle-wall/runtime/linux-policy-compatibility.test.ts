import { describe, expect, it, vi } from "vitest";

import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import { CURATED_ALLOWLIST } from "../../../src/castle-wall/runtime/curated-allowlist.js";
import {
  LINUX_IP_CIDR_POLICY_PROFILE,
  inspectLinuxPolicyCompatibility,
  publishLinuxCompatiblePolicy,
} from "../../../src/castle-wall/runtime/linux-policy-compatibility.js";
import type { ManifestStorage } from "../../../src/castle-wall/runtime/manifest-publisher.js";

function rule(overrides: Partial<AllowlistRule> = {}): AllowlistRule {
  return {
    id: "linux-explicit-ip",
    schema_version: 1,
    created_at: "2026-09-03T00:00:00Z",
    match: { ip: ["203.0.113.10"], port: [443], protocol: "tcp" },
    scope: { agent_ids: ["agent-a"] },
    disposition: "allow",
    ...overrides,
  };
}

describe("Linux IP/CIDR policy compatibility preflight", () => {
  it("publishes an explicit, usable IP/CIDR profile and accepts both destination forms", () => {
    expect(LINUX_IP_CIDR_POLICY_PROFILE.id).toBe("linux-ip-cidr-v1");
    expect(inspectLinuxPolicyCompatibility([rule()])).toEqual([]);
    expect(
      inspectLinuxPolicyCompatibility([
        rule({ id: "linux-explicit-cidr", match: { cidr: "2001:db8::/32" }, scope: {} }),
      ])
    ).toEqual([]);
  });

  it("refuses every shipped host-only curated rule instead of signing an inadmissible bundle", () => {
    for (const entry of CURATED_ALLOWLIST) {
      expect(inspectLinuxPolicyCompatibility([entry.rule])).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ ruleId: entry.rule_id, axis: "match.host" }),
          expect.objectContaining({ ruleId: entry.rule_id, axis: "match.destination" }),
        ])
      );
    }
  });

  it("reports every unsupported host, pattern, template, time, and missing-destination axis", () => {
    const issues = inspectLinuxPolicyCompatibility([
      rule({
        id: "all-unsupported",
        match: { host: ["api.example.com"], host_pattern: "*.example.com" },
        scope: { template_ids: ["coding-assistant"] },
        time_window: { start: "00:00", end: "23:59" },
      }),
    ]);
    expect(issues.map((issue) => issue.axis)).toEqual([
      "time_window",
      "match.host",
      "match.host_pattern",
      "scope.template_ids",
      "match.destination",
    ]);
  });

  it("fails before signing or storage mutation", async () => {
    const sign = vi.fn(() => new Uint8Array(64));
    const storage: ManifestStorage = {
      writeRule: vi.fn(async () => undefined),
      atomicRenameManifest: vi.fn(async () => undefined),
      listRules: vi.fn(async () => []),
      removeRule: vi.fn(async () => undefined),
    };

    await expect(
      publishLinuxCompatiblePolicy(
        {
          fortressId: "deadbeef",
          issuedAt: "2026-09-03T00:00:00Z",
          generation: 1,
          rules: [CURATED_ALLOWLIST[0]!.rule],
          signer: { signingKeyId: "sha256:" + "11".repeat(32), sign },
        },
        storage
      )
    ).rejects.toMatchObject({
      name: "RuntimeLinuxActivationError",
      reason: "policy_incompatible",
    });
    expect(sign).not.toHaveBeenCalled();
    expect(storage.writeRule).not.toHaveBeenCalled();
    expect(storage.atomicRenameManifest).not.toHaveBeenCalled();
  });
});
