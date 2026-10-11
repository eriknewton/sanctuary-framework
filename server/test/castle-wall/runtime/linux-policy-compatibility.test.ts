import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import { CURATED_ALLOWLIST } from "../../../src/castle-wall/runtime/curated-allowlist.js";
import {
  LINUX_IP_CIDR_POLICY_PROFILE,
  assertLinuxPolicyCompatibility,
  inspectLinuxPolicyCompatibility,
  publishLinuxCompatiblePolicy,
} from "../../../src/castle-wall/runtime/linux-policy-compatibility.js";
import type { ManifestStorage } from "../../../src/castle-wall/runtime/manifest-publisher.js";

const TEST_DIAGNOSTIC_TEXT_CAP = 8 * 8;
const TEST_MAX_LISTED_OFFENDERS = 8;
const TEST_LONG_TEXT_LENGTH = TEST_DIAGNOSTIC_TEXT_CAP * TEST_DIAGNOSTIC_TEXT_CAP;
const TEST_OFFENDER_COUNT = 10 ** 3;

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
  // LINUX-SCOPE-UIDS-TS-RUST-PARITY-01
  it("declares the Linux signable scope subset against the daemon modeled scope set", () => {
    const rustSource = readFileSync(resolve("..", "castle-wall-daemon/src/policy.rs"), "utf8");
    // Narrow parser for the Rust `pub struct RuleScope { ... }` declaration:
    // this test is a full-field parity tripwire, not a general Rust parser.
    const declaration = rustSource.match(
      /(?<attrs>(?:#\[[^\n]*\]\n)*)pub struct RuleScope \{(?<body>[\s\S]*?)\n\}/
    )?.groups;
    expect(declaration).toBeDefined();
    // Comment lines are dropped so prose inside the struct can never read as a field or an attribute.
    const block = declaration!.body.replace(/^\s*\/\/.*$/gm, "");
    // Any serde option that changes accepted wire names makes field identifiers stop matching the
    // JSON keys the daemon admits, so the tripwire refuses them rather than modelling each form.
    const wireNameOption = /#\s*\[\s*serde\s*\([^\]]*\b(?:rename|rename_all|alias|flatten)\b/;
    expect(declaration!.attrs).not.toMatch(wireNameOption);
    expect(block).not.toMatch(wireNameOption);
    // Every field counts, public or not: serde deserializes private fields too.
    const rustScopeFields = [
      ...block.matchAll(/^\s*(?:pub(?:\s*\([^)]*\))?\s+)?([a-z_][a-z0-9_]*)\s*:/gm),
    ]
      .map((match) => match[1])
      .sort();
    expect(rustScopeFields).toEqual(["agent_ids", "template_ids"]);

    const profile = LINUX_IP_CIDR_POLICY_PROFILE as typeof LINUX_IP_CIDR_POLICY_PROFILE & {
      daemon_modeled_scope_axes?: readonly string[];
      scope_axis_subset_reason?: string;
    };
    expect([...(profile.daemon_modeled_scope_axes ?? [])].sort()).toEqual(rustScopeFields);
    expect(profile.supported_scope_axes).toEqual(["agent_ids"]);
    expect(profile.scope_axis_subset_reason).toContain("template_ids");
    expect(profile.scope_axis_subset_reason).toContain("template attestation");
  });

  it("refuses empty scope.uids because the daemon refuses unknown scope fields", () => {
    expect(inspectLinuxPolicyCompatibility([rule({ scope: { uids: [] } })])).toEqual([
      expect.objectContaining({
        axis: "scope.uids",
        reason: expect.stringContaining("not modeled by the Linux daemon"),
      }),
    ]);
  });

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

  it("keeps Linux compatibility refusal diagnostics within the display budget", () => {
    const longRuleId = "rule-" + "r".repeat(TEST_LONG_TEXT_LENGTH);
    const longAxis = "axis-" + "a".repeat(TEST_LONG_TEXT_LENGTH);
    const issues = Array.from({ length: TEST_OFFENDER_COUNT }, (_, index) =>
      rule({
        id: index === 0 ? longRuleId : `extra-${index}`,
        scope:
          index === 0
            ? ({ [longAxis]: [] } as AllowlistRule["scope"])
            : ({ [`axis-${index}`]: [] } as AllowlistRule["scope"]),
      })
    );

    let message = "";
    try {
      assertLinuxPolicyCompatibility(issues);
    } catch (error) {
      message = String((error as Error).message);
    }

    expect(message).toContain(`original length ${longRuleId.length}`);
    expect(message).toContain(`original length ${`scope.${longAxis}`.length}`);
    expect(message).toContain(`and ${TEST_OFFENDER_COUNT - TEST_MAX_LISTED_OFFENDERS} more`);
    expect(message).not.toContain(longRuleId);
    expect(message).not.toContain(`scope.${longAxis}`);
    expect(message.length).toBeLessThan(TEST_DIAGNOSTIC_TEXT_CAP * TEST_DIAGNOSTIC_TEXT_CAP);
  });

  it("refuses macOS-only uid scopes before broker publication signing", async () => {
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
          rules: [rule({ scope: { uids: [60123] } })],
          signer: { signingKeyId: "sha256:" + "11".repeat(32), sign },
        },
        storage
      )
    ).rejects.toThrow(/scope\.uids.*macOS-only/);
    expect(sign).not.toHaveBeenCalled();
    expect(storage.writeRule).not.toHaveBeenCalled();
    expect(storage.atomicRenameManifest).not.toHaveBeenCalled();
  });

  it("refuses uid-mode broker publication scopes outside the confined id form before signing", async () => {
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
          rules: [rule({ scope: { agent_ids: ["deadbeef/uid-60123"] } })],
          agentOrigin: {
            mode: "uid",
            agent_uid: 60123,
            system_uid_allow_ceiling: 1000,
          },
          signer: { signingKeyId: "sha256:" + "11".repeat(32), sign },
        },
        storage
      )
    ).rejects.toThrow("expected uid-<decimal uid>; re-sign with the uid-<uid> form");
    expect(sign).not.toHaveBeenCalled();
    expect(storage.writeRule).not.toHaveBeenCalled();
    expect(storage.atomicRenameManifest).not.toHaveBeenCalled();
  });

  it("keeps confined-agent refusal diagnostics within the display budget", async () => {
    const longRuleId = "rule-" + "r".repeat(TEST_LONG_TEXT_LENGTH);
    const longAgentId = "agent-" + "a".repeat(TEST_LONG_TEXT_LENGTH);
    const sign = vi.fn(() => new Uint8Array(64));
    const storage: ManifestStorage = {
      writeRule: vi.fn(async () => undefined),
      atomicRenameManifest: vi.fn(async () => undefined),
      listRules: vi.fn(async () => []),
      removeRule: vi.fn(async () => undefined),
    };

    let message = "";
    try {
      await publishLinuxCompatiblePolicy(
        {
          fortressId: "deadbeef",
          issuedAt: "2026-09-03T00:00:00Z",
          generation: 1,
          rules: [rule({ id: longRuleId, scope: { agent_ids: [longAgentId] } })],
          agentOrigin: {
            mode: "uid",
            agent_uid: 60123,
            system_uid_allow_ceiling: 1000,
          },
          signer: { signingKeyId: "sha256:" + "11".repeat(32), sign },
        },
        storage
      );
    } catch (error) {
      message = String((error as Error).message);
    }

    expect(message).toContain(`original length ${longRuleId.length}`);
    expect(message).toContain(`original length ${JSON.stringify(longAgentId).length}`);
    expect(message).not.toContain(longRuleId);
    expect(message).not.toContain(longAgentId);
    expect(message.length).toBeLessThan(TEST_DIAGNOSTIC_TEXT_CAP * TEST_DIAGNOSTIC_TEXT_CAP);
    expect(sign).not.toHaveBeenCalled();
  });

  it("refuses a broker publication scope naming the gate uid before signing", async () => {
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
          rules: [rule({ scope: { agent_ids: ["uid-60124"] } })],
          agentOrigin: {
            mode: "uid",
            agent_uid: 60123,
            gate_uid: 60124,
            system_uid_allow_ceiling: 1000,
          },
          signer: { signingKeyId: "sha256:" + "11".repeat(32), sign },
        },
        storage
      )
    ).rejects.toThrow("expected admitted uid 60123");
    expect(sign).not.toHaveBeenCalled();
    expect(storage.writeRule).not.toHaveBeenCalled();
    expect(storage.atomicRenameManifest).not.toHaveBeenCalled();
  });
});
