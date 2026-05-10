/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-2
 *
 * Loader / parser regression tests for the new `approval_redirect` block
 * in principal-policy.yaml.
 */

import { describe, it, expect } from "vitest";

import {
  DEFAULT_POLICY,
  parsePolicy,
} from "../../src/principal-policy/loader.js";

describe("loader.parsePolicy — approval_redirect (Upsilon-2)", () => {
  it("DEFAULT_POLICY ships with approval_redirect off in replace mode", () => {
    expect(DEFAULT_POLICY.approval_redirect).toEqual({
      enabled: false,
      mode: "replace",
    });
  });

  it("policy without approval_redirect parses to the safe default", () => {
    const yaml = [
      "version: 1",
      "tier1_always_approve:",
      "  - state_export",
      "approval_channel:",
      "  type: stderr",
      "  timeout_seconds: 300",
    ].join("\n");
    const parsed = parsePolicy(yaml);
    expect(parsed.approval_redirect).toEqual({ enabled: false, mode: "replace" });
  });

  it("policy with approval_redirect enabled + notify mode parses correctly", () => {
    const yaml = [
      "version: 1",
      "tier1_always_approve:",
      "  - state_export",
      "approval_channel:",
      "  type: stderr",
      "  timeout_seconds: 300",
      "approval_redirect:",
      "  enabled: true",
      "  mode: notify",
    ].join("\n");
    const parsed = parsePolicy(yaml);
    expect(parsed.approval_redirect).toEqual({ enabled: true, mode: "notify" });
  });

  it("policy with approval_redirect enabled defaults mode to replace", () => {
    const yaml = [
      "version: 1",
      "tier1_always_approve:",
      "  - state_export",
      "approval_channel:",
      "  type: stderr",
      "  timeout_seconds: 300",
      "approval_redirect:",
      "  enabled: true",
    ].join("\n");
    const parsed = parsePolicy(yaml);
    expect(parsed.approval_redirect).toEqual({ enabled: true, mode: "replace" });
  });

  it("policy with malformed approval_redirect.mode hard-rejects", () => {
    const yaml = [
      "version: 1",
      "tier1_always_approve:",
      "  - state_export",
      "approval_channel:",
      "  type: stderr",
      "  timeout_seconds: 300",
      "approval_redirect:",
      "  enabled: true",
      "  mode: bogus",
    ].join("\n");
    expect(() => parsePolicy(yaml)).toThrow(/approval_redirect\.mode/);
  });

  it("JSON policy with approval_redirect block parses correctly", () => {
    const json = JSON.stringify({
      version: 1,
      tier1_always_approve: ["state_export"],
      approval_channel: { type: "stderr", timeout_seconds: 300 },
      approval_redirect: {
        enabled: true,
        mode: "replace",
        per_agent: { "agent-foo": { enabled: true, mode: "notify" } },
      },
    });
    const parsed = parsePolicy(json);
    expect(parsed.approval_redirect?.enabled).toBe(true);
    expect(parsed.approval_redirect?.mode).toBe("replace");
    // per_agent is reserved for v1.4; persisted but not validated.
    expect(parsed.approval_redirect?.per_agent).toBeDefined();
  });
});
