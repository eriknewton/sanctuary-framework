/**
 * Sanctuary v1.1 Dashboard — Template Registry tests.
 *
 * Covers:
 *  - Required test 5: unknown template id renders safe diagnostic fallback,
 *    does NOT throw.
 *  - Coverage assertion: every Tier 1 operation_category, every privacy
 *    event kind, every blocked_egress reason class has a registered entry.
 */

import { describe, expect, it } from "vitest";
import {
  renderTemplate,
  listRegisteredTemplateIds,
} from "../../../src/dashboard/v1_1/templates.js";

describe("v1.1 dashboard template registry", () => {
  it("renders a known template with typed args", () => {
    const out = renderTemplate(
      "approval_pending.tier1.lockdown",
      [{ kind: "agent_id", value: "agent-alpha" }],
    );
    expect(out).toContain("agent-alpha");
    expect(out.toLowerCase()).toContain("lock down");
  });

  it("returns a diagnostic fallback for an unknown template id (no throw)", () => {
    expect(() => {
      const out = renderTemplate("approval_pending.tier1.fictional", []);
      expect(out).toBe("[unrecognized template: approval_pending.tier1.fictional]");
    }).not.toThrow();
  });

  it("registers entries for every Tier 1 operation_category", () => {
    const required = [
      "state_export",
      "state_import",
      "state_delete",
      "identity_rotate",
      "reputation_export",
      "reputation_import",
      "sanctuary_export_identity_bundle",
      "exit_bundle_export",
      "exit_bundle_import",
      "exit_bundle_rekey",
      "policy_change",
      "lockdown",
      "fortress_lockdown",
      "unwrap",
      "other",
    ];
    const ids = listRegisteredTemplateIds();
    for (const op of required) {
      expect(ids).toContain(`approval_pending.tier1.${op}`);
    }
  });

  it("registers entries for every privacy event kind", () => {
    const kinds = ["filtered", "allowed", "denied", "error", "rehydrated"];
    const ids = listRegisteredTemplateIds();
    for (const k of kinds) expect(ids).toContain(`privacy_event.${k}`);
  });

  it("registers entries for every blocked_egress reason class", () => {
    const reasons = [
      "egress_policy_deny",
      "budget_exceeded",
      "privacy_fail_closed",
      "privacy_deny_rule",
      "lockdown_active",
      "other",
    ];
    const ids = listRegisteredTemplateIds();
    for (const r of reasons) expect(ids).toContain(`blocked_egress.${r}`);
  });

  it("registers entries for every recovery_class", () => {
    const classes = [
      "passphrase_reset",
      "keychain_rebind",
      "config_backup_restore",
      "exit_drill",
      "other",
    ];
    const ids = listRegisteredTemplateIds();
    for (const c of classes) expect(ids).toContain(`recovery_prompt.${c}`);
  });

  it("registers entries for every activity feed category", () => {
    const cats = [
      "policy_decision",
      "approval",
      "denial",
      "egress",
      "privacy",
      "handoff",
      "lifecycle",
      "config",
      "other",
    ];
    const ids = listRegisteredTemplateIds();
    for (const c of cats) expect(ids).toContain(`activity.${c}`);
  });

  it("does not interpolate unknown args into the fallback string", () => {
    // Args are NOT echoed into the fallback (defense-in-depth for any arg
    // shape that might carry sensitive content via a future broken
    // backend).
    const out = renderTemplate("totally.fake.id", [
      { kind: "agent_id", value: "secret-agent-xyz" },
    ]);
    expect(out).not.toContain("secret-agent-xyz");
  });

  it("renders the fortress lockdown approval template with consequences", () => {
    const out = renderTemplate("approval_pending.tier1.fortress_lockdown", []);
    expect(out).toContain("Lockdown approval pending");
    expect(out).toContain("records fortress lockdown status");
    expect(out).toContain("does not by itself block writes");
    expect(out).not.toContain("[unrecognized template");
  });
});
