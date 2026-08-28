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
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

/**
 * Extracts the key set of the client's `TEMPLATES` mirror map by
 * EVALUATING the map literal from the embedded client script (the client
 * is plain TS-as-string; there is no importable client TEMPLATES export).
 * Evaluating the real object literal, rather than regex-matching entry
 * spellings, means any entry syntax that parses contributes its key, so a
 * differently-written entry cannot evade the parity check. The entry
 * VALUES are arrow functions that are never invoked here, so no client
 * helper stubs are needed; slicing failures throw rather than returning
 * an empty set (fail-loud, never a vacuous pass).
 */
function extractClientTemplateIds(): string[] {
  const script = getClientScript();
  const marker = "const TEMPLATES = {";
  const start = script.indexOf(marker);
  if (start === -1) {
    throw new Error("client TEMPLATES map not found in embedded script");
  }
  const end = script.indexOf("\n};", start);
  if (end === -1) {
    throw new Error("client TEMPLATES map close brace not found");
  }
  // Reconstruct the full object literal and evaluate it. The block text
  // between the marker and the close brace is the literal's body.
  const objectLiteral =
    "{" + script.slice(start + marker.length, end) + "\n}";
  const evaluated = new Function(`"use strict"; return (${objectLiteral});`)() as
    Record<string, unknown>;
  const ids = Object.keys(evaluated);
  if (ids.length === 0) {
    throw new Error("client TEMPLATES map evaluated to an empty object");
  }
  return ids.sort();
}

describe("v1.1 dashboard template registry", () => {
  it("renders a known template with typed args", () => {
    const out = renderTemplate(
      "approval_pending.tier1.lockdown",
      [{ kind: "agent_id", value: "agent-alpha" }],
    );
    expect(out).toContain("agent-alpha");
    expect(out.toLowerCase()).toContain("network access");
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

  it("registers entries for every lockdown activity operation this build emits", () => {
    const ops = [
      "agent_lockdown_engaged",
      "agent_lockdown_partial",
      "agent_lockdown_refused",
      "fortress_lockdown_engaged",
      "fortress_lockdown_partial",
      "fortress_lockdown_failed",
      "fortress_lockdown_no_agents",
    ];
    for (const op of ops) {
      const templateId = `activity.lifecycle.${op}`;
      const out = renderTemplate(templateId, [
        { kind: "agent_id", value: "agent-alpha" },
        { kind: "iso8601", value: "2026-08-08T00:00:00.000Z" },
      ]);
      expect(out).not.toContain("[unrecognized template");
    }
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

  it("keeps the client TEMPLATES mirror (client.ts) in full-set parity with the server registry (IC-24)", () => {
    // Full-set equality in BOTH directions: a server template with no
    // client mirror falls through to "[unrecognized template: ...]" on a
    // live operator-facing approval or activity card (the IC-24 shape);
    // a client-only orphan is dead code masquerading as a live template.
    // A test that only samples a handful of ids (as the rest of this file
    // deliberately does, per rule 5 in AGENTS.md) cannot catch a single
    // missing entry in a 60-entry registry; only a full-set diff can.
    const serverIds = listRegisteredTemplateIds();
    const clientIds = extractClientTemplateIds();

    const missingFromClient = serverIds.filter((id) => !clientIds.includes(id));
    const orphanedInClient = clientIds.filter((id) => !serverIds.includes(id));

    expect(
      missingFromClient,
      `template ids registered on the server but missing from the client mirror: ${missingFromClient.join(", ")}`,
    ).toEqual([]);
    expect(
      orphanedInClient,
      `template ids in the client mirror with no server registry entry: ${orphanedInClient.join(", ")}`,
    ).toEqual([]);
  });

  it("renders the fortress lockdown approval template with consequences", () => {
    const out = renderTemplate("approval_pending.tier1.fortress_lockdown", []);
    expect(out).toContain("Lockdown approval pending");
    expect(out).toContain("revokes network access");
    expect(out).not.toContain("writes are blocked");
    expect(out).not.toContain("[unrecognized template");
  });
});
