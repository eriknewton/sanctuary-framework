/**
 * Sanctuary v1.1 Dashboard — Template Registry tests.
 *
 * Covers:
 *  - Required test 5: unknown template id renders safe diagnostic fallback,
 *    does NOT throw.
 *  - Coverage assertion: every Tier 1 operation_category, every privacy
 *    event kind, every blocked_egress reason class has a registered entry.
 */
// fail-before-exempt: slice 6a anchors the approved pending-removal sentence exactly; this inherited sentence already passes on the base, as does mirror parity.

import { describe, expect, it } from "vitest";
import {
  renderTemplate,
  listRegisteredTemplateIds,
} from "../../../src/dashboard/v1_1/templates.js";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import { STATUS_MAPPING } from "../../../src/dashboard/v1_1/status-mapping.js";
import type { HubDisplayTemplateArg } from "../../../src/contracts/v1.1/hub-events.js";
import {
  OPERATION_NAME_CATEGORIES,
  projectCharterApproval,
} from "../../../src/hub/charter-approval-bridge.js";

/**
 * Extracts the key set of the client's `TEMPLATES` mirror map by
 * EVALUATING the map literal from the embedded client script (the client
 * is plain TS-as-string; there is no importable client TEMPLATES export).
 * Evaluating the real object literal, rather than regex-matching entry
 * spellings, means any entry syntax that parses contributes its key, so a
 * differently-written entry cannot evade the parity check. Rendering tests
 * invoke those arrow functions through the client's own `arg` helper, sliced
 * from the same embedded script; slicing failures throw rather than returning
 * an empty set (fail-loud, never a vacuous pass).
 */
function extractClientTemplateIds(): string[] {
  return Object.keys(extractClientTemplates()).sort();
}

function extractClientArg(): (args: Array<{ kind: string; value: unknown }>, kind: string, fallback?: string) => string {
  const script = getClientScript();
  const marker = "function arg(args, kind, fallback) {";
  const start = script.indexOf(marker);
  if (start === -1) {
    throw new Error("client arg helper not found in embedded script");
  }
  const endMarker = "\n}\n\n// Cross-file contract:";
  const end = script.indexOf(endMarker, start);
  if (end === -1) {
    throw new Error("client arg helper close brace not found");
  }
  const fnText = script.slice(start, end + 2);
  return new Function(`"use strict"; ${fnText}; return arg;`)() as (
    args: Array<{ kind: string; value: unknown }>,
    kind: string,
    fallback?: string,
  ) => string;
}

function extractClientTemplates(): Record<string, (args: unknown[]) => string> {
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
  const evaluated = new Function(
    "arg",
    `"use strict"; return (${objectLiteral});`,
  )(extractClientArg()) as Record<string, (args: unknown[]) => string>;
  if (Object.keys(evaluated).length === 0) {
    throw new Error("client TEMPLATES map evaluated to an empty object");
  }
  return evaluated;
}

function extractClientStatusMap(): Record<string, { label: string; glyph: string }> {
  const script = getClientScript();
  const marker = "const STATUS_MAP = {";
  const start = script.indexOf(marker);
  if (start === -1) {
    throw new Error("client STATUS_MAP not found in embedded script");
  }
  const end = script.indexOf("\n};", start);
  if (end === -1) {
    throw new Error("client STATUS_MAP close brace not found");
  }
  const objectLiteral =
    "{" + script.slice(start + marker.length, end) + "\n}";
  const evaluated = new Function(`"use strict"; return (${objectLiteral});`)() as
    Record<string, { label: string; glyph: string }>;
  if (Object.keys(evaluated).length === 0) {
    throw new Error("client STATUS_MAP evaluated to an empty object");
  }
  return evaluated;
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

  it("keeps every mirrored client template and status label in parity with the server tables", () => {
    // Full-set equality (AGENTS.md rule 5): a parity check over one entry cannot
    // see a drifted sibling. Every template id both registries carry renders the
    // same text from the same args, and every status key carries the same label
    // and glyph on both sides.
    const args: HubDisplayTemplateArg[] = [
      { kind: "agent_id", value: "agent-alpha" },
      { kind: "channel_template_id", value: "channel-beta" },
      { kind: "destination_category", value: "tool-api" },
      { kind: "policy_id", value: "policy-delta" },
    ];
    const clientTemplates = extractClientTemplates();
    const shared = listRegisteredTemplateIds().filter((id) => id in clientTemplates);
    expect(shared.length).toBeGreaterThan(0);
    // The client mirror has no render context and always writes the past-tense
    // activity wording, so it is compared with the server's activity surface.
    // Known drift, recorded rather than hidden: these client mirrors omit the
    // agent or time suffix the server appends. Aligning them is a separate
    // change; this list must shrink to empty, and a new id here fails the test.
    const KNOWN_CLIENT_TEMPLATE_DRIFT = [
      "activity.config",
      "activity.lifecycle",
      "approval_pending.tier1.exit_bundle_import",
      "approval_pending.tier1.exit_bundle_rekey",
      "approval_pending.tier1.sanctuary_export_identity_bundle",
    ];
    const driftedWithArgs = shared
      .filter((id) => clientTemplates[id](args) !== renderTemplate(id, args, { surface: "activity" }))
      .sort();
    expect(driftedWithArgs).toEqual([...KNOWN_CLIENT_TEMPLATE_DRIFT].sort());

    // Missing-argument parity has its own drift list because fallback wording
    // is a separate contract from populated slot rendering.
    const KNOWN_CLIENT_TEMPLATE_DRIFT_WITH_MISSING_ARGS = [
      "activity.config",
      "activity.lifecycle",
      "approval_pending.tier1.exit_bundle_import",
      "approval_pending.tier1.exit_bundle_rekey",
      "approval_pending.tier1.sanctuary_export_identity_bundle",
    ];
    const driftedWithMissingArgs = shared
      .filter((id) => clientTemplates[id]([]) !== renderTemplate(id, [], { surface: "activity" }))
      .sort();
    expect(driftedWithMissingArgs).toEqual([...KNOWN_CLIENT_TEMPLATE_DRIFT_WITH_MISSING_ARGS].sort());

    const clientStatus = extractClientStatusMap();
    const serverStatusKeys = Object.keys(STATUS_MAPPING).sort();
    const clientStatusKeys = Object.keys(clientStatus).sort();
    const missingFromClientStatus = serverStatusKeys.filter((key) => !clientStatusKeys.includes(key));
    const clientOnlyStatusKeys = clientStatusKeys.filter((key) => !serverStatusKeys.includes(key));
    const KNOWN_CLIENT_ONLY_STATUS_KEYS: string[] = [];
    expect(
      missingFromClientStatus,
      `status keys registered on the server but missing from the client mirror: ${missingFromClientStatus.join(", ")}`,
    ).toEqual([]);
    expect(
      clientOnlyStatusKeys,
      `status keys in the client mirror with no server status table entry: ${clientOnlyStatusKeys.join(", ")}`,
    ).toEqual(KNOWN_CLIENT_ONLY_STATUS_KEYS);
    const statusDrift = (Object.keys(STATUS_MAPPING) as Array<keyof typeof STATUS_MAPPING>)
      .filter((key) => clientStatus[key]?.label !== STATUS_MAPPING[key].label || clientStatus[key]?.glyph !== STATUS_MAPPING[key].glyph)
      .map((key) => ({ key, client: clientStatus[key], server: STATUS_MAPPING[key] }));
    // Known drift: the client labels an active agent "Protected" where the
    // server table says "Running". Resolving which word the evidence supports
    // is a separate change; a new drifted key fails this test.
    expect(statusDrift.map((row) => row.key)).toEqual(["active"]);
  });

  it("renders the fortress lockdown approval template with consequences", () => {
    const out = renderTemplate("approval_pending.tier1.fortress_lockdown", []);
    expect(out).toContain("Lockdown approval pending");
    expect(out).toContain("revokes network access");
    expect(out).not.toContain("writes are blocked");
    expect(out).not.toContain("[unrecognized template");
  });
});

it("anchors the approved pending-removal sentence", () => {
  expect(renderTemplate("approval_pending.tier1.unwrap", [{ kind: "agent_id", value: "agent-alpha" }])).toBe("Request to remove protection from agent agent-alpha. This build refuses unsupported removals before approval is queued.");
});

// A configured requester with a distinctive id, so any sentence that names it is caught.
const CHARTER_REQUESTER = "agent:claude-code:fortress-requester-a";
// The catalog's neutral fallback for a missing target, shared by server and client arg().
const UNKNOWN_TARGET = "(unknown)";

it("renders every Charter card category without naming the requester or a defaulted target, on server and client", () => {
  // Full-set (AGENTS.md rule 5): every category the bridge can emit is projected
  // and rendered by both catalogs, so a category added later whose sentence
  // defaults its target cannot slip past TARGET_DEFAULTING_CATEGORIES.
  const clientTemplates = extractClientTemplates();
  for (const operation of OPERATION_NAME_CATEGORIES) {
    for (const tier of [1, 2] as const) {
      const card = projectCharterApproval(
        {
          id: "hold-1",
          operation,
          tier,
          created_at: "2026-10-21T00:00:00.000Z",
          requesting_agent_id: CHARTER_REQUESTER,
        },
        "operator-identity",
      );
      expect(card.agent_id, operation).toBe(CHARTER_REQUESTER);
      expect(card.display_template_args.some((a) => a.kind === "agent_id"), operation).toBe(false);
      const client = clientTemplates[card.display_template_id];
      expect(client, `${card.display_template_id} has a client mirror`).toBeDefined();
      for (const sentence of [
        renderTemplate(card.display_template_id, card.display_template_args),
        client!(card.display_template_args),
      ]) {
        expect(sentence, operation).not.toContain(CHARTER_REQUESTER);
        expect(sentence.startsWith("[unrecognized template"), operation).toBe(false);
        // Either the sentence leaves the target unknown, or the card uses the
        // tier's catch-all, whose sentence names no target.
        const neutral =
          sentence.includes(UNKNOWN_TARGET) || card.display_template_id.endsWith(".other");
        expect(neutral, `${operation} tier ${tier}: ${sentence}`).toBe(true);
      }
    }
  }
});
