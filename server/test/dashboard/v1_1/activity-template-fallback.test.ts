/**
 * Hub activity entries resolve through the dashboard category sentences.
 * Exercises the real audit feed projection and the embedded client renderer.
 */
import { runInNewContext } from "node:vm";
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import {
  ACTIVITY_FALLBACK_TEMPLATE_BY_NAMESPACE,
  listRegisteredTemplateIds,
  renderTemplate,
} from "../../../src/dashboard/v1_1/templates.js";
import { aggregateActivity } from "../../../src/hub/activity-feed.js";
import { HUB_ACTIVITY_TEMPLATE_NAMESPACES } from "../../../src/hub/constants.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import type { HubDisplayTemplateArg } from "../../../src/contracts/v1.1/hub-events.js";

const IDENTITY_ID = "activity-template-fixture";
const AUDIT_KEY_BYTES = 32; // AuditLog uses a 256-bit master key: 256 / 8 bytes.
const OPERATIONS = {
  policy_decision: "policy_decision",
  approval: "tier1_approval_granted",
  denial: "egress_policy_deny",
  egress: "egress_allowed",
  privacy: "privacy_event",
  handoff: "handoff_created",
  lifecycle: "pause",
  config: "config_change",
  other: "unclassified_fixture_event",
} satisfies Record<keyof typeof HUB_ACTIVITY_TEMPLATE_NAMESPACES, string>;

const categories = Object.keys(HUB_ACTIVITY_TEMPLATE_NAMESPACES) as Array<keyof typeof OPERATIONS>;

// Fixture feed entries carry no agent_id argument, so each sentence shows its renderer's missing-argument text.
const GENERAL_SENTENCE = "Audit event recorded for agent (fortress).";
// A category keeps its own sentence on the fallback only where that sentence holds for every operation filed there.
const EXPECTED_SENTENCES = {
  policy_decision: GENERAL_SENTENCE,
  approval: GENERAL_SENTENCE,
  denial: GENERAL_SENTENCE,
  egress: GENERAL_SENTENCE,
  privacy: "Privacy event recorded for agent (unknown).",
  handoff: "Internal handoff event involving agent (unknown).",
  lifecycle: GENERAL_SENTENCE,
  config: GENERAL_SENTENCE,
  other: GENERAL_SENTENCE,
} satisfies Record<keyof typeof HUB_ACTIVITY_TEMPLATE_NAMESPACES, string>;

// Operations the hub files under a category whose own sentence they would contradict: aggregator views and
// duplicates under approval, an automated denial, a blocked connection, a policy view on the l2 catch-all, a panel
// view on the agent_ catch-all, and a failed configuration read.
const CONTRADICTING_OPERATIONS = [
  ["cross_harness_approval_audit_trail_viewed", "l2", "approval"],
  ["cross_harness_approval_deduped", "l2", "approval"],
  ["tool_auto_deny", "l1", "denial"],
  ["egress_blocked", "l1", "egress"],
  ["principal_policy_view", "l2", "policy_decision"],
  ["agent_inspect_panel_opened", "l1", "lifecycle"],
  ["config_read_failed", "l1", "config"],
] as const;

async function feedEntry(operation: string, layer: "l1" | "l2" = "l1") {
  const auditLog = new AuditLog(new MemoryStorage(), randomBytes(AUDIT_KEY_BYTES));
  // The unclassified operation needs l1 because l2 defaults to policy_decision.
  await auditLog.append(layer, operation, IDENTITY_ID, {});
  await auditLog.flush();
  const entries = await aggregateActivity({ auditLog, identityId: IDENTITY_ID });
  expect(entries).toHaveLength(1);
  return entries[0]!;
}

function clientRenderer() {
  const script = getClientScript();
  const start = script.indexOf("function arg(args, kind, fallback) {");
  const end = script.indexOf("const STATUS_MAP = {", start);
  if (start < 0 || end < start) throw new Error("client template block not found");
  // Evaluate the shipped helper, registry and lookup together, including the injected list.
  return runInNewContext(`${script.slice(start, end)}\nrenderTemplate;`) as (
    id: string, args: HubDisplayTemplateArg[],
  ) => string;
}

describe("activity template namespace fallback", () => {
  for (const category of categories) {
    const namespace = HUB_ACTIVITY_TEMPLATE_NAMESPACES[category];

    it(`renders real ${category} feed entries through the server category sentence`, async () => {
      const entry = await feedEntry(OPERATIONS[category]);
      expect(entry.category).toBe(category);
      expect(entry.display_template_id).toBe(`${namespace}.${OPERATIONS[category]}`);
      // Operation coverage comes from fallback, without registering any new template ids.
      expect(listRegisteredTemplateIds()).not.toContain(entry.display_template_id);
      const actual = renderTemplate(entry.display_template_id, entry.display_template_args, { surface: "activity" });
      expect(actual).toBe(EXPECTED_SENTENCES[category]);
    });

    it(`renders real ${category} feed entries through the client category sentence`, async () => {
      const entry = await feedEntry(OPERATIONS[category]);
      const renderClient = clientRenderer();
      const actual = renderClient(entry.display_template_id, entry.display_template_args);
      expect(actual).toBe(EXPECTED_SENTENCES[category]);
    });
  }

  for (const [operation, layer, category] of CONTRADICTING_OPERATIONS) {
    it(`renders ${operation} through the general sentence, not the ${category} sentence`, async () => {
      const entry = await feedEntry(operation, layer);
      expect(entry.category).toBe(category);
      const namespace = HUB_ACTIVITY_TEMPLATE_NAMESPACES[category];
      expect(renderTemplate(entry.display_template_id, entry.display_template_args, { surface: "activity" })).toBe(
        GENERAL_SENTENCE,
      );
      expect(clientRenderer()(entry.display_template_id, entry.display_template_args)).toBe(GENERAL_SENTENCE);
      // The bare category id keeps its registered sentence; only the operation fallback is narrowed.
      expect(renderTemplate(namespace, entry.display_template_args, { surface: "activity" })).not.toBe(GENERAL_SENTENCE);
    });
  }

  it("injects the complete hub namespace set into the client", () => {
    const script = getClientScript();
    const marker = "const ACTIVITY_TEMPLATE_NAMESPACES = ";
    const start = script.indexOf(marker);
    expect(start).toBeGreaterThanOrEqual(0);
    const end = script.indexOf(";", start);
    const namespaces = JSON.parse(script.slice(start + marker.length, end)) as string[];
    expect(namespaces.sort()).toEqual(Object.values(HUB_ACTIVITY_TEMPLATE_NAMESPACES).sort());
  });

  it("injects the server fallback map into the client unchanged", () => {
    const script = getClientScript();
    const marker = "const ACTIVITY_FALLBACK_TEMPLATES = ";
    const start = script.indexOf(marker);
    expect(start).toBeGreaterThanOrEqual(0);
    const end = script.indexOf(";", start);
    expect(JSON.parse(script.slice(start + marker.length, end))).toEqual({ ...ACTIVITY_FALLBACK_TEMPLATE_BY_NAMESPACE });
    expect(Object.keys(ACTIVITY_FALLBACK_TEMPLATE_BY_NAMESPACE).sort()).toEqual(
      Object.values(HUB_ACTIVITY_TEMPLATE_NAMESPACES).sort(),
    );
  });

  // Exact-id precedence and the unknown-id boundary already hold on main; these cases pin them under the fallback.
  it("keeps an exact operation sentence ahead of its category sentence", async () => {
    const entry = await feedEntry("agent_lockdown_engaged");
    const expected = "Network access revoked for agent (unknown).";
    const renderClient = clientRenderer();
    expect(renderTemplate(entry.display_template_id, entry.display_template_args)).toBe(expected);
    expect(renderClient(entry.display_template_id, entry.display_template_args)).toBe(expected);
    expect(renderClient("activity.lifecycle", entry.display_template_args)).not.toBe(expected);
  });

  for (const id of [
    "approval_pending.tier1.fictional",
    "totally.fake.id",
    "activity.denialish.operation",
    "xactivity.denial.operation",
  ]) {
    it(`keeps ${id} outside the activity namespace fallback`, () => {
      const expected = `[unrecognized template: ${id}]`;
      const args: HubDisplayTemplateArg[] = [{ kind: "agent_id", value: "fixture-agent" }];
      expect(renderTemplate(id, args)).toBe(expected);
      expect(clientRenderer()(id, args)).toBe(expected);
    });
  }
});
