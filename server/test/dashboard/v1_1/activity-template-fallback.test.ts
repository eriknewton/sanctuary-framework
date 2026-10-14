/**
 * Hub activity entries resolve through the dashboard category sentences.
 * Exercises the real audit feed projection and the embedded client renderer.
 */
import { runInNewContext } from "node:vm";
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import { listRegisteredTemplateIds, renderTemplate } from "../../../src/dashboard/v1_1/templates.js";
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

async function feedEntry(operation: string) {
  const auditLog = new AuditLog(new MemoryStorage(), randomBytes(AUDIT_KEY_BYTES));
  // The unclassified operation needs l1 because l2 defaults to policy_decision.
  await auditLog.append("l1", operation, IDENTITY_ID, {});
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
      const expected = renderTemplate(namespace, entry.display_template_args, { surface: "activity" });
      const actual = renderTemplate(entry.display_template_id, entry.display_template_args, { surface: "activity" });
      expect(actual).not.toContain("[unrecognized");
      expect(actual).toBe(expected);
    });

    it(`renders real ${category} feed entries through the client category sentence`, async () => {
      const entry = await feedEntry(OPERATIONS[category]);
      const renderClient = clientRenderer();
      const actual = renderClient(entry.display_template_id, entry.display_template_args);
      expect(actual).not.toContain("[unrecognized");
      expect(actual).toBe(renderClient(namespace, entry.display_template_args));
      // Frozen lifecycle/config copy already differs, as pinned in templates.test.ts.
      // Preserve those bounds explicitly instead of claiming all category sentences agree.
      if (category === "lifecycle") {
        expect(actual).toBe("Lifecycle change on agent (unknown).");
      } else if (category === "config") {
        expect(actual).toBe("Configuration change applied.");
      } else {
        expect(actual).toBe(renderTemplate(entry.display_template_id, entry.display_template_args, { surface: "activity" }));
      }
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

  // fail-before-exempt: exact-id precedence and unknown-id boundaries already hold on base.
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
