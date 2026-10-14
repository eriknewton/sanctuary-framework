/**
 * Hub activity entries resolve through the dashboard category sentences.
 * Exercises the real audit feed projection and the embedded client renderer.
 */
import { runInNewContext } from "node:vm";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
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
import type { AuditEntry } from "../../../src/operational/audit-log.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../../src/castle-wall/constants.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import type { HubDisplayTemplateArg } from "../../../src/contracts/v1.1/hub-events.js";
import type { LocalAgentRecord } from "../../../src/contracts/v1.1/local-agent-records.js";

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

// Unsigned fixture entries carry no verified agent. Privacy names a missing agent as unknown; every other category
// renders the general sentence, which needs a verified agent, so those rows keep the diagnostic fallback.
const PRIVACY_SENTENCE = "Privacy event recorded for agent (unknown).";
const unattributedText = (category: keyof typeof OPERATIONS, id: string) =>
  category === "privacy" ? PRIVACY_SENTENCE : `[unrecognized template: ${id}]`;

// A producer-signed fixture row the feed attributes to this agent, as in test/hub/activity-feed-attestation.test.ts.
const FORTRESS_ID = "fortress:test";
const VERIFIED_AGENT_ID = "verified-fixture-agent";
const VERIFIED_SUBJECT = `${FORTRESS_ID}/uid-503`;
const SIGNED_AT_MS = 1_777_777_777_777;
const PRODUCER_SEQ = 77;
const producerPriv = ed25519.utils.randomPrivateKey();
const GENERAL_SENTENCE = `Audit event recorded for agent ${VERIFIED_AGENT_ID}.`;
const VERIFIED_AGENT: LocalAgentRecord = {
  version: "1.1",
  agent_id: VERIFIED_AGENT_ID,
  protection_subject: VERIFIED_SUBJECT,
  identity_id: IDENTITY_ID,
  harness: "claude_code",
  model_provider: { vendor: "anthropic", model_id: "fixture-model", runs_locally: false },
  policy_id: "policy-default",
  status: "active",
  budget_summary: {
    daily: { unit: "tokens", cap: 100_000, used: 0 },
    last_refreshed_at: "2026-07-20T00:00:00.000Z",
  },
  last_activity_at: "2026-07-20T10:00:00.000Z",
  wrapped_at: "2026-07-20T00:00:00.000Z",
  capabilities: {
    can_pause: true,
    can_resume: true,
    can_restart: true,
    can_unwrap: true,
    can_lockdown: true,
    can_chat: true,
    can_change_template: true,
  },
};

// Operations the hub files under a category whose own sentence they would contradict: aggregator views and
// duplicates under approval, an automated denial, a blocked connection, a policy view on the l2 catch-all, a panel
// view on the agent_ catch-all, a failed configuration read, and a handoff row.
const CONTRADICTING_OPERATIONS = [
  ["cross_harness_approval_audit_trail_viewed", "l2", "approval"],
  ["cross_harness_approval_deduped", "l2", "approval"],
  ["tool_auto_deny", "l1", "denial"],
  ["egress_blocked", "l1", "egress"],
  ["principal_policy_view", "l2", "policy_decision"],
  ["agent_inspect_panel_opened", "l1", "lifecycle"],
  ["config_read_failed", "l1", "config"],
  ["handoff_created", "l1", "handoff"],
] as const;

async function feedEntry(operation: string, layer: "l1" | "l2" = "l1", details: Record<string, unknown> = {}) {
  const auditLog = new AuditLog(new MemoryStorage(), randomBytes(AUDIT_KEY_BYTES));
  // The unclassified operation needs l1 because l2 defaults to policy_decision.
  await auditLog.append(layer, operation, IDENTITY_ID, details);
  await auditLog.flush();
  const entries = await aggregateActivity({ auditLog, identityId: IDENTITY_ID });
  expect(entries).toHaveLength(1);
  return entries[0]!;
}

function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function verifiedFeedEntry(operation: string, layer: "l1" | "l2") {
  const auditLog = new AuditLog(new MemoryStorage(), randomBytes(AUDIT_KEY_BYTES));
  const unsigned: AuditEntry = {
    timestamp: "2026-07-20T10:00:00.000Z",
    layer,
    operation,
    identity_id: VERIFIED_SUBJECT,
    result: "success",
    details: { agent_id: VERIFIED_AGENT_ID },
  };
  const body = JSON.stringify({
    timestamp: unsigned.timestamp,
    layer: unsigned.layer,
    operation: unsigned.operation,
    identity_id: unsigned.identity_id,
    result: unsigned.result,
    details: unsigned.details,
  });
  const sig = ed25519.sign(producerSigningBytes(body, SIGNED_AT_MS, PRODUCER_SEQ), producerPriv);
  await auditLog.appendCritical({
    layer: unsigned.layer,
    operation: unsigned.operation,
    identity_id: unsigned.identity_id,
    timestamp: unsigned.timestamp,
    result: unsigned.result,
    details: {
      ...unsigned.details,
      seq: PRODUCER_SEQ,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  });
  await auditLog.flush();
  const entries = await aggregateActivity({
    auditLog,
    identityId: VERIFIED_SUBJECT,
    pinnedProducerKeyB64url: toBase64url(ed25519.getPublicKey(producerPriv)),
    subjectFortressId: FORTRESS_ID,
    listLocalAgents: () => [VERIFIED_AGENT],
  });
  expect(entries).toHaveLength(1);
  expect(entries[0]!.agent_id).toBe(VERIFIED_AGENT_ID);
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

    it(`renders real unattributed ${category} feed entries through the server fallback rule`, async () => {
      const entry = await feedEntry(OPERATIONS[category]);
      expect(entry.category).toBe(category);
      expect(entry.agent_id).toBeUndefined();
      expect(entry.display_template_id).toBe(`${namespace}.${OPERATIONS[category]}`);
      // Operation coverage comes from fallback, without registering any new template ids.
      expect(listRegisteredTemplateIds()).not.toContain(entry.display_template_id);
      const actual = renderTemplate(entry.display_template_id, entry.display_template_args, { surface: "activity" });
      expect(actual).toBe(unattributedText(category, entry.display_template_id));
    });

    it(`renders real unattributed ${category} feed entries through the client fallback rule`, async () => {
      const entry = await feedEntry(OPERATIONS[category]);
      const renderClient = clientRenderer();
      const actual = renderClient(entry.display_template_id, entry.display_template_args);
      expect(actual).toBe(unattributedText(category, entry.display_template_id));
    });
  }

  for (const [operation, layer, category] of CONTRADICTING_OPERATIONS) {
    it(`renders a verified agent's ${operation} through the general sentence, not the ${category} sentence`, async () => {
      const entry = await verifiedFeedEntry(operation, layer);
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

  it("keeps an unsigned row that names an agent only in its details on the diagnostic fallback", async () => {
    // Details metadata is forgeable, so the feed projects no agent from it and the row has no verified subject.
    const entry = await feedEntry(OPERATIONS.handoff, "l1", { agent_id: "claimed-agent" });
    expect(entry.agent_id).toBeUndefined();
    const expected = `[unrecognized template: ${entry.display_template_id}]`;
    expect(renderTemplate(entry.display_template_id, entry.display_template_args, { surface: "activity" })).toBe(expected);
    expect(clientRenderer()(entry.display_template_id, entry.display_template_args)).toBe(expected);
  });

  it("keeps an operation id with an empty agent arg on the diagnostic fallback", () => {
    const id = `${HUB_ACTIVITY_TEMPLATE_NAMESPACES.other}.${OPERATIONS.other}`;
    const args: HubDisplayTemplateArg[] = [{ kind: "agent_id", value: "" }];
    expect(renderTemplate(id, args)).toBe(`[unrecognized template: ${id}]`);
    expect(clientRenderer()(id, args)).toBe(`[unrecognized template: ${id}]`);
  });

  it("keeps an operation id with a null agent arg on the diagnostic fallback in both renderers", () => {
    // A null element is outside the typed contract; both mirrors of hasArgValue skip it rather than throw.
    const id = `${HUB_ACTIVITY_TEMPLATE_NAMESPACES.other}.${OPERATIONS.other}`;
    const args = [null] as unknown as HubDisplayTemplateArg[];
    expect(renderTemplate(id, args)).toBe(`[unrecognized template: ${id}]`);
    expect(clientRenderer()(id, args)).toBe(`[unrecognized template: ${id}]`);
  });

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
    // A verified agent makes the general fallback eligible, so only the exact-first order keeps the exact sentence.
    const entry = await verifiedFeedEntry("agent_lockdown_engaged", "l1");
    const expected = `Network access revoked for agent ${VERIFIED_AGENT_ID}.`;
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
