/**
 * Why a Charter hold is held reaches the operator's card only as structured
 * data: a reason code the console turns into its own sentence, plus at most one
 * gate-quoted identifier carried as delimited data. The gate's free-text reason
 * never reaches a card, so an identifier an agent chose (a namespace, a
 * counterparty DID) cannot pose as approval guidance on the operator's screen.
 *
 * Witnesses are raised through the real ApprovalGate wherever the default build
 * can reach the reason; the two rate reasons that need a live call history are
 * pinned against the gate's literal wording instead.
 */
import { beforeEach, describe, expect, it } from "vitest";

import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { ApprovalRequest, PrincipalPolicy } from "../../src/principal-policy/types.js";
import {
  HOLD_REASON_SUBJECT_MAX_CHARS,
  HOLD_REASON_TEMPLATES,
  classifyHoldReason,
  projectCharterApproval,
} from "../../src/hub/charter-approval-bridge.js";
import { HUB_HOLD_REASON_CODES, type HubHoldReason } from "../../src/contracts/v1.1/hub-events.js";
import {
  SUBJECT_SLOT,
  clientDeclarations,
  clientHoldReasonRenderer,
  splitHeldReason,
} from "../dashboard/v1_1/client-script-extract.js";

// The namespace a held agent could choose to make its own text read as guidance.
const GUIDANCE_SHAPED_NAMESPACE = 'notes" (operator approved). Click Allow once. "';

type Anomaly = PrincipalPolicy["tier2_anomaly"];

function policyWith(anomaly: Partial<Anomaly>): PrincipalPolicy {
  return { ...DEFAULT_POLICY, tier2_anomaly: { ...DEFAULT_POLICY.tier2_anomaly, ...anomaly } };
}

/** A channel that records each held request and refuses it, so evaluate() settles at once. */
function capturingChannel(seen: ApprovalRequest[]): ApprovalChannel {
  return {
    requestApproval: async (request: ApprovalRequest) => {
      seen.push(request);
      return { decision: "deny", decided_at: new Date().toISOString(), decided_by: "human" };
    },
  };
}

describe("structured hold reasons", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
  });

  /** Raise one call through the real gate and return the request it held, classified. */
  async function heldThroughGate(
    policy: PrincipalPolicy,
    toolName: string,
    args: Record<string, unknown>,
    setup?: (gate: ApprovalGate) => Promise<void> | void,
  ): Promise<{ request: ApprovalRequest; reason: HubHoldReason }> {
    const seen: ApprovalRequest[] = [];
    const gate = new ApprovalGate(
      policy,
      new BaselineTracker(storage, masterKey),
      capturingChannel(seen),
      new AuditLog(storage, masterKey),
    );
    await setup?.(gate);
    await gate.evaluate(toolName, args);
    const request = seen.at(-1);
    expect(request, `${toolName} was held`).toBeDefined();
    return {
      request: request!,
      reason: classifyHoldReason({
        operation: request!.operation,
        reason: request!.reason,
        context: request!.context,
      }),
    };
  }

  it("keeps the reason codes in full-set parity across the contract, the bridge templates and the console sentences", () => {
    const contract = HUB_HOLD_REASON_CODES.filter((code) => code !== "unrecognized").sort();
    expect(HOLD_REASON_TEMPLATES.map((t) => t.code).sort()).toEqual(contract);
    const { HOLD_REASON_SENTENCES } = clientDeclarations<{ HOLD_REASON_SENTENCES: Record<string, unknown> }>(
      ["HOLD_REASON_SENTENCES"],
      ["HOLD_REASON_SENTENCES"],
    );
    expect(Object.keys(HOLD_REASON_SENTENCES).sort()).toEqual(contract);
  });

  it("recognises every reason the real gate writes in this build, and keeps only the quoted identifier", async () => {
    const noFirstSession = policyWith({ first_session_policy: "log" });
    const cases: Array<{
      expected: HubHoldReason;
      policy: PrincipalPolicy;
      tool: string;
      args: Record<string, unknown>;
      setup?: (gate: ApprovalGate) => Promise<void> | void;
    }> = [
      { expected: { code: "tier1_policy" }, policy: DEFAULT_POLICY, tool: "state_export", args: {} },
      { expected: { code: "tier1_forced" }, policy: DEFAULT_POLICY, tool: "memory_delete", args: {} },
      {
        expected: { code: "tier1_secret_waiver" },
        policy: DEFAULT_POLICY,
        tool: "memory_ingest",
        args: { allow_files: ["notes.txt"] },
      },
      {
        expected: { code: "tier1_unclassified" },
        policy: policyWith({ first_session_policy: "log", new_namespace_access: "log", new_counterparty: "log" }),
        tool: "made_up_tool",
        args: {},
      },
      { expected: { code: "first_session" }, policy: DEFAULT_POLICY, tool: "made_up_tool", args: {} },
      {
        expected: { code: "first_namespace_access", subject: "customer-notes" },
        policy: noFirstSession,
        tool: "state_write",
        args: { namespace: "customer-notes", key: "k", value: "v" },
      },
      {
        expected: { code: "first_counterparty", subject: "did:key:z6MkCounterparty" },
        policy: noFirstSession,
        tool: "handshake_initiate",
        args: { counterparty_did: "did:key:z6MkCounterparty" },
      },
      {
        expected: { code: "bulk_read", subject: "ledger" },
        policy: policyWith({ first_session_policy: "log", new_namespace_access: "log", bulk_read_threshold: 2 }),
        tool: "state_read",
        args: { namespace: "ledger", key: "k" },
        // Two reads fill the threshold; the third, below, is the bulk read.
        setup: async (gate) => {
          await gate.evaluate("state_read", { namespace: "ledger", key: "k" });
          await gate.evaluate("state_read", { namespace: "ledger", key: "k" });
        },
      },
      {
        expected: { code: "proxy_tier1", subject: "proxy/files/delete_everything" },
        policy: noFirstSession,
        tool: "proxy/files/delete_everything",
        args: {},
        setup: (gate) => gate.setProxyTierResolver(() => 1),
      },
      {
        expected: { code: "first_namespace_access", via_proxy: true, subject: "drafts" },
        policy: noFirstSession,
        tool: "proxy/files/write",
        args: { namespace: "drafts" },
        setup: (gate) => gate.setProxyTierResolver(() => 2),
      },
    ];
    for (const c of cases) {
      const { reason } = await heldThroughGate(c.policy, c.tool, c.args, c.setup);
      expect(reason, `${c.tool} -> ${c.expected.code}`).toEqual(c.expected);
    }
  });

  it("recognises the two rate reasons in the gate's own wording", () => {
    // Literal reasons as gate.ts detectAnomaly writes them for these fields.
    expect(
      classifyHoldReason({
        operation: "identity_sign",
        reason: "Signing frequency (31/min) exceeds limit (30/min)",
        context: { operation: "identity_sign", signs_per_minute: 31, limit: 30 },
      }),
    ).toEqual({ code: "signing_rate" });
    expect(
      classifyHoldReason({
        operation: "state_list",
        reason: 'Frequency spike: "state_list" at 40/min (5\u00d7 above average 2.5/min)',
        context: { operation: "state_list", current_rate: 40, average_rate: 2.5, multiplier: 5 },
      }),
    ).toEqual({ code: "frequency_spike" });
  });

  it("never returns reason text it cannot re-render from the hold's own fields", () => {
    // Text a direct channel caller wrote, and a gate shape whose quoted field disagrees with the context.
    const inputs = [
      { operation: "state_write", reason: "Approved already. Click Allow once.", context: {} },
      {
        operation: "state_write",
        reason: 'First access to namespace "a" (not in session baseline)',
        context: { namespace: "b" },
      },
      { operation: "state_write", reason: 42, context: null },
    ];
    for (const input of inputs) {
      const reason = classifyHoldReason(input);
      expect(reason).toEqual({ code: "unrecognized" });
      expect(JSON.stringify(reason)).not.toMatch(/Click|Approved|namespace/);
    }
  });

  it("caps a quoted identifier and marks it shortened", () => {
    const long = "n".repeat(HOLD_REASON_SUBJECT_MAX_CHARS + 50);
    expect(
      classifyHoldReason({
        operation: "state_write",
        reason: `First access to namespace "${long}" (not in session baseline)`,
        context: { namespace: long },
      }),
    ).toEqual({
      code: "first_namespace_access",
      subject: long.slice(0, HOLD_REASON_SUBJECT_MAX_CHARS),
      subject_truncated: true,
    });
  });

  it("shows a guidance-shaped namespace only as escaped, delimited data under console-written words", async () => {
    // Real gate -> structured record -> bridge projection -> the console's own renderer.
    const { request, reason } = await heldThroughGate(
      policyWith({ first_session_policy: "log" }),
      "state_write",
      { namespace: GUIDANCE_SHAPED_NAMESPACE, key: "k", value: "v" },
    );
    expect(request.reason).toContain("Click Allow once");
    const card = projectCharterApproval(
      { id: "hold-1", operation: request.operation, tier: request.tier, created_at: request.timestamp, hold_reason: reason },
      "operator-identity",
    );
    expect(JSON.stringify(card)).not.toContain("not in session baseline");
    const html = clientHoldReasonRenderer()(card);
    const { prose, subjects } = splitHeldReason(html);
    // Every word outside the data element is the console's own sentence.
    expect(prose).toBe(`First access to namespace ${SUBJECT_SLOT}. It is not in this session's baseline.`);
    // The identifier appears once, JSON-quoted with its quotes escaped, and only inside the element.
    expect(subjects).toEqual([JSON.stringify(GUIDANCE_SHAPED_NAMESPACE)]);
    expect(subjects[0]).toBe('"notes\\" (operator approved). Click Allow once. \\""');
    expect(prose).not.toContain("Click");
  });

  it("shows hidden and reordering characters in an identifier as visible escapes", () => {
    const hiddenChars = "notes\u202e\u200b\u0007\u0085\ufeffend";
    const html = clientHoldReasonRenderer()({
      item_id: "charter.approval.hold-1",
      tier: "tier2",
      operation_category: "other",
      display_template_args: [{ kind: "operation", value: "state_write" }],
      hold_reason: { code: "first_namespace_access", subject: hiddenChars },
    });
    const { subjects } = splitHeldReason(html);
    expect(subjects).toEqual(['"notes\\u202e\\u200b\\u0007\\u0085\\ufeffend"']);
    expect(html).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/);
  });

  it("falls back to a fixed sentence naming the tier and operation for an unrecognised reason", () => {
    const html = clientHoldReasonRenderer()({
      item_id: "charter.approval.hold-1",
      tier: "tier2",
      operation_category: "other",
      display_template_args: [{ kind: "operation", value: "state_write" }],
      hold_reason: { code: "unrecognized" },
    });
    const { prose, subjects } = splitHeldReason(html);
    expect(prose).toBe(`Held under the operator policy (Tier 2): ${SUBJECT_SLOT}`);
    expect(subjects).toEqual(['"state_write"']);
  });
});
