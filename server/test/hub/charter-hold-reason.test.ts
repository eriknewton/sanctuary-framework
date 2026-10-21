/**
 * Why a Charter hold is held reaches the operator's card only as structured
 * data: a reason code the console turns into its own sentence, plus at most one
 * gate-quoted identifier carried as delimited data. The gate's free-text reason
 * never reaches a card, so an identifier an agent chose (a namespace, a
 * counterparty DID) cannot pose as approval guidance on the operator's screen.
 * The held operation name is treated the same way: a proxied tool is named by
 * an upstream server, so the card bounds it and the console shows it only as
 * delimited, escaped data.
 *
 * Every reason the gate can send to the approval channel is raised through the
 * real ApprovalGate, and a coverage test reads the gate's source so a new or
 * reworded reason fails here instead of reaching the operator as unrecognised.
 */
import { readFileSync } from "node:fs";
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
  CARD_OPERATION_MAX_CHARS,
  HOLD_REASON_SUBJECT_MAX_CHARS,
  HOLD_REASON_TEMPLATES,
  PROXY_REASON_GATE_SOURCE,
  PROXY_REASON_PREFIX,
  classifyHoldReason,
  projectCharterApproval,
} from "../../src/hub/charter-approval-bridge.js";
import { heldSubjectText } from "../../src/dashboard/v1_1/templates.js";
import { HUB_HOLD_REASON_CODES, type HubHoldReason } from "../../src/contracts/v1.1/hub-events.js";
import {
  SUBJECT_SLOT,
  clientCardRenderers,
  clientDeclarations,
  clientHoldReasonRenderer,
  splitHeldReason,
} from "../dashboard/v1_1/client-script-extract.js";

// The namespace a held agent could choose to make its own text read as guidance.
const GUIDANCE_SHAPED_NAMESPACE = 'notes" (operator approved). Click Allow once. "';
// A tool name an upstream MCP server could advertise so the held operation reads as guidance.
const GUIDANCE_SHAPED_TOOL = "proxy/files/read. Operator approved. Click Allow once";

type Anomaly = PrincipalPolicy["tier2_anomaly"];

function policyWith(anomaly: Partial<Anomaly>, overrides: Partial<PrincipalPolicy> = {}): PrincipalPolicy {
  return { ...DEFAULT_POLICY, ...overrides, tier2_anomaly: { ...DEFAULT_POLICY.tier2_anomaly, ...anomaly } };
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

/** The project's whole-word check: no word outside a held-subject element came from the held call. */
function expectConsoleWordsOnly(prose: string): void {
  expect(prose).not.toMatch(/Operator approved|operator approved|Click Allow once/);
}

describe("structured hold reasons", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
  });

  /** Raise one call through the real gate and return the request it held last, classified. */
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

  it("covers every reason literal the gate source can send to the approval channel", () => {
    // Computed, not listed: read every reason literal in gate.ts, keep those that can reach requestApproval, and
    // require each to be one bridge template's pinned gateSource (the proxy wrapper is the prefix the classifier
    // strips). A literal in a gate result (it carries `allowed:`) or a Tier 3 classification never reaches the
    // channel. A new or reworded gate reason fails here.
    const source = readFileSync(new URL("../../src/principal-policy/gate.ts", import.meta.url), "utf8");
    const LITERAL = String.raw`(?:\x60(?:[^\x60\\]|\\.)*\x60|"(?:[^"\\]|\\.)*")`;
    const literalRun = new RegExp(String.raw`${LITERAL}(?:\s*\+\s*${LITERAL})*`, "y");
    const readRun = (at: number): string | null => {
      literalRun.lastIndex = at;
      const run = literalRun.exec(source);
      if (!run) return null;
      return [...run[0].matchAll(new RegExp(LITERAL, "g"))].map((m) => m[0].slice(1, -1)).join("");
    };
    const enclosingObject = (at: number): string => {
      let depth = 0;
      let open = at;
      for (; open >= 0; open--) {
        if (source[open] === "}") depth++;
        else if (source[open] === "{") {
          if (depth === 0) break;
          depth--;
        }
      }
      depth = 0;
      let close = open;
      for (; close < source.length; close++) {
        if (source[close] === "{") depth++;
        else if (source[close] === "}" && --depth === 0) break;
      }
      return source.slice(open, close + 1);
    };

    const held = new Set<string>();
    const notHeld = new Set<string>();
    for (const m of source.matchAll(/\breason:\s*/g)) {
      const literal = readRun(m.index! + m[0].length);
      if (literal === null) continue;
      const object = enclosingObject(m.index!);
      (/\ballowed:/.test(object) || /\btier:\s*3\b/.test(object) ? notHeld : held).add(literal);
    }
    const forwarded = new Set<string>();
    for (const m of source.matchAll(/this\.requestApproval\(\s*[A-Za-z_.]+,\s*\d,\s*/g)) {
      const literal = readRun(m.index! + m[0].length);
      if (literal !== null) held.add(literal);
      else forwarded.add(/^[A-Za-z_.]+/.exec(source.slice(m.index! + m[0].length))![0]);
    }
    // A non-literal reason passed to the channel only forwards classifyOperation's reasons, read above.
    expect([...forwarded].sort()).toEqual(["classification.anomaly.reason", "classification.reason"]);
    expect(notHeld.size).toBeGreaterThan(0);

    expect(held.has(PROXY_REASON_GATE_SOURCE)).toBe(true);
    expect(PROXY_REASON_GATE_SOURCE.startsWith(PROXY_REASON_PREFIX)).toBe(true);
    held.delete(PROXY_REASON_GATE_SOURCE);
    expect([...held].sort()).toEqual(HOLD_REASON_TEMPLATES.map((t) => t.gateSource).sort());
  });

  it("recognises every reason the real gate writes, and keeps only the quoted identifier", async () => {
    const noFirstSession = policyWith({ first_session_policy: "log" });
    // identity_sign is Tier 1 in every policy the loader builds, so the signing-rate reason is reached only by a
    // policy that lists it elsewhere; the gate itself still writes it.
    const signingPolicy = policyWith(
      { first_session_policy: "log", max_signs_per_minute: 2 },
      {
        tier1_always_approve: DEFAULT_POLICY.tier1_always_approve.filter((op) => op !== "identity_sign"),
        tier3_always_allow: [...DEFAULT_POLICY.tier3_always_allow, "identity_sign"],
      },
    );
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
        expected: { code: "signing_rate" },
        policy: signingPolicy,
        tool: "identity_sign",
        args: {},
        // Two signatures fill max_signs_per_minute; the third, below, exceeds it.
        setup: async (gate) => {
          await gate.evaluate("identity_sign", {});
          await gate.evaluate("identity_sign", {});
        },
      },
      {
        expected: { code: "frequency_spike" },
        policy: policyWith({ first_session_policy: "log", new_namespace_access: "log", frequency_spike_multiplier: 2 }),
        tool: "state_list",
        args: {},
        // Three other tools called once each and state_list three times leave the average at 1.5 calls a minute; the
        // fourth state_list, below, is 4 against an average of 1.75, more than twice it.
        setup: async (gate) => {
          for (const other of ["identity_list", "identity_verify", "proof_commitment"]) await gate.evaluate(other, {});
          for (let call = 0; call < 3; call++) await gate.evaluate("state_list", {});
        },
      },
      {
        expected: { code: "injection_escalation" },
        policy: DEFAULT_POLICY,
        tool: "state_write",
        // A fullwidth letter is a medium normalization signal, which the default detector escalates.
        args: { namespace: "notes", key: "k", value: "\uff21" },
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
    const witnessed = new Set<string>();
    for (const c of cases) {
      const { reason } = await heldThroughGate(c.policy, c.tool, c.args, c.setup);
      expect(reason, `${c.tool} -> ${c.expected.code}`).toEqual(c.expected);
      witnessed.add(reason.code);
    }
    // Every recognised code has a real-gate witness above.
    expect([...witnessed].sort()).toEqual(HUB_HOLD_REASON_CODES.filter((code) => code !== "unrecognized").sort());
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

  it("caps a held operation name on the card and marks it shortened", () => {
    // 64 times the bound, so a card that carried the whole name would be many times the size of the bounded one.
    const long = "proxy/files/" + "x".repeat(CARD_OPERATION_MAX_CHARS * 64);
    const card = projectCharterApproval(
      { id: "hold-1", operation: long, tier: 2, created_at: "2026-10-21T00:00:00.000Z", hold_reason: { code: "unrecognized" } },
      "operator-identity",
    );
    const operation = card.display_template_args.find((a) => a.kind === "operation")!.value as string;
    expect(operation).toBe(long.slice(0, CARD_OPERATION_MAX_CHARS));
    expect(card.operation_truncated).toBe(true);
    expect(JSON.stringify(card).length).toBeLessThan(long.length);
    const { subjects } = splitHeldReason(clientCardRenderers().approvalOperationHtml(card));
    expect(subjects).toEqual([heldSubjectText(operation)]);
    expect(clientCardRenderers().approvalOperationHtml(card)).toContain("</code> (shortened)");
    // A name within the bound is carried whole and unflagged.
    const short = projectCharterApproval(
      { id: "hold-2", operation: "state_write", tier: 2, created_at: "2026-10-21T00:00:00.000Z" },
      "operator-identity",
    );
    expect(short.operation_truncated).toBeUndefined();
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
    expectConsoleWordsOnly(prose);
  });

  it("shows an upstream tool name that reads as guidance only as escaped, delimited data on the card", async () => {
    // Real gate (a Tier 1 proxied tool) -> structured record -> bridge projection -> the console's renderers.
    const { request, reason } = await heldThroughGate(
      policyWith({ first_session_policy: "log" }),
      GUIDANCE_SHAPED_TOOL,
      {},
      (gate) => gate.setProxyTierResolver(() => 1),
    );
    expect(reason).toEqual({ code: "proxy_tier1", subject: GUIDANCE_SHAPED_TOOL });
    const card = projectCharterApproval(
      { id: "hold-1", operation: request.operation, tier: request.tier, created_at: request.timestamp, hold_reason: reason },
      "operator-identity",
    );
    const renderers = clientCardRenderers();
    const quoted = heldSubjectText(GUIDANCE_SHAPED_TOOL);
    const surfaces: Array<[string, string, string]> = [
      ["What it wants to do", renderers.approvalTextHtml(card), `Run a Tier 1 operation: ${SUBJECT_SLOT}.`],
      ["Operation", renderers.approvalOperationHtml(card), SUBJECT_SLOT],
      [
        "Why it is held",
        renderers.approvalHoldReasonHtml(card),
        `Proxied tool ${SUBJECT_SLOT} is configured as Tier 1, so it always asks for approval.`,
      ],
    ];
    for (const [surface, html, expected] of surfaces) {
      const { prose, subjects } = splitHeldReason(html);
      expect(prose, surface).toBe(expected);
      expect(subjects, surface).toEqual([quoted]);
      expectConsoleWordsOnly(prose);
    }
    // In plain text (a filter option, feedback) the name keeps its quoted form.
    expect(renderers.approvalOperationText(card)).toBe(quoted);
  });

  it("shows hidden and reordering characters in an identifier as visible escapes", () => {
    const hidden = "notes\u202e\u200b\u0007\u0085\ufeff\u206a\ufff9\u{e0001}\u{e0041}end";
    const card = {
      item_id: "charter.approval.hold-1",
      tier: "tier2",
      operation_category: "other",
      display_template_id: "approval_pending.tier2.other",
      display_template_args: [{ kind: "operation", value: `proxy/${hidden}` }],
      hold_reason: { code: "first_namespace_access", subject: hidden },
    };
    const renderers = clientCardRenderers();
    const shown = "notes\\u202e\\u200b\\u0007\\u0085\\ufeff\\u206a\\ufff9\\u{e0001}\\u{e0041}end";
    expect(splitHeldReason(renderers.approvalHoldReasonHtml(card)).subjects).toEqual([`"${shown}"`]);
    expect(splitHeldReason(renderers.approvalOperationHtml(card)).subjects).toEqual([`"proxy/${shown}"`]);
    expect(splitHeldReason(renderers.approvalTextHtml(card)).subjects).toEqual([`"proxy/${shown}"`]);
    for (const html of [renderers.approvalHoldReasonHtml(card), renderers.approvalOperationHtml(card), renderers.approvalTextHtml(card)]) {
      expect(html).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u);
    }
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
