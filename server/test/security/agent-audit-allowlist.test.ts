/**
 * Agent-facing audit redaction ALLOWLIST — acceptance + structure tripwire.
 *
 * Covers the CISO 2026-06-15 findings that motivated inverting the agent-facing
 * audit redaction from a DENYLIST to an ALLOWLIST:
 *
 *   HIGH-1 (LIVE leak): the free-text `reason` field carried anomaly THRESHOLDS
 *     ("Signing frequency (7/min) exceeds limit (5/min)", "… threshold: 50", "3×
 *     above average", "not classified in any policy tier"). `reason` was never on
 *     the denylist, so it shipped to agents via monitor_audit_log. The allowlist
 *     view drops `details` entirely → no reason, no threshold.
 *   MED-1: audit_export_siem formatted from raw details (tier, agent DID, session
 *     id) with no redaction. Now routed through the allowlist + own-identity.
 *   MED-2: the router catch-all returned raw err.message (fail-open info
 *     disclosure). Now logs the full error operator-side, returns a generic
 *     payload + audit_ref.
 *   MED-3 / LOW-1: own-identity filter on monitor_audit_log + audit_export_siem;
 *     search needle restricted to the allowlisted fields.
 *
 * STRUCTURE TRIPWIRE: asserts NO agent-facing audit path emits a raw `details`
 * object or any non-allowlisted field — the regression guard that makes the
 * inversion durable (a new operator-attribution detail key cannot leak).
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { createSanctuaryServer } from "../../src/index.js";
import { AuditLog, BROKER_OPS } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  redactAuditEntryForAgent,
  buildAgentSearchCorpus,
  AGENT_AUDIT_VIEW_FIELDS,
  AGENT_AUDIT_SEARCHABLE_DETAIL_KEYS,
} from "../../src/operational/agent-audit-redaction.js";
import { createSIEMTools } from "../../src/audit/siem-tools.js";
import { createServer } from "../../src/router.js";
import { fingerprintIdentityId } from "../../src/agent-native/safety-base.js";
import type { ToolDefinition } from "../../src/router.js";
import { Broker } from "../../src/disclosure/broker/broker.js";
import { createBrokerMcpServer } from "../../src/broker-mcp/broker-server.js";
import type { Backend } from "../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/disclosure/broker/backend-interface.js";

const ALLOWED_VIEW_KEYS = [...AGENT_AUDIT_VIEW_FIELDS].sort();
const ALLOWED_EVENT_KEYS = [
  "cursor_event_id",
  ...AGENT_AUDIT_VIEW_FIELDS,
].sort();

// Threshold-bearing free-text reasons, exactly as the gate writes them into the
// audit `details.reason` field (principal-policy/gate.ts). Each leaks a policy
// threshold / partition if it reaches an agent.
const THRESHOLD_REASONS = [
  'Signing frequency (7/min) exceeds limit (5/min)',
  'Bulk read detected: 60 reads from "secrets" in 60 seconds (threshold: 50)',
  'Frequency spike: "state_read" at 30/min (3× above average 4.0/min)',
  '"state_export" is not classified in any policy tier — requires approval (SEC-011 safe default)',
];

async function callServerTool(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"],
  name: string,
  args: Record<string, unknown> = {}
) {
  const handler = (
    server as unknown as { _requestHandlers: Map<string, Function> }
  )._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  return await handler(
    { method: "tools/call" as const, params: { name, arguments: args } },
    {}
  );
}

function parse(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0]!.text);
}

async function withSessionIdentity(identityId: string, fn: () => Promise<void>) {
  const prev = process.env.SANCTUARY_SESSION_IDENTITY_ID;
  process.env.SANCTUARY_SESSION_IDENTITY_ID = identityId;
  try {
    await fn();
  } finally {
    if (prev === undefined) delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
    else process.env.SANCTUARY_SESSION_IDENTITY_ID = prev;
  }
}

function binding(identityId: string) {
  return {
    identity_id: identityId,
    requester_identity_fingerprint: fingerprintIdentityId(identityId),
  };
}

describe("agent-audit-allowlist: unit (redactAuditEntryForAgent)", () => {
  it("(a) emits ONLY {timestamp, operation, result, has_details} — never reason/threshold/details", () => {
    for (const reason of THRESHOLD_REASONS) {
      const view = redactAuditEntryForAgent({
        timestamp: "2026-06-15T00:00:00.000Z",
        layer: "l2",
        operation: "gate_deny:identity_sign",
        identity_id: "system",
        result: "failure",
        details: {
          tier: 2,
          reason, // threshold-bearing free text
          decided_by: "channel_failure",
          rule_id: "deny-secret-rule",
        },
      });
      expect(Object.keys(view).sort()).toEqual(ALLOWED_VIEW_KEYS);
      expect(view.has_details).toBe(true);
      const serialized = JSON.stringify(view);
      // No reason, no threshold number, no tier, no rule id.
      expect(serialized).not.toContain(reason);
      expect(serialized).not.toContain("threshold");
      expect(serialized).not.toContain("exceeds limit");
      expect(serialized).not.toContain("above average");
      expect(serialized).not.toContain("deny-secret-rule");
      expect((view as Record<string, unknown>).details).toBeUndefined();
      expect((view as Record<string, unknown>).identity_id).toBeUndefined();
    }
  });

  it("has_details is false when the entry carries no details", () => {
    const view = redactAuditEntryForAgent({
      timestamp: "2026-06-15T00:00:00.000Z",
      layer: "l2",
      operation: "state_read",
      identity_id: "ag",
      result: "success",
    });
    expect(view.has_details).toBe(false);
  });

  it("search corpus is an ALLOWLIST: only safe keys survive; decision/reason/rule_id/tier omitted", () => {
    const corpus = buildAgentSearchCorpus({
      details: {
        dest_host: "host.example",
        // none of these may appear in the corpus:
        decision: "deny_once", // REMOVED 2026-06-16 (policy-disposition oracle)
        reason: "Signing frequency (7/min) exceeds limit (5/min)",
        rule_id: "deny-secret-rule",
        tier: 2,
        decision_provenance: "policy-path",
      },
    });
    expect(corpus).toEqual({ dest_host: "host.example" });
    const serialized = JSON.stringify(corpus);
    expect(serialized).not.toContain("decision");
    expect(serialized).not.toContain("deny_once");
    expect(serialized).not.toContain("reason");
    expect(serialized).not.toContain("exceeds limit");
    expect(serialized).not.toContain("rule_id");
    expect(serialized).not.toContain("deny-secret-rule");
    expect(serialized).not.toContain("tier");
    expect(serialized).not.toContain("decision_provenance");
  });

  it("the searchable allowlist stays tiny and obviously-safe (guard against scope creep)", () => {
    // If this changes, a reviewer must consciously confirm the new key carries
    // no policy-inference signal. Keep it minimal — that is the allowlist's point.
    // `decision` was REMOVED 2026-06-16: its fine granularity
    // (allow_once/allow_always/deny_once/deny_always/timeout_default_deny) let an
    // agent probe WHICH policy disposition fired off `result_count`.
    expect([...AGENT_AUDIT_SEARCHABLE_DETAIL_KEYS].sort()).toEqual([
      "dest_host",
      "destination",
    ]);
  });
});

describe("agent-audit-allowlist: monitor_audit_log (HIGH-1 live leak, MED-3 own-identity)", () => {
  it("(a) a threshold-bearing gate entry returns NO reason/details to the agent", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "allowlist-monitor-threshold",
    });
    await withSessionIdentity("ag-threshold", async () => {
      // Seed a gate entry exactly as requestApproval writes it, but owned by the
      // caller so it passes the own-identity filter — proving the redaction (not
      // just the identity filter) is what strips the threshold.
      await auditLog.appendCritical({
        layer: "l2",
        operation: "gate_deny:identity_sign",
        identity_id: "ag-threshold",
        result: "failure",
        details: {
          tier: 2,
          reason: "Signing frequency (7/min) exceeds limit (5/min)",
          decided_by: "channel_failure",
        },
      });
      const res = await callServerTool(server, "monitor_audit_log", { limit: 10 });
      const parsed = parse(res);
      const text = res.content[0]!.text;
      const entry = parsed.entries.find(
        (e: { operation: string }) => e.operation === "gate_deny:identity_sign"
      );
      expect(entry).toBeDefined();
      expect(Object.keys(entry).sort()).toEqual(ALLOWED_VIEW_KEYS);
      expect(entry.details).toBeUndefined();
      expect(text).not.toContain("exceeds limit");
      expect(text).not.toContain("7/min");
      expect(text).not.toContain("Signing frequency");
    });
  });

  it("(b) returns only the CALLER's own entries (system/other-identity entries withheld)", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "allowlist-monitor-own-identity",
    });
    await withSessionIdentity("ag-self", async () => {
      await auditLog.append("l2", "state_read", "ag-self", { decision: "allow" });
      await auditLog.append("l2", "state_write", "ag-other", { decision: "allow" });
      await auditLog.appendCritical({
        layer: "l2",
        operation: "gate_deny:identity_sign",
        identity_id: "system",
        result: "failure",
        details: { tier: 2, reason: "Signing frequency (9/min) exceeds limit (5/min)" },
      });
      const res = await callServerTool(server, "monitor_audit_log", { limit: 50 });
      const parsed = parse(res);
      const ops = (parsed.entries as Array<{ operation: string }>).map(
        (e) => e.operation
      );
      expect(ops).toContain("state_read");
      // No other-identity entry, no system gate entry.
      expect(ops).not.toContain("state_write");
      expect(ops).not.toContain("gate_deny:identity_sign");
      expect(res.content[0]!.text).not.toContain("exceeds limit");
    });
  });

  it("fails CLOSED (returns nothing) when there is no bound session identity", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "allowlist-monitor-failclosed",
    });
    // Ensure no session identity is set.
    const prev = process.env.SANCTUARY_SESSION_IDENTITY_ID;
    delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
    try {
      await auditLog.append("l2", "state_read", "someone", { decision: "allow" });
      const res = await callServerTool(server, "monitor_audit_log", { limit: 10 });
      const parsed = parse(res);
      expect(parsed.entries).toEqual([]);
      expect(parsed.count).toBe(0);
    } finally {
      if (prev !== undefined) process.env.SANCTUARY_SESSION_IDENTITY_ID = prev;
    }
  });

  // (a) regression direction: the SAME assertion would FAIL against the pre-fix
  // denylist, because `reason` was never denylisted and would pass through. We
  // prove the post-fix behavior here; the pre-fix failure is documented in the
  // PR (the denylist did not contain `reason`).
});

describe("agent-audit-allowlist: LOW-1 gate-entry identity invariant", () => {
  // The threshold-bearing gate decisions (gate_deny / gate_unclassified /
  // gate_injection_block / gate_allow) are written with identity_id === "system",
  // so they are withheld from agents by the own-identity filter EVEN BEFORE the
  // allowlist drops their details — defence in depth. (The single intentional
  // exception is `gate_approval_proof`, which records the agent's OWN verified
  // approval under the agent's identity; its `tier` detail is protected by the
  // allowlist, not the identity filter. Documented in the PR, not changed here.)
  it("gate_deny written by the gate uses the system identity (threshold reason never owned by the agent)", async () => {
    const { ApprovalGate } = await import("../../src/principal-policy/gate.js");
    const { BaselineTracker } = await import("../../src/principal-policy/baseline.js");
    const { CallbackApprovalChannel } = await import(
      "../../src/principal-policy/approval-channel.js"
    );
    const { DEFAULT_POLICY } = await import("../../src/principal-policy/loader.js");

    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const agentId = "ag-gate-low1";
    const gate = new ApprovalGate(
      DEFAULT_POLICY,
      new BaselineTracker(storage, masterKey),
      // Channel denies → produces a gate_deny audit entry.
      new CallbackApprovalChannel(async () => ({
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      })),
      auditLog,
      undefined,
      undefined,
      undefined,
      {
        currentSessionBinding: () => binding(agentId),
      }
    );

    // Drive a real gate denial (identity_sign is a Tier-1 always-approve op; the
    // channel denies → the gate writes a gate_deny audit entry). The point of
    // this test is the IDENTITY invariant: the gate-written deny entry — which
    // carries the policy `tier` and a policy `reason` in its operator details —
    // is owned by "system", never by the agent.
    const res = await gate.evaluate("identity_sign", { commitment: "x" });
    expect(res.allowed).toBe(false);
    await new Promise((r) => setTimeout(r, 50));

    const q = await auditLog.query({ limit: 200 });
    const gateDenies = q.entries.filter((e) =>
      e.operation.startsWith("gate_deny:")
    );
    expect(gateDenies.length).toBeGreaterThan(0);
    // Every gate_deny is system-owned (so the own-identity filter withholds it
    // from agents) AND carries policy detail (tier/reason) that the allowlist
    // view drops regardless.
    for (const e of gateDenies) {
      expect(e.identity_id).toBe("system");
      const view = redactAuditEntryForAgent(e);
      expect((view as Record<string, unknown>).details).toBeUndefined();
      // The agent view never carries the policy tier or reason.
      const s = JSON.stringify(view);
      expect(s).not.toContain("tier");
      if (typeof e.details?.reason === "string") {
        expect(s).not.toContain(e.details.reason as string);
      }
    }
  });
});

describe("agent-audit-allowlist: audit_export_siem (MED-1, MED-3)", () => {
  function siemTool(auditLog: AuditLog, caller: string): ToolDefinition {
    const { tools } = createSIEMTools(auditLog, () => binding(caller));
    const t = tools.find((x) => x.name === "audit_export_siem");
    if (!t) throw new Error("audit_export_siem not found");
    return t;
  }

  it("never emits tier, agent DID, session id, or free-text reason (CEF + OCSF)", async () => {
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    await auditLog.append("l2", "identity_sign", "ag-siem", {
      decision: "deny_once",
      gate_decision: "deny",
      tier: 1,
      session_id: "sess-secret-1",
      agent_did: "did:key:zSECRETDID",
      reason: "Signing frequency (7/min) exceeds limit (5/min)",
    }, "failure");
    await new Promise((r) => setTimeout(r, 50));
    const tool = siemTool(auditLog, "ag-siem");

    for (const format of ["cef", "ocsf"] as const) {
      const res = await tool.handler({ format });
      const whole = res.content.map((c: { text: string }) => c.text).join("\n");
      expect(whole).not.toContain("tier=");
      expect(whole).not.toContain('"tier"');
      expect(whole).not.toContain("did:key:");
      expect(whole).not.toContain("zSECRETDID");
      expect(whole).not.toContain("sess-secret-1");
      expect(whole).not.toContain("exceeds limit");
      expect(whole).not.toContain("Signing frequency");
      // The matched-rule / gate_decision raw value never appears.
      expect(whole).not.toContain("gate_decision");
    }
  });

  it("(b) exports only the caller's own entries; fails closed without a binding", async () => {
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    await auditLog.append("l2", "state_read", "ag-mine", { decision: "allow" });
    await auditLog.append("l2", "state_write", "ag-theirs", { decision: "allow" });
    await new Promise((r) => setTimeout(r, 50));

    const mine = siemTool(auditLog, "ag-mine");
    const res = await mine.handler({ format: "cef" });
    const meta = JSON.parse(res.content[0].text);
    const body = res.content[1].text;
    expect(meta.count).toBe(1);
    expect(body).toContain("state_read");
    expect(body).not.toContain("state_write");

    // No binding → fail closed (export nothing).
    const { tools } = createSIEMTools(auditLog, () => undefined);
    const unbound = tools.find((x) => x.name === "audit_export_siem")!;
    const res2 = await unbound.handler({ format: "cef" });
    const meta2 = JSON.parse(res2.content[0].text);
    expect(meta2.count).toBe(0);
  });
});

describe("agent-audit-allowlist: router catch-all (MED-2 fail-closed errors)", () => {
  it("(e) returns a generic error + audit_ref to the agent and logs the full error operator-side", async () => {
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    const SECRET = "SECRET_INTERNAL_/etc/sanctuary/policy.yaml not found";
    const tools: ToolDefinition[] = [
      {
        name: "boom",
        description: "throws",
        tool_class: "read",
        inputSchema: { type: "object", properties: {} },
        handler: async () => {
          throw new Error(SECRET);
        },
      },
    ];
    const server = createServer(tools, {
      auditLog,
      currentAgentId: () => "ag-err",
    });
    const handler = (
      server as unknown as { _requestHandlers: Map<string, Function> }
    )._requestHandlers.get("tools/call")!;
    const res = await handler(
      { method: "tools/call" as const, params: { name: "boom", arguments: {} } },
      {}
    );
    const payload = JSON.parse(res.content[0].text);
    // Agent sees ONLY the generic shape — never the raw message.
    expect(payload.error).toBe("tool execution failed");
    expect(typeof payload.audit_ref).toBe("string");
    expect(payload.audit_ref).toMatch(/^audit:tool_error:/);
    expect(JSON.stringify(payload)).not.toContain(SECRET);
    expect(JSON.stringify(payload)).not.toContain("/etc/sanctuary");
    expect(res.isError).toBe(true);

    // Operator-side: the full error IS in the audit log under the same ref.
    await new Promise((r) => setTimeout(r, 50));
    const q = await auditLog.query({ limit: 50 });
    const logged = q.entries.find((e) => e.operation === "tool_error:boom");
    expect(logged).toBeDefined();
    expect(logged?.details?.error).toBe(SECRET);
    expect(logged?.details?.audit_ref).toBe(payload.audit_ref);
    expect(logged?.result).toBe("failure");
  });
});

describe("agent-audit-allowlist: STRUCTURE TRIPWIRE (regression guard)", () => {
  // The load-bearing durability guarantee: NO agent-facing audit path may emit a
  // raw `details` object or any field outside the fixed allowlist. Seed an entry
  // carrying a brand-new, never-before-seen operator-attribution key
  // ("future_operator_secret") plus a threshold `reason`, then drive EVERY
  // agent-facing surface and assert neither the key nor any non-allowlisted field
  // escapes. This is what catches a future leak introduced by adding a detail
  // key without touching a denylist.
  const FUTURE_KEY = "future_operator_secret";
  const FUTURE_VALUE = "v-must-never-leak-7f3a";
  const THRESHOLD = "Signing frequency (7/min) exceeds limit (5/min)";

  async function seedLeakyEntry(auditLog: AuditLog, owner: string) {
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: owner,
      result: "failure",
      details: {
        dest_host: "host.example", // allowlisted-searchable (agent-supplied), safe
        // Everything below must NEVER reach an agent surface:
        decision: "deny_once", // REMOVED from the search corpus 2026-06-16
        reason: THRESHOLD,
        tier: 2,
        rule_id: "deny-secret-rule",
        rule_id_matched: "deny-secret-rule-2",
        decision_provenance: "operator-policy-path",
        [FUTURE_KEY]: FUTURE_VALUE,
      },
    });
  }

  function assertNoLeak(serialized: string, opts: { searchable?: boolean } = {}) {
    expect(serialized).not.toContain(FUTURE_KEY);
    expect(serialized).not.toContain(FUTURE_VALUE);
    expect(serialized).not.toContain(THRESHOLD);
    expect(serialized).not.toContain("exceeds limit");
    expect(serialized).not.toContain("deny-secret-rule");
    expect(serialized).not.toContain("decision_provenance");
    expect(serialized).not.toContain("operator-policy-path");
    // The raw details object marker keys never appear (except the allowlisted
    // searchable ones, which only the search corpus may contain).
    if (!opts.searchable) {
      expect(serialized).not.toContain("dest_host");
      expect(serialized).not.toContain("deny_once");
    }
  }

  it("monitor_audit_log emits no raw details / non-allowlisted field", async () => {
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "allowlist-tripwire-monitor",
    });
    await withSessionIdentity("ag-tripwire", async () => {
      await seedLeakyEntry(auditLog, "ag-tripwire");
      const res = await callServerTool(server, "monitor_audit_log", { limit: 10 });
      const parsed = parse(res);
      const entry = parsed.entries.find(
        (e: { operation: string }) => e.operation === "egress_blocked"
      );
      expect(entry).toBeDefined();
      expect(Object.keys(entry).sort()).toEqual(ALLOWED_VIEW_KEYS);
      assertNoLeak(res.content[0]!.text);
    });
  });

  it("audit_export_siem (CEF + OCSF) emits no raw details / non-allowlisted field", async () => {
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    await seedLeakyEntry(auditLog, "ag-tripwire");
    await new Promise((r) => setTimeout(r, 50));
    const { tools } = createSIEMTools(auditLog, () => binding("ag-tripwire"));
    const tool = tools.find((x) => x.name === "audit_export_siem")!;
    for (const format of ["cef", "ocsf"] as const) {
      const res = await tool.handler({ format });
      const whole = res.content.map((c: { text: string }) => c.text).join("\n");
      assertNoLeak(whole);
    }
  });

  it("sanctuary_audit_search + sanctuary_events_read emit no raw details / non-allowlisted field (incl. a brand-new operator key)", async () => {
    // Drive the REAL cooperative tools end-to-end against a leaky entry whose
    // details include a brand-new, never-allowlisted operator key. phase2 covers
    // the known sensitive keys; this adds the FUTURE_KEY dimension to prove the
    // allowlist (not a denylist) is what keeps a NEW key from leaking.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const { StateStore } = await import("../../src/cognitive/state-store.js");
    const { createL1Tools } = await import("../../src/cognitive/tools.js");
    const { createAgentNativeCooperativeTools } = await import(
      "../../src/agent-native/cooperative-surface.js"
    );
    const { ApprovalProofStore } = await import(
      "../../src/agent-native/safety-base.js"
    );

    const stateStore = new StateStore(storage, masterKey);
    let active: ReturnType<typeof binding> | undefined;
    const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
      { currentSessionBinding: () => active }
    );
    await identityManager.load();
    const id = JSON.parse(
      (await l1Tools.find((t) => t.name === "identity_create")!.handler({
        label: "tw",
      })).content[0]!.text
    );
    active = binding(id.identity_id as string);
    const { tools: facadeTools } = createAgentNativeCooperativeTools({
      identityManager,
      namespaceRegistry,
      auditLog,
      currentSessionBinding: () => active,
      primitiveTools: l1Tools,
      storage,
      approvalProofStore: new ApprovalProofStore(),
    });

    // Seed a leaky entry OWNED by the active identity (so it is in own_signed
    // scope) carrying the brand-new operator key and a threshold reason.
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: active.identity_id,
      result: "failure",
      details: {
        decision: "deny_once",
        dest_host: "host.example",
        reason: THRESHOLD,
        tier: 2,
        rule_id: "deny-secret-rule",
        decision_provenance: "operator-policy-path",
        [FUTURE_KEY]: FUTURE_VALUE,
      },
    });

    const search = facadeTools.find((t) => t.name === "sanctuary_audit_search")!;

    // Discoverable by the non-sensitive operation name.
    const byOp = parse(
      await search.handler({ query: "egress_blocked", scope: "own_signed" })
    );
    expect((byOp.results as unknown[]).length).toBe(1);
    // Returned rows carry no details and none of the sensitive material.
    assertNoLeak(JSON.stringify(byOp.results));

    // A needle for the brand-new key, its value, the threshold, the rule id, or
    // the provenance must NOT differentially match (absent from the corpus).
    for (const probe of [
      FUTURE_KEY,
      FUTURE_VALUE,
      "exceeds limit",
      "deny-secret-rule",
      "operator-policy-path",
      "reason",
    ]) {
      const probed = parse(
        await search.handler({ query: probe, scope: "own_signed" })
      );
      expect(
        (probed.results as unknown[]).length,
        `probe "${probe}" must not match`
      ).toBe(0);
      assertNoLeak(JSON.stringify(probed.results));
    }

    // sanctuary_events_read: open a cursor and read; the redacted event carries
    // only top-level has_details, never raw details.
    const cursor = parse(
      await facadeTools
        .find((t) => t.name === "sanctuary_events_open_cursor")!
        .handler({ filter: { operation: "egress_blocked" } })
    ).cursor as string;
    const page = parse(
      await facadeTools
        .find((t) => t.name === "sanctuary_events_read")!
        .handler({ cursor })
    );
    for (const event of page.events as Array<Record<string, unknown>>) {
      expect(Object.keys(event).sort()).toEqual(ALLOWED_EVENT_KEYS);
      expect(typeof event.has_details).toBe("boolean");
      expect(event).not.toHaveProperty("summary");
      expect(event).not.toHaveProperty("layer");
      expect(event).not.toHaveProperty("identity_match");
    }
    assertNoLeak(JSON.stringify(page.events));
  });

  it("broker/audit_query (the 5th agent-facing audit surface) emits no raw details / secret name / scope / reason", async () => {
    // The broker MCP surface is agent-facing: a harnessed agent calls
    // broker/audit_query. Its underlying details carry the credential NAME, the
    // granted/requested scope, the ttl, the `scope_exceeds_grant` reason, and the
    // tenant/audience claims — none of which may cross to the agent. Drive the
    // REAL broker MCP tool against denied+issued activity and assert the
    // allowlist view, not the raw details.
    const store = new Map<string, string>([["gmail_oauth", "SECRET-VALUE-XYZ"]]);
    const backend: Backend = {
      async ensureInitialized() {},
      async unlock() {},
      async isUnlocked() {
        return true;
      },
      async addSecret(n, v) {
        if (store.has(n)) throw new Error("exists");
        store.set(n, v);
      },
      async readSecret(n) {
        const v = store.get(n);
        if (v === undefined) throw new SecretNotFoundError(n);
        return v;
      },
      async rotateSecret(n, v) {
        if (!store.has(n)) throw new SecretNotFoundError(n);
        store.set(n, v);
      },
      async deleteSecret(n) {
        if (!store.delete(n)) throw new SecretNotFoundError(n);
      },
      async listSecretNames() {
        return Array.from(store.keys());
      },
    };
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    const broker = new Broker({
      backend,
      auditLog,
      grants: [{ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" }],
      principalIdentityId: "did:sanctuary:1",
    });
    const server = createBrokerMcpServer(broker, {
      skill: "gmail-triage",
      agentId: "nsa",
      identityId: "did:sanctuary:1",
      tenantId: "tenant-alpha",
      fortressId: "fortress-alpha",
      audience: "sanctuary-broker",
    });
    const handler = (
      server as unknown as { _requestHandlers: Map<string, Function> }
    )._requestHandlers.get("tools/call")!;
    const call = (name: string, a: Record<string, unknown> = {}) =>
      handler({ method: "tools/call" as const, params: { name, arguments: a } }, {});

    const issue = parse(await call("broker/request_token", { skill: "gmail-triage", secret: "gmail_oauth" }));
    await call("broker/read_secret", { token: issue.token });
    // Over-scope → TOKEN_DENIED with reason "scope_exceeds_grant" + granted_scope.
    await call("broker/request_token", { skill: "gmail-triage", secret: "gmail_oauth", scope: "rotate" });

    const body = parse(await call("broker/audit_query", {}));
    // Surfaced ops, but every entry is the fixed allowlist view.
    expect(body.entries.length).toBeGreaterThan(0);
    for (const e of body.entries) {
      expect(Object.keys(e).sort()).toEqual(ALLOWED_VIEW_KEYS);
      expect(e.details).toBeUndefined();
    }
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain("SECRET-VALUE-XYZ");
    expect(serialized).not.toContain("gmail_oauth"); // the credential NAME
    expect(serialized).not.toContain("granted_scope");
    expect(serialized).not.toContain("scope_exceeds_grant");
    expect(serialized).not.toContain("ttl_seconds");
    expect(serialized).not.toContain("tenant-alpha");
    expect(serialized).not.toContain("sanctuary-broker"); // audience
    // The operator path still has the full reason (defence-in-depth: redaction
    // is at the agent boundary, the persisted entry is unchanged).
    const opQ = await auditLog.query({ operation_type: BROKER_OPS.TOKEN_DENIED, layer: "l3" });
    expect(opQ.entries[0]?.details?.reason).toBe("scope_exceeds_grant");
  });
});

describe("agent-audit-allowlist: HIGH — decision-granularity search oracle (all 5 values)", () => {
  // Property #11 attack: the persisted `decision` is fine-grained (the 5 values
  // an operator policy can yield — castle-wall/ipc/messages.ts). When it was in
  // the search corpus, a cooperative agent could probe each value and read
  // WHICH disposition fired off the differential `result_count`. With `decision`
  // removed from the corpus, a probe for ANY of the 5 values yields zero matches
  // for EVERY value — no differential oracle — even though all entries remain
  // discoverable by their (non-sensitive) operation name.
  const DECISION_VALUES = [
    "allow_once",
    "allow_always",
    "deny_once",
    "deny_always",
    "timeout_default_deny",
  ] as const;

  async function cooperativeSearchHarness() {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const { StateStore } = await import("../../src/cognitive/state-store.js");
    const { createL1Tools } = await import("../../src/cognitive/tools.js");
    const { createAgentNativeCooperativeTools } = await import(
      "../../src/agent-native/cooperative-surface.js"
    );
    const { ApprovalProofStore } = await import(
      "../../src/agent-native/safety-base.js"
    );
    const stateStore = new StateStore(storage, masterKey);
    let active: ReturnType<typeof binding> | undefined;
    const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
      { currentSessionBinding: () => active }
    );
    await identityManager.load();
    const id = JSON.parse(
      (await l1Tools.find((t) => t.name === "identity_create")!.handler({
        label: "dec",
      })).content[0]!.text
    );
    active = binding(id.identity_id as string);
    const { tools: facadeTools } = createAgentNativeCooperativeTools({
      identityManager,
      namespaceRegistry,
      auditLog,
      currentSessionBinding: () => active,
      primitiveTools: l1Tools,
      storage,
      approvalProofStore: new ApprovalProofStore(),
    });
    return { auditLog, facadeTools, active };
  }

  it("a probe for ANY of the 5 decision values yields no differential result_count match", async () => {
    const { auditLog, facadeTools, active } = await cooperativeSearchHarness();

    // Seed one own-signed entry per decision value under a stable operation
    // name. Each entry's `decision` differs; nothing else policy-sensitive.
    for (const value of DECISION_VALUES) {
      await auditLog.appendCritical({
        layer: "l1",
        operation: "egress_blocked",
        identity_id: active!.identity_id,
        result: value.startsWith("deny") || value.startsWith("timeout") ? "failure" : "success",
        details: { decision: value, dest_host: "host.example" },
      });
    }

    const search = facadeTools.find((t) => t.name === "sanctuary_audit_search")!;

    // Baseline: all entries ARE discoverable by the non-sensitive op name.
    const byOp = parse(
      await search.handler({ query: "egress_blocked", scope: "own_signed" })
    );
    expect((byOp.results as unknown[]).length).toBe(DECISION_VALUES.length);

    // The oracle attack: probing each of the 5 decision values must return the
    // SAME result_count (zero) — no value differentially matches, so the agent
    // cannot learn which disposition any entry carries.
    const counts: number[] = [];
    for (const value of DECISION_VALUES) {
      const probed = parse(
        await search.handler({ query: value, scope: "own_signed" })
      );
      const n = (probed.results as unknown[]).length;
      expect(n, `probe "${value}" must not differentially match`).toBe(0);
      // And no decision value leaks into the returned rows.
      expect(JSON.stringify(probed.results)).not.toContain(value);
      counts.push(n);
    }
    // No differential across the 5 probes.
    expect(new Set(counts).size).toBe(1);
    expect(counts.every((c) => c === 0)).toBe(true);

    // A substring shared by 4 of the 5 values ("allow"/"deny") must also not
    // differentially match — the corpus carries none of them.
    for (const frag of ["allow", "deny", "timeout_default_deny"]) {
      const probed = parse(
        await search.handler({ query: frag, scope: "own_signed" })
      );
      expect(
        (probed.results as unknown[]).length,
        `fragment "${frag}" must not match via decision`
      ).toBe(0);
    }
  });
});

// ── COMPREHENSIVE structural guard ──────────────────────────────────────────
// The behavioral tripwire above proves the FIVE known agent-facing audit reads
// are clean. This guard makes the durability claim COMPREHENSIVE: it pins the
// exhaustive registry of agent-facing audit-read surfaces and asserts each one's
// source routes its audit output through the allowlist (redactAuditEntryForAgent
// / AgentAuditView) and never returns a raw audit-`details` object on its
// agent-facing path. A NEW agent-facing audit read that bypasses the allowlist —
// or a regression that re-introduces a raw-details return into one of these
// files — turns this RED. The operator-only audit consumers (anomaly detectors,
// sentinels, dashboard, CLI, compliance, posture/feature-health) legitimately
// see full fidelity and are deliberately NOT in this set.
describe("agent-audit-allowlist: STRUCTURE TRIPWIRE (comprehensive — agent-facing audit-read registry)", () => {
  const SERVER_SRC = join(
    fileURLToPath(import.meta.url),
    "..",
    "..",
    "..",
    "src"
  );
  const read = (rel: string) => readFileSync(join(SERVER_SRC, rel), "utf8");

  // The EXHAUSTIVE set of source modules that expose an audit READ to an
  // agent-facing boundary (an MCP tool an agent can call). Adding a new one is a
  // CONSCIOUS, reviewed act: it must be added here AND route through the
  // allowlist, or this guard reds.
  const AGENT_FACING_AUDIT_READ_MODULES = [
    "index.ts", // monitor_audit_log
    "audit/siem-tools.ts", // audit_export_siem
    "agent-native/cooperative-surface.ts", // sanctuary_audit_search / sanctuary_events_read
    "disclosure/broker/broker.ts", // broker/audit_query (queryAudit)
  ] as const;

  // Agent-callable MCP tools that DO read the audit log but never surface audit
  // ENTRIES (or their `details`) to the agent — so there is nothing to redact.
  // They are agent-facing (NOT operator/internal), pinned here and guarded below
  // (must copy no raw `details`) so that a future edit which starts returning
  // entries from one of them turns RED instead of silently leaking.
  //   audit/tools.ts — `sovereignty_audit` queries with { limit: 0 } and reads
  //     only result.integrity_findings (audit-chain health); no entries.
  //   shr/tools.ts   — `shr_generate` (gatherReputationEvidence) derives a single
  //     boolean (verascore_linked) from a reputation_publish probe; no entries
  //     are returned.
  const AGENT_FACING_NON_ENTRY_AUDIT_READS = [
    "audit/tools.ts",
    "shr/tools.ts",
  ] as const;

  // Operator / internal / principal audit reads that legitimately see FULL
  // fidelity (the deciding rule, the tier, the reason). NONE is reachable by an
  // agent calling an MCP tool: they are internal analyzers, CLI commands, the
  // human operator's HTTP dashboard/hub routes, cross-agent coordination
  // internals, or the principal's own Tier-1-approval-gated Exit export. Per the
  // agent-audit-redaction.ts header they MUST NOT use the agent redaction. Listed
  // explicitly so that adding a NEW audit reader forces a conscious classification
  // (asserted by the auto-discovery closure test below).
  const OPERATOR_INTERNAL_AUDIT_READS = [
    // anomaly detection — internal scoring over the audit stream
    "anomaly-detection/detectors/audit-event-class-distribution-detector.ts",
    "anomaly-detection/feature-extractors/audit-event-class-distribution.ts",
    "anomaly-detection/feature-extractors/credential-use-sequence.ts",
    "anomaly-detection/feature-extractors/cross-agent-timing.ts",
    "anomaly-detection/feature-extractors/per-agent-activity.ts",
    "anomaly-detection/feature-extractors/time-of-day-activity.ts",
    "anomaly-detection/feature-extractors/tool-call-sequence.ts",
    // sentinels — internal background watchers
    "sentinel/sentinels/agent-egress-watcher.ts",
    "sentinel/sentinels/credential-usage-watcher.ts",
    "sentinel/sentinels/cross-agent-chatter-watcher.ts",
    "sentinel/sentinels/egress-volume-watcher.ts",
    "sentinel/sentinels/suspicious-tool-call-detector.ts",
    // operator dashboards / hub / activity feed — human-facing HTTP surfaces
    "dashboard/aggregator.ts",
    "dashboard/v1_1/wiring.ts",
    "hub/activity-feed.ts",
    "principal-policy/dashboard.ts",
    "principal-policy/approval-aggregator.ts",
    "principal-policy/feature-health.ts",
    "principal-policy/posture.ts",
    "principal-policy/unified-inbox-producers.ts",
    // operator CLI
    // NOTE (observe-fold idempotency chokepoint, 2026-07-14): cli/castle-wall-observe.ts
    // no longer uses auditLog.query at all -- runObserveCandidates now folds via
    // castle-wall/observe/refresh.ts over streamVerifiedChain (window-independent,
    // strict-verified, watermark-incremental), which is not one of the query sites
    // this tripwire discovers, so it needs no row here.
    "cli/audit.ts",
    "cli/castle-wall.ts",
    "wrap/cli.ts",
    // compliance report generation — operator artifact
    "compliance/eu_ai_act/generator.ts",
    // law-firm evidence pack — operator artifact. The CLI reads the full audit
    // history to COUNT quarter activity; only aggregate counts/categories/
    // timestamps are emitted into the pack, never raw entry `details`.
    "evidence-pack/cli.ts",
    // operator chat context / concierge — human operator surface
    "chat/agent-context-cache.ts",
    "concierge/sanctuary-context-reader.ts",
    // cross-agent coordination handoff log — internal
    "coordination/handoff-log.ts",
    // query-anonymity routes — operator analytics
    "query-anonymity/query-anonymity-routes.ts",
    // posture routes — operator/principal Evidence View (Phase 2 section 2.5):
    // the filterable audit-entry table at /api/posture/evidence.  Full-fidelity
    // read behind the SAME checkAuth gate as /api/audit-log; never agent-facing.
    "principal-policy/posture-routes.ts",
    // principal Exit bundle — full-fidelity receipts, Tier-1 approval-gated
    "exit/bundle.ts",
  ] as const;

  // ── AUTO-DISCOVERY ──────────────────────────────────────────────────────
  // Statically enumerate EVERY `(<receiver>.)auditLog.query(...)` call site
  // under src/ with the TypeScript parser. This is the load-bearing inversion
  // the codex #573 review asked for: the agent-facing registry is no longer the
  // sole defence. A brand-new agent-facing audit-read tool added in a NEW file
  // is auto-discovered here and must be consciously CLASSIFIED — it can no longer
  // slip past review just by not being added to a hand-maintained list.
  //
  // No type-checker is needed: every audit read in the tree uses the `auditLog`
  // receiver name (the codebase convention), so a syntactic match on
  // `<ident|...>.query(...)` where the receiver's terminal name is `auditLog`
  // captures them all while correctly NOT matching the unrelated `.query(`
  // receivers — pgvector `client.query`, `reputationStore.query`,
  // `handoffLog.query`, the `auditPreflight` connectivity probe, or the broker's
  // own `broker.queryAudit` facade (whose underlying read lives in broker.ts and
  // IS matched there).
  function discoverAuditLogReaders(): string[] {
    const found = new Set<string>();
    const isAuditLogReceiver = (expr: ts.Expression): boolean => {
      if (ts.isIdentifier(expr)) return expr.text === "auditLog";
      if (ts.isPropertyAccessExpression(expr)) return expr.name.text === "auditLog";
      return false;
    };
    const walkDir = (dir: string) => {
      // withFileTypes: the dir/file decision comes from the directory listing
      // itself (the Dirent), not a separate statSync(p), so there is no
      // check-then-use (TOCTOU) gap on p between the type check and the read.
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const name = entry.name;
        const p = join(dir, name);
        if (entry.isDirectory()) {
          if (name === "node_modules") continue;
          walkDir(p);
          continue;
        }
        if (!name.endsWith(".ts") || name.endsWith(".d.ts") || name.endsWith(".test.ts")) {
          continue;
        }
        let source: string;
        try {
          source = readFileSync(p, "utf8");
        } catch {
          continue; // file vanished mid-walk: skip, don't crash
        }
        const sf = ts.createSourceFile(
          p,
          source,
          ts.ScriptTarget.Latest,
          /*setParentNodes*/ false
        );
        const visit = (node: ts.Node) => {
          if (
            ts.isCallExpression(node) &&
            ts.isPropertyAccessExpression(node.expression) &&
            node.expression.name.text === "query" &&
            isAuditLogReceiver(node.expression.expression)
          ) {
            found.add(relative(SERVER_SRC, p).split(sep).join("/"));
          }
          ts.forEachChild(node, visit);
        };
        visit(sf);
      }
    };
    walkDir(SERVER_SRC);
    return [...found].sort();
  }

  // ══════════════════════════════════════════════════════════════════════════
  // EAGER-POSTURE READ CHOKEPOINT (v2, INVERTED to default-eager)
  // ══════════════════════════════════════════════════════════════════════════
  //
  // PROBLEM (the recurring defect): an OPERATOR audit read that re-verifies the
  // whole tamper-evident chain from disk on every call. On a real long-lived
  // fortress (10k entries / 40MB) that is 11-30s and pegs the event loop (the
  // #714 wedge); the SSE board made it continuous. #717/#719/#721 fixed the
  // posture composition by serving from the audit log's eagerly-maintained
  // verified view (an `runEagerReads`/`queryEager` scope: O(1), STILL honest via
  // the fingerprint sentinel + 30s backstop). But that fix is OPT-IN per call
  // site, so the SAME defect recurred three times in three code paths.
  //
  // WHY v1 (PR #722) was NOT enough (the 4 evasions a deep review slipped past
  // it, recorded on #722): a new operator-posture read could (H1) live in a
  // module that simply isn't in the hand-picked posture sub-bucket, or (H2) be a
  // bare read in another operator module (e.g. dashboard/v1_1/wiring.ts) that the
  // narrow bucket never scanned; (H3) be an ALIASED receiver `const x = auditLog;
  // x.query()` the receiver matcher missed; (H4) drop the eager wrap on ONE of a
  // builder's callers while another caller still wraps it (v1's caller-wraps
  // proof only checked the builder NAME appeared in SOME eager call, anywhere);
  // and (M1) hide behind a one-line escape with no real reason / arbitrary kind.
  //
  // THE INVERSION (v2): the scope is now EVERY operator audit read in the tree,
  // not a hand-picked posture list. Default = eager. A non-eager operator read is
  // permitted ONLY with an explicit, ENUMERATED escape (a `kind` from a fixed
  // enum + a real reason), keyed by `module:fn`. There is no silent "pick the
  // no-eager bucket": a brand-new bare operator read in ANY module — including a
  // new module — REDS until it is either eager-wrapped or consciously escaped.
  // This closes H1/H2 (scope is all operator reads), H3 (best-effort local-alias
  // tracking, residual documented), H4 (WHOLE-TREE per-CALL-SITE caller-wraps
  // proof: discover EVERY call site of EVERY caller-wrapped builder across ALL
  // src modules — not a hard-coded entry-point list — so dropping the wrap on ONE
  // caller, OR calling a builder bare from a NEW/4th module, reds; a deliberately
  // per-request standalone builder call needs a conscious BARE_BUILDER_CALL_ESCAPE),
  // and M1 (enum kind + non-empty reason + stale-escape guard).
  //
  // HONESTY BOUNDARY (preserved, structurally): the inverted scope is the
  // OPERATOR universe = (every src module with a direct OR aliased auditLog.query
  // read) MINUS the agent-facing buckets (AGENT_FACING_AUDIT_READ_MODULES +
  // AGENT_FACING_NON_ENTRY_AUDIT_READS). Agent-facing reads are therefore NEVER
  // in scope and are NEVER asked to be eager: they keep their per-request,
  // fully-re-verified on-disk tamper detection. A disjointness guard pins this.
  //
  // WHAT THIS CHOKEPOINT DOES AND DOES NOT CLAIM (no overclaim — the v1 lesson):
  //   DOES: force every NEW operator audit read (any module, including a brand-new
  //     one; direct or same-file-aliased) to be EITHER eager-scoped OR a conscious
  //     enumerated escape; catch a dropped eager wrap on any directly-named builder
  //     call anywhere in the tree (incl. a bare builder call from a brand-new
  //     module, not just the three former hard-coded entry-point modules; the
  //     lexical-alias caveat is in the H3 RESIDUAL below); keep the
  //     registry honest (enum kind + real reason + no stale escapes);
  //     keep the agent-facing honesty boundary disjoint; and surface (not bless)
  //     the known HOT read backlog.
  //   DOES NOT: prove the eager READ PATH is itself correct/fast (that is the
  //     audit-log unit tests for queryEager/runEagerReads, not this structural
  //     guard); decide WHICH non-eager reads are acceptable (a human reviews the
  //     escape `kind`+`reason`); or close the FULL alias surface — see the H3
  //     RESIDUAL below. It governs WHERE a read runs, not the verification
  //     contract, and it is structural, so a same-PR escape+source change is
  //     caught by REVIEW, not mechanically (same boundary as every ratchet here).
  //   H3 RESIDUAL (documented, deliberately not closed): same-file
  //     `const x = auditLog; x.query()` IS tracked (best-effort, lexical). NOT
  //     tracked without the TS type checker: cross-file / cross-function aliases,
  //     a param typed AuditLog passed under a new name, a let-reassigned alias, a
  //     destructured `{ query } = auditLog`. The SAME lexical limit applies to the
  //     builder-call axis (H4): a builder invoked under a lexical alias or
  //     import-rename (`const f = buildAuditDigest; f()` or
  //     `import { buildAuditDigest as d }; d()`) is NOT caught, for the same reason.
  //     Honesty over completeness: we take the cheap heuristic and surface the gap
  //     rather than build a type resolver.

  type EagerEscapeKind =
    // Posture shaper whose internal `query` runs inside the entry point's
    // `runEagerReads` AsyncLocalStorage scope (opened one frame up, invisible to
    // a lexical check). REQUIRES the per-call-site caller-wraps proof below.
    | "caller-wrapped-builder"
    // One-shot full read: CLI command, Exit bundle, compliance report. Runs once
    // per invocation, never on the SSE/board hot path; the eager view (kept warm
    // across many reads) is the wrong lever — these WANT a single full re-verify.
    | "operator-batch"
    // Internal background analyzer / sentinel scoring over the audit stream. Runs
    // on its own scheduler, full-fidelity by design; the eager warm view is not
    // the relevant cost lever (and these are the redaction-exempt internals).
    | "operator-background"
    // Deliberately per-request operator request-path read where honest immediate
    // on-disk tamper detection is the chosen contract (an inspectable listing,
    // or a low-frequency human-paced concierge fetch). NOT the SSE hot path.
    | "operator-per-request"
    // AGENT-facing read that lives on an otherwise-operator module: the honesty
    // boundary. MUST stay per-request fully re-verified; NEVER pushed to eager.
    | "agent-facing-per-request"
    // KNOWN HOT operator read flagged HIGH for separate triage: a recurring /
    // timer-driven / SSE-cadence full-chain re-verify that genuinely SHOULD be
    // eager but whose fix is a PRODUCT behavior change out of scope for this
    // test-infra-only build. The escape does NOT claim the read is fine — it
    // records the wedge HONESTLY and points at the triage. The chokepoint counts
    // these (a non-empty set is a standing alarm), and the build that makes them
    // eager removes the escape (the stale-escape guard then forces the cleanup).
    | "operator-hot-pending-triage";

  const EAGER_ESCAPE_KINDS: readonly EagerEscapeKind[] = [
    "caller-wrapped-builder",
    "operator-batch",
    "operator-background",
    "operator-per-request",
    "agent-facing-per-request",
    "operator-hot-pending-triage",
  ] as const;

  // CONSCIOUS PER-CALL ESCAPE REGISTRY. An operator-universe `auditLog.query`
  // (or aliased read) that is NOT lexically eager-contained is permitted ONLY if
  // its enclosing function is registered here with a kind + reason. This makes "I
  // chose NOT to be eager" a reviewed, named act. A NEW bare operator read whose
  // function is absent here REDS the build — the chokepoint. Keyed by module:fn
  // (stable across line drift). M1 is closed by: kind ∈ EAGER_ESCAPE_KINDS,
  // reason non-trivial, and the stale-escape guard (every escape must match a
  // real, currently-non-eager site).
  const EAGER_QUERY_ESCAPES: ReadonlyArray<{
    module: string;
    fn: string;
    kind: EagerEscapeKind;
    reason: string;
  }> = [
    // ── caller-wrapped posture builders ────────────────────────────────────
    // Their internal `query` runs inside the entry point's runEagerReads scope.
    // The per-call-site caller-wraps proof below ties EACH to a real entry point
    // that wraps the builder DIRECTLY (drop the wrap on one caller → reds).
    {
      module: "principal-policy/posture.ts",
      fn: "buildCastleWallPosture",
      kind: "caller-wrapped-builder",
      reason:
        "arm-state shaper; entry points posture-routes buildWallPosture, dashboard buildStatusCastleWall, and the aggregator hero shield each open the eager scope directly around the call.",
    },
    {
      module: "principal-policy/posture.ts",
      fn: "buildAuditDigest",
      kind: "caller-wrapped-builder",
      reason:
        "audit-digest shaper; posture-routes buildDigest opens the eager scope directly around the call.",
    },
    {
      module: "principal-policy/posture.ts",
      fn: "buildCustodyExitPanel",
      kind: "caller-wrapped-builder",
      reason:
        "custody-exit shaper; posture-routes buildCustodyExit opens the eager scope directly around the call.",
    },
    {
      module: "principal-policy/posture.ts",
      fn: "buildRecognitionPanel",
      kind: "caller-wrapped-builder",
      reason:
        "recognition shaper; posture-routes buildRecognition opens the eager scope directly around the call.",
    },
    {
      module: "principal-policy/feature-health.ts",
      fn: "buildFeatureHealthPanel",
      kind: "caller-wrapped-builder",
      reason:
        "feature-health shaper; posture-routes buildFeatureHealth opens the eager scope directly around the call.",
    },
    {
      module: "query-anonymity/query-anonymity-routes.ts",
      fn: "computeQueryAnonymityStats",
      kind: "caller-wrapped-builder",
      reason:
        "query-privacy stats shaper; posture-routes buildQueryPrivacy opens the eager scope directly around the call.",
    },
    // ── operator-batch: one-shot full reads, never the hot path ─────────────
    {
      module: "cli/audit.ts",
      fn: "runAuditCommand",
      kind: "operator-batch",
      reason:
        "operator CLI `audit` command: a single MAX_SAFE_INTEGER full dump per invocation; one full re-verify is the desired honest behavior, not a warm view.",
    },
    {
      module: "cli/castle-wall.ts",
      fn: "runAuditDump",
      kind: "operator-batch",
      reason:
        "operator CLI castle-wall audit dump: one-shot full read per invocation; wants a single full re-verify.",
    },
    // NOTE (observe-fold idempotency chokepoint, 2026-07-14): runObserveCandidates
    // (cli/castle-wall-observe.ts) no longer has an auditLog.query site -- the fold
    // now streams the WHOLE verified chain via streamVerifiedChain (one-shot,
    // strict full re-verify per invocation, watermark-incremental fold; see
    // castle-wall/observe/refresh.ts), which this query-site tripwire does not
    // discover, so it needs no escape row.
    {
      module: "cli/castle-wall.ts",
      fn: "runAuditVerify",
      kind: "operator-batch",
      reason:
        "operator CLI castle-wall audit-verify (Slice M reader leg): one-shot full read per invocation that re-verifies every enforcement entry's producer signature; a single full re-verify across all entries IS the desired tamper-evidence behavior, never a warm/eager hot-path view.",
    },
    {
      module: "exit/bundle.ts",
      fn: "exportAuditReceipts",
      kind: "operator-batch",
      reason:
        "principal Exit bundle (Tier-1 approval-gated): flush()+full read of up to 100k receipts, once at export; a full re-verify is the integrity contract.",
    },
    {
      module: "compliance/eu_ai_act/generator.ts",
      fn: "computeAuditPeriodSummary",
      kind: "operator-batch",
      reason:
        "EU AI Act report generator: effectively-unbounded period read, run once when generating the operator compliance artifact; one full re-verify is desired.",
    },
    {
      module: "evidence-pack/cli.ts",
      fn: "runEvidencePack",
      kind: "operator-batch",
      reason:
        "law-firm evidence pack CLI: one full retained-history read per invocation to aggregate a calendar quarter; one full re-verify is the desired honest behavior, not a warm view, and only aggregate counts leave the generator.",
    },
    // ── operator-background: internal analyzers / sentinels on own schedule ──
    {
      module: "anomaly-detection/detectors/audit-event-class-distribution-detector.ts",
      fn: "primeBaselineFromHistory",
      kind: "operator-background",
      reason:
        "anomaly-detection baseline prime: a one-time large history read on detector init; internal scoring, not the board hot path.",
    },
    {
      module: "anomaly-detection/feature-extractors/audit-event-class-distribution.ts",
      fn: "extractAuditEventClassDistributions",
      kind: "operator-background",
      reason:
        "anomaly feature extractor: windowed read on the anomaly pipeline's own evaluation cadence; internal full-fidelity scoring, not the SSE board.",
    },
    {
      module: "anomaly-detection/feature-extractors/credential-use-sequence.ts",
      fn: "extractCredentialUseSequence",
      kind: "operator-background",
      reason:
        "anomaly feature extractor: windowed read on the anomaly pipeline cadence; internal scoring, not the SSE board.",
    },
    {
      module: "anomaly-detection/feature-extractors/cross-agent-timing.ts",
      fn: "extractCrossAgentTiming",
      kind: "operator-background",
      reason:
        "anomaly feature extractor: windowed read on the anomaly pipeline cadence; internal scoring, not the SSE board.",
    },
    {
      module: "anomaly-detection/feature-extractors/per-agent-activity.ts",
      fn: "extractPerAgentActivity",
      kind: "operator-background",
      reason:
        "anomaly feature extractor: windowed read on the anomaly pipeline cadence; internal scoring, not the SSE board.",
    },
    {
      module: "anomaly-detection/feature-extractors/time-of-day-activity.ts",
      fn: "extractTimeOfDayActivity",
      kind: "operator-background",
      reason:
        "anomaly feature extractor: windowed read on the anomaly pipeline cadence; internal scoring, not the SSE board.",
    },
    {
      module: "anomaly-detection/feature-extractors/tool-call-sequence.ts",
      fn: "extractToolCallSequence",
      kind: "operator-background",
      reason:
        "anomaly feature extractor: windowed read on the anomaly pipeline cadence; internal scoring, not the SSE board.",
    },
    {
      module: "sentinel/sentinels/agent-egress-watcher.ts",
      fn: "evaluate",
      kind: "operator-background",
      reason:
        "sentinel background watcher (confined-agent egress MED-3): windowed l1 read of egress denials + probe failures on its own cadence; internal scoring, not the SSE board.",
    },
    {
      module: "sentinel/sentinels/credential-usage-watcher.ts",
      fn: "evaluate",
      kind: "operator-background",
      reason:
        "sentinel background watcher: windowed l3 read on its own evaluation cadence; internal full-fidelity scoring, not the SSE board.",
    },
    {
      module: "sentinel/sentinels/cross-agent-chatter-watcher.ts",
      fn: "evaluate",
      kind: "operator-background",
      reason:
        "sentinel background watcher: windowed read on its own cadence; internal scoring.",
    },
    {
      module: "sentinel/sentinels/egress-volume-watcher.ts",
      fn: "evaluate",
      kind: "operator-background",
      reason:
        "sentinel background watcher: windowed read on its own cadence; internal scoring.",
    },
    {
      module: "sentinel/sentinels/suspicious-tool-call-detector.ts",
      fn: "evaluate",
      kind: "operator-background",
      reason:
        "sentinel background watcher: windowed read on its own cadence; internal scoring.",
    },
    // NOTE (F1 anti-rollback §8.6 round 2): dashboard.deriveGuardianFloorFromAudit
    // does NOT use auditLog.query at all. It reads the WHOLE verified chain via
    // streamVerifiedChain (window-independent per §8.6 P0), which is not one of
    // the query sites this tripwire discovers, so it needs no query-escape row.
    // ── operator-per-request: deliberately per-request operator reads ───────
    {
      module: "principal-policy/dashboard.ts",
      fn: "handleAuditLog",
      kind: "operator-per-request",
      reason:
        "legacy /api/audit-log raw JSON listing: an inspectable surface kept per-request by design (honest immediate on-disk tamper detection, like /api/posture/evidence). NOT the SSE hot path. Erik-confirmable.",
    },
    {
      module: "principal-policy/approval-aggregator.ts",
      fn: "getAuditTrail",
      kind: "operator-per-request",
      reason:
        "operator approval-aggregator trail lookup: bounded (limit 1000) since-windowed read on the human-paced approval-inbox request path; not the SSE board cadence.",
    },
    {
      module: "principal-policy/unified-inbox-producers.ts",
      fn: "aggregateRhoDailyPrivacyEvents",
      kind: "operator-per-request",
      reason:
        "unified-inbox producer: a 24h-windowed operator inbox projection on the inbox request path; bounded and human-paced, not the SSE board.",
    },
    {
      module: "principal-policy/unified-inbox-producers.ts",
      fn: "ingestWrappedAgentErrors",
      kind: "operator-per-request",
      reason:
        "unified-inbox producer: bounded operator inbox projection on the inbox request path; human-paced, not the SSE board.",
    },
    {
      module: "hub/activity-feed.ts",
      fn: "aggregateActivity",
      kind: "operator-per-request",
      reason:
        "operator activity-feed: per-message, identity-filtered projection on the hub request path (limit*4 bounded). Bursty but NOT the 5s SSE posture cadence; per-request honest on-disk tamper detection is the safe default.",
    },
    {
      module: "concierge/sanctuary-context-reader.ts",
      fn: "readAuditLog",
      kind: "operator-per-request",
      reason:
        "operator concierge context reader: a bounded since/operation-filtered read on the human-paced concierge request path; not the SSE board.",
    },
    {
      module: "coordination/handoff-log.ts",
      fn: "query",
      kind: "operator-per-request",
      reason:
        "operator coordination handoff list/snapshot read on the /api/coordination/handoffs request + stream-connect path (SSE deltas push via the event bridge, not this poll); request/connect-paced, honest on-disk re-verify is the default.",
    },
    {
      module: "coordination/handoff-log.ts",
      fn: "getEntry",
      kind: "operator-per-request",
      reason:
        "operator coordination handoff single-entry detail lookup on the request path; honest on-disk re-verify per request is the default, not the SSE board.",
    },
    {
      module: "dashboard/v1_1/wiring.ts",
      fn: "buildConciergeContextProviders",
      kind: "operator-per-request",
      reason:
        "operator concierge context provider (recentActivity, limit 30): fires when the human operator sends a concierge chat message; bounded + human-paced, not the SSE board.",
    },
    {
      module: "dashboard/v1_1/wiring.ts",
      fn: "buildConciergeContextFetchers",
      kind: "operator-per-request",
      reason:
        "operator concierge context fetchers (agent_activity limit 50 / audit_log limit 30 / recent_receipts limit 100): fire on a human operator concierge chat turn; bounded + human-paced, not the SSE board.",
    },
    // ── operator-hot-pending-triage: KNOWN WEDGE, flagged HIGH ──────────────
    // Surfaced by the v2 inversion (v1's narrow posture bucket never scanned it).
    // This is a RECURRING timer-driven full-chain re-verify — the exact #714
    // wedge class — that genuinely SHOULD be eager. Making it eager is a PRODUCT
    // change (out of scope for this test-infra-only build), so it is escaped
    // HONESTLY here and flagged HIGH for separate triage, NOT blessed as benign.
    {
      module: "chat/agent-context-cache.ts",
      fn: "refresh",
      kind: "operator-hot-pending-triage",
      reason:
        "HIGH/TRIAGE: AgentContextCache.refresh() runs on a 60s setInterval (DEFAULT_REFRESH_CADENCE_MS) and does a full-chain re-verify (query since/limit 500) every cycle — a recurring #714-class wedge on a 10k/40MB chain. Should move to the eager view; deferred as a product change (this build is test-infra only). Tracked by this escape so the inversion does not silently green it.",
    },
    // ── agent-facing-per-request: the honesty boundary (NEVER eager) ────────
    {
      module: "principal-policy/posture-routes.ts",
      fn: "buildEvidence",
      kind: "agent-facing-per-request",
      reason:
        "/api/posture/evidence inspectable audit surface: per-request on-disk tamper detection is the honesty contract; must NEVER be pushed into eager mode.",
    },
  ];

  // CONSCIOUS BARE-BUILDER-CALL ESCAPE REGISTRY (the H4 axis).
  // A `caller-wrapped-builder` claims its OWN internal `auditLog.query` runs
  // inside the eager scope its CALLER opens. The H4 proof below discovers EVERY
  // call site of every such builder across the WHOLE tree (not a hard-coded
  // entry-point list) and requires each call to be lexically inside an
  // `runEagerReads`/`queryEager` scope. A builder call that is DELIBERATELY
  // per-request (a standalone, low-frequency, human-paced operator endpoint that
  // is NOT on the SSE board cadence) is permitted ONLY if its enclosing function
  // is registered here with a kind + reason — the SAME conscious-named-act
  // discipline as EAGER_QUERY_ESCAPES, but on the builder-CALL-site axis rather
  // than the query-site axis. A NEW bare builder call whose enclosing function is
  // absent here REDS — including a brand-new builder call in a brand-new module.
  // Keyed by module:fn (the ENCLOSING function of the bare builder call).
  const BARE_BUILDER_CALL_ESCAPES: ReadonlyArray<{
    module: string;
    fn: string;
    builder: string;
    kind: EagerEscapeKind;
    reason: string;
  }> = [
    {
      module: "query-anonymity/query-anonymity-routes.ts",
      fn: "handleQueryAnonymityStatsRequest",
      builder: "computeQueryAnonymityStats",
      kind: "operator-per-request",
      reason:
        "/api/query-anonymity/stats standalone endpoint: a discrete, human-paced operator dashboard fetch (NO SPA consumer yet; not the 5s SSE posture cadence; the SSE board reads the SAME stats through posture-routes buildQueryPrivacy, which IS eager-wrapped). computeQueryAnonymityStats is dual-nature: eager on the board path, deliberately per-request on this standalone stats route where honest immediate on-disk re-verify is the chosen contract, exactly like dashboard handleAuditLog / approval-aggregator getAuditTrail.",
    },
  ];

  interface OperatorQuerySite {
    module: string;
    fn: string;
    line: number;
    eagerContained: boolean;
    aliased: boolean;
  }

  // Discover EVERY operator-universe audit read (auditLog.query OR an aliased
  // local-variable read) across ALL of src/, then mark each: is it lexically
  // inside an `runEagerReads`/`queryEager` scope, and what function encloses it.
  //
  // H3 (alias) — best-effort: within a source file we track local `const <name> =
  // <auditLog-receiver>` bindings and treat `<name>.query(...)` as an audit read
  // too. RESIDUAL (documented, NOT closed without full type resolution): a cross-
  // function or cross-file alias, a parameter typed `AuditLog` passed under a new
  // name, a reassigned/let alias, or a destructured `{ query } = auditLog` would
  // still slip the lexical tracker. Closing those needs the TS type checker
  // (Program + TypeChecker over the whole project); we deliberately take the
  // cheap best-effort heuristic here (honesty over completeness) and surface the
  // residual rather than sink hours into a type resolver. The same-name alias
  // (`const auditLog = sources.auditLog`) is already caught by the receiver
  // terminal-name match independent of this tracker.
  // Walk EVERY src module (not a pre-filtered list) so an OPERATOR module whose
  // ONLY read is via an alias — and which `discoverAuditLogReaders` (direct
  // `auditLog.query` only) therefore never lists — is still in scope. The scope
  // is "all modules MINUS the agent-facing buckets": a module is operator-in-scope
  // unless it is explicitly an agent-facing read surface. This is what closes
  // H1/H2 for alias-only NEW modules together with the H3 alias arm.
  function discoverOperatorQuerySites(
    excludeModules: ReadonlySet<string>,
  ): OperatorQuerySite[] {
    const sites: OperatorQuerySite[] = [];
    const isAuditLogReceiver = (expr: ts.Expression): boolean => {
      if (ts.isIdentifier(expr)) return expr.text === "auditLog";
      if (ts.isPropertyAccessExpression(expr)) return expr.name.text === "auditLog";
      return false;
    };
    // CANONICAL POSTURE ENTRY: a read is "eager-contained" iff a lexical ancestor
    // in the SAME file is a call to `runEagerReads`/`queryEager` on an audit-shaped
    // receiver. These two are blessed as THE operator-posture entry API (no new
    // symbol; fewer surfaces). A bare read outside such a scope is the wedge.
    const isEagerEntry = (call: ts.CallExpression): boolean => {
      if (!ts.isPropertyAccessExpression(call.expression)) return false;
      const m = call.expression.name.text;
      return m === "runEagerReads" || m === "queryEager";
    };
    const enclosingFnName = (node: ts.Node): string => {
      let p: ts.Node | undefined = node.parent;
      while (p) {
        if (ts.isFunctionDeclaration(p) && p.name) return p.name.text;
        if (ts.isMethodDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
        if (
          (ts.isFunctionExpression(p) || ts.isArrowFunction(p)) &&
          ts.isVariableDeclaration(p.parent) &&
          ts.isIdentifier(p.parent.name)
        ) {
          return p.parent.name.text;
        }
        p = p.parent;
      }
      return "(module-scope)";
    };
    const walkDir = (dir: string) => {
      // withFileTypes: the dir/file decision comes from the directory listing
      // itself (the Dirent), not a separate statSync(p), so there is no
      // check-then-use (TOCTOU) gap on p between the type check and the read.
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const name = entry.name;
        const p = join(dir, name);
        if (entry.isDirectory()) {
          if (name === "node_modules") continue;
          walkDir(p);
          continue;
        }
        if (
          !name.endsWith(".ts") ||
          name.endsWith(".d.ts") ||
          name.endsWith(".test.ts")
        ) {
          continue;
        }
        const rel = relative(SERVER_SRC, p).split(sep).join("/");
        if (excludeModules.has(rel)) continue; // agent-facing → out of scope
        let source: string;
        try {
          source = readFileSync(p, "utf8");
        } catch {
          continue; // file vanished mid-walk: skip, don't crash
        }
        const sf = ts.createSourceFile(
          p,
          source,
          ts.ScriptTarget.Latest,
          /*setParentNodes*/ true,
        );
        // H3 best-effort: collect local alias identifier names bound to an
        // audit-shaped receiver via `const <name> = <auditLog-receiver>`.
        const aliasNames = new Set<string>();
        const collectAliases = (node: ts.Node) => {
          if (
            ts.isVariableDeclaration(node) &&
            ts.isIdentifier(node.name) &&
            node.initializer &&
            isAuditLogReceiver(node.initializer) &&
            node.name.text !== "auditLog" // already matched by receiver name
          ) {
            aliasNames.add(node.name.text);
          }
          ts.forEachChild(node, collectAliases);
        };
        collectAliases(sf);
        const recordIfQuery = (node: ts.CallExpression, aliased: boolean) => {
          let eager = false;
          let anc: ts.Node | undefined = node.parent;
          while (anc) {
            if (ts.isCallExpression(anc) && isEagerEntry(anc)) {
              eager = true;
              break;
            }
            anc = anc.parent;
          }
          const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
          sites.push({
            module: rel,
            fn: enclosingFnName(node),
            line: line + 1,
            eagerContained: eager,
            aliased,
          });
        };
        const visit = (node: ts.Node) => {
          if (
            ts.isCallExpression(node) &&
            ts.isPropertyAccessExpression(node.expression) &&
            node.expression.name.text === "query"
          ) {
            const recv = node.expression.expression;
            if (isAuditLogReceiver(recv)) {
              recordIfQuery(node, false);
            } else if (ts.isIdentifier(recv) && aliasNames.has(recv.text)) {
              recordIfQuery(node, true); // H3 aliased read
            }
          }
          ts.forEachChild(node, visit);
        };
        visit(sf);
      }
    };
    walkDir(SERVER_SRC);
    return sites;
  }

  // The agent-facing read surfaces — the ONLY modules EXCLUDED from the operator
  // eager scope (the honesty boundary). Everything else is operator-in-scope.
  function agentFacingExclusions(): Set<string> {
    return new Set<string>([
      ...AGENT_FACING_AUDIT_READ_MODULES,
      ...AGENT_FACING_NON_ENTRY_AUDIT_READS,
    ]);
  }

  // The OPERATOR UNIVERSE: every discovered (direct) auditLog.query reader MINUS
  // the agent-facing buckets. Used for the disjointness + vacuous-green checks.
  // (The site walk in discoverOperatorQuerySites is broader — it also catches
  // alias-only operator modules this direct-reader list cannot see.)
  function operatorUniverse(): Set<string> {
    const exclude = agentFacingExclusions();
    return new Set(discoverAuditLogReaders().filter((m) => !exclude.has(m)));
  }

  describe("eager-posture read chokepoint (v2, inverted to default-eager)", () => {
    it("THE TEETH: every OPERATOR audit read is eager-scoped or a registered conscious escape", () => {
      const universe = operatorUniverse();
      const sites = discoverOperatorQuerySites(agentFacingExclusions());

      // Vacuous-green guard: the inverted walk must actually find operator reads.
      // (An empty walk would make the violations set-difference trivially pass.)
      // The site walk is broader than the direct-reader universe (it also catches
      // alias-only modules), so it must find AT LEAST as many sites as there are
      // direct-reader operator modules.
      expect(
        sites.length,
        "operator-universe walk found no auditLog.query sites — the walk is broken",
      ).toBeGreaterThanOrEqual(universe.size);

      const escapeFor = (s: OperatorQuerySite) =>
        EAGER_QUERY_ESCAPES.find((e) => e.module === s.module && e.fn === s.fn);

      // A read that is neither eager-contained nor a registered escape is a bare
      // operator read — exactly the 11-30s wedge the chokepoint forbids. Closes
      // H1/H2 (scope is ALL operator modules) and H3 (aliased reads are sites too).
      const violations = sites
        .filter((s) => !s.eagerContained && !escapeFor(s))
        .map(
          (s) =>
            `${s.module}:${s.line} (${s.fn})${s.aliased ? " [aliased]" : ""} — ` +
            `bare auditLog.query outside an runEagerReads/queryEager scope. Wrap ` +
            `it in the eager scope, or, if it is deliberately not eager (batch / ` +
            `background / per-request / agent-facing), register module:fn in ` +
            `EAGER_QUERY_ESCAPES with a kind + reason.`,
        );
      expect(violations, violations.join("\n")).toEqual([]);
    });

    it("M1: every escape has a valid enum kind and a real reason (no one-line abuse)", () => {
      for (const e of EAGER_QUERY_ESCAPES) {
        expect(
          (EAGER_ESCAPE_KINDS as readonly string[]).includes(e.kind),
          `escape ${e.module} (${e.fn}) has non-enum kind "${e.kind}"`,
        ).toBe(true);
        // A reason must be present and substantive, not a placeholder. This is the
        // structural half of M1; the semantic half is the human reviewer reading it.
        const reason = e.reason.trim();
        expect(
          reason.length,
          `escape ${e.module} (${e.fn}) needs a substantive reason`,
        ).toBeGreaterThanOrEqual(40);
        expect(
          /^(n\/?a|todo|tbd|fixme|xxx|because|reason|escape|skip)\.?$/i.test(reason),
          `escape ${e.module} (${e.fn}) reason looks like a placeholder: "${reason}"`,
        ).toBe(false);
      }
      // Registry shape is unique per module:fn (no duplicate / shadowing rows).
      const keys = EAGER_QUERY_ESCAPES.map((e) => `${e.module}::${e.fn}`);
      expect(new Set(keys).size, "duplicate EAGER_QUERY_ESCAPES key(s)").toBe(
        keys.length,
      );
    });

    it("M1: no STALE escapes — every escape matches a real, currently-non-eager site", () => {
      const sites = discoverOperatorQuerySites(agentFacingExclusions());
      const liveNonEager = sites.filter((s) => !s.eagerContained);
      const stale = EAGER_QUERY_ESCAPES.filter(
        (e) => !liveNonEager.some((s) => s.module === e.module && s.fn === e.fn),
      ).map((e) => `${e.module} (${e.fn})`);
      expect(
        stale,
        `Stale EAGER_QUERY_ESCAPES entr(ies) — the function no longer has a ` +
          `non-eager auditLog.query (renamed, removed, or now eager-wrapped). ` +
          `Remove: ${stale.join(", ")}`,
      ).toEqual([]);
    });

    it("positive control: the eager-detection arm is not vacuously passing (≥1 site IS eager-contained)", () => {
      const sites = discoverOperatorQuerySites(agentFacingExclusions());
      // #721 wrapped the aggregator snapshot listing read in runEagerReads. If the
      // eager-detection arm broke (e.g. matched no scope), it would classify even
      // that as non-eager and the escape registry would mask everything — this
      // catches that failure mode.
      expect(
        sites.some((s) => s.eagerContained),
        "no eager-contained operator query site found — the eager-detection arm may be broken (expected at least the #721 aggregator snapshot read)",
      ).toBe(true);
    });

    it("H4: each caller-wrapped builder is wrapped AT EVERY call site across the WHOLE tree (drop one wrap or call it bare from a new module → red)", () => {
      // The "caller-wrapped-builder" escape claims the eager scope is opened one
      // frame up by the CALLER. v1's proof only checked the builder NAME appeared
      // inside SOME runEagerReads call anywhere — so dropping the wrap on ONE
      // caller while another still wrapped it passed. The first v2 cut narrowed
      // to per-CALL-SITE but only scanned THREE hard-coded ENTRY_POINT_MODULES —
      // so a bare call to a caller-wrapped builder from a NEW/4th operator module
      // (no surrounding runEagerReads) evaded the whole suite: the builder's own
      // read is the escaped `caller-wrapped-builder` (not flagged), and the bare
      // call site is a call to the BUILDER, not an `auditLog.query`, so THE TEETH's
      // query-site walk never sees it either. At runtime the builder's internal
      // `auditLog.query({ limit: 10_000 | 50_000 })` then runs NON-eager = the
      // #714 wedge, silently. (Empirically real: this inversion surfaced exactly
      // such a site — handleQueryAnonymityStatsRequest calling
      // computeQueryAnonymityStats bare — which the 3-module scan never saw.)
      //
      // THE INVERSION (same shape THE TEETH was inverted): discover EVERY call
      // site of EVERY caller-wrapped builder across ALL src modules MINUS the
      // agent-facing buckets — NOT a hard-coded entry-point list. Each such call
      // MUST be lexically inside an `runEagerReads`/`queryEager` scope, OR its
      // enclosing function must be a conscious, enumerated BARE_BUILDER_CALL_ESCAPE
      // (a deliberately per-request standalone operator endpoint). A bare builder
      // call from ANY module — including a brand-new one — with no escape REDS.
      const builderFns = new Set(
        EAGER_QUERY_ESCAPES.filter((e) => e.kind === "caller-wrapped-builder").map(
          (e) => e.fn,
        ),
      );

      const isEagerEntry = (call: ts.CallExpression): boolean => {
        if (!ts.isPropertyAccessExpression(call.expression)) return false;
        const m = call.expression.name.text;
        return m === "runEagerReads" || m === "queryEager";
      };
      const enclosingFnName = (node: ts.Node): string => {
        let p: ts.Node | undefined = node.parent;
        while (p) {
          if (ts.isFunctionDeclaration(p) && p.name) return p.name.text;
          if (ts.isMethodDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
          if (
            (ts.isFunctionExpression(p) || ts.isArrowFunction(p)) &&
            ts.isVariableDeclaration(p.parent) &&
            ts.isIdentifier(p.parent.name)
          ) {
            return p.parent.name.text;
          }
          p = p.parent;
        }
        return "(module-scope)";
      };

      // WHOLE-TREE DISCOVERY: walk every src module (minus the agent-facing
      // buckets) and record every CallExpression whose callee is a builder name,
      // with its enclosing function and whether it is lexically eager-contained.
      const exclude = agentFacingExclusions();
      const builderCallSites: Array<{
        module: string;
        fn: string;
        enclosingFn: string;
        line: number;
        eager: boolean;
      }> = [];
      const walkDir = (dir: string) => {
        // withFileTypes: the dir/file decision comes from the directory listing
        // itself (the Dirent), not a separate statSync(p), so there is no
        // check-then-use (TOCTOU) gap on p between the type check and the read.
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          const name = entry.name;
          const p = join(dir, name);
          if (entry.isDirectory()) {
            if (name === "node_modules") continue;
            walkDir(p);
            continue;
          }
          if (
            !name.endsWith(".ts") ||
            name.endsWith(".d.ts") ||
            name.endsWith(".test.ts")
          ) {
            continue;
          }
          const rel = relative(SERVER_SRC, p).split(sep).join("/");
          if (exclude.has(rel)) continue; // agent-facing → out of scope
          let source: string;
          try {
            source = readFileSync(p, "utf8");
          } catch {
            continue; // file vanished mid-walk: skip, don't crash
          }
          const sf = ts.createSourceFile(
            p,
            source,
            ts.ScriptTarget.Latest,
            /*setParentNodes*/ true,
          );
          const visit = (node: ts.Node) => {
            if (
              ts.isCallExpression(node) &&
              ts.isIdentifier(node.expression) &&
              builderFns.has(node.expression.text)
            ) {
              let eager = false;
              let anc: ts.Node | undefined = node.parent;
              while (anc) {
                if (ts.isCallExpression(anc) && isEagerEntry(anc)) {
                  eager = true;
                  break;
                }
                anc = anc.parent;
              }
              const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
              builderCallSites.push({
                module: rel,
                fn: node.expression.text,
                enclosingFn: enclosingFnName(node),
                line: line + 1,
                eager,
              });
            }
            ts.forEachChild(node, visit);
          };
          visit(sf);
        }
      };
      walkDir(SERVER_SRC);

      // Vacuous-green guard: whole-tree discovery must actually find builder calls
      // (one per registered caller-wrapped builder at minimum). An empty walk —
      // or a builder-name set that drifted out of sync — would make the
      // set-difference checks below trivially pass.
      expect(
        builderCallSites.length,
        "whole-tree builder-call discovery found no call sites — the walk or the builder-name set is broken",
      ).toBeGreaterThanOrEqual(builderFns.size);

      // (1) Every caller-wrapped-builder escape must have AT LEAST ONE real call
      // site SOMEWHERE in the tree (else the escape is unfounded — a builder that
      // is never invoked needs no caller-wraps claim).
      const builderHasCall = new Set(builderCallSites.map((c) => c.fn));
      const unfounded = [...builderFns]
        .filter((fn) => !builderHasCall.has(fn))
        .map(
          (fn) =>
            `${fn}: no call site found anywhere in src — the ` +
            `caller-wrapped-builder escape is unfounded (the builder must be ` +
            `invoked by a posture entry point that opens the eager scope).`,
        );
      expect(unfounded, unfounded.join("\n")).toEqual([]);

      // (2) THE H4 TEETH: every builder call site must be eager-wrapped OR carry a
      // conscious BARE_BUILDER_CALL_ESCAPE for its enclosing function. A bare call
      // from ANY module — including a brand-new one — with no escape REDS.
      const escapeFor = (c: { module: string; enclosingFn: string }) =>
        BARE_BUILDER_CALL_ESCAPES.find(
          (e) => e.module === c.module && e.fn === c.enclosingFn,
        );
      const droppedWraps = builderCallSites
        .filter((c) => !c.eager && !escapeFor(c))
        .map(
          (c) =>
            `${c.module}:${c.line} calls ${c.fn} OUTSIDE an ` +
            `runEagerReads/queryEager scope (in ${c.enclosingFn}). A ` +
            `caller-wrapped-builder must be eager-wrapped at EVERY call site; wrap ` +
            `this call, make the builder's own read eager and drop the escape, or, ` +
            `if it is a deliberately per-request standalone operator endpoint, ` +
            `register ${c.module}:${c.enclosingFn} in BARE_BUILDER_CALL_ESCAPES ` +
            `with a kind + reason.`,
        );
      expect(droppedWraps, droppedWraps.join("\n")).toEqual([]);

      // (3) M1 on the builder-call axis: every BARE_BUILDER_CALL_ESCAPE has a
      // valid enum kind, a substantive reason, and is NOT stale (it must match a
      // real, currently-non-eager builder call site — so a wrap landing on that
      // site later forces the escape's removal).
      for (const e of BARE_BUILDER_CALL_ESCAPES) {
        expect(
          (EAGER_ESCAPE_KINDS as readonly string[]).includes(e.kind),
          `bare-builder escape ${e.module} (${e.fn}) has non-enum kind "${e.kind}"`,
        ).toBe(true);
        const reason = e.reason.trim();
        expect(
          reason.length,
          `bare-builder escape ${e.module} (${e.fn}) needs a substantive reason`,
        ).toBeGreaterThanOrEqual(40);
        expect(
          builderFns.has(e.builder),
          `bare-builder escape ${e.module} (${e.fn}) names builder "${e.builder}" which is not a caller-wrapped-builder`,
        ).toBe(true);
      }
      const liveBareBuilderCalls = builderCallSites.filter((c) => !c.eager);
      const staleBuilderEscapes = BARE_BUILDER_CALL_ESCAPES.filter(
        (e) =>
          !liveBareBuilderCalls.some(
            (c) =>
              c.module === e.module &&
              c.enclosingFn === e.fn &&
              c.fn === e.builder,
          ),
      ).map((e) => `${e.module} (${e.fn} → ${e.builder})`);
      expect(
        staleBuilderEscapes,
        `Stale BARE_BUILDER_CALL_ESCAPE(s) — the function no longer has a ` +
          `non-eager call to the named builder (renamed, removed, or now ` +
          `eager-wrapped). Remove: ${staleBuilderEscapes.join(", ")}`,
      ).toEqual([]);
    });

    it("HOT-read alarm: the operator-hot-pending-triage set is the explicit HIGH backlog (kept honest, not hidden)", () => {
      // This test does NOT fail on the existence of a HOT read — that would block
      // the test-infra build on a product change. It PINS the set so the HIGH
      // backlog is visible and cannot silently grow: any new
      // operator-hot-pending-triage escape must be added here consciously, and
      // when the product fix lands (the read becomes eager) the stale-escape guard
      // forces removal from BOTH places. Today there is exactly one: the 60s-timer
      // AgentContextCache.refresh re-verify surfaced by the v2 inversion.
      const hot = EAGER_QUERY_ESCAPES.filter(
        (e) => e.kind === "operator-hot-pending-triage",
      ).map((e) => `${e.module} (${e.fn})`);
      expect(hot).toEqual(["chat/agent-context-cache.ts (refresh)"]);
      // Every HOT escape's reason must carry the HIGH/TRIAGE marker so it reads as
      // a flagged alarm, never as a benign per-request blessing.
      for (const e of EAGER_QUERY_ESCAPES.filter(
        (x) => x.kind === "operator-hot-pending-triage",
      )) {
        expect(
          /HIGH|TRIAGE/i.test(e.reason),
          `operator-hot-pending-triage escape ${e.module} (${e.fn}) must mark its reason HIGH/TRIAGE`,
        ).toBe(true);
      }
    });

    it("honesty boundary: agent-facing reads are NEVER in the eager scope (operator universe disjoint from agent buckets)", () => {
      // Structural proof the chokepoint does not bleed across the honesty
      // boundary: the inverted scope EXCLUDES the agent-facing buckets by
      // construction, so no agent-facing read is ever asked to become eager.
      const universe = operatorUniverse();
      const agentFacing = [
        ...AGENT_FACING_AUDIT_READ_MODULES,
        ...AGENT_FACING_NON_ENTRY_AUDIT_READS,
      ];
      const crossed = agentFacing.filter((m) => universe.has(m));
      expect(
        crossed,
        `agent-facing audit-read module(s) leaked into the operator eager scope: ` +
          `${crossed.join(", ")}. Agent reads must stay per-request re-verified.`,
      ).toEqual([]);
      // The lone agent-facing read that lives ON an operator module
      // (posture-routes buildEvidence, /api/posture/evidence) is registered
      // agent-facing-per-request — never asked to be eager.
      const evidence = EAGER_QUERY_ESCAPES.find((e) => e.fn === "buildEvidence");
      expect(evidence?.kind).toBe("agent-facing-per-request");
    });

    it("H3 residual is documented honestly (best-effort alias tracking, not a type checker)", () => {
      // This pins the HONEST scope of the alias guard so the test does not
      // overclaim. The discovery tracks same-file `const <name> = <auditLog>`
      // aliases (best-effort). It does NOT resolve cross-file / cross-function /
      // reassigned / destructured aliases — that needs the TS type checker. The
      // assertion is a self-documenting marker: if someone strengthens the guard
      // to full type resolution, they update this list and the test stays honest.
      const RESIDUAL_ALIAS_SHAPES_NOT_CLOSED = [
        "cross-function alias (auditLog passed to another fn under a new name)",
        "cross-file alias",
        "let-reassigned alias",
        "destructured `{ query } = auditLog`",
      ] as const;
      // The residual is non-empty (we did NOT claim to close it) and best-effort
      // same-file aliasing IS tracked (the discovery has an alias arm).
      expect(RESIDUAL_ALIAS_SHAPES_NOT_CLOSED.length).toBeGreaterThan(0);
    });
  });

  it("every agent-facing audit-read module imports the allowlist projection", () => {
    for (const mod of AGENT_FACING_AUDIT_READ_MODULES) {
      const src = read(mod);
      expect(
        /redactAuditEntryForAgent|AgentAuditView|buildAgentSearchCorpus/.test(src),
        `${mod} must route audit reads through the allowlist (agent-audit-redaction)`
      ).toBe(true);
      // It must IMPORT from the single allowlist source of truth, not re-derive
      // a parallel projection.
      expect(
        src.includes("agent-audit-redaction"),
        `${mod} must import from agent-audit-redaction (single source of truth)`
      ).toBe(true);
    }
  });

  it("the broker's AGENT-facing audit return type is the allowlist view (TS-enforced, no raw details)", () => {
    const src = read("disclosure/broker/broker.ts");
    // The agent-facing AuditSummary entry type is the allowlist view. Because
    // `queryAudit` is typed `Promise<AuditSummary>`, the compiler itself forbids
    // returning a raw `details` field on the agent path — this guard pins the
    // type so a future widening (adding `details?` back to AuditSummary) reds.
    expect(src).toMatch(/export interface AuditSummary\s*\{[\s\S]*?entries:\s*AgentAuditView\[\]/);
    // The agent path applies the redaction explicitly…
    expect(src).toMatch(/queryAudit\([\s\S]*?\):\s*Promise<AuditSummary>/);
    expect(src).toContain("redactAuditEntryForAgent");
  });

  it("raw broker audit `details` flow only through the explicitly OPERATOR-named surface", () => {
    // The broker is the one module with BOTH an agent read (queryAudit →
    // redacted AuditSummary) and an operator read (queryAuditOperator → full
    // OperatorAuditSummary). The durability requirement is that any raw-details
    // passthrough is on the OPERATOR surface only. We assert every raw-`details`
    // copy site in the file lives within an `Operator`-named symbol — so a future
    // change that routes raw details onto the AGENT path (queryAudit /
    // AuditSummary) reds. The agent-facing modules that have NO operator audit
    // read must carry no raw-details copy at all.
    const RAW_DETAILS_COPY = /(?:details:\s*\w+\??\.details\b|\.\.\.\s*\w+\??\.details\b)/g;

    // (a) The three agent-only audit-read modules never copy raw details.
    for (const mod of [
      "index.ts",
      "audit/siem-tools.ts",
      "agent-native/cooperative-surface.ts",
    ]) {
      const src = read(mod);
      expect(
        RAW_DETAILS_COPY.test(src),
        `${mod} has no operator audit read; it must not copy a raw \`details\` object at all`
      ).toBe(false);
      RAW_DETAILS_COPY.lastIndex = 0;
    }

    // (b) In broker.ts, every raw-details copy site must be inside an
    // `Operator`-named region (OperatorAuditSummary type / queryAuditOperator).
    // We slice the file at the operator symbols and assert no raw-details copy
    // survives OUTSIDE those operator regions.
    const brokerSrc = read("disclosure/broker/broker.ts");
    const OPERATOR_REGION =
      /(export interface OperatorAuditSummary[\s\S]*?\n\}\n)|(async queryAuditOperator\([\s\S]*?\n  \}\n)/g;
    const outsideOperator = brokerSrc.replace(OPERATOR_REGION, "");
    expect(
      RAW_DETAILS_COPY.test(outsideOperator),
      "broker.ts copies a raw `details` object OUTSIDE the operator-only surface — the agent path must stay redacted"
    ).toBe(false);
  });

  it("the allowlist view is exactly the fixed 4-field shape (pins the contract)", () => {
    // If a field is added/removed from the agent-facing view, this guard reds so
    // the change is a conscious, reviewed widening of what every surface emits.
    expect([...AGENT_AUDIT_VIEW_FIELDS].sort()).toEqual([
      "has_details",
      "operation",
      "result",
      "timestamp",
    ]);
  });

  it("AUTO-DISCOVERY: every auditLog.query reader is classified; a NEW agent-facing audit read cannot evade the registry", () => {
    const discovered = discoverAuditLogReaders();

    // Sanity: the parser actually walked the tree. Guards against a vacuous
    // green (e.g. an empty walk would make every set-difference trivially pass).
    expect(
      discovered.length,
      "auto-discovery found no auditLog.query readers — the source walk is broken"
    ).toBeGreaterThanOrEqual(AGENT_FACING_AUDIT_READ_MODULES.length);
    for (const m of AGENT_FACING_AUDIT_READ_MODULES) {
      expect(
        discovered,
        `known agent-facing reader ${m} must be auto-discovered`
      ).toContain(m);
    }

    const agentFacing = new Set<string>(AGENT_FACING_AUDIT_READ_MODULES);
    const nonEntry = new Set<string>(AGENT_FACING_NON_ENTRY_AUDIT_READS);
    const operator = new Set<string>(OPERATOR_INTERNAL_AUDIT_READS);

    // Each reader is classified EXACTLY once — the three buckets are disjoint.
    const overlap = [
      ...[...agentFacing].filter((f) => nonEntry.has(f) || operator.has(f)),
      ...[...nonEntry].filter((f) => operator.has(f)),
    ].sort();
    expect(
      overlap,
      `audit-read module(s) classified in more than one bucket: ${overlap.join(", ")}`
    ).toEqual([]);

    const classified = new Set<string>([
      ...agentFacing,
      ...nonEntry,
      ...operator,
    ]);

    // (1) THE GAP CLOSURE (codex #573): any discovered reader not in a bucket is
    // a NEW, unclassified audit read. A brand-new agent-facing audit-read tool
    // added in a NEW file lands HERE and REDS — it can no longer slip past by
    // simply not being added to the hand-maintained agent-facing list.
    const unaccounted = discovered.filter((f) => !classified.has(f));
    expect(
      unaccounted,
      `Unclassified auditLog.query reader(s): ${unaccounted.join(", ")}. ` +
        `Classify each one: if an AGENT can reach it via an MCP tool AND it returns ` +
        `audit ENTRIES, route them through redactAuditEntryForAgent / ` +
        `buildAgentSearchCorpus and add it to AGENT_FACING_AUDIT_READ_MODULES; ` +
        `if it is an agent tool that surfaces NO entries, add it to ` +
        `AGENT_FACING_NON_ENTRY_AUDIT_READS; if it is an operator/internal/principal ` +
        `full-fidelity read, add it to OPERATOR_INTERNAL_AUDIT_READS.`
    ).toEqual([]);

    // (2) No stale registry entries: every classified module must still be a real
    // auditLog.query reader, so the lists stay honest as files move or refactor.
    const stale = [...classified].filter((f) => !discovered.includes(f)).sort();
    expect(
      stale,
      `Classified module(s) no longer read the audit log — remove or update: ${stale.join(", ")}`
    ).toEqual([]);
  });

  it("agent-facing NON-entry audit reads surface no raw `details` (nothing redactable crosses to the agent)", () => {
    // These tools are agent-callable but classified as surfacing no audit
    // entries. Pin that: a raw `details` copy appearing in one of them would mean
    // entry data is now reaching the agent path and the file must move into
    // AGENT_FACING_AUDIT_READ_MODULES (and route through the allowlist).
    const RAW_DETAILS_COPY = /(?:details:\s*\w+\??\.details\b|\.\.\.\s*\w+\??\.details\b)/g;
    for (const mod of AGENT_FACING_NON_ENTRY_AUDIT_READS) {
      const src = read(mod);
      expect(
        RAW_DETAILS_COPY.test(src),
        `${mod} is agent-facing but classified non-entry — it must not copy a raw \`details\` object`
      ).toBe(false);
      RAW_DETAILS_COPY.lastIndex = 0;
    }
  });
});
