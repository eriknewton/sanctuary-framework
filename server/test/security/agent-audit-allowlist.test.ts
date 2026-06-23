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
import { readFileSync, readdirSync, statSync } from "node:fs";
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
  // OPERATOR-POSTURE sub-bucket (carved out of OPERATOR_INTERNAL below).
  // ------------------------------------------------------------------------
  // The modules whose `auditLog.query` reads compose the always-on OPERATOR
  // posture surface (dashboard home board, the /v1/status + hero-shield arm
  // badge, feature-health, the protection snapshot, query-privacy stats). These
  // are the high-frequency / SSE-reachable reads that, on a real long-lived
  // fortress (10k entries / 40MB), turned an honest full-chain re-verify into an
  // 11-30s wedge per poll (the #714 incident). #717/#719/#721 fixed it by
  // serving those reads from the audit log's eagerly-maintained verified view
  // (an `runEagerReads`/`queryEager` scope) which is O(1) and STILL honest
  // (fingerprint sentinel + 30s backstop catch out-of-band tamper). That fix is
  // OPT-IN per call site, so the same defect recurred three times in three code
  // paths. This sub-bucket + the EAGER-SCOPE ASSERTION below is the chokepoint
  // that ends the whack-a-mole: a posture-module `auditLog.query` that is not
  // eager-scoped (and not on the conscious per-call escape registry) REDS CI.
  //
  // This enforces an ALREADY-established honesty boundary; it does NOT change it.
  // It NEVER pushes the agent-facing reads (in the allowlist / non-entry buckets)
  // into eager mode: those keep their per-request on-disk re-verify. The split is
  // ENTRY-POINTS (open the eager scope directly) vs caller-wrapped BUILDERS (the
  // shaper functions whose internal `query` runs inside the entry point's scope).
  const OPERATOR_POSTURE_AUDIT_READS = [
    // entry points: open the eager scope (or carry a conscious per-request escape)
    "dashboard/aggregator.ts",
    "principal-policy/dashboard.ts",
    "principal-policy/posture-routes.ts",
    // caller-wrapped builders: their internal `query` runs inside the entry
    // point's `runEagerReads` scope (asserted caller-wrapped via the registry +
    // the builder-marker guard below). They are NOT entry points; they never open
    // the scope themselves.
    "principal-policy/posture.ts",
    "principal-policy/feature-health.ts",
    "query-anonymity/query-anonymity-routes.ts",
  ] as const;

  // Operator / internal / principal audit reads that legitimately see FULL
  // fidelity AND are NOT on the high-frequency posture surface (batch reads, CLI,
  // background analyzers, the per-request activity feed) where the eager view is
  // not the relevant cost lever. Kept per-request by design.
  const OPERATOR_NON_POSTURE_AUDIT_READS = [
    // anomaly detection — internal scoring over the audit stream
    "anomaly-detection/detectors/audit-event-class-distribution-detector.ts",
    "anomaly-detection/feature-extractors/audit-event-class-distribution.ts",
    "anomaly-detection/feature-extractors/credential-use-sequence.ts",
    "anomaly-detection/feature-extractors/cross-agent-timing.ts",
    "anomaly-detection/feature-extractors/per-agent-activity.ts",
    "anomaly-detection/feature-extractors/time-of-day-activity.ts",
    "anomaly-detection/feature-extractors/tool-call-sequence.ts",
    // sentinels — internal background watchers
    "sentinel/sentinels/credential-usage-watcher.ts",
    "sentinel/sentinels/cross-agent-chatter-watcher.ts",
    "sentinel/sentinels/egress-volume-watcher.ts",
    "sentinel/sentinels/suspicious-tool-call-detector.ts",
    // operator dashboards - human-facing HTTP surfaces
    "dashboard/v1_1/wiring.ts",
    // operator activity feed: per-message, identity-filtered projection. Bursty
    // but NOT the 5s SSE posture cadence, so deliberately kept per-request (the
    // narrow scoping per the design doc's open-question 3: start narrow). Its
    // honest on-disk tamper detection on every read is the safe default.
    "hub/activity-feed.ts",
    "principal-policy/approval-aggregator.ts",
    "principal-policy/unified-inbox-producers.ts",
    // operator CLI
    "cli/audit.ts",
    "cli/castle-wall.ts",
    // compliance report generation — operator artifact
    "compliance/eu_ai_act/generator.ts",
    // operator chat context / concierge — human operator surface
    "chat/agent-context-cache.ts",
    "concierge/sanctuary-context-reader.ts",
    // cross-agent coordination handoff log — internal
    "coordination/handoff-log.ts",
    // principal Exit bundle — full-fidelity receipts, Tier-1 approval-gated
    "exit/bundle.ts",
  ] as const;

  // The full operator/internal set (posture + non-posture) - preserves the
  // closure + disjointness contract the auto-discovery test relies on. NONE is
  // reachable by an agent calling an MCP tool: they are internal analyzers, CLI
  // commands, the human operator's HTTP dashboard/hub routes, cross-agent
  // coordination internals, or the principal's own Tier-1-approval-gated Exit
  // export. Per the agent-audit-redaction.ts header they MUST NOT use the agent
  // redaction. Listed explicitly so that adding a NEW audit reader forces a
  // conscious classification (asserted by the auto-discovery closure test below).
  const OPERATOR_INTERNAL_AUDIT_READS = [
    ...OPERATOR_POSTURE_AUDIT_READS,
    ...OPERATOR_NON_POSTURE_AUDIT_READS,
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
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        if (statSync(p).isDirectory()) {
          if (name === "node_modules") continue;
          walkDir(p);
          continue;
        }
        if (!name.endsWith(".ts") || name.endsWith(".d.ts") || name.endsWith(".test.ts")) {
          continue;
        }
        const sf = ts.createSourceFile(
          p,
          readFileSync(p, "utf8"),
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

  // ── EAGER-POSTURE CHOKEPOINT: per-call-site discovery ────────────────────
  // The module-level discovery above answers "which files read the audit log".
  // The chokepoint needs finer grain: for each `auditLog.query` CALL SITE in a
  // posture module, is it lexically inside an `runEagerReads`/`queryEager` scope,
  // and what function encloses it (so the conscious per-call escape registry can
  // be keyed by a stable function name, not a drifting line number)?
  interface PostureQuerySite {
    module: string;
    fn: string;
    line: number;
    eagerContained: boolean;
  }

  function discoverPostureQuerySites(modules: readonly string[]): PostureQuerySite[] {
    const sites: PostureQuerySite[] = [];
    const isAuditLogReceiver = (expr: ts.Expression): boolean => {
      if (ts.isIdentifier(expr)) return expr.text === "auditLog";
      if (ts.isPropertyAccessExpression(expr)) return expr.name.text === "auditLog";
      return false;
    };
    // CANONICAL POSTURE ENTRY: a `query` is "eager-contained" iff a lexical
    // ancestor in the SAME source file is a call to `runEagerReads` or
    // `queryEager` on an auditLog-shaped receiver. These two are blessed as THE
    // operator-posture entry API (no new symbol; fewer surfaces, per the design
    // doc's open-question 2). A bare `query` outside such a scope is the wedge.
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
    for (const mod of modules) {
      const abs = join(SERVER_SRC, ...mod.split("/"));
      const source = readFileSync(abs, "utf8");
      const sf = ts.createSourceFile(
        abs,
        source,
        ts.ScriptTarget.Latest,
        /*setParentNodes*/ true
      );
      const visit = (node: ts.Node) => {
        if (
          ts.isCallExpression(node) &&
          ts.isPropertyAccessExpression(node.expression) &&
          node.expression.name.text === "query" &&
          isAuditLogReceiver(node.expression.expression)
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
          sites.push({
            module: mod,
            fn: enclosingFnName(node),
            line: line + 1,
            eagerContained: eager,
          });
        }
        ts.forEachChild(node, visit);
      };
      visit(sf);
    }
    return sites;
  }

  // CONSCIOUS PER-CALL ESCAPE REGISTRY. A posture-module `auditLog.query` that is
  // NOT lexically eager-contained is permitted ONLY if its enclosing function is
  // registered here with a reason. This makes "I chose NOT to be eager" (or "my
  // caller opens the scope") a reviewed, named act, never an accident. A NEW bare
  // posture query whose function is absent here REDS the build - the chokepoint.
  //
  // kind:
  //   "caller-wrapped-builder"   - shaper whose internal `query` runs inside the
  //        entry point's `runEagerReads` scope (the AsyncLocalStorage scope is
  //        opened one frame up; a lexical check cannot see it). The caller-wraps
  //        proof below ties this to a real entry point that wraps the builder.
  //   "operator-per-request"     - a deliberately per-request operator read
  //        (honest immediate on-disk tamper detection is the chosen default).
  //   "agent-facing-per-request" - an AGENT-facing read that MUST stay
  //        per-request (the honesty boundary; never pushed into eager mode).
  const POSTURE_QUERY_ESCAPES: ReadonlyArray<{
    module: string;
    fn: string;
    kind:
      | "caller-wrapped-builder"
      | "operator-per-request"
      | "agent-facing-per-request";
    reason: string;
  }> = [
    // Builders: the entry points (posture-routes home builders, the dashboard
    // /v1/status badge, the aggregator hero shield) wrap these in runEagerReads,
    // so their internal query reads the eager view at runtime. (#717/#719/#721.)
    {
      module: "principal-policy/posture.ts",
      fn: "buildCastleWallPosture",
      kind: "caller-wrapped-builder",
      reason:
        "arm-state shaper; callers (posture-routes buildWallPosture, dashboard buildStatusCastleWall, aggregator hero shield) open the eager scope.",
    },
    {
      module: "principal-policy/posture.ts",
      fn: "buildAuditDigest",
      kind: "caller-wrapped-builder",
      reason: "audit-digest shaper; posture-routes buildDigest opens the eager scope.",
    },
    {
      module: "principal-policy/posture.ts",
      fn: "buildCustodyExitPanel",
      kind: "caller-wrapped-builder",
      reason: "custody-exit shaper; posture-routes buildCustodyExit opens the eager scope.",
    },
    {
      module: "principal-policy/posture.ts",
      fn: "buildRecognitionPanel",
      kind: "caller-wrapped-builder",
      reason: "recognition shaper; posture-routes buildRecognition opens the eager scope.",
    },
    {
      module: "principal-policy/feature-health.ts",
      fn: "buildFeatureHealthPanel",
      kind: "caller-wrapped-builder",
      reason: "feature-health shaper; posture-routes buildFeatureHealth opens the eager scope.",
    },
    {
      module: "query-anonymity/query-anonymity-routes.ts",
      fn: "computeQueryAnonymityStats",
      kind: "caller-wrapped-builder",
      reason:
        "query-privacy stats shaper; posture-routes buildQueryPrivacy opens the eager scope (the operator query-anonymity route is a low-frequency batch read).",
    },
    // Deliberate per-request operator read (OPEN QUESTION for Erik): the legacy
    // dashboard raw audit JSON listing. Treated like the inspectable evidence
    // surface (keep immediate on-disk tamper detection), NOT made eager. Confirm.
    {
      module: "principal-policy/dashboard.ts",
      fn: "handleAuditLog",
      kind: "operator-per-request",
      reason:
        "legacy /api/audit-log raw listing: inspectable surface kept per-request by design pending Erik's confirm (honest default; not the SSE hot path).",
    },
    // Agent-facing read on the posture-routes module: /api/posture/evidence. The
    // HONESTY BOUNDARY - must stay per-request fully re-verified. NEVER eager.
    {
      module: "principal-policy/posture-routes.ts",
      fn: "buildEvidence",
      kind: "agent-facing-per-request",
      reason:
        "/api/posture/evidence inspectable audit surface: per-request on-disk tamper detection is the honesty contract; must never be pushed into eager mode.",
    },
  ];

  it("EAGER-POSTURE CHOKEPOINT: every operator-posture audit read is eager-scoped or a registered conscious per-request escape", () => {
    const sites = discoverPostureQuerySites(OPERATOR_POSTURE_AUDIT_READS);

    // Sanity: the walk actually found posture query sites (guards a vacuous
    // green if a refactor moved every read out of these modules).
    expect(
      sites.length,
      "no auditLog.query sites found in the posture modules - the call-site walk is broken or the modules moved"
    ).toBeGreaterThanOrEqual(OPERATOR_POSTURE_AUDIT_READS.length);

    const escapeFor = (s: PostureQuerySite) =>
      POSTURE_QUERY_ESCAPES.find((e) => e.module === s.module && e.fn === s.fn);

    // THE TEETH: a posture-module query that is neither eager-contained nor on
    // the conscious escape registry is a bare operator-posture read - exactly the
    // 11-30s wedge the chokepoint exists to forbid.
    const violations = sites
      .filter((s) => !s.eagerContained && !escapeFor(s))
      .map(
        (s) =>
          `${s.module}:${s.line} (${s.fn}) - bare auditLog.query outside an ` +
          `runEagerReads/queryEager scope. Wrap the read in the eager scope, or, ` +
          `if it is deliberately per-request (operator-inspectable or agent-facing), ` +
          `register the function in POSTURE_QUERY_ESCAPES with a reason.`
      );
    expect(violations, violations.join("\n")).toEqual([]);

    // NO STALE ESCAPES: every registered escape must match a real, currently
    // NON-eager-contained query site. If a builder is refactored to wrap its own
    // read (becoming eager-contained), or a function is renamed/removed, its
    // escape goes stale and must be pruned - otherwise the registry rots and a
    // future bare read could hide behind a dead entry.
    const liveNonEager = sites.filter((s) => !s.eagerContained);
    const staleEscapes = POSTURE_QUERY_ESCAPES.filter(
      (e) => !liveNonEager.some((s) => s.module === e.module && s.fn === e.fn)
    ).map((e) => `${e.module} (${e.fn})`);
    expect(
      staleEscapes,
      `Stale POSTURE_QUERY_ESCAPES entr(ies) - the function no longer has a ` +
        `non-eager auditLog.query (renamed, removed, or now eager-wrapped). ` +
        `Remove: ${staleEscapes.join(", ")}`
    ).toEqual([]);

    // The honesty boundary, pinned: at least one site IS genuinely eager-contained
    // (proves the eager-detection arm is not vacuously passing every site via the
    // escape registry). #721 wrapped the aggregator snapshot listing read.
    expect(
      sites.some((s) => s.eagerContained),
      "no eager-contained posture query site found - the eager-detection arm may be broken (expected at least the #721 aggregator snapshot listing read)"
    ).toBe(true);
  });

  it("EAGER-POSTURE CHOKEPOINT: each caller-wrapped builder is actually wrapped in an eager scope by a posture entry point", () => {
    // The "caller-wrapped-builder" escape asserts the eager scope is opened one
    // frame up (in AsyncLocalStorage), invisible to the builder's own lexical
    // check. Pin that contract to REAL SOURCE, not a doc-comment: each such
    // builder function name must appear lexically inside an
    // `runEagerReads`/`queryEager` call in at least one ENTRY-POINT posture module
    // (the modules that open the scope). So a builder whose every caller drops the
    // eager wrap (re-introducing the wedge) reds HERE - the escape can no longer
    // be claimed once no entry point actually wraps it.
    const ENTRY_POINT_MODULES = [
      "principal-policy/posture-routes.ts",
      "principal-policy/dashboard.ts",
      "dashboard/aggregator.ts",
    ] as const;

    // Collect, per entry-point module, the set of identifier names that appear
    // lexically inside any `runEagerReads(...)` / `queryEager(...)` call.
    const wrappedBuilderNames = new Set<string>();
    for (const mod of ENTRY_POINT_MODULES) {
      const abs = join(SERVER_SRC, ...mod.split("/"));
      const sf = ts.createSourceFile(
        abs,
        readFileSync(abs, "utf8"),
        ts.ScriptTarget.Latest,
        /*setParentNodes*/ false
      );
      const collectIdentifiers = (node: ts.Node) => {
        if (ts.isIdentifier(node)) wrappedBuilderNames.add(node.text);
        ts.forEachChild(node, collectIdentifiers);
      };
      const visit = (node: ts.Node) => {
        if (
          ts.isCallExpression(node) &&
          ts.isPropertyAccessExpression(node.expression) &&
          (node.expression.name.text === "runEagerReads" ||
            node.expression.name.text === "queryEager")
        ) {
          // Walk the eager-call body (its argument closure) collecting every
          // identifier referenced inside the scope.
          for (const arg of node.arguments) collectIdentifiers(arg);
        }
        ts.forEachChild(node, visit);
      };
      visit(sf);
    }

    const builderFns = POSTURE_QUERY_ESCAPES.filter(
      (e) => e.kind === "caller-wrapped-builder"
    );
    const unwrapped = builderFns
      .filter((e) => !wrappedBuilderNames.has(e.fn))
      .map(
        (e) =>
          `${e.module} (${e.fn}) - no posture entry point wraps a call to ` +
          `${e.fn} in runEagerReads/queryEager. Either an entry point must open ` +
          `the eager scope around it, or this builder's read must be made eager ` +
          `directly and the escape removed.`
      );
    expect(unwrapped, unwrapped.join("\n")).toEqual([]);
  });

  it("EAGER-POSTURE CHOKEPOINT: agent-facing reads are NEVER required to be eager (honesty boundary preserved)", () => {
    // Structural proof the chokepoint does not bleed across the honesty boundary:
    // the eager assertion runs ONLY over OPERATOR_POSTURE_AUDIT_READS, and that
    // set must be disjoint from the agent-facing buckets. So no agent-facing read
    // is ever asked to become eager; they keep their per-request re-verify.
    const posture = new Set<string>(OPERATOR_POSTURE_AUDIT_READS);
    const agentFacing = [
      ...AGENT_FACING_AUDIT_READ_MODULES,
      ...AGENT_FACING_NON_ENTRY_AUDIT_READS,
    ];
    const crossed = agentFacing.filter((m) => posture.has(m));
    expect(
      crossed,
      `agent-facing audit-read module(s) leaked into the operator-posture eager ` +
        `bucket: ${crossed.join(", ")}. Agent reads must stay per-request re-verified.`
    ).toEqual([]);
    // And the lone agent-facing read that lives ON a posture module
    // (posture-routes buildEvidence) is registered as agent-facing-per-request,
    // never asked to be eager.
    const evidenceEscape = POSTURE_QUERY_ESCAPES.find(
      (e) => e.fn === "buildEvidence"
    );
    expect(evidenceEscape?.kind).toBe("agent-facing-per-request");
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
