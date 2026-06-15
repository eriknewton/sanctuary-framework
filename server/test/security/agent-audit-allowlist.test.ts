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
import { createSanctuaryServer } from "../../src/index.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  redactAuditEntryForAgent,
  buildAgentSearchCorpus,
  AGENT_AUDIT_VIEW_FIELDS,
  AGENT_AUDIT_SEARCHABLE_DETAIL_KEYS,
} from "../../src/l2-operational/agent-audit-redaction.js";
import { createSIEMTools } from "../../src/audit/siem-tools.js";
import { createServer } from "../../src/router.js";
import { fingerprintIdentityId } from "../../src/agent-native/safety-base.js";
import type { ToolDefinition } from "../../src/router.js";

const ALLOWED_VIEW_KEYS = [...AGENT_AUDIT_VIEW_FIELDS].sort();

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

  it("search corpus is an ALLOWLIST: only safe keys survive; reason/rule_id/tier omitted", () => {
    const corpus = buildAgentSearchCorpus({
      details: {
        decision: "deny_once",
        dest_host: "host.example",
        // none of these may appear in the corpus:
        reason: "Signing frequency (7/min) exceeds limit (5/min)",
        rule_id: "deny-secret-rule",
        tier: 2,
        decision_provenance: "policy-path",
      },
    });
    expect(corpus).toEqual({ decision: "deny_once", dest_host: "host.example" });
    const serialized = JSON.stringify(corpus);
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
    expect([...AGENT_AUDIT_SEARCHABLE_DETAIL_KEYS].sort()).toEqual([
      "decision",
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
        decision: "deny_once", // allowlisted-searchable, safe
        dest_host: "host.example", // allowlisted-searchable, safe
        // Everything below must NEVER reach an agent surface:
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
    const { StateStore } = await import("../../src/l1-cognitive/state-store.js");
    const { createL1Tools } = await import("../../src/l1-cognitive/tools.js");
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
    // only a has_details summary, never raw details.
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
    assertNoLeak(JSON.stringify(page.events));
  });
});
