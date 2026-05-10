/**
 * Sanctuary v1.3 WP-V1.3-9 Tau-5, agent-context cache unit tests
 *
 * Pure-function coverage for `agent-context-cache.ts`. Tests the
 * snapshot derivation, prompt-section rendering with token-budget
 * urgency-ordered prune, proactive starter generation, and the
 * cache's refresh / observe / fail-soft contracts.
 */

import { describe, it, expect, vi } from "vitest";
import {
  AgentContextCache,
  buildSnapshot,
  formatCurrentAgentStateSection,
  generateProactiveStarter,
  DEFAULT_AGENT_CONTEXT_TOKEN_BUDGET,
  type AgentContextSnapshot,
  type VerascoreDeltaSource,
} from "../../src/chat/agent-context-cache.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { HubAgentRegistrySource } from "../../src/hub/types.js";
import type { AuditLog, AuditEntry } from "../../src/l2-operational/audit-log.js";

const NOW = new Date("2026-05-10T15:00:00.000Z").getTime();

function makeRecord(
  agentId: string,
  overrides: Partial<LocalAgentRecord> = {},
): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: agentId,
    identity_id: overrides.identity_id ?? "op-1",
    harness: "openclaw",
    model_provider: { vendor: "anthropic", model_id: "claude", runs_locally: false },
    policy_id: "p-1",
    status: "running",
    budget_summary: { last_refreshed_at: new Date(NOW).toISOString() },
    last_activity_at: new Date(NOW - 30 * 60 * 1000).toISOString(),
    wrapped_at: new Date(NOW - 7 * 24 * 60 * 60 * 1000).toISOString(),
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: false,
      can_change_template: true,
    },
    ...overrides,
  };
}

function makeEntry(
  agentId: string | null,
  operation: string,
  ageMs: number,
  result: "success" | "failure" = "success",
): AuditEntry {
  return {
    timestamp: new Date(NOW - ageMs).toISOString(),
    layer: "l2",
    operation,
    identity_id: "op-1",
    result,
    ...(agentId !== null ? { details: { agent_id: agentId } } : {}),
  };
}

function makeStubAuditLog(entries: AuditEntry[]): AuditLog {
  return {
    query: vi.fn(async () => ({ entries: entries.slice(), total: entries.length })),
  } as unknown as AuditLog;
}

function makeStubRegistry(records: LocalAgentRecord[]): HubAgentRegistrySource {
  return {
    list: () => records.slice(),
    get: (id: string) => records.find((r) => r.agent_id === id) ?? null,
    put: () => {},
    updateStatus: () => records[0]!,
    updatePolicyBinding: () => records[0]!,
    updateChannelTemplateBinding: () => records[0]!,
  };
}

describe("buildSnapshot derivation (Tau-5)", () => {
  it("counts audit + composition + egress events scoped to the agent", () => {
    const record = makeRecord("OpenClaw", { channel_template_id: "research" });
    const recentEntries = [
      makeEntry("OpenClaw", "policy_change", 5 * 60 * 1000),
      makeEntry("OpenClaw", "composition_receipt_packed", 30 * 60 * 1000),
      makeEntry("OpenClaw", "context_gate_filter", 60 * 60 * 1000),
      makeEntry("Cline", "policy_change", 5 * 60 * 1000), // owned by another agent
      makeEntry(null, "system_event", 5 * 60 * 1000), // unscoped
    ];
    const snap = buildSnapshot({
      record,
      recentEntries,
      nowMs: NOW,
      verascoreSource: undefined,
    });
    expect(snap.recent_audit_count_24h).toBe(3);
    expect(snap.recent_concordia_receipts_count_24h).toBe(1);
    expect(snap.recent_egress_count_24h).toBe(1);
    expect(snap.template).toBe("research");
    expect(snap.recent_verascore_delta_24h).toBeNull();
  });

  it("flags 'active' on recent activity, 'idle' on >1h, 'stuck' on harness_error", () => {
    // Active
    const recent = makeRecord("R", {
      last_activity_at: new Date(NOW - 5 * 60 * 1000).toISOString(),
    });
    expect(
      buildSnapshot({ record: recent, recentEntries: [], nowMs: NOW, verascoreSource: undefined })
        .state_flags,
    ).toContain("active");

    // Idle (>1h, no other flags)
    const idle = makeRecord("I", {
      last_activity_at: new Date(NOW - 4 * 60 * 60 * 1000).toISOString(),
    });
    expect(
      buildSnapshot({ record: idle, recentEntries: [], nowMs: NOW, verascoreSource: undefined })
        .state_flags,
    ).toContain("idle");

    // Stuck (record-level error)
    const stuck = makeRecord("S", {
      status: "error",
      status_reason_class: "harness_error",
    });
    expect(
      buildSnapshot({ record: stuck, recentEntries: [], nowMs: NOW, verascoreSource: undefined })
        .state_flags,
    ).toContain("stuck");
  });

  it("flags has_pending_approvals when an approval-class audit event surfaces for the agent", () => {
    const record = makeRecord("Cline");
    const recentEntries = [
      makeEntry("Cline", "approval_request", 10 * 60 * 1000),
    ];
    const snap = buildSnapshot({
      record,
      recentEntries,
      nowMs: NOW,
      verascoreSource: undefined,
    });
    expect(snap.state_flags).toContain("has_pending_approvals");
  });

  it("derives current_work_summary from the most recent audit event", () => {
    const record = makeRecord("Cline");
    const recentEntries = [
      makeEntry("Cline", "policy_change", 1 * 60 * 60 * 1000),
      makeEntry("Cline", "composition_receipt_packed", 5 * 60 * 1000, "failure"),
    ];
    const snap = buildSnapshot({
      record,
      recentEntries,
      nowMs: NOW,
      verascoreSource: undefined,
    });
    expect(snap.current_work_summary).toBe("failed composition_receipt_packed");
  });

  it("reads verascore delta from the optional source", () => {
    const record = makeRecord("OpenClaw");
    const verascoreSource: VerascoreDeltaSource = {
      read: (id) => (id === "OpenClaw" ? -0.42 : null),
    };
    const snap = buildSnapshot({
      record,
      recentEntries: [],
      nowMs: NOW,
      verascoreSource,
    });
    expect(snap.recent_verascore_delta_24h).toBe(-0.42);
  });
});

describe("formatCurrentAgentStateSection (Tau-5 prompt rendering)", () => {
  it("returns the empty string when no snapshots are passed", () => {
    expect(formatCurrentAgentStateSection([])).toBe("");
  });

  it("renders one bullet per snapshot with the canonical header", () => {
    const snapshots: AgentContextSnapshot[] = [
      {
        agent_id: "OpenClaw",
        agent_name: "OpenClaw",
        template: "research",
        last_activity_at: new Date(NOW).toISOString(),
        current_work_summary: "performed policy_change",
        recent_audit_count_24h: 12,
        recent_egress_count_24h: 0,
        recent_concordia_receipts_count_24h: 3,
        recent_verascore_delta_24h: null,
        state_flags: ["idle"],
      },
    ];
    const out = formatCurrentAgentStateSection(snapshots);
    expect(out).toContain("## Current agent state");
    expect(out).toContain("- OpenClaw");
    expect(out).toContain("template: research");
    expect(out).toContain("12 audit/24h");
    expect(out).toContain("3 receipts");
  });

  it("token-budget prunes by urgency: stuck > pending-approvals > findings > active > idle", () => {
    const snapshots: AgentContextSnapshot[] = [
      mkSnap("LowIdle", ["idle"]),
      mkSnap("LowActive", ["active"]),
      mkSnap("MidFindings", ["has_open_findings"]),
      mkSnap("MidApprovals", ["has_pending_approvals"]),
      mkSnap("HighStuck", ["stuck"]),
    ];
    // Tight budget: only ~2-3 lines fit.
    const out = formatCurrentAgentStateSection(snapshots, { maxTokens: 60 });
    // Stuck must appear; idle should be the first to drop.
    expect(out).toContain("HighStuck");
    expect(out).not.toContain("LowIdle");
  });

  it("respects DEFAULT_AGENT_CONTEXT_TOKEN_BUDGET when many agents are present", () => {
    // 50 agents, each emitting ~30-40 chars per line. 50 lines is well
    // over the default 400-token budget (1600 chars proxy), so the
    // section should be truncated.
    const snapshots: AgentContextSnapshot[] = Array.from({ length: 50 }, (_, i) =>
      mkSnap(`Agent${i}`, ["idle"]),
    );
    const out = formatCurrentAgentStateSection(snapshots);
    const renderedLines = out.split("\n").filter((l) => l.startsWith("- "));
    // Approx 4 chars per token, default budget 400 tokens, ~1600 chars.
    // Each line is ~50-70 chars, so roughly 20-30 lines fit; far less
    // than 50.
    expect(renderedLines.length).toBeLessThan(50);
    expect(renderedLines.length).toBeGreaterThan(0);
    expect(out.length).toBeLessThanOrEqual(
      DEFAULT_AGENT_CONTEXT_TOKEN_BUDGET * 4 + 200,
    );
  });
});

describe("generateProactiveStarter (Tau-5 starter generation)", () => {
  it("returns null when there are no agents", () => {
    expect(generateProactiveStarter([])).toBeNull();
  });

  it("returns the all_idle starter when nothing urgent surfaces", () => {
    const snapshots = [mkSnap("A", ["idle"]), mkSnap("B", ["idle"])];
    const starter = generateProactiveStarter(snapshots);
    expect(starter).not.toBeNull();
    expect(starter!.trigger).toBe("all_idle");
    expect(starter!.text.toLowerCase()).toContain("quiet");
  });

  it("returns the stuck_agent starter and names the first stuck agent", () => {
    const snapshots = [
      mkSnap("Cursor", ["stuck"], { current_work_summary: "failed harness boot" }),
      mkSnap("OpenClaw", ["idle"]),
    ];
    const starter = generateProactiveStarter(snapshots);
    expect(starter).not.toBeNull();
    expect(starter!.trigger).toBe("stuck_agent");
    expect(starter!.text).toContain("Cursor");
    expect(starter!.text.toLowerCase()).toContain("session state");
  });

  it("returns the pending_approvals starter when approvals are present", () => {
    const snapshots = [
      mkSnap("Cline", ["has_pending_approvals"]),
      mkSnap("OpenClaw", ["has_pending_approvals"]),
    ];
    const starter = generateProactiveStarter(snapshots);
    expect(starter).not.toBeNull();
    expect(starter!.trigger).toBe("pending_approvals");
    expect(starter!.triggered_agents_count).toBe(2);
    expect(starter!.text.toLowerCase()).toContain("walk through");
  });
});

describe("AgentContextCache lifecycle (Tau-5)", () => {
  it("refresh aggregates registry + audit-log data into per-agent snapshots", async () => {
    const records = [makeRecord("OpenClaw"), makeRecord("Cline")];
    const entries = [
      makeEntry("OpenClaw", "policy_change", 5 * 60 * 1000),
      makeEntry("OpenClaw", "composition_receipt_packed", 10 * 60 * 1000),
      makeEntry("Cline", "approval_request", 5 * 60 * 1000),
    ];
    const cache = new AgentContextCache({
      identityId: "op-1",
      agentRegistry: makeStubRegistry(records),
      auditLog: makeStubAuditLog(entries),
      clock: () => NOW,
    });
    const snaps = await cache.refresh();
    expect(snaps.length).toBe(2);
    const oc = snaps.find((s) => s.agent_id === "OpenClaw")!;
    const cl = snaps.find((s) => s.agent_id === "Cline")!;
    expect(oc.recent_audit_count_24h).toBe(2);
    expect(oc.recent_concordia_receipts_count_24h).toBe(1);
    expect(cl.state_flags).toContain("has_pending_approvals");
  });

  it("multi-fortress isolation: cache scoped to identityId does not surface other-fortress agents", async () => {
    // Registry returns records from BOTH fortresses but the cache filters
    // by identity_id. Stub mirrors the real InMemoryLocalAgentRegistry's
    // behavior of honoring the filter.
    const all = [
      makeRecord("OpenClaw", { identity_id: "op-1" }),
      makeRecord("LeakedAgent", { identity_id: "op-2" }),
    ];
    const filtering: HubAgentRegistrySource = {
      list: (filter) =>
        filter?.identity_id
          ? all.filter((r) => r.identity_id === filter.identity_id)
          : all.slice(),
      get: () => null,
      put: () => {},
      updateStatus: () => all[0]!,
      updatePolicyBinding: () => all[0]!,
      updateChannelTemplateBinding: () => all[0]!,
    };
    const cache = new AgentContextCache({
      identityId: "op-1",
      agentRegistry: filtering,
      auditLog: makeStubAuditLog([]),
      clock: () => NOW,
    });
    const snaps = await cache.refresh();
    expect(snaps.map((s) => s.agent_id)).toEqual(["OpenClaw"]);
    expect(snaps.find((s) => s.agent_id === "LeakedAgent")).toBeUndefined();
  });

  it("refresh failure returns [] and routes the error to onRefreshError; cache stays empty", async () => {
    const failingAuditLog = {
      query: vi.fn(async () => {
        throw new Error("audit-log io_failed");
      }),
    } as unknown as AuditLog;
    const onRefreshError = vi.fn();
    const cache = new AgentContextCache({
      identityId: "op-1",
      agentRegistry: makeStubRegistry([makeRecord("OpenClaw")]),
      auditLog: failingAuditLog,
      onRefreshError,
      clock: () => NOW,
    });
    const out = await cache.refresh();
    expect(out).toEqual([]);
    expect(onRefreshError).toHaveBeenCalledTimes(1);
    // The cache must keep returning [] from read() without a prior
    // successful refresh in flight.
    expect(cache.read()).toEqual([]);
  });

  it("observeChanges fires per successful refresh and unsubscribe stops the handler", async () => {
    const cache = new AgentContextCache({
      identityId: "op-1",
      agentRegistry: makeStubRegistry([makeRecord("OpenClaw")]),
      auditLog: makeStubAuditLog([]),
      clock: () => NOW,
    });
    const handler = vi.fn();
    const unsubscribe = cache.observeChanges(handler);
    await cache.refresh();
    expect(handler).toHaveBeenCalledTimes(1);
    unsubscribe();
    await cache.refresh();
    expect(handler).toHaveBeenCalledTimes(1);
  });
});

// ── Test helpers ─────────────────────────────────────────────────────────

function mkSnap(
  agentName: string,
  state_flags: AgentContextSnapshot["state_flags"],
  overrides: Partial<AgentContextSnapshot> = {},
): AgentContextSnapshot {
  return {
    agent_id: agentName,
    agent_name: agentName,
    template: "research",
    last_activity_at: new Date(NOW).toISOString(),
    current_work_summary: null,
    recent_audit_count_24h: 0,
    recent_egress_count_24h: 0,
    recent_concordia_receipts_count_24h: 0,
    recent_verascore_delta_24h: null,
    state_flags,
    ...overrides,
  };
}
