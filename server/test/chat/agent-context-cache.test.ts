/**
 * Sanctuary v1.3 WP-V1.3-9 Tau-5, agent-context cache unit tests
 *
 * Pure-function coverage for `agent-context-cache.ts`. Tests the
 * snapshot derivation, prompt-section rendering with token-budget
 * urgency-ordered prune, proactive starter generation, and the
 * cache's refresh / observe / fail-soft contracts.
 */

import { describe, it, expect, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
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
import type { AuditLog, AuditEntry } from "../../src/operational/audit-log.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import { protectionSubjectForUid } from "../../src/castle-wall/subject-binding.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../src/castle-wall/constants.js";

const NOW = new Date("2026-05-10T15:00:00.000Z").getTime();

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const producerPriv = ed25519.utils.randomPrivateKey();
const producerPubB64 = toBase64url(ed25519.getPublicKey(producerPriv));
const SIGNED_AT_MS = 1_777_777_777_777;
const FORTRESS_ID = "fortress:test";

function auditTokenForRuid(uid: number): string {
  const vals = [
    0xffffffff,
    uid,
    uid,
    uid,
    uid,
    0x00000269,
    0x000186ae,
    0x00000566,
  ];
  return vals
    .map((value) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
      return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    })
    .join("");
}

function withProducerSignature(
  entry: AuditEntry,
  identityId: string,
): AuditEntry {
  const seq = typeof entry.details?.seq === "number" ? entry.details.seq : 93;
  const body = JSON.stringify({
    timestamp: entry.timestamp,
    layer: entry.layer,
    operation: entry.operation,
    identity_id: identityId,
    result: entry.result,
    details: entry.details ?? {},
  });
  const sig = ed25519.sign(
    producerSigningBytes(body, SIGNED_AT_MS, seq),
    producerPriv,
  );
  return {
    ...entry,
    identity_id: identityId,
    details: {
      ...(entry.details ?? {}),
      seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  };
}

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
      withProducerSignature(
        makeEntry("OpenClaw", "policy_change", 5 * 60 * 1000),
        "OpenClaw",
      ),
      withProducerSignature(
        makeEntry("OpenClaw", "composition_receipt_packed", 30 * 60 * 1000),
        "OpenClaw",
      ),
      withProducerSignature(
        makeEntry("OpenClaw", "context_gate_filter", 60 * 60 * 1000),
        "OpenClaw",
      ),
      makeEntry("Cline", "policy_change", 5 * 60 * 1000), // owned by another agent
      makeEntry(null, "system_event", 5 * 60 * 1000), // unscoped
    ];
    const snap = buildSnapshot({
      record,
      recentEntries,
      nowMs: NOW,
      verascoreSource: undefined,
      auditAttribution: {
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: FORTRESS_ID,
      },
    });
    expect(snap.recent_audit_count_24h).toBe(3);
    expect(snap.recent_concordia_receipts_count_24h).toBe(1);
    expect(snap.recent_egress_count_24h).toBe(1);
    expect(snap.template).toBe("research");
    expect(snap.recent_verascore_delta_24h).toBeNull();
  });

  it("does not count forged unsigned Castle Wall evidence for a victim agent", () => {
    const record = makeRecord("victim-agent-b");
    const recentEntries: AuditEntry[] = [
      {
        timestamp: new Date(NOW - 5 * 60 * 1000).toISOString(),
        layer: "l1",
        operation: "egress_blocked",
        identity_id: "op-1",
        result: "success",
        details: {
          agent_id: "victim-agent-b",
          dest_host: "evil.example",
          dest_ip: "203.0.113.55",
          dest_port: 443,
          dest_protocol: "tcp",
        },
      },
    ];

    const snap = buildSnapshot({
      record,
      recentEntries,
      nowMs: NOW,
      verascoreSource: undefined,
    });

    expect(snap.recent_audit_count_24h).toBe(0);
    expect(snap.recent_egress_count_24h).toBe(0);
    expect(snap.current_work_summary).toBeNull();
  });

  it("counts legitimate producer-signed Castle Wall evidence when attribution context is supplied", () => {
    const record = makeRecord("victim-agent-b");
    const signed = withProducerSignature(
      {
        timestamp: new Date(NOW - 5 * 60 * 1000).toISOString(),
        layer: "l1",
        operation: "egress_blocked",
        identity_id: "victim-agent-b",
        result: "success",
        details: {
          agent_id: "victim-agent-b",
          agent_template: "claude-code",
          dest_host: "legitimate.example.com",
          dest_ip: "198.51.100.10",
          dest_port: 443,
          dest_protocol: "tcp",
        },
      },
      "victim-agent-b",
    );

    const snap = buildSnapshot({
      record,
      recentEntries: [signed],
      nowMs: NOW,
      verascoreSource: undefined,
      auditAttribution: {
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: FORTRESS_ID,
      },
    });

    expect(snap.recent_audit_count_24h).toBe(1);
    expect(snap.recent_egress_count_24h).toBe(1);
    expect(snap.current_work_summary).toBe("performed egress_blocked");
  });

  it("counts macOS producer-signed Castle Wall evidence by protection subject", () => {
    const protectionSubject = protectionSubjectForUid(FORTRESS_ID, 503);
    expect(protectionSubject).not.toBeNull();
    const record = makeRecord("victim-agent-b", {
      protection_subject: protectionSubject!,
    });
    const signed = withProducerSignature(
      {
        timestamp: new Date(NOW - 5 * 60 * 1000).toISOString(),
        layer: "l1",
        operation: "egress_blocked",
        identity_id: protectionSubject!,
        result: "success",
        details: {
          agent_id: auditTokenForRuid(503),
          agent_template: "claude-code",
          dest_host: "legitimate.example.com",
          dest_ip: "198.51.100.10",
          dest_port: 443,
          dest_protocol: "tcp",
        },
      },
      protectionSubject!,
    );

    const snap = buildSnapshot({
      record,
      recentEntries: [signed],
      nowMs: NOW,
      verascoreSource: undefined,
      auditAttribution: {
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: FORTRESS_ID,
      },
    });

    expect(snap.recent_audit_count_24h).toBe(1);
    expect(snap.recent_egress_count_24h).toBe(1);
    expect(snap.current_work_summary).toBe("performed egress_blocked");
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
      withProducerSignature(
        makeEntry("Cline", "approval_request", 10 * 60 * 1000),
        "Cline",
      ),
    ];
    const snap = buildSnapshot({
      record,
      recentEntries,
      nowMs: NOW,
      verascoreSource: undefined,
      auditAttribution: {
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: FORTRESS_ID,
      },
    });
    expect(snap.state_flags).toContain("has_pending_approvals");
  });

  it("derives current_work_summary from the most recent audit event", () => {
    const record = makeRecord("Cline");
    const recentEntries = [
      withProducerSignature(
        makeEntry("Cline", "policy_change", 1 * 60 * 60 * 1000),
        "Cline",
      ),
      withProducerSignature(
        makeEntry(
          "Cline",
          "composition_receipt_packed",
          5 * 60 * 1000,
          "failure",
        ),
        "Cline",
      ),
    ];
    const snap = buildSnapshot({
      record,
      recentEntries,
      nowMs: NOW,
      verascoreSource: undefined,
      auditAttribution: {
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: FORTRESS_ID,
      },
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
      withProducerSignature(
        makeEntry("OpenClaw", "policy_change", 5 * 60 * 1000),
        "OpenClaw",
      ),
      withProducerSignature(
        makeEntry("OpenClaw", "composition_receipt_packed", 10 * 60 * 1000),
        "OpenClaw",
      ),
      withProducerSignature(
        makeEntry("Cline", "approval_request", 5 * 60 * 1000),
        "Cline",
      ),
    ];
    const cache = new AgentContextCache({
      identityId: "op-1",
      agentRegistry: makeStubRegistry(records),
      auditLog: makeStubAuditLog(entries),
      resolveAuditAttribution: () => ({
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: FORTRESS_ID,
      }),
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
