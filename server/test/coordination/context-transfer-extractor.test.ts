/**
 * WP-V1.3-3 Omega-2 Per-handoff context-transfer breakdown regression suite.
 *
 * Coverage:
 *  - Path A (structured-source events): explicit transferred + withheld
 *    array shapes, category-keyed object shapes, mixed string + object
 *    entries.
 *  - Path B (composition events): receipt-references decomposition,
 *    payload-without-receipt fall-through to heuristic.
 *  - Path C (heuristic): cross_harness_approval policy_rule_id mapping,
 *    v1.1_local_handoff status-derived denial vs accepted.
 *  - LLM-assist fallback: substrate-classifier returns category;
 *    substrate failure degrades silent to heuristic.
 *  - HTTP route extension: detail response carries
 *    context_transfer_breakdown; emits audit event; backward-compat
 *    when extractor deps absent (operator gets the breakdown via the
 *    default-empty deps path; legacy clients ignore the new field).
 *  - Confidence scoring monotonicity: structured 1.0 > composition 0.9
 *    > llm-assist 0.6 > heuristic with category 0.5 > heuristic
 *    fallback 0.3.
 *  - Multi-fortress isolation: extractor produces per-handoff result;
 *    cross-fortress leakage requires audit-log access (which Omega-1
 *    already isolates).
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/l2-operational/audit-log.js";
import {
  HandoffLog,
  HANDOFF_LOG_OBSERVED_OPS,
  OPERATOR_PSEUDO_AGENT,
  type HandoffEntry,
  type HandoffEntryDetail,
} from "../../src/coordination/handoff-log.js";
import {
  COORDINATION_HANDOFFS_PREFIX,
  HandoffEventBridge,
  handleCoordinationRoute,
} from "../../src/coordination/handoff-routes.js";
import {
  CONTEXT_TRANSFER_AUDIT_OPS,
  extractContextTransferBreakdown,
  type ContextTransferBreakdown,
} from "../../src/coordination/context-transfer-extractor.js";
import type {
  SubstrateSelector,
} from "../../src/intelligence/selector.js";
import type {
  SubstrateResponse,
  ClassifyRequest,
  Surface,
} from "../../src/intelligence/types.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_test";

/**
 * Stateful stub audit log: backs both `query()` (HandoffLog reads)
 * and `append()` (route emissions). Mirrors the Omega-1 test pattern.
 */
class StubAuditLog {
  readonly entries: AuditEntry[] = [];

  async query(opts: {
    since?: string;
    layer?: AuditEntry["layer"];
    operation_type?: string;
    limit?: number;
  }): Promise<{ entries: AuditEntry[]; total: number }> {
    let filtered = this.entries;
    if (opts.since) {
      const sinceMs = Date.parse(opts.since);
      filtered = filtered.filter(
        (e) => Date.parse(e.timestamp) >= sinceMs,
      );
    }
    if (opts.layer) {
      filtered = filtered.filter((e) => e.layer === opts.layer);
    }
    const limit = opts.limit ?? 50;
    return { entries: filtered.slice(-limit), total: filtered.length };
  }

  append(
    layer: AuditEntry["layer"],
    operation: string,
    identityId: string,
    details?: Record<string, unknown>,
    result: AuditEntry["result"] = "success",
  ): void {
    this.entries.push({
      timestamp: new Date().toISOString(),
      layer,
      operation,
      identity_id: identityId,
      result,
      details,
    });
  }

  pushEntry(entry: AuditEntry): void {
    this.entries.push(entry);
  }

  async flush(): Promise<void> {
    /* no-op for stub */
  }
}

interface Rig {
  auditLog: AuditLog;
  stub: StubAuditLog;
  handoffLog: HandoffLog;
  events: HandoffEventBridge;
}

function makeRig(opts?: { fortressId?: string }): Rig {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const stub = new StubAuditLog();
  const auditLog = stub as unknown as AuditLog;
  const handoffLog = new HandoffLog({ auditLog, fortressId });
  const events = new HandoffEventBridge();
  return { auditLog, stub, handoffLog, events };
}

function pushHandoff(
  stub: StubAuditLog,
  ts: Date,
  sender: string,
  recipient: string,
  extra: Record<string, unknown> = {},
): void {
  stub.pushEntry({
    timestamp: ts.toISOString(),
    layer: "l2",
    operation: HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
    identity_id: sender,
    result: "success",
    details: {
      sender_agent_id: sender,
      recipient_agent_id: recipient,
      event_id: `evt-${ts.getTime()}-${sender}-${recipient}`,
      ...extra,
    },
  });
}

function pushCrossHarness(
  stub: StubAuditLog,
  ts: Date,
  sourceHarness: string,
  extra: Record<string, unknown> = {},
): void {
  stub.pushEntry({
    timestamp: ts.toISOString(),
    layer: "l2",
    operation: HANDOFF_LOG_OBSERVED_OPS.CROSS_HARNESS_APPROVAL,
    identity_id: "system",
    result: "success",
    details: {
      source_harness: sourceHarness,
      aggregator_id: `agg-${ts.getTime()}-${sourceHarness}`,
      ...extra,
    },
  });
}

function pushComposition(
  stub: StubAuditLog,
  ts: Date,
  sender: string,
  recipient: string,
  extra: Record<string, unknown> = {},
): void {
  stub.pushEntry({
    timestamp: ts.toISOString(),
    layer: "l2",
    operation: "composition_completed",
    identity_id: sender,
    result: "success",
    details: {
      sender_agent_id: sender,
      recipient_agent_id: recipient,
      event_id: `comp-${ts.getTime()}-${sender}-${recipient}`,
      ...extra,
    },
  });
}

/** Build a HandoffEntryDetail directly so tests don't depend on HandoffLog's audit-log query path. */
function mkDetail(
  source: string,
  target: string,
  operation: string,
  details: Record<string, unknown>,
): HandoffEntryDetail {
  const ts = "2026-05-09T12:00:00.000Z";
  const audit: AuditEntry = {
    timestamp: ts,
    layer: "l2",
    operation,
    identity_id: source,
    result: "success",
    details,
  };
  const entry: HandoffEntry = {
    entry_id: "x".repeat(32),
    audit_event_id: `evt-${operation}-${source}-${target}`,
    source_agent_id: source,
    target_agent_id: target,
    observed_at: ts,
    event_class: operation,
    context_transfer_summary: `${source} -> ${target}`,
    workflow_link: null,
  };
  return { entry, source_audit_entry: audit };
}

class StubSubstrate {
  classify_response: { category: string; confidence: number }[] = [];
  shouldThrow = false;
  invokeCount = 0;

  async invokeClassify(
    _surface: Surface,
    req: ClassifyRequest,
  ): Promise<SubstrateResponse> {
    void req;
    this.invokeCount += 1;
    if (this.shouldThrow) throw new Error("substrate exploded");
    return {
      servedBy: { backend: "local", model: "stub" } as never,
      failureClass: null,
      body: { kind: "classify", results: this.classify_response },
      completedAt: new Date().toISOString(),
      latencyMs: 1,
    };
  }
}

describe("WP-V1.3-3 Omega-2 Path A: structured-source events", () => {
  it("decomposes explicit transferred + withheld arrays of objects with full confidence", async () => {
    const detail = mkDetail("agent-a", "agent-b", "v1.1_local_handoff", {
      sender_agent_id: "agent-a",
      recipient_agent_id: "agent-b",
      transferred: [
        { category: "memory", summary: "research notes", size_hint: "medium" },
        { category: "plans", summary: "next steps", size_hint: "small" },
      ],
      withheld: [
        { category: "credentials", summary: "db_admin_token", size_hint: "minimal" },
      ],
    });
    const result = await extractContextTransferBreakdown(detail);
    expect(result.source).toBe("structured");
    expect(result.confidence).toBe(1.0);
    expect(result.transferred.length).toBe(2);
    expect(result.withheld.length).toBe(1);
    expect(result.transferred[0]?.category).toBe("memory");
    expect(result.withheld[0]?.category).toBe("credentials");
  });

  it("decomposes category-keyed object shape (transferred: { memory: [...], plans: [...] })", async () => {
    const detail = mkDetail("agent-a", "agent-b", "v1.1_local_handoff", {
      sender_agent_id: "agent-a",
      recipient_agent_id: "agent-b",
      transferred: {
        memory: ["research notes", "task history"],
        plans: ["next steps"],
      },
    });
    const result = await extractContextTransferBreakdown(detail);
    expect(result.source).toBe("structured");
    expect(result.confidence).toBe(1.0);
    expect(result.transferred.length).toBe(3);
    expect(
      result.transferred.filter((t) => t.category === "memory").length,
    ).toBe(2);
    expect(
      result.transferred.filter((t) => t.category === "plans").length,
    ).toBe(1);
  });

  it("decomposes mixed string + object entries in transferred arrays", async () => {
    const detail = mkDetail("agent-a", "agent-b", "v1.1_local_handoff", {
      sender_agent_id: "agent-a",
      recipient_agent_id: "agent-b",
      transferred: [
        "raw string -> 'other' category",
        { category: "outputs", summary: "result.json" },
      ],
      withheld: ["another string"],
    });
    const result = await extractContextTransferBreakdown(detail);
    expect(result.source).toBe("structured");
    expect(result.transferred.length).toBe(2);
    expect(result.transferred[0]?.category).toBe("other");
    expect(result.transferred[1]?.category).toBe("outputs");
    expect(result.withheld.length).toBe(1);
    expect(result.withheld[0]?.category).toBe("other");
  });
});

describe("WP-V1.3-3 Omega-2 Path B: composition events", () => {
  it("decomposes composition_completed via receipt-references graph", async () => {
    const detail = mkDetail("cline", "openclaw", "composition_completed", {
      sender_agent_id: "cline",
      recipient_agent_id: "openclaw",
      receipt: [
        { category: "memory", summary: "research_doc_v3", size_hint: "medium" },
      ],
      source_state_snapshot: [
        { category: "memory", summary: "research_doc_v3", size_hint: "medium" },
        { category: "credentials", summary: "github_token", size_hint: "minimal" },
      ],
    });
    const result = await extractContextTransferBreakdown(detail);
    expect(result.source).toBe("composition");
    expect(result.confidence).toBe(0.9);
    expect(result.transferred.length).toBe(1);
    expect(result.transferred[0]?.category).toBe("memory");
    expect(result.withheld.length).toBe(1);
    expect(result.withheld[0]?.category).toBe("credentials");
    expect(result.withheld[0]?.summary).toBe("github_token");
  });

  it("composition_completed without a receipt falls through to heuristic Path C", async () => {
    const detail = mkDetail("cline", "openclaw", "composition_completed", {
      sender_agent_id: "cline",
      recipient_agent_id: "openclaw",
    });
    const result = await extractContextTransferBreakdown(detail);
    expect(result.source).toBe("heuristic");
    expect(result.confidence).toBeLessThanOrEqual(0.5);
  });
});

describe("WP-V1.3-3 Omega-2 Path C: heuristic fallback", () => {
  it("derives transferred category from cross_harness_approval policy_rule_id (state_export -> outputs)", async () => {
    const detail = mkDetail(
      "claude-code",
      OPERATOR_PSEUDO_AGENT,
      "cross_harness_approval_aggregated",
      {
        source_harness: "claude-code",
        policy_rule_id: "tier1:state_export",
      },
    );
    const result = await extractContextTransferBreakdown(detail);
    expect(result.source).toBe("heuristic");
    expect(result.confidence).toBe(0.5);
    expect(result.transferred.length).toBe(1);
    expect(result.transferred[0]?.category).toBe("outputs");
    expect(result.withheld.length).toBe(0);
  });

  it("derives credentials category from broker_secret_read policy rule", async () => {
    const detail = mkDetail(
      "openclaw",
      OPERATOR_PSEUDO_AGENT,
      "cross_harness_approval_aggregated",
      {
        source_harness: "openclaw",
        policy_rule_id: "tier2:broker_secret_read",
      },
    );
    const result = await extractContextTransferBreakdown(detail);
    expect(result.source).toBe("heuristic");
    expect(result.transferred[0]?.category).toBe("credentials");
  });

  it("v1.1_local_handoff with new_status=denied populates withheld + reason_class", async () => {
    const detail = mkDetail("agent-a", "agent-b", "v1.1_local_handoff", {
      sender_agent_id: "agent-a",
      recipient_agent_id: "agent-b",
      new_status: "denied",
      reason_class: "policy_deny",
    });
    const result = await extractContextTransferBreakdown(detail);
    expect(result.source).toBe("heuristic");
    expect(result.confidence).toBe(0.5);
    expect(result.transferred.length).toBe(0);
    expect(result.withheld.length).toBe(1);
    expect(result.withheld[0]?.summary).toContain("policy_deny");
  });
});

describe("WP-V1.3-3 Omega-2 LLM-assist fallback", () => {
  it("invokes the substrate selector when the heuristic confidence is low and a selector is supplied", async () => {
    const detail = mkDetail("unknown-agent", "unknown-agent-b", "novel_event_class", {
      sender_agent_id: "unknown-agent",
      recipient_agent_id: "unknown-agent-b",
    });
    const stub = new StubSubstrate();
    stub.classify_response = [{ category: "memory", confidence: 0.85 }];
    const selector = stub as unknown as SubstrateSelector;
    const result = await extractContextTransferBreakdown(detail, {
      substrateSelector: selector,
    });
    expect(stub.invokeCount).toBe(1);
    expect(result.source).toBe("llm-assist");
    expect(result.confidence).toBe(0.6);
    expect(result.transferred.length).toBe(1);
    expect(result.transferred[0]?.category).toBe("memory");
  });

  it("substrate selector throwing degrades silent to the Path C heuristic result", async () => {
    const detail = mkDetail("unknown-agent", "unknown-agent-b", "novel_event_class", {
      sender_agent_id: "unknown-agent",
      recipient_agent_id: "unknown-agent-b",
    });
    const stub = new StubSubstrate();
    stub.shouldThrow = true;
    const selector = stub as unknown as SubstrateSelector;
    const result = await extractContextTransferBreakdown(detail, {
      substrateSelector: selector,
    });
    expect(result.source).toBe("heuristic");
    expect(result.confidence).toBe(0.3);
  });

  it("LLM-assist confidence below 0.4 is rejected; falls back to heuristic", async () => {
    const detail = mkDetail("unknown-agent", "unknown-agent-b", "novel_event_class", {
      sender_agent_id: "unknown-agent",
      recipient_agent_id: "unknown-agent-b",
    });
    const stub = new StubSubstrate();
    stub.classify_response = [{ category: "memory", confidence: 0.1 }];
    const selector = stub as unknown as SubstrateSelector;
    const result = await extractContextTransferBreakdown(detail, {
      substrateSelector: selector,
    });
    expect(result.source).toBe("heuristic");
  });
});

describe("WP-V1.3-3 Omega-2 confidence scoring", () => {
  it("orders confidence: structured 1.0 > composition 0.9 > llm-assist 0.6 > heuristic-with-match 0.5 > heuristic-fallback 0.3", async () => {
    const structured = await extractContextTransferBreakdown(
      mkDetail("a", "b", "v1.1_local_handoff", {
        sender_agent_id: "a",
        recipient_agent_id: "b",
        transferred: [{ category: "memory", summary: "x", size_hint: "small" }],
      }),
    );
    const composition = await extractContextTransferBreakdown(
      mkDetail("a", "b", "composition_completed", {
        sender_agent_id: "a",
        recipient_agent_id: "b",
        receipt: [{ category: "memory", summary: "x", size_hint: "small" }],
      }),
    );
    const heuristicMatch = await extractContextTransferBreakdown(
      mkDetail("a", OPERATOR_PSEUDO_AGENT, "cross_harness_approval_aggregated", {
        source_harness: "a",
        policy_rule_id: "tier1:state_export",
      }),
    );
    const heuristicFallback = await extractContextTransferBreakdown(
      mkDetail("a", "b", "novel_event_class", {
        sender_agent_id: "a",
        recipient_agent_id: "b",
      }),
    );
    expect(structured.confidence).toBeGreaterThan(composition.confidence);
    expect(composition.confidence).toBeGreaterThan(heuristicMatch.confidence);
    expect(heuristicMatch.confidence).toBeGreaterThan(
      heuristicFallback.confidence,
    );
  });
});

describe("WP-V1.3-3 Omega-2 HTTP route integration", () => {
  async function makeServer(rig: Rig): Promise<{
    base: string;
    close: () => Promise<void>;
  }> {
    const server: Server = createServer(async (req, res) => {
      const handled = await handleCoordinationRoute(
        {
          authConfig: { loopbackAutoAuth: true },
          handoffLog: rig.handoffLog,
          auditLog: rig.auditLog,
          operatorId: OPERATOR,
          events: rig.events,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const addr = server.address() as AddressInfo;
    return {
      base: `http://127.0.0.1:${addr.port}`,
      close: () =>
        new Promise<void>((resolve) =>
          server.close(() => {
            resolve();
          }),
        ),
    };
  }

  it("GET /api/coordination/handoffs/:id returns ContextTransferBreakdown alongside the source audit entry", async () => {
    const rig = makeRig();
    pushHandoff(
      rig.stub,
      new Date("2026-05-09T12:00:00.000Z"),
      "agent-a",
      "agent-b",
      {
        transferred: [
          { category: "memory", summary: "research", size_hint: "medium" },
        ],
        withheld: [
          { category: "credentials", summary: "db_token", size_hint: "minimal" },
        ],
      },
    );
    const list = await rig.handoffLog.query({});
    const id = list[0]!.entry_id;
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${COORDINATION_HANDOFFS_PREFIX}/${encodeURIComponent(id)}`,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: {
          entry: HandoffEntry;
          source_audit_entry: AuditEntry;
          context_transfer_breakdown?: ContextTransferBreakdown;
        };
      };
      expect(body.data.context_transfer_breakdown).toBeDefined();
      expect(body.data.context_transfer_breakdown?.source).toBe("structured");
      expect(body.data.context_transfer_breakdown?.confidence).toBe(1.0);
      expect(body.data.context_transfer_breakdown?.transferred.length).toBe(1);
      expect(body.data.context_transfer_breakdown?.withheld.length).toBe(1);
    } finally {
      await close();
    }
  });

  it("emits operator_handoff_context_transfer_decoded audit event on detail route", async () => {
    const rig = makeRig();
    pushCrossHarness(
      rig.stub,
      new Date("2026-05-09T12:00:00.000Z"),
      "claude-code",
      { policy_rule_id: "tier1:state_export" },
    );
    const list = await rig.handoffLog.query({});
    const id = list[0]!.entry_id;
    const { base, close } = await makeServer(rig);
    try {
      await fetch(
        `${base}${COORDINATION_HANDOFFS_PREFIX}/${encodeURIComponent(id)}`,
      );
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const decoded = audit.entries.filter(
        (e) => e.operation === CONTEXT_TRANSFER_AUDIT_OPS.DECODED,
      );
      expect(decoded.length).toBe(1);
      expect(decoded[0]?.details?.["extractor_path"]).toBe("heuristic");
      expect(decoded[0]?.details?.["transferred_count"]).toBe(1);
      expect(decoded[0]?.details?.["withheld_count"]).toBe(0);
    } finally {
      await close();
    }
  });

  it("backward-compatibility: response carries entry + source_audit_entry whether or not extractor produces a breakdown", async () => {
    const rig = makeRig();
    pushHandoff(
      rig.stub,
      new Date("2026-05-09T12:00:00.000Z"),
      "agent-a",
      "agent-b",
    );
    const list = await rig.handoffLog.query({});
    const id = list[0]!.entry_id;
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${COORDINATION_HANDOFFS_PREFIX}/${encodeURIComponent(id)}`,
      );
      const body = (await res.json()) as {
        ok: boolean;
        data: {
          entry: HandoffEntry;
          source_audit_entry: AuditEntry;
          context_transfer_breakdown?: ContextTransferBreakdown;
        };
      };
      expect(body.data.entry.entry_id).toBe(id);
      expect(body.data.source_audit_entry.operation).toBe(
        HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
      );
      // breakdown may or may not be present depending on extractor wiring;
      // the legacy fields are stable either way.
    } finally {
      await close();
    }
  });
});

describe("WP-V1.3-3 Omega-2 multi-fortress isolation", () => {
  it("each fortress's HandoffLog produces breakdowns only for entries it can see", async () => {
    const rigA = makeRig({ fortressId: FORTRESS_A });
    const rigB = makeRig({ fortressId: FORTRESS_B });
    pushHandoff(
      rigA.stub,
      new Date("2026-05-09T12:00:00.000Z"),
      "agent-a",
      "agent-b",
      { task_scope: "research", new_status: "accepted" },
    );
    const listA = await rigA.handoffLog.query({});
    const listB = await rigB.handoffLog.query({});
    expect(listA.length).toBe(1);
    expect(listB.length).toBe(0);
    const detailA = await rigA.handoffLog.getEntry(listA[0]!.entry_id);
    const detailFromBLookup = await rigB.handoffLog.getEntry(listA[0]!.entry_id);
    expect(detailA).not.toBeNull();
    expect(detailFromBLookup).toBeNull();
    const breakdown = await extractContextTransferBreakdown(detailA!);
    expect(breakdown.handoff_entry_id).toBe(listA[0]!.entry_id);
  });
});

describe("WP-V1.3-3 Omega-2 composition path scaffolding (audit-event + receipt round-trip)", () => {
  it("HandoffLog does NOT include composition_completed in its union (per Omega-1 deviation); extractor still works against direct details", async () => {
    const rig = makeRig();
    pushComposition(
      rig.stub,
      new Date("2026-05-09T12:00:00.000Z"),
      "cline",
      "openclaw",
      {
        receipt: [
          { category: "outputs", summary: "result.json", size_hint: "small" },
        ],
      },
    );
    // Verify Omega-1's deliberate scope: composition_completed isn't in
    // the HandoffLog union (would need a future iteration to extend).
    const list = await rig.handoffLog.query({});
    expect(list.length).toBe(0);
    // But the extractor itself handles the shape directly (Omega-2 ships
    // the path; the union extension is a forward-compat hook).
    const detail = mkDetail("cline", "openclaw", "composition_completed", {
      sender_agent_id: "cline",
      recipient_agent_id: "openclaw",
      receipt: [
        { category: "outputs", summary: "result.json", size_hint: "small" },
      ],
    });
    const breakdown = await extractContextTransferBreakdown(detail);
    expect(breakdown.source).toBe("composition");
    expect(breakdown.transferred[0]?.category).toBe("outputs");
  });
});
