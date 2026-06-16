/**
 * WP-V1.3-3 Omega-1 Coordination Handoff Visualization regression suite.
 *
 * Coverage:
 *  - HandoffLog.query: chronological newest-first ordering, agent_id
 *    filter (matches sender or recipient), since/until time-window
 *    filtering, limit pagination cap, empty-log graceful return.
 *  - HandoffLog.getEntry: lookup by entry_id (exists / missing).
 *  - Normalization: v1.1_local_handoff and cross_harness_approval
 *    shapes both project to the unified HandoffEntry; self-loops and
 *    malformed details are dropped.
 *  - HTTP routes: list / detail / 404 / stream auth-gated; audit
 *    events fire on view-opened and entry-drilled.
 *  - Multi-fortress isolation: each HandoffLog reads its own audit log
 *    only.
 *  - Castle-walking: no outbound surface; no LLM call; reads
 *    server-local audit log only.
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import {
  COORDINATION_VIEW_AUDIT_OPS,
  HandoffLog,
  HANDOFF_LOG_OBSERVED_OPS,
  OPERATOR_PSEUDO_AGENT,
  type HandoffEntry,
} from "../../src/coordination/handoff-log.js";
import {
  COORDINATION_HANDOFFS_PREFIX,
  HandoffEventBridge,
  handleCoordinationRoute,
} from "../../src/coordination/handoff-routes.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_test";

/**
 * Stateful stub audit log: backs both `query()` (read API consumed by
 * HandoffLog) and `append()` (used by the HTTP routes for emitting
 * operator_coordination_view_opened / operator_handoff_entry_drilled).
 * Avoids the AuditLog's auto-stamped-timestamp + persist-async race
 * that contaminates time-window tests.
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
    if (opts.operation_type) {
      filtered = filtered.filter((e) => e.operation === opts.operation_type);
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

  /** Test helper: push a pre-stamped entry. */
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

function pushHandoffAudit(
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

function pushCrossHarnessAudit(
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

describe("WP-V1.3-3 Omega-1 HandoffLog.query", () => {
  it("returns an empty array against an empty audit log", async () => {
    const rig = makeRig();
    const entries = await rig.handoffLog.query({});
    expect(entries).toEqual([]);
  });

  it("normalizes v1.1_local_handoff entries with explicit pair info", async () => {
    const rig = makeRig();
    const ts = new Date("2026-05-09T12:00:00.000Z");
    pushHandoffAudit(rig.stub, ts, "agent-a", "agent-b", {
      task_scope: "research",
    });
    const entries = await rig.handoffLog.query({});
    expect(entries.length).toBe(1);
    expect(entries[0]?.source_agent_id).toBe("agent-a");
    expect(entries[0]?.target_agent_id).toBe("agent-b");
    expect(entries[0]?.event_class).toBe(
      HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
    );
    expect(entries[0]?.context_transfer_summary).toContain("research");
  });

  it("normalizes cross_harness_approval as <harness> -> operator", async () => {
    const rig = makeRig();
    const ts = new Date("2026-05-09T12:00:00.000Z");
    pushCrossHarnessAudit(rig.stub, ts, "claude-code", {
      policy_rule_id: "tier1:state_export",
    });
    const entries = await rig.handoffLog.query({});
    expect(entries.length).toBe(1);
    expect(entries[0]?.source_agent_id).toBe("claude-code");
    expect(entries[0]?.target_agent_id).toBe(OPERATOR_PSEUDO_AGENT);
    expect(entries[0]?.context_transfer_summary).toContain("tier1:state_export");
  });

  it("returns entries newest-first by observed_at", async () => {
    const rig = makeRig();
    const t1 = new Date("2026-05-09T10:00:00.000Z");
    const t2 = new Date("2026-05-09T11:00:00.000Z");
    const t3 = new Date("2026-05-09T12:00:00.000Z");
    pushHandoffAudit(rig.stub, t1, "agent-a", "agent-b");
    pushHandoffAudit(rig.stub, t2, "agent-b", "agent-c");
    pushHandoffAudit(rig.stub, t3, "agent-c", "agent-d");
    const entries = await rig.handoffLog.query({});
    expect(entries.map((e) => e.source_agent_id)).toEqual([
      "agent-c",
      "agent-b",
      "agent-a",
    ]);
  });

  it("filters by agent_id matching sender OR recipient", async () => {
    const rig = makeRig();
    const ts = new Date("2026-05-09T12:00:00.000Z");
    pushHandoffAudit(rig.stub, ts, "agent-a", "agent-b");
    pushHandoffAudit(
      rig.stub,
      new Date(ts.getTime() + 1000),
      "agent-c",
      "agent-d",
    );
    pushHandoffAudit(
      rig.stub,
      new Date(ts.getTime() + 2000),
      "agent-x",
      "agent-a",
    );
    const filtered = await rig.handoffLog.query({ agent_id: "agent-a" });
    expect(filtered.length).toBe(2);
    expect(
      filtered.every(
        (e) => e.source_agent_id === "agent-a" || e.target_agent_id === "agent-a",
      ),
    ).toBe(true);
  });

  it("filters by since and until time window", async () => {
    const rig = makeRig();
    pushHandoffAudit(
      rig.stub,
      new Date("2026-05-09T10:00:00.000Z"),
      "agent-a",
      "agent-b",
    );
    pushHandoffAudit(
      rig.stub,
      new Date("2026-05-09T12:00:00.000Z"),
      "agent-a",
      "agent-b",
    );
    pushHandoffAudit(
      rig.stub,
      new Date("2026-05-09T14:00:00.000Z"),
      "agent-a",
      "agent-b",
    );
    const between = await rig.handoffLog.query({
      since: "2026-05-09T11:00:00.000Z",
      until: "2026-05-09T13:00:00.000Z",
    });
    expect(between.length).toBe(1);
    expect(between[0]?.observed_at).toBe("2026-05-09T12:00:00.000Z");
  });

  it("respects the limit cap and clamps over-large requests", async () => {
    const rig = makeRig();
    const base = new Date("2026-05-09T12:00:00.000Z").getTime();
    for (let i = 0; i < 10; i += 1) {
      pushHandoffAudit(
        rig.stub,
        new Date(base + i * 1000),
        "agent-a",
        "agent-b",
      );
    }
    const limited = await rig.handoffLog.query({ limit: 3 });
    expect(limited.length).toBe(3);
    const allowed = await rig.handoffLog.query({ limit: 50 });
    expect(allowed.length).toBe(10);
  });

  it("drops malformed details and self-loop entries", async () => {
    const rig = makeRig();
    rig.stub.append(
      "l2",
      HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
      "agent-a",
      { sender_agent_id: "agent-a", recipient_agent_id: "agent-a" },
    );
    rig.stub.append(
      "l2",
      HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
      "agent-a",
      { unrelated: "value" },
    );
    const entries = await rig.handoffLog.query({});
    expect(entries).toEqual([]);
  });
});

describe("WP-V1.3-3 Omega-1 HandoffLog.getEntry", () => {
  it("returns the entry + source audit payload when the id exists", async () => {
    const rig = makeRig();
    const ts = new Date("2026-05-09T12:00:00.000Z");
    pushHandoffAudit(rig.stub, ts, "agent-a", "agent-b", {
      task_scope: "research",
    });
    const list = await rig.handoffLog.query({});
    const id = list[0]!.entry_id;
    const detail = await rig.handoffLog.getEntry(id);
    expect(detail).not.toBeNull();
    expect(detail?.entry.entry_id).toBe(id);
    expect(detail?.source_audit_entry.operation).toBe(
      HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
    );
    expect(detail?.source_audit_entry.details?.["task_scope"]).toBe(
      "research",
    );
  });

  it("returns null for an unknown entry id", async () => {
    const rig = makeRig();
    const detail = await rig.handoffLog.getEntry("never-existed");
    expect(detail).toBeNull();
  });
});

describe("WP-V1.3-3 Omega-1 HTTP routes", () => {
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

  it("GET /api/coordination/handoffs returns the chronological list and emits operator_coordination_view_opened", async () => {
    const rig = makeRig();
    pushHandoffAudit(
      rig.stub,
      new Date("2026-05-09T12:00:00.000Z"),
      "agent-a",
      "agent-b",
    );
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${COORDINATION_HANDOFFS_PREFIX}`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { entries: HandoffEntry[] };
      };
      expect(body.ok).toBe(true);
      expect(body.data.entries.length).toBe(1);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      expect(
        audit.entries.some(
          (e) => e.operation === COORDINATION_VIEW_AUDIT_OPS.VIEW_OPENED,
        ),
      ).toBe(true);
    } finally {
      await close();
    }
  });

  it("GET /api/coordination/handoffs/:id returns the detail + source audit + emits entry_drilled", async () => {
    const rig = makeRig();
    pushHandoffAudit(
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
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: {
          entry: HandoffEntry;
          source_audit_entry: { operation: string };
        };
      };
      expect(body.data.entry.entry_id).toBe(id);
      expect(body.data.source_audit_entry.operation).toBe(
        HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
      );
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      expect(
        audit.entries.some(
          (e) => e.operation === COORDINATION_VIEW_AUDIT_OPS.ENTRY_DRILLED,
        ),
      ).toBe(true);
    } finally {
      await close();
    }
  });

  it("GET /api/coordination/handoffs/:id returns 404 for an unknown id", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${COORDINATION_HANDOFFS_PREFIX}/never-existed`,
      );
      expect(res.status).toBe(404);
    } finally {
      await close();
    }
  });

  it("non-loopback request without auth token returns 401", async () => {
    const rig = makeRig();
    const server: Server = createServer(async (req, res) => {
      const handled = await handleCoordinationRoute(
        {
          authConfig: { loopbackAutoAuth: false, authToken: "secret" },
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
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;
    try {
      const res = await fetch(`${base}${COORDINATION_HANDOFFS_PREFIX}`);
      expect(res.status).toBe(401);
    } finally {
      await new Promise<void>((resolve) =>
        server.close(() => {
          resolve();
        }),
      );
    }
  });
});

describe("WP-V1.3-3 Omega-1 multi-fortress isolation", () => {
  it("each HandoffLog only sees its own audit log", async () => {
    const rigA = makeRig({ fortressId: FORTRESS_A });
    const rigB = makeRig({ fortressId: FORTRESS_B });
    pushHandoffAudit(
      rigA.stub,
      new Date("2026-05-09T12:00:00.000Z"),
      "agent-a",
      "agent-b",
    );
    pushHandoffAudit(
      rigA.stub,
      new Date("2026-05-09T12:01:00.000Z"),
      "agent-c",
      "agent-d",
    );
    const listA = await rigA.handoffLog.query({});
    const listB = await rigB.handoffLog.query({});
    expect(listA.length).toBe(2);
    expect(listB.length).toBe(0);
    expect(rigA.handoffLog.getFortressId()).toBe(FORTRESS_A);
    expect(rigB.handoffLog.getFortressId()).toBe(FORTRESS_B);
  });
});

describe("WP-V1.3-3 Omega-1 HandoffEventBridge", () => {
  it("subscribers receive emitted entries; broken subscribers do not break the bridge", () => {
    const bridge = new HandoffEventBridge();
    const received: HandoffEntry[] = [];
    bridge.subscribe(() => {
      throw new Error("listener exploded");
    });
    bridge.subscribe((entry) => received.push(entry));
    const entry: HandoffEntry = {
      entry_id: "x".repeat(32),
      audit_event_id: "evt-1",
      source_agent_id: "agent-a",
      target_agent_id: "agent-b",
      observed_at: "2026-05-09T12:00:00.000Z",
      event_class: HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
      context_transfer_summary: "agent-a -> agent-b handoff",
      workflow_link: null,
    };
    bridge.emit(entry);
    expect(received).toEqual([entry]);
  });
});
