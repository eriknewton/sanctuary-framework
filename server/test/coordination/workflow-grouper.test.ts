/**
 * WP-V1.3-3 Omega-3 Workflow grouping + state determination + HTTP routes regression suite.
 *
 * Coverage:
 *  - groupHandoffsIntoWorkflows: explicit workflow_link grouping;
 *    heuristic chain grouping; multi-hop chain stitching; root
 *    identification; multi-workflow disambiguation (handoffs more
 *    than 5 minutes apart fall into distinct workflows).
 *  - determineWorkflowState: completed (operator recipient + cycle
 *    closure), stalled (>2h since last activity), in_progress
 *    (recent), unknown (empty input).
 *  - HTTP routes: list, detail, stream, auth gate, 404 unknown id.
 *  - Workflow state-change audit emission (WORKFLOW_STATE_CHANGED).
 *  - Multi-fortress isolation.
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
  COORDINATION_WORKFLOWS_PREFIX,
  HandoffEventBridge,
  handleCoordinationRoute,
} from "../../src/coordination/handoff-routes.js";
import {
  groupHandoffsIntoWorkflows,
  determineWorkflowState,
  workflowIdFromRoot,
  type Workflow,
} from "../../src/coordination/workflow-grouper.js";
import { WorkflowStateTracker } from "../../src/coordination/workflow-state-tracker.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_test";
const NOW = new Date("2026-05-10T15:00:00.000Z");

/**
 * Stateful stub audit log: mirrors Omega-1's test stub. Backs both
 * `query()` (HandoffLog read) and `append()` (route audit emission).
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
      filtered = filtered.filter((e) => Date.parse(e.timestamp) >= sinceMs);
    }
    if (opts.layer) filtered = filtered.filter((e) => e.layer === opts.layer);
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

  pushEntry(entry: AuditEntry): void {
    this.entries.push(entry);
  }

  async flush(): Promise<void> {}
}

interface Rig {
  auditLog: AuditLog;
  stub: StubAuditLog;
  handoffLog: HandoffLog;
  events: HandoffEventBridge;
  tracker: WorkflowStateTracker;
}

function makeRig(opts?: { fortressId?: string }): Rig {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const stub = new StubAuditLog();
  const auditLog = stub as unknown as AuditLog;
  const handoffLog = new HandoffLog({ auditLog, fortressId });
  const events = new HandoffEventBridge();
  const tracker = new WorkflowStateTracker({ now: () => NOW });
  return { auditLog, stub, handoffLog, events, tracker };
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

/** Construct a synthetic HandoffEntry without going through audit log. */
function mkHandoff(opts: {
  entryId?: string;
  source: string;
  target: string;
  ageMs: number;
  workflowLink?: string | null;
}): HandoffEntry {
  return {
    entry_id: opts.entryId ?? `h-${opts.source}-${opts.target}-${opts.ageMs}`,
    audit_event_id: `evt-${opts.ageMs}`,
    source_agent_id: opts.source,
    target_agent_id: opts.target,
    observed_at: new Date(NOW.getTime() - opts.ageMs).toISOString(),
    event_class: HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
    context_transfer_summary: `${opts.source} -> ${opts.target}`,
    workflow_link: opts.workflowLink ?? null,
  };
}

// ── Grouping ─────────────────────────────────────────────────────────────

describe("WP-V1.3-3 Omega-3 groupHandoffsIntoWorkflows", () => {
  it("groups handoffs by explicit workflow_link when present", () => {
    const handoffs = [
      mkHandoff({ source: "a", target: "b", ageMs: 1000, workflowLink: "wf-1" }),
      mkHandoff({ source: "b", target: "c", ageMs: 500, workflowLink: "wf-1" }),
      mkHandoff({ source: "x", target: "y", ageMs: 200, workflowLink: "wf-2" }),
    ];
    const workflows = groupHandoffsIntoWorkflows(handoffs, { now: NOW });
    expect(workflows.length).toBe(2);
    const wf1 = workflows.find((w) =>
      w.member_handoffs.some((h) => h.workflow_link === "wf-1"),
    )!;
    expect(wf1.member_handoffs.length).toBe(2);
    expect(wf1.involved_agents).toContain("a");
    expect(wf1.involved_agents).toContain("c");
  });

  it("heuristically chains handoffs that share an agent within 5 minutes", () => {
    // Cline -> OpenClaw at t-3min, OpenClaw -> Cursor at t-1min: same chain.
    const handoffs = [
      mkHandoff({ source: "Cline", target: "OpenClaw", ageMs: 3 * 60 * 1000 }),
      mkHandoff({ source: "OpenClaw", target: "Cursor", ageMs: 60 * 1000 }),
    ];
    const workflows = groupHandoffsIntoWorkflows(handoffs, { now: NOW });
    expect(workflows.length).toBe(1);
    const wf = workflows[0]!;
    expect(wf.member_handoffs.length).toBe(2);
    expect(wf.involved_agents).toEqual(
      ["Cline", "Cursor", "OpenClaw"].sort(),
    );
    expect(wf.root_handoff.source_agent_id).toBe("Cline");
  });

  it("separates handoffs more than 5 minutes apart into distinct workflows", () => {
    const handoffs = [
      mkHandoff({ source: "a", target: "b", ageMs: 20 * 60 * 1000 }), // 20m ago
      mkHandoff({ source: "b", target: "c", ageMs: 60 * 1000 }),       // 1m ago
    ];
    const workflows = groupHandoffsIntoWorkflows(handoffs, { now: NOW });
    expect(workflows.length).toBe(2);
  });

  it("derives root from the oldest member; stable workflow_id from root entry_id", () => {
    const handoffs = [
      mkHandoff({ entryId: "root-id", source: "a", target: "b", ageMs: 4 * 60 * 1000 }),
      mkHandoff({ entryId: "h2", source: "b", target: "c", ageMs: 2 * 60 * 1000 }),
    ];
    const workflows = groupHandoffsIntoWorkflows(handoffs, { now: NOW });
    expect(workflows.length).toBe(1);
    const wf = workflows[0]!;
    expect(wf.root_handoff.entry_id).toBe("root-id");
    expect(wf.workflow_id).toBe(workflowIdFromRoot("root-id"));
  });
});

// ── State determination ─────────────────────────────────────────────────

describe("WP-V1.3-3 Omega-3 determineWorkflowState", () => {
  it("returns 'completed' when the last handoff is to the operator pseudo-agent", () => {
    const handoffs = [
      mkHandoff({ source: "a", target: "b", ageMs: 2 * 60 * 1000 }),
      mkHandoff({ source: "b", target: OPERATOR_PSEUDO_AGENT, ageMs: 60 * 1000 }),
    ];
    expect(determineWorkflowState(handoffs, NOW)).toBe("completed");
  });

  it("returns 'completed' on cycle closure (>2 hops returning to root agent)", () => {
    const handoffs = [
      mkHandoff({ source: "a", target: "b", ageMs: 4 * 60 * 1000 }),
      mkHandoff({ source: "b", target: "c", ageMs: 3 * 60 * 1000 }),
      mkHandoff({ source: "c", target: "d", ageMs: 2 * 60 * 1000 }),
      mkHandoff({ source: "d", target: "a", ageMs: 60 * 1000 }),
    ];
    expect(determineWorkflowState(handoffs, NOW)).toBe("completed");
  });

  it("returns 'stalled' when no activity has occurred for over 2 hours", () => {
    const handoffs = [
      mkHandoff({ source: "a", target: "b", ageMs: 3 * 60 * 60 * 1000 }),
    ];
    expect(determineWorkflowState(handoffs, NOW)).toBe("stalled");
  });

  it("returns 'in_progress' on recent activity without a completion signal", () => {
    const handoffs = [
      mkHandoff({ source: "a", target: "b", ageMs: 90 * 1000 }),
    ];
    expect(determineWorkflowState(handoffs, NOW)).toBe("in_progress");
  });

  it("returns 'unknown' on an empty member list", () => {
    expect(determineWorkflowState([], NOW)).toBe("unknown");
  });
});

// ── HTTP routes ──────────────────────────────────────────────────────────

describe("WP-V1.3-3 Omega-3 HTTP routes", () => {
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
          workflowStateTracker: rig.tracker,
          now: () => NOW,
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

  it("GET /api/coordination/workflows returns the workflow list + emits operator_workflow_view_opened", async () => {
    const rig = makeRig();
    pushHandoffAudit(rig.stub, new Date(NOW.getTime() - 60_000), "a", "b");
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${COORDINATION_WORKFLOWS_PREFIX}`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { workflows: Workflow[] };
      };
      expect(body.ok).toBe(true);
      expect(body.data.workflows.length).toBe(1);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      expect(
        audit.entries.some(
          (e) =>
            e.operation === COORDINATION_VIEW_AUDIT_OPS.WORKFLOW_VIEW_OPENED,
        ),
      ).toBe(true);
    } finally {
      await close();
    }
  });

  it("GET /api/coordination/workflows/:workflow_id returns detail + emits operator_workflow_drilled", async () => {
    const rig = makeRig();
    pushHandoffAudit(rig.stub, new Date(NOW.getTime() - 60_000), "a", "b");
    const handoffs = await rig.handoffLog.query({});
    const wfs = groupHandoffsIntoWorkflows(handoffs, { now: NOW });
    const id = wfs[0]!.workflow_id;
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${COORDINATION_WORKFLOWS_PREFIX}/${encodeURIComponent(id)}`,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { workflow: Workflow };
      };
      expect(body.data.workflow.workflow_id).toBe(id);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      expect(
        audit.entries.some(
          (e) => e.operation === COORDINATION_VIEW_AUDIT_OPS.WORKFLOW_DRILLED,
        ),
      ).toBe(true);
    } finally {
      await close();
    }
  });

  it("GET /api/coordination/workflows/:workflow_id returns 404 for an unknown id", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${COORDINATION_WORKFLOWS_PREFIX}/never-existed`,
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
          workflowStateTracker: rig.tracker,
          now: () => NOW,
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
      const res = await fetch(`${base}${COORDINATION_WORKFLOWS_PREFIX}`);
      expect(res.status).toBe(401);
    } finally {
      await new Promise<void>((resolve) =>
        server.close(() => {
          resolve();
        }),
      );
    }
  });

  it("emits coordination_workflow_state_changed on first observation of a workflow", async () => {
    const rig = makeRig();
    pushHandoffAudit(rig.stub, new Date(NOW.getTime() - 60_000), "a", "b");
    const { base, close } = await makeServer(rig);
    try {
      await fetch(`${base}${COORDINATION_WORKFLOWS_PREFIX}`);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const transitions = audit.entries.filter(
        (e) =>
          e.operation === COORDINATION_VIEW_AUDIT_OPS.WORKFLOW_STATE_CHANGED,
      );
      expect(transitions.length).toBe(1);
      expect(transitions[0]!.details?.previous_state).toBe("unobserved");
      expect(transitions[0]!.details?.new_state).toBe("in_progress");
    } finally {
      await close();
    }
  });

  it("emits another workflow_state_changed when state transitions (in_progress -> stalled)", async () => {
    // Push an old handoff so the workflow is initially stalled.
    const rig = makeRig();
    pushHandoffAudit(rig.stub, new Date(NOW.getTime() - 90 * 1000), "a", "b");
    const { base, close } = await makeServer(rig);
    try {
      // First call observes the workflow as in_progress.
      await fetch(`${base}${COORDINATION_WORKFLOWS_PREFIX}`);

      // Mutate the audit entry's timestamp so the same workflow is
      // now perceived as stalled (>2h old).
      const oldHandoff = rig.stub.entries.find(
        (e) => e.operation === HANDOFF_LOG_OBSERVED_OPS.LOCAL_HANDOFF,
      )!;
      oldHandoff.timestamp = new Date(
        NOW.getTime() - 3 * 60 * 60 * 1000,
      ).toISOString();

      // Second call should detect the in_progress -> stalled transition.
      await fetch(`${base}${COORDINATION_WORKFLOWS_PREFIX}`);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 200 });
      const transitions = audit.entries.filter(
        (e) =>
          e.operation === COORDINATION_VIEW_AUDIT_OPS.WORKFLOW_STATE_CHANGED,
      );
      expect(transitions.length).toBe(2);
      expect(transitions[1]!.details?.previous_state).toBe("in_progress");
      expect(transitions[1]!.details?.new_state).toBe("stalled");
    } finally {
      await close();
    }
  });
});

// ── Multi-fortress isolation ─────────────────────────────────────────────

describe("WP-V1.3-3 Omega-3 multi-fortress isolation", () => {
  it("each fortress's workflow surface reads its own audit log only", async () => {
    const rigA = makeRig({ fortressId: FORTRESS_A });
    const rigB = makeRig({ fortressId: FORTRESS_B });
    pushHandoffAudit(rigA.stub, new Date(NOW.getTime() - 60_000), "a", "b");
    pushHandoffAudit(rigA.stub, new Date(NOW.getTime() - 30_000), "b", "c");
    const handoffsA = await rigA.handoffLog.query({});
    const handoffsB = await rigB.handoffLog.query({});
    const wfA = groupHandoffsIntoWorkflows(handoffsA, { now: NOW });
    const wfB = groupHandoffsIntoWorkflows(handoffsB, { now: NOW });
    expect(wfA.length).toBe(1);
    expect(wfA[0]!.involved_agents).toEqual(["a", "b", "c"]);
    expect(wfB.length).toBe(0);
  });
});

// ── WorkflowStateTracker unit ────────────────────────────────────────────

describe("WP-V1.3-3 Omega-3 WorkflowStateTracker", () => {
  it("emits 'unobserved -> X' on the first observation, then no-op until state changes", () => {
    const tracker = new WorkflowStateTracker({ now: () => NOW });
    const wf: Workflow = {
      workflow_id: "w-1",
      root_handoff: mkHandoff({ source: "a", target: "b", ageMs: 60_000 }),
      member_handoffs: [
        mkHandoff({ source: "a", target: "b", ageMs: 60_000 }),
      ],
      state: "in_progress",
      started_at: new Date(NOW.getTime() - 60_000).toISOString(),
      last_activity_at: new Date(NOW.getTime() - 60_000).toISOString(),
      involved_agents: ["a", "b"],
    };
    const first = tracker.observe([wf]);
    expect(first.length).toBe(1);
    expect(first[0]!.previous_state).toBe("unobserved");
    expect(first[0]!.new_state).toBe("in_progress");

    const second = tracker.observe([wf]);
    expect(second.length).toBe(0);

    const stalled: Workflow = { ...wf, state: "stalled" };
    const third = tracker.observe([stalled]);
    expect(third.length).toBe(1);
    expect(third[0]!.previous_state).toBe("in_progress");
    expect(third[0]!.new_state).toBe("stalled");
  });
});
