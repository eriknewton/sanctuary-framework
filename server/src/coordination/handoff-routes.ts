/**
 * Sanctuary v1.3 WP-V1.3-3 Omega-1 Coordination handoff HTTP routes.
 *
 * Mounted under `/api/coordination/*`. Mirrors the Phi-1 sentinel
 * route module shape (Standing CTO call: follow Phi-1 sibling-view
 * pattern; spawn-prompt's `dashboard-handoff-view.ts` filename did
 * not exist on main, so the routes live under the
 * `coordination/` subsystem with the rest of the handoff machinery).
 *
 * Routes:
 *   GET    /api/coordination/handoffs              (chronological list, filtered)
 *   GET    /api/coordination/handoffs/stream       (SSE stream of new entries)
 *   GET    /api/coordination/handoffs/:entry_id    (full detail incl. source audit entry)
 *
 * Auth-gated via existing operator middleware. Multi-fortress
 * isolation enforced at the audit-log encryption boundary the
 * underlying HandoffLog reads through.
 *
 * Two new operator-action audit events fire on these routes:
 *  - `operator_coordination_view_opened` on the list route.
 *  - `operator_handoff_entry_drilled` on the detail route.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import { sendCaughtError } from "../http/error-envelope.js";
import type { AuditLog } from "../operational/audit-log.js";
import {
  COORDINATION_VIEW_AUDIT_OPS,
  type HandoffLog,
  type HandoffEntry,
} from "./handoff-log.js";
import {
  CONTEXT_TRANSFER_AUDIT_OPS,
  extractContextTransferBreakdown,
  type ContextTransferBreakdown,
  type ContextTransferExtractorDeps,
} from "./context-transfer-extractor.js";
import {
  groupHandoffsIntoWorkflows,
  type Workflow,
  type WorkflowState,
} from "./workflow-grouper.js";
import { WorkflowStateTracker } from "./workflow-state-tracker.js";

export const COORDINATION_API_PREFIX = "/api/coordination";
export const COORDINATION_HANDOFFS_PREFIX = "/api/coordination/handoffs";
export const COORDINATION_WORKFLOWS_PREFIX = "/api/coordination/workflows";

const COORDINATION_LIST_DEFAULT_LIMIT = 50;
const COORDINATION_LIST_MAX_LIMIT = 500;

export interface HandoffRouterDeps {
  authConfig: AuthConfig;
  handoffLog: HandoffLog;
  auditLog: AuditLog;
  /** Operator identity attribution for audit events emitted by these routes. */
  operatorId: string;
  /** In-process SSE event bridge; the route subscribes for fanout. */
  events: HandoffEventBridge;
  /**
   * v1.3 WP-V1.3-3 Omega-2 context-transfer extractor deps. Optional;
   * when provided, the detail route enriches its response with a
   * `context_transfer_breakdown` field. Backward-compatible: Omega-1
   * callers that ignore the field still work.
   */
  contextTransfer?: ContextTransferExtractorDeps;
  /**
   * v1.3 WP-V1.3-3 Omega-3 workflow state tracker. Optional; when
   * provided, the workflow routes emit
   * `coordination_workflow_state_changed` audit events as the
   * tracker observes state transitions. Backward-compatible: a route
   * call without a tracker still serves the list/detail/stream
   * responses without state-change emissions.
   */
  workflowStateTracker?: WorkflowStateTracker;
  /**
   * v1.3 WP-V1.3-3 Omega-3 clock provider for workflow-state
   * determination. Defaults to `Date.now()`-backed clock; tests
   * inject a fixed clock so stall/in-progress decisions are
   * deterministic.
   */
  now?: () => Date;
}

/**
 * In-process bridge that lets the dispatcher (or any other in-process
 * source) push handoff events to live SSE subscribers without
 * coupling the HandoffLog to a transport. The list route reads
 * historical state via HandoffLog.query(); the stream route subscribes
 * here for new entries.
 */
export class HandoffEventBridge {
  private readonly listeners = new Set<(entry: HandoffEntry) => void>();

  subscribe(listener: (entry: HandoffEntry) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(entry: HandoffEntry): void {
    for (const listener of this.listeners) {
      try {
        listener(entry);
      } catch {
        // Listener exceptions never fail the bridge.
      }
    }
  }
}

function writeJSON(
  res: ServerResponse,
  status: number,
  payload: unknown,
): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function parseLimit(
  raw: string | null,
  defaultValue: number,
  max: number,
): number {
  if (raw === null || raw === "") return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) return defaultValue;
  return Math.min(parsed, max);
}

function matchEntryRoute(path: string): { entryId: string } | null {
  const prefix = `${COORDINATION_HANDOFFS_PREFIX}/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0 || rest === "stream") return null;
  if (rest.includes("/")) return null;
  return { entryId: decodeURIComponent(rest) };
}

function matchWorkflowRoute(path: string): { workflowId: string } | null {
  const prefix = `${COORDINATION_WORKFLOWS_PREFIX}/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0 || rest === "stream") return null;
  if (rest.includes("/")) return null;
  return { workflowId: decodeURIComponent(rest) };
}

/**
 * Group + state-tag the current handoff log into workflows, then
 * route state transitions through the optional tracker. Shared by
 * list + stream + detail handlers so the same group computation
 * drives every workflow surface and the tracker sees every emission.
 */
async function computeWorkflowsAndTrackTransitions(
  deps: HandoffRouterDeps,
): Promise<{ workflows: Workflow[]; transitions: ReturnType<WorkflowStateTracker["observe"]> }> {
  const handoffs = await deps.handoffLog.query({ limit: 500 });
  const workflows = groupHandoffsIntoWorkflows(handoffs, {
    ...(deps.now !== undefined ? { now: deps.now() } : {}),
  });
  const transitions = deps.workflowStateTracker
    ? deps.workflowStateTracker.observe(workflows)
    : [];
  // Emit one `coordination_workflow_state_changed` audit event per
  // observed transition. Body carries `workflow_id`, the previous
  // state (or `unobserved` for first observation), the new state,
  // and the tracker's clock-stamped observation time. The body does
  // NOT carry raw handoff content; member-handoff details are
  // available through the detail route.
  for (const change of transitions) {
    void deps.auditLog.append(
      "l2",
      COORDINATION_VIEW_AUDIT_OPS.WORKFLOW_STATE_CHANGED,
      deps.operatorId,
      {
        fortress_id: deps.handoffLog.getFortressId(),
        workflow_id: change.workflow_id,
        previous_state: change.previous_state,
        new_state: change.new_state,
      },
    );
  }
  return { workflows, transitions };
}

function filterWorkflowList(
  workflows: Workflow[],
  opts: { state?: string; agentId?: string; since?: string; limit: number },
): Workflow[] {
  let filtered = workflows;
  if (opts.state) {
    filtered = filtered.filter((w) => w.state === opts.state);
  }
  if (opts.agentId) {
    filtered = filtered.filter((w) => w.involved_agents.includes(opts.agentId!));
  }
  if (opts.since) {
    filtered = filtered.filter((w) => w.last_activity_at >= opts.since!);
  }
  return filtered.slice(0, opts.limit);
}

function isWorkflowState(value: string): value is WorkflowState {
  return (
    value === "in_progress" ||
    value === "completed" ||
    value === "stalled" ||
    value === "unknown"
  );
}

async function handleWorkflowStream(
  deps: HandoffRouterDeps,
  res: ServerResponse,
): Promise<void> {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  // Snapshot first so the dashboard renders historical state before
  // any new handoff arrives. Tracker is observed once at connect so
  // initial states surface as transitions in the audit log; the
  // unsubscribe loop below feeds subsequent transitions.
  const initial = await computeWorkflowsAndTrackTransitions(deps);
  res.write(
    `event: workflow_snapshot\ndata: ${JSON.stringify({ workflows: initial.workflows })}\n\n`,
  );
  if (initial.transitions.length > 0) {
    res.write(
      `event: workflow_state_changed\ndata: ${JSON.stringify({ transitions: initial.transitions })}\n\n`,
    );
  }
  // Re-evaluate workflows whenever a new handoff is broadcast through
  // the HandoffEventBridge. Any state transitions get fanned out to
  // this SSE subscriber as a `workflow_state_changed` event and to
  // the audit log via the shared compute helper.
  const unsubscribe = deps.events.subscribe(() => {
    void (async () => {
      try {
        const tick = await computeWorkflowsAndTrackTransitions(deps);
        res.write(
          `event: workflow_snapshot\ndata: ${JSON.stringify({ workflows: tick.workflows })}\n\n`,
        );
        if (tick.transitions.length > 0) {
          res.write(
            `event: workflow_state_changed\ndata: ${JSON.stringify({ transitions: tick.transitions })}\n\n`,
          );
        }
      } catch {
        // emission errors never break the bridge subscription
      }
    })();
  });
  const cleanup = (): void => {
    unsubscribe();
  };
  res.on("close", cleanup);
  res.on("error", cleanup);
}

async function handleStream(
  deps: HandoffRouterDeps,
  res: ServerResponse,
): Promise<void> {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  // Send a snapshot of recent handoffs so the operator UI shows
  // historical context as soon as the stream connects.
  const snapshot = await deps.handoffLog.query({ limit: 50 });
  res.write(
    `event: handoff_snapshot\ndata: ${JSON.stringify({ entries: snapshot })}\n\n`,
  );
  const unsubscribe = deps.events.subscribe((entry) => {
    try {
      res.write(
        `event: handoff_added\ndata: ${JSON.stringify(entry)}\n\n`,
      );
    } catch {
      // socket gone; cleanup runs on close
    }
  });
  const keepAlive = setInterval(() => {
    try {
      res.write(": keepalive\n\n");
    } catch {
      // ignore
    }
  }, 25_000);
  const cleanup = (): void => {
    clearInterval(keepAlive);
    unsubscribe();
  };
  res.on("close", cleanup);
  res.on("error", cleanup);
}

/**
 * Handle a request against the coordination surface. Returns true
 * when served (including 4xx/5xx); returns false to let the caller
 * continue routing.
 */
export async function handleCoordinationRoute(
  deps: HandoffRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== COORDINATION_API_PREFIX &&
    !path.startsWith(`${COORDINATION_API_PREFIX}/`)
  ) {
    return false;
  }
  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  try {
    if (
      method === "GET" &&
      path === `${COORDINATION_HANDOFFS_PREFIX}/stream`
    ) {
      await handleStream(deps, res);
      return true;
    }

    if (method === "GET" && path === COORDINATION_HANDOFFS_PREFIX) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        COORDINATION_LIST_DEFAULT_LIMIT,
        COORDINATION_LIST_MAX_LIMIT,
      );
      const since = url.searchParams.get("since") ?? undefined;
      const until = url.searchParams.get("until") ?? undefined;
      const agentId = url.searchParams.get("agent_id") ?? undefined;
      const entries = await deps.handoffLog.query({
        limit,
        ...(since !== undefined ? { since } : {}),
        ...(until !== undefined ? { until } : {}),
        ...(agentId !== undefined ? { agent_id: agentId } : {}),
      });
      void deps.auditLog.append(
        "l2",
        COORDINATION_VIEW_AUDIT_OPS.VIEW_OPENED,
        deps.operatorId,
        {
          fortress_id: deps.handoffLog.getFortressId(),
          result_count: entries.length,
          ...(since !== undefined ? { since } : {}),
          ...(until !== undefined ? { until } : {}),
          ...(agentId !== undefined ? { agent_id: agentId } : {}),
        },
      );
      writeJSON(res, 200, { ok: true, data: { entries } });
      return true;
    }

    // v1.3 WP-V1.3-3 Omega-3 workflow routes.
    if (
      method === "GET" &&
      path === `${COORDINATION_WORKFLOWS_PREFIX}/stream`
    ) {
      await handleWorkflowStream(deps, res);
      return true;
    }
    if (method === "GET" && path === COORDINATION_WORKFLOWS_PREFIX) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        COORDINATION_LIST_DEFAULT_LIMIT,
        COORDINATION_LIST_MAX_LIMIT,
      );
      const rawState = url.searchParams.get("state");
      const state = rawState && isWorkflowState(rawState) ? rawState : undefined;
      const since = url.searchParams.get("since") ?? undefined;
      const agentId = url.searchParams.get("agent_id") ?? undefined;
      const computed = await computeWorkflowsAndTrackTransitions(deps);
      const filtered = filterWorkflowList(computed.workflows, {
        ...(state !== undefined ? { state } : {}),
        ...(agentId !== undefined ? { agentId } : {}),
        ...(since !== undefined ? { since } : {}),
        limit,
      });
      void deps.auditLog.append(
        "l2",
        COORDINATION_VIEW_AUDIT_OPS.WORKFLOW_VIEW_OPENED,
        deps.operatorId,
        {
          fortress_id: deps.handoffLog.getFortressId(),
          result_count: filtered.length,
          ...(state !== undefined ? { state } : {}),
          ...(agentId !== undefined ? { agent_id: agentId } : {}),
          ...(since !== undefined ? { since } : {}),
        },
      );
      writeJSON(res, 200, { ok: true, data: { workflows: filtered } });
      return true;
    }
    const workflowMatch = matchWorkflowRoute(path);
    if (method === "GET" && workflowMatch) {
      const computed = await computeWorkflowsAndTrackTransitions(deps);
      const wf = computed.workflows.find(
        (w) => w.workflow_id === workflowMatch.workflowId,
      );
      if (!wf) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      void deps.auditLog.append(
        "l2",
        COORDINATION_VIEW_AUDIT_OPS.WORKFLOW_DRILLED,
        deps.operatorId,
        {
          fortress_id: deps.handoffLog.getFortressId(),
          workflow_id: wf.workflow_id,
          state: wf.state,
          member_count: wf.member_handoffs.length,
          involved_agent_count: wf.involved_agents.length,
        },
      );
      writeJSON(res, 200, { ok: true, data: { workflow: wf } });
      return true;
    }

    const entryMatch = matchEntryRoute(path);
    if (method === "GET" && entryMatch) {
      const detail = await deps.handoffLog.getEntry(entryMatch.entryId);
      if (!detail) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      void deps.auditLog.append(
        "l2",
        COORDINATION_VIEW_AUDIT_OPS.ENTRY_DRILLED,
        deps.operatorId,
        {
          fortress_id: deps.handoffLog.getFortressId(),
          entry_id: detail.entry.entry_id,
          event_class: detail.entry.event_class,
          source_agent_id: detail.entry.source_agent_id,
          target_agent_id: detail.entry.target_agent_id,
        },
      );
      // v1.3 WP-V1.3-3 Omega-2: enrich the detail response with the
      // structured context-transfer breakdown when extractor deps are
      // wired. Backward-compatible: Omega-1 callers that ignore the
      // field still parse the response. Extractor failure is silent;
      // the operator still gets the underlying handoff detail.
      let breakdown: ContextTransferBreakdown | null = null;
      try {
        breakdown = await extractContextTransferBreakdown(
          detail,
          deps.contextTransfer ?? {},
        );
        void deps.auditLog.append(
          "l2",
          CONTEXT_TRANSFER_AUDIT_OPS.DECODED,
          deps.operatorId,
          {
            fortress_id: deps.handoffLog.getFortressId(),
            entry_id: detail.entry.entry_id,
            extractor_path: breakdown.source,
            confidence: breakdown.confidence,
            transferred_count: breakdown.transferred.length,
            withheld_count: breakdown.withheld.length,
          },
        );
      } catch {
        // Extractor failure is non-fatal; surface the base detail
        // and skip the audit emission.
      }
      const responseData =
        breakdown !== null
          ? { ...detail, context_transfer_breakdown: breakdown }
          : detail;
      writeJSON(res, 200, { ok: true, data: responseData });
      return true;
    }

    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    sendCaughtError(res, 500, "internal_error", err, {
      route: "coordination",
      operation: `${method} ${path}`,
    });
    return true;
  }
}
