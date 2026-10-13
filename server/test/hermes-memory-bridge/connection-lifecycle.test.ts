import { describe, expect, it } from "vitest";
import {
  HERMES_MAX_CALL_RECORDS,
  HERMES_MEMORY_DENIAL_MESSAGE,
  HERMES_MAX_PUBLIC_CONNECTIONS,
  HERMES_SETTLING_RESERVE,
  HermesConnectionLifecycle,
  classifyHermesPublicFrameSummary,
  type HermesClassifiedPublicFrame,
  type HermesConnectionState,
  type HermesLifecycleAction,
  type HermesLifecycleEvent,
} from "../../src/hermes-memory-bridge/index.js";

const CONNECTION_STATES = [
  "UNKNOWN",
  "OPEN_IDLE",
  "OPEN_BUSY",
  "OPEN_IDLE_PEER_SHUTTING",
  "OPEN_BUSY_PEER_SHUTTING",
  "NODE_CLOSED",
] as const satisfies readonly HermesConnectionState[];

const CELL_EVENTS = [
  "accepted",
  "call",
  "cancel",
  "public_shutdown",
  "public_unparseable",
  "control_invalid",
  "relay_closed",
  "node_response_written",
  "node_close",
] as const;

type CellEventType = (typeof CELL_EVENTS)[number];

interface CellExpectation {
  readonly next: HermesConnectionState;
  readonly actions: readonly HermesLifecycleAction["type"][];
  readonly fatal?: string;
  readonly refusal?: string;
  readonly recordState?: string;
}

interface SetupResult {
  readonly lifecycle: HermesConnectionLifecycle;
  readonly recordId?: string;
}

const CELL_TABLE: Record<HermesConnectionState, Record<CellEventType, CellExpectation>> = {
  UNKNOWN: {
    accepted: { next: "OPEN_IDLE", actions: [] },
    call: { next: "UNKNOWN", actions: [], fatal: "unknown_connection" },
    cancel: { next: "UNKNOWN", actions: [], fatal: "unknown" },
    public_shutdown: { next: "UNKNOWN", actions: [], fatal: "unknown" },
    public_unparseable: { next: "UNKNOWN", actions: [], fatal: "unknown" },
    control_invalid: { next: "UNKNOWN", actions: [], fatal: "unknown" },
    relay_closed: { next: "UNKNOWN", actions: [], fatal: "closed_for_unknown_or_duplicate" },
    node_response_written: { next: "UNKNOWN", actions: [], refusal: "record_not_current" },
    node_close: { next: "UNKNOWN", actions: [] },
  },
  OPEN_IDLE: {
    accepted: { next: "OPEN_IDLE", actions: [], fatal: "duplicate_accepted" },
    call: { next: "OPEN_BUSY", actions: ["route_call"], recordState: "IN_FLIGHT" },
    cancel: { next: "OPEN_IDLE", actions: [] },
    public_shutdown: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [] },
    public_unparseable: { next: "NODE_CLOSED", actions: ["send_close"] },
    control_invalid: { next: "OPEN_IDLE", actions: [] },
    relay_closed: { next: "UNKNOWN", actions: [] },
    node_response_written: { next: "OPEN_IDLE", actions: [], refusal: "no_current_record" },
    node_close: { next: "NODE_CLOSED", actions: ["send_close"] },
  },
  OPEN_BUSY: {
    accepted: { next: "OPEN_BUSY", actions: [], fatal: "duplicate_accepted", recordState: "IN_FLIGHT" },
    call: { next: "OPEN_BUSY", actions: [], fatal: "second_call_forwarded", recordState: "IN_FLIGHT" },
    cancel: { next: "OPEN_BUSY", actions: ["deliver_control"], recordState: "IN_FLIGHT" },
    public_shutdown: { next: "OPEN_BUSY_PEER_SHUTTING", actions: ["deliver_control"], recordState: "IN_FLIGHT" },
    public_unparseable: { next: "NODE_CLOSED", actions: ["send_close"], recordState: "CLOSED_BY_NODE" },
    control_invalid: { next: "OPEN_BUSY", actions: [], recordState: "IN_FLIGHT" },
    relay_closed: { next: "UNKNOWN", actions: [], recordState: "CONNECTION_GONE" },
    node_response_written: { next: "OPEN_IDLE", actions: [] },
    node_close: { next: "NODE_CLOSED", actions: ["send_close"], recordState: "CLOSED_BY_NODE" },
  },
  OPEN_IDLE_PEER_SHUTTING: {
    accepted: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [], fatal: "duplicate_accepted" },
    call: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown" },
    cancel: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown" },
    public_shutdown: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown" },
    public_unparseable: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown" },
    control_invalid: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown" },
    relay_closed: { next: "UNKNOWN", actions: [] },
    node_response_written: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [], refusal: "no_current_record" },
    node_close: { next: "NODE_CLOSED", actions: ["send_close"] },
  },
  OPEN_BUSY_PEER_SHUTTING: {
    accepted: { next: "OPEN_BUSY_PEER_SHUTTING", actions: [], fatal: "duplicate_accepted", recordState: "IN_FLIGHT" },
    call: { next: "OPEN_BUSY_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown", recordState: "IN_FLIGHT" },
    cancel: { next: "OPEN_BUSY_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown", recordState: "IN_FLIGHT" },
    public_shutdown: { next: "OPEN_BUSY_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown", recordState: "IN_FLIGHT" },
    public_unparseable: { next: "OPEN_BUSY_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown", recordState: "IN_FLIGHT" },
    control_invalid: { next: "OPEN_BUSY_PEER_SHUTTING", actions: [], fatal: "event_after_peer_shutdown", recordState: "IN_FLIGHT" },
    relay_closed: { next: "UNKNOWN", actions: [], recordState: "CONNECTION_GONE" },
    node_response_written: { next: "OPEN_IDLE_PEER_SHUTTING", actions: [] },
    node_close: { next: "NODE_CLOSED", actions: ["send_close"], recordState: "CLOSED_BY_NODE" },
  },
  NODE_CLOSED: {
    accepted: { next: "NODE_CLOSED", actions: [], fatal: "duplicate_accepted", recordState: "CLOSED_BY_NODE" },
    call: { next: "NODE_CLOSED", actions: [], recordState: "CLOSED_BY_NODE" },
    cancel: { next: "NODE_CLOSED", actions: [], recordState: "CLOSED_BY_NODE" },
    public_shutdown: { next: "NODE_CLOSED", actions: [], recordState: "CLOSED_BY_NODE" },
    public_unparseable: { next: "NODE_CLOSED", actions: [], recordState: "CLOSED_BY_NODE" },
    control_invalid: { next: "NODE_CLOSED", actions: [], recordState: "CLOSED_BY_NODE" },
    relay_closed: { next: "UNKNOWN", actions: [], recordState: "CLOSED_BY_NODE" },
    node_response_written: { next: "NODE_CLOSED", actions: [], refusal: "record_not_current", recordState: "CLOSED_BY_NODE" },
    node_close: { next: "NODE_CLOSED", actions: [], recordState: "CLOSED_BY_NODE" },
  },
};

function eventFor(type: CellEventType, recordId: string | undefined): HermesLifecycleEvent {
  switch (type) {
    case "accepted":
      return { type, connectionId: "c1" };
    case "call":
      return { type, connectionId: "c1", requestId: "r-next", kind: "tools_call", valid: true };
    case "cancel":
      return { type, connectionId: "c1", mcpRequestId: "r1" };
    case "public_shutdown":
    case "public_unparseable":
    case "control_invalid":
    case "relay_closed":
      return { type, connectionId: "c1" };
    case "node_response_written":
      return { type, connectionId: "c1", recordId: recordId ?? "missing" };
    case "node_close":
      return { type, connectionId: "c1", reason: "unparseable_call" };
  }
}

function actionTypes(actions: readonly HermesLifecycleAction[]): readonly HermesLifecycleAction["type"][] {
  return actions.map((action) => action.type);
}

function expectedActionsFor(
  event: HermesLifecycleEvent,
  recordId: string | undefined,
  expectedTypes: readonly HermesLifecycleAction["type"][],
): readonly HermesLifecycleAction[] {
  if (expectedTypes.length === 0) return [];
  if (expectedTypes[0] === "route_call" && event.type === "call") {
    return [{ type: "route_call", connectionId: event.connectionId, recordId: recordId ?? "call-1", requestId: event.requestId, kind: event.kind }];
  }
  if (expectedTypes[0] === "deliver_control" && event.type === "cancel" && recordId !== undefined) {
    return [{ type: "deliver_control", connectionId: event.connectionId, recordId, requestId: event.mcpRequestId, control: "cancel" }];
  }
  if (expectedTypes[0] === "deliver_control" && event.type === "public_shutdown" && recordId !== undefined) {
    return [{ type: "deliver_control", connectionId: event.connectionId, recordId, requestId: "r1", control: "shutdown" }];
  }
  if (expectedTypes[0] === "send_close" && "connectionId" in event) {
    return [{ type: "send_close", connectionId: event.connectionId }];
  }
  return [];
}

function exactFrameActions(summary: Parameters<typeof classifyHermesPublicFrameSummary>[0], state: "idle" | "busy"): readonly HermesLifecycleAction[] {
  const classified = classifyHermesPublicFrameSummary(summary);
  if (state === "idle" && classified.type === "call") {
    if (classified.valid) {
      return [{ type: "route_call", connectionId: "c1", recordId: "call-1", requestId: classified.requestId, kind: classified.kind }];
    }
    return [
      {
        type: "send_fixed_denial",
        connectionId: "c1",
        recordId: "call-1",
        requestId: classified.requestId,
        message: HERMES_MEMORY_DENIAL_MESSAGE,
        responseClass: "immediate",
      },
    ];
  }
  if (state === "idle" && classified.type === "public_unparseable") return [{ type: "send_close", connectionId: "c1" }];
  if (state === "busy" && classified.type === "cancel") {
    return [{ type: "deliver_control", connectionId: "c1", recordId: "call-1", requestId: classified.mcpRequestId, control: "cancel" }];
  }
  if (state === "busy" && classified.type === "public_shutdown") {
    return [{ type: "deliver_control", connectionId: "c1", recordId: "call-1", requestId: "r1", control: "shutdown" }];
  }
  if (state === "busy" && classified.type === "public_unparseable") return [{ type: "send_close", connectionId: "c1" }];
  return [];
}

function firstRecordId(actions: readonly HermesLifecycleAction[]): string {
  const action = actions[0];
  if (action === undefined || !("recordId" in action)) throw new Error("expected record action");
  return action.recordId;
}

function setupState(state: HermesConnectionState): SetupResult {
  const lifecycle = new HermesConnectionLifecycle();
  if (state === "UNKNOWN") return { lifecycle };
  lifecycle.apply({ type: "accepted", connectionId: "c1" });
  if (state === "OPEN_IDLE") return { lifecycle };
  if (state === "OPEN_IDLE_PEER_SHUTTING") {
    lifecycle.apply({ type: "public_shutdown", connectionId: "c1" });
    return { lifecycle };
  }
  const call = lifecycle.apply({ type: "call", connectionId: "c1", requestId: "r1", kind: "tools_call", valid: true });
  const recordId = firstRecordId(call.actions);
  if (state === "OPEN_BUSY") return { lifecycle, recordId };
  if (state === "OPEN_BUSY_PEER_SHUTTING") {
    lifecycle.apply({ type: "public_shutdown", connectionId: "c1" });
    return { lifecycle, recordId };
  }
  lifecycle.apply({ type: "node_close", connectionId: "c1", reason: "unparseable_call" });
  return { lifecycle, recordId };
}

function busy(lifecycle: HermesConnectionLifecycle, connectionId: string, requestId: string): string {
  lifecycle.apply({ type: "accepted", connectionId });
  return firstRecordId(lifecycle.apply({ type: "call", connectionId, requestId, kind: "tools_call", valid: true }).actions);
}

describe("Hermes connection lifecycle table", () => {
  it("declares the full state and event cross product", () => {
    expect(Object.keys(CELL_TABLE).sort()).toEqual([...CONNECTION_STATES].sort());
    for (const state of CONNECTION_STATES) {
      expect(Object.keys(CELL_TABLE[state]).sort()).toEqual([...CELL_EVENTS].sort());
    }
  });

  it.each(CONNECTION_STATES.flatMap((state) => CELL_EVENTS.map((event) => [state, event] as const)))(
    "%s x %s follows the lifecycle table",
    (state, event) => {
      const { lifecycle, recordId } = setupState(state);
      const lifecycleEvent = eventFor(event, recordId);
      const result = lifecycle.apply(lifecycleEvent);
      const expected = CELL_TABLE[state][event];
      expect(actionTypes(result.actions)).toEqual(expected.actions);
      expect(result.actions).toEqual(expectedActionsFor(lifecycleEvent, recordId, expected.actions));
      expect(result.fatal?.reason).toBe(expected.fatal);
      expect(result.refusal?.reason).toBe(expected.refusal);
      expect(lifecycle.stateOf("c1")).toBe(expected.next);
      if (expected.recordState !== undefined && recordId !== undefined) {
        expect(lifecycle.recordsSnapshot().find((record) => record.id === recordId)?.state).toBe(expected.recordState);
      }
    },
  );

});

describe("Hermes lifecycle amendments", () => {
  it("accepts a deleted connection id as a new row and rejects only live duplicates", () => {
    const lifecycle = new HermesConnectionLifecycle();
    expect(lifecycle.apply({ type: "accepted", connectionId: "c1" }).fatal).toBeUndefined();
    expect(lifecycle.apply({ type: "accepted", connectionId: "c1" }).fatal?.reason).toBe("duplicate_accepted");
    lifecycle.apply({ type: "relay_closed", connectionId: "c1" });
    expect(lifecycle.apply({ type: "accepted", connectionId: "c1" }).fatal).toBeUndefined();
    expect(lifecycle.stateOf("c1")).toBe("OPEN_IDLE");
  });

  it("routes recoverable calls and denies invalid calls without retaining their record", () => {
    const lifecycle = new HermesConnectionLifecycle();
    lifecycle.apply({ type: "accepted", connectionId: "c1" });
    const invalid = lifecycle.apply({ type: "call", connectionId: "c1", requestId: "r1", kind: "tools_call", valid: false });
    expect(actionTypes(invalid.actions)).toEqual(["send_fixed_denial"]);
    expect(invalid.refusal?.reason).toBe("call_validation_failed");
    expect(lifecycle.recordCount).toBe(0);
    expect(lifecycle.stateOf("c1")).toBe("OPEN_IDLE");
  });

  it("allows the next call as soon as a response is handed to the writer", () => {
    const lifecycle = new HermesConnectionLifecycle();
    const first = busy(lifecycle, "c1", "r1");
    lifecycle.apply({ type: "node_response_written", connectionId: "c1", recordId: first });
    const second = lifecycle.apply({ type: "call", connectionId: "c1", requestId: "r2", kind: "tools_call", valid: true });
    expect(actionTypes(second.actions)).toEqual(["route_call"]);
  });

  it("delivers cancel only to the matching request and coalesces controls", () => {
    const lifecycle = new HermesConnectionLifecycle();
    const recordId = busy(lifecycle, "c1", "r1");
    expect(lifecycle.apply({ type: "cancel", connectionId: "c1", mcpRequestId: "other" }).actions).toEqual([]);
    const cancel = lifecycle.apply({ type: "cancel", connectionId: "c1", mcpRequestId: "r1" });
    expect(actionTypes(cancel.actions)).toEqual(["deliver_control"]);
    expect(lifecycle.apply({ type: "cancel", connectionId: "c1", mcpRequestId: "r1" }).actions).toEqual([]);
    const shutdown = lifecycle.apply({ type: "public_shutdown", connectionId: "c1" });
    expect(actionTypes(shutdown.actions)).toEqual(["deliver_control"]);
    expect(lifecycle.recordsSnapshot().find((record) => record.id === recordId)).toMatchObject({
      pendingCancel: true,
      pendingShutdown: true,
    });
  });

  it("uses only the two Node close reasons from the relay contract", () => {
    const reasons: HermesLifecycleEvent[] = [
      { type: "node_close", connectionId: "c1", reason: "unparseable_call" },
      { type: "node_close", connectionId: "c1", reason: "private_cap_overflow" },
    ];
    expect(reasons.map((event) => (event.type === "node_close" ? event.reason : ""))).toEqual(["unparseable_call", "private_cap_overflow"]);
  });

  it("shuts down attached and detached records once and stops later sends", () => {
    const lifecycle = new HermesConnectionLifecycle();
    const gone = busy(lifecycle, "gone", "r1");
    lifecycle.apply({ type: "relay_closed", connectionId: "gone" });
    const nodeClosed = busy(lifecycle, "node", "r2");
    lifecycle.apply({ type: "node_close", connectionId: "node", reason: "unparseable_call" });
    const alreadyShutdown = busy(lifecycle, "peer", "r3");
    lifecycle.apply({ type: "public_shutdown", connectionId: "peer" });
    const attached = busy(lifecycle, "busy", "r4");
    const shutdown = lifecycle.apply({ type: "relay_shutdown_or_eof" });
    const reached = new Set(shutdown.actions.map((action) => ("recordId" in action ? action.recordId : "")));
    expect(reached.has(gone)).toBe(true);
    expect(reached.has(nodeClosed)).toBe(true);
    expect(reached.has(attached)).toBe(true);
    expect(reached.has(alreadyShutdown)).toBe(false);
    expect(shutdown.actions).toEqual([
      { type: "deliver_control", connectionId: "gone", recordId: gone, requestId: "r1", control: "shutdown" },
      { type: "deliver_control", connectionId: "node", recordId: nodeClosed, requestId: "r2", control: "shutdown" },
      { type: "deliver_control", connectionId: "busy", recordId: attached, requestId: "r4", control: "shutdown" },
    ]);
    expect(lifecycle.recordsSnapshot().every((record) => record.state === "SHUT_DOWN")).toBe(true);
    expect(lifecycle.apply({ type: "call", connectionId: "busy", requestId: "later", kind: "hello", valid: true }).actions).toEqual([]);
    expect(lifecycle.apply({ type: "public_unparseable", connectionId: "busy" }).actions).toEqual([]);
  });

  it("admits a call when live closed rows and settling records remain under the total cap", () => {
    const lifecycle = new HermesConnectionLifecycle();
    for (let i = 1; i <= HERMES_SETTLING_RESERVE - 1; i += 1) {
      busy(lifecycle, `gone-${i}`, `gone-${i}`);
      lifecycle.apply({ type: "relay_closed", connectionId: `gone-${i}` });
    }
    busy(lifecycle, "closed-live", "closed-live");
    lifecycle.apply({ type: "node_close", connectionId: "closed-live", reason: "private_cap_overflow" });
    lifecycle.apply({ type: "accepted", connectionId: "new" });
    const routed = lifecycle.apply({ type: "call", connectionId: "new", requestId: "new", kind: "hello", valid: true });
    expect(actionTypes(routed.actions)).toEqual(["route_call"]);
    expect(lifecycle.recordCount).toBe(HERMES_SETTLING_RESERVE + 1);
    expect(lifecycle.recordCount).toBeLessThanOrEqual(HERMES_MAX_CALL_RECORDS);
  });

  it("counts NODE_CLOSED rows against the live connection cap", () => {
    const lifecycle = new HermesConnectionLifecycle();
    for (let i = 1; i <= HERMES_MAX_PUBLIC_CONNECTIONS; i += 1) {
      busy(lifecycle, `closed-${i}`, `closed-${i}`);
      lifecycle.apply({ type: "node_close", connectionId: `closed-${i}`, reason: "unparseable_call" });
    }
    const fifth = lifecycle.apply({ type: "accepted", connectionId: "fifth" });
    expect(fifth.fatal?.reason).toBe("too_many_live");
    expect(lifecycle.liveCount).toBe(HERMES_MAX_PUBLIC_CONNECTIONS);
  });

  it("refuses the first accepted connection beyond the live cap", () => {
    const lifecycle = new HermesConnectionLifecycle();
    for (let i = 1; i <= HERMES_MAX_PUBLIC_CONNECTIONS; i += 1) {
      expect(lifecycle.apply({ type: "accepted", connectionId: `idle-${i}` }).fatal).toBeUndefined();
    }
    const fifth = lifecycle.apply({ type: "accepted", connectionId: "fifth" });
    expect(fifth.fatal?.reason).toBe("too_many_live");
    expect(lifecycle.liveCount).toBe(HERMES_MAX_PUBLIC_CONNECTIONS);
  });

  it("answers immediately without retaining a record at the total call-record cap", () => {
    const lifecycle = new HermesConnectionLifecycle();
    for (let i = 1; i <= HERMES_MAX_CALL_RECORDS; i += 1) {
      busy(lifecycle, `gone-${i}`, `gone-${i}`);
      lifecycle.apply({ type: "relay_closed", connectionId: `gone-${i}` });
    }
    lifecycle.apply({ type: "accepted", connectionId: "new" });
    const denied = lifecycle.apply({ type: "call", connectionId: "new", requestId: "new", kind: "tools_call", valid: true });
    expect(actionTypes(denied.actions)).toEqual(["send_fixed_denial"]);
    expect(denied.refusal?.reason).toBe("call_record_capacity");
    expect(lifecycle.recordCount).toBe(HERMES_MAX_CALL_RECORDS);
    expect(lifecycle.stateOf("new")).toBe("OPEN_IDLE");
  });

  it("keeps the total record cap continuous across live and settling calls", () => {
    const lifecycle = new HermesConnectionLifecycle();
    for (let i = 1; i <= HERMES_SETTLING_RESERVE - 1; i += 1) {
      busy(lifecycle, `gone-${i}`, `gone-${i}`);
      lifecycle.apply({ type: "relay_closed", connectionId: `gone-${i}` });
    }
    for (let i = 1; i <= HERMES_MAX_PUBLIC_CONNECTIONS; i += 1) {
      lifecycle.apply({ type: "accepted", connectionId: `live-${i}` });
      expect(actionTypes(lifecycle.apply({ type: "call", connectionId: `live-${i}`, requestId: `live-${i}`, kind: "tools_call", valid: true }).actions)).toEqual(["route_call"]);
    }
    for (let i = 1; i <= HERMES_MAX_PUBLIC_CONNECTIONS; i += 1) {
      lifecycle.apply({ type: "relay_closed", connectionId: `live-${i}` });
    }
    expect(lifecycle.recordCount).toBe(HERMES_MAX_CALL_RECORDS - 1);
    lifecycle.apply({ type: "accepted", connectionId: "eighth" });
    expect(actionTypes(lifecycle.apply({ type: "call", connectionId: "eighth", requestId: "eighth", kind: "tools_call", valid: true }).actions)).toEqual(["route_call"]);
    lifecycle.apply({ type: "accepted", connectionId: "ninth" });
    const denied = lifecycle.apply({ type: "call", connectionId: "ninth", requestId: "ninth", kind: "tools_call", valid: true });
    expect(actionTypes(denied.actions)).toEqual(["send_fixed_denial"]);
    expect(denied.refusal?.reason).toBe("call_record_capacity");
    expect(lifecycle.recordCount).toBe(HERMES_MAX_CALL_RECORDS);
  });

  it("requires a response event to name the current record", () => {
    const lifecycle = new HermesConnectionLifecycle();
    const first = busy(lifecycle, "c1", "r1");
    expect(actionTypes(lifecycle.release(first).actions)).toEqual(["send_fixed_denial"]);
    const second = firstRecordId(lifecycle.apply({ type: "call", connectionId: "c1", requestId: "r2", kind: "tools_call", valid: true }).actions);
    const stale = lifecycle.apply({ type: "node_response_written", connectionId: "c1", recordId: first });
    expect(stale.refusal?.reason).toBe("record_not_current");
    expect(lifecycle.stateOf("c1")).toBe("OPEN_BUSY");
    expect(lifecycle.recordsSnapshot().some((record) => record.id === second && record.state === "IN_FLIGHT")).toBe(true);
  });

  it("classifies public frames with the shared top-level scan result", () => {
    const rows: readonly [Parameters<typeof classifyHermesPublicFrameSummary>[0], HermesClassifiedPublicFrame["type"]][] = [
      [{ topLevelType: "hello", requestId: "a", strictValid: true }, "call"],
      [{ topLevelType: "tools_list", requestId: "a", strictValid: true }, "call"],
      [{ topLevelType: "tools_call", requestId: "a", strictValid: false }, "call"],
      [{ topLevelType: "tools_call", strictValid: true }, "public_unparseable"],
      [{ topLevelType: "cancel", mcpRequestId: "a", strictValid: true }, "cancel"],
      [{ topLevelType: "cancel", mcpRequestId: "a", strictValid: false }, "control_invalid"],
      [{ topLevelType: "cancel", strictValid: false }, "control_invalid"],
      [{ topLevelType: "shutdown", strictValid: true }, "public_shutdown"],
      [{ topLevelType: "shutdown", strictValid: false }, "control_invalid"],
      [{ topLevelType: "ping", strictValid: true }, "public_unparseable"],
      [{ topLevelType: "", strictValid: false }, "public_unparseable"],
    ];
    for (const [summary, expected] of rows) {
      expect(classifyHermesPublicFrameSummary(summary).type).toBe(expected);
    }
    const machineRows = [
      [{ topLevelType: "tools_call", requestId: "r9", strictValid: true }, ["route_call"], "second_call_forwarded"],
      [{ topLevelType: "tools_call", requestId: "r9", strictValid: false }, ["send_fixed_denial"], "second_call_forwarded"],
      [{ topLevelType: "cancel", mcpRequestId: "r1", strictValid: true }, [], ["deliver_control"]],
      [{ topLevelType: "cancel", mcpRequestId: "r1", strictValid: false }, [], []],
      [{ topLevelType: "shutdown", strictValid: true }, [], ["deliver_control"]],
      [{ topLevelType: "shutdown", strictValid: false }, [], []],
      [{ topLevelType: "?", strictValid: false }, ["send_close"], ["send_close"]],
    ] as const;
    for (const [summary, idleWant, busyWant] of machineRows) {
      for (const state of ["idle", "busy"] as const) {
        const lifecycle = new HermesConnectionLifecycle();
        lifecycle.apply({ type: "accepted", connectionId: "c1" });
        if (state === "busy") lifecycle.apply({ type: "call", connectionId: "c1", requestId: "r1", kind: "tools_call", valid: true });
        const result = lifecycle.apply({ ...classifyHermesPublicFrameSummary(summary), connectionId: "c1" } as HermesLifecycleEvent);
        const want = state === "idle" ? idleWant : busyWant;
        if (typeof want === "string") expect(result.fatal?.reason).toBe(want);
        else {
          expect(actionTypes(result.actions)).toEqual(want);
          expect(result.actions).toEqual(exactFrameActions(summary, state));
        }
      }
    }
  });

  it("keeps re-accepted rows detached from old records and returns a typed cap refusal", () => {
    const lifecycle = new HermesConnectionLifecycle();
    for (let i = 1; i <= HERMES_SETTLING_RESERVE; i += 1) {
      const recordId = busy(lifecycle, "reuse", `reuse-${i}`);
      lifecycle.apply({ type: "node_close", connectionId: "reuse", reason: "unparseable_call" });
      lifecycle.apply({ type: "relay_closed", connectionId: "reuse" });
      expect(lifecycle.recordsSnapshot().some((record) => record.id === recordId && record.state === "CLOSED_BY_NODE")).toBe(true);
    }
    lifecycle.apply({ type: "accepted", connectionId: "reuse" });
    expect(lifecycle.stateOf("reuse")).toBe("OPEN_IDLE");
    expect(lifecycle.recordsSnapshot().filter((record) => record.connectionId === "reuse" && record.state === "IN_FLIGHT")).toEqual([]);
    const oldRecord = lifecycle.recordsSnapshot().find((record) => record.connectionId === "reuse")?.id;
    expect(oldRecord).toBeDefined();
    expect(lifecycle.apply({ type: "node_response_written", connectionId: "reuse", recordId: oldRecord ?? "missing" }).refusal?.reason).toBe("no_current_record");
    expect(lifecycle.release(oldRecord ?? "missing").actions).toEqual([]);
    expect(lifecycle.stateOf("reuse")).toBe("OPEN_IDLE");
    expect(lifecycle.recordCount).toBe(HERMES_SETTLING_RESERVE - 1);

    for (let i = 1; i <= HERMES_SETTLING_RESERVE + 1; i += 1) {
      busy(lifecycle, `gone-${i}`, `gone-${i}`);
      lifecycle.apply({ type: "relay_closed", connectionId: `gone-${i}` });
    }
    lifecycle.apply({ type: "accepted", connectionId: "new" });
    expect(() => lifecycle.apply({ type: "call", connectionId: "new", requestId: "new", kind: "tools_call", valid: true })).not.toThrow();
    const denied = lifecycle.apply({ type: "call", connectionId: "new", requestId: "new-2", kind: "tools_call", valid: true });
    expect(denied.refusal?.reason).toBe("call_record_capacity");
    expect(lifecycle.stateOf("new")).toBe("OPEN_IDLE");
    expect(lifecycle.recordCount).toBe(HERMES_MAX_CALL_RECORDS);
  });

  it("release of a busy peer-shutting call keeps the peer-shutting state", () => {
    const lifecycle = new HermesConnectionLifecycle();
    const recordId = busy(lifecycle, "c1", "r1");
    lifecycle.apply({ type: "public_shutdown", connectionId: "c1" });
    expect(actionTypes(lifecycle.release(recordId).actions)).toEqual(["send_fixed_denial"]);
    expect(lifecycle.stateOf("c1")).toBe("OPEN_IDLE_PEER_SHUTTING");
    expect(lifecycle.apply({ type: "call", connectionId: "c1", requestId: "r2", kind: "tools_call", valid: true }).fatal?.reason).toBe("event_after_peer_shutdown");
  });

  it("releases settled records across repeated lifecycle paths", () => {
    const lifecycle = new HermesConnectionLifecycle();
    for (let i = 0; i < 2000; i += 1) {
      const connectionId = `c${i}`;
      const recordId = busy(lifecycle, connectionId, `r${i}`);
      switch (i % 5) {
        case 0:
          lifecycle.apply({ type: "node_response_written", connectionId, recordId });
          lifecycle.apply({ type: "relay_closed", connectionId });
          break;
        case 1:
          lifecycle.apply({ type: "node_close", connectionId, reason: "unparseable_call" });
          lifecycle.apply({ type: "relay_closed", connectionId });
          lifecycle.release(recordId);
          break;
        case 2:
          lifecycle.apply({ type: "relay_closed", connectionId });
          lifecycle.release(recordId);
          break;
        case 3:
          lifecycle.release(recordId);
          lifecycle.apply({ type: "call", connectionId, requestId: `bad-${i}`, kind: "hello", valid: false });
          lifecycle.apply({ type: "public_shutdown", connectionId });
          lifecycle.apply({ type: "relay_closed", connectionId });
          break;
        case 4:
          lifecycle.apply({ type: "public_shutdown", connectionId });
          lifecycle.apply({ type: "node_response_written", connectionId, recordId });
          lifecycle.apply({ type: "relay_closed", connectionId });
          break;
      }
    }
    expect([lifecycle.liveCount, lifecycle.recordCount]).toEqual([0, 0]);
  });

  it("keeps event fields required at the type boundary", () => {
    // @ts-expect-error call.valid is part of the lifecycle event contract.
    const missingValid: HermesLifecycleEvent = { type: "call", connectionId: "c1", requestId: "r1", kind: "tools_call" };
    // @ts-expect-error node_response_written.recordId is part of the lifecycle event contract.
    const missingRecordId: HermesLifecycleEvent = { type: "node_response_written", connectionId: "c1" };
    expect([missingValid, missingRecordId]).toHaveLength(2);
  });
});
