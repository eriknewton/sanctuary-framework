/**
 * A call scope gives every audit row appended inside it the call's reference,
 * decides the call's outcome once, and marks a successful call with one
 * system row per audit log it wrote to. Readers leave those markers out
 * unless they ask for them.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  agentVisibleEntries,
  AuditLog,
  CALL_OUTCOME_SUCCESS_OPERATION,
  ReservedAuditOperationError,
  runInCallScope,
  settleCallOutcome,
  visibleCallRefs,
  writeCallOutcomeMarkers,
  type AuditEntry,
  type AuditEntryInput,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

type PrivateWrites = {
  writeAuditEntryBytes: (key: string, bytes: Uint8Array) => Promise<void>;
  writeHeadAnchor: (...args: unknown[]) => Promise<void>;
};

function freshLog(): { storage: MemoryStorage; masterKey: Uint8Array; log: AuditLog } {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  return { storage, masterKey, log: new AuditLog(storage, masterKey) };
}

async function allRows(log: AuditLog): Promise<AuditEntry[]> {
  return (await log.query({ limit: 10_000, include_outcome_markers: true })).entries;
}

function markers(rows: readonly AuditEntry[]): AuditEntry[] {
  return rows.filter((row) => row.operation === CALL_OUTCOME_SUCCESS_OPERATION);
}

function own(log: AuditLog, operation: string, details?: Record<string, unknown>): Promise<void> {
  return log.append("l2", operation, "agent:one", details);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("call reference stamp", () => {
  it("a row appended inside a call scope carries the call reference, and its identity and details are unchanged", async () => {
    const { log } = freshLog();
    let callRef = "";
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      await own(log, "op_in_call", { k: "v" });
      await log.appendCritical({ layer: "l1", operation: "critical_in_call", identity_id: "agent:one", result: "success" });
    });
    const rows = await allRows(log);
    expect(rows.map((row) => [row.operation, row.identity_id, row.details, row.call_ref])).toEqual([
      ["op_in_call", "agent:one", { k: "v" }, callRef],
      ["critical_in_call", "agent:one", undefined, callRef],
    ]);
  });

  it("a row appended outside any scope has no call reference", async () => {
    const { log } = freshLog();
    await own(log, "op_outside");
    const [row] = await allRows(log);
    expect(row).toBeDefined();
    expect(Object.hasOwn(row!, "call_ref")).toBe(false);
  });

  it("a caller-supplied call reference is never kept", async () => {
    const { log } = freshLog();
    const forged = { layer: "l2", operation: "forged", identity_id: "agent:one", result: "success", call_ref: "f".repeat(16) };
    await log.appendCritical(forged as unknown as AuditEntryInput);
    let inScopeRef = "";
    await runInCallScope(async (scope) => {
      inScopeRef = scope.call_ref;
      await log.appendCritical(forged as unknown as AuditEntryInput);
    });
    const rows = await allRows(log);
    expect(Object.hasOwn(rows[0]!, "call_ref")).toBe(false);
    expect(rows[1]!.call_ref).toBe(inScopeRef);
  });

  it("the call reference is taken when the caller appends, not when the queue drains", async () => {
    const { log } = freshLog();
    const writes = log as unknown as PrivateWrites;
    const original = writes.writeAuditEntryBytes.bind(log);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let blocked = false;
    vi.spyOn(writes, "writeAuditEntryBytes").mockImplementation(async (key, bytes) => {
      if (!blocked) {
        blocked = true;
        await gate;
      }
      return original(key, bytes);
    });
    let callRef = "";
    let pending!: Promise<void>;
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      pending = own(log, "queued_in_call");
      expect(settleCallOutcome(scope, "succeeded")).toBe("succeeded");
      writeCallOutcomeMarkers(scope);
    });
    release();
    await pending;
    await log.flush();
    const rows = await allRows(log);
    expect(rows.map((row) => row.operation)).toEqual(["queued_in_call", CALL_OUTCOME_SUCCESS_OPERATION]);
    expect(rows[0]!.call_ref).toBe(callRef);
    expect(rows[1]!.details).toEqual({ call_ref: callRef, outcome: "success" });
  });

  it("a row appended after its call settled keeps its call reference", async () => {
    const { log } = freshLog();
    let callRef = "";
    let late!: Promise<void>;
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      settleCallOutcome(scope, "refused");
      // Work the call scheduled runs after the call returned.
      late = new Promise<void>((resolve, reject) => {
        setTimeout(() => { own(log, "late_row").then(resolve, reject); }, 5);
      });
    });
    await late;
    const [row] = await allRows(log);
    expect(row!.call_ref).toBe(callRef);
  });

  it("a successful call whose only rows were appended after it settled gets no marker", async () => {
    const { log } = freshLog();
    await runInCallScope(async (scope) => {
      settleCallOutcome(scope, "succeeded");
      await own(log, "after_settle");
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    const rows = await allRows(log);
    expect(rows.map((row) => row.operation)).toEqual(["after_settle"]);
  });

  it("the call reference is sixteen lowercase hex characters, unique across a thousand calls", async () => {
    const refs = new Set<string>();
    for (let i = 0; i < 1_000; i++) {
      await runInCallScope(async (scope) => {
        expect(scope.call_ref).toMatch(/^[0-9a-f]{16}$/);
        refs.add(scope.call_ref);
      });
    }
    expect(refs.size).toBe(1_000);
  });
});

describe("call outcome latch", () => {
  it("the first settlement wins: a success after a refusal stays refused, and a refusal after a success stays succeeded", async () => {
    await runInCallScope(async (scope) => {
      expect(scope.state).toBe("scope_OPEN");
      expect(settleCallOutcome(scope, "refused")).toBe("refused");
      expect(settleCallOutcome(scope, "succeeded")).toBe("refused");
      expect(scope.state).toBe("scope_REFUSED");
    });
    await runInCallScope(async (scope) => {
      expect(settleCallOutcome(scope, "succeeded")).toBe("succeeded");
      expect(settleCallOutcome(scope, "refused")).toBe("succeeded");
      expect(scope.state).toBe("scope_SUCCEEDED");
    });
  });
});

describe("success markers", () => {
  it("a success writes one marker per log that stamped a row, and none for a log that stamped nothing", async () => {
    const a = freshLog();
    const b = freshLog();
    const c = freshLog();
    let callRef = "";
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      await own(a.log, "row_a1");
      await own(a.log, "row_a2");
      await own(b.log, "row_b");
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
    });
    await Promise.all([a.log.flush(), b.log.flush(), c.log.flush()]);
    for (const log of [a.log, b.log]) {
      const found = markers(await allRows(log));
      expect(found).toHaveLength(1);
      expect(found[0]).toMatchObject({
        layer: "l2",
        identity_id: "system",
        result: "success",
        details: { call_ref: callRef, outcome: "success" },
      });
      expect(Object.hasOwn(found[0]!, "call_ref")).toBe(false);
    }
    expect(await allRows(c.log)).toEqual([]);
  });

  it("writing markers twice for the same scope enqueues one marker per log", async () => {
    const { log } = freshLog();
    await runInCallScope(async (scope) => {
      await own(log, "row");
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    expect(markers(await allRows(log))).toHaveLength(1);
  });

  it("a refused scope writes no marker", async () => {
    const { log } = freshLog();
    await runInCallScope(async (scope) => {
      await own(log, "row");
      settleCallOutcome(scope, "refused");
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    expect(markers(await allRows(log))).toEqual([]);
  });

  it("the marker lands after every row of its call already enqueued when it was written", async () => {
    const { log } = freshLog();
    const pending: Array<Promise<void>> = [];
    await runInCallScope(async (scope) => {
      pending.push(own(log, "first"), own(log, "second"));
      const third = log.appendCritical({ layer: "l1", operation: "third", identity_id: "agent:one", result: "success" });
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
      await third;
    });
    await Promise.all(pending);
    await log.flush();
    expect((await allRows(log)).map((row) => row.operation))
      .toEqual(["first", "second", "third", CALL_OUTCOME_SUCCESS_OPERATION]);
  });

  it("a row its call appends after the marker keeps its reference and lands after the marker", async () => {
    // Its visibility once durable is witnessed under "agent visibility" below.
    const { log } = freshLog();
    let callRef = "";
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      await own(log, "before_marker");
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
      await own(log, "after_marker");
    });
    await log.flush();
    const rows = await allRows(log);
    expect(rows.map((row) => [row.operation, row.call_ref])).toEqual([
      ["before_marker", callRef],
      [CALL_OUTCOME_SUCCESS_OPERATION, undefined],
      ["after_marker", callRef],
    ]);
  });

  it("only the marker writer can append the outcome-marker operation", async () => {
    const { log } = freshLog();
    expect(() => log.append("l2", CALL_OUTCOME_SUCCESS_OPERATION, "system", { call_ref: "a".repeat(16), outcome: "success" }))
      .toThrow(ReservedAuditOperationError);
    expect(() => log.appendCritical({
      layer: "l2",
      operation: CALL_OUTCOME_SUCCESS_OPERATION,
      identity_id: "system",
      result: "success",
      details: { call_ref: "a".repeat(16), outcome: "success" },
    })).toThrow(ReservedAuditOperationError);
    await log.flush();
    expect(await allRows(log)).toEqual([]);
    expect(log.size).toBe(0);
  });
});

describe("default marker exclusion", () => {
  it("query leaves markers out unless asked, and queryEager follows the same default", async () => {
    const { log } = freshLog();
    await runInCallScope(async (scope) => {
      await own(log, "activity");
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    const plain = await log.query({ limit: 100 });
    expect(plain.entries.map((row) => row.operation)).toEqual(["activity"]);
    expect(plain.total).toBe(1);
    const eager = await log.queryEager({ limit: 100 });
    expect(eager.entries.map((row) => row.operation)).toEqual(["activity"]);
    expect(eager.total).toBe(1);
    const asked = await log.query({ limit: 100, include_outcome_markers: true });
    expect(asked.total).toBe(2);
    const eagerAsked = await log.queryEager({ limit: 100, include_outcome_markers: true });
    expect(eagerAsked.total).toBe(2);
  });
});

describe("marker faults and reopen", () => {
  it("a marker the store refuses before writing hides nothing it should show and writes one stderr line", async () => {
    const { log } = freshLog();
    const writes = log as unknown as PrivateWrites;
    const original = writes.writeAuditEntryBytes.bind(log);
    let failNext = false;
    vi.spyOn(writes, "writeAuditEntryBytes").mockImplementation(async (key, bytes) => {
      if (failNext) {
        failNext = false;
        throw new Error("injected store refusal");
      }
      return original(key, bytes);
    });
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const returned = await runInCallScope(async (scope) => {
      await own(log, "row_of_call");
      failNext = true;
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
      return "handler result";
    });
    expect(returned).toBe("handler result");
    await log.flush();
    await new Promise((resolve) => setImmediate(resolve));
    const rows = await allRows(log);
    expect(rows.map((row) => row.operation)).toEqual(["row_of_call"]);
    const lines = stderr.mock.calls.map((call) => call.join(" ")).filter((line) => line.includes(CALL_OUTCOME_SUCCESS_OPERATION));
    expect(lines).toEqual([`[audit-log] ${CALL_OUTCOME_SUCCESS_OPERATION} append failed`]);
  });

  it("a marker whose append rejects after its row is durable is a valid marker after reopen", async () => {
    const { storage, masterKey, log } = freshLog();
    const writes = log as unknown as PrivateWrites;
    const original = writes.writeHeadAnchor.bind(log);
    let failNext = false;
    vi.spyOn(writes, "writeHeadAnchor").mockImplementation(async (...args: unknown[]) => {
      if (failNext) {
        failNext = false;
        throw new Error("injected anchor failure");
      }
      return original(...args);
    });
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    let callRef = "";
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      await own(log, "row_of_call");
      failNext = true;
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    const reopened = new AuditLog(storage, masterKey);
    const result = await reopened.query({ limit: 100, include_outcome_markers: true });
    expect(result.integrity_findings).toEqual([]);
    expect(result.entries.map((row) => [row.operation, row.call_ref ?? row.details?.call_ref])).toEqual([
      ["row_of_call", callRef],
      [CALL_OUTCOME_SUCCESS_OPERATION, callRef],
    ]);
  });

  it("rows whose marker never landed carry no marker after reopen", async () => {
    const { storage, masterKey, log } = freshLog();
    let callRef = "";
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      await own(log, "row_one");
      await own(log, "row_two");
      // The process stops here: the call never reaches its marker.
    });
    await log.flush();
    const reopened = new AuditLog(storage, masterKey);
    const rows = await allRows(reopened);
    expect(rows.map((row) => [row.operation, row.call_ref])).toEqual([
      ["row_one", callRef],
      ["row_two", callRef],
    ]);
    expect(markers(rows)).toEqual([]);
  });

  it("a stored call reference and a stored marker survive reopen", async () => {
    const { storage, masterKey, log } = freshLog();
    let callRef = "";
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      await own(log, "row_of_call");
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    const before = await allRows(log);
    const reopened = new AuditLog(storage, masterKey);
    const after = await allRows(reopened);
    expect(after).toEqual(before);
    expect(after[0]!.call_ref).toBe(callRef);
    expect(markers(after)[0]!.details).toEqual({ call_ref: callRef, outcome: "success" });
  });
});

describe("agent visibility", () => {
  async function markedCall(log: AuditLog, operation: string, outcome: "succeeded" | "refused"): Promise<string> {
    let callRef = "";
    await runInCallScope(async (scope) => {
      callRef = scope.call_ref;
      await own(log, operation);
      settleCallOutcome(scope, outcome);
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    return callRef;
  }

  it("agent-visible query returns a stamped row only when its marker is in the retained window; an unstamped row is returned as today", async () => {
    const { log } = freshLog();
    await own(log, "outside");
    await markedCall(log, "succeeded_call", "succeeded");
    await markedCall(log, "refused_call", "refused");
    const visible = await log.query({ limit: 100, agent_visible: true });
    expect(visible.entries.map((row) => row.operation)).toEqual(["outside", "succeeded_call"]);
    const operator = await log.query({ limit: 100 });
    expect(operator.entries.map((row) => row.operation)).toEqual(["outside", "succeeded_call", "refused_call"]);
  });

  it("a normal row whose details carry a call reference makes nothing visible", async () => {
    const { log } = freshLog();
    const callRef = await markedCall(log, "refused_call", "refused");
    await log.append("l2", "lookalike", "system", { call_ref: callRef, outcome: "success" });
    await log.append("l2", "lookalike_agent", "agent:one", { call_ref: callRef, outcome: "success" });
    await log.flush();
    const visible = await log.query({ limit: 100, agent_visible: true });
    expect(visible.entries.map((row) => row.operation)).not.toContain("refused_call");
  });

  it("the visibility filter runs before the limit", async () => {
    const { log } = freshLog();
    await markedCall(log, "visible_row", "succeeded");
    for (let i = 0; i < 5; i++) await markedCall(log, `hidden_${i}`, "refused");
    const visible = await log.query({ limit: 1, agent_visible: true, identity_id: "agent:one" });
    expect(visible.entries.map((row) => row.operation)).toEqual(["visible_row"]);
  });

  it("every number query returns is taken after visibility", async () => {
    const { log } = freshLog();
    await markedCall(log, "visible_row", "succeeded");
    for (let i = 0; i < 3; i++) await markedCall(log, `hidden_${i}`, "refused");
    const visible = await log.query({ limit: 100, agent_visible: true, identity_id: "agent:one" });
    expect(visible.total).toBe(1);
    expect(visible.entries).toHaveLength(1);
  });

  it("retention that prunes a call's rows but keeps its marker exposes nothing", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    // Two retained rows: the call's last row and its marker survive, its first row is pruned.
    const log = new AuditLog(storage, masterKey, { maxEntries: 2, maxInMemoryEntries: 2 });
    await runInCallScope(async (scope) => {
      await own(log, "pruned_row");
      await own(log, "kept_row");
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    const raw = (await log.query({ limit: 100, include_outcome_markers: true })).entries.map((row) => row.operation);
    const visible = (await log.query({ limit: 100, agent_visible: true })).entries.map((row) => row.operation);
    for (const operation of visible) expect(raw).toContain(operation);
    expect(visible).not.toContain("pruned_row");
    expect(visible.every((operation) => operation === "kept_row")).toBe(true);
  });

  it("retention that prunes a marker but keeps a late row of its call hides that row", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const log = new AuditLog(storage, masterKey, { maxEntries: 2, maxInMemoryEntries: 2 });
    await runInCallScope(async (scope) => {
      await own(log, "in_call");
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
      await log.flush();
      await own(log, "late_row");
    });
    await own(log, "outside");
    await log.flush();
    const raw = (await log.query({ limit: 100, include_outcome_markers: true })).entries.map((row) => row.operation);
    expect(raw).toEqual(["late_row", "outside"]);
    const visible = (await log.query({ limit: 100, agent_visible: true })).entries.map((row) => row.operation);
    expect(visible).toEqual(["outside"]);
  });

  it("the visibility rule reads each retained row at most twice", () => {
    const WINDOW = 1_000;
    const rows: AuditEntry[] = Array.from({ length: WINDOW }, (_, i) => i % 3 === 0
      ? { timestamp: "t", layer: "l2", operation: CALL_OUTCOME_SUCCESS_OPERATION, identity_id: "system", result: "success", details: { call_ref: `ref-${i}`, outcome: "success" } }
      : { timestamp: "t", layer: "l2", operation: "row", identity_id: "agent:one", result: "success", call_ref: `ref-${i - (i % 3)}` });
    let reads = 0;
    const counted = new Proxy(rows, {
      get(target, property, receiver) {
        if (typeof property === "string" && /^\d+$/.test(property)) reads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    const visible = agentVisibleEntries(counted);
    expect(reads).toBeLessThanOrEqual(2 * WINDOW);
    expect(visibleCallRefs(rows).size).toBeLessThanOrEqual(WINDOW);
    expect(visible).toHaveLength(WINDOW);
  });

  it("a marker written by one AuditLog instance makes the rows visible to an agent reader on another instance over the same storage", async () => {
    const { storage, masterKey, log } = freshLog();
    await markedCall(log, "cross_instance", "succeeded");
    const reader = new AuditLog(storage, masterKey);
    const visible = await reader.query({ limit: 100, agent_visible: true });
    expect(visible.entries.map((row) => row.operation)).toEqual(["cross_instance"]);
  });

  it("a reader instance never shows a stamped row whose marker is not yet persisted", async () => {
    const { storage, masterKey, log } = freshLog();
    const reader = new AuditLog(storage, masterKey);
    await runInCallScope(async (scope) => {
      await own(log, "not_yet_marked");
      expect((await reader.query({ limit: 100, agent_visible: true })).entries).toEqual([]);
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
    });
    await log.flush();
    expect((await reader.query({ limit: 100, agent_visible: true })).entries.map((row) => row.operation)).toEqual(["not_yet_marked"]);
  });

  it("a row its call appends after the marker is visible once durable, and a late row of a refused call stays hidden", async () => {
    const { log } = freshLog();
    let lateSucceeded!: Promise<void>;
    let lateRefused!: Promise<void>;
    await runInCallScope(async (scope) => {
      await own(log, "succeeded_call");
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
      lateSucceeded = new Promise<void>((resolve, reject) => { setTimeout(() => { own(log, "late_of_success").then(resolve, reject); }, 5); });
    });
    await runInCallScope(async (scope) => {
      await own(log, "refused_call");
      settleCallOutcome(scope, "refused");
      lateRefused = new Promise<void>((resolve, reject) => { setTimeout(() => { own(log, "late_of_refusal").then(resolve, reject); }, 5); });
    });
    await Promise.all([lateSucceeded, lateRefused]);
    await log.flush();
    expect((await log.query({ limit: 100, agent_visible: true })).entries.map((row) => row.operation))
      .toEqual(["succeeded_call", "late_of_success"]);
  });
});
