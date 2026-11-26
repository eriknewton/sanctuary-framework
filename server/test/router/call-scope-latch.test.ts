/**
 * The router decides each call's outcome once. Every exit settles the call,
 * cancellation before the success commits makes the call refused, only a
 * committed success writes its success marker, and a cause noted inside the
 * call reaches the ledger once.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { getEventListeners } from "node:events";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { noteRefusalCause, type DenialCause, type DenialRecorder, type DenialRecordInput } from "../../src/agent-native/denial-ledger.js";
import { refusalResult } from "../../src/agent-native/safety-base.js";
import { AuditLog, CALL_OUTCOME_SUCCESS_OPERATION, type AuditEntry, type CallScopeHandle } from "../../src/operational/audit-log.js";
import type { ApprovalGate } from "../../src/principal-policy/gate.js";
import { createServer, toolResult, type ToolDefinition } from "../../src/router.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

// Every scope the router opens, so a test can read each call's terminal state.
const scopes = vi.hoisted(() => [] as CallScopeHandle[]);
vi.mock("../../src/operational/audit-log.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/operational/audit-log.js")>();
  return {
    ...actual,
    runInCallScope: <T>(fn: (scope: CallScopeHandle) => Promise<T>) => actual.runInCallScope((scope) => {
      scopes.push(scope);
      return fn(scope);
    }),
  };
});

type CallHandler = (request: unknown, extra: { signal: AbortSignal }) => Promise<unknown>;

interface Recorded {
  readonly cause: DenialCause;
  readonly input: DenialRecordInput;
}

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  vi.restoreAllMocks();
  scopes.length = 0;
});

function recorder(): { ledger: DenialRecorder; records: Recorded[] } {
  const records: Recorded[] = [];
  return { records, ledger: { record: (cause, input) => { records.push({ cause, input }); } } };
}

function tool(name: string, handler: ToolDefinition["handler"], extra: Partial<ToolDefinition> = {}): ToolDefinition {
  return { name, description: name, tool_class: "write", inputSchema: { type: "object", properties: {} }, handler, ...extra };
}

/** A gate that writes one own row per evaluation and allows unless told otherwise. */
function stubGate(auditLog: AuditLog, verdict: { allowed: boolean } = { allowed: true }): ApprovalGate {
  return {
    recordPreGateRefusal: async (operation: string) => {
      await auditLog.append("l2", `gate_deny:${operation}`, "system", {}, "failure");
    },
    evaluate: async (operation: string) => {
      await auditLog.append("l2", `gate_eval:${operation}`, "agent:unknown");
      return { allowed: verdict.allowed, approval_audit_id: "approval:fixture" };
    },
  } as unknown as ApprovalGate;
}

interface Rig {
  readonly auditLog: AuditLog;
  readonly records: Recorded[];
  readonly handler: CallHandler;
  readonly client: Client;
}

async function rig(tools: ToolDefinition[], opts: { gate?: (log: AuditLog) => ApprovalGate } = {}): Promise<Rig> {
  const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  const { ledger, records } = recorder();
  const server = createServer(tools, { auditLog, denialLedger: ledger, ...(opts.gate ? { gate: opts.gate(auditLog) } : {}) });
  const handler = (server as unknown as { _requestHandlers: Map<string, CallHandler> })._requestHandlers.get("tools/call")!;
  const client = new Client({ name: "call-scope-latch", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  cleanups.push(async () => { await client.close(); await server.close(); });
  return { auditLog, records, handler, client };
}

function request(name: string): unknown {
  return { method: "tools/call", params: { name, arguments: {} } };
}

async function rows(log: AuditLog): Promise<AuditEntry[]> {
  await log.flush();
  return (await log.query({ limit: 10_000, include_outcome_markers: true })).entries;
}

function markerRefs(entries: readonly AuditEntry[]): string[] {
  return entries.filter((e) => e.operation === CALL_OUTCOME_SUCCESS_OPERATION).map((e) => e.details!.call_ref as string);
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

async function until(predicate: () => boolean): Promise<void> {
  for (let i = 0; i < 2_000 && !predicate(); i++) await new Promise((r) => setImmediate(r));
  expect(predicate()).toBe(true);
}

describe("every exit settles the call once", () => {
  const cases: Array<{
    title: string;
    tools: (log: () => AuditLog) => ToolDefinition[];
    gate?: (log: AuditLog) => ApprovalGate;
    setup?: (r: Rig) => void;
    cause: DenialCause | null;
  }> = [
    {
      title: "a pre-gate refusal",
      tools: () => [tool("t", async () => toolResult({ ok: true }), { approvalTargetArgs: async () => { throw new Error("bad args"); } })],
      gate: (log) => stubGate(log),
      cause: "pre_gate_argument_refused",
    },
    {
      title: "a gate denial",
      tools: () => [tool("t", async () => toolResult({ ok: true }))],
      gate: (log) => stubGate(log, { allowed: false }),
      cause: "gate_denied",
    },
    {
      title: "a write stop",
      tools: () => [tool("t", async () => toolResult({ ok: true }))],
      gate: (log) => stubGate(log),
      setup: (r) => {
        vi.spyOn(r.auditLog, "getIntegrityFindings").mockResolvedValue([{ kind: "hash_mismatch", key: "k", message: "m" }] as never);
      },
      cause: "write_integrity_stop",
    },
    {
      title: "an integrity read fault",
      tools: () => [tool("t", async () => toolResult({ ok: true }))],
      gate: (log) => stubGate(log),
      setup: (r) => { vi.spyOn(r.auditLog, "getIntegrityFindings").mockRejectedValue(new Error("read fault")); },
      cause: "integrity_read_fault",
    },
    {
      title: "a handler throw",
      tools: () => [tool("t", async () => { throw new Error("handler fault"); })],
      gate: (log) => stubGate(log),
      cause: "handler_error",
    },
    {
      title: "a non-success body",
      tools: (log) => [tool("t", async () => { await log().append("l2", "own_row", "agent:unknown"); return toolResult({ error: "refused body" }); })],
      gate: (log) => stubGate(log),
      cause: "post_allow_refusal",
    },
    {
      title: "a success",
      tools: (log) => [tool("t", async () => { await log().append("l2", "own_row", "agent:unknown"); return toolResult({ ok: true }); })],
      gate: (log) => stubGate(log),
      cause: null,
    },
  ];

  for (const c of cases) {
    it(`${c.title} settles the call once, marks only a success and removes the abort listener`, async () => {
      let log!: AuditLog;
      const r = await rig(c.tools(() => log), c.gate ? { gate: c.gate } : {});
      log = r.auditLog;
      c.setup?.(r);
      const controller = new AbortController();
      const result = await r.handler(request("t"), { signal: controller.signal });
      expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
      expect(scopes.map((scope) => scope.state)).toEqual([c.cause === null ? "scope_SUCCEEDED" : "scope_REFUSED"]);
      const entries = await rows(r.auditLog);
      const callRefs = new Set(entries.map((e) => e.call_ref).filter((ref) => ref !== undefined));
      expect(callRefs.size).toBe(1);
      if (c.cause === null) {
        expect(result).toEqual(toolResult({ ok: true }));
        expect(markerRefs(entries)).toEqual([...callRefs]);
        expect(r.records).toEqual([]);
      } else {
        expect(result).toEqual(refusalResult());
        expect(markerRefs(entries)).toEqual([]);
        expect(r.records.map((rec) => rec.cause)).toEqual([c.cause]);
      }
    });
  }
});

describe("cancellation", () => {
  it("a cancelled call whose handler later succeeds is refused, writes no marker and records call_cancelled", async () => {
    let log!: AuditLog;
    const release = deferred();
    const entered = deferred();
    const r = await rig([tool("t", async () => {
      await log.append("l2", "own_row", "agent:unknown");
      entered.resolve();
      await release.promise;
      return toolResult({ ok: true });
    })]);
    log = r.auditLog;
    const controller = new AbortController();
    const pending = r.handler(request("t"), { signal: controller.signal });
    await entered.promise;
    expect(scopes.map((scope) => scope.state)).toEqual(["scope_OPEN"]);
    controller.abort();
    // Cancellation settles the call at once, before the handler returns.
    expect(scopes.map((scope) => scope.state)).toEqual(["scope_REFUSED"]);
    release.resolve();
    expect(await pending).toEqual(refusalResult());
    expect(markerRefs(await rows(log))).toEqual([]);
    expect(r.records.map((rec) => rec.cause)).toEqual(["call_cancelled"]);
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });

  it("an already-aborted signal makes the call refused", async () => {
    let log!: AuditLog;
    const r = await rig([tool("t", async () => { await log.append("l2", "own_row", "agent:unknown"); return toolResult({ ok: true }); })]);
    log = r.auditLog;
    const controller = new AbortController();
    controller.abort();
    expect(await r.handler(request("t"), { signal: controller.signal })).toEqual(refusalResult());
    expect(markerRefs(await rows(log))).toEqual([]);
    expect(r.records.map((rec) => rec.cause)).toEqual(["call_cancelled"]);
    expect(scopes.map((scope) => scope.state)).toEqual(["scope_REFUSED"]);
  });

  it("cancellation in repeated waves never pairs a refusal with a marker, at the handler and through the SDK", async () => {
    const WAVES = 3;
    const PER_WAVE = 8;
    let log!: AuditLog;
    let gates: Array<{ promise: Promise<void>; resolve: () => void }> = [];
    const signals: AbortSignal[] = [];
    let blocking = true;
    const r = await rig([tool("t", async (_args, _caller, context) => {
      await log.append("l2", "own_row", "agent:unknown");
      if (context?.signal) signals.push(context.signal);
      if (blocking) {
        const g = deferred();
        gates.push(g);
        await g.promise;
      }
      return toolResult({ ok: true });
    })]);
    log = r.auditLog;
    for (let wave = 0; wave < WAVES; wave++) {
      gates = [];
      signals.length = 0;
      blocking = true;
      const recordsBefore = r.records.length;
      const markersBefore = markerRefs(await rows(log)).length;
      // Half the wave at the request handler, half through the SDK with client-side cancellation.
      const controllers = Array.from({ length: PER_WAVE }, () => new AbortController());
      const direct = controllers.slice(0, PER_WAVE / 2).map((c) => r.handler(request("t"), { signal: c.signal }));
      const viaSdk = controllers.slice(PER_WAVE / 2).map((c) =>
        r.client.callTool({ name: "t", arguments: {} }, undefined, { signal: c.signal }).then(() => "resolved", () => "rejected"));
      await until(() => gates.length === PER_WAVE);
      for (const c of controllers) c.abort();
      await until(() => signals.length === PER_WAVE && signals.every((s) => s.aborted));
      for (const g of gates) g.resolve();
      for (const result of await Promise.all(direct)) expect(result).toEqual(refusalResult());
      expect(await Promise.all(viaSdk)).toEqual(Array(PER_WAVE / 2).fill("rejected"));
      await until(() => r.records.length - recordsBefore === PER_WAVE);
      expect(r.records.slice(recordsBefore).map((rec) => rec.cause)).toEqual(Array(PER_WAVE).fill("call_cancelled"));
      expect(markerRefs(await rows(log)).length).toBe(markersBefore);
      for (const s of signals) expect(getEventListeners(s, "abort")).toHaveLength(0);
      // The next calls in the same server still commit and mark.
      blocking = false;
      for (let i = 0; i < PER_WAVE; i++) {
        expect(await r.client.callTool({ name: "t", arguments: {} })).toEqual(toolResult({ ok: true }));
      }
      expect(markerRefs(await rows(log)).length).toBe(markersBefore + PER_WAVE);
    }
  });

  it("a client deadline reaches the call as cancellation and the call is refused", async () => {
    let log!: AuditLog;
    const release = deferred();
    let seen: AbortSignal | undefined;
    const r = await rig([tool("t", async (_args, _caller, context) => {
      seen = context?.signal;
      await log.append("l2", "own_row", "agent:unknown");
      await release.promise;
      return toolResult({ ok: true });
    })]);
    log = r.auditLog;
    await expect(r.client.callTool({ name: "t", arguments: {} }, undefined, { timeout: 20 })).rejects.toThrow();
    await until(() => seen?.aborted === true);
    release.resolve();
    await until(() => r.records.length === 1);
    expect(r.records.map((rec) => rec.cause)).toEqual(["call_cancelled"]);
    expect(markerRefs(await rows(log))).toEqual([]);
    expect(getEventListeners(seen!, "abort")).toHaveLength(0);
  });

  it("abort after commit stays success, one marker, the listener is removed", async () => {
    let log!: AuditLog;
    const r = await rig([tool("t", async () => { await log.append("l2", "own_row", "agent:unknown"); return toolResult({ ok: true }); })]);
    log = r.auditLog;
    // A throw between the settlement and the return, after the marker is enqueued.
    const queue = log as unknown as { enqueueAppend: (entry: unknown, options: { outcomeMarker?: true }) => Promise<void> };
    const original = queue.enqueueAppend.bind(log);
    vi.spyOn(queue, "enqueueAppend").mockImplementation((entry, options) => {
      const written = original(entry, options);
      if (options.outcomeMarker === true) throw new Error("injected fault after the marker");
      return written;
    });
    const controller = new AbortController();
    const result = await r.handler(request("t"), { signal: controller.signal });
    controller.abort();
    expect(result).toEqual(toolResult({ ok: true }));
    expect(markerRefs(await rows(log))).toHaveLength(1);
    expect(r.records).toEqual([]);
    expect(scopes.map((scope) => scope.state)).toEqual(["scope_SUCCEEDED"]);
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });
});

describe("rows of a refused call", () => {
  it("the router's own failure row in a refused call is stamped with the call reference", async () => {
    let log!: AuditLog;
    const r = await rig([tool("t", async () => { await log.append("l2", "own_row", "agent:unknown"); throw new Error("handler fault"); })]);
    log = r.auditLog;
    expect(await r.handler(request("t"), { signal: new AbortController().signal })).toEqual(refusalResult());
    const entries = await rows(log);
    const own = entries.find((e) => e.operation === "own_row")!;
    const failure = entries.find((e) => e.operation === "tool_error:t")!;
    expect(own.call_ref).toMatch(/^[0-9a-f]{16}$/);
    expect(failure.call_ref).toBe(own.call_ref);
    expect(r.records[0]!.input.linked_ref).toBe(failure.details!.audit_ref);
  });
});

describe("cause notes", () => {
  it("a noted cause reaches the ledger with its linked reference, the first note wins, and a call with no note records its stage cause", async () => {
    const r = await rig([
      tool("noted", async () => {
        noteRefusalCause("origin_unresolved", "ref:first");
        noteRefusalCause("export_capacity", "ref:second");
        return toolResult({ error: "refused body" });
      }),
      tool("plain", async () => toolResult({ error: "refused body" })),
    ]);
    const signal = new AbortController().signal;
    expect(await r.handler(request("noted"), { signal })).toEqual(refusalResult());
    expect(await r.handler(request("plain"), { signal })).toEqual(refusalResult());
    expect(r.records.map((rec) => [rec.cause, rec.input.tool, rec.input.linked_ref])).toEqual([
      ["origin_unresolved", "noted", "ref:first"],
      ["post_allow_refusal", "plain", undefined],
    ]);
  });

  it("a stage fault keeps its stage cause whatever was noted", async () => {
    const r = await rig([tool("t", async () => {
      noteRefusalCause("origin_unresolved", "ref:noted");
      throw new Error("handler fault");
    })]);
    expect(await r.handler(request("t"), { signal: new AbortController().signal })).toEqual(refusalResult());
    expect(r.records.map((rec) => rec.cause)).toEqual(["handler_error"]);
    expect(r.records[0]!.input.linked_ref).toMatch(/^audit:tool_error:/);
  });

  it("a note on a call that succeeds is discarded", async () => {
    const r = await rig([tool("t", async () => {
      noteRefusalCause("origin_unresolved", "ref:noted");
      return toolResult({ ok: true });
    })]);
    expect(await r.handler(request("t"), { signal: new AbortController().signal })).toEqual(toolResult({ ok: true }));
    expect(r.records).toEqual([]);
  });
});
