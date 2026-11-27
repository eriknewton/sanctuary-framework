/**
 * The events cursor table is bounded and releases what it reserves: at most 64
 * cursors and at most 64 opens in flight per server, a reservation is promoted
 * only while it is still held, live and unexpired, an evicted or cancelled
 * reservation releases its slot and its abort listener, and every refusal is
 * the one refusal with its own operator cause.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { getEventListeners } from "node:events";
import { recordingNamespaceInserts } from "../helpers/cooperative-test-options.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog, readCallScopeNote, runInCallScope } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { toolResult, type ToolDefinition } from "../../src/router.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { ApprovalProofStore, fingerprintIdentityId, fixedDenial, type SessionBinding } from "../../src/agent-native/safety-base.js";

// A test can make the next cursor id repeat an earlier one; every other random draw is the real one.
const forcedCursorId = vi.hoisted(() => ({ value: undefined as Buffer | undefined }));
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  const randomBytes = ((size: number, ...rest: unknown[]) =>
    size === 12 && forcedCursorId.value !== undefined
      ? Buffer.from(forcedCursorId.value)
      : (actual.randomBytes as (...args: unknown[]) => Buffer)(size, ...rest)) as typeof actual.randomBytes;
  return { ...actual, randomBytes };
});

// Must match the events cursor's bounds in agent-native/cooperative-surface.ts.
const MAX_OPEN_CURSORS = 64;
const MAX_READS = 10;
const CURSOR_TTL_MS = 900_000;
const OPERATION_MAX_CHARS = 128;
const OPEN = "sanctuary_events_open_cursor";
const REFUSAL = toolResult(fixedDenial());

afterEach(() => { vi.restoreAllMocks(); });

async function setup() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  let active: SessionBinding | undefined;
  const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(stateStore, storage, masterKey, "recovery-key", auditLog,
    { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => active });
  await identityManager.load();
  const created = JSON.parse((await l1Tools.find((t) => t.name === "identity_create")!.handler({ label: "cursor-table" })).content[0]!.text);
  const identityId = created.identity_id as string;
  active = { identity_id: identityId, requester_identity_fingerprint: fingerprintIdentityId(identityId) };
  const clock = { now: 1_800_000_000_000 };
  const factory = () => createAgentNativeCooperativeTools({
    now: () => clock.now,
    baselineNamespaceInserts: recordingNamespaceInserts(),
    identityManager,
    namespaceRegistry,
    auditLog,
    currentSessionBinding: () => active,
    primitiveTools: l1Tools,
    storage,
    approvalProofStore: new ApprovalProofStore(),
  });
  const { tools, eventCursorTable } = factory();
  const tool = (name: string, from: ToolDefinition[] = tools): ToolDefinition => from.find((t) => t.name === name)!;
  /** Run one handler inside its own call scope, returning the body and the cause it noted. */
  const call = async (name: string, args: Record<string, unknown> = {}, signal?: AbortSignal, from: ToolDefinition[] = tools) =>
    runInCallScope(async (scope) => {
      const result = await tool(name, from).handler(args, "agent:cursor-table", signal ? { signal } : {});
      return { result, body: JSON.parse(result.content[0]!.text) as Record<string, unknown>, cause: readCallScopeNote(scope)?.cause };
    });
  const open = async (signal?: AbortSignal) => (await call(OPEN, {}, signal)).body.cursor as string | undefined;
  return { auditLog, identityId, clock, factory, tools, eventCursorTable, call, open };
}

/** Holds each cursor open's own audit append while `holding` is set, until released. */
function holdOpenAudits(log: AuditLog) {
  const held: Array<() => void> = [];
  const state = { holding: true };
  const appendCritical = log.appendCritical.bind(log);
  vi.spyOn(log, "appendCritical").mockImplementation(async (entry) => {
    if (entry.operation === OPEN && state.holding) await new Promise<void>((release) => { held.push(release); });
    return appendCritical(entry);
  });
  return {
    state,
    held: () => held.length,
    releaseAll: () => { for (const release of held.splice(0)) release(); },
  };
}

async function until(condition: () => boolean): Promise<void> {
  for (let i = 0; i < 4_000 && !condition(); i++) await new Promise((resolve) => setImmediate(resolve));
  expect(condition()).toBe(true);
}

const abortListeners = (signal: AbortSignal): number => getEventListeners(signal, "abort").length;

describe("a reservation is promoted only while it is still held, live and unexpired", () => {
  it("cancel then late settle returns no id and leaves no entry", async () => {
    const r = await setup();
    const hold = holdOpenAudits(r.auditLog);
    const controller = new AbortController();
    const pending = r.call(OPEN, {}, controller.signal);
    await until(() => hold.held() === 1);
    expect(r.eventCursorTable.size).toBe(1);
    controller.abort();
    // The cancelled reservation's slot and listener are released before its work settles.
    expect(r.eventCursorTable.size).toBe(0);
    expect(abortListeners(controller.signal)).toBe(0);
    expect(r.eventCursorTable.opensInFlight).toBe(1);
    hold.releaseAll();
    const settled = await pending;
    expect(settled.result).toEqual(REFUSAL);
    expect(settled.body.cursor).toBeUndefined();
    expect(r.eventCursorTable.size).toBe(0);
    expect(r.eventCursorTable.opensInFlight).toBe(0);
  });

  it("a reservation evicted while its audit is blocked is refused when the audit settles, and its listener is already released", async () => {
    const r = await setup();
    const hold = holdOpenAudits(r.auditLog);
    const controller = new AbortController();
    const blocked = r.call(OPEN, {}, controller.signal);
    await until(() => hold.held() === 1);
    hold.state.holding = false;
    r.clock.now += CURSOR_TTL_MS;
    for (let i = 1; i < MAX_OPEN_CURSORS; i++) expect(typeof (await r.open())).toBe("string");
    expect(r.eventCursorTable.size).toBe(MAX_OPEN_CURSORS);
    // The full table evicts its one expired entry, the blocked reservation, to admit this open.
    const admitted = await r.open();
    expect(typeof admitted).toBe("string");
    expect(abortListeners(controller.signal)).toBe(0);
    expect(r.eventCursorTable.size).toBe(MAX_OPEN_CURSORS);
    hold.releaseAll();
    const settled = await blocked;
    expect(settled.result).toEqual(REFUSAL);
    expect(settled.cause).toBe("cursor_open_evicted");
    expect(r.eventCursorTable.ids()).toContain(admitted);
    expect((await r.call("sanctuary_events_read", { cursor: admitted })).body.next_cursor).toBe(admitted);
  });

  it("a reservation evicted while its audit is blocked is refused at settlement even when the clock has stepped back", async () => {
    const r = await setup();
    const reservedAt = r.clock.now;
    const hold = holdOpenAudits(r.auditLog);
    const blocked = r.call(OPEN, {});
    await until(() => hold.held() === 1);
    hold.state.holding = false;
    r.clock.now += CURSOR_TTL_MS;
    for (let i = 0; i < MAX_OPEN_CURSORS; i++) expect(typeof (await r.open())).toBe("string");
    // The wall clock steps back below the reservation's expiry; the entry is gone all the same.
    r.clock.now = reservedAt;
    hold.releaseAll();
    const settled = await blocked;
    expect(settled.result).toEqual(REFUSAL);
    expect(settled.cause).toBe("cursor_open_evicted");
    expect(r.eventCursorTable.size).toBe(MAX_OPEN_CURSORS);
  });

  it("a late settlement after eviction never removes a later entry that holds the same id", async () => {
    const r = await setup();
    const reused = Buffer.alloc(12, 7);
    const hold = holdOpenAudits(r.auditLog);
    forcedCursorId.value = reused;
    const blocked = r.call(OPEN, {});
    forcedCursorId.value = undefined;
    await until(() => hold.held() === 1);
    hold.state.holding = false;
    r.clock.now += CURSOR_TTL_MS;
    for (let i = 1; i < MAX_OPEN_CURSORS; i++) expect(typeof (await r.open())).toBe("string");
    forcedCursorId.value = reused;
    const later = r.call(OPEN, {});
    forcedCursorId.value = undefined;
    const id = `cursor:${reused.toString("hex")}`;
    expect((await later).body.cursor).toBe(id);
    hold.releaseAll();
    expect((await blocked).cause).toBe("cursor_open_evicted");
    expect(r.eventCursorTable.ids()).toContain(id);
    expect((await r.call("sanctuary_events_read", { cursor: id })).body.next_cursor).toBe(id);
  });

  it("a reservation that expires while its audit is blocked is refused when the audit settles", async () => {
    const r = await setup();
    const hold = holdOpenAudits(r.auditLog);
    const blocked = r.call(OPEN, {});
    await until(() => hold.held() === 1);
    r.clock.now += CURSOR_TTL_MS;
    hold.releaseAll();
    const settled = await blocked;
    expect(settled.result).toEqual(REFUSAL);
    expect(settled.cause).toBe("cursor_open_evicted");
    expect(r.eventCursorTable.size).toBe(0);
    expect(r.eventCursorTable.opensInFlight).toBe(0);
  });

  it("repeated eviction and admission waves then late settlements never hold more than 64 cursors or 64 unsettled opens, and return no late id", async () => {
    const r = await setup();
    const hold = holdOpenAudits(r.auditLog);
    for (let wave = 0; wave < 3; wave++) {
      hold.state.holding = true;
      const controllers = Array.from({ length: MAX_OPEN_CURSORS }, () => new AbortController());
      const blocked = controllers.map((controller) => r.call(OPEN, {}, controller.signal));
      await until(() => hold.held() === MAX_OPEN_CURSORS);
      // The 64 audits stay held; later opens' audits are not.
      hold.state.holding = false;
      expect(r.eventCursorTable.size).toBe(MAX_OPEN_CURSORS);
      expect(r.eventCursorTable.opensInFlight).toBe(MAX_OPEN_CURSORS);
      r.clock.now += CURSOR_TTL_MS;
      // The first new open evicts every expired reservation; it and every later one refuse while 64 opens are unsettled.
      for (let i = 0; i < MAX_OPEN_CURSORS; i++) {
        const refused = await r.call(OPEN, {});
        expect(refused.result).toEqual(REFUSAL);
        expect(refused.cause).toBe("cursor_table_full");
        expect(r.eventCursorTable.size).toBeLessThanOrEqual(MAX_OPEN_CURSORS);
        expect(r.eventCursorTable.opensInFlight).toBeLessThanOrEqual(MAX_OPEN_CURSORS);
      }
      expect(r.eventCursorTable.size).toBe(0);
      for (const controller of controllers) expect(abortListeners(controller.signal)).toBe(0);
      // The 65th open while 64 evicted-but-blocked opens are unsettled refuses, though the table has room.
      const extra = await r.call(OPEN, {});
      expect(extra.body.cursor).toBeUndefined();
      expect(extra.cause).toBe("cursor_table_full");
      expect(r.eventCursorTable.opensInFlight).toBe(MAX_OPEN_CURSORS);
      hold.releaseAll();
      const late = await Promise.all(blocked);
      expect(late.every((settled) => settled.body.cursor === undefined)).toBe(true);
      expect(new Set(late.map((settled) => settled.cause))).toEqual(new Set(["cursor_open_evicted"]));
      expect(r.eventCursorTable.opensInFlight).toBe(0);
      expect(r.eventCursorTable.size).toBe(0);
      // Every id returned after the wave reads.
      const fresh = [await r.open(), await r.open()];
      for (const cursor of fresh) {
        expect(typeof cursor).toBe("string");
        expect((await r.call("sanctuary_events_read", { cursor })).body.next_cursor).toBe(cursor);
        expect((await r.call("sanctuary_events_close", { cursor })).body.closed).toBe(true);
      }
    }
  });
});

describe("eviction, close and the stored filter", () => {
  it("a spent cursor is evicted before a fresh one", async () => {
    const r = await setup();
    const opened: string[] = [];
    for (let i = 0; i < MAX_OPEN_CURSORS; i++) opened.push((await r.open())!);
    for (let i = 0; i < MAX_READS; i++) await r.call("sanctuary_events_read", { cursor: opened[10] });
    // Every entry is past its TTL; the spent one still goes first, ahead of older fresh ones.
    r.clock.now += CURSOR_TTL_MS;
    expect(typeof (await r.open())).toBe("string");
    expect(r.eventCursorTable.ids()).not.toContain(opened[10]);
    expect(r.eventCursorTable.ids()).toContain(opened[0]);
  });

  it("an evicted cursor's close refuses with the one refusal", async () => {
    const r = await setup();
    const opened: string[] = [];
    for (let i = 0; i < MAX_OPEN_CURSORS; i++) opened.push((await r.open())!);
    r.clock.now += CURSOR_TTL_MS;
    expect(typeof (await r.open())).toBe("string");
    const closed = await r.call("sanctuary_events_close", { cursor: opened[0] });
    expect(closed.result).toEqual(REFUSAL);
    expect(closed.cause).toBe("cursor_unknown");
  });

  it("an over-long operation filter refuses", async () => {
    const r = await setup();
    const refused = await r.call(OPEN, { filter: { operation: "x".repeat(OPERATION_MAX_CHARS + 1) } });
    expect(refused.result).toEqual(REFUSAL);
    expect(refused.cause).toBe("cursor_filter_too_long");
    expect(r.eventCursorTable.size).toBe(0);
    expect(typeof (await r.call(OPEN, { filter: { operation: "x".repeat(OPERATION_MAX_CHARS) } })).body.cursor).toBe("string");
  });

  it("a pending cursor cannot be read or closed", async () => {
    const r = await setup();
    const query = r.auditLog.query.bind(r.auditLog);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(r.auditLog, "query").mockImplementation(async (options) => {
      if (options.with_sequences === true && options.limit !== Number.MAX_SAFE_INTEGER) await gate;
      return query(options);
    });
    const pending = r.call(OPEN, {});
    await until(() => r.eventCursorTable.size === 1);
    const [id] = r.eventCursorTable.ids();
    const read = await r.call("sanctuary_events_read", { cursor: id });
    expect(read.result).toEqual(REFUSAL);
    expect(read.cause).toBe("cursor_unknown");
    const closed = await r.call("sanctuary_events_close", { cursor: id });
    expect(closed.result).toEqual(REFUSAL);
    expect(closed.cause).toBe("cursor_unknown");
    expect(r.eventCursorTable.ids()).toEqual([id]);
    release();
    expect((await pending).body.cursor).toBe(id);
    expect((await r.call("sanctuary_events_close", { cursor: id })).body.closed).toBe(true);
  });

  it("opened_at comes from the injected clock", async () => {
    const r = await setup();
    const cursor = (await r.open())!;
    expect(r.eventCursorTable.openedAt(cursor)).toBe(new Date(r.clock.now).toISOString());
  });

  it("two factories do not share a cursor table", async () => {
    const r = await setup();
    const other = r.factory();
    const cursor = (await r.open())!;
    const foreign = await r.call("sanctuary_events_read", { cursor }, undefined, other.tools);
    expect(foreign.result).toEqual(REFUSAL);
    expect(r.eventCursorTable.size).toBe(1);
    expect(other.eventCursorTable.size).toBe(0);
  });
});
