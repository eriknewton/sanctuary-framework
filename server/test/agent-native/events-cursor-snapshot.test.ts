/**
 * An events cursor pages through the rows that were visible when it was
 * opened, in order, and skips a row that has since left the retained window.
 * Rows that become visible later appear in a new cursor. One server holds at
 * most 64 cursors; a spent cursor makes room for a new one.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { recordingNamespaceInserts } from "../helpers/cooperative-test-options.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import {
  AuditLog,
  CALL_OUTCOME_SUCCESS_OPERATION,
  runInCallScope,
  settleCallOutcome,
  writeCallOutcomeMarkers,
  type AuditEntry,
  type CallScopeHandle,
} from "../../src/operational/audit-log.js";
import { redactAuditEntryForAgent } from "../../src/operational/agent-audit-redaction.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { ToolDefinition } from "../../src/router.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { ApprovalProofStore, fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";

const OWN = "own_row";
// Must match the events cursor's caps in agent-native/cooperative-surface.ts.
const MAX_READS = 10;
const PAGE = 25;
const SNAPSHOT_ROWS = MAX_READS * PAGE;
const WINDOW_ROWS = 500;
const MAX_OPEN_CURSORS = 64;

afterEach(() => { vi.restoreAllMocks(); });

async function setup(config?: { maxEntries?: number; maxInMemoryEntries?: number }, storage = new MemoryStorage(), masterKey = generateRandomKey()) {
  const auditLog = new AuditLog(storage, masterKey, config);
  const stateStore = new StateStore(storage, masterKey);
  let active: SessionBinding | undefined;
  const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(stateStore, storage, masterKey, "recovery-key", auditLog,
    { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => active });
  await identityManager.load();
  const created = JSON.parse((await l1Tools.find((t) => t.name === "identity_create")!.handler({ label: "cursor" })).content[0]!.text);
  const identityId = created.identity_id as string;
  active = { identity_id: identityId, requester_identity_fingerprint: fingerprintIdentityId(identityId) };
  const { tools } = createAgentNativeCooperativeTools({
    baselineNamespaceInserts: recordingNamespaceInserts(),
    identityManager,
    namespaceRegistry,
    auditLog,
    currentSessionBinding: () => active,
    primitiveTools: l1Tools,
    storage,
    approvalProofStore: new ApprovalProofStore(),
  });
  const tool = (name: string): ToolDefinition => tools.find((t) => t.name === name)!;
  const run = async (name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> =>
    JSON.parse((await tool(name).handler(args, `agent:cursor`, {})).content[0]!.text) as Record<string, unknown>;
  const ownRows = async (n: number, tag = "") => {
    for (let i = 0; i < n; i++) await auditLog.append("l2", OWN, identityId, { tag: `${tag}${i}` });
    await auditLog.flush();
  };
  const visibleAtOpen = async () =>
    (await auditLog.query({ operation_type: OWN, identity_id: identityId, agent_visible: true, limit: WINDOW_ROWS })).entries.slice(0, SNAPSHOT_ROWS);
  const open = async () => (await run("sanctuary_events_open_cursor", { filter: { operation: OWN } })).cursor as string;
  const read = async (cursor: string) => run("sanctuary_events_read", { cursor, opts: { limit: PAGE } });
  const readAll = async (cursor: string) => {
    const events: Array<Record<string, unknown>> = [];
    for (let i = 0; i < MAX_READS; i++) {
      const page = (await read(cursor)).events as Array<Record<string, unknown>> | undefined;
      if (!page || page.length === 0) break;
      events.push(...page);
    }
    return events;
  };
  return { auditLog, storage, masterKey, identityId, run, ownRows, visibleAtOpen, open, read, readAll, tool };
}

function expected(rows: readonly AuditEntry[]): Array<Record<string, unknown>> {
  return rows.map((row, position) => ({ cursor_event_id: position, ...redactAuditEntryForAgent(row) }));
}

/** A call whose rows are written now and whose outcome settles later. */
async function heldCall(log: AuditLog, identityId: string, n: number, tag: string) {
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  let handle!: CallScopeHandle;
  const done = runInCallScope(async (scope) => {
    handle = scope;
    for (let i = 0; i < n; i++) await log.append("l2", OWN, identityId, { tag: `${tag}${i}` });
    await released;
  });
  await log.flush();
  return {
    succeed: async () => {
      settleCallOutcome(handle, "succeeded");
      writeCallOutcomeMarkers(handle);
      release();
      await done;
      await log.flush();
    },
  };
}

describe("events cursor snapshot paging", () => {
  it("a cursor's pages equal its snapshot", async () => {
    const r = await setup();
    await r.ownRows(60);
    const snapshot = await r.visibleAtOpen();
    const cursor = await r.open();
    expect(await r.readAll(cursor)).toEqual(expected(snapshot));
  });

  for (const where of ["before", "at", "after"] as const) {
    it(`a row that becomes visible ${where} the read position does not appear`, async () => {
      const r = await setup();
      // Hidden rows sit older than the next page, at its first slot, or newer than it.
      const before = where === "before" ? 10 : where === "at" ? PAGE : 55;
      await r.ownRows(before, "a");
      const held = await heldCall(r.auditLog, r.identityId, 3, "held");
      await r.ownRows(60 - before, "b");
      const snapshot = await r.visibleAtOpen();
      const cursor = await r.open();
      const first = (await r.read(cursor)).events as unknown[];
      await held.succeed();
      const rest: unknown[] = [];
      for (let i = 1; i < MAX_READS; i++) {
        const page = (await r.read(cursor)).events as unknown[];
        if (page.length === 0) break;
        rest.push(...page);
      }
      expect([...first, ...rest]).toEqual(expected(snapshot));
    });
  }

  it("a full window: 500 visible rows at open, then more calls finish, and the pages equal the snapshot's 250 positions", async () => {
    const r = await setup();
    await r.ownRows(WINDOW_ROWS);
    const snapshot = await r.visibleAtOpen();
    expect(snapshot).toHaveLength(SNAPSHOT_ROWS);
    const cursor = await r.open();
    const events: unknown[] = [];
    for (let i = 0; i < MAX_READS; i++) {
      events.push(...((await r.read(cursor)).events as unknown[]));
      await r.ownRows(5, `later-${i}-`);
    }
    expect(events).toEqual(expected(snapshot));
  });

  it("a row evicted after open is skipped and the rest still page in order", async () => {
    const r = await setup({ maxEntries: 40, maxInMemoryEntries: 40 });
    await r.ownRows(30);
    const snapshot = await r.visibleAtOpen();
    const cursor = await r.open();
    // The cursor's own audit rows and ten more rows push the oldest snapshot rows out of retention.
    await r.ownRows(10, "late");
    const events = await r.readAll(cursor);
    const all = expected(snapshot);
    // Every returned event is the snapshot's row at its own position, in snapshot order, and the pruned ones are gone.
    expect(events.length).toBeGreaterThan(0);
    expect(events.length).toBeLessThan(snapshot.length);
    for (const event of events) expect(event).toEqual(all[event.cursor_event_id as number]);
    const positions = events.map((event) => event.cursor_event_id as number);
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it("a row no longer visible at read, because retention pruned its call's marker, is skipped", async () => {
    // Retention prunes in batches, so filler rows sit between the marker and the late row.
    const FILLER = 20;
    const r = await setup({ maxEntries: 40, maxInMemoryEntries: 40 });
    let late!: Promise<void>;
    let releaseLate!: () => void;
    const fillersDone = new Promise<void>((resolve) => { releaseLate = resolve; });
    await runInCallScope(async (scope) => {
      await r.auditLog.append("l2", OWN, r.identityId, { tag: "in-call" });
      settleCallOutcome(scope, "succeeded");
      writeCallOutcomeMarkers(scope);
      await r.auditLog.flush();
      // Work the call left running appends its late row once the fillers are in.
      late = (async () => {
        await fillersDone;
        await r.auditLog.append("l2", OWN, r.identityId, { tag: "late" });
      })();
    });
    for (let i = 0; i < FILLER; i++) await r.auditLog.append("l2", "filler", r.identityId);
    releaseLate();
    await late;
    await r.auditLog.flush();
    const snapshot = await r.visibleAtOpen();
    expect(snapshot.map((row) => row.details?.tag)).toContain("late");
    const cursor = await r.open();
    // Rows are added one at a time until the marker is pruned; the late row, next oldest, stays retained but is no
    // longer visible.
    const markerRetained = async () => (await r.auditLog.query({ limit: 100, include_outcome_markers: true })).entries
      .some((row) => row.operation === CALL_OUTCOME_SUCCESS_OPERATION);
    for (let i = 0; i < 60 && await markerRetained(); i++) await r.ownRows(1, `after-${i}-`);
    expect(await markerRetained()).toBe(false);
    const raw = (await r.auditLog.query({ operation_type: OWN, limit: 100 })).entries.map((row) => row.details?.tag);
    expect(raw).toContain("late");
    const events = await r.readAll(cursor);
    expect(events.map((event) => event.cursor_event_id)).not.toContain(snapshot.findIndex((row) => row.details?.tag === "late"));
  });

  it("a new cursor shows rows that became visible after the old one opened", async () => {
    const r = await setup();
    await r.ownRows(5);
    const held = await heldCall(r.auditLog, r.identityId, 2, "held");
    const first = await r.open();
    expect(await r.readAll(first)).toHaveLength(5);
    await held.succeed();
    const second = await r.open();
    expect(await r.readAll(second)).toHaveLength(7);
  });

  it("a cursor key survives reload for duplicate legacy rows, and each appears once by its own key", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditKey = derivePurposeKey(masterKey, "audit-log");
    const legacy: AuditEntry = { timestamp: "2026-05-16T00:00:00.000Z", layer: "l2", operation: OWN, identity_id: "agent:legacy", result: "success" };
    // Two byte-different stored copies of an identical legacy row.
    for (const key of ["legacy-1", "legacy-2"]) {
      await storage.write("_audit", key, stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(legacy)), auditKey))));
    }
    const reader = new AuditLog(storage, masterKey);
    const keyed = await reader.query({ operation_type: OWN, limit: 100, with_sequences: true });
    expect(keyed.sequences).toEqual([{ legacy_key: "legacy-1" }, { legacy_key: "legacy-2" }]);
    const reloaded = await new AuditLog(storage, masterKey).query({ operation_type: OWN, limit: 100, with_sequences: true });
    expect(reloaded.sequences).toEqual(keyed.sequences);
    // A chained row after them keys by its sequence, and trimming the window drops the legacy keys first.
    await reader.append("l2", OWN, "agent:legacy");
    await reader.flush();
    const mixed = await reader.query({ operation_type: OWN, limit: 100, with_sequences: true });
    expect(mixed.sequences).toEqual([{ legacy_key: "legacy-1" }, { legacy_key: "legacy-2" }, { sequence: 3 }]);
  });

  it("closing a spent cursor succeeds", async () => {
    const r = await setup();
    await r.ownRows(3);
    const cursor = await r.open();
    for (let i = 0; i < MAX_READS; i++) await r.read(cursor);
    expect(await r.run("sanctuary_events_close", { cursor })).toMatchObject({ closed: true });
  });

  it("the events-read description is unchanged", () => {
    return setup().then((r) => {
      expect(r.tool("sanctuary_events_read").description).toBe(
        "Read the next page of redacted events from a cursor opened with sanctuary_events_open_cursor (default 10, max 25 per call). Returns { events, next_cursor, audit_ref }. Only your own identity's events are visible; capped at 10 reads per cursor, then rate-limited.",
      );
    });
  });
});

describe("the open-cursor cap", () => {
  it("64 concurrent opens at the boundary plus one more: exactly 64 held, the extra one refuses", async () => {
    const r = await setup();
    const opened = await Promise.all(Array.from({ length: MAX_OPEN_CURSORS + 1 }, () => r.run("sanctuary_events_open_cursor", {})));
    const held = opened.filter((o) => typeof o.cursor === "string");
    expect(held).toHaveLength(MAX_OPEN_CURSORS);
    expect(opened.filter((o) => o.cursor === undefined)).toHaveLength(1);
  });

  it("three waves of blocked snapshot queries never hold more than 64 cursors", async () => {
    const r = await setup();
    const query = r.auditLog.query.bind(r.auditLog);
    for (let wave = 0; wave < 3; wave++) {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => { release = resolve; });
      const spy = vi.spyOn(r.auditLog, "query").mockImplementation(async (options) => {
        await gate;
        return query(options);
      });
      const pending = Array.from({ length: MAX_OPEN_CURSORS + 8 }, () => r.run("sanctuary_events_open_cursor", {}));
      release();
      const results = await Promise.all(pending);
      spy.mockRestore();
      const held = results.filter((o) => typeof o.cursor === "string").map((o) => o.cursor as string);
      expect(held.length).toBeLessThanOrEqual(MAX_OPEN_CURSORS);
      expect(held.length).toBe(MAX_OPEN_CURSORS);
      for (const cursor of held) expect(await r.run("sanctuary_events_close", { cursor })).toMatchObject({ closed: true });
    }
  });

  it("a sequential 65th open refuses", async () => {
    const r = await setup();
    for (let i = 0; i < MAX_OPEN_CURSORS; i++) expect(typeof (await r.run("sanctuary_events_open_cursor", {})).cursor).toBe("string");
    expect((await r.run("sanctuary_events_open_cursor", {})).cursor).toBeUndefined();
  });

  it("a spent cursor is evicted to admit a new open, and closing the evicted cursor refuses", async () => {
    const r = await setup();
    const cursors: string[] = [];
    for (let i = 0; i < MAX_OPEN_CURSORS; i++) cursors.push((await r.run("sanctuary_events_open_cursor", {})).cursor as string);
    for (let i = 0; i < MAX_READS; i++) await r.read(cursors[3]!);
    expect(typeof (await r.run("sanctuary_events_open_cursor", {})).cursor).toBe("string");
    expect((await r.run("sanctuary_events_close", { cursor: cursors[3]! })).closed).toBeUndefined();
    expect((await r.run("sanctuary_events_open_cursor", {})).cursor).toBeUndefined();
  });

  it("an open whose snapshot query throws holds no cursor", async () => {
    const r = await setup();
    const query = r.auditLog.query.bind(r.auditLog);
    let fail = true;
    vi.spyOn(r.auditLog, "query").mockImplementation(async (options) => {
      if (fail && options.with_sequences === true) throw new Error("injected query failure");
      return query(options);
    });
    for (let i = 0; i < MAX_OPEN_CURSORS + 1; i++) expect((await r.run("sanctuary_events_open_cursor", {})).cursor).toBeUndefined();
    fail = false;
    expect(typeof (await r.run("sanctuary_events_open_cursor", {})).cursor).toBe("string");
  });
});
