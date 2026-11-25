/**
 * A refused or cancelled call adds nothing to the agent's own audit history:
 * no row, count, match or page in any agent reader, while the operator view
 * still holds the call's rows. Each case builds two identically seeded
 * servers with the same setup; only the treatment makes the measured call,
 * then both run the same observation schedule and must read back the same.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest, ApprovalResponse } from "../../src/principal-policy/types.js";
import { createSanctuaryServer, type SanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { CALL_OUTCOME_SUCCESS_OPERATION } from "../../src/operational/audit-log.js";
import { SIEM_EXPORT_FORMATS } from "../../src/audit/siem-tools.js";
import { AGENT_AUDIT_READ_MAX_LIMIT } from "../../src/operational/agent-audit-redaction.js";
import { INTERNAL_SIGNING_DOMAIN_PREFIXES } from "../../src/core/signing-domains.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { buildAuditDigest } from "../../src/principal-policy/posture.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import { expectedRefusal } from "../helpers/expected-refusal.js";

type CallResult = Awaited<ReturnType<Client["callTool"]>>;

interface World {
  app: SanctuaryServer;
  client: Client;
  storage: MemoryStorage;
  identityId: string;
}

// The events tool's caps: at most 10 reads per cursor, at most 25 events per read.
const EVENT_PAGES_READ = 10;
const EVENTS_PER_PAGE = 25;
// sanctuary_audit_search has no paging; this is its largest allowed limit.
const AUDIT_SEARCH_MAX_LIMIT = 25;
// Every search corpus is the operation name followed by a canonical JSON object, so "{" matches every row.
const MATCH_EVERY_ROW = "{";
// One more own row than a search page and an events page hold, so the control pass crosses both boundaries.
const BOUNDARY_SETUP_SAVES = AUDIT_SEARCH_MAX_LIMIT + 1;

let home: Awaited<ReturnType<typeof createTempHome>>;
const worlds: World[] = [];
let previousSession: string | undefined;
let previousAgent: string | undefined;

beforeAll(async () => {
  previousSession = process.env.SANCTUARY_SESSION_IDENTITY_ID;
  previousAgent = process.env.SANCTUARY_AGENT_ID;
  process.env.SANCTUARY_AGENT_ID = "readback-agent";
  home = await createTempHome("sanctuary-readback-opacity");
  await mkdir(home.defaultFortressPath, { recursive: true, mode: 0o700 });
  // Owner-only mode matches the production policy writer.
  await writeFile(
    join(home.defaultFortressPath, "principal-policy.yaml"),
    generateDefaultPolicyYaml().replace(/approval_channel:\n  type: \w+/, "approval_channel:\n  type: callback"),
    { mode: 0o600 },
  );
}, 60_000);

afterEach(async () => {
  vi.restoreAllMocks();
  for (const world of worlds.splice(0)) {
    try { await world.client.close(); } finally { await world.app.cleanup(); }
  }
});

afterAll(async () => {
  if (previousSession === undefined) delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
  else process.env.SANCTUARY_SESSION_IDENTITY_ID = previousSession;
  if (previousAgent === undefined) delete process.env.SANCTUARY_AGENT_ID;
  else process.env.SANCTUARY_AGENT_ID = previousAgent;
  await home?.cleanup();
});

// Every approval request the observation schedule and the cases raise is approved; Tier 1 state_delete stays denied.
const DENIED_OPERATIONS = new Set(["state_delete"]);
const approvalCallback = async (request: ApprovalRequest): Promise<ApprovalResponse> => ({
  decision: DENIED_OPERATIONS.has(request.operation) ? "deny" : "approve",
  decided_at: new Date().toISOString(),
  decided_by: "human",
});

async function boot(storage = new MemoryStorage()): Promise<World> {
  delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
  const app = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE, approvalCallback });
  const client = new Client({ name: "readback-opacity", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await app.server.connect(serverTransport);
  await client.connect(clientTransport);
  const world: World = { app, client, storage, identityId: "" };
  worlds.push(world);
  const created = body(await client.callTool({ name: "identity_create", arguments: { label: "readback" } }));
  world.identityId = created.identity_id as string;
  return world;
}

/** The session identity is process-wide; each world's calls run under its own. */
function use(world: World): World {
  process.env.SANCTUARY_SESSION_IDENTITY_ID = world.identityId;
  return world;
}

function call(world: World, name: string, args: Record<string, unknown> = {}, options?: { signal?: AbortSignal }): Promise<CallResult> {
  use(world);
  return world.client.callTool({ name, arguments: args }, undefined, options);
}

function body(result: CallResult): Record<string, unknown> {
  return JSON.parse((result.content as Array<{ text: string }>)[0]!.text) as Record<string, unknown>;
}

async function succeed(world: World, name: string, args: Record<string, unknown> = {}): Promise<CallResult> {
  const result = await call(world, name, args);
  expect(result, name).not.toEqual(expectedRefusal());
  return result;
}

/** One observation pass: every agent reader, each at its widest read. Generated identifiers are compared by position only. */
async function observe(world: World): Promise<unknown> {
  const opened = body(await succeed(world, "sanctuary_events_open_cursor", {}));
  const pages: Array<Array<[unknown, unknown, unknown, unknown]>> = [];
  for (let page = 0; page < EVENT_PAGES_READ; page += 1) {
    const read = body(await succeed(world, "sanctuary_events_read", { cursor: opened.cursor, opts: { limit: EVENTS_PER_PAGE } }));
    const events = read.events as Array<Record<string, unknown>>;
    pages.push(events.map((e) => [e.cursor_event_id, e.operation, e.result, e.has_details]));
    if (events.length === 0) break;
  }
  await succeed(world, "sanctuary_events_close", { cursor: opened.cursor });
  const searched = body(await succeed(world, "sanctuary_audit_search", { query: MATCH_EVERY_ROW, limit: AUDIT_SEARCH_MAX_LIMIT }));
  const search = (searched.results as Array<Record<string, unknown>>).map((r) => [r.audit_ref, r.operation, r.verification, r.summary]);
  const monitored = body(await succeed(world, "monitor_audit_log", { limit: 1_000 }));
  const monitor = {
    count: monitored.count,
    rows: (monitored.entries as Array<Record<string, unknown>>).map((e) => [e.operation, e.result, e.has_details]),
  };
  const siem: Record<string, unknown> = {};
  for (const format of SIEM_EXPORT_FORMATS) {
    const exported = await succeed(world, "audit_export_siem", { format, limit: 1_000 });
    const head = body(exported);
    const events = (exported.content as Array<{ text: string }>)[1]!.text;
    siem[format] = {
      count: head.count,
      total_available: head.total_available,
      events: format === "cef" ? events.split("\n").filter((line) => line.length > 0).length : (JSON.parse(events) as unknown[]).length,
    };
  }
  return { pages, search, monitor, siem };
}

async function operatorRows(world: World): Promise<Array<{ operation: string; identity_id: string; call_ref?: string }>> {
  await world.app.auditLog.flush();
  return (await world.app.auditLog.query({ limit: 100_000 })).entries;
}

interface Case {
  label: string;
  setup: (world: World) => Promise<void>;
  measured: (world: World) => Promise<CallResult>;
  /** The measured call writes at least one row under the agent's own identity. */
  writesOwnRow: boolean;
}

const CASES: Case[] = [
  {
    label: "recall of a hidden key",
    setup: async (w) => {
      await succeed(w, "sanctuary_remember", { key: "hidden-key", value: "v" });
      await succeed(w, "sanctuary_hide", { key: "hidden-key" });
    },
    measured: (w) => call(w, "sanctuary_recall", { key: "hidden-key" }),
    writesOwnRow: true,
  },
  {
    label: "recall of an absent key",
    setup: async (w) => { await succeed(w, "sanctuary_remember", { key: "present-key", value: "v" }); },
    measured: (w) => call(w, "sanctuary_recall", { key: "never-written" }),
    writesOwnRow: false,
  },
  {
    label: "reserved-domain identity_sign",
    setup: async () => undefined,
    measured: (w) => call(w, "identity_sign", {
      identity_id: w.identityId,
      payload: toBase64url(stringToBytes(`${INTERNAL_SIGNING_DOMAIN_PREFIXES[0]}forged`)),
    }),
    writesOwnRow: true,
  },
  {
    label: "Tier 1 denied",
    setup: async () => undefined,
    measured: (w) => call(w, "state_delete", { namespace: "opacity", key: "k" }),
    writesOwnRow: false,
  },
  {
    label: "primitive state_write to a reserved namespace",
    setup: async () => undefined,
    measured: (w) => call(w, "state_write", { namespace: "_reputation", key: "k", value: "v" }),
    writesOwnRow: false,
  },
];

describe("a refused call adds nothing to any agent reader", () => {
  it("control: two worlds with the same history read back the same across a page boundary and the search limit", async () => {
    const a = await boot();
    const b = await boot();
    for (const world of [a, b]) {
      for (let i = 0; i < BOUNDARY_SETUP_SAVES; i += 1) await succeed(world, "sanctuary_remember", { key: `k-${i}`, value: "v" });
    }
    const oa = await observe(a) as { pages: unknown[][]; search: unknown[] };
    const ob = await observe(b);
    expect(oa.pages[0]).toHaveLength(EVENTS_PER_PAGE);
    expect(oa.pages[1]!.length).toBeGreaterThan(0);
    expect(oa.search).toHaveLength(AUDIT_SEARCH_MAX_LIMIT);
    expect(ob).toEqual(oa);
  }, 240_000);

  for (const c of CASES) {
    it(`${c.label} adds no row, count, match or page to any agent reader`, async () => {
      const control = await boot();
      const treatment = await boot();
      await c.setup(control);
      await c.setup(treatment);
      const before = (await operatorRows(treatment)).length;
      expect(await c.measured(treatment)).toEqual(expectedRefusal());
      const added = (await operatorRows(treatment)).slice(before);
      if (c.writesOwnRow) {
        // The operator still sees the refused call's rows under the agent's identity.
        expect(added.some((row) => row.identity_id === treatment.identityId), c.label).toBe(true);
      }
      expect(added.some((row) => row.operation === CALL_OUTCOME_SUCCESS_OPERATION)).toBe(false);
      expect(await observe(treatment)).toEqual(await observe(control));
    }, 240_000);
  }

  it("a cancelled call's rows, including the router's failure row, reach no agent reader", async () => {
    const control = await boot();
    const treatment = await boot();
    await succeed(control, "sanctuary_remember", { key: "warm", value: "v" });
    await succeed(treatment, "sanctuary_remember", { key: "warm", value: "v" });
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    let entered = false;
    const write = treatment.storage.write.bind(treatment.storage);
    vi.spyOn(treatment.storage, "write").mockImplementation(async (namespace, key, value) => {
      if (key.includes("cancel-me")) {
        entered = true;
        await held;
      }
      return write(namespace, key, value);
    });
    const controller = new AbortController();
    const pending = call(treatment, "sanctuary_remember", { key: "cancel-me", value: "v" }, { signal: controller.signal })
      .then(() => "resolved", () => "rejected");
    await vi.waitFor(() => { expect(entered).toBe(true); });
    controller.abort();
    await new Promise((resolve) => setTimeout(resolve, 20));
    release();
    expect(await pending).toBe("rejected");
    await vi.waitFor(async () => {
      const rows = await operatorRows(treatment);
      expect(rows.some((row) => row.operation === "denial_cause")).toBe(true);
    });
    expect(await observe(treatment)).toEqual(await observe(control));
  }, 240_000);
});

describe("successful calls and lost markers", () => {
  it("a successful call's rows are agent-visible once it returns", async () => {
    const world = await boot();
    await succeed(world, "sanctuary_remember", { key: "seen", value: "v" });
    const monitored = body(await succeed(world, "monitor_audit_log", { limit: 1_000 }));
    expect((monitored.entries as Array<{ operation: string }>).map((e) => e.operation)).toContain("sanctuary_remember");
  }, 120_000);

  it("a marker the store refuses before writing hides the call's rows from every agent reader", async () => {
    const control = await boot();
    const treatment = await boot();
    const log = treatment.app.auditLog as unknown as {
      persistChainedEntry: (entry: { operation: string }, ...rest: unknown[]) => Promise<void>;
    };
    const persist = log.persistChainedEntry.bind(treatment.app.auditLog);
    let refuseMarkers = true;
    vi.spyOn(log, "persistChainedEntry").mockImplementation(async (entry, ...rest) => {
      if (refuseMarkers && entry.operation === CALL_OUTCOME_SUCCESS_OPERATION) throw new Error("injected store refusal");
      return persist(entry, ...rest);
    });
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const result = await call(treatment, "sanctuary_remember", { key: "unmarked", value: "v" });
    expect(result).not.toEqual(expectedRefusal());
    expect(Object.keys(body(result)).sort()).toEqual(Object.keys(body(await succeed(control, "sanctuary_remember", { key: "unmarked", value: "v" }))).sort());
    refuseMarkers = false;
    const own = (await operatorRows(treatment)).filter((row) => row.identity_id === treatment.identityId && row.call_ref !== undefined);
    expect(own.length).toBeGreaterThan(0);
    // The control's save is visible; the treatment's is not, so the treatment reads back one save fewer.
    const controlRead = body(await succeed(control, "monitor_audit_log", { limit: 1_000 }));
    const treatmentRead = body(await succeed(treatment, "monitor_audit_log", { limit: 1_000 }));
    const saves = (read: Record<string, unknown>) => (read.entries as Array<{ operation: string }>).filter((e) => e.operation === "sanctuary_remember").length;
    expect(saves(controlRead)).toBe(1);
    expect(saves(treatmentRead)).toBe(0);
    const searched = body(await succeed(treatment, "sanctuary_audit_search", { query: "sanctuary_remember", limit: AUDIT_SEARCH_MAX_LIMIT }));
    expect(searched.results).toEqual([]);
  }, 240_000);

  it("rows whose marker never landed stay hidden from every agent reader after reopen", async () => {
    const storage = new MemoryStorage();
    const first = await boot(storage);
    const identityId = first.identityId;
    const log = first.app.auditLog as unknown as {
      persistChainedEntry: (entry: { operation: string }, ...rest: unknown[]) => Promise<void>;
    };
    const persist = log.persistChainedEntry.bind(first.app.auditLog);
    vi.spyOn(log, "persistChainedEntry").mockImplementation(async (entry, ...rest) => {
      // The process stops before the marker lands.
      if (entry.operation === CALL_OUTCOME_SUCCESS_OPERATION) throw new Error("process stopped");
      return persist(entry, ...rest);
    });
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    await succeed(first, "sanctuary_remember", { key: "crash-key", value: "v" });
    await first.client.close();
    await first.app.cleanup();
    worlds.splice(worlds.indexOf(first), 1);
    vi.restoreAllMocks();
    delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
    const app = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE, approvalCallback });
    const client = new Client({ name: "readback-opacity-reopen", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await app.server.connect(serverTransport);
    await client.connect(clientTransport);
    const reopened: World = { app, client, storage, identityId };
    worlds.push(reopened);
    const operator = await operatorRows(reopened);
    expect(operator.some((row) => row.operation === "sanctuary_remember" && row.identity_id === identityId)).toBe(true);
    const monitored = body(await succeed(reopened, "monitor_audit_log", { limit: 1_000 }));
    expect((monitored.entries as Array<{ operation: string }>).map((e) => e.operation)).not.toContain("sanctuary_remember");
  }, 240_000);
});

describe("the agent audit read ceiling", () => {
  it("monitor_audit_log returns at most 1000 rows, and SIEM and monitor share one cap", async () => {
    // The SIEM export's per-call ceiling, which monitor_audit_log shares.
    const CEILING = 1000;
    const world = await boot();
    // Rows written outside any call are agent-visible as they always were; one more than the ceiling.
    for (let i = 0; i <= CEILING; i += 1) await world.app.auditLog.append("l2", "own_row", world.identityId);
    await world.app.auditLog.flush();
    const monitored = body(await succeed(world, "monitor_audit_log", { limit: 5_000 }));
    expect(monitored.count).toBe(CEILING);
    const exported = body(await succeed(world, "audit_export_siem", { format: "ocsf", limit: 5_000 }));
    expect(exported.count).toBe(CEILING);
    expect(AGENT_AUDIT_READ_MAX_LIMIT).toBe(CEILING);
  }, 240_000);
});

describe("monitor_health across refusals and markers", () => {
  it("storage_bytes is the same before and after every refusal in the set, and after a successful call's marker", async () => {
    const world = await boot();
    const storageBytes = async () => body(await succeed(world, "monitor_health", {})).storage_bytes;
    for (const c of CASES) {
      await c.setup(world);
      const before = await storageBytes();
      expect(await c.measured(world)).toEqual(expectedRefusal());
      expect(await storageBytes(), c.label).toBe(before);
    }
    // A successful call that writes only audit rows, so its marker is the one change to measure.
    const before = await storageBytes();
    await succeed(world, "sanctuary_audit_search", { query: MATCH_EVERY_ROW, limit: AUDIT_SEARCH_MAX_LIMIT });
    await world.app.auditLog.flush();
    expect((await operatorRows(world)).length).toBeGreaterThan(0);
    expect(await storageBytes()).toBe(before);
  }, 240_000);
});

describe("audit-failure rows in agent readers", () => {
  it("monitor_audit_log and every SIEM format never surface an error_class from an audit-failure row", async () => {
    const world = await boot();
    const sentinel = "SentinelAuditWriteErrorClass";
    // Must match the `${operation}_audit_failed` rows with an error_class detail in sdw/memory-file-tools.ts.
    await world.app.auditLog.append("l2", "sdw_memory_file_audit_failed", world.identityId, { error_class: sentinel }, "failure");
    await world.app.auditLog.flush();
    const monitored = await succeed(world, "monitor_audit_log", { limit: 1_000 });
    expect((body(monitored).entries as Array<{ operation: string }>).map((e) => e.operation)).toContain("sdw_memory_file_audit_failed");
    const texts = [JSON.stringify(monitored)];
    for (const format of SIEM_EXPORT_FORMATS) texts.push(JSON.stringify(await succeed(world, "audit_export_siem", { format, limit: 1_000 })));
    for (const text of texts) {
      expect(text).not.toContain(sentinel);
      expect(text).not.toContain("error_class");
    }
  }, 240_000);
});

describe("the operator dashboard's activity counts", () => {
  it("a refused call and a success marker leave the operator digest's activity counts as the operator rows give them", async () => {
    const world = await boot();
    const digest = () => buildAuditDigest({ auditLog: world.app.auditLog, originMachine: "fortress:test", protectionClaimSubject: null, now: Date.now() });
    const operatorTotal = async () => { await world.app.auditLog.flush(); return (await world.app.auditLog.query({ limit: 100_000 })).total; };
    const start = await digest();
    const startRows = await operatorTotal();
    // A refused call: its rows stay operator activity.
    expect(await call(world, "sanctuary_recall", { key: "never-written" })).toEqual(expectedRefusal());
    await succeed(world, "sanctuary_remember", { key: "counted", value: "v" });
    const end = await digest();
    const endRows = await operatorTotal();
    expect(end.total_operations - start.total_operations).toBe(endRows - startRows);
    const markers = (await world.app.auditLog.query({ limit: 100_000, include_outcome_markers: true })).entries
      .filter((e) => e.operation === CALL_OUTCOME_SUCCESS_OPERATION).length;
    expect(markers).toBeGreaterThan(0);
    expect(end.by_agent.reduce((n, row) => n + row.operations, 0)).toBe(end.total_operations);
  }, 240_000);
});

