/**
 * A refused or cancelled call adds nothing to the agent's own audit history:
 * no row, count, match or page in any agent reader, while the operator view
 * still holds the call's rows. Each case builds two identically seeded
 * servers with the same setup; only the treatment makes the measured call,
 * then both run the same observation schedule, under one frozen clock, and
 * must read back the same, SIEM event contents included.
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
import { AuditLogPersistenceError, BROKER_OPS, CALL_OUTCOME_SUCCESS_OPERATION } from "../../src/operational/audit-log.js";
import { SIEM_EXPORT_FORMATS } from "../../src/audit/siem-tools.js";
import { AGENT_AUDIT_READ_MAX_LIMIT } from "../../src/operational/agent-audit-redaction.js";
import { INTERNAL_SIGNING_DOMAIN_PREFIXES } from "../../src/core/signing-domains.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { buildAuditDigest } from "../../src/principal-policy/posture.js";
import { Broker } from "../../src/disclosure/broker/broker.js";
import { SecretNotFoundError, type Backend } from "../../src/disclosure/broker/backend-interface.js";
import { createBrokerMcpServer } from "../../src/broker-mcp/broker-server.js";
import { gatherReputationEvidence } from "../../src/shr/tools.js";
import { ReputationStore } from "../../src/reputation/reputation-store.js";
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
  // Every reader's whole result, every content block plus isError and the envelope fields, normalized.
  const whole: string[] = [];
  const reader = async (name: string, args: Record<string, unknown> = {}): Promise<CallResult> => {
    const result = await succeed(world, name, args);
    whole.push(normalizeWhole(world, result));
    return result;
  };
  const opened = body(await reader("sanctuary_events_open_cursor", {}));
  const pages: Array<Array<[unknown, unknown, unknown, unknown]>> = [];
  for (let page = 0; page < EVENT_PAGES_READ; page += 1) {
    const pageRead = body(await reader("sanctuary_events_read", { cursor: opened.cursor, opts: { limit: EVENTS_PER_PAGE } }));
    const events = pageRead.events as Array<Record<string, unknown>>;
    pages.push(events.map((e) => [e.cursor_event_id, e.operation, e.result, e.has_details]));
    if (events.length === 0) break;
  }
  await reader("sanctuary_events_close", { cursor: opened.cursor });
  const searched = body(await reader("sanctuary_audit_search", { query: MATCH_EVERY_ROW, limit: AUDIT_SEARCH_MAX_LIMIT }));
  const search = (searched.results as Array<Record<string, unknown>>).map((r) => [r.audit_ref, r.operation, r.verification, r.summary]);
  const monitored = body(await reader("monitor_audit_log", { limit: 1_000 }));
  const monitor = {
    count: monitored.count,
    rows: (monitored.entries as Array<Record<string, unknown>>).map((e) => [e.operation, e.result, e.has_details]),
  };
  const siem: Record<string, unknown> = {};
  for (const format of SIEM_EXPORT_FORMATS) {
    const exported = await reader("audit_export_siem", { format, limit: 1_000 });
    const head = body(exported);
    const events = (exported.content as Array<{ text: string }>)[1]!.text;
    siem[format] = {
      count: head.count,
      total_available: head.total_available,
      events: format === "cef" ? events.split("\n").filter((line) => line.length > 0).length : (JSON.parse(events) as unknown[]).length,
      // The serialized events themselves, so a refused row cannot hide behind an equal count.
      contents: normalizeTimes(events),
    };
  }
  return { pages, search, monitor, siem, whole };
}

// Rows written before observation carry each world's own write time; only their order and contents are compared.
const ISO_TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/g;
// 13 digits = epoch milliseconds from 2001 to 2286, the SIEM formats' numeric time fields.
const EPOCH_MILLIS = /\b\d{13}\b/g;

function normalizeTimes(text: string): string {
  return text.replace(ISO_TIMESTAMP, "<timestamp>").replace(EPOCH_MILLIS, "<epoch_ms>");
}

// Must match the cursor id shape `cursor:<24 hex>` and the audit_ref shape `audit:<operation>:<16 hex>` the cooperative surface returns.
const CURSOR_ID = /cursor:[0-9a-f]{24}/g;
const AUDIT_REF = /audit:[a-z_]+:[0-9a-f]{16}/g;

/** A reader's whole result serialized, with times, the world's own identity and per-call random identifiers normalized. */
function normalizeWhole(world: World, result: CallResult): string {
  return normalizeTimes(JSON.stringify(result))
    .split(world.identityId).join("<self>")
    .replace(CURSOR_ID, "<cursor>")
    .replace(AUDIT_REF, "<audit_ref>");
}

/** Both worlds' observation passes under one frozen clock, so no reading depends on when a world was observed. */
async function observeFrozen(treatment: World, control: World): Promise<{ treatment: unknown; control: unknown }> {
  vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
  try {
    return { treatment: await observe(treatment), control: await observe(control) };
  } finally {
    vi.useRealTimers();
  }
}

/** The cause the ledger recorded for the treatment's refused call of `tool`, so each case is the class it names. */
async function ledgerCause(world: World, tool: string): Promise<unknown> {
  let cause: unknown;
  await vi.waitFor(async () => {
    const row = (await operatorRows(world)).find((r) => r.operation === "denial_cause" && r.details?.tool === tool);
    expect(row).toBeDefined();
    cause = row!.details?.cause;
  });
  return cause;
}

async function operatorRows(world: World): Promise<Array<{ operation: string; identity_id: string; call_ref?: string; details?: Record<string, unknown> }>> {
  await world.app.auditLog.flush();
  return (await world.app.auditLog.query({ limit: 100_000 })).entries;
}

interface Case {
  label: string;
  setup: (world: World) => Promise<void>;
  measured: (world: World) => Promise<CallResult>;
  /** The measured call writes at least one row under the agent's own identity. */
  writesOwnRow: boolean;
  /** The refusal class this case drives, as the ledger records it, with the tool it is recorded under. */
  ledger?: { tool: string; cause: string };
}

/** Fault injection for one measured call only; every other call in the world runs unfaulted. */
function duringMeasured<T>(arm: (on: { active: boolean }) => void, measured: () => Promise<T>): Promise<T> {
  const on = { active: true };
  arm(on);
  return measured().finally(() => { on.active = false; });
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
  {
    label: "pre-gate refusal of a bound-only tool in a session with no identity",
    setup: async () => undefined,
    measured: async (w) => {
      delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
      return w.client.callTool({ name: "sanctuary_events_open_cursor", arguments: {} });
    },
    writesOwnRow: false,
    ledger: { tool: "sanctuary_events_open_cursor", cause: "session_not_bound" },
  },
  {
    label: "write stop on audit integrity findings",
    setup: async () => undefined,
    measured: (w) => duringMeasured((on) => {
      // The prototype's method, so a world that already carries a spy from an earlier case is not re-entered.
      const read = Object.getPrototypeOf(w.app.auditLog).getIntegrityFindings.bind(w.app.auditLog) as typeof w.app.auditLog.getIntegrityFindings;
      vi.spyOn(w.app.auditLog, "getIntegrityFindings").mockImplementation(async () =>
        on.active ? [{ kind: "entry_hash_mismatch", message: "injected finding", sequence: 1 }] as Awaited<ReturnType<typeof read>> : read());
    }, () => call(w, "sanctuary_remember", { key: "stopped", value: "v" })),
    writesOwnRow: false,
    ledger: { tool: "sanctuary_remember", cause: "write_integrity_stop" },
  },
  {
    label: "integrity read fault",
    setup: async () => undefined,
    measured: (w) => duringMeasured((on) => {
      // The prototype's method, so a world that already carries a spy from an earlier case is not re-entered.
      const read = Object.getPrototypeOf(w.app.auditLog).getIntegrityFindings.bind(w.app.auditLog) as typeof w.app.auditLog.getIntegrityFindings;
      vi.spyOn(w.app.auditLog, "getIntegrityFindings").mockImplementation(async () => {
        if (on.active) throw new Error("injected integrity read fault");
        return read();
      });
    }, () => call(w, "sanctuary_remember", { key: "unread", value: "v" })),
    writesOwnRow: false,
    ledger: { tool: "sanctuary_remember", cause: "integrity_read_fault" },
  },
  {
    label: "handler throw",
    setup: async () => undefined,
    measured: (w) => duringMeasured((on) => {
      const write = (Object.getPrototypeOf(w.storage).write as MemoryStorage["write"]).bind(w.storage);
      vi.spyOn(w.storage, "write").mockImplementation(async (namespace, key, value) => {
        if (on.active && key.includes("thrown")) throw new Error("injected store fault");
        return write(namespace, key, value);
      });
    }, () => call(w, "state_write", { namespace: "opacity", key: "thrown", value: "v" })),
    writesOwnRow: false,
    ledger: { tool: "state_write", cause: "handler_error" },
  },
];

describe("a refused call adds nothing to any agent reader", () => {
  it("control: two worlds with the same history read back the same across a page boundary and the search limit", async () => {
    const a = await boot();
    const b = await boot();
    for (const world of [a, b]) {
      for (let i = 0; i < BOUNDARY_SETUP_SAVES; i += 1) await succeed(world, "sanctuary_remember", { key: `k-${i}`, value: "v" });
    }
    const observed = await observeFrozen(a, b);
    const oa = observed.treatment as { pages: unknown[][]; search: unknown[] };
    const ob = observed.control;
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
      if (c.ledger) expect(await ledgerCause(treatment, c.ledger.tool), c.label).toBe(c.ledger.cause);
      const observed = await observeFrozen(treatment, control);
      expect(observed.treatment).toEqual(observed.control);
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
    const observed = await observeFrozen(treatment, control);
    expect(observed.treatment).toEqual(observed.control);
  }, 240_000);
});

// The publish endpoint path reputation_publish posts to; the mocked transport answers it and nothing else.
const PUBLISH_PATH = "/api/publish";
// A status the publish endpoint can answer with that the tool reports as not published.
const PUBLISH_REFUSED_STATUS = 403;
const PUBLISH_DATA = { sovereigntyLayers: [], reputationDimensions: [], capabilities: [], overallScore: 0 };

/** The transport, mocked as seam12-shr-publish-evidence mocks it: no call leaves the process, and only the publish path answers. */
function mockPublishTransport(status: number): void {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.endsWith(PUBLISH_PATH)) throw new Error("unexpected transport call");
    return { ok: status < 400, status, json: async () => ({ success: status < 400 }) } as unknown as Response;
  });
}

/** The SHR reputation evidence the agent-reachable SHR tools gather for this world's identity. */
async function shrEvidence(world: World): Promise<string> {
  const identity = world.app.identityManager.get(world.identityId)!;
  return JSON.stringify(await gatherReputationEvidence(new ReputationStore(world.storage, world.app.masterKey), world.app.auditLog, identity));
}

describe("reputation_publish through the router adds nothing to any agent reader or the SHR evidence", () => {
  it("a publish the endpoint refuses leaves every agent reader and the SHR evidence byte-equal to a world without it", async () => {
    mockPublishTransport(PUBLISH_REFUSED_STATUS);
    const control = await boot();
    const treatment = await boot();
    expect(await call(treatment, "reputation_publish", { type: "shr", data: PUBLISH_DATA })).toEqual(expectedRefusal());
    // The operator sees the publish row the refused call wrote, so the comparison below is not vacuous.
    const publishRows = (await operatorRows(treatment)).filter((row) => row.operation === "reputation_publish" && row.identity_id === treatment.identityId);
    expect(publishRows).toHaveLength(1);
    expect(await ledgerCause(treatment, "reputation_publish")).toBe("post_allow_refusal");
    const observed = await observeFrozen(treatment, control);
    expect(observed.treatment).toEqual(observed.control);
    expect(await shrEvidence(treatment)).toBe(await shrEvidence(control));
  }, 240_000);

  it("a publish cancelled after its success row is written leaves every agent reader and the SHR evidence byte-equal to a world without it", async () => {
    mockPublishTransport(200);
    const control = await boot();
    const treatment = await boot();
    const controller = new AbortController();
    const appendCritical = treatment.app.auditLog.appendCritical.bind(treatment.app.auditLog);
    vi.spyOn(treatment.app.auditLog, "appendCritical").mockImplementation(async (entry) => {
      await appendCritical(entry);
      // Cancelled once the publish row is durable, before the handler returns its success.
      if (entry.operation === "reputation_publish") controller.abort();
    });
    use(treatment);
    // The router's own request handler, so the cancel reaches the call's signal at once.
    const handler = (treatment.app.server as unknown as { _requestHandlers: Map<string, (request: unknown, extra: unknown) => Promise<unknown>> })
      ._requestHandlers.get("tools/call")!;
    const result = await handler({ method: "tools/call", params: { name: "reputation_publish", arguments: { type: "shr", data: PUBLISH_DATA } } }, { signal: controller.signal });
    expect(result).toEqual(expectedRefusal());
    expect(await ledgerCause(treatment, "reputation_publish")).toBe("call_cancelled");
    // The operator sees a success publish row for this identity, which the gather would count if it were not filtered.
    const publishRows = (await operatorRows(treatment)).filter((row) => row.operation === "reputation_publish" && row.identity_id === treatment.identityId);
    expect(publishRows.map((row) => (row as { result?: string }).result)).toEqual(["success"]);
    const observed = await observeFrozen(treatment, control);
    expect(observed.treatment).toEqual(observed.control);
    expect(await shrEvidence(treatment)).toBe(await shrEvidence(control));
    expect(JSON.parse(await shrEvidence(treatment)).verascore_linked).toBe(false);
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
    // The refused marker is reported by the next flush, once.
    await expect(treatment.app.auditLog.flush()).rejects.toBeInstanceOf(AuditLogPersistenceError);
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
    await expect(first.app.auditLog.flush()).rejects.toBeInstanceOf(AuditLogPersistenceError);
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

// Retention headroom above the rows already stored when the cap is set: enough successes to pass the cap and prune,
// with the refused calls landing after pruning has begun.
const RETENTION_HEADROOM_ROWS = 12;
const RETENTION_FILL_SAVES = RETENTION_HEADROOM_ROWS * 2;
// Few enough successes after the refused calls that their rows are still retained when the readers run.
const RETENTION_TAIL_SAVES = 2;

function emptyBackend(): Backend {
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() { return true; },
    async addSecret() {},
    async readSecret(n) { throw new SecretNotFoundError(n); },
    async rotateSecret() {},
    async deleteSecret() {},
    async listSecretNames() { return []; },
  };
}

describe("agent readers at the retention limit", () => {
  for (const boundary of ["count", "bytes"] as const) {
    it(`at the ${boundary} cap, no agent reader returns or counts a refused call's row`, async () => {
      const world = await boot();
      const log = world.app.auditLog;
      const broker = new Broker({ backend: emptyBackend(), auditLog: log, surrogateBoundSecrets: new Set(), grants: [{ skill: "gmail-triage", secret: "granted-key", scope: "read" }], principalIdentityId: world.identityId });
      const brokerServer = createBrokerMcpServer(broker, {
        skill: "gmail-triage", agentId: "nsa", identityId: world.identityId,
        tenantId: "tenant-alpha", fortressId: "fortress-alpha", audience: "sanctuary-broker",
      });
      type Handler = (req: unknown, extra: unknown) => Promise<{ isError?: boolean }>;
      const brokerCall = (brokerServer as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers.get("tools/call")!;
      await succeed(world, "sanctuary_remember", { key: "hidden-key", value: "v" });
      await succeed(world, "sanctuary_hide", { key: "hidden-key" });
      await log.flush();
      const usage = await log.getRetentionUsage();
      // The test sets the live log's retention caps; every other retention rule runs as configured.
      const caps = log as unknown as { maxEntries: number; maxTotalSizeBytes: number; rotationHysteresis: number };
      if (boundary === "count") {
        caps.maxEntries = usage.entryCount + RETENTION_HEADROOM_ROWS;
        caps.rotationHysteresis = 1;
      } else {
        caps.maxTotalSizeBytes = usage.totalSizeBytes + Math.ceil(usage.totalSizeBytes / usage.entryCount) * RETENTION_HEADROOM_ROWS;
      }
      for (let i = 0; i < RETENTION_FILL_SAVES; i += 1) await succeed(world, "sanctuary_remember", { key: `fill-${i}`, value: "v" });
      await log.flush();
      expect((await log.getRetentionUsage()).everPruned).toBe(true);

      // Two refused calls at the cap: a hidden recall through the server and a no-grant broker request on the same log.
      // Pruning shifts positions, so the refused calls' rows are found by the call references they add.
      const refsBefore = new Set((await operatorRows(world)).map((r) => r.call_ref));
      expect(await call(world, "sanctuary_recall", { key: "hidden-key" })).toEqual(expectedRefusal());
      expect((await brokerCall({ method: "tools/call", params: { name: "broker/request_token", arguments: { skill: "gmail-triage", secret: "never-granted" } } }, { signal: new AbortController().signal })).isError).toBe(true);
      const refusedRefs = new Set((await operatorRows(world)).map((r) => r.call_ref).filter((ref): ref is string => ref !== undefined && !refsBefore.has(ref)));
      for (let i = 0; i < RETENTION_TAIL_SAVES; i += 1) await succeed(world, "sanctuary_remember", { key: `tail-${i}`, value: "v" });
      const retained = await operatorRows(world);
      const refusedRows = retained.filter((r) => r.call_ref !== undefined && refusedRefs.has(r.call_ref));
      const otherOps = new Set(retained.filter((r) => !refusedRows.includes(r)).map((r) => r.operation));
      // Operations only the refused calls wrote, so their presence in any reader is a refused row. Only the refused
      // broker request writes a token denial in this world, so that operation is named without a call reference.
      const refusedOps = new Set([
        BROKER_OPS.TOKEN_DENIED,
        ...refusedRows.filter((r) => r.identity_id === world.identityId).map((r) => r.operation).filter((op) => !otherOps.has(op)),
      ]);
      // The operator view still holds the refused broker row at the cap, under the agent's identity.
      expect(retained.some((r) => r.operation === BROKER_OPS.TOKEN_DENIED && r.identity_id === world.identityId)).toBe(true);

      const observed = await observe(world) as { pages: Array<Array<[unknown, unknown, unknown, unknown]>>; search: Array<[unknown, unknown, unknown, unknown]>; monitor: { count: number; rows: Array<[unknown, unknown, unknown]> }; siem: Record<string, { count: number; total_available: number; events: number; contents: string }> };
      for (const page of observed.pages) for (const [, operation] of page) expect(refusedOps.has(operation as string), `events ${String(operation)}`).toBe(false);
      for (const [, operation] of observed.search) expect(refusedOps.has(operation as string), `search ${String(operation)}`).toBe(false);
      for (const [operation] of observed.monitor.rows) expect(refusedOps.has(operation as string), `monitor ${String(operation)}`).toBe(false);
      // Every limit is above the visible total, so each count is the number of rows the reader returned.
      expect(observed.monitor.count).toBe(observed.monitor.rows.length);
      for (const [format, siem] of Object.entries(observed.siem)) {
        expect(siem.count, format).toBe(siem.events);
        expect(siem.total_available, format).toBe(siem.count);
        for (const op of refusedOps) expect(siem.contents.includes(op), `${format} ${op}`).toBe(false);
      }
      const brokerRead = await broker.queryAudit({ limit: 1_000 });
      expect(brokerRead.total).toBe(brokerRead.entries.length);
      expect(brokerRead.entries.map((e) => e.operation)).not.toContain(BROKER_OPS.TOKEN_DENIED);
      // Both refused calls' rows, the recall's included, are still retained at the cap.
      expect(refusedRows.filter((r) => r.identity_id === world.identityId).map((r) => r.operation)).toEqual(expect.arrayContaining([BROKER_OPS.TOKEN_DENIED]));
      expect(refusedOps.size).toBeGreaterThan(1);
    }, 240_000);
  }
});
