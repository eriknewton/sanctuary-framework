/** Own-scope saves run silently and name their caller through the production server. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest, ApprovalResponse } from "../../src/principal-policy/types.js";
import { handlePostureRoute } from "../../src/principal-policy/posture-routes.js";
import { createDashboardReadFlightMap } from "../../src/dashboard/read-response.js";
import { createPosturePanelStore } from "../../src/principal-policy/panel-producer.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const WRAPPED_AGENT_ID = "hermes:fortress-0123456789abcdef";
const AGENT = `agent:${WRAPPED_AGENT_ID}`;
// Owner-only policy and fortress permissions match the production writer.
const POLICY_FILE_MODE = 0o600;
const FORTRESS_DIR_MODE = 0o700;
let fortressHome: Awaited<ReturnType<typeof createTempHome>>;
let originalAgentId: string | undefined;
let originalSessionId: string | undefined;
let cleanups: Array<() => Promise<void>>;

beforeEach(async () => {
  originalAgentId = process.env.SANCTUARY_AGENT_ID;
  originalSessionId = process.env.SANCTUARY_SESSION_IDENTITY_ID;
  delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
  process.env.SANCTUARY_AGENT_ID = WRAPPED_AGENT_ID;
  cleanups = [];
  fortressHome = await createTempHome("sanctuary-memory-saves");
  await mkdir(fortressHome.defaultFortressPath, { recursive: true, mode: FORTRESS_DIR_MODE });
});
afterEach(async () => {
  try {
    for (const cleanup of cleanups.reverse()) await cleanup();
  } finally {
    if (originalAgentId === undefined) delete process.env.SANCTUARY_AGENT_ID;
    else process.env.SANCTUARY_AGENT_ID = originalAgentId;
    if (originalSessionId === undefined) delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
    else process.env.SANCTUARY_SESSION_IDENTITY_ID = originalSessionId;
    await fortressHome.cleanup();
  }
});

async function boot(shape: "default" | "old" | "always" = "default") {
  let yaml = generateDefaultPolicyYaml().replace(/approval_channel:\n  type: \w+/, "approval_channel:\n  type: callback");
  if (shape === "old") {
    yaml = yaml.replace(/^memory_save_approval:.*\n/gm, "")
      .replace(/^  - memory_insert\n/gm, "")
      .replace("tier1_always_approve:\n", "tier1_always_approve:\n  - memory_insert\n");
  }
  if (shape === "always") {
    yaml = yaml.replace(/^memory_save_approval:.*\n/gm, "") + "\nmemory_save_approval: always\n";
  }
  await writeFile(join(fortressHome.defaultFortressPath, "principal-policy.yaml"), yaml, { mode: POLICY_FILE_MODE });
  const captured: ApprovalRequest[] = [];
  const deny = async (request: ApprovalRequest): Promise<ApprovalResponse> => {
    captured.push(request);
    return { decision: "deny", decided_at: new Date().toISOString(), decided_by: "human" };
  };
  const storage = new MemoryStorage();
  const booted = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE, approvalCallback: deny });
  cleanups.push(() => booted.cleanup());
  const handler = (booted.server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  const call = (name: string, args: Record<string, unknown>) => handler({ method: "tools/call", params: { name, arguments: args } }, {});
  // A real wrapped installation has a primary identity and an active session.
  // Provision both through the production identity tool in this empty temp fortress.
  const identity = JSON.parse((await call("identity_create", { label: "memory-owner" })).content[0].text);
  expect(identity.identity_id).toEqual(expect.any(String));
  process.env.SANCTUARY_SESSION_IDENTITY_ID = identity.identity_id;
  return { booted, captured, call, storage };
}

async function evidence(booted: Awaited<ReturnType<typeof createSanctuaryServer>>, query = "") {
  // Same route-layer rig as posture-evidence.test.ts: dashboard checkAuth belongs
  // to its caller; this exercises the exported route's unlocked-log data source.
  const server: Server = createServer(async (req, res) => {
    await handlePostureRoute({
      // The route requires its per-instance panel store (fails closed at the type level); same rig as posture-evidence.test.ts.
      panelStore: createPosturePanelStore(), readFlightMap: createDashboardReadFlightMap(), auditLog: booted.auditLog,
      originMachine: "fortress:memory-saves", listAgents: () => [], detectInstalledHarnesses: async () => [],
    }, req, res, new URL(req.url ?? "/", `http://${req.headers.host}`), req.method ?? "GET");
  });
  cleanups.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const response = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/api/posture/evidence${query}`);
  expect(response.status).toBe(200);
  return await response.json() as { entries: Array<Record<string, unknown>> };
}

for (const shape of ["default", "old"] as const) {
  describe(`${shape} fortress policy`, () => {
    it("inserts silently with exactly one agent-named save record", async () => {
      const { booted, captured, call } = await boot(shape);
      const result = await call("memory_insert", { text: "A quiet memory of a blue cup.", taint: "user_content" });
      expect(JSON.parse(result.content[0].text).inserted).toBe(true);
      expect(captured).toHaveLength(0);
      const { entries } = await booted.auditLog.query({});
      const saves = entries.filter(e => e.operation === "memory_insert");
      expect(saves).toHaveLength(1);
      expect(saves[0]).toMatchObject({ identity_id: AGENT, details: { agent_id: AGENT } });
      expect(entries.filter(e => /^(gate_approve|gate_deny|gate_unclassified|approval)/.test(e.operation))).toHaveLength(0);
    });
    it("remembers silently on first access with one agent-named save record", async () => {
      const { booted, captured, call } = await boot(shape);
      const result = await call("sanctuary_remember", { key: "cup", value: "blue" });
      expect(JSON.parse(result.content[0].text).key).toBe("cup");
      expect(captured).toHaveLength(0);
      const { entries } = await booted.auditLog.query({});
      const saves = entries.filter(e => e.operation === "sanctuary_remember");
      expect(saves).toHaveLength(1);
      expect(saves[0]?.details?.agent_id).toBe(AGENT);
    });
    it("serves both agent-named saves from the Evidence data source", async () => {
      const { booted, call } = await boot(shape);
      await call("memory_insert", { text: "A blue cup.", taint: "user_content" });
      await call("sanctuary_remember", { key: "cup", value: "blue" });
      const body = await evidence(booted);
      expect(body.entries).toEqual(expect.arrayContaining([
        expect.objectContaining({ operation: "memory_insert", identity_id: AGENT }),
        expect.objectContaining({ operation: "sanctuary_remember", details: expect.objectContaining({ agent_id: AGENT }) }),
      ]));
    });
  });
}
it("honors the explicit always policy with one denied Tier 1 hold and no passage", async () => {
  const { booted, captured, call } = await boot("always");
  expect(booted.policy).toHaveProperty("memory_save_approval", "always");
  await call("memory_insert", { text: "A blue cup.", taint: "user_content", passage_id: "never-written" });
  expect(captured).toHaveLength(1);
  expect(captured[0]).toMatchObject({ operation: "memory_insert", tier: 1 });
  const result = await call("memory_get", { passage_id: "never-written" });
  expect(JSON.parse(result.content[0].text).passage).toBeUndefined();
  expect((await booted.auditLog.query({})).entries.filter(e => e.operation === "memory_insert")).toHaveLength(0);
});

// fail-before-exempt: W6 expands the closed save table; forced Tier 1 must also remain intact.
it("keeps delete, forget, export, signing, policy reads and batch execution at Tier 1", async () => {
  const { OWN_SCOPE_MEMORY_SAVES } = await import("../../src/principal-policy/gate.js");
  if (OWN_SCOPE_MEMORY_SAVES) expect(Object.keys(OWN_SCOPE_MEMORY_SAVES).sort()).toEqual(["memory_insert", "sanctuary_remember"]);
  const { captured, call } = await boot();
  const cases: Array<[string, Record<string, unknown>]> = [
    ["sanctuary_forget", { key: "cup", mode: "secure", approval_ref: "" }],
    ["memory_delete", { passage_id: "cup" }],
    ["state_export", {}],
    ["identity_sign", { payload: "message" }],
    ["principal_policy_view", {}],
    ["sanctuary_policy_status", {}],
    ["sanctuary_compound_execute", { steps: [{ tool: "sanctuary_remember", args: { key: "cup", value: "blue" } }] }],
  ];
  for (const [name, args] of cases) {
    const before = captured.length;
    await call(name, args);
    expect(captured.length, name).toBe(before + 1);
    expect(captured.at(-1)?.tier, name).toBe(1);
  }
});
it("remembers later saves without a hold and observes the first namespace", async () => {
  const { booted, call, captured } = await boot();
  for (const value of ["blue", "green"]) {
    const result = JSON.parse((await call("sanctuary_remember", { key: "cup", value })).content[0].text);
    expect(result.key).toBe("cup");
  }
  expect(captured).toHaveLength(0);
  const { entries } = await booted.auditLog.query({});
  expect(entries.filter(e => e.operation === "sanctuary_remember")).toHaveLength(2);
  expect(entries.filter(e => e.operation === "memory_save_anomaly_observed:state_write")).toHaveLength(1);
});
// fail-before-exempt: bypassing facadeMemoryNamespace ownership would turn this red.
it("refuses a remember handle owned by another session before the gate", async () => {
  const { call, captured } = await boot();
  const first = JSON.parse((await call("sanctuary_remember", { key: "cup", value: "blue" })).content[0].text);
  expect(first.namespace_handle).toEqual(expect.any(String));
  const other = JSON.parse((await call("identity_create", { label: "other-session" })).content[0].text);
  process.env.SANCTUARY_SESSION_IDENTITY_ID = other.identity_id;
  const result = JSON.parse((await call("sanctuary_remember", { key: "cup", value: "green", opts: { namespace: first.namespace_handle } })).content[0].text);
  expect(result.denied).toBe(true);
  expect(captured).toHaveLength(0);
});
it("refuses a second wrapped identity after silent admission with an audited isolation denial", async () => {
  const { call, booted, captured } = await boot();
  expect(JSON.parse((await call("memory_insert", { text: "first", taint: "user_content" })).content[0].text).inserted).toBe(true);
  process.env.SANCTUARY_AGENT_ID = "other:fortress-0123456789abcdef";
  expect(JSON.parse((await call("memory_insert", { text: "second", taint: "user_content" })).content[0].text).denied).toBe(true);
  expect(captured).toHaveLength(0);
  const { entries } = await booted.auditLog.query({});
  expect(entries.filter(e => e.operation === "memory_insert")).toHaveLength(1);
  expect(entries).toEqual(expect.arrayContaining([expect.objectContaining({ operation: "memory_insert_denied", details: expect.objectContaining({ denial_class: "sdw_memory_multi_agent_isolation_required" }) })]));
});
it("refuses an unset wrapped identity after silent admission with owner_identity_missing", async () => {
  const { call, booted, captured } = await boot();
  delete process.env.SANCTUARY_AGENT_ID;
  expect(JSON.parse((await call("memory_insert", { text: "no owner", taint: "user_content" })).content[0].text).denied).toBe(true);
  expect(captured).toHaveLength(0);
  const { entries } = await booted.auditLog.query({});
  expect(entries.filter(e => e.operation === "memory_insert")).toHaveLength(0);
  expect(entries).toEqual(expect.arrayContaining([expect.objectContaining({ operation: "memory_insert_denied", details: expect.objectContaining({ denial_class: "sdw_memory_multi_agent_isolation_required" }) })]));
});

it("denies remember without persisting a value when its attribution audit fails", async () => {
  const { booted, call, storage } = await boot();
  const append = booted.auditLog.appendCritical.bind(booted.auditLog);
  const spy = vi.spyOn(booted.auditLog, "appendCritical").mockImplementation(async entry => {
    if (entry.operation === "sanctuary_remember_intent") throw new Error("injected attribution failure");
    return append(entry);
  });
  const writes = vi.spyOn(storage, "write");
  try {
    const result = JSON.parse((await call("sanctuary_remember", { key: "audit-failure", value: "blue" })).content[0].text);
    expect(result.denied).toBe(true);
    expect(writes.mock.calls.filter(([, key]) => key === "audit-failure")).toHaveLength(0);
    expect((await booted.auditLog.query({})).entries.filter(e => e.operation === "sanctuary_remember")).toHaveLength(0);
  } finally { spy.mockRestore(); writes.mockRestore(); }
});

it.each(["interrupt", "resume"])("remember %s between durable attribution and commit preserves ordering", async outcome => {
  const { booted, call, storage } = await boot();
  const append = booted.auditLog.appendCritical.bind(booted.auditLog);
  let release!: () => void;
  let entered!: () => void;
  const paused = new Promise<void>(resolve => { release = resolve; });
  const started = new Promise<void>(resolve => { entered = resolve; });
  const spy = vi.spyOn(booted.auditLog, "appendCritical").mockImplementation(async entry => {
    const result = await append(entry);
    if (entry.operation === "sanctuary_remember_intent") {
      entered();
      await paused;
      if (outcome === "interrupt") throw new Error("interrupted before value commit");
    }
    return result;
  });
  const writes = vi.spyOn(storage, "write");
  const pending = call("sanctuary_remember", { key: "audit-order", value: "blue" });
  try {
    await started;
    expect(writes.mock.calls.filter(([, key]) => key === "audit-order")).toHaveLength(0);
    expect((await booted.auditLog.query({})).entries.filter(e => e.operation === "sanctuary_remember_intent"))
      .toEqual([expect.objectContaining({ details: expect.objectContaining({ agent_id: AGENT }) })]);
    expect((await booted.auditLog.query({})).entries.filter(e => e.operation === "sanctuary_remember")).toEqual([]);
    release();
    const result = JSON.parse((await pending).content[0].text);
    if (outcome === "interrupt") {
      expect(result.denied).toBe(true);
      expect(writes.mock.calls.filter(([, key]) => key === "audit-order")).toHaveLength(0);
      expect((await booted.auditLog.query({})).entries.filter(e => e.operation === "sanctuary_remember")).toEqual([]);
    } else {
      expect(result.key).toBe("audit-order");
      expect(writes.mock.calls.filter(([, key]) => key === "audit-order")).toHaveLength(1);
      const rows = (await booted.auditLog.query({})).entries;
      const intent = rows.find(e => e.operation === "sanctuary_remember_intent")!;
      expect(rows.filter(e => e.operation === "sanctuary_remember")).toEqual([expect.objectContaining({ result: "success", details: expect.objectContaining({ agent_id: AGENT, intent_audit_ref: intent.details!.audit_ref }) })]);
    }
  } finally { release(); await pending; spy.mockRestore(); writes.mockRestore(); }
});

it("marks an unknown remember caller without changing silent-save behavior", async () => {
  const { booted, call, captured } = await boot();
  delete process.env.SANCTUARY_AGENT_ID;
  expect(JSON.parse((await call("sanctuary_remember", { key: "unknown", value: "blue" })).content[0].text).key).toBe("unknown");
  expect(captured).toHaveLength(0);
  expect((await booted.auditLog.query({})).entries.filter(e => e.operation === "sanctuary_remember"))
    .toEqual([expect.objectContaining({ details: expect.objectContaining({ agent_id: "agent:unknown" }) })]);
});


it("records a refused remember as intent plus linked failure without a success or value", async () => {
  const { booted, call, storage } = await boot();
  const key = "\ud800x";
  const writes = vi.spyOn(storage, "write");
  try {
    const result = JSON.parse((await call("sanctuary_remember", { key, value: "blue" })).content[0].text);
    expect(result.denied).toBe(true);
    expect(writes.mock.calls.filter(([, writtenKey]) => writtenKey === key)).toEqual([]);
    const rows = (await booted.auditLog.query({})).entries;
    const intents = rows.filter(e => e.operation === "sanctuary_remember_intent");
    expect(intents).toHaveLength(1);
    expect(intents[0].details!.agent_id).toBe(AGENT);
    expect(rows.filter(e => e.operation === "sanctuary_remember")).toEqual([expect.objectContaining({ result: "failure", details: expect.objectContaining({ agent_id: AGENT, intent_audit_ref: intents[0].details!.audit_ref }) })]);
  } finally { writes.mockRestore(); }
});

it("a thrown write leaves intent only and returns the caller an error", async () => {
  const { booted, call, storage } = await boot();
  const write = storage.write.bind(storage);
  const spy = vi.spyOn(storage, "write").mockImplementation(async (namespace, key, value) => {
    if (key === "throw-write") throw new Error("injected storage failure");
    return write(namespace, key, value);
  });
  try {
    const result = await call("sanctuary_remember", { key: "throw-write", value: "blue" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).error).toBe("tool execution failed");
    const rows = (await booted.auditLog.query({})).entries;
    const intent = rows.find(e => e.operation === "sanctuary_remember_intent")!;
    expect(intent.details!.agent_id).toBe(AGENT);
    expect(rows.filter(e => e.operation === "sanctuary_remember")).toEqual([]);
    const failedWrite = spy.mock.calls.find(([, key]) => key === "throw-write");
    expect(failedWrite).toBeDefined();
    expect(await storage.read(failedWrite![0], failedWrite![1])).toBeNull();
  } finally { spy.mockRestore(); }
});

it("an interruption after commit leaves the value with intent only in Evidence", async () => {
  const { booted, call, storage } = await boot();
  const append = booted.auditLog.appendCritical.bind(booted.auditLog);
  const spy = vi.spyOn(booted.auditLog, "appendCritical").mockImplementation(async entry => {
    if (entry.operation === "sanctuary_remember") throw new Error("interrupted before outcome append");
    return append(entry);
  });
  const writes = vi.spyOn(storage, "write");
  try {
    expect(JSON.parse((await call("sanctuary_remember", { key: "committed-intent", value: "blue" })).content[0].text).denied).toBe(true);
    expect(writes.mock.calls.filter(([, key]) => key === "committed-intent")).toHaveLength(1);
    expect(JSON.parse((await call("sanctuary_recall", { key: "committed-intent" })).content[0].text).value).toBe("blue");
    const served = await evidence(booted);
    expect(served.entries.filter(e => e.operation === "sanctuary_remember_intent")).toEqual([expect.objectContaining({ details: expect.objectContaining({ agent_id: AGENT }) })]);
    expect(served.entries.filter(e => e.operation === "sanctuary_remember")).toEqual([]);
  } finally { spy.mockRestore(); writes.mockRestore(); }
});


it("a last-write anchor failure preserves the value and intent without an outcome", async () => {
  const { STATE_ENVELOPE_VERSION_ANCHORS_KEY } = await import("../../src/cognitive/state-store.js");
  const { booted, call, storage } = await boot();
  const write = storage.write.bind(storage);
  let persisted: [string, string] | undefined;
  const spy = vi.spyOn(storage, "write").mockImplementation(async (namespace, key, value) => {
    if (key === STATE_ENVELOPE_VERSION_ANCHORS_KEY && persisted) throw new Error("injected final anchor failure");
    await write(namespace, key, value);
    if (key === "anchor-failure") persisted = [namespace, key];
  });
  try {
    const result = await call("sanctuary_remember", { key: "anchor-failure", value: "blue" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).error).toBe("tool execution failed");
    expect(persisted).toBeDefined();
    expect(await storage.read(...persisted!)).not.toBeNull();
    spy.mockRestore();
    expect(JSON.parse((await call("sanctuary_recall", { key: "anchor-failure" })).content[0].text).value).toBe("blue");
    const rows = (await booted.auditLog.query({})).entries;
    expect(rows.filter(e => e.operation === "sanctuary_remember_intent")).toEqual([
      expect.objectContaining({ details: expect.objectContaining({ agent_id: AGENT }) }),
    ]);
    expect(rows.filter(e => e.operation === "sanctuary_remember")).toEqual([]);
    expect(rows).toContainEqual(expect.objectContaining({ operation: "tool_error:sanctuary_remember", details: expect.objectContaining({ error: "injected final anchor failure" }) }));
  } finally { spy.mockRestore(); }
});

it.each(["committed", "duplicate_passage", "classifier_reject", "throw"])("insert %s has truthful intent and outcome evidence", async scenario => {
  const { SdwMemoryBackendAdapter } = await import("../../src/sdw/adapters/sdw-memory-backend.js");
  const { booted, call } = await boot();
  const args = { passage_id: "insert-outcome", text: "A blue cup.", taint: "user_content" };
  if (scenario === "duplicate_passage") await call("memory_insert", args);
  if (scenario === "classifier_reject") args.text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----";
  const insert = SdwMemoryBackendAdapter.prototype.insertPassage;
  const spy = scenario === "throw" ? vi.spyOn(SdwMemoryBackendAdapter.prototype, "insertPassage").mockImplementation(async function (this: InstanceType<typeof SdwMemoryBackendAdapter>, ...params) {
    await insert.apply(this, params);
    throw new Error("injected insert completion failure");
  }) : undefined;
  try {
    const result = await call("memory_insert", args);
    const rows = (await booted.auditLog.query({})).entries;
    const intent = rows.filter(e => e.operation === "memory_insert_intent").at(-1)!;
    expect(intent).toMatchObject({ identity_id: AGENT, details: { agent_id: AGENT, audit_ref: expect.any(String) } });
    const outcomes = rows.filter(e => e.operation === "memory_insert" && e.details?.intent_audit_ref === intent.details!.audit_ref);
    if (scenario === "throw") {
      expect(result.isError).toBe(true);
      expect(outcomes).toEqual([]);
      expect(JSON.parse((await call("memory_get", { passage_id: args.passage_id })).content[0].text).found).toBe(true);
    } else {
      const committed = scenario === "committed";
      expect(JSON.parse(result.content[0].text)[committed ? "inserted" : "denied"]).toBe(true);
      expect(outcomes).toEqual([expect.objectContaining({ result: committed ? "success" : "failure", identity_id: AGENT })]);
      if (!committed) expect(outcomes.filter(e => e.result === "success")).toEqual([]);
    }
    // Execute the shipping chip projection against the actual served rows, including a duplicate's second intent.
    const served = await evidence(booted);
    expect(served.entries).toContainEqual(expect.objectContaining({ operation: "memory_insert_intent", details: expect.objectContaining({ audit_ref: intent.details!.audit_ref }) }));
    const { getClientScript } = await import("../../src/dashboard/v1_1/client.js");
    const { runInNewContext } = await import("node:vm");
    const script = getClientScript();
    const chipFunction = script.slice(script.indexOf("function evidenceResultChip("), script.indexOf("// The Agent cell", script.indexOf("function evidenceResultChip(")));
    const chip = runInNewContext(chipFunction + "\nevidenceResultChip(intent)", {
      intent, state: { evidence: { view: served } }, renderEvidenceStatusChip: (_kind: string, label: string) => label,
    });
    expect(chip).toContain("save attempted,");
    expect(chip).not.toMatch(/Success|success/);
    if (scenario === "throw") expect(chip).toBe("save attempted, outcome not shown on this page");
  } finally { spy?.mockRestore(); }
});

it("denies insert without persisting when its intent cannot be audited", async () => {
  const { booted, call } = await boot();
  const append = booted.auditLog.appendCritical.bind(booted.auditLog);
  const spy = vi.spyOn(booted.auditLog, "appendCritical").mockImplementation(async entry => {
    if (entry.operation === "memory_insert_intent") throw new Error("injected intent failure");
    return append(entry);
  });
  try {
    expect(JSON.parse((await call("memory_insert", { passage_id: "intent-failed", text: "blue", taint: "user_content" })).content[0].text).denied).toBe(true);
    expect(JSON.parse((await call("memory_get", { passage_id: "intent-failed" })).content[0].text).found).toBe(false);
    expect((await booted.auditLog.query({})).entries.filter(e => e.operation === "memory_insert")).toEqual([]);
  } finally { spy.mockRestore(); }
});

it("Evidence agent filtering finds displayed remember attribution before pagination without changing own-signed access", async () => {
  const { booted, call } = await boot();
  await call("sanctuary_remember", { key: "filtered", value: "blue" });
  const rows = (await booted.auditLog.query({})).entries.filter(e => e.operation.startsWith("sanctuary_remember"));
  expect(rows).toHaveLength(2); // One intent and its outcome.
  for (const operation of ["state_read", "unrelated"]) {
    await booted.auditLog.appendCritical({ layer: "l2", operation, identity_id: "other", result: "success", details: { agent_id: AGENT } });
  }
  const served = await evidence(booted, `?agent=${encodeURIComponent(AGENT)}&limit=2`);
  expect(served.entries).toEqual(rows);
  expect((await booted.auditLog.query({ identity_id: AGENT })).entries.filter(e => e.operation.startsWith("sanctuary_remember"))).toEqual([]);
  expect((await booted.auditLog.query({ identity_id: rows[0].identity_id, evidence_agent: AGENT })).entries).toEqual(rows);
});

it("an insert outcome append failure leaves the committed passage with intent only", async () => {
  const { booted, call } = await boot();
  const append = booted.auditLog.appendCritical.bind(booted.auditLog);
  const spy = vi.spyOn(booted.auditLog, "appendCritical").mockImplementation(async entry => {
    if (entry.operation === "memory_insert") throw new Error("injected insert outcome failure");
    return append(entry);
  });
  try {
    const result = await call("memory_insert", { passage_id: "outcome-failed", text: "blue", taint: "user_content" });
    expect(result.isError).toBe(true);
    expect(JSON.parse((await call("memory_get", { passage_id: "outcome-failed" })).content[0].text).found).toBe(true);
    const rows = (await booted.auditLog.query({})).entries;
    expect(rows.filter(e => e.operation === "memory_insert_intent")).toEqual([expect.objectContaining({ details: expect.objectContaining({ agent_id: AGENT }) })]);
    expect(rows.filter(e => e.operation === "memory_insert")).toEqual([]);
  } finally { spy.mockRestore(); }
});

it("public save copy states the bounded allowance and ordinary Tier 2 approval", async () => {
  const { readFile } = await import("node:fs/promises");
  const { booted } = await boot();
  const list = (booted.server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get("tools/list")!;
  const tools = (await list({ method: "tools/list", params: {} }, {})).tools as Array<{ name: string; description: string }>;
  const description = tools.find(t => t.name === "memory_insert")!.description;
  // The generated operator policy comment is shipped copy too: generateDefaultPolicyYaml() is written into the policy file.
  const copies = [description, generateDefaultPolicyYaml(),
    await readFile(new URL("../../../docs/agent-guided-install.md", import.meta.url), "utf8"),
    await readFile(new URL("../../../docs/rung1-fresh-host.md", import.meta.url), "utf8"),
    await readFile(new URL("../../../CHANGELOG.md", import.meta.url), "utf8"),
    await readFile(new URL("../../../plugin/skills/sanctuary/SKILL.md", import.meta.url), "utf8"),
  ];
  for (const copy of copies) {
    expect(copy).toContain("under the default policy within a bounded save allowance");
    expect(copy).toContain("beyond it an ordinary Tier 2 approval is requested");
  }
});


it("a real insert rollback failure preserves records and intent only with a generic router error", async () => {
  const { SDW_DOCUMENT_CORPUS_NAMESPACE } = await import("../../src/sdw/records.js");
  const { booted, call, storage } = await boot();
  const write = storage.write.bind(storage);
  const remove = storage.delete.bind(storage);
  const written = new Map<string, Uint8Array>();
  const refusedDeletes: string[] = [];
  let failedAfterDocument = false;
  const writes = vi.spyOn(storage, "write").mockImplementation(async (namespace, key, data) => {
    await write(namespace, key, data);
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE) {
      written.set(key, new Uint8Array(data));
      if (key.startsWith("doc.")) {
        failedAfterDocument = true;
        throw new Error("injected failure after document persistence");
      }
    }
  });
  const deletes = vi.spyOn(storage, "delete").mockImplementation(async (namespace, key, ...rest) => {
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE && failedAfterDocument) {
      refusedDeletes.push(key);
      throw new Error("injected compensating delete failure");
    }
    return remove(namespace, key, ...rest);
  });
  try {
    const result = await call("memory_insert", { passage_id: "rollback-survivor", text: "A blue cup.", taint: "user_content" });
    expect(failedAfterDocument).toBe(true);
    expect(refusedDeletes).toEqual(expect.arrayContaining([...written.keys()]));
    expect([...written.keys()].some(key => key.startsWith("doc."))).toBe(true);
    expect([...written.keys()].some(key => key.startsWith("chunk."))).toBe(true);
    for (const [key, bytes] of written) expect(await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key)).toEqual(bytes);
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toEqual({ error: "tool execution failed", audit_ref: expect.any(String) });
    const rows = (await booted.auditLog.query({})).entries;
    expect(rows.filter(e => e.operation === "memory_insert_intent")).toEqual([
      expect.objectContaining({ identity_id: AGENT, details: expect.objectContaining({ agent_id: AGENT, audit_ref: expect.any(String) }) }),
    ]);
    expect(rows.filter(e => e.operation === "memory_insert")).toEqual([]);
  } finally { writes.mockRestore(); deletes.mockRestore(); }
});

it.each(["invalid_text", "invalid_identifier"])("insert pre-write %s is a confirmed refusal", async category => {
  const { booted, call, storage } = await boot();
  const { SDW_DOCUMENT_CORPUS_NAMESPACE } = await import("../../src/sdw/records.js");
  const result = await call("memory_insert", {
    passage_id: "invalid-input", taint: "user_content",
    text: category === "invalid_text" ? "bad \ud800 text" : "A blue cup.",
    tags: category === "invalid_identifier" ? ["bad tag with spaces"] : [],
  });
  expect(JSON.parse(result.content[0].text).denied).toBe(true);
  expect(await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE)).toEqual([]);
  const rows = (await booted.auditLog.query({})).entries;
  const intent = rows.find(e => e.operation === "memory_insert_intent")!;
  expect(intent).toBeDefined();
  expect(rows.filter(e => e.operation === "memory_insert")).toEqual([
    expect.objectContaining({ result: "failure", details: expect.objectContaining({ intent_audit_ref: intent.details!.audit_ref }) }),
  ]);
  expect(rows).toContainEqual(expect.objectContaining({ operation: "memory_insert_denied", details: expect.objectContaining({ denial_class: category }) }));
});

it("an unclassified validation throw after insert commit leaves intent only", async () => {
  const { SdwMemoryBackendAdapter } = await import("../../src/sdw/adapters/sdw-memory-backend.js");
  const { SdwValidationError } = await import("../../src/sdw/errors.js");
  const { booted, call } = await boot();
  const insert = SdwMemoryBackendAdapter.prototype.insertPassage;
  const spy = vi.spyOn(SdwMemoryBackendAdapter.prototype, "insertPassage").mockImplementation(async function (this: InstanceType<typeof SdwMemoryBackendAdapter>, ...params) {
    await insert.apply(this, params);
    throw new SdwValidationError("unclassified", "injected late validation error");
  });
  try {
    const result = await call("memory_insert", { passage_id: "late-validation", text: "A blue cup.", taint: "user_content" });
    expect(JSON.parse(result.content[0].text)).toMatchObject({ error: "tool execution failed" });
    expect(JSON.parse((await call("memory_get", { passage_id: "late-validation" })).content[0].text).found).toBe(true);
    const rows = (await booted.auditLog.query({})).entries;
    expect(rows.filter(e => e.operation === "memory_insert_intent")).toHaveLength(1);
    expect(rows.filter(e => e.operation === "memory_insert")).toEqual([]);
  } finally { spy.mockRestore(); }
});
