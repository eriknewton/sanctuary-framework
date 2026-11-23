/** A session with no identity says so, and its bound-only cooperative tools refuse before the gate. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createSanctuaryServer } from "../../src/index.js";
import { DenialLedger } from "../../src/agent-native/denial-ledger.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest, ApprovalResponse } from "../../src/principal-policy/types.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import { expectedRefusal, expectedRefusalBody } from "../helpers/expected-refusal.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";
import { COOPERATIVE_TOOL_NAMES } from "../../src/agent-native/tool-names.js";

// The two operator sentences, written out byte for byte and never imported.
const UNBOUND_SENTENCE = "This session has no Sanctuary identity. Tell your operator; they can enable default binding with sanctuary session-binding enable or name an identity with SANCTUARY_SESSION_IDENTITY_ID, then restart this server.";
const UNCONFIRMED_SENTENCE = "This session's identity could not be confirmed. Tell your operator and restart this server.";

// Owner-only policy and fortress permissions match the production writer.
const POLICY_FILE_MODE = 0o600;
const FORTRESS_DIR_MODE = 0o700;

const BOUND_ONLY_TOOLS: Array<[string, Record<string, unknown>]> = [
  ["sanctuary_remember", { key: "k", value: "v" }],
  ["sanctuary_recall", { key: "k" }],
  ["sanctuary_hide", { key: "k" }],
  ["sanctuary_forget", { key: "k", mode: "secure", approval_ref: "approval:none" }],
  ["sanctuary_events_open_cursor", {}],
  ["sanctuary_events_read", { cursor: "cursor:none" }],
  ["sanctuary_events_close", { cursor: "cursor:none" }],
  ["sanctuary_audit_search", { query: "remember" }],
  ["sanctuary_compound_execute", { steps: [{ tool: "sanctuary_recall", args: { key: "k" } }] }],
];
const ANSWERING_TOOLS: Array<[string, Record<string, unknown>]> = [
  ["sanctuary_help", { intent: "save my timezone" }],
  ["sanctuary_capabilities", {}],
  ["sanctuary_who_am_i", {}],
  ["sanctuary_active_protections", {}],
];
const ANSWERING_CATALOG = new Set(["sanctuary_help", "sanctuary_who_am_i", "sanctuary_active_protections"]);

let home: Awaited<ReturnType<typeof createTempHome>>;
let cleanups: Array<() => Promise<void>>;

beforeEach(async () => {
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", undefined);
  cleanups = [];
  home = await createTempHome("unbound-session-surface");
  await mkdir(home.defaultFortressPath, { recursive: true, mode: FORTRESS_DIR_MODE });
  const yaml = generateDefaultPolicyYaml().replace(/approval_channel:\n  type: \w+/, "approval_channel:\n  type: callback");
  await writeFile(join(home.defaultFortressPath, "principal-policy.yaml"), yaml, { mode: POLICY_FILE_MODE });
});
afterEach(async () => {
  try { for (const cleanup of cleanups.reverse()) await cleanup(); }
  finally { vi.restoreAllMocks(); vi.unstubAllEnvs(); await home.cleanup(); }
});

async function boot(decision: "deny" | "approve" = "deny", storage = new MemoryStorage()) {
  const captured: ApprovalRequest[] = [];
  const deny = vi.fn(async (request: ApprovalRequest): Promise<ApprovalResponse> => {
    captured.push(request);
    return { decision, decided_at: new Date().toISOString(), decided_by: "human" };
  });
  const app = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE, approvalCallback: deny });
  cleanups.push(() => app.cleanup());
  const handler = (app.server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get("tools/call")!;
  const call = (name: string, args: Record<string, unknown> = {}) => handler({ method: "tools/call", params: { name, arguments: args } }, {});
  const create = async () => JSON.parse((await call("identity_create", { label: "unbound-subject" })).content[0].text).identity_id as string;
  const gateRows = async () => (await app.auditLog.query({ limit: Number.MAX_SAFE_INTEGER })).entries
    .filter((row) => row.operation.startsWith("gate_"));
  return { app, storage, call, create, captured, deny, gateRows };
}

function body(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function status(layers: unknown, id: string): string | undefined {
  return (layers as Array<{ id: string; status: string }> | undefined)?.find((row) => row.id === id)?.status;
}

it("in a non-bound session exactly four cooperative tools answer and every other one refuses before the gate with no approval request", async () => {
  // The two sets together are every cooperative tool, with no overlap.
  expect(new Set([...ANSWERING_TOOLS, ...BOUND_ONLY_TOOLS].map(([tool]) => tool)))
    .toEqual(new Set(Object.values(COOPERATIVE_TOOL_NAMES)));
  expect(ANSWERING_TOOLS.length + BOUND_ONLY_TOOLS.length).toBe(Object.values(COOPERATIVE_TOOL_NAMES).length);
  const b = await boot();
  await b.create();
  const ledger = vi.spyOn(DenialLedger.prototype, "record");
  for (const [tool, args] of ANSWERING_TOOLS) {
    const before = (await b.gateRows()).length;
    ledger.mockClear();
    const result = await b.call(tool, args);
    expect(result.isError, tool).not.toBe(true);
    const answer = body(result);
    expect(answer.audit_ref, tool).toEqual(expect.any(String));
    for (const key of ["denied", "error", "status"]) expect(Object.hasOwn(answer, key), `${tool}: ${key}`).toBe(false);
    // An ordinary Tier 3 call: one gate_allow row and nothing for the ledger.
    expect((await b.gateRows()).slice(before).map((row) => row.operation), tool).toEqual([`gate_allow:${tool}`]);
    expect(ledger.mock.calls, tool).toEqual([]);
  }
  for (const [tool, args] of BOUND_ONLY_TOOLS) {
    const before = (await b.gateRows()).length;
    ledger.mockClear();
    expect(await b.call(tool, args), tool).toEqual(expectedRefusal());
    const rows = (await b.gateRows()).slice(before);
    expect(rows.map((row) => row.operation), tool).toEqual([expect.stringMatching(/^gate_deny:/)]);
    expect(rows[0]!.details, tool).toMatchObject({ decided_by: "pre_gate" });
    expect(ledger.mock.calls, tool).toEqual([["session_not_bound", expect.objectContaining({ tool })]]);
  }
  expect(b.deny).not.toHaveBeenCalled();
  expect(b.captured).toEqual([]);
});

it("a primitive call in a non-bound session behaves as on main", async () => {
  // Main's primitive path may ask the operator about a new namespace; an approving operator lets the write land as before.
  const b = await boot("approve");
  await b.create();
  const written = await b.call("state_write", { namespace: "unbound-notes", key: "k", value: "unbound value" });
  expect(written.isError).not.toBe(true);
  const raw = await b.storage.read("unbound-notes", "k");
  expect(raw).not.toBeNull();
  expect(JSON.parse(new TextDecoder().decode(raw!)).provenance_stamp).toMatchObject({ origin_actor: "operator" });
  const read = await b.call("state_read", { namespace: "unbound-notes", key: "k" });
  expect(read.isError).not.toBe(true);
  expect(body(read).value).toBe("unbound value");
});

it("the argument builders return the handler arguments unchanged", async () => {
  const b = await boot();
  const id = await b.create();
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", id);
  const evaluate = vi.spyOn(ApprovalGate.prototype, "evaluate");
  const builderTools = BOUND_ONLY_TOOLS.filter(([tool]) => [
    "sanctuary_events_open_cursor", "sanctuary_events_read", "sanctuary_events_close",
    "sanctuary_audit_search", "sanctuary_compound_execute",
  ].includes(tool));
  expect(builderTools).toHaveLength(5);
  for (const [tool, args] of builderTools) {
    evaluate.mockClear();
    await b.call(tool, args);
    expect(evaluate.mock.calls.length, tool).toBeGreaterThan(0);
    const [operation, gateArgs] = evaluate.mock.calls[0]!;
    expect(operation, tool).toBe(tool);
    expect(gateArgs, tool).toEqual(args);
  }
});

it("who-am-I in a session with no identity answers bound false with the operator sentence and no identity fact", async () => {
  const b = await boot();
  await b.create();
  const answer = body(await b.call("sanctuary_who_am_i"));
  expect(Object.keys(answer).sort()).toEqual(["audit_ref", "bound", "operator_action"]);
  expect(answer.bound).toBe(false);
  expect(answer.operator_action).toBe(UNBOUND_SENTENCE);
  const rows = (await b.app.auditLog.query({ operation_type: "sanctuary_who_am_i" })).entries;
  expect(rows.at(-1)).toMatchObject({ identity_id: "system" });
});

it("who-am-I in a sole-bound session reports the default binding", async () => {
  const b = await soleBoot();
  const answer = body(await b.call("sanctuary_who_am_i"));
  expect(answer).toMatchObject({ bound: true, binding_source: "sole_identity", did: expect.any(String) });
});

it("active protections answers in a session with no identity and reports the identity layer unknown", async () => {
  const b = await boot();
  await b.create();
  const answer = body(await b.call("sanctuary_active_protections"));
  expect(answer.denied).toBeUndefined();
  expect(status(answer.layers, "identity")).toBe("unknown");
});

it("active protections in a sole-bound session does not report the identity layer unknown", async () => {
  const b = await soleBoot();
  const answer = body(await b.call("sanctuary_active_protections"));
  expect(status(answer.layers, "identity")).toBe("on");
});

it("capabilities in a session with no identity reports exactly bound false with the operator sentence and marks only the answering tools available", async () => {
  const b = await boot();
  await b.create();
  const answer = body(await b.call("sanctuary_capabilities"));
  expect(answer.session).toEqual({ bound: false, operator_action: UNBOUND_SENTENCE });
  for (const entry of answer.capabilities as Array<{ tool: string; available: boolean }>) {
    expect(entry.available, entry.tool).toBe(ANSWERING_CATALOG.has(entry.tool));
  }
});

/** The cooperative factory over real primitives, with a session binding the test controls. */
async function direct(binding: () => SessionBinding | undefined) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  let primitiveBinding: SessionBinding | undefined;
  const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
    stateStore, storage, masterKey, "recovery-key", auditLog,
    { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => primitiveBinding },
  );
  await identityManager.load();
  const created = await l1Tools.find((tool) => tool.name === "identity_create")!.handler({ label: "direct-subject" });
  const id = JSON.parse(created.content[0]!.text).identity_id as string;
  primitiveBinding = { identity_id: id, requester_identity_fingerprint: fingerprintIdentityId(id) };
  const { tools } = createAgentNativeCooperativeTools({
    identityManager, namespaceRegistry, auditLog, currentSessionBinding: binding, primitiveTools: l1Tools, storage, stateStore,
  });
  const call = async (name: string) => body(await tools.find((tool) => tool.name === name)!.handler({}));
  return { id, call, identityManager };
}

it("who-am-I, capabilities and active protections give the fixed denial when the session read fails for a reason other than identity", async () => {
  const f = await direct(() => { throw new Error("session read failed"); });
  for (const tool of ["sanctuary_who_am_i", "sanctuary_capabilities", "sanctuary_active_protections"]) {
    const answer = await f.call(tool);
    expect(answer, tool).toEqual(expectedRefusalBody());
    expect(answer.bound, tool).toBeUndefined();
  }
});

it("who-am-I, capabilities and active protections agree that an expired binding is not a confirmed identity", async () => {
  let binding: SessionBinding | undefined;
  const f = await direct(() => binding);
  binding = { identity_id: f.id, requester_identity_fingerprint: fingerprintIdentityId(f.id),
    expires_at: new Date(Date.now() - 60_000).toISOString() };
  const who = await f.call("sanctuary_who_am_i");
  expect(Object.keys(who).sort()).toEqual(["audit_ref", "bound", "operator_action"]);
  expect(who).toMatchObject({ bound: false, operator_action: UNCONFIRMED_SENTENCE });
  const capabilities = await f.call("sanctuary_capabilities");
  expect(capabilities.session).toEqual({ bound: false, operator_action: UNCONFIRMED_SENTENCE });
  for (const entry of capabilities.capabilities as Array<{ tool: string; available: boolean }>) {
    expect(entry.available, entry.tool).toBe(ANSWERING_CATALOG.has(entry.tool));
  }
  const protections = await f.call("sanctuary_active_protections");
  expect(protections.denied).toBeUndefined();
  expect(status(protections.layers, "identity")).toBe("unknown");
  expect(JSON.stringify(protections)).not.toContain(f.id);
});

async function soleBoot() {
  const first = await boot("approve");
  const id = await first.create();
  await first.app.cleanup();
  cleanups.pop();
  const configPath = join(home.defaultFortressPath, "sanctuary.json");
  const config = JSON.parse(await readFile(configPath, "utf8"));
  await writeFile(configPath, JSON.stringify({ ...config, session_binding: { sole_identity: true } }));
  return { ...(await boot("deny", first.storage)), id };
}

it("a cooperative call refuses when the bound identity is gone from the manager", async () => {
  // A sole binding is frozen at boot, so only the cooperative session read consults the manager on each call.
  const b = await soleBoot();
  const id = b.id;
  // Test-only manager: the bound identity reads as gone once armed; every other lookup is the real one.
  const realGet = IdentityManager.prototype.get;
  let armed = false;
  vi.spyOn(IdentityManager.prototype, "get").mockImplementation(function (this: IdentityManager, lookup: string) {
    return armed && lookup === id ? undefined : realGet.call(this, lookup);
  });
  const ledger = vi.spyOn(DenialLedger.prototype, "record");
  // Remember also reads the manager through its namespace handle; the event cursor reads it only through the session predicate.
  for (const [tool, args] of [["sanctuary_remember", { key: "gone", value: "v" }], ["sanctuary_events_open_cursor", {}]] as const) {
    const before = (await b.gateRows()).length;
    ledger.mockClear();
    armed = true;
    const result = await b.call(tool, args);
    armed = false;
    expect(result, tool).toEqual(expectedRefusal());
    const rows = (await b.gateRows()).slice(before);
    expect(rows.map((row) => row.operation), tool).toEqual([expect.stringMatching(/^gate_deny:/)]);
    expect(rows[0]!.details, tool).toMatchObject({ decided_by: "pre_gate" });
    expect(ledger.mock.calls, tool).toEqual([["pre_gate_argument_refused", expect.objectContaining({ tool })]]);
  }
  expect(b.deny).not.toHaveBeenCalled();
});

it("who-am-I, capabilities and active protections agree when the bound identity is gone from the manager", async () => {
  let binding: SessionBinding | undefined;
  const f = await direct(() => binding);
  binding = { identity_id: f.id, requester_identity_fingerprint: fingerprintIdentityId(f.id), binding_source: "launch_variable" };
  // Test-only manager: the bound identity reads as gone; every other lookup is the real one.
  const realGet = f.identityManager.get.bind(f.identityManager);
  vi.spyOn(f.identityManager, "get").mockImplementation((lookup: string) => (lookup === f.id ? undefined : realGet(lookup)));
  const who = await f.call("sanctuary_who_am_i");
  expect(Object.keys(who).sort()).toEqual(["audit_ref", "bound", "operator_action"]);
  expect(who).toMatchObject({ bound: false, operator_action: UNCONFIRMED_SENTENCE });
  const capabilities = await f.call("sanctuary_capabilities");
  expect(capabilities.session).toEqual({ bound: false, operator_action: UNCONFIRMED_SENTENCE });
  for (const entry of capabilities.capabilities as Array<{ tool: string; available: boolean }>) {
    expect(entry.available, entry.tool).toBe(ANSWERING_CATALOG.has(entry.tool));
  }
  const protections = await f.call("sanctuary_active_protections");
  expect(protections.denied).toBeUndefined();
  expect(status(protections.layers, "identity")).toBe("unknown");
});
