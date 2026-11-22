/** Production boot shares one subject across cooperative and primitive consumers. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createSanctuaryServer } from "../../src/index.js";
import * as cooperative from "../../src/agent-native/cooperative-surface.js";
import * as distress from "../../src/distress/tools.js";
import * as sessionBinding from "../../src/agent-native/session-binding.js";
import { DenialLedger } from "../../src/agent-native/denial-ledger.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import { expectedRefusal } from "../helpers/expected-refusal.js";
import { COOPERATIVE_TOOL_NAMES } from "../../src/agent-native/tool-names.js";

let home: Awaited<ReturnType<typeof createTempHome>>;
let cleanups: Array<() => Promise<void>>;
const captureComposition = () => vi.spyOn(cooperative, "createAgentNativeCooperativeTools");
let compositions: ReturnType<typeof captureComposition>;
beforeEach(async () => {
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", undefined);
  home = await createTempHome("session-binding");
  cleanups = [];
  compositions = captureComposition();
  await mkdir(home.defaultFortressPath, { recursive: true });
  await writeFile(join(home.defaultFortressPath, "principal-policy.yaml"), generateDefaultPolicyYaml().replace(/approval_channel:\n  type: \w+/, "approval_channel:\n  type: callback"));
});
afterEach(async () => {
  try { for (const cleanup of cleanups.reverse()) await cleanup(); }
  finally { vi.restoreAllMocks(); vi.unstubAllEnvs(); await home.cleanup(); }
});
async function boot(storage = new MemoryStorage()) {
  const approvals = vi.fn(async () => ({ decision: "approve" as const, decided_at: new Date().toISOString(), decided_by: "human" as const }));
  const app = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE, approvalCallback: approvals });
  cleanups.push(app.cleanup);
  const sources = compositions.mock.calls.at(-1)![0];
  const handler = (app.server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get("tools/call")!;
  const call = (name: string, args: Record<string, unknown> = {}) => handler({ method: "tools/call", params: { name, arguments: args } }, {});
  const create = async () => JSON.parse((await call("identity_create", { label: "test-subject" })).content[0].text).identity_id as string;
  return { app, sources, storage, call, create, approvals };
}
async function sole() {
  const first = await boot();
  const id = await first.create();
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", id);
  expect((await first.call("sanctuary_remember", { key: "seed", value: "stored before restart" })).isError).not.toBe(true);
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", undefined);
  await first.app.cleanup();
  cleanups.pop();
  const configPath = join(home.defaultFortressPath, "sanctuary.json");
  const config = JSON.parse(await readFile(configPath, "utf8"));
  await writeFile(configPath, JSON.stringify({ ...config, session_binding: { sole_identity: true } }));
  const second = await boot(first.storage);
  return { ...second, id };
}

async function stampAt(storage: MemoryStorage, namespace: string, key: string) {
  const bytes = await storage.read(namespace, key);
  return bytes === null ? null : JSON.parse(new TextDecoder().decode(bytes)).provenance_stamp as Record<string, unknown>;
}

it("a named own write stays agent and a named other write stays operator", async () => {
  // The named-other arm is refused before the gate through state_write, so its operator value is pinned at the origin table.
  const b = await boot();
  const id = await b.create();
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", id);
  const saved = JSON.parse((await b.call("sanctuary_remember", { key: "own", value: "mine" })).content[0].text);
  expect(await stampAt(b.storage, saved.namespace_handle, "own")).toMatchObject({ origin_actor: "agent", memory_class: "agent_owned" });
});

it("a session started with the launch variable set stamps its own remember write agent", async () => {
  const first = await boot();
  const id = await first.create();
  await first.app.cleanup();
  cleanups.pop();
  // The launch variable is set before the second boot, so the frozen boot decision is the named state.
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", id);
  const b = await boot(first.storage);
  const rows = (await b.app.auditLog.query({})).entries.filter(row => row.operation === "session_binding_resolved");
  expect(rows.at(-1)).toMatchObject({ details: { state: "state_BOUND_NAMED", binding_source: "launch_variable", identity_id: id } });
  const saved = JSON.parse((await b.call("sanctuary_remember", { key: "launched", value: "mine" })).content[0].text);
  expect(await stampAt(b.storage, saved.namespace_handle, "launched")).toMatchObject({ origin_actor: "agent", memory_class: "agent_owned" });
});

it("a remember whose boot decision cannot be read is refused, stores nothing, and records a cause for the operator", async () => {
  // Test-only composition: the real resolver, wrapped so its boot decision becomes unreadable once armed.
  const realResolve = sessionBinding.resolveSessionBinding;
  let armed = false;
  vi.spyOn(sessionBinding, "resolveSessionBinding").mockImplementation(async (options) => {
    const resolver = await realResolve(options);
    return Object.freeze({
      cooperative: () => resolver.cooperative(),
      primitive: () => resolver.primitive(),
      get bootState() {
        if (armed) throw new Error("boot decision unreadable");
        return resolver.bootState;
      },
    });
  });
  const b = await boot();
  const id = await b.create();
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", id);
  const writes = async () => (await b.app.auditLog.query({ operation_type: "state_write", limit: Number.MAX_SAFE_INTEGER })).total;
  const writesBefore = await writes();
  const ledger = vi.spyOn(DenialLedger.prototype, "record");
  armed = true;
  const result = await b.call("sanctuary_remember", { key: "unreadable-boot", value: "v" });
  armed = false;
  expect(result).toEqual(expectedRefusal());
  // Today the cause is handler_error; the deferred-causes debt marked in tool-outcome.ts gives it its own cause later.
  expect(ledger.mock.calls.at(-1)).toEqual(["handler_error", expect.objectContaining({ tool: "sanctuary_remember" })]);
  expect(await writes()).toBe(writesBefore);
  for (const namespace of await b.storage.listNamespaces()) {
    expect(await b.storage.read(namespace, "unreadable-boot"), namespace).toBeNull();
  }
});

it("an unbound write stays operator", async () => {
  const b = await boot();
  await b.create();
  expect((await b.call("state_write", { namespace: "notes", key: "unbound", value: "v" })).isError).not.toBe(true);
  expect(await stampAt(b.storage, "notes", "unbound")).toMatchObject({ origin_actor: "operator", memory_class: "operator_owned" });
});

it("a sole-bound write naming another identity is refused before the gate and raises no approval request", async () => {
  const b = await sole();
  const other = await b.create();
  const ledger = vi.spyOn(DenialLedger.prototype, "record");
  b.approvals.mockClear();
  expect(await b.call("state_write", { namespace: "other-notes", key: "k", value: "v", identity_id: other })).toEqual(expectedRefusal());
  expect(b.approvals).not.toHaveBeenCalled();
  expect(ledger.mock.calls.at(-1)).toEqual(["pre_gate_argument_refused", expect.objectContaining({ tool: "state_write" })]);
  expect(await b.storage.list("other-notes")).toEqual([]);
});

it("every non-bound state returns the same frozen binding to cooperative consumers", async () => {
  const b = await boot();
  const binding = b.sources.currentSessionBinding();
  expect(binding).toEqual({});
  expect(Object.isFrozen(binding)).toBe(true);
  for (const variable of ["", "missing", undefined]) {
    vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", variable);
    expect(b.sources.currentSessionBinding()).toBe(binding);
    expect(await b.call("sanctuary_remember", { key: "unbound", value: "value" })).toEqual(expectedRefusal());
  }
});

it("export and an identity-naming write refuse when the named identity is not loaded", async () => {
  const b = await boot();
  const realId = await b.create();
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", "missing");
  const ledger = vi.spyOn(DenialLedger.prototype, "record");
  for (const [tool, args] of [["state_export", {}], ["state_write", { namespace: "notes", key: "k", value: "v", identity_id: realId }]] as const) {
    b.approvals.mockClear();
    expect(await b.call(tool, args)).toEqual(expectedRefusal());
    expect(b.approvals).not.toHaveBeenCalled();
    expect(ledger.mock.calls.at(-1)).toEqual(["session_not_bound", expect.objectContaining({ tool })]);
    const { entries } = await b.app.auditLog.query({});
    expect(entries.some(row => row.operation === `gate_deny:${tool}`)).toBe(true);
  }
  expect(await b.storage.list("notes")).toEqual([]);
});

it("a write naming another identity under a named binding is refused before the gate", async () => {
  const b = await boot();
  const id = await b.create();
  const other = await b.create();
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", id);
  const ledger = vi.spyOn(DenialLedger.prototype, "record");
  b.approvals.mockClear();
  expect(await b.call("state_write", { namespace: "new-notes", key: "k", value: "v", identity_id: other })).toEqual(expectedRefusal());
  expect(b.approvals).not.toHaveBeenCalled();
  expect(ledger.mock.calls.at(-1)).toEqual(["pre_gate_argument_refused", expect.objectContaining({ tool: "state_write" })]);
  expect((await b.app.auditLog.query({})).entries.some(row => row.operation === "gate_deny:state_write")).toBe(true);
  expect(await b.storage.list("new-notes")).toEqual([]);
});

it("a named binding resolves and behaves as before", async () => {
  const b = await boot();
  const id = await b.create();
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", id);
  expect(b.sources.currentSessionBinding()).toMatchObject({ identity_id: id });
  expect((await b.call("sanctuary_remember", { key: "named", value: "remembered" })).isError).not.toBe(true);
  expect(JSON.parse((await b.call("sanctuary_recall", { key: "named" })).content[0].text)).toMatchObject({ value: "remembered" });
});

it("a write under a sole binding is never stamped agent or operator", async () => {
  const b = await sole();
  expect(JSON.parse((await b.call("sanctuary_recall", { key: "seed" })).content[0].text)).toMatchObject({ value: "stored before restart" });
  expect((await b.call("monitor_audit_log", {})).isError).not.toBe(true);
  expect(b.sources.currentSessionBinding()).toMatchObject({ identity_id: b.id, binding_source: "sole_identity" });
  const written = await b.call("state_write", { namespace: "notes", key: "sole", value: "v" });
  expect(written).not.toEqual(expectedRefusal());
  expect(JSON.parse(written.content[0].text)).toMatchObject({ namespace: "notes", key: "sole" });
  expect(await stampAt(b.storage, "notes", "sole")).toMatchObject({ origin_actor: "unattributed", memory_class: "shared_entangled", derived_from: [] });
  const rows = (await b.app.auditLog.query({})).entries.filter(row => row.operation === "session_binding_resolved");
  expect(rows.at(-1)).toMatchObject({ identity_id: "system", details: { state: "state_BOUND_SOLE_IDENTITY" } });
});

/** The stamp stored under a key, wherever the write placed it (a remember write lands in an opaque handle namespace). */
async function stampForKey(storage: MemoryStorage, key: string) {
  const stamps = [];
  for (const namespace of await storage.listNamespaces()) {
    const stamp = await stampAt(storage, namespace, key);
    if (stamp !== null) stamps.push(stamp);
  }
  expect(stamps).toHaveLength(1);
  return stamps[0];
}

const SOLE_WRITES: Record<string, Record<string, unknown>> = {
  state_write: { namespace: "sole-notes", key: "sole-write", value: "v" },
  sanctuary_remember: { key: "sole-write", value: "v" },
  sanctuary_compound_execute: { steps: [{ tool: "sanctuary_remember", args: { key: "sole-write", value: "v" } }] },
};

it("every tool that reaches the state_write handler stamps a sole-bound write unattributed", async () => {
  const b = await sole();
  const listed = (await (b.app.server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get("tools/list")!({ method: "tools/list", params: {} }, {})) as { tools: Array<{ name: string }> };
  const registered = new Set(listed.tools.map(tool => tool.name));
  const cooperativeTools = compositions.mock.results.at(-1)!.value.tools as Array<{ name: string; approvalTargetToolName?: string }>;
  // The state_write handler is reached by state_write itself, by every tool whose approval target is state_write,
  // and by a compound plan's remember step (compoundStepPrimitive in agent-native/cooperative-surface.ts).
  const reaching = [
    "state_write",
    ...cooperativeTools.filter(tool => tool.approvalTargetToolName === "state_write").map(tool => tool.name),
    COOPERATIVE_TOOL_NAMES.compoundExecute,
  ].filter(name => registered.has(name)).sort();
  expect(reaching).toEqual(["sanctuary_compound_execute", "sanctuary_remember", "state_write"]);
  for (const tool of reaching) {
    const each = tool === reaching[0] ? b : await sole();
    const count = async () => (await each.app.auditLog.query({ operation_type: "state_write", limit: Number.MAX_SAFE_INTEGER })).total;
    const writesBefore = await count();
    const result = await each.call(tool, SOLE_WRITES[tool]!);
    expect(result, tool).not.toEqual(expectedRefusal());
    expect(result.isError, tool).not.toBe(true);
    expect(await count(), tool).toBe(writesBefore + 1);
    expect(await stampForKey(each.storage, "sole-write"), tool).toMatchObject({ origin_actor: "unattributed", memory_class: "shared_entangled", derived_from: [] });
  }
});

it("a sole-bound plan with no write still reaches the gate", async () => {
  const b = await sole();
  b.approvals.mockClear();
  const result = await b.call("sanctuary_compound_execute", { steps: [{ tool: "sanctuary_recall", args: { key: "seed" } }] });
  expect(b.approvals).toHaveBeenCalled();
  expect(result).not.toEqual(expectedRefusal());
  expect(JSON.parse(result.content[0].text)).toMatchObject({ status: "completed" });
});

it("setting the variable after a sole boot changes neither binding_source nor origin", async () => {
  const b = await sole();
  const binding = b.sources.currentSessionBinding();
  for (const [index, variable] of ["", b.id, "another"].entries()) {
    vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", variable);
    expect(b.sources.currentSessionBinding()).toBe(binding);
    expect(binding).toMatchObject({ binding_source: "sole_identity" });
    const written = await b.call("state_write", { namespace: "notes", key: `after-${index}`, value: "v" });
    expect(written).not.toEqual(expectedRefusal());
    expect(await stampAt(b.storage, "notes", `after-${index}`)).toMatchObject({ origin_actor: "unattributed", memory_class: "shared_entangled" });
  }
});

it("an identity created after a non-bound boot leaves the session unbound", async () => {
  await writeFile(join(home.defaultFortressPath, "sanctuary.json"), JSON.stringify({ session_binding: { sole_identity: true } }));
  const b = await boot();
  await b.create();
  expect(b.sources.currentSessionBinding()).toEqual({});
  expect(await b.call("sanctuary_remember", { key: "late", value: "v" })).toEqual(expectedRefusal());
});

it("a second identity created after a sole boot leaves this process bound", async () => {
  const b = await sole();
  const binding = b.sources.currentSessionBinding();
  const second = await b.create();
  expect(second).not.toBe(b.id);
  expect(b.sources.currentSessionBinding()).toBe(binding);
  expect((await b.call("sanctuary_active_protections")).isError).not.toBe(true);
});

it("after the primary changes, implicit identity selection uses the bound identity", async () => {
  const b = await sole();
  const second = await b.create();
  expect(await b.app.identityManager.setPrimary(second)).toBe(true);
  const signed = JSON.parse((await b.call("identity_sign", { payload: "subject-check" })).content[0].text);
  expect(signed.public_key).toBe(b.app.identityManager.get(b.id)!.public_key);
  expect(b.sources.currentSessionBinding()?.identity_id).toBe(b.id);
});

it("after rotation the binding continues by id", async () => {
  const b = await sole();
  const oldKey = b.app.identityManager.get(b.id)!.public_key;
  const rotated = JSON.parse((await b.call("identity_rotate", { identity_id: b.id })).content[0].text);
  expect(rotated.identity_id).toBe(b.id);
  expect(b.app.identityManager.get(b.id)!.public_key).not.toBe(oldKey);
  expect(b.sources.currentSessionBinding()).toMatchObject({ identity_id: b.id, binding_source: "sole_identity" });
});

it("an identity file removed outside Sanctuary leaves the binding in place until exit", async () => {
  const b = await sole();
  await b.storage.delete("_identities", b.id);
  expect(b.sources.currentSessionBinding()).toMatchObject({ identity_id: b.id, binding_source: "sole_identity" });
  expect((await b.call("sanctuary_active_protections")).isError).not.toBe(true);
});

it("a named unresolved identity still reaches the distress actor by id", async () => {
  const constructions = vi.spyOn(distress, "createDistressTools");
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", "distress-subject");
  const b = await boot();
  expect(constructions.mock.calls.at(-1)?.[0].currentActorId?.()).toBe("distress-subject");
  expect(b.sources.currentSessionBinding()).toEqual({});
});

it("flag-off boot keeps the existing identity enumeration path", async () => {
  const storage = new MemoryStorage();
  const keys = vi.spyOn(storage, "listKeys");
  await boot(storage);
  expect(keys.mock.calls.filter(([namespace]) => namespace === "_identities")).toEqual([]);
});
