/** A session with no identity says so, and its bound-only cooperative tools refuse before the gate. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createSanctuaryServer } from "../../src/index.js";
import { DenialLedger } from "../../src/agent-native/denial-ledger.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest, ApprovalResponse } from "../../src/principal-policy/types.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import { expectedRefusal } from "../helpers/expected-refusal.js";

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
const ANSWERING_TOOLS = ["sanctuary_help", "sanctuary_capabilities"];

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

async function boot(decision: "deny" | "approve" = "deny") {
  const captured: ApprovalRequest[] = [];
  const deny = vi.fn(async (request: ApprovalRequest): Promise<ApprovalResponse> => {
    captured.push(request);
    return { decision, decided_at: new Date().toISOString(), decided_by: "human" };
  });
  const storage = new MemoryStorage();
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

it("in a non-bound session the bound-only cooperative tools refuse before the gate with no approval request", async () => {
  const b = await boot();
  await b.create();
  const ledger = vi.spyOn(DenialLedger.prototype, "record");
  for (const tool of ANSWERING_TOOLS) {
    const result = await b.call(tool, tool === "sanctuary_help" ? { intent: "save my timezone" } : {});
    expect(result.isError, tool).not.toBe(true);
    expect(body(result).audit_ref, tool).toEqual(expect.any(String));
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
