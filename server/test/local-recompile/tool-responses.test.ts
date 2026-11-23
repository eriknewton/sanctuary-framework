// The router-level response cases fail on base by assertion: the tool is absent there.
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { FORTRESS_STATE_DIRECTORY } from "../../src/core/custody-markers.js";
import { isCompoundExecutableToolName } from "../../src/agent-native/tool-names.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import * as responses from "../../src/local-recompile/responses.js";
import { bootLocalTaskServer, VALID_ARGS, type LocalTaskServer } from "./helpers/local-task-server.js";

// Test-local copies; must match src/local-recompile/responses.ts (the parity case below checks them).
const TOOL = "sanctuary_local_task";
const FIXED_ID = "0123456789abcdef0123456789abcdef";
const A1 = `{"status":"submitted","request_id":"${FIXED_ID}","note":"Submitted. Any result appears only in the user's Sanctuary dashboard."}`;
const A2 = '{"status":"invalid_input"}';
const A3 = '{"status":"unavailable"}';
const A5 = '{"status":"busy"}';
const DESCRIPTION =
  "Hands a summary task over records stored in Sanctuary to the local model on this machine. " +
  "The summary is shown only to the user, in the Sanctuary dashboard, and is never returned to you. " +
  "Every accepted request gets the same acknowledgement, whether or not it later succeeds. " +
  "No hosted model is called. Tell the user the summary will appear in their dashboard.";
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

let server: LocalTaskServer;
let now = Date.UTC(2026, 10, 22);
let throwAt: string | undefined;

beforeAll(async () => {
  server = await bootLocalTaskServer({
    seams: {
      idSource: () => FIXED_ID,
      clock: () => now,
      callHook: (state) => {
        if (state === throwAt) throw new Error("injected stage fault");
      },
    },
  });
}, 120_000);
afterAll(async () => {
  await server?.close();
});

function args(overrides: Record<string, unknown> = {}) {
  return { ...VALID_ARGS, ...overrides };
}
function refs(list: unknown) {
  return args({ sources: { refs: list } });
}

/** A fresh rate window for the seat, so each case is independent. */
function nextWindow() {
  now += 2 * HOUR;
}

async function auditEntries(): Promise<Array<{ key: string; size: number }>> {
  await server.runtime.auditLog.flush();
  const storage = new FilesystemStorage(join(server.storagePath, FORTRESS_STATE_DIRECTORY));
  return (await storage.list("_audit")).map((entry) => ({ key: entry.key, size: entry.size_bytes }));
}

async function newOperations(before: Set<string>): Promise<string[]> {
  await server.runtime.auditLog.flush();
  const { entries } = await server.runtime.auditLog.query({ limit: 500 });
  return entries.filter((entry) => !before.has(`${entry.timestamp}|${entry.operation}|${JSON.stringify(entry.details)}`))
    .map((entry) => entry.operation);
}
async function snapshot(): Promise<Set<string>> {
  await server.runtime.auditLog.flush();
  const { entries } = await server.runtime.auditLog.query({ limit: 500 });
  return new Set(entries.map((entry) => `${entry.timestamp}|${entry.operation}|${JSON.stringify(entry.details)}`));
}

describe("local task responses", () => {
  it("the test-local literals match the source", () => {
    expect(responses.LOCAL_TASK_TOOL_NAME).toBe(TOOL);
    expect(responses.LOCAL_TASK_DESCRIPTION).toBe(DESCRIPTION);
    expect(responses.submittedResponse(FIXED_ID).content[0]!.text).toBe(A1);
    expect(responses.INVALID_INPUT_TEXT).toBe(A2);
    expect(responses.UNAVAILABLE_TEXT).toBe(A3);
    expect(responses.BUSY_TEXT).toBe(A5);
  });

  it("the tool is listed with its description", async () => {
    const listed = await server.client.listTools();
    const tool = listed.tools.find((entry) => entry.name === TOOL);
    expect(tool?.description).toBe(DESCRIPTION);
  });

  it("a valid call is acknowledged with the fixed bytes", async () => {
    nextWindow();
    const result = await server.call(args());
    expect(result).toEqual({ text: A1, isError: false, items: 1 });
  });

  const long = "x".repeat(501);
  it.each([
    ["sources with a key other than refs", args({ sources: { refs: [{ namespace: "notes", key: "one" }], extra: 1 } })],
    ["refs not an array", refs({ namespace: "notes", key: "one" })],
    ["no refs", refs([])],
    ["33 refs", refs(Array.from({ length: 33 }, (_, i) => ({ namespace: "notes", key: `k${i}` })))],
    ["a ref with an extra field", refs([{ namespace: "notes", key: "one", extra: "x" }])],
    ["a ref missing its key", refs([{ namespace: "notes" }])],
    ["a ref with an empty namespace", refs([{ namespace: "", key: "one" }])],
    ["a ref with a non-string key", refs([{ namespace: "notes", key: 7 }])],
    ["a ref that is not an object", refs(["notes/one"])],
    ["a reserved namespace", refs([{ namespace: "_identities", key: "one" }])],
    ["a local store namespace", refs([{ namespace: "_local_results", key: "one" }])],
    ["a namespace that is not a storage name", refs([{ namespace: "..", key: "one" }])],
    ["a key that is not a storage name", refs([{ namespace: "notes", key: "." }])],
    ["an instruction over 500 characters", args({ instruction: long })],
    ["an instruction with a control character", args({ instruction: "focus\u0007here" })],
    ["an instruction with a C1 control character", args({ instruction: "focus\u0085here" })],
    ["a prototype key in sources", args({ sources: JSON.parse('{"refs":[{"namespace":"notes","key":"one"}],"__proto__":{"x":1}}') })],
    ["a prototype key in a ref", refs([JSON.parse('{"namespace":"notes","key":"one","__proto__":{"y":1}}')])],
  ])("an invalid input is refused at the handler: %s", async (_label, input) => {
    nextWindow();
    expect(await server.call(input)).toEqual({ text: A2, isError: false, items: 1 });
  });

  it("an instruction of exactly 500 characters with newlines and tabs is accepted", async () => {
    nextWindow();
    const instruction = `${"y".repeat(498)}\n\t`;
    expect((await server.call(args({ instruction }))).text).toBe(A1);
  });

  it.each([
    ["an unknown top-level key", args({ extra: true })],
    ["a compartment key", args({ compartment: "work" })],
    ["a kind outside the enum", args({ kind: "split" })],
    ["an instruction that is not a string", args({ instruction: 5 })],
  ])("the router's schema check refuses %s with its own result", async (_label, input) => {
    nextWindow();
    const result = await server.call(input);
    expect(result.text).not.toBe(A1);
    expect([A2, A3, A5]).not.toContain(result.text);
    expect(result.text).toContain("validation_failed");
  });

  it("the fifth call in a minute is busy", async () => {
    nextWindow();
    const texts: string[] = [];
    for (let i = 0; i < 5; i += 1) texts.push((await server.call(args())).text);
    expect(texts).toEqual([A1, A1, A1, A1, A5]);
  });

  it("the twenty-first call in an hour is busy", async () => {
    nextWindow();
    const texts: string[] = [];
    for (let i = 0; i < 21; i += 1) {
      now += 2 * MINUTE;
      texts.push((await server.call(args())).text);
    }
    expect(texts.slice(0, 20).every((text) => text === A1)).toBe(true);
    expect(texts[20]).toBe(A5);
  });

  it("every response is one text item and never an error result", async () => {
    nextWindow();
    const results = [
      await server.call(args()),
      await server.call(refs([])),
      ...(await Promise.all([1, 2, 3, 4].map(() => server.call(args())))),
    ];
    for (const result of results) {
      expect(result.items).toBe(1);
      expect(result.isError).toBe(false);
      expect(() => JSON.parse(result.text)).not.toThrow();
    }
  });

  it("a submitting call adds the gate row and one fixed submission row; busy and invalid calls add only the gate row", async () => {
    nextWindow();
    const sizes: number[][] = [];
    const counts: number[] = [];
    const operations: string[][] = [];
    const calls = [args(), args({ instruction: "a much longer instruction text than the first one" }), refs([]), args(), args(), args()];
    const expected = [A1, A1, A2, A1, A1, A5];
    for (const [index, input] of calls.entries()) {
      const beforeKeys = new Set((await auditEntries()).map((entry) => entry.key));
      const beforeOps = await snapshot();
      expect((await server.call(input)).text).toBe(expected[index]);
      const added = (await auditEntries()).filter((entry) => !beforeKeys.has(entry.key));
      counts.push(added.length);
      sizes.push(added.map((entry) => entry.size));
      operations.push(await newOperations(beforeOps));
    }
    expect(counts).toEqual([2, 2, 1, 2, 2, 1]);
    for (const index of [0, 1, 3, 4]) expect(operations[index]).toContain("local_request_submitted");
    for (const index of [2, 5]) expect(operations[index]).not.toContain("local_request_submitted");
    // The submission row's stored size does not depend on the request.
    expect(sizes[1]).toEqual(sizes[0]);
  });

  it("the submission row is durable before the acknowledgement", async () => {
    nextWindow();
    const auditLog = server.runtime.auditLog;
    const original = auditLog.appendCritical.bind(auditLog);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let settled = false;
    const spy = vi.spyOn(auditLog, "appendCritical").mockImplementation(async (entry) => {
      if (entry.operation === "local_request_submitted") await gate;
      return original(entry);
    });
    try {
      const pending = server.call(args()).then((result) => { settled = true; return result; });
      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(settled).toBe(false);
      release();
      expect((await pending).text).toBe(A1);
    } finally {
      spy.mockRestore();
    }
  });

  it("a submission row that cannot be made durable gives the unavailable response", async () => {
    nextWindow();
    const auditLog = server.runtime.auditLog;
    const original = auditLog.appendCritical.bind(auditLog);
    const spy = vi.spyOn(auditLog, "appendCritical").mockImplementation(async (entry) => {
      if (entry.operation === "local_request_submitted") throw new Error("durability refused");
      return original(entry);
    });
    try {
      expect((await server.call(args())).text).toBe(A3);
    } finally {
      spy.mockRestore();
    }
  });

  it.each([
    ["state_PARSE", A3],
    ["state_ARMED", A3],
    ["state_RATE", A3],
    ["state_ROW", A3],
    ["state_ENQUEUE", A1],
    ["state_ACK", A1],
  ])("a throw injected at %s never writes a tool_error row", async (state, expected) => {
    nextWindow();
    const before = await snapshot();
    throwAt = state;
    try {
      const result = await server.call(args());
      expect(result).toEqual({ text: expected, isError: false, items: 1 });
    } finally {
      throwAt = undefined;
    }
    expect(await newOperations(before)).not.toContain("tool_error");
  });

  it("compound execute refuses the local task before the gate", () => {
    expect(isCompoundExecutableToolName(TOOL)).toBe(false);
  });
});
