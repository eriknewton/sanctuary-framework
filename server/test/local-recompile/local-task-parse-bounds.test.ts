// The tool's strict check does bounded work on oversized input before any linear pass over it.
import { afterEach, describe, expect, it, vi } from "vitest";
import { createLocalTaskTool, parseLocalTaskArgs } from "../../src/local-recompile/tool.js";

// Several megabytes: far over every bound, so only an O(1) length check should touch it.
const HUGE = 4 * 1024 * 1024;

afterEach(() => {
  vi.restoreAllMocks();
});

function args(overrides: { namespace?: string; key?: string; instruction?: string }) {
  return {
    kind: "summarize",
    sources: { refs: [{ namespace: overrides.namespace ?? "notes", key: overrides.key ?? "one" }] },
    instruction: overrides.instruction ?? "Summarize.",
  };
}

describe("the local task's strict check on oversized input", () => {
  it("a multi-megabyte instruction is refused before its characters are counted", async () => {
    const instruction = "x".repeat(HUGE);
    const from = vi.spyOn(Array, "from");
    expect(parseLocalTaskArgs(args({ instruction }))).toBeNull();
    expect(from.mock.calls.filter((call) => call[0] === instruction)).toEqual([]);
    const tool = createLocalTaskTool({ armed: false, cause: "test_runtime" });
    expect(await tool.handler(args({ instruction }))).toEqual({ content: [{ type: "text", text: '{"status":"invalid_input"}' }] });
  });

  it.each([["namespace"], ["key"]] as Array<["namespace" | "key"]>)("a multi-megabyte %s is refused before it is encoded", async (field) => {
    const name = "n".repeat(HUGE);
    const replace = vi.spyOn(String.prototype, "replace");
    expect(parseLocalTaskArgs(args({ [field]: name }))).toBeNull();
    expect(replace.mock.contexts.filter((context) => String(context).length === HUGE)).toEqual([]);
    const tool = createLocalTaskTool({ armed: false, cause: "test_runtime" });
    expect(await tool.handler(args({ [field]: name }))).toEqual({ content: [{ type: "text", text: '{"status":"invalid_input"}' }] });
  });

  it("names and an instruction at their bounds are still accepted", () => {
    const parsed = parseLocalTaskArgs(args({ key: "k".repeat(255), instruction: "\u{1F600}".repeat(500) }));
    expect(parsed?.instruction).toHaveLength(1_000);
  });
});
