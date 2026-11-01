// The Python plugin pins complete public contracts without changing the TypeScript producers.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import * as P from "../../src/hermes-memory-client/protocol.js";
import { HERMES_MAX_PUBLIC_CONNECTIONS } from "../../src/hermes-memory-bridge/constants.js";
import { RECALL_PREFETCH_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { HERMES_TOOL_OUTCOMES, HERMES_TOOLS_LIST_PAYLOAD } from "../../src/hermes-memory-bridge/public-results.js";

const root = resolve("../hermes-plugin");
const path = join(root, "sanctuary/sanctuary_client.py");
const source = readFileSync(path, "utf8");
const constants = ["TOOL_NAMES", "MAX_STDIO_LINE_BYTES", "SHIM_CALL_DEADLINE_MS", "HERMES_TOOL_TIMEOUT_MS",
  "SHIM_CONNECT_HELLO_TIMEOUT_MS", "SHIM_INITIALIZATION_TIMEOUT_MS", "SHIM_STDIN_EOF_EXIT_MS",
  "RECALL_PREFETCH_BUDGET_MS", "HERMES_MAX_PUBLIC_CONNECTIONS", "MCP_PROTOCOL_VERSION", "CLIENT_NAME",
  "MAX_QUEUED_CALLS", "OUTCOMES", "TOOL_SCHEMAS", "SANCTUARY_INSTALL_ROOT"];
const actual = JSON.parse(execFileSync("python3", ["-I", "-B", "-c",
  "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('parity',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(json.dumps({k:getattr(m,k) for k in json.loads(sys.argv[2])}))",
  path, JSON.stringify(constants)], { encoding: "utf8" }));

describe("Hermes plugin public contract", () => {
  it("pins every catalog name and numeric bound", () => {
    expect(actual.TOOL_NAMES).toHaveLength(P.TOOL_NAMES.length);
    expect(new Set(actual.TOOL_NAMES)).toEqual(new Set(P.TOOL_NAMES));
    for (const name of ["MAX_STDIO_LINE_BYTES", "SHIM_CALL_DEADLINE_MS", "HERMES_TOOL_TIMEOUT_MS",
      "SHIM_CONNECT_HELLO_TIMEOUT_MS", "SHIM_INITIALIZATION_TIMEOUT_MS", "SHIM_STDIN_EOF_EXIT_MS", "CLIENT_NAME"] as const) {
      expect(actual[name], name).toBe(P[name]);
    }
    expect(actual.RECALL_PREFETCH_BUDGET_MS).toBe(RECALL_PREFETCH_BUDGET_MS);
    expect(actual.HERMES_MAX_PUBLIC_CONNECTIONS).toBe(HERMES_MAX_PUBLIC_CONNECTIONS);
    expect(actual.MAX_QUEUED_CALLS).toBe(HERMES_MAX_PUBLIC_CONNECTIONS);
    expect(actual.MCP_PROTOCOL_VERSION).toBe(P.VERSIONS[0]);
    expect(source).toContain('TOOL_NAMES = ("memory_insert", "memory_get", "memory_search", "memory_recall", "sign_statement", "export_memory", "protection_rules")\n');
    expect(source).toContain("MAX_QUEUED_CALLS = HERMES_MAX_PUBLIC_CONNECTIONS\n");
  });
  it("pins all outcome pairs and their single wording source", () => {
    expect(Object.keys(actual.OUTCOMES).sort()).toEqual([...Object.keys(HERMES_TOOL_OUTCOMES), "saved"].sort());
    const all = source + readFileSync(join(root, "sanctuary/__init__.py"), "utf8") + readFileSync(join(root, "sanctuary_memory/__init__.py"), "utf8");
    for (const [name, result] of Object.entries(HERMES_TOOL_OUTCOMES)) {
      const pair = JSON.parse((result.content[0] as { text: string }).text);
      expect(actual.OUTCOMES[name]).toEqual(pair);
      expect(all.split(pair.message)).toHaveLength(2); // One occurrence creates two split fragments.
      expect(JSON.stringify(actual.OUTCOMES[name])).not.toMatch(/error|failed/i);
    }
  });
  it("pins all three tool descriptions and complete schemas", () => {
    const expected = HERMES_TOOLS_LIST_PAYLOAD.tools.filter(tool => ["sign_statement", "export_memory", "protection_rules"].includes(tool.name))
      .map(tool => ({ name: tool.name, description: "description" in tool ? tool.description : undefined, parameters: tool.input_schema }));
    expect(actual.TOOL_SCHEMAS).toEqual(expected);
  });
  it("pins the native path prefix and keeps the plugin free of private decision content", () => {
    expect(actual.SANCTUARY_INSTALL_ROOT).toBe(P.FIXED_SOCKET_PATH.split("Sanctuary/")[0] + "Sanctuary/");
    const visit = (directory: string): void => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const file = join(directory, entry.name);
        if (entry.isDirectory()) visit(file);
        else expect(readFileSync(file, "utf8"), file).not.toMatch(/\btier\b|tier[_ -]?[0-9]|principal[_-]?policy|approval|allowlist|blocklist/i);
      }
    };
    visit(join(root, "sanctuary")); visit(join(root, "sanctuary_memory"));
  });
});
