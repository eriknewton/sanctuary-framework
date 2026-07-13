/**
 * Governed File-Grant v1 -- `_file_grants` reserved-namespace firewall pin.
 *
 * A grant record describes exactly what an agent may read, so it must NEVER be
 * reachable through the agent-facing generic state tools (that would be a
 * policy-inference leak). The `_file_grants` namespace is on the reserved list
 * in cognitive/tools.ts (same posture as `_audit`/`_identities`), and the
 * `state_read` / `state_list` / `state_delete` MCP tool handlers reject any
 * `_`-prefixed namespace. This test PINS that firewall so a future edit that
 * dropped `_file_grants` from the reserved set (or weakened the `_`-prefix
 * contract) would fail loudly. Internal subsystems still reach the namespace
 * directly through `FileGrantStore` (which bypasses these tool-level checks);
 * that operator-facing path is exercised in state-store-roundtrip.test.ts.
 */

import { describe, expect, it } from "vitest";

import { createL1Tools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FILE_GRANT_NAMESPACE } from "../../src/file-grant/index.js";

type ToolResult = { content: Array<{ type: string; text: string }> };
type Tool = {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<ToolResult>;
};

function makeTools(): Tool[] {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  return createL1Tools(stateStore, storage, masterKey, "recovery-key", auditLog)
    .tools as unknown as Tool[];
}

async function callTool(
  tools: Tool[],
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

describe("_file_grants reserved-namespace firewall (agent-facing state_* tools reject it)", () => {
  for (const toolName of ["state_read", "state_list", "state_delete"] as const) {
    it(`${toolName} rejects the _file_grants namespace`, async () => {
      const tools = makeTools();
      const res = await callTool(tools, toolName, {
        namespace: FILE_GRANT_NAMESPACE,
        key: "fg_0123456789abcdef",
      });
      expect(res.error).toBe("namespace_reserved");
    });
  }

  it("the file-grant namespace constant is `_file_grants` (underscore-reserved)", () => {
    expect(FILE_GRANT_NAMESPACE).toBe("_file_grants");
    expect(FILE_GRANT_NAMESPACE.startsWith("_")).toBe(true);
  });
});
