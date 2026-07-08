/**
 * Castle Wall Observe / Learn Allow-List v1 -- `_castle_wall_observe`
 * reserved-namespace firewall pin.
 *
 * CI DoD test 5 (part 2): the suggestion store is invisible to the agent
 * being watched. A candidate row is a map of "destinations the operator has
 * not yet allowed" -- exposing it to the agent would leak policy structure
 * (Invariant #7, property #11). The `_castle_wall_observe` namespace is
 * `_`-prefixed, so it is reserved by construction (`cognitive/tools.ts`'s
 * firewall rejects EVERY `_`-prefixed namespace, not just a curated list),
 * and it is additionally listed in the curated `RESERVED_NAMESPACE_PREFIXES`
 * set for a precise violation label. This test pins BOTH: the agent-facing
 * `state_read`/`state_list`/`state_delete` MCP tools reject it, and the
 * namespace constant itself is underscore-reserved.
 *
 * Modeled on test/file-grant/reserved-namespace-firewall.test.ts.
 */

import { describe, expect, it } from "vitest";

import { createL1Tools } from "../../../src/cognitive/tools.js";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { OBSERVE_NAMESPACE } from "../../../src/castle-wall/observe/index.js";

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

describe("_castle_wall_observe reserved-namespace firewall (agent-facing state_* tools reject it)", () => {
  for (const toolName of ["state_read", "state_list", "state_delete"] as const) {
    it(`${toolName} rejects the _castle_wall_observe namespace`, async () => {
      const tools = makeTools();
      const res = await callTool(tools, toolName, {
        namespace: OBSERVE_NAMESPACE,
        key: "candidate:0123456789abcdef0123456789abcdef",
      });
      expect(res.error).toBe("namespace_reserved");
    });
  }

  it("the observe namespace constant is `_castle_wall_observe` (underscore-reserved)", () => {
    expect(OBSERVE_NAMESPACE).toBe("_castle_wall_observe");
    expect(OBSERVE_NAMESPACE.startsWith("_")).toBe(true);
  });
});
