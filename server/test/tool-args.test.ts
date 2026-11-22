/** String length declarations are enforced by the shared validator for registered schemas. */
import { describe, expect, it } from "vitest";
import * as toolArgs from "../src/tool-args.js";
import { createAgentNativeCooperativeTools } from "../src/agent-native/cooperative-surface.js";
import { createL1Tools } from "../src/cognitive/tools.js";
import { StateStore } from "../src/cognitive/state-store.js";
import { MemoryStorage } from "../src/storage/memory.js";
import { AuditLog } from "../src/operational/audit-log.js";
import { generateRandomKey } from "../src/core/random.js";

function helpSchema() {
  const storage = new MemoryStorage();
  const key = generateRandomKey();
  const auditLog = new AuditLog(storage, key);
  const { tools, identityManager, namespaceRegistry } = createL1Tools(new StateStore(storage, key), storage, key, "recovery-key", auditLog);
  return createAgentNativeCooperativeTools({ identityManager, namespaceRegistry, auditLog, primitiveTools: tools, currentSessionBinding: () => undefined }).tools.find(tool => tool.name === "sanctuary_help")!.inputSchema;
}

describe("declared string lengths", () => {
  it("counts Unicode code points through shared validation violations", () => {
    const shape = { type: "object", properties: { intent: { type: "string", maxLength: 4096 } }, required: ["intent"] };
    const schema = toolArgs.enforceDeclaredStringLengths?.(shape) ?? shape;
    expect(toolArgs.validateArgs({ intent: "😀".repeat(4096) }, schema)).toEqual([]);
    expect(toolArgs.validateArgs({ intent: "😀".repeat(4097) }, schema)).toEqual([{
      field: "intent", message: 'Field "intent" exceeds maximum length (4097 code points > 4096 code points)',
    }]);
  });
  it("leaves unregistered string declarations unenforced", () => {
    expect(toolArgs.validateArgs({ detail: "x".repeat(300) }, {
      type: "object", properties: { detail: { type: "string", maxLength: 280 } },
    })).toEqual([]);
    for (const field of ["signer_did", "reason"]) {
      expect(toolArgs.validateArgs({ [field]: "x".repeat(300) }, {
        type: "object", properties: { [field]: { type: "string", maxLength: 256 } },
      })).toEqual([]);
    }
  });
  it("registers the production help schema for normalization", () => {
    const intent = "lorem ".repeat(682) + "ipsum";
    expect(intent).toHaveLength(4097);
    const schema = helpSchema();
    expect(() => toolArgs.normalizeToolArgsForValidation({ args: { intent }, schema })).toThrow(toolArgs.ToolArgumentValidationError);
    expect(toolArgs.validateArgs({ intent }, schema)).toHaveLength(1);
    expect(toolArgs.validateArgs({ intent: "😀".repeat(4096) }, schema)).toEqual([]);
  });
});
