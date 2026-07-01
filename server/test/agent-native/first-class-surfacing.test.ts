import { describe, expect, it } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { ToolDefinition } from "../../src/router.js";
import {
  COOPERATIVE_DENIAL_DISCOVERY_HINT,
  fingerprintIdentityId,
  type SessionBinding,
} from "../../src/agent-native/safety-base.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import {
  COOPERATIVE_CAPABILITIES,
  buildServerInstructions,
} from "../../src/agent-native/capabilities-catalog.js";

async function callTool(
  tools: ToolDefinition[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`missing tool: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function session(identityId: string): SessionBinding {
  return {
    identity_id: identityId,
    requester_identity_fingerprint: fingerprintIdentityId(identityId),
  };
}

async function setup() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  let active: SessionBinding | undefined;
  const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog,
    { currentSessionBinding: () => active }
  );
  await identityManager.load();
  const identity = await callTool(l1Tools, "identity_create", { label: "agent-a" });
  active = session(identity.identity_id as string);
  const { tools: facadeTools } = createAgentNativeCooperativeTools({
    identityManager,
    namespaceRegistry,
    auditLog,
    currentSessionBinding: () => active,
    primitiveTools: l1Tools,
    storage,
  });
  return { facadeTools, auditLog, active };
}

describe("first-class tool surfacing", () => {
  describe("move 1: capabilities discovery surface", () => {
    it("registers a read-only sanctuary_capabilities tool taking no arguments", async () => {
      const { facadeTools } = await setup();
      const tool = facadeTools.find((candidate) => candidate.name === "sanctuary_capabilities");
      expect(tool).toBeDefined();
      expect(tool!.tool_class).toBe("read");
      expect(tool!.inputSchema).toEqual({ type: "object", properties: {} });
    });

    it("returns the full cooperative catalog with does/when for each tool", async () => {
      const { facadeTools } = await setup();
      const result = await callTool(facadeTools, "sanctuary_capabilities");
      const capabilities = result.capabilities as Array<Record<string, string>>;
      expect(capabilities).toHaveLength(COOPERATIVE_CAPABILITIES.length);
      for (const entry of capabilities) {
        expect(typeof entry.tool).toBe("string");
        expect(entry.does.length).toBeGreaterThan(0);
        expect(entry.when.length).toBeGreaterThan(0);
      }
      expect(typeof result.audit_ref).toBe("string");
    });

    it("only lists tools that are actually registered on the surface", async () => {
      const { facadeTools } = await setup();
      const registered = new Set(facadeTools.map((candidate) => candidate.name));
      for (const entry of COOPERATIVE_CAPABILITIES) {
        expect(registered.has(entry.tool), entry.tool).toBe(true);
      }
    });

    it("builds MCP server instructions naming the discovery entrypoints and every catalog tool", () => {
      const instructions = buildServerInstructions();
      expect(instructions).toContain("sanctuary_help");
      expect(instructions).toContain("sanctuary_capabilities");
      for (const entry of COOPERATIVE_CAPABILITIES) {
        expect(instructions, entry.tool).toContain(entry.tool);
      }
      // Never overclaim: the cooperative layer does not itself block anything;
      // the instructions must not promise enforcement it cannot deliver.
      expect(instructions.toLowerCase()).not.toContain("unbypassable");
      expect(instructions.toLowerCase()).not.toContain("block");
    });
  });

  describe("move 3: enforcement-as-teacher (harness-agnostic, non-wall)", () => {
    it("attaches a discovery_hint to a cooperative denial", async () => {
      const { facadeTools } = await setup();
      // A recall of a never-stored key denies (unverified read); the denial must
      // carry the static discovery pointer.
      const denied = await callTool(facadeTools, "sanctuary_recall", { key: "never_stored" });
      expect(denied.denied).toBe(true);
      expect(denied.discovery_hint).toBe(COOPERATIVE_DENIAL_DISCOVERY_HINT);
    });

    it("keeps the discovery_hint IDENTICAL across different denials (no policy leak)", async () => {
      const { facadeTools } = await setup();
      const recallDenied = await callTool(facadeTools, "sanctuary_recall", { key: "absent_a" });
      const forgetDenied = await callTool(facadeTools, "sanctuary_forget", {
        key: "absent_b",
        mode: "plain",
        approval_ref: "approval:missing",
      });
      expect(recallDenied.denied).toBe(true);
      expect(forgetDenied.denied).toBe(true);
      // Rule 7: the hint must be byte-for-byte identical so it cannot reveal
      // which tool/tier/rule produced the denial or what was attempted.
      expect(recallDenied.discovery_hint).toBe(forgetDenied.discovery_hint);
      expect(recallDenied.discovery_hint).toBe(COOPERATIVE_DENIAL_DISCOVERY_HINT);
    });

    it("names only general discovery entrypoints, never a per-request tool", () => {
      // The hint must not name any operation-specific tool (which would leak
      // the attempted operation class); only sanctuary_help / sanctuary_capabilities.
      expect(COOPERATIVE_DENIAL_DISCOVERY_HINT).toContain("sanctuary_help");
      expect(COOPERATIVE_DENIAL_DISCOVERY_HINT).toContain("sanctuary_capabilities");
      for (const leaky of ["sanctuary_forget", "sanctuary_remember", "sanctuary_recall", "sanctuary_hide"]) {
        expect(COOPERATIVE_DENIAL_DISCOVERY_HINT).not.toContain(leaky);
      }
    });
  });
});
