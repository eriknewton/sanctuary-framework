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
  ASSURANCE_MATRIX_URL,
  COOPERATIVE_CAPABILITIES,
  EVALUATE_NOUN_WORDS,
  EVALUATE_NOUNS,
  EVALUATE_RELATED_TOOLS,
  EVALUATE_ROUTE_TOOLS,
  EVALUATE_ROUTES,
  SERVER_BOUNDS,
  buildBoundsParagraph,
  buildServerInstructions,
} from "../../src/agent-native/capabilities-catalog.js";
import { createSanctuaryServer } from "../../src/index.js";
import { DEFAULT_POLICY, enforceForcedTiers } from "../../src/principal-policy/loader.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import {
  CATALOG_COOPERATIVE_TOOL_NAMES,
  COOPERATIVE_TOOL_NAMES,
} from "../../src/agent-native/tool-names.js";

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
      const tool = facadeTools.find((candidate) => candidate.name === COOPERATIVE_TOOL_NAMES.capabilities);
      expect(tool).toBeDefined();
      expect(tool!.tool_class).toBe("read");
      expect(tool!.inputSchema).toEqual({ type: "object", properties: {} });
    });

    it("returns the full cooperative catalog with does/when for each tool", async () => {
      const { facadeTools } = await setup();
      const result = await callTool(facadeTools, COOPERATIVE_TOOL_NAMES.capabilities);
      const capabilities = result.capabilities as Array<Record<string, string>>;
      expect(capabilities).toHaveLength(COOPERATIVE_CAPABILITIES.length);
      expect(capabilities.map((entry) => entry.tool)).toEqual(CATALOG_COOPERATIVE_TOOL_NAMES);
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
      expect([...registered].sort()).toEqual([...Object.values(COOPERATIVE_TOOL_NAMES)].sort());
      for (const entry of COOPERATIVE_CAPABILITIES) {
        expect(registered.has(entry.tool), entry.tool).toBe(true);
      }
    });

    it("builds MCP server instructions naming the discovery entrypoints and every catalog tool", () => {
      const instructions = buildServerInstructions();
      expect(instructions).toContain(COOPERATIVE_TOOL_NAMES.help);
      expect(instructions).toContain(COOPERATIVE_TOOL_NAMES.capabilities);
      for (const entry of COOPERATIVE_CAPABILITIES) {
        expect(instructions, entry.tool).toContain(entry.tool);
      }
      // Never overclaim: the cooperative layer does not itself block anything;
      // the instructions must not promise enforcement it cannot deliver.
      expect(instructions.toLowerCase()).not.toContain("unbypassable");
      expect(instructions.toLowerCase()).not.toContain("block");
      // The bounds paragraph is appended, whole, after the catalog: platforms
      // with the patched-host qualifier on the enforcement sentence, the three
      // tiers with Tier 1 waiting on a human, the never-claimed line, and the
      // evidence URL. At most four sentences, zero em-dashes.
      expect(instructions.endsWith(buildBoundsParagraph())).toBe(true);
      expect(instructions).toContain("Bounds, tiers and evidence:");
      for (const sentence of Object.values(SERVER_BOUNDS)) {
        expect(instructions).toContain(sentence);
      }
      expect(SERVER_BOUNDS.platforms).toContain("on a patched host");
      expect(SERVER_BOUNDS.platforms).toContain("Windows");
      expect(SERVER_BOUNDS.tiers).toContain("Tier 1");
      expect(SERVER_BOUNDS.evidence).toContain(ASSURANCE_MATRIX_URL);
      expect(Object.keys(SERVER_BOUNDS)).toHaveLength(4);
      expect(instructions).not.toContain("\u2014");
    });

    it("pins the evaluate-route tools to the real registry and their tiers to the default policy", async () => {
      // Registry pin: a rename of monitor_health, sovereignty_audit or
      // sanctuary_policy_status anywhere in server/src fails here, because the
      // route table names them by literal rather than importing them.
      const fortressHome = await createTempHome("sanctuary-evaluate-routes");
      const booted = await createSanctuaryServer({
        storage: new MemoryStorage(),
        passphrase: TEST_PASSPHRASE,
      });
      try {
        const handler = (
          booted.server as unknown as { _requestHandlers: Map<string, (...a: unknown[]) => unknown> }
        )._requestHandlers.get("tools/list")!;
        const listed = (await handler({ method: "tools/list", params: {} }, {})) as {
          tools: Array<{ name: string }>;
        };
        const registered = new Set(listed.tools.map((tool) => tool.name));
        for (const name of Object.values(EVALUATE_ROUTE_TOOLS)) {
          expect(registered.has(name), name).toBe(true);
        }
      } finally {
        await booted.cleanup();
        await fortressHome.cleanup();
      }
      // Every route resolves to a pinned tool or to CLI guidance, never to a
      // name outside the pin table.
      const pinned = new Set<string>(Object.values(EVALUATE_ROUTE_TOOLS));
      for (const route of EVALUATE_ROUTES) {
        expect(route.tool === null || pinned.has(route.tool), route.question).toBe(true);
        expect(route.guidance.length, route.question).toBeGreaterThan(0);
        expect(route.matches.flags, route.question).not.toContain("g");
      }
      // Tier labels agree with the default policy the gate enforces.
      const policy = enforceForcedTiers(DEFAULT_POLICY);
      for (const entry of EVALUATE_RELATED_TOOLS) {
        const expected = policy.tier1_always_approve.includes(entry.tool) ? "Tier 1" : "Tier 3";
        expect(entry.tier.startsWith(expected), entry.tool).toBe(true);
        if (expected === "Tier 3") expect(policy.tier3_always_allow).toContain(entry.tool);
      }
    });

    it("every evaluate noun resolves to a route, so a noun hit never falls to the ambiguous answer", () => {
      // The catalog comment claims every noun lands on a question; this makes
      // the claim an invariant the suite enforces (round-2 finding F2:
      // "installation" once matched the noun gate and no route).
      const unrouted = EVALUATE_NOUN_WORDS.filter(
        (word) => EVALUATE_ROUTES.find((route) => route.matches.test(word)) === undefined
      );
      expect(unrouted).toEqual([]);
      for (const word of EVALUATE_NOUN_WORDS) {
        expect(EVALUATE_NOUNS.test(word), word).toBe(true);
        expect(EVALUATE_NOUNS.test(`${word}ish`), word).toBe(false);
      }
      expect(EVALUATE_NOUNS.flags).not.toContain("g");
      expect(EVALUATE_NOUNS.test("protected")).toBe(false);
    });
  });

  describe("move 3: enforcement-as-teacher (harness-agnostic, non-wall)", () => {
    it("attaches a discovery_hint to a cooperative denial", async () => {
      const { facadeTools } = await setup();
      // A recall of a never-stored key denies (unverified read); the denial must
      // carry the static discovery pointer.
      const denied = await callTool(facadeTools, COOPERATIVE_TOOL_NAMES.recall, { key: "never_stored" });
      expect(denied.denied).toBe(true);
      expect(denied.discovery_hint).toBe(COOPERATIVE_DENIAL_DISCOVERY_HINT);
    });

    it("keeps the discovery_hint IDENTICAL across different denials (no policy leak)", async () => {
      const { facadeTools } = await setup();
      const recallDenied = await callTool(facadeTools, COOPERATIVE_TOOL_NAMES.recall, { key: "absent_a" });
      const forgetDenied = await callTool(facadeTools, COOPERATIVE_TOOL_NAMES.forget, {
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
      expect(COOPERATIVE_DENIAL_DISCOVERY_HINT).toContain(COOPERATIVE_TOOL_NAMES.help);
      expect(COOPERATIVE_DENIAL_DISCOVERY_HINT).toContain(COOPERATIVE_TOOL_NAMES.capabilities);
      for (const leaky of [
        COOPERATIVE_TOOL_NAMES.forget,
        COOPERATIVE_TOOL_NAMES.remember,
        COOPERATIVE_TOOL_NAMES.recall,
        COOPERATIVE_TOOL_NAMES.hide,
      ]) {
        expect(COOPERATIVE_DENIAL_DISCOVERY_HINT).not.toContain(leaky);
      }
    });
  });
});
