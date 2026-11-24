/** The session text an agent reads in tools/list and the capabilities catalog is frozen. */
import { afterEach, expect, it, vi } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

// Each literal is written out in full and never imported, so a change to the shipped text fails here.
const WHO_AM_I_DESCRIPTION = "Return whether this session has a Sanctuary identity and how it was bound, with the disclosable identity facts when it does: label, did, active-identity fingerprint and memory namespace handle. With no identity it answers bound false and says what to tell your operator. A default binding lasts until this server process exits. Read-only; private keys are never included.";
const ACTIVE_PROTECTIONS_DESCRIPTION = "List every layer of Sanctuary with its evidence-based status, including layers that are off, not built, or unknown. Use to ask what is protecting this session right now. Read-only; returns { guarantees, layers, summary, audit_ref }. The guarantees field preserves legacy flags; layers and the one-line-per-layer summary report observed status. Answers in a session with no identity; the identity layer then reads unknown.";
const CAPABILITIES_DESCRIPTION = "Return the start-here catalog of Sanctuary's cooperative tools: for each tool, what it does and when to reach for it. Read-only, takes no arguments. Call this to discover what cooperative memory/identity/audit tools are available and route your work through them instead of ad-hoc state. The same catalog is also delivered in the MCP server instructions at connect time; this tool re-serves it on demand. Returns { session: { bound, binding_source } when bound or { bound, operator_action } when not, capabilities: [{ tool, does, when, available }], audit_ref }.";
const COMPOUND_EXECUTE_DESCRIPTION = "Execute a short plan of sanctuary_remember, sanctuary_recall, sanctuary_hide and sanctuary_forget steps in order, in one call. Tier 1 under the default policy: requires operator approval for the call itself. Each step is { tool, args } and gets a step_id by position (step-1, step-2, and so on). Every sanctuary_forget step also needs its own operator approval, passed in approvals keyed by step_id and bound to this exact plan and step. Step approvals are reserved before any step runs, and if one is missing or does not match, no step runs. Completed steps are not rolled back: if a step fails, the call returns the standard refusal, and the steps before it may have taken effect; use sanctuary_recall to check your current memory state.";
const WHO_AM_I_CATALOG_DOES = "Returns whether this session has an identity and how it was bound, with the disclosable identity facts when it does (label, did, identity fingerprint, memory namespace handle). Never returns private keys.";

let cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  try { for (const cleanup of cleanups.reverse()) await cleanup(); }
  finally { cleanups = []; vi.unstubAllEnvs(); }
});

async function connect() {
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", undefined);
  const home = await createTempHome("sanctuary-session-strings");
  cleanups.push(() => home.cleanup());
  await mkdir(home.defaultFortressPath, { recursive: true });
  await writeFile(join(home.defaultFortressPath, "principal-policy.yaml"),
    generateDefaultPolicyYaml().replace(/approval_channel:\n  type: \w+/, "approval_channel:\n  type: callback"));
  const approve = async () => ({ decision: "approve" as const, decided_at: new Date().toISOString(), decided_by: "human" as const });
  const app = await createSanctuaryServer({ storage: new MemoryStorage(), passphrase: TEST_PASSPHRASE, approvalCallback: approve });
  const client = new Client({ name: "session-strings-witness", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await app.server.connect(serverTransport);
  await client.connect(clientTransport);
  cleanups.push(async () => { try { await client.close(); } finally { await app.cleanup(); } });
  return client;
}

it("tools/list carries the session descriptions byte for byte", async () => {
  const client = await connect();
  const { tools } = await client.listTools();
  const description = (name: string) => tools.find((tool) => tool.name === name)?.description;
  expect(description("sanctuary_who_am_i")).toBe(WHO_AM_I_DESCRIPTION);
  expect(description("sanctuary_active_protections")).toBe(ACTIVE_PROTECTIONS_DESCRIPTION);
  expect(description("sanctuary_capabilities")).toBe(CAPABILITIES_DESCRIPTION);
  expect(description("sanctuary_compound_execute")).toBe(COMPOUND_EXECUTE_DESCRIPTION);
});

it("the capabilities catalog says what who-am-I does byte for byte", async () => {
  const client = await connect();
  const result = await client.callTool({ name: "sanctuary_capabilities", arguments: {} }) as { content: Array<{ text: string }> };
  const answer = JSON.parse(result.content[0]!.text) as { capabilities: Array<{ tool: string; does: string }> };
  expect(answer.capabilities.find((entry) => entry.tool === "sanctuary_who_am_i")?.does).toBe(WHO_AM_I_CATALOG_DOES);
});
