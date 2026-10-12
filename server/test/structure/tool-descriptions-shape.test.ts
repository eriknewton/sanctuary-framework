/**
 * Tool-description shape guard: the socket describes itself truthfully to an
 * evaluating agent.
 *
 * CAPABILITY. An agent deciding whether to install Sanctuary, or whether to
 * call a tool, reads the MCP tool `description` fields as product copy
 * (CONTRIBUTING.md forward rule: what the tool does, when to call it, what it
 * returns, and its key constraints). Two constraints an agent cannot discover
 * any other way before calling are the approval tier (a Tier 1 call waits on
 * a human) and the typography rule every public artifact in this repository
 * obeys (zero em-dashes). This guard holds three shape properties over the
 * FULL wire-registered tool set, built from the real composition root
 * (`createSanctuaryServer` + `tools/list`), never from a hand list, so a tool
 * added anywhere in `server/src` is covered the moment it registers:
 *
 *   (a) no description contains an em-dash (U+2014);
 *   (b) every tool whose DEFAULT tier is Tier 1 names its tier in its own
 *       description, in a sentence that also says who approves;
 *   (c) every description is a non-empty string.
 *
 * WHERE THE TIER 1 SET COMES FROM. The default Principal Policy is
 * `DEFAULT_POLICY` after `enforceForcedTiers` (the loader's merge, which folds
 * the non-relaxable forced set into `tier1_always_approve`). A registered tool
 * is Tier 1 by default when its operation name is in that merged Tier 1 list,
 * OR when it is in neither list: the gate's classifier falls an unclassified
 * operation to Tier 1 (the SEC-011 safe default). Must match the precedence
 * in `classifyOperation`, `server/src/principal-policy/gate.ts` (forced Tier 1,
 * then policy Tier 1, then anomaly, then Tier 3, then the unclassified
 * fallback). A wired agreement check below asks the real `ApprovalGate` to
 * classify every registered name against the same policy, so this file's
 * derivation and the shipped classifier cannot disagree silently.
 *
 * SCOPE BOUND, stated so the claim does not exceed the reach: the set under
 * test is what `tools/list` emits to an agent. Tools the router hides from the
 * agent catalog are not agent-facing copy and are out of scope here; the
 * standalone broker MCP server registers its own catalog and is covered by the
 * public-surface snapshot, not by this guard.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import {
  DEFAULT_POLICY,
  enforceForcedTiers,
  extractOperationName,
} from "../../src/principal-policy/loader.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

/** The one code point the no-em-dash rule forbids. */
const EM_DASH = "—";

/**
 * A tier statement names the tier ("Tier 1", "Tier-1", "tier 1") and, in the
 * SAME sentence, who approves (an approval, the operator, or a human). The
 * same-sentence rule is what distinguishes "Tier 1: requires operator
 * approval" (a statement about this tool) from "returns the Tier 1 and Tier 3
 * operation lists" (a statement about something this tool returns).
 */
const TIER_1_TOKEN = /\btier[ -]?1\b/i;
const APPROVER_TOKEN = /approv|operator|human/i;
/** Sentence boundary: terminal punctuation followed by whitespace. */
const SENTENCE_BOUNDARY = /(?<=[.!?])\s+/;

/**
 * Sanity floor for the booted registry: a count at or below it means the boot
 * path registered a fragment, not the catalog. It sits well below the 111
 * tools registered at the time of writing and well above any partial
 * registration; the golden fixtures own the exact set, not this guard.
 */
const REGISTRY_SANITY_FLOOR = 100;

interface WireTool {
  name: string;
  description?: unknown;
}

function namesItsTier(description: string): boolean {
  return description
    .split(SENTENCE_BOUNDARY)
    .some((sentence) => TIER_1_TOKEN.test(sentence) && APPROVER_TOKEN.test(sentence));
}

/** Reach into the MCP SDK Server's private request-handler map (test-only). */
async function listWireTools(server: unknown): Promise<WireTool[]> {
  const handler = (
    server as { _requestHandlers: Map<string, (...a: unknown[]) => unknown> }
  )._requestHandlers.get("tools/list");
  if (!handler) throw new Error("tools/list handler not registered");
  const result = (await handler({ method: "tools/list", params: {} }, {})) as {
    tools: WireTool[];
  };
  return result.tools;
}

// Fortress hermeticity: `createSanctuaryServer` writes the config
// unconditionally, so HOME is moved onto a throwaway directory for the boot
// (the same discipline as public-surface-snapshot.test.ts).
let fortressHome: Awaited<ReturnType<typeof createTempHome>>;
let cleanupServer: (() => Promise<void>) | undefined;
let registry: WireTool[] = [];

beforeAll(async () => {
  fortressHome = await createTempHome("sanctuary-tool-descriptions");
  const booted = await createSanctuaryServer({
    storage: new MemoryStorage(),
    passphrase: TEST_PASSPHRASE,
  });
  cleanupServer = booted.cleanup;
  registry = await listWireTools(booted.server);
});

// Reap the booted server and the throwaway fortress so no timer, inbox tick,
// or temp directory outlives this file.
afterAll(async () => {
  await cleanupServer?.();
  await fortressHome?.cleanup();
});

describe("tool descriptions describe the socket truthfully to an evaluating agent", () => {
  it("the registry under test is the real wire catalog, not a hand list", () => {
    expect(registry.length).toBeGreaterThan(REGISTRY_SANITY_FLOOR);
  });

  it("(a) no tool description contains an em-dash (U+2014)", () => {
    const offenders = registry
      .filter((tool) => typeof tool.description === "string" && tool.description.includes(EM_DASH))
      .map((tool) => tool.name);
    expect(
      offenders,
      "Tool descriptions are public product copy and ship on the wire; the no-em-dash rule " +
        "applies. Replace each em-dash with a comma, colon, or a new sentence:\n  " +
        offenders.join("\n  "),
    ).toEqual([]);
  });

  it("(b) every tool whose default tier is Tier 1 names its tier in its description", () => {
    const policy = enforceForcedTiers(DEFAULT_POLICY);
    const tier1 = new Set<string>(policy.tier1_always_approve);
    const tier3 = new Set<string>(policy.tier3_always_allow);
    const defaultTier1 = registry.filter((tool) => {
      const operation = extractOperationName(tool.name);
      // Must match the unclassified fallback in classifyOperation
      // (server/src/principal-policy/gate.ts): in neither list is Tier 1.
      return tier1.has(operation) || !tier3.has(operation);
    });
    expect(defaultTier1.length).toBeGreaterThan(0);
    const silent = defaultTier1
      .filter((tool) => !namesItsTier(String(tool.description ?? "")))
      .map((tool) => tool.name);
    expect(
      silent,
      "These tools wait on operator approval under the default policy but their " +
        "description does not say so. State the tier the way the best descriptions " +
        "do (for example \"Tier 1: requires operator approval\"):\n  " +
        silent.join("\n  "),
    ).toEqual([]);
  });

  it("(c) every tool description is a non-empty string", () => {
    const empty = registry
      .filter((tool) => typeof tool.description !== "string" || tool.description.trim().length === 0)
      .map((tool) => tool.name);
    expect(empty, "Every wire tool must carry agent-facing copy:\n  " + empty.join("\n  ")).toEqual([]);
  });

  it("the derived Tier 1 set agrees with the shipped ApprovalGate classifier", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();
    const channel = new CallbackApprovalChannel(async () => {
      throw new Error("dry-run classification must never reach the approval channel");
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);
    const policy = enforceForcedTiers(DEFAULT_POLICY);
    const tier1 = new Set<string>(policy.tier1_always_approve);
    const tier3 = new Set<string>(policy.tier3_always_allow);

    const disagreements: string[] = [];
    for (const tool of registry) {
      const operation = extractOperationName(tool.name);
      const classified = gate.classifyRiskTier(tool.name, {});
      if (tier1.has(operation) && classified !== 1) {
        disagreements.push(`${tool.name}: policy Tier 1, gate ${classified}`);
      } else if (tier3.has(operation) && classified !== 3) {
        disagreements.push(`${tool.name}: policy Tier 3, gate ${classified}`);
      } else if (!tier1.has(operation) && !tier3.has(operation) && classified === 3) {
        // An unclassified operation may classify as Tier 1 (safe default) or
        // Tier 2 (first-session anomaly on a fresh baseline); it never
        // auto-allows.
        disagreements.push(`${tool.name}: unclassified, yet gate auto-allowed (3)`);
      }
    }
    expect(disagreements).toEqual([]);
  });
});
