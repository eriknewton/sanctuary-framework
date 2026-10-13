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
 *   (b1) every tool in the default policy's Tier 1 list names Tier 1 in its
 *        own description, in a sentence that also says who approves;
 *   (b2) every tool in NEITHER default list says it requires operator
 *        approval and never calls itself "Tier 1";
 *   (c) every description is a non-empty string.
 *
 * WHERE THE TWO SETS COME FROM. The default Principal Policy is
 * `DEFAULT_POLICY` after `enforceForcedTiers` (the loader's merge, which folds
 * the non-relaxable forced set into `tier1_always_approve`). The explicit
 * Tier 1 set is the registered tools whose operation name is in that merged
 * list. The unlisted set is the registered tools in neither list. The two
 * wordings differ because the tier NUMBER differs for an unlisted tool while
 * the approval requirement does not: `classifyOperation` in
 * `server/src/principal-policy/gate.ts` checks forced Tier 1, then the policy
 * Tier 1 list, then `detectAnomaly`, then Tier 3, then the unclassified
 * fallback; `detectAnomaly` on a FIRST session (default
 * `first_session_policy: "approve"`) flags every operation outside
 * `tier3_always_allow`, so an unlisted tool is Tier 2 on a first session and
 * Tier 1 (the SEC-011 safe default) afterwards. "Tier 1" in an unlisted
 * tool's copy would therefore be false on the agent's first session; "requires
 * operator approval" is true on every session. The wording pin on the gate's
 * fallback branch says the same thing from the other side. The wired
 * agreement check below asks the real `ApprovalGate` to classify every
 * registered name against the same policy on a fresh baseline and again on
 * an established one, so this file's derivation and the shipped classifier
 * cannot disagree silently.
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
/**
 * The unlisted-tool statement: approval is required, with no tier number.
 * Must match the wording the twelve unlisted tools carry and the pin on the
 * unclassified fallback in `classifyOperation` (gate.ts).
 */
const OPERATOR_APPROVAL_TOKEN = /\brequires operator approval\b/i;
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

/**
 * Split the wire registry into the explicit default Tier 1 set and the
 * unlisted set (neither list). Must match the precedence in
 * `classifyOperation` (gate.ts): the policy Tier 1 list is checked before the
 * anomaly detector, so an explicit Tier 1 tool is Tier 1 on every session; an
 * unlisted tool reaches the detector and then the safe-default fallback.
 */
function partitionRegistry(): { explicitTier1: WireTool[]; unlisted: WireTool[]; tier3: WireTool[] } {
  const policy = enforceForcedTiers(DEFAULT_POLICY);
  const tier1 = new Set<string>(policy.tier1_always_approve);
  const tier3 = new Set<string>(policy.tier3_always_allow);
  const explicitTier1: WireTool[] = [];
  const unlisted: WireTool[] = [];
  const allowed: WireTool[] = [];
  for (const tool of registry) {
    const operation = extractOperationName(tool.name);
    if (tier1.has(operation)) explicitTier1.push(tool);
    else if (tier3.has(operation)) allowed.push(tool);
    else unlisted.push(tool);
  }
  return { explicitTier1, unlisted, tier3: allowed };
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

  it("(b1) every tool in the default Tier 1 list names Tier 1 and its approver in one sentence", () => {
    const { explicitTier1 } = partitionRegistry();
    expect(explicitTier1.length).toBeGreaterThan(0);
    const silent = explicitTier1
      .filter((tool) => !namesItsTier(String(tool.description ?? "")))
      .map((tool) => tool.name);
    expect(
      silent,
      "These tools are Tier 1 under the default policy but their description does " +
        "not say so. State the tier the way the best descriptions do (for example " +
        "\"Tier 1: requires operator approval\"):\n  " +
        silent.join("\n  "),
    ).toEqual([]);
  });

  it("(b2) every tool in neither default list says it requires operator approval and never calls itself Tier 1", () => {
    const { unlisted } = partitionRegistry();
    expect(unlisted.length).toBeGreaterThan(0);
    const silent: string[] = [];
    const overclaims: string[] = [];
    for (const tool of unlisted) {
      const description = String(tool.description ?? "");
      if (!OPERATOR_APPROVAL_TOKEN.test(description)) silent.push(tool.name);
      // "Tier 1" is false for this tool on a first session (Tier 2 anomaly);
      // the approval requirement is what holds on every session.
      if (TIER_1_TOKEN.test(description)) overclaims.push(tool.name);
    }
    expect(
      silent,
      "These tools are in neither default policy list, so the gate requires operator " +
        "approval for them, but their description does not say so:\n  " +
        silent.join("\n  "),
    ).toEqual([]);
    expect(
      overclaims,
      "These tools are in neither default policy list; they are Tier 2 on a first " +
        "session and Tier 1 afterwards, so a description must not name Tier 1. Use " +
        "\"Requires operator approval under the default policy (not named in a policy " +
        "tier; the gate's safe default).\":\n  " +
        overclaims.join("\n  "),
    ).toEqual([]);
  });

  it("(c) every tool description is a non-empty string", () => {
    const empty = registry
      .filter((tool) => typeof tool.description !== "string" || tool.description.trim().length === 0)
      .map((tool) => tool.name);
    expect(empty, "Every wire tool must carry agent-facing copy:\n  " + empty.join("\n  ")).toEqual([]);
  });

  it("the derived sets agree with the shipped ApprovalGate classifier on a first session and on an established one", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const channel = new CallbackApprovalChannel(async () => {
      throw new Error("dry-run classification must never reach the approval channel");
    });
    const { explicitTier1, unlisted, tier3 } = partitionRegistry();

    // Session 1: a fresh tracker with nothing persisted is a first session.
    const firstSession = new BaselineTracker(storage, masterKey);
    await firstSession.load();
    expect(firstSession.isFirstSession).toBe(true);
    const firstGate = new ApprovalGate(DEFAULT_POLICY, firstSession, channel, auditLog);
    // Persist it, so the next tracker on the same storage is an established
    // session, the way the tracker itself distinguishes the two.
    await firstSession.save();
    const established = new BaselineTracker(storage, masterKey);
    await established.load();
    expect(established.isFirstSession).toBe(false);
    const establishedGate = new ApprovalGate(DEFAULT_POLICY, established, channel, auditLog);

    // Description wording pin (must match the unclassified fallback comment in
    // classifyOperation, gate.ts, and tests (b1)/(b2) above): an explicit
    // Tier 1 tool is 1 on both sessions, so its copy may say "Tier 1"; an
    // unlisted tool is 2 on the first session and 1 afterwards, so its copy
    // says "requires operator approval" and never "Tier 1".
    const disagreements: string[] = [];
    for (const tool of explicitTier1) {
      for (const [label, gate] of [["first", firstGate], ["established", establishedGate]] as const) {
        const classified = gate.classifyRiskTier(tool.name, {});
        if (classified !== 1) disagreements.push(`${tool.name}: policy Tier 1, ${label}-session gate ${classified}`);
      }
    }
    for (const tool of tier3) {
      for (const [label, gate] of [["first", firstGate], ["established", establishedGate]] as const) {
        const classified = gate.classifyRiskTier(tool.name, {});
        if (classified !== 3) disagreements.push(`${tool.name}: policy Tier 3, ${label}-session gate ${classified}`);
      }
    }
    for (const tool of unlisted) {
      const first = firstGate.classifyRiskTier(tool.name, {});
      if (first !== 2) disagreements.push(`${tool.name}: unlisted, first-session gate ${first} (expected 2)`);
      const later = establishedGate.classifyRiskTier(tool.name, {});
      if (later !== 1) disagreements.push(`${tool.name}: unlisted, established-session gate ${later} (expected 1)`);
    }
    expect(disagreements).toEqual([]);
  });
});
