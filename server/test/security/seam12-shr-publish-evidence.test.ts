/**
 * Honesty seam #12: auto-generated SHR publish payload must be evidence-based.
 *
 * The reputation_publish 'shr' path, when called with no explicit `data`,
 * previously hardcoded a perfect score (L1/L3/L4 = 100/active/"cryptographically
 * verified") and then signed it with the agent's real key and POSTed it to an
 * EXTERNAL reputation surface (Verascore). A relying party could not tell a
 * hardcoded 100 from an earned 100, and an instance with no Castle Wall
 * enforcement evidence still published "L1 100 active".
 *
 * The honest behavior, verified here:
 *  - The auto-generated payload derives sovereigntyLayers from the SAME
 *    evidence source monitor_health uses (buildHealthEvidenceReport).
 *  - A layer with no observed enforcement evidence (Castle Wall unwired →
 *    L1 cognitive status "unknown") publishes as "unknown" with score 0,
 *    NOT "100 / active".
 *  - The overall score is the mean of evidence-derived scores, not a constant.
 *  - The advertised capabilities do not unconditionally claim "zk-proofs".
 *  - With no live evidence source the path refuses to fabricate a payload.
 *  - An explicit caller-supplied payload is still published unchanged.
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { loadConfig } from "../../src/config.js";

type ToolList = Array<{
  name: string;
  handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }>;
}>;

async function callTool(tools: ToolList, name: string, args: Record<string, unknown> = {}) {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function setup(withConfig: boolean) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);

  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  await identityManager.load();

  const config = withConfig ? await loadConfig() : undefined;
  const { tools: l4Tools } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog,
    undefined,
    "https://verascore.ai",
    config
  );

  const tools = [...l1Tools, ...l4Tools] as ToolList;
  await callTool(tools, "identity_create", { label: "seam12-publisher" });
  return { tools };
}

/**
 * Stub global fetch to capture the published request body without a real POST.
 */
function captureFetch(): { calls: Array<Record<string, unknown>> } {
  const calls: Array<Record<string, unknown>> = [];
  globalThis.fetch = (async (_url: string, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    calls.push(body);
    return {
      ok: true,
      status: 200,
      json: async () => ({ success: true }),
    } as unknown as Response;
  }) as typeof fetch;
  return { calls };
}

describe("seam #12: SHR publish payload is evidence-based, not a hardcoded perfect score", () => {
  it("derives sovereigntyLayers from live health evidence; L1 is 'unknown' (not 'active') with no Castle Wall evidence", async () => {
    const { tools } = await setup(true);
    const { calls } = captureFetch();

    await callTool(tools, "reputation_publish", { type: "shr" });

    expect(calls).toHaveLength(1);
    const layers = (calls[0].data as { sovereigntyLayers: Array<Record<string, unknown>> })
      .sovereigntyLayers;

    const l1 = layers.find((l) => l.name === "L1")!;
    expect(l1.status).toBe("unknown");
    expect(l1.score).toBe(0);
    expect(String(l1.description)).not.toMatch(/cryptographically verified/i);

    const l2 = layers.find((l) => l.name === "L2")!;
    expect(l2.status).toBe("degraded");
  });

  it("overall score is the mean of evidence-derived layer scores, not a hardcoded constant", async () => {
    const { tools } = await setup(true);
    const { calls } = captureFetch();

    await callTool(tools, "reputation_publish", { type: "shr" });

    const data = calls[0].data as {
      sovereigntyLayers: Array<{ score: number }>;
      overallScore: number;
    };
    const mean = Math.round(
      data.sovereigntyLayers.reduce((s, l) => s + l.score, 0) / data.sovereigntyLayers.length
    );
    expect(data.overallScore).toBe(mean);
    expect(data.overallScore).toBeLessThan(93);
  });

  it("does not unconditionally advertise the zk-proofs capability", async () => {
    const { tools } = await setup(true);
    const { calls } = captureFetch();

    await callTool(tools, "reputation_publish", { type: "shr" });

    const capabilities = (calls[0].data as { capabilities: string[] }).capabilities;
    expect(capabilities).not.toContain("zk-proofs");
  });

  it("refuses to fabricate a payload when no live evidence source (config) is available", async () => {
    const { tools } = await setup(false);
    const { calls } = captureFetch();

    const parsed = await callTool(tools, "reputation_publish", { type: "shr" });

    expect(parsed.error).toBeDefined();
    expect(String(parsed.error)).toMatch(/explicit 'data'|evidence source/i);
    expect(calls).toHaveLength(0);
  });

  it("still publishes an explicit caller-supplied payload unchanged (legitimate path preserved)", async () => {
    const { tools } = await setup(true);
    const { calls } = captureFetch();

    const explicit = {
      sovereigntyLayers: [
        { name: "L4", label: "Verifiable Reputation", score: 88, status: "active", description: "earned" },
      ],
      overallScore: 88,
    };
    await callTool(tools, "reputation_publish", { type: "shr", data: explicit });

    expect(calls).toHaveLength(1);
    expect(calls[0].data).toEqual(explicit);
  });
});
