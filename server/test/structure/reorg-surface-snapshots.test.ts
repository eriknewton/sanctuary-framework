/**
 * Reorg surface snapshots — MCP tools/list wire shape + operation-policy tiers.
 *
 * Phase-0 deliverable (a). Two committed goldens that a pure reorg (file moves,
 * the l1-l4 -> named-layer rename, god-file splits, the index.ts registration-
 * group split) must NOT change:
 *
 *   1. test/fixtures/tools-list-wire-golden.json — the agent-facing MCP
 *      `tools/list` response: the exact tool NAMES, their registration ORDER,
 *      and the count. The index.ts split (scoping §8 risk 10) can silently
 *      reorder or drop a tool while unit tests stay green; reordering
 *      registration "for tidiness" is explicitly forbidden. This golden catches
 *      it. (router.ts emits only name/description/inputSchema on the wire; the
 *      richer internal metadata — tool_class, approvalTarget* — is NOT
 *      reachable from the wire and is presence-guarded by frozen-surfaces +
 *      noted as a follow-up internal-registry snapshot in the surface manifest.)
 *
 *   2. test/fixtures/operation-policy-golden.json — DEFAULT_POLICY's tier1 /
 *      tier3 op lists and the full tier2 anomaly config. Tiering is BEHAVIOR but
 *      is invisible to tools/list (scoping §7 operation-policy snapshot). A
 *      reorg that moves a loader constant and silently re-tiers an op (or drops
 *      one to a weaker tier) reds here.
 *
 * Determinism harness (scoping §7 snapshot-determinism): the server is built
 * with an in-memory storage backend + a fixed passphrase, no network, no
 * external config — so the catalog is reproducible, not environment-flaky.
 *
 * Regenerate intentionally (when a tool/tier change is real + reviewed) by
 * temporarily writing the goldens from the same harness; do NOT loosen these to
 * make a reorg pass.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";

const FIXTURES = join(fileURLToPath(import.meta.url), "..", "..", "fixtures");

interface WireGolden {
  tool_count: number;
  tools: string[];
}
interface PolicyGolden {
  tier1_always_approve: string[];
  tier2_anomaly: Record<string, unknown>;
  tier3_always_allow: string[];
}

/** Issue a tools/list request against the built server's registered handler. */
async function listToolNames(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"],
): Promise<string[]> {
  const handler = (
    server as unknown as { _requestHandlers: Map<string, (...a: unknown[]) => unknown> }
  )._requestHandlers.get("tools/list");
  if (!handler) throw new Error("tools/list handler not registered");
  const result = (await handler(
    { method: "tools/list", params: {} },
    {},
  )) as { tools: Array<{ name: string }> };
  return result.tools.map((t) => t.name);
}

describe("reorg surface snapshot: MCP tools/list wire shape", () => {
  it("the agent-facing tool catalog matches the committed wire golden (names + order + count)", async () => {
    const golden = JSON.parse(
      readFileSync(join(FIXTURES, "tools-list-wire-golden.json"), "utf-8"),
    ) as WireGolden;

    const { server } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "snapshot-harness-deterministic-v1",
    });
    const names = await listToolNames(server);

    // Count first (clearest failure if a tool was added/removed).
    expect(
      names.length,
      `Agent tool catalog count changed from the golden (${golden.tool_count}) ` +
        `to ${names.length}. A reorg must not add/remove/hide a wire tool. If a ` +
        "tool change is intentional + reviewed, regenerate the golden in this PR.",
    ).toBe(golden.tool_count);

    // Then exact order — the index.ts registration-group split must preserve it.
    expect(
      names,
      "tools/list NAMES or ORDER drifted from the committed golden. Never " +
        "reorder tool registration for tidiness; a hidden MCP client may depend " +
        "on order/identity. Regenerate the golden only for an intentional, " +
        "reviewed tool change.",
    ).toEqual(golden.tools);
  });

  it("the catalog has no duplicate tool names", async () => {
    const { server } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "snapshot-harness-deterministic-v1",
    });
    const names = await listToolNames(server);
    const dupes = names.filter((n, i) => names.indexOf(n) !== i);
    expect(dupes, `duplicate tool names: ${dupes.join(", ")}`).toEqual([]);
  });
});

describe("reorg surface snapshot: operation-policy tiers", () => {
  const golden = JSON.parse(
    readFileSync(join(FIXTURES, "operation-policy-golden.json"), "utf-8"),
  ) as PolicyGolden;

  it("DEFAULT_POLICY.tier1_always_approve matches the committed golden", () => {
    expect(
      [...DEFAULT_POLICY.tier1_always_approve].sort(),
      "Tier-1 (always-approve) op set drifted from the golden. A reorg must not " +
        "re-tier an operation. Regenerate the golden only for a reviewed change.",
    ).toEqual(golden.tier1_always_approve);
  });

  it("DEFAULT_POLICY.tier3_always_allow matches the committed golden", () => {
    expect(
      [...DEFAULT_POLICY.tier3_always_allow].sort(),
      "Tier-3 (auto-allow) op set drifted from the golden. Re-tiering an op is a " +
        "behavior change, not a reorg.",
    ).toEqual(golden.tier3_always_allow);
  });

  it("DEFAULT_POLICY.tier2_anomaly config matches the committed golden", () => {
    const current = Object.fromEntries(
      Object.entries(DEFAULT_POLICY.tier2_anomaly).sort(([a], [b]) =>
        a.localeCompare(b),
      ),
    );
    expect(
      current,
      "Tier-2 anomaly config (thresholds / defaults) drifted from the golden.",
    ).toEqual(golden.tier2_anomaly);
  });
});
