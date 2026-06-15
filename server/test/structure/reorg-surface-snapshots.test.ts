/**
 * Reorg surface snapshots — MCP tools/list wire shape + operation-policy tiers.
 *
 * Phase-0 deliverable (a). Two committed goldens that a pure reorg (file moves,
 * the l1-l4 -> named-layer rename, god-file splits, the index.ts registration-
 * group split) must NOT change:
 *
 *   1. test/fixtures/tools-list-wire-golden.json — the agent-facing MCP
 *      `tools/list` response: the exact tool NAMES, each tool's INPUT SCHEMA,
 *      their registration ORDER, and the count. The index.ts split (scoping §8
 *      risk 10) can silently reorder or drop a tool while unit tests stay green;
 *      reordering registration "for tidiness" is explicitly forbidden. A reorg
 *      could also silently alter an inputSchema (a wire contract a hidden MCP
 *      client validates against). This golden catches both.
 *
 *      DELIBERATE EXCLUSION — the top-level tool `description`. router.ts emits
 *      name/description/inputSchema on the wire, but tool descriptions are
 *      AI-agent-audience product copy that legitimately changes under the
 *      forward / doc-coverage rule (memory: market-directly-to-ai-agents; the
 *      tool `description` fields ARE the agent-facing pitch and are iterated
 *      independently of any reorg). Snapshotting them here would red every
 *      legitimate doc/copy PR. So the golden freezes the WIRE CONTRACT
 *      ({name, inputSchema}) and omits the prose. NOTE: per-parameter schema
 *      descriptions INSIDE inputSchema are part of the JSON-Schema contract a
 *      client validates/branches on, so they stay in the snapshot — only the
 *      top-level tool description is dropped. The richer internal metadata —
 *      tool_class, approvalTarget* — is NOT reachable from the wire and is
 *      presence-guarded by frozen-surfaces + noted as a follow-up
 *      internal-registry snapshot in the surface manifest.)
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

/** The frozen wire contract per tool: name + input schema, NOT description. */
interface WireTool {
  name: string;
  inputSchema: Record<string, unknown>;
}
interface WireGolden {
  tool_count: number;
  tools: WireTool[];
}
interface PolicyGolden {
  tier1_always_approve: string[];
  tier2_anomaly: Record<string, unknown>;
  tier3_always_allow: string[];
}

/**
 * Issue a tools/list request against the built server's registered handler and
 * return the canonical wire contract per tool: {name, inputSchema}. The
 * top-level `description` is deliberately dropped (see the file header — it is
 * AI-agent-audience copy that changes under the forward-doc rule, not a reorg
 * surface).
 */
async function listToolWire(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"],
): Promise<WireTool[]> {
  const handler = (
    server as unknown as { _requestHandlers: Map<string, (...a: unknown[]) => unknown> }
  )._requestHandlers.get("tools/list");
  if (!handler) throw new Error("tools/list handler not registered");
  const result = (await handler(
    { method: "tools/list", params: {} },
    {},
  )) as { tools: Array<{ name: string; inputSchema: Record<string, unknown> }> };
  return result.tools.map((t) => ({ name: t.name, inputSchema: t.inputSchema }));
}

describe("reorg surface snapshot: MCP tools/list wire shape", () => {
  it("the agent-facing tool catalog matches the committed wire golden (names + inputSchema + order + count)", async () => {
    const golden = JSON.parse(
      readFileSync(join(FIXTURES, "tools-list-wire-golden.json"), "utf-8"),
    ) as WireGolden;

    const { server } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "snapshot-harness-deterministic-v1",
    });
    const wire = await listToolWire(server);

    // Count first (clearest failure if a tool was added/removed).
    expect(
      wire.length,
      `Agent tool catalog count changed from the golden (${golden.tool_count}) ` +
        `to ${wire.length}. A reorg must not add/remove/hide a wire tool. If a ` +
        "tool change is intentional + reviewed, regenerate the golden in this PR.",
    ).toBe(golden.tool_count);

    // Names + order — the index.ts registration-group split must preserve them.
    // Surfaced as a separate assertion because a name/order drift is the most
    // common + clearest failure, and reads better than a deep-equal diff.
    expect(
      wire.map((t) => t.name),
      "tools/list NAMES or ORDER drifted from the committed golden. Never " +
        "reorder tool registration for tidiness; a hidden MCP client may depend " +
        "on order/identity. Regenerate the golden only for an intentional, " +
        "reviewed tool change.",
    ).toEqual(golden.tools.map((t) => t.name));

    // Then the full wire contract: {name, inputSchema} per tool, in order. This
    // catches a silent inputSchema drift (a changed/removed required field, a
    // re-typed property) that a names-only snapshot would miss. The top-level
    // tool `description` is intentionally NOT compared (see the file header).
    expect(
      wire,
      "tools/list wire contract ({name, inputSchema}) drifted from the committed " +
        "golden — an input schema changed (or a tool moved). A reorg must not " +
        "alter the wire schema. If a schema change is intentional + reviewed, " +
        "regenerate the golden in this PR. (Tool DESCRIPTIONS are excluded from " +
        "this golden by design and never trip it.)",
    ).toEqual(golden.tools);
  });

  it("the catalog has no duplicate tool names", async () => {
    const { server } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "snapshot-harness-deterministic-v1",
    });
    const names = (await listToolWire(server)).map((t) => t.name);
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
