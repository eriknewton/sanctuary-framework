/**
 * Public-surface snapshot (l1-l4 rename PR-0 safety net).
 *
 * The l1-l4 -> named-layer rename happens across several PRs. Before any rename
 * touches code, this test FREEZES the entire agent-/consumer-facing public
 * surface as committed JSON fixtures, so every later rename PR provably changes
 * ZERO public bytes: if a rename PR reds this test, it altered something a
 * consumer can see (a wire tool name or input schema, the SHR shape, the
 * sovereignty-audit shape, or an exported API name) and must be corrected.
 *
 * Four committed goldens under __fixtures__/public-surface/, each asserted with
 * plain `toEqual` against a value re-extracted from the CURRENT tree by the
 * SHARED extractor (public-surface-extract.ts) — NOT Vitest auto-`.snap`, so the
 * baseline is a reviewable committed file and any diff is a deliberate, reviewed
 * surface change (regenerate with gen-public-surface-snapshot.ts in that PR).
 *
 *   1. mcp-tool-surface.json        — {name, inputSchema} for every MCP tool
 *                                      (main catalog + broker/*), sorted by name.
 *   2. shr-shape.json               — SHR body.layers key/field shape + the
 *                                      degradations[].layer value set (l1..l4).
 *   3. sovereignty-audit-shape.json — analyzeSovereignty layers/gap-id/gap-layer
 *                                      surface + gateway-adapter layer_scores /
 *                                      layer_status keys.
 *   4. exported-names.json          — sorted names re-exported from src/index.ts.
 *
 * RECONCILIATION with the existing Phase-0 guards in this directory (so PR-0 adds
 * coverage, not duplication): reorg-surface-snapshots.test.ts froze the main
 * catalog's wire {name, inputSchema} in REGISTRATION ORDER and deliberately
 * EXCLUDED description prose (it is iterated agent-facing copy) while keeping a
 * separate presence guard. This snapshot is COMPLEMENTARY: it is SORTED BY NAME
 * (rename-order-agnostic), INCLUDES the broker/* tools the reorg golden omits,
 * and adds the SHR / sovereignty-audit / exported-name surfaces. It follows the
 * SAME description policy as reorg: description PROSE is NOT frozen here, so
 * legitimate copy iteration never reds it and PR-1's doc/comment stage may edit
 * layer-number prose inside a description; the frozen tool contract is
 * {name, inputSchema}. reorg-surface-snapshots keeps descriptions present + non-empty.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createTempHome } from "../helpers/temp-fortress.js";

import {
  extractToolSurface,
  extractShrShape,
  extractSovereigntyAuditShape,
  extractExportedNames,
  type ToolSurfaceEntry,
  type ShrShape,
  type SovereigntyAuditShape,
} from "./public-surface-extract.js";

const FIXTURES = join(
  fileURLToPath(import.meta.url),
  "..",
  "__fixtures__",
  "public-surface",
);

function readFixture<T>(name: string): T {
  return JSON.parse(
    readFileSync(join(FIXTURES, name), "utf-8"),
  ) as T;
}

const REGEN =
  "If this change is intentional + reviewed, regenerate the fixture in this " +
  "same PR with `npx tsx test/structure/gen-public-surface-snapshot.ts`. A " +
  "pure l1-l4 -> named-layer rename must NOT change it.";


// Fortress hermeticity: the tool-catalog extractor boots the real server, and
// `createSanctuaryServer` step 20 writes the config unconditionally. With
// `HOME` left alone that write lands on the operator's own
// `~/.sanctuary/sanctuary.json`. Moving `HOME` redirects the mkdir, the
// permission tightening, and the config write onto a throwaway directory
// without changing the surface under snapshot. `saveConfig` fails such a write
// closed under Vitest, so removing this turns the leak into a loud failure.
let fortressHome: Awaited<ReturnType<typeof createTempHome>>;

beforeEach(async () => {
  fortressHome = await createTempHome("sanctuary-public-surface");
});

afterEach(async () => {
  await fortressHome.cleanup();
});

describe("public-surface snapshot: MCP tool catalog", () => {
  it("the full agent-facing tool catalog ({name, inputSchema}, by name) matches the committed golden", async () => {
    const golden = readFixture<ToolSurfaceEntry[]>("mcp-tool-surface.json");
    const current = await extractToolSurface();

    // Count first — clearest failure if a tool was added/removed/hidden.
    expect(
      current.length,
      `MCP tool catalog count changed from the golden (${golden.length}) to ` +
        `${current.length}. A rename must not add/remove/hide a tool. ${REGEN}`,
    ).toBe(golden.length);

    // Names — the most common + clearest drift, surfaced separately.
    expect(
      current.map((t) => t.name),
      `MCP tool NAMES drifted from the committed golden. A layer rename must ` +
        `not rename a wire tool. ${REGEN}`,
    ).toEqual(golden.map((t) => t.name));

    // Full surface: {name, inputSchema} per tool, sorted by name.
    expect(
      current,
      `MCP tool surface ({name, inputSchema}) drifted from the committed ` +
        `golden — a wire tool name or input schema changed. ${REGEN}`,
    ).toEqual(golden);
  });

  it("the catalog has no duplicate tool names", async () => {
    const names = (await extractToolSurface()).map((t) => t.name);
    const dupes = names.filter((n, i) => names.indexOf(n) !== i);
    expect(dupes, `duplicate tool names: ${dupes.join(", ")}`).toEqual([]);
  });
});

describe("public-surface snapshot: SHR JSON shape", () => {
  it("the signed-SHR body layer/degradation shape matches the committed golden", () => {
    const golden = readFixture<ShrShape>("shr-shape.json");
    const current = extractShrShape();
    expect(
      current,
      `SHR body shape (layers.* keys/fields or degradations[].layer values) ` +
        `drifted from the committed golden. A layer rename must not change the ` +
        `l1..l4 SHR surface a counterparty parses. ${REGEN}`,
    ).toEqual(golden);
  });
});

describe("public-surface snapshot: sovereignty-audit JSON shape", () => {
  it("the analyzer + gateway-adapter layer/gap shape matches the committed golden", () => {
    const golden = readFixture<SovereigntyAuditShape>(
      "sovereignty-audit-shape.json",
    );
    const current = extractSovereigntyAuditShape();
    expect(
      current,
      `Sovereignty-audit shape (analyzer layers.*/gaps[].id/gaps[].layer or ` +
        `gateway-adapter layer_scores.*/layer_status.* keys) drifted from the ` +
        `committed golden. ${REGEN}`,
    ).toEqual(golden);
  });
});

describe("public-surface snapshot: exported package API", () => {
  it("the names re-exported from src/index.ts match the committed golden", () => {
    const golden = readFixture<string[]>("exported-names.json");
    const current = extractExportedNames();

    expect(
      current.length,
      `Exported-name count changed from the golden (${golden.length}) to ` +
        `${current.length}. A rename must not add/remove a public export. ${REGEN}`,
    ).toBe(golden.length);

    expect(
      current,
      `The public export surface of src/index.ts (what becomes dist/index.d.ts) ` +
        `drifted from the committed golden — an exported name was added, removed, ` +
        `or renamed. ${REGEN}`,
    ).toEqual(golden);
  });
});
