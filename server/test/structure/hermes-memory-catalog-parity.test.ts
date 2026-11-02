// Every consumer uses the complete catalog and the same local timing and output bounds.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { HERMES_MEMORY_TOOL_NAMES, HERMES_MEMORY_WIRE_SCHEMAS } from "../../src/hermes-memory-bridge/envelopes.js";
import { HERMES_TOOLS_LIST_PAYLOAD } from "../../src/hermes-memory-bridge/public-results.js";
import { TOOL_NAMES, SHIM_CONNECT_HELLO_TIMEOUT_MS } from "../../src/hermes-memory-client/protocol.js";
import { RECALL_PREFETCH_BUDGET_MS, RECALL_PASSAGE_MAX_UNITS, RECALL_MAX_CANDIDATES_SCANNED } from "../../src/hermes-memory-bridge/recall.js";
import { HERMES_INSERT_DEADLINE_MS, HERMES_TOOL_TIMEOUT_MS, PROBE_REPLY_BOUND_MS, HERMES_RESPONSE_MARGIN_MS } from "../../src/hermes-memory-bridge/constants.js";
import { MEMORY_CORPUS_SCAN_CAP, MEMORY_BATCH_LOCK_TIMEOUT_MS } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { HUB_APPROVAL_PASSAGE_MAX_UNITS } from "../../src/contracts/v1.1/hub-events.js";
const root = join(import.meta.dirname, "../../..");
it("keeps the full seven-tool set in every consumer", () => {
  const expected = ["memory_insert", "memory_get", "memory_search", "memory_recall", "sign_statement", "export_memory", "protection_rules"];
  const python = readFileSync(join(root, "server/test/hermes-memory-client/real_client.py"), "utf8");
  const literal = python.match(/assert \[t.name for t in tools.tools\]==\[([^\]]+)\]/u)![1]!;
  const seam = readFileSync(join(root, "hermes-memory-relay/SEAM.md"), "utf8").match(/The exact seven names are ([^.]+), with no cursor/u)![1]!;
  for (const names of [HERMES_MEMORY_TOOL_NAMES, HERMES_TOOLS_LIST_PAYLOAD.tools.map(t => t.name), Object.keys(HERMES_MEMORY_WIRE_SCHEMAS.toolArguments),
    TOOL_NAMES, [...literal.matchAll(/'([^']+)'/gu)].map(m => m[1]), seam.split(", ")]) {
    expect(names).toHaveLength(expected.length);
    expect(new Set(names)).toEqual(new Set(expected));
  }
  expect(HERMES_TOOLS_LIST_PAYLOAD.tools.map(t => t.name)).toEqual(HERMES_MEMORY_TOOL_NAMES);
});
it("pins recall limits on both sides", () => {
  expect(RECALL_PREFETCH_BUDGET_MS).toBe(SHIM_CONNECT_HELLO_TIMEOUT_MS);
  expect(RECALL_PASSAGE_MAX_UNITS).toBe(HUB_APPROVAL_PASSAGE_MAX_UNITS);
  expect(RECALL_MAX_CANDIDATES_SCANNED).toBe(MEMORY_CORPUS_SCAN_CAP);
  expect(HERMES_INSERT_DEADLINE_MS).toBe(HERMES_TOOL_TIMEOUT_MS - MEMORY_BATCH_LOCK_TIMEOUT_MS - PROBE_REPLY_BOUND_MS - HERMES_RESPONSE_MARGIN_MS);
});
it("reserves the deprecated deadline alias for the authority profile", () => {
  const old = "HERMES_APPROVAL_DEADLINE_MS";
  for (const directory of ["hermes-memory-bridge", "hermes-memory-client"]) {
    for (const file of readdirSync(join(root, "server/src", directory)).filter(f => f.endsWith(".ts"))) {
      const source = readFileSync(join(root, "server/src", directory, file), "utf8");
      // The required alias declaration itself is the only exception to the no-reference rule.
      expect(source.replace(`export const ${old} = HERMES_INSERT_DEADLINE_MS;`, ""), file).not.toContain(old);
    }
  }
});
