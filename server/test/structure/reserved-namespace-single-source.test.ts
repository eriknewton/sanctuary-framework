/**
 * Reserved-namespace contract: single source of truth (RESERVED-NS-DIVERGE-01).
 *
 * `RESERVED_NAMESPACE_PREFIXES` and `isReservedNamespace` used to be
 * hand-mirrored between `cognitive/tools.ts` (19 curated entries) and
 * `cognitive/state-store.ts` (16 entries, missing `_facade`, `_file_grants`,
 * and `_castle_wall_observe`). The exported `isReservedNamespace` also only
 * checked the curated list, so a caller that forgot the separate
 * `namespace.startsWith("_")` inline check would have missed an uncurated
 * `_`-namespace. Both `cognitive/tools.ts` and `exit/bundle.ts` now import
 * the list and predicate from `cognitive/state-store.ts`, and
 * `isReservedNamespace` applies the blanket underscore rule on its own.
 *
 * This test is the reconciliation guard for that consolidation:
 *
 *   1. A structural scan asserts there is exactly ONE
 *      `RESERVED_NAMESPACE_PREFIXES` array literal definition anywhere in
 *      `server/src` (in `cognitive/state-store.ts`) — a second one reopens
 *      the divergence class.
 *   2. A behavioral full-set check asserts `isReservedNamespace` classifies
 *      every entry from the pre-consolidation union of both lists, a nested
 *      child of each, an uncurated `_foo`, and a normal (non-reserved)
 *      namespace correctly — not just a first-entry smoke check.
 */

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  isReservedNamespace,
  RESERVED_NAMESPACE_PREFIXES,
} from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";

const HERE = fileURLToPath(import.meta.url);
const SERVER_DIR = join(HERE, "..", "..", "..");
const SERVER_SRC = join(SERVER_DIR, "src");

// The pre-consolidation union of tools.ts's 19-entry list and
// state-store.ts's 16-entry list (state-store.ts was missing these three).
const EXPECTED_PREFIXES = [
  "_identities",
  "_policies",
  "_audit",
  "_meta",
  "_principal",
  "_commitments",
  "_reputation",
  "_escrow",
  "_guarantees",
  "_bridge",
  "_federation",
  "_handshake",
  "_shr",
  "_sovereignty_profile",
  "_context_gate_policies",
  "_fortress_mode",
  "_facade",
  "_file_grants",
  "_castle_wall_observe",
];

// Matches `const RESERVED_NAMESPACE_PREFIXES = [` with an optional `export`,
// the exact shape of the array-literal declaration this list was defined as
// in both hand-mirrored copies before consolidation.
const DEFINITION_PATTERN = /(export\s+)?const\s+RESERVED_NAMESPACE_PREFIXES\s*=\s*\[/;

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

function rel(full: string): string {
  return relative(SERVER_SRC, full).split("\\").join("/");
}

describe("reserved-namespace contract: single source of truth", () => {
  it("exactly one RESERVED_NAMESPACE_PREFIXES array-literal definition exists in server/src", () => {
    const definers = tsFiles(SERVER_SRC)
      .map((full) => ({ rel: rel(full), text: readFileSync(full, "utf-8") }))
      .filter((f) => DEFINITION_PATTERN.test(f.text))
      .map((f) => f.rel);

    expect(
      definers,
      "a RESERVED_NAMESPACE_PREFIXES array literal was found outside " +
        "cognitive/state-store.ts; this reopens the divergence class " +
        "RESERVED-NS-DIVERGE-01 fixed - the list must have exactly one " +
        "definition and every other consumer must import it: " + definers.join(", ")
    ).toEqual(["cognitive/state-store.ts"]);
  });

  it("RESERVED_NAMESPACE_PREFIXES contains the full pre-consolidation union, no more, no fewer", () => {
    expect(new Set(RESERVED_NAMESPACE_PREFIXES)).toEqual(new Set(EXPECTED_PREFIXES));
  });

  it("isReservedNamespace classifies every curated prefix, and a nested child of each, as reserved", () => {
    for (const prefix of EXPECTED_PREFIXES) {
      expect(isReservedNamespace(prefix), `expected ${prefix} to be reserved`).toBe(true);
      expect(
        isReservedNamespace(`${prefix}/child`),
        `expected ${prefix}/child to be reserved`
      ).toBe(true);
    }
  });

  it("isReservedNamespace classifies an uncurated underscore-prefixed namespace as reserved (the blanket rule)", () => {
    expect(isReservedNamespace("_foo")).toBe(true);
    expect(isReservedNamespace("_not_on_the_curated_list/child")).toBe(true);
  });

  it("isReservedNamespace classifies non-underscore namespaces as not reserved", () => {
    expect(isReservedNamespace("foo")).toBe(false);
    expect(isReservedNamespace("reputation")).toBe(false);
    // Deliberately similar to a reserved prefix but without the underscore -
    // the prefix match must not fire on substring similarity alone.
    expect(isReservedNamespace("identities")).toBe(false);
  });
});

// --- Tool-layer classification parity -------------------------------------
//
// getReservedNamespaceViolation (cognitive/tools.ts) is internal, so its
// classification is exercised the same way test/file-grant/
// reserved-namespace-firewall.test.ts already exercises `_file_grants`: via
// the agent-facing state_* MCP tool handlers. This proves the tools-layer
// label lookup still rejects namespaces that were only ever curated in
// tools.ts's list (never in state-store.ts's, pre-consolidation) now that
// both files share one list.

type ToolResult = { content: Array<{ type: string; text: string }> };
type Tool = {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<ToolResult>;
};

function makeTools(): Tool[] {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  return createL1Tools(stateStore, storage, masterKey, "recovery-key", auditLog)
    .tools as unknown as Tool[];
}

async function callTool(
  tools: Tool[],
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

describe("tools-layer classification parity after consolidation", () => {
  for (const namespace of ["_facade", "_castle_wall_observe", "_file_grants", "_uncurated_foo"]) {
    it(`state_read rejects ${namespace}`, async () => {
      const tools = makeTools();
      const res = await callTool(tools, "state_read", {
        namespace,
        key: "some_key_0123456789abcdef",
      });
      expect(res.error).toBe("namespace_reserved");
    });
  }

  it("state_read accepts a normal namespace (no false-positive reservation)", async () => {
    const tools = makeTools();
    const res = await callTool(tools, "state_read", {
      namespace: "notes",
      key: "some_key_0123456789abcdef",
    });
    // Not present, but must fail for "not found", never "namespace_reserved".
    expect(res.error).not.toBe("namespace_reserved");
  });
});
