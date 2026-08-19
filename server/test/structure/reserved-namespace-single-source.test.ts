// fail-before-exempt: this PR's only change to this file is a comment correcting where getReservedNamespaceViolation now lives; no assertion changed, so nothing here can fail against pre-fix source.
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

// Matches a `const`/`let`/`var` declaration of `RESERVED_NAMESPACE_PREFIXES`,
// with an optional `export` and an optional type annotation, initialized
// either as an array literal or as `new Set([...])`. Widened from the
// original `const RESERVED_NAMESPACE_PREFIXES = [` (the exact shape both
// hand-mirrored copies used before consolidation) after an adversarial gate
// on this PR found that shape alone stays green under a type-annotated
// const, a `new Set(...)` initializer, and a `let` in place of `const` -
// see the scope note on the assertion below for what this still cannot
// catch.
const DEFINITION_PATTERN =
  /(export\s+)?(const|let|var)\s+RESERVED_NAMESPACE_PREFIXES\s*(:[^=]+)?=\s*(\[|new\s+Set\s*\(\s*\[)/;

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

    // Scope note (this IS the guard's real reach, not aspirational): this
    // scan covers `const`/`let`/`var` array-literal or `new Set([...])`
    // declarations of this EXACT identifier name, with or without a type
    // annotation, in `.ts` files under `server/src` only. It CANNOT catch a
    // copy under a different name (e.g. `RESERVED_PREFIXES`), a copy in a
    // `.mts`/`.cts`/`.js` file, a copy in `server/test` or outside
    // `server/src` entirely, or a class-static/object-property/spread-built
    // list. A renamed or differently-shaped copy is a name-based-scan blind
    // spot no regex closes; catching it needs a semantic (AST/type-level)
    // check, not this test.
    expect(
      definers,
      "a RESERVED_NAMESPACE_PREFIXES declaration (const/let/var array " +
        "literal or new Set([...]) initializer, with or without a type " +
        "annotation) was found outside cognitive/state-store.ts; this " +
        "reopens the divergence class RESERVED-NS-DIVERGE-01 fixed - the " +
        "list must have exactly one definition and every other consumer " +
        "must import it. This scan covers only .ts files under server/src " +
        "and only this exact identifier name (see the scope note above " +
        "this assertion for what it cannot catch). Found in: " +
        definers.join(", ")
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

// --- DEFINITION_PATTERN coverage --------------------------------------
//
// An independent adversarial gate on this PR mutation-tested the original
// `(export\s+)?const\s+RESERVED_NAMESPACE_PREFIXES\s*=\s*\[` pattern and
// found four reintroduction shapes that stayed 10/10 green: a type-annotated
// const, a `new Set([...])` initializer, `let` in place of `const`, and a
// renamed const. The widened `DEFINITION_PATTERN` above closes the first
// three (each is asserted directly below); the fourth is a name-based-scan
// blind spot the widening cannot close, asserted here only to document that
// it stays open, never to claim coverage it does not have.
describe("DEFINITION_PATTERN: widened shape coverage", () => {
  const newlyCoveredShapes: Record<string, string> = {
    "type-annotated const": 'const RESERVED_NAMESPACE_PREFIXES: readonly string[] = [\n  "_a",\n];',
    "let instead of const": 'let RESERVED_NAMESPACE_PREFIXES = [\n  "_a",\n];',
    "var instead of const": 'var RESERVED_NAMESPACE_PREFIXES = [\n  "_a",\n];',
    "new Set(...) initializer": 'const RESERVED_NAMESPACE_PREFIXES = new Set([\n  "_a",\n]);',
    "exported, type-annotated, new Set(...)":
      'export const RESERVED_NAMESPACE_PREFIXES: ReadonlySet<string> = new Set([\n  "_a",\n]);',
  };

  for (const [label, snippet] of Object.entries(newlyCoveredShapes)) {
    it(`matches a reintroduction shaped as: ${label}`, () => {
      expect(DEFINITION_PATTERN.test(snippet)).toBe(true);
    });
  }

  it("still matches the original plain-const shape (no regression from widening)", () => {
    expect(
      DEFINITION_PATTERN.test('const RESERVED_NAMESPACE_PREFIXES = [\n  "_a",\n];')
    ).toBe(true);
  });

  it(
    "does NOT match a renamed copy - documents the known scan gap, not a claim " +
      "of coverage (a name-based regex cannot see a different identifier)",
    () => {
      expect(
        DEFINITION_PATTERN.test('const RESERVED_PREFIXES = [\n  "_a",\n];')
      ).toBe(false);
    }
  );
});

// --- Tool-layer classification parity -------------------------------------
//
// getReservedNamespaceViolation now lives beside the list it labels, in
// cognitive/state-store.ts (it moved out of cognitive/tools.ts when a second
// consumer, cognitive/unattributed-disclosure.ts, needed the same label
// lookup; a second copy would have reopened this very divergence class). It
// carries no separate list of its own, so its
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
