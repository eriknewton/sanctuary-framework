/**
 * Sanctuary MCP Server - Evidence Pack unmapped-op guard (exhaustiveness) test
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * ANTI-DRIFT GUARD (closes the slice-1 HIGH root cause). Reads the ACTUAL
 * `principal-policy/gate.ts` source, extracts every `gate_*` audit operation
 * the gate emits, and asserts each is explicitly categorized in
 * `GATE_DECISION_OP_CATEGORIES`. Adding a new `gate_*` decision op to the gate
 * without categorizing it FAILS this test, so a new op can never silently
 * vanish into `other` or a flattering allow/deny total the way `gate_approve`
 * did in slice 1. Runtime, an unmapped gate op still surfaces as
 * `uncategorized` (see categorizeEntry); this test makes the mapping's
 * completeness a hard gate at build time.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  categorizeEntry,
  GATE_DECISION_OP_CATEGORIES,
} from "../../src/evidence-pack/aggregate.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const GATE_TS = join(HERE, "..", "..", "src", "principal-policy", "gate.ts");
const PRINCIPAL_POLICY_DIR = join(HERE, "..", "..", "src", "principal-policy");

/** Recursively list every .ts file under a directory. */
function tsFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...tsFilesUnder(p));
    else if (ent.name.endsWith(".ts")) out.push(p);
  }
  return out;
}

/**
 * Extract the set of `gate_*` audit-operation prefixes emitted across the WHOLE
 * `principal-policy/` tree (L2-L3: a future `gate_*` producer added in another
 * module must not evade this build-time completeness gate), plus the dynamic
 * `gate_${decision}:` producer's union members derived from gate.ts.
 */
function emittedGateOpPrefixes(): Set<string> {
  const src = readFileSync(GATE_TS, "utf8");
  const prefixes = new Set<string>();
  // Literal producers, e.g. `operation: `gate_allow:${...}``, across the tree.
  for (const file of tsFilesUnder(PRINCIPAL_POLICY_DIR)) {
    for (const m of readFileSync(file, "utf8").matchAll(/operation:\s*`(gate_[a-z_]+):/g)) {
      prefixes.add(m[1]!);
    }
  }
  // The dynamic producer `operation: `gate_${response.decision}:...``. Rather
  // than hardcode {approve, deny}, DERIVE the decision union members from the
  // gate's own type declaration (`decision: "approve" | "deny";`), so a future
  // widening of that union is caught here (LOW-2 fix): the new value is added
  // to the expected set and the exhaustiveness assertion then fails until it is
  // categorized in GATE_DECISION_OP_CATEGORIES.
  if (/operation:\s*`gate_\$\{[^}]*decision[^}]*\}:/.test(src)) {
    const members = new Set<string>();
    for (const decl of src.matchAll(/\bdecision:\s*("[a-z_]+"(?:\s*\|\s*"[a-z_]+")*)\s*;/g)) {
      for (const lit of decl[1]!.matchAll(/"([a-z_]+)"/g)) {
        members.add(lit[1]!);
      }
    }
    if (members.size === 0) {
      throw new Error(
        "op-exhaustiveness: found the dynamic `gate_${...decision...}:` producer " +
          "but could not parse the `decision:` union members from gate.ts; " +
          "update this test's parser."
      );
    }
    for (const member of members) prefixes.add(`gate_${member}`);
  }
  return prefixes;
}

describe("unmapped-op guard: gate decision-op mapping is exhaustive", () => {
  it("extracts a non-trivial set of gate ops from gate.ts (vacuous-green guard)", () => {
    const emitted = emittedGateOpPrefixes();
    expect(emitted.size).toBeGreaterThanOrEqual(6);
  });

  it("every gate_* op the gate emits is explicitly categorized (no silent 'other'/flattering fold)", () => {
    const emitted = emittedGateOpPrefixes();
    const unmapped = [...emitted].filter(
      (p) => GATE_DECISION_OP_CATEGORIES[p] === undefined
    );
    expect(
      unmapped,
      `gate.ts emits these gate_* audit ops that are NOT in GATE_DECISION_OP_CATEGORIES: ${unmapped.join(
        ", "
      )}. Add each to the map (with the correct human/automated category) so it is not miscounted or surfaced as 'uncategorized'.`
    ).toEqual([]);
    // And each mapped op categorizes to a concrete decision (never uncategorized/other).
    for (const prefix of emitted) {
      const category = categorizeEntry({
        timestamp: "2026-08-01T00:00:00.000Z",
        layer: "l2",
        operation: `${prefix}:some_tool`,
        identity_id: "a",
        result: "success",
      });
      expect(["uncategorized", "other"]).not.toContain(category);
    }
  });

  it("every mapped category is a real allow/deny/human/automated bucket", () => {
    const allowed = new Set([
      "allowed",
      "allowed_proxy",
      "human_approved",
      "human_denied",
      "denied",
      "injection_blocked",
      "unclassified",
    ]);
    for (const category of Object.values(GATE_DECISION_OP_CATEGORIES)) {
      expect(allowed.has(category)).toBe(true);
    }
  });
});
