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
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  categorizeEntry,
  GATE_DECISION_OP_CATEGORIES,
} from "../../src/evidence-pack/aggregate.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const GATE_TS = join(HERE, "..", "..", "src", "principal-policy", "gate.ts");

/** Extract the set of `gate_*` audit-operation prefixes emitted in gate.ts. */
function emittedGateOpPrefixes(): Set<string> {
  const src = readFileSync(GATE_TS, "utf8");
  const prefixes = new Set<string>();
  // Literal producers, e.g. `operation: `gate_allow:${...}``.
  for (const m of src.matchAll(/operation:\s*`(gate_[a-z_]+):/g)) {
    prefixes.add(m[1]!);
  }
  // The dynamic producer `operation: `gate_${response.decision}:...``, where
  // `decision` is typed `"approve" | "deny"` (gate.ts). Both expansions must be
  // categorized.
  if (/operation:\s*`gate_\$\{[^}]*decision[^}]*\}:/.test(src)) {
    prefixes.add("gate_approve");
    prefixes.add("gate_deny");
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
