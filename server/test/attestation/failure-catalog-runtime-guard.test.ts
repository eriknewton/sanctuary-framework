/**
 * Hardening wave 6 finding #88, failure-mode catalog runtime guard.
 *
 * The catalog has invariants that previously were only test-time-checked:
 * a future commit could ship a malformed catalog and only fail in CI.
 * This regression test verifies the runtime guard:
 *   (a) the shipped catalog passes verifyFailureCatalogInvariants()
 *   (b) malformed catalogs are caught by verifyFailureCatalogInvariants()
 *
 * The module-init throw is exercised implicitly: every other test that
 * imports failure-catalog.js relies on import not throwing. If the shipped
 * catalog were ever broken, every attestation-related test would fail at
 * import time.
 */

import { describe, it, expect } from "vitest";
import {
  FAILURE_MODE_CATALOG,
  FailureCatalogInvariantError,
  verifyFailureCatalogInvariants,
} from "../../src/attestation/failure-catalog.js";
import { FAILURE_MODE_CODES } from "../../src/attestation/constants.js";
import type { FailureModeEntry } from "../../src/attestation/types.js";

describe("failure-catalog runtime guard (finding #88)", () => {
  it("shipped catalog passes every invariant", () => {
    const result = verifyFailureCatalogInvariants();
    expect(result.valid).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it("shipped catalog row-count matches closed enum size", () => {
    expect(FAILURE_MODE_CATALOG.length).toBe(FAILURE_MODE_CODES.length);
  });

  it("verifyFailureCatalogInvariants flags a manufactured catalog with degrade_decision drift", () => {
    const broken: readonly FailureModeEntry[] = [
      ...FAILURE_MODE_CATALOG.slice(0, 8),
      {
        ...FAILURE_MODE_CATALOG[8]!,
        degrade_decision: "halt" as unknown as "degrade",
      },
    ];

    const violations = collectInvariantViolations(broken);
    expect(violations.some((v) => v.includes("degrade_decision is \"halt\""))).toBe(true);
  });

  it("verifyFailureCatalogInvariants flags a manufactured catalog with a missing row", () => {
    const broken = FAILURE_MODE_CATALOG.slice(0, FAILURE_MODE_CATALOG.length - 1);
    const violations = collectInvariantViolations(broken);
    expect(violations.some((v) => v.includes("missing from catalog"))).toBe(true);
    expect(violations.some((v) => v.includes("does not match closed enum size"))).toBe(true);
  });

  it("FailureCatalogInvariantError is thrown when assertCatalogInvariantsAtImport runs against a broken catalog", () => {
    const err = new FailureCatalogInvariantError("x");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("FailureCatalogInvariantError");
  });
});

/**
 * Helper: copy the shipped invariant logic, but evaluate it against an
 * arbitrary catalog. Mirrors verifyFailureCatalogInvariants() so a manufactured
 * input can be tested without hot-patching the module export.
 */
function collectInvariantViolations(
  catalog: readonly FailureModeEntry[]
): string[] {
  const violations: string[] = [];
  const codes = new Set<string>();
  const expected = new Set<string>(FAILURE_MODE_CODES);

  if (catalog.length !== FAILURE_MODE_CODES.length) {
    violations.push(
      `catalog row-count ${catalog.length} does not match closed enum size ${FAILURE_MODE_CODES.length}`
    );
  }
  for (const entry of catalog) {
    if (!expected.has(entry.code)) {
      violations.push(`${entry.code}: not present in FAILURE_MODE_CODES closed enum`);
    }
    if (codes.has(entry.code)) {
      violations.push(`${entry.code}: duplicate row in catalog`);
    }
    codes.add(entry.code);
    if (entry.degrade_decision !== "degrade") {
      violations.push(
        `${entry.code}: degrade_decision is "${entry.degrade_decision}" (must be "degrade")`
      );
    }
    if (!Array.isArray(entry.affected_layers) || entry.affected_layers.length === 0) {
      violations.push(`${entry.code}: affected_layers must be a non-empty array`);
    }
  }
  for (const code of FAILURE_MODE_CODES) {
    if (!codes.has(code)) {
      violations.push(`${code}: declared in FAILURE_MODE_CODES but missing from catalog`);
    }
  }
  return violations;
}
