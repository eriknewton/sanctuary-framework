/**
 * Sanctuary MCP Server - Evidence Pack read-outcome chokepoint tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests the shared typed read-outcome primitives. The strongest guarantee (a
 * definitive negative cannot be emitted from a read_failed outcome) is enforced
 * by the TYPE system (`claimFromCompleteRead` requires a `Complete<T>`); these
 * runtime tests lock the constructors, the exhaustive fold, and the narrowing
 * helper that back it.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  populated,
  emptyVerified,
  readFailed,
  isComplete,
  claimFromCompleteRead,
  foldOutcome,
  type ReadOutcome,
} from "../../src/evidence-pack/read-outcome.js";

describe("read-outcome primitives", () => {
  it("constructors produce the right discriminants", () => {
    expect(populated(7)).toEqual({ status: "populated", value: 7 });
    expect(emptyVerified()).toEqual({ status: "empty_verified" });
    expect(readFailed("boom")).toEqual({ status: "read_failed", reason: "boom" });
  });

  it("isComplete is true for populated + empty_verified, false for read_failed", () => {
    expect(isComplete(populated(1))).toBe(true);
    expect(isComplete(emptyVerified())).toBe(true);
    expect(isComplete(readFailed("x"))).toBe(false);
  });

  it("foldOutcome dispatches each arm and hands a Complete witness to the non-failed arms", () => {
    const label = (o: ReadOutcome<number[]>): string =>
      foldOutcome(o, {
        populated: (v, witness) => {
          // The witness typechecks as a definitive-claim proof.
          claimFromCompleteRead(witness, "ok");
          return `populated:${v.length}`;
        },
        emptyVerified: (witness) => claimFromCompleteRead(witness, "none"),
        readFailed: (reason) => `failed:${reason}`,
      });
    expect(label(populated([1, 2]))).toBe("populated:2");
    expect(label(emptyVerified())).toBe("none");
    expect(label(readFailed("db down"))).toBe("failed:db down");
  });

  it("claimFromCompleteRead returns exactly the definitive line it is given", () => {
    // The proof value is unused at runtime; its TYPE is the compile-time gate.
    expect(claimFromCompleteRead(emptyVerified(), "No servers configured.")).toBe(
      "No servers configured."
    );
  });

  it("CHOKEPOINT: a read_failed cannot be used to assert a definitive negative", () => {
    // SECONDARY documentation of the guarantee. NOTE: this @ts-expect-error is
    // NOT the durable tripwire - `server/tsconfig.json` EXCLUDES `test/` from
    // typechecking and vitest does not typecheck, so `npm run typecheck` never
    // compiles this file. The REAL, CI-enforced guard lives in `src` at
    // `read-outcome.ts` (`_assertReadFailedExcludedFromComplete`), which
    // `tsc --noEmit` over `src/**` DOES compile and which fails to compile if
    // `Complete<T>` is ever widened to admit `ReadFailed`. This directive is
    // kept as readable documentation of the intent; if a test-scoped typecheck
    // is later wired in, it also becomes a live second tripwire.
    // @ts-expect-error read_failed is not a Complete<T> witness.
    claimFromCompleteRead(readFailed("db down"), "No servers configured.");
    expect(true).toBe(true);
  });

  it("HIGH-1: the DURABLE src-compiled guard exists in read-outcome.ts (the CI-enforced tripwire)", () => {
    // The real durability guarantee lives in `src` so `npm run typecheck`
    // (which excludes `test/`) compiles it. This test ensures the guard cannot
    // be silently deleted: if it goes, this fails, pointing back to the src file
    // that must fail to compile when Complete<T> is widened to admit ReadFailed.
    const here = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(
      join(here, "..", "..", "src", "evidence-pack", "read-outcome.ts"),
      "utf8"
    );
    expect(src).toContain("_assertReadFailedExcludedFromComplete");
    expect(src).toContain("ReadFailed extends Complete<unknown>");
  });
});
