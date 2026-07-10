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

  it("CHOKEPOINT (compile-time): a read_failed cannot be used to assert a definitive negative", () => {
    // This @ts-expect-error IS the guarantee: passing a read_failed outcome to
    // claimFromCompleteRead must be a TYPE error (ReadFailed is not a
    // Complete<T>). If a future edit weakens Complete to admit ReadFailed, this
    // directive becomes unused and `tsc --noEmit` fails - the chokepoint holds
    // by the type checker, not by a runtime assertion.
    // @ts-expect-error read_failed is not a Complete<T> witness.
    claimFromCompleteRead(readFailed("db down"), "No servers configured.");
    expect(true).toBe(true);
  });
});
