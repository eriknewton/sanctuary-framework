/**
 * In-memory lifecycle counter unit tests.
 *
 * The lifecycle integration suite covers next()/peek() sequencing, per-name
 * independence, and strict refusal to lower an existing counter. This file
 * covers the remaining InMemoryCounterStore branches and boundary behavior:
 * untouched peek defaults, invalid set() inputs, equal-value set(), and
 * forward set() continuation through next().
 */

import { describe, it, expect } from "vitest";
import { InMemoryCounterStore } from "../../src/mesh/lifecycle/counters.js";

describe("InMemoryCounterStore: untouched counters", () => {
  it("returns 0 when peeking an untouched counter", () => {
    const counters = new InMemoryCounterStore();

    expect(counters.peek("locator_update_seq")).toBe(0);
  });
});

describe("InMemoryCounterStore: set() validation", () => {
  it("rejects a non-integer float", () => {
    const counters = new InMemoryCounterStore();

    expect(() => counters.set("heartbeat_seq", 1.5)).toThrow(
      /non-negative safe integer/
    );
  });

  it("rejects a negative value", () => {
    const counters = new InMemoryCounterStore();

    expect(() => counters.set("audit_batch_seq", -1)).toThrow(
      /non-negative safe integer/
    );
  });

  it("rejects NaN", () => {
    const counters = new InMemoryCounterStore();

    expect(() => counters.set("envelope_monotonic_seq", NaN)).toThrow(
      /non-negative safe integer/
    );
  });
});

describe("InMemoryCounterStore: unsafe-integer boundary (fail-closed)", () => {
  /*
   * Regression tests for the §8.3 rollback canary.
   *
   * The validator uses Number.isSafeInteger (not Number.isInteger), so set()
   * fails CLOSED on any integer above 2^53. Such a value would otherwise pass
   * Number.isInteger but lose precision under next()'s `current + 1`, collapsing
   * two distinct sequence values onto one representable double — a silent
   * rollback-canary defeat. set() must reject it outright; there is no value
   * stored to collide.
   */
  it("rejects unsafe integers through set()", () => {
    const counters = new InMemoryCounterStore();
    const unsafeValue = Number.MAX_SAFE_INTEGER + 100;

    expect(() => counters.set("heartbeat_seq", unsafeValue)).toThrow(
      /non-negative safe integer/
    );
    // Rejected, so the counter is untouched (still at its default 0).
    expect(counters.peek("heartbeat_seq")).toBe(0);
  });

  it("does not collide sequence values: unsafe set() is rejected before any next()", () => {
    const counters = new InMemoryCounterStore();
    const unsafeValue = Number.MAX_SAFE_INTEGER + 100;

    expect(() => counters.set("audit_batch_seq", unsafeValue)).toThrow(
      /non-negative safe integer/
    );

    // Nothing was stored, so next() advances cleanly from 0 — no precision
    // loss, no collision.
    const first = counters.next("audit_batch_seq");
    const second = counters.next("audit_batch_seq");

    expect(first).toBe(0);
    expect(second).toBe(1);
    expect(second).not.toBe(first);
  });

  it("admits the largest safe integer (boundary stays open for legit values)", () => {
    const counters = new InMemoryCounterStore();

    expect(() =>
      counters.set("heartbeat_seq", Number.MAX_SAFE_INTEGER)
    ).not.toThrow();
    expect(counters.peek("heartbeat_seq")).toBe(Number.MAX_SAFE_INTEGER);
  });

  it("next() refuses to advance past the safe-integer ceiling (no collision)", () => {
    const counters = new InMemoryCounterStore();

    // set() admits MAX_SAFE_INTEGER, but next() must not push current + 1 into
    // unsafe territory where two sequence values would collide.
    counters.set("audit_batch_seq", Number.MAX_SAFE_INTEGER);

    expect(() => counters.next("audit_batch_seq")).toThrow(
      /safe-integer ceiling/
    );
    // The counter is unchanged; the canary holds rather than silently colliding.
    expect(counters.peek("audit_batch_seq")).toBe(Number.MAX_SAFE_INTEGER);
  });
});

describe("InMemoryCounterStore: set() boundaries and continuation", () => {
  it("allows setting equal to the prior value", () => {
    const counters = new InMemoryCounterStore();

    counters.set("heartbeat_seq", 4);

    expect(() => counters.set("heartbeat_seq", 4)).not.toThrow();
    expect(counters.peek("heartbeat_seq")).toBe(4);
  });

  it("raises a counter forward and next() continues from the set value", () => {
    const counters = new InMemoryCounterStore();

    counters.next("audit_batch_seq");
    counters.set("audit_batch_seq", 7);

    expect(counters.next("audit_batch_seq")).toBe(7);
    expect(counters.peek("audit_batch_seq")).toBe(8);
  });

  it("sets a fresh counter to a positive value", () => {
    const counters = new InMemoryCounterStore();

    counters.set("locator_update_seq", 3);

    expect(counters.peek("locator_update_seq")).toBe(3);
  });

  it("sets a fresh counter to 0", () => {
    const counters = new InMemoryCounterStore();

    expect(() => counters.set("envelope_monotonic_seq", 0)).not.toThrow();
    expect(counters.peek("envelope_monotonic_seq")).toBe(0);
  });
});
