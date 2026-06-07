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
      /non-negative integer/
    );
  });

  it("rejects a negative value", () => {
    const counters = new InMemoryCounterStore();

    expect(() => counters.set("audit_batch_seq", -1)).toThrow(
      /non-negative integer/
    );
  });

  it("rejects NaN", () => {
    const counters = new InMemoryCounterStore();

    expect(() => counters.set("envelope_monotonic_seq", NaN)).toThrow(
      /non-negative integer/
    );
  });
});

describe("InMemoryCounterStore: unsafe-integer boundary (latent gap)", () => {
  /*
   * Characterization tests, not approval tests.
   *
   * These document a latent production gap surfaced by adversarial review:
   * the current production validator in src/mesh/lifecycle/counters.ts uses
   * Number.isInteger(value) and value < 0, so it admits unsafe integers. The
   * real fix site is that validator, tracked separately.
   */
  it("admits unsafe integers through set()", () => {
    const counters = new InMemoryCounterStore();
    const unsafeValue = Number.MAX_SAFE_INTEGER + 100;

    expect(() => counters.set("heartbeat_seq", unsafeValue)).not.toThrow();
    expect(Number.isSafeInteger(counters.peek("heartbeat_seq"))).toBe(false);
  });

  it("can collide sequence values after precision loss past 2^53", () => {
    const counters = new InMemoryCounterStore();
    const unsafeValue = Number.MAX_SAFE_INTEGER + 100;

    counters.set("audit_batch_seq", unsafeValue);

    // Above 2^53, integer spacing is wider than 1, so current + 1 can round
    // back to the same representable double instead of advancing.
    const first = counters.next("audit_batch_seq");
    const second = counters.next("audit_batch_seq");

    expect(second).toBe(first);
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
