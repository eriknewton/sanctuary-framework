/**
 * FG-EXPIRY-CALENDAR-01: a finite parse is not calendar validity.
 *
 * `Date.parse` NORMALISES an impossible calendar date that fits its grammar
 * instead of refusing it: February 30 rolls forward into March, day 31 of a
 * 30-day month rolls into the next month, and the `24:00:00` spelling rolls
 * into the next day's midnight. Every one of those yields a FINITE result, so
 * the shared strict predicate's finite check answered "readable" for a value
 * whose written calendar date does not exist -- and on the grant-expiry
 * surface that preserved access past the date actually written (`2999-02-30`
 * was honoured as March 2).
 *
 * The fix compares the WRITTEN calendar fields against the parsed instant
 * re-rendered in the SAME offset the string carried; a mismatch means the
 * engine invented an instant the writer never wrote, and the value is refused.
 * Refusal is the fail-closed direction on every consumer of this predicate
 * (an unreadable expiry counts as expired; an unreadable window stamp is a
 * typed refusal).
 *
 * THE OVER-STRICTNESS HAZARD is the other half of this file, and the reason
 * the must-pass corpus below is not optional: an over-strict version of this
 * check would refuse LEGITIMATE grants and remove their access, which is the
 * destructive direction. The trap is rendering the parsed instant in UTC
 * rather than in the written offset -- a stamp like `2026-03-01T20:00:00-08:00`
 * is a real instant whose UTC rendering falls on March 2, so a UTC-rendered
 * comparison would refuse it. The corpus pins that exact shape.
 */
import { describe, expect, it } from "vitest";

import { parseIsoInstantWithOffset } from "../../src/core/time.js";

describe("parseIsoInstantWithOffset calendar validity (FG-EXPIRY-CALENDAR-01)", () => {
  it("refuses the register's executed reproductions instead of honouring their normalisation", () => {
    // Each of these previously parsed to a finite instant DAYS after the date
    // actually written. The label records what the engine normalised it to.
    const reproductions: Array<[string, string]> = [
      ["2999-02-30T00:00:00.000Z", "2999-03-02"],
      ["2026-02-29T00:00:00.000Z", "2026-03-01"],
      ["2026-04-31T00:00:00.000Z", "2026-05-01"],
    ];
    for (const [written, normalisedTo] of reproductions) {
      expect(
        parseIsoInstantWithOffset(written),
        `${written} was honoured as ${normalisedTo}`
      ).toBeUndefined();
    }
  });

  it("refuses an impossible date in every offset spelling, and the hour-24 rollover", () => {
    for (const written of [
      // impossible dates carried on non-UTC offsets: the check must judge the
      // written fields, not only the Z spelling
      "2999-02-30T00:00:00+05:30",
      "2026-02-29T12:00:00-08:00",
      "2026-04-31T23:59:59.999+00:00",
      // the `24:00:00` spelling normalises to the NEXT day's midnight; the
      // shipping producer (`toISOString`) never emits it, so honouring it would
      // widen the parse surface for no caller that exists
      "2026-08-16T24:00:00Z",
      "2026-08-16T24:00:00.000-08:00",
    ]) {
      expect(parseIsoInstantWithOffset(written), written).toBeUndefined();
    }
  });

  it("must-pass corpus: every legitimate spelling still parses, to the written instant", () => {
    // Each entry: the written stamp, and its expected absolute instant spelled
    // as the canonical Z form (computed by the test's own `new Date`, which is
    // exact for canonical spellings).
    const mustPass: Array<[string, string]> = [
      // real toISOString output -- the shipping mint path's exact shape
      [new Date(1787097600000).toISOString(), "2026-08-19T00:00:00.000Z"],
      // offset-bearing ISO
      ["2026-08-19T10:00:00+05:30", "2026-08-19T04:30:00.000Z"],
      // a REAL leap day
      ["2028-02-29T00:00:00.000Z", "2028-02-29T00:00:00.000Z"],
      // end-of-month boundaries
      ["2026-01-31T00:00:00.000Z", "2026-01-31T00:00:00.000Z"],
      ["2026-04-30T00:00:00.000Z", "2026-04-30T00:00:00.000Z"],
      ["2026-12-31T23:59:59.999Z", "2026-12-31T23:59:59.999Z"],
      // written day differs from the UTC day: a UTC-rendered comparison would
      // refuse these legitimate instants, which is the over-strict failure mode
      ["2026-03-01T20:00:00-08:00", "2026-03-02T04:00:00.000Z"],
      ["2026-08-19T02:00:00+05:30", "2026-08-18T20:30:00.000Z"],
      // a real leap day written in an offset whose UTC rendering is March 1
      ["2028-02-29T20:00:00-08:00", "2028-03-01T04:00:00.000Z"],
      // sub-millisecond fractional digits: V8 truncates to milliseconds, and
      // truncation cannot roll a calendar field, so this stays readable
      ["2026-08-16T00:00:00.123456789-08:00", "2026-08-16T08:00:00.123Z"],
      // single fractional digit
      ["2026-08-16T00:00:00.5Z", "2026-08-16T00:00:00.500Z"],
    ];
    for (const [written, canonical] of mustPass) {
      expect(parseIsoInstantWithOffset(written), `refused ${written}`).toBe(
        new Date(canonical).getTime()
      );
    }
  });

  it("still refuses what it always refused: offset-less, out-of-shape, out-of-range", () => {
    for (const written of [
      "2026-08-16T00:00:00", // offset-less
      "2026-08-16", // date only
      "2026-13-45T00:00:00.000Z", // out-of-range month: NaN before and after
      "2026-08-32T00:00:00Z", // day beyond the grammar's own range: NaN
      "banana",
    ]) {
      expect(parseIsoInstantWithOffset(written), written).toBeUndefined();
    }
  });
});
