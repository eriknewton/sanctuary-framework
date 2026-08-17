/**
 * TZ-SIB-01 / TZ-SIB-02 — the strict-offset timestamp rule at the two
 * consumers outside the guardian quorum module.
 *
 * Capability under test: the DMswitch grace-window gate (TZ-SIB-01) and the
 * post-recovery prompt ordering (TZ-SIB-02) read their timestamps through the
 * shared strict predicate `parseIsoInstantWithOffset` (`core/time.ts`), so a
 * timestamp means ONE absolute instant on every node that evaluates it.
 *
 * WHY two-timezone cases: a date-time with no offset is resolved by the
 * ECMAScript parser against the READER's local zone, so any window or ordering
 * built from such a stamp differs per node across the inhabited offset range.
 * The DMswitch window gates the guardian-revocation path, so its verdict must
 * be fleet-uniform; the prompt ordering must name the same "latest" rotation
 * everywhere. The assertions pin that the verdicts AGREE across the extreme
 * zones, and that they agree on refusal for the ambiguous form (fail-closed,
 * MUST-NEVER #5 — a refused stamp throws, never degrades to a local reading).
 *
 * Mutation probe (captured in the PR record): revert the DMswitch site to a
 * bare `Date.parse` finiteness test and the two-timezone agreement case below
 * fails, because the offset-less stamp then evaluates to a different absolute
 * window per zone and the verdicts diverge.
 *
 * The `Etc/GMT+12` name is POSIX-signed and means UTC-12; `Pacific/Kiritimati`
 * is UTC+14. Together they span the inhabited offset range.
 */

import { describe, it, expect } from "vitest";

import { parseIsoInstantWithOffset } from "../../src/core/time.js";
import {
  evaluateDMswitchGraceWindow,
  enforceDMswitchGraceWindow,
  DMswitchGraceWindowActive,
} from "../../src/mesh/recovery-flows/index.js";
import {
  PostRecoveryPromptStore,
  type PostRecoveryPromptState,
} from "../../src/mesh/guardian/index.js";

/** 3_600_000 = 60 min * 60 s * 1000 ms. */
const HOUR_MS = 60 * 60 * 1000;

const TZ_UTC = "UTC";
/** POSIX sign inversion: `Etc/GMT+12` is UTC-12, the western extreme. */
const TZ_WEST = "Etc/GMT+12";
/** UTC+14, the eastern extreme. */
const TZ_EAST = "Pacific/Kiritimati";

/**
 * Run `fn` with `process.env.TZ` set, restoring the previous value even on
 * throw. Node re-reads the cached zone when `process.env.TZ` is assigned; the
 * FIRST case in this file asserts that mechanism is live rather than assuming
 * it, so an environment where the assignment is inert fails loudly there
 * instead of turning every later two-timezone assertion into a tautology.
 *
 * Vitest's default pool isolates each test FILE in its own process, so this
 * mutation cannot leak into a concurrently running file. If the pool is ever
 * switched to shared threads, this helper is the thing that has to change.
 */
function withTz<T>(tz: string, fn: () => T): T {
  const previous = process.env.TZ;
  process.env.TZ = tz;
  try {
    return fn();
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
}

/** An ISO-shaped date-time carrying NO offset — the ambiguous form. */
const OFFSETLESS_ACTIVITY = "2026-08-16T00:00:00.000";

describe("TZ-SIB timestamp offset (DMswitch gate + prompt ordering)", () => {
  it("the two-timezone mechanism is live: an offset-less stamp really does move, a Z stamp does not", () => {
    const westMs = withTz(TZ_WEST, () => Date.parse(OFFSETLESS_ACTIVITY));
    const eastMs = withTz(TZ_EAST, () => Date.parse(OFFSETLESS_ACTIVITY));
    const utcMs = withTz(TZ_UTC, () => Date.parse(OFFSETLESS_ACTIVITY));
    // 26 h = the span from UTC-12 to UTC+14. If this is 0 the TZ assignment is
    // inert in this runtime and every agreement case below proves nothing.
    expect(westMs - eastMs).toBe(26 * HOUR_MS);
    expect(westMs - utcMs).toBe(12 * HOUR_MS);

    // The same wall-clock reading with a `Z` is one instant in every zone.
    const withZ = `${OFFSETLESS_ACTIVITY}Z`;
    expect(withTz(TZ_WEST, () => Date.parse(withZ))).toBe(
      withTz(TZ_EAST, () => Date.parse(withZ))
    );
  });

  describe("TZ-SIB-01 — DMswitch grace window", () => {
    /**
     * A verdict string rather than a boolean, so an "agree" assertion cannot
     * be satisfied by two different outcomes that merely both throw or both
     * pass. Windows chosen so that a LENIENT (zone-relative) reading of the
     * offset-less stamp would diverge three ways at the same evaluation
     * instant: absence 1 h + grace 1 h on a 00:00 stamp makes the window end
     * 02:00 in the stamp's resolved zone, and the evaluation instant 01:30Z is
     * inside the UTC reading (blocked until 02:00Z), inside the UTC-12 reading
     * with a DIFFERENT bound (blocked until 14:00Z), and past the UTC+14
     * reading entirely (clear).
     */
    const ABSENCE_MS = HOUR_MS;
    const GRACE_MS = HOUR_MS;
    const EVALUATION_MS = Date.parse("2026-08-16T01:30:00.000Z");

    function verdict(lastActivity: string): string {
      try {
        const r = evaluateDMswitchGraceWindow({
          last_operator_activity_at: lastActivity,
          now_ms: EVALUATION_MS,
          absence_ms: ABSENCE_MS,
          grace_ms: GRACE_MS,
        });
        return r.blocked ? `blocked-until:${r.available_at}` : "clear";
      } catch {
        return "refused";
      }
    }

    it("an offset-less activity stamp draws the SAME refusal in every zone", () => {
      const verdicts = [TZ_UTC, TZ_WEST, TZ_EAST].map((tz) =>
        withTz(tz, () => verdict(OFFSETLESS_ACTIVITY))
      );
      // Agreement is the property: one stamp, one verdict, fleet-wide — and
      // the agreed verdict is refusal, not an accident of the window state.
      expect(verdicts).toEqual(["refused", "refused", "refused"]);
    });

    it("a Z stamp draws the SAME substantive verdict in every zone (the check refuses ambiguity, not the fleet)", () => {
      // Inside the window: the same wall-clock reading as the ambiguous form,
      // now anchored — blocked everywhere, with the same available_at.
      const anchored = `${OFFSETLESS_ACTIVITY}Z`;
      const verdicts = [TZ_UTC, TZ_WEST, TZ_EAST].map((tz) =>
        withTz(tz, () => verdict(anchored))
      );
      expect(new Set(verdicts).size).toBe(1);
      expect(verdicts[0]).toBe("blocked-until:2026-08-16T02:00:00.000Z");

      // Outside the window: clear everywhere.
      const longAgo = "2026-08-15T00:00:00.000Z";
      for (const tz of [TZ_UTC, TZ_WEST, TZ_EAST]) {
        expect(withTz(tz, () => verdict(longAgo)), `zone ${tz}`).toBe("clear");
      }
    });

    it("a numeric-offset stamp is accepted and means the same instant as its Z spelling", () => {
      // 2026-08-16T05:30:00+05:30 IS 2026-08-16T00:00:00Z.
      expect(verdict("2026-08-16T05:30:00.000+05:30")).toBe(
        verdict("2026-08-16T00:00:00.000Z")
      );
    });

    it("refuses every loose form with a throw (fail-closed preserved)", () => {
      for (const loose of [
        "2026",
        "Aug 16 2026",
        "",
        "2026-08-16",
        "2026-08-16T00:00:00",
        "2026-08-16 00:00:00Z",
        "2026-08-16T00:00:00+0000",
        "2026-08-16T00:00Z",
        "2026-13-45T00:00:00.000Z",
      ]) {
        expect(
          () =>
            evaluateDMswitchGraceWindow({
              last_operator_activity_at: loose,
              now_ms: EVALUATION_MS,
            }),
          `accepted: ${loose}`
        ).toThrow(/strict ISO-8601/);
      }
    });

    it("enforceDMswitchGraceWindow keeps both behaviors: typed block, refusal throw", () => {
      expect(() =>
        enforceDMswitchGraceWindow({
          last_operator_activity_at: `${OFFSETLESS_ACTIVITY}Z`,
          now_ms: EVALUATION_MS,
          absence_ms: ABSENCE_MS,
          grace_ms: GRACE_MS,
        })
      ).toThrow(DMswitchGraceWindowActive);
      expect(() =>
        enforceDMswitchGraceWindow({
          last_operator_activity_at: OFFSETLESS_ACTIVITY,
          now_ms: EVALUATION_MS,
        })
      ).toThrow(/strict ISO-8601/);
    });

    it("the already-fired bypass is unaffected (no stamp is read at all)", () => {
      const r = evaluateDMswitchGraceWindow({
        last_operator_activity_at: OFFSETLESS_ACTIVITY,
        now_ms: EVALUATION_MS,
        dmswitch_already_fired: true,
      });
      expect(r.blocked).toBe(false);
    });
  });

  describe("TZ-SIB-02 — post-recovery prompt ordering", () => {
    function state(rotated_at: string): PostRecoveryPromptState {
      return {
        rotated_at,
        old_master_pubkey: "old",
        new_master_pubkey: "new",
        credentials: [],
        rotated: {},
      };
    }

    it("latest() names the SAME rotation in every zone when one stamp is offset-less", () => {
      // Chosen so a LENIENT reading diverges: on a UTC-12 node the offset-less
      // 23:00 reads as 2026-08-17T11:00Z (wins), on a UTC+14 node it reads as
      // 2026-08-15T09:00Z (loses). The strict ordering refuses the ambiguous
      // stamp instead, so the anchored rotation wins everywhere.
      const anchored = "2026-08-16T00:30:00.000Z";
      const ambiguous = "2026-08-16T23:00:00.000";
      const winners = [TZ_UTC, TZ_WEST, TZ_EAST].map((tz) =>
        withTz(tz, () => {
          const store = new PostRecoveryPromptStore();
          store.put(state(anchored));
          store.put(state(ambiguous));
          return store.latest()?.rotated_at;
        })
      );
      expect(winners).toEqual([anchored, anchored, anchored]);
    });

    it("orders mixed-offset stamps by ABSOLUTE instant, identically in every zone", () => {
      // 20:00+11:00 is 09:00Z; the 10:00Z stamp is the later instant even
      // though its wall-clock digits are smaller.
      const earlierInstant = "2026-08-16T20:00:00.000+11:00";
      const laterInstant = "2026-08-16T10:00:00.000Z";
      expect(parseIsoInstantWithOffset(laterInstant)!).toBeGreaterThan(
        parseIsoInstantWithOffset(earlierInstant)!
      );
      for (const tz of [TZ_UTC, TZ_WEST, TZ_EAST]) {
        const winner = withTz(tz, () => {
          const store = new PostRecoveryPromptStore();
          store.put(state(earlierInstant));
          store.put(state(laterInstant));
          return store.latest()?.rotated_at;
        });
        expect(winner, `zone ${tz}`).toBe(laterInstant);
      }
    });

    it("a store holding ONLY a refused stamp still returns it (ordering refuses ambiguity, not data)", () => {
      // The refused stamp sorts earliest; it is never silently dropped. With a
      // single entry there is nothing to misorder, so it is still returned.
      const store = new PostRecoveryPromptStore();
      store.put(state("2026-08-16T23:00:00.000"));
      expect(store.latest()?.rotated_at).toBe("2026-08-16T23:00:00.000");
    });
  });
});
