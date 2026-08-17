/**
 * TZ-WINDOW-01 — every timestamp a guardian quorum context carries must denote
 * ONE absolute instant, identically on every node that reads it.
 *
 * The shared guardian quorum-context parser and its two sibling bounds
 * (`assertRotatedAtWithinContext`, the sync-anchored `effective_at` branch of
 * `assertQuorumContextFresh`) validate timestamps with
 * `parseIsoInstantWithOffset`, which demands an ISO-8601 date-time carrying a
 * `Z` designator or a `±HH:MM` offset.
 *
 * WHY that matters enough to test across two timezones: a date-time with no
 * offset is resolved by the ECMAScript parser against the READER's local zone.
 * A window built from two such stamps therefore denotes a different absolute
 * interval on every node, sliding across the inhabited offset range, so a
 * signed quorum could be inside its window on one node and outside it on
 * another at the same instant. That is the signer partially selecting its own
 * trust duration, which is the exact property this freshness machinery exists
 * to remove (AGENTS.md rule 10). The assertions below pin that the two verdicts
 * AGREE, and that they agree on refusal.
 *
 * Mutation probe: delete the `ISO_INSTANT_WITH_OFFSET_RE` test inside
 * `parseIsoInstantWithOffset` (leaving the finite check) and the two-timezone
 * case fails, because the offset-less window then evaluates to a different
 * absolute interval per zone and the verdicts diverge.
 *
 * The `Etc/GMT+12` name is POSIX-signed and means UTC-12; `Pacific/Kiritimati`
 * is UTC+14. Together they span the inhabited offset range.
 */

import { describe, it, expect } from "vitest";

import {
  GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
  GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
  assertQuorumContextFresh,
  assertRotatedAtWithinContext,
  mintRevokeCollectionContext,
  parseGuardianRevokeQuorumContext,
  parseIsoInstantWithOffset,
  parseMasterRotationQuorumContext,
  QuorumFreshnessError,
  type ParsedQuorumContext,
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
 * first case in this file asserts that mechanism is live rather than assuming
 * it, so an environment where the assignment is inert fails loudly here instead
 * of turning every later assertion into a tautology.
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
const OFFSETLESS_INITIATED = "2026-08-16T00:00:00.000";
const OFFSETLESS_EXPIRES = "2026-08-16T04:00:00.000";
const CEREMONY_ID = "a".repeat(32);

/**
 * A fixed absolute instant to evaluate against. Chosen so that a LENIENT parse
 * would disagree across the two zones: read as UTC the offset-less window closes
 * at 04:00Z (this instant is past it), read as UTC-12 it spans 12:00Z..16:00Z
 * (this instant is inside it).
 */
const EVALUATION_INSTANT = new Date("2026-08-16T13:00:00.000Z");

type Verdict = string;

/**
 * The full relying-side verdict for a wire context: parse, then freshness. A
 * string rather than a boolean so an "agree" assertion cannot be satisfied by
 * two refusals for unrelated reasons.
 */
function evaluateVerdict(wire: unknown, now: Date): Verdict {
  const parsed = parseGuardianRevokeQuorumContext(wire);
  if (!parsed.ok) return `refused:parse:${parsed.reason}`;
  try {
    assertQuorumContextFresh(parsed.context, { mode: "strict", now });
    return "accepted";
  } catch (err) {
    return `refused:freshness:${(err as Error).name}`;
  }
}

function offsetLessWire(): Record<string, unknown> {
  return {
    input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
    ceremony_id: CEREMONY_ID,
    initiated_at: OFFSETLESS_INITIATED,
    expires_at: OFFSETLESS_EXPIRES,
  };
}

describe("TZ-WINDOW-01 timestamp offset", () => {
  it("the two-timezone mechanism is live: an offset-less stamp really does move, a Z stamp does not", () => {
    const westMs = withTz(TZ_WEST, () => Date.parse(OFFSETLESS_INITIATED));
    const eastMs = withTz(TZ_EAST, () => Date.parse(OFFSETLESS_INITIATED));
    const utcMs = withTz(TZ_UTC, () => Date.parse(OFFSETLESS_INITIATED));
    // 26 h = the span from UTC-12 to UTC+14. If this is 0 the TZ assignment is
    // inert in this runtime and the verdict case below proves nothing.
    expect(westMs - eastMs).toBe(26 * HOUR_MS);
    expect(westMs - utcMs).toBe(12 * HOUR_MS);

    // The same wall-clock reading with a `Z` is one instant in every zone.
    const withZ = `${OFFSETLESS_INITIATED}Z`;
    expect(withTz(TZ_WEST, () => Date.parse(withZ))).toBe(
      withTz(TZ_EAST, () => Date.parse(withZ))
    );
  });

  it("an offset-less window draws the SAME refusal on a UTC node and a UTC-12 node", () => {
    const utcVerdict = withTz(TZ_UTC, () =>
      evaluateVerdict(offsetLessWire(), EVALUATION_INSTANT)
    );
    const westVerdict = withTz(TZ_WEST, () =>
      evaluateVerdict(offsetLessWire(), EVALUATION_INSTANT)
    );
    const eastVerdict = withTz(TZ_EAST, () =>
      evaluateVerdict(offsetLessWire(), EVALUATION_INSTANT)
    );

    // Agreement is the property: one signed context, one verdict, fleet-wide.
    expect(utcVerdict).toBe(westVerdict);
    expect(utcVerdict).toBe(eastVerdict);
    // And the agreed verdict is refusal at the PARSE stage, not an accident of
    // the window happening to be closed everywhere.
    expect(utcVerdict).toBe("refused:parse:initiated_at_not_iso");
  });

  it("an offset-BEARING window draws the same verdict in every zone (the check refuses ambiguity, not the fleet)", () => {
    const context = mintRevokeCollectionContext({ now: EVALUATION_INSTANT });
    const wire = {
      input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
      ceremony_id: context.ceremony_id,
      initiated_at: context.initiated_at,
      expires_at: context.expires_at,
    };
    for (const tz of [TZ_UTC, TZ_WEST, TZ_EAST]) {
      expect(
        withTz(tz, () => evaluateVerdict(wire, EVALUATION_INSTANT)),
        `zone ${tz}`
      ).toBe("accepted");
    }
  });

  it("refuses every loose timestamp form, with the malformed reason and not the expired one", () => {
    const good = {
      input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
      ceremony_id: CEREMONY_ID,
      initiated_at: "2026-08-16T00:00:00.000Z",
      expires_at: "2026-08-16T04:00:00.000Z",
    };
    expect(parseGuardianRevokeQuorumContext(good).ok).toBe(true);

    const looseForms: Array<[unknown, string]> = [
      ["2026", "a bare year"],
      ["Aug 16 2026", "a human-readable date"],
      ["", "an empty string"],
      [42, "a non-string"],
      [null, "null"],
      ["2026-08-16", "a date with no time"],
      ["2026-08-16T00:00:00.000", "an offset-less date-time"],
      ["2026-08-16T00:00:00", "an offset-less date-time without fraction"],
      ["2026-08-16 00:00:00Z", "a space date/time separator"],
      ["2026-08-16T00:00:00+0000", "a basic-format offset"],
      ["2026-08-16T00:00Z", "a missing seconds field"],
      ["2026-13-45T00:00:00.000Z", "an in-shape but out-of-range date"],
    ];

    for (const [value, label] of looseForms) {
      const onInitiated = parseGuardianRevokeQuorumContext({
        ...good,
        initiated_at: value,
      });
      expect(onInitiated.ok, `initiated_at accepted ${label}`).toBe(false);
      if (!onInitiated.ok) expect(onInitiated.reason).toBe("initiated_at_not_iso");

      const onExpires = parseGuardianRevokeQuorumContext({
        ...good,
        expires_at: value,
      });
      expect(onExpires.ok, `expires_at accepted ${label}`).toBe(false);
      if (!onExpires.ok) expect(onExpires.reason).toBe("expires_at_not_iso");
    }
  });

  it("the master-rotation entry point shares the parser, so it refuses the same forms", () => {
    const wire = {
      input_schema: GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
      ceremony_id: CEREMONY_ID,
      initiated_at: OFFSETLESS_INITIATED,
      expires_at: OFFSETLESS_EXPIRES,
    };
    const parsed = parseMasterRotationQuorumContext(wire);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.reason).toBe("initiated_at_not_iso");
  });

  it("the rotated_at bound refuses an offset-less stamp and accepts an offset-bearing one", () => {
    const context = mintRevokeCollectionContext({ now: EVALUATION_INSTANT });
    const parsed = parseMasterRotationQuorumContext({
      input_schema: GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
      ceremony_id: context.ceremony_id,
      initiated_at: context.initiated_at,
      expires_at: context.expires_at,
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const parsedContext: ParsedQuorumContext = parsed.context;

    // The offset-less rendering of an instant that IS inside the window: only
    // its ambiguity is disqualifying, which is why the same instant with a `Z`
    // is accepted immediately below.
    //
    // Pinned to TZ=UTC deliberately: under UTC the offset-less string and the
    // `Z` string denote the SAME number, so the strict predicate is the only
    // thing that can separate them. Left on the ambient zone this case would
    // pass on a machine whose offset happens to push the stamp out of the
    // window, which is a test that goes green for the wrong reason.
    withTz(TZ_UTC, () => {
      const insideWindow = new Date(parsedContext.initiated_at_ms + HOUR_MS);
      const offsetLessInside = insideWindow.toISOString().replace("Z", "");
      expect(Date.parse(offsetLessInside)).toBe(insideWindow.getTime());
      expect(() =>
        assertRotatedAtWithinContext({
          context: parsedContext,
          rotated_at: offsetLessInside,
        })
      ).toThrow(QuorumFreshnessError);
      expect(() =>
        assertRotatedAtWithinContext({
          context: parsedContext,
          rotated_at: insideWindow.toISOString(),
        })
      ).not.toThrow();
    });
  });

  it("the sync-anchored effective_at refuses an offset-less stamp and accepts an offset-bearing one", () => {
    const context = mintRevokeCollectionContext({ now: EVALUATION_INSTANT });
    const parsed = parseGuardianRevokeQuorumContext({
      input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
      ceremony_id: context.ceremony_id,
      initiated_at: context.initiated_at,
      expires_at: context.expires_at,
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    // TZ=UTC for the same reason as the rotated_at case: it makes the two
    // spellings numerically identical, so only the strictness check can refuse
    // one and admit the other.
    withTz(TZ_UTC, () => {
      const insideWindow = new Date(parsed.context.initiated_at_ms + HOUR_MS);
      const offsetLessInside = insideWindow.toISOString().replace("Z", "");
      expect(Date.parse(offsetLessInside)).toBe(insideWindow.getTime());
      expect(() =>
        assertQuorumContextFresh(parsed.context, {
          mode: "sync_anchored",
          now: EVALUATION_INSTANT,
          effective_at: offsetLessInside,
        })
      ).toThrow(QuorumFreshnessError);
      expect(() =>
        assertQuorumContextFresh(parsed.context, {
          mode: "sync_anchored",
          now: EVALUATION_INSTANT,
          effective_at: insideWindow.toISOString(),
        })
      ).not.toThrow();
    });
  });

  it("every context this tree mints satisfies the predicate (producer-side audit, executable)", () => {
    // The generating side uses `toISOString`, which always emits `Z`; this is
    // the assertion that keeps the tightening non-breaking for our own minters
    // rather than a claim in a review comment.
    for (let i = 0; i < 32; i++) {
      const context = mintRevokeCollectionContext();
      expect(parseIsoInstantWithOffset(context.initiated_at)).toBeTypeOf(
        "number"
      );
      expect(parseIsoInstantWithOffset(context.expires_at)).toBeTypeOf("number");
    }
  });
});
