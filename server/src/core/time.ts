/**
 * Strict timestamp parsing — the ONE predicate every timestamp entering trust
 * arithmetic is read through (TZ-WINDOW-01 established it; TZ-SIB-01/TZ-SIB-02
 * promoted it here so a single structure pin can cover every consumer).
 *
 * INVARIANT: a timestamp that participates in a trust, freshness, window, or
 * fleet-visible ordering decision carries a mandatory ISO-8601 offset; an
 * offset-less stamp is refused, never resolved against local time.
 *
 * This lives in `core/` (not in any one ceremony's module) because the defect
 * class it forecloses is a SHARED-SUBSTRATE class: a per-module copy of the
 * strict check is the hand-mirror shape AGENTS.md rule 5 forbids, and a
 * module-scoped structure pin cannot see a consumer added elsewhere. The
 * server-wide pin over this predicate lives in
 * `server/test/structure/tz-strict-offset-adoption.test.ts` (must match the
 * names exported here).
 */

/**
 * The accepted form: ISO-8601 extended date-time with a MANDATORY UTC
 * designator (`Z`) or numeric offset (`±HH:MM`).
 *
 * WHY the offset is mandatory and not cosmetic: a date-time with no offset is
 * resolved by the ECMAScript parser against the RECEIVER's local zone, so the
 * same signed bytes denote a DIFFERENT absolute instant on every node in the
 * fleet, and any window built from such stamps slides by the width of the
 * inhabited offset range. That hands the signer partial control over its own
 * trust duration, which is the exact property the freshness machinery exists
 * to remove (AGENTS.md rule 10). A relying party must read one absolute
 * instant or refuse; refusing is the fail-closed half of MUST-NEVER #5.
 *
 * Accepts:  `2026-08-16T00:00:00Z`, `2026-08-16T00:00:00.000Z`,
 *           `2026-08-16T00:00:00+05:30`, `2026-08-16T00:00:00.123456789-08:00`.
 * Rejects:  an offset-less date-time (`2026-08-16T00:00:00`, the ambiguous
 *           case), a bare year (`2026`), a date only (`2026-08-16`), a
 *           human-readable date (`Aug 16 2026`), a space date/time separator,
 *           a missing seconds field, and the BASIC-format offset `+0000`.
 *           The parse function additionally refuses an in-shape date that
 *           names no real calendar day (`2999-02-30`) and the `24:00:00`
 *           spelling -- see the calendar-validity note on the function.
 *
 * Extended-format offsets only, deliberately: every producer of these fields in
 * this tree mints them with `Date.prototype.toISOString`, which emits `Z`, so
 * accepting more spellings widens the parse surface without serving any caller
 * that exists. The non-offset rejections carry no ambiguity risk of their own;
 * they are refused because a parser that shrugs at `2026` while its failure
 * reason reads `*_not_iso` hides the real gap from the next reader.
 *
 * `\d{1,9}` fractional digits = one digit through nanosecond precision;
 * `toISOString` emits exactly 3.
 *
 * The capture groups feed the calendar-validity comparison below
 * (FG-EXPIRY-CALENDAR-01): 1=year 2=month 3=day 4=hour 5=minute 6=second
 * 7=fraction 8=offset sign 9=offset hours 10=offset minutes (8-10 absent for
 * `Z`). They change nothing about what the pattern matches.
 */
const ISO_INSTANT_WITH_OFFSET_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** 60_000 = 60 seconds per minute x 1000 milliseconds per second. */
const MS_PER_MINUTE = 60 * 1000;
/** Offset hours contribute 60 minutes each to the offset's total minutes. */
const MINUTES_PER_HOUR = 60;
/**
 * 3 = millisecond precision: the number of fractional-second digits that
 * survive `Date.parse` (V8 TRUNCATES further digits, so truncation can never
 * roll a calendar field forward).
 */
const PARSED_FRACTION_DIGITS = 3;

/**
 * Parse a timestamp field to epoch milliseconds, or `undefined` when it is not
 * a strict ISO-8601 instant carrying an offset.
 *
 * Consumers funnel through this rather than re-testing the pattern locally, so
 * a new timestamp field cannot acquire a looser rule by being written somewhere
 * else (rule 5). Known consumers: the guardian quorum-context parser and its
 * sibling bounds (TZ-WINDOW-01), the DMswitch grace-window gate (TZ-SIB-01),
 * and the post-recovery prompt ordering (TZ-SIB-02); the structure pin asserts
 * each by its argument spelling, not by count.
 *
 * The shape check does NOT subsume the range check: `2026-13-45T00:00:00Z`
 * matches the pattern and still parses to `NaN`, so the finite test stays.
 *
 * AND THE FINITE CHECK DOES NOT SUBSUME CALENDAR VALIDITY
 * (FG-EXPIRY-CALENDAR-01): `Date.parse` NORMALISES an impossible calendar date
 * that fits its grammar instead of refusing it -- `2999-02-30` parses finitely
 * to March 2, `2026-04-31` to May 1, and the `24:00:00` spelling to the next
 * day's midnight -- so a finite result can denote an instant the writer never
 * wrote. On this predicate's consumers that silently moved a grant expiry DAYS
 * past the date actually written, preserving access. So after parsing, the
 * WRITTEN calendar fields are compared against the parsed instant re-rendered
 * in the SAME offset the string carried; any mismatch means the engine
 * invented the instant, and the value is refused (`undefined`), which every
 * consumer already treats as fail-closed. The comparison MUST run in the
 * written offset, not UTC: `2026-03-01T20:00:00-08:00` is a real instant whose
 * UTC rendering falls on March 2, and rendering in UTC would refuse it --
 * the over-strict direction, which costs a legitimate grant its access.
 */
export function parseIsoInstantWithOffset(value: string): number | undefined {
  const match = ISO_INSTANT_WITH_OFFSET_RE.exec(value);
  if (match === null) return undefined;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return undefined;

  const [
    ,
    year,
    month,
    day,
    hour,
    minute,
    second,
    fraction,
    offsetSign,
    offsetHours,
    offsetMinutes,
  ] = match;
  // Total signed offset in ms; the `Z` spelling captures no offset groups and
  // means zero.
  const offsetMs =
    offsetSign === undefined
      ? 0
      : (offsetSign === "-" ? -1 : 1) *
        (Number(offsetHours) * MINUTES_PER_HOUR + Number(offsetMinutes)) *
        MS_PER_MINUTE;
  // The parsed instant re-rendered on the WRITTEN offset's wall clock: shift
  // by the offset, then read UTC fields. If the written fields named a real
  // wall-clock time, this reproduces them exactly; if the engine normalised,
  // at least one field differs.
  const wallClock = new Date(ms + offsetMs);
  // The written fraction's surviving digits, right-padded: `.5` means 500 ms.
  const writtenMs = Number(
    (fraction ?? "").padEnd(PARSED_FRACTION_DIGITS, "0").slice(0, PARSED_FRACTION_DIGITS)
  );
  const calendarFieldsMatch =
    wallClock.getUTCFullYear() === Number(year) &&
    // getUTCMonth is 0-based; the written month is 1-based
    wallClock.getUTCMonth() + 1 === Number(month) &&
    wallClock.getUTCDate() === Number(day) &&
    wallClock.getUTCHours() === Number(hour) &&
    wallClock.getUTCMinutes() === Number(minute) &&
    wallClock.getUTCSeconds() === Number(second) &&
    wallClock.getUTCMilliseconds() === writtenMs;
  return calendarFieldsMatch ? ms : undefined;
}
