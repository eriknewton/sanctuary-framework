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
 */
const ISO_INSTANT_WITH_OFFSET_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

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
 */
export function parseIsoInstantWithOffset(value: string): number | undefined {
  if (!ISO_INSTANT_WITH_OFFSET_RE.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
}
