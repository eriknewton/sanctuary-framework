/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: typed read-outcome chokepoint
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * THE STRUCTURAL CHOKEPOINT that makes the false-census / overclaim state
 * UNREPRESENTABLE for a law-firm-facing signed artifact. Every data source the
 * report renders from (audit aggregation, coverage-window bound, inventory,
 * discrete exports, custody) yields a {@link ReadOutcome}, and a DEFINITIVE
 * negative claim ("none", "zero", "full quarter covered", "no denials",
 * "complete") may be emitted ONLY from a {@link Complete} witness -- a source
 * proven, at the TYPE level, to have been read to completion. A `read_failed`
 * source cannot reach {@link claimFromCompleteRead} (it is a compile error to
 * pass it), so a failed or absent read can never render as an affirmative
 * absence. This is the executable form of the recurring-honesty-bug fix: the
 * three shipped defects ("Denied by policy" for a human call, "full quarter
 * covered" for an in-progress quarter, "No MCP servers configured" on a read
 * failure) all had the same shape - absent/failed data becoming a definitive
 * claim - and this type prevents that shape from being written at all.
 */

/** A source read that returned a value (non-empty rows, a real bound, counts). */
export interface Populated<T> {
  readonly status: "populated";
  readonly value: T;
}

/**
 * A source read that SUCCEEDED and is verifiably empty (a genuine "none"). This
 * is the ONLY empty state from which a definitive negative may be asserted; it
 * is distinct from `read_failed`, where the store could not be read at all.
 */
export interface EmptyVerified {
  readonly status: "empty_verified";
}

/** A source that could NOT be read. Carries a lay-reader reason for the report. */
export interface ReadFailed {
  readonly status: "read_failed";
  readonly reason: string;
}

/**
 * A source read to completion: it either has a value or is verifiably empty. A
 * definitive negative/completeness claim may be asserted ONLY from a value of
 * this type (see {@link claimFromCompleteRead}); `ReadFailed` is deliberately
 * excluded.
 */
export type Complete<T> = Populated<T> | EmptyVerified;

/** The outcome of reading one data source the report renders from. */
export type ReadOutcome<T> = Complete<T> | ReadFailed;

/** Construct a populated outcome. */
export const populated = <T>(value: T): Populated<T> => ({
  status: "populated",
  value,
});

/** Construct a verified-empty outcome (a read that genuinely found nothing). */
export const emptyVerified = (): EmptyVerified => ({ status: "empty_verified" });

/** Construct a read-failure outcome with a lay-reader reason. */
export const readFailed = (reason: string): ReadFailed => ({
  status: "read_failed",
  reason,
});

/** True iff the source was read to completion (a value OR a verified empty). */
export function isComplete<T>(outcome: ReadOutcome<T>): outcome is Complete<T> {
  return outcome.status !== "read_failed";
}

/**
 * The ONE gate for a DEFINITIVE claim of absence or completeness ("none
 * configured", "full quarter covered", "no denials this quarter"). It REQUIRES
 * a {@link Complete} witness, so a `read_failed` outcome CANNOT reach it:
 * passing a {@link ReadOutcome} that might be `read_failed` is a COMPILE error,
 * because `ReadFailed` is not assignable to `Complete<T>`. A caller must first
 * narrow the outcome (handling the read-failed arm) before it can assert the
 * negative. This is the structural chokepoint: the false-census claim is
 * unrepresentable, not merely untested.
 *
 * The witness value is not otherwise used; its TYPE is the proof.
 */
export function claimFromCompleteRead<T>(
  _completeRead: Complete<T>,
  line: string
): string {
  return line;
}

/**
 * Exhaustive fold over a {@link ReadOutcome}: the caller MUST handle all three
 * arms, so the `read_failed` case can never be forgotten. The `populated` and
 * `emptyVerified` arms receive the outcome itself as a {@link Complete} witness
 * so a definitive claim inside them can pass {@link claimFromCompleteRead}.
 */
export function foldOutcome<T, R>(
  outcome: ReadOutcome<T>,
  arms: {
    populated: (value: T, witness: Populated<T>) => R;
    emptyVerified: (witness: EmptyVerified) => R;
    readFailed: (reason: string) => R;
  }
): R {
  switch (outcome.status) {
    case "populated":
      return arms.populated(outcome.value, outcome);
    case "empty_verified":
      return arms.emptyVerified(outcome);
    case "read_failed":
      return arms.readFailed(outcome.reason);
    default: {
      // Exhaustiveness guard: a new ReadOutcome variant fails to compile here.
      const _never: never = outcome;
      return _never;
    }
  }
}
