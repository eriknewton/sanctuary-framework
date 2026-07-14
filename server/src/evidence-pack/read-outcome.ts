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

// ── SOURCE-COMPILED DURABILITY GUARD ─────────────────────────────────
//
// The whole point of the chokepoint is that a definitive negative cannot be
// asserted from a `read_failed` outcome, because `ReadFailed` is not a
// `Complete<T>` (see {@link claimFromCompleteRead}). That invariant must be
// enforced by the REAL typecheck. `server/tsconfig.json` typechecks `src/**`
// only and EXCLUDES `test/`, and vitest does not typecheck, so a guard living
// in a test file fires nowhere. This guard therefore lives HERE, in `src`, so
// `npm run typecheck` (= `tsc --noEmit` over `src/**`, which CI runs) fails to
// compile the moment `Complete<T>` is ever widened to admit `ReadFailed`.
//
// Mechanism: if `Complete<T>` is loosened to include `ReadFailed`, the
// conditional resolves to `never`, so `_assertReadFailedExcludedFromComplete`
// can no longer be initialized with `true` and `tsc` errors (TS2322). Verified
// by injection: weakening `Complete<T>` makes `npm run typecheck` FAIL. This is
// the durable, CI-enforced tripwire.
type ReadFailedExcludedFromComplete = ReadFailed extends Complete<unknown>
  ? never
  : true;
const _assertReadFailedExcludedFromComplete: ReadFailedExcludedFromComplete = true;
// Reference it so an unused-locals rule cannot strip the guard.
void _assertReadFailedExcludedFromComplete;

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
 * passing a {@link ReadOutcome} that might be `read_failed` here is a COMPILE
 * error over `src/**` (which `npm run typecheck` compiles and CI runs), because
 * `ReadFailed` is not assignable to `Complete<T>`. A caller must first narrow
 * the outcome (handling the read-failed arm) before it can assert the negative.
 * This is the structural chokepoint: the false-census claim is unrepresentable,
 * not merely untested.
 *
 * The witness value is not otherwise used; its TYPE is the proof. The invariant
 * that keeps this gate load-bearing (`Complete<T>` never admitting `ReadFailed`)
 * is itself enforced by the source-compiled
 * `_assertReadFailedExcludedFromComplete` guard above.
 */
export function claimFromCompleteRead<T>(
  _completeRead: Complete<T>,
  line: string
): string {
  return line;
}

// ── SOURCE-COMPILED DURABILITY GUARD (parameter vector) ──────────────
//
// `_assertReadFailedExcludedFromComplete` above catches a future widening of
// `Complete<T>` itself, but NOT the other loosening vector: widening
// `claimFromCompleteRead`'s PARAMETER from `Complete<T>` to `ReadOutcome<T>`, a
// contravariant loosening that breaks no caller and so produces no compile
// error anywhere else in `src/**`. This guard closes that vector.
//
// Mechanism: `Parameters<typeof claimFromCompleteRead>[0]` is the gate's
// declared parameter type (the generic instantiates as `Complete<unknown>`).
// If the signature is ever loosened so that a `ReadFailed` becomes an
// acceptable argument, the conditional resolves to `never`, the initializer
// below can no longer be `true`, and `npm run typecheck` (= `tsc --noEmit`
// over `src/**`, which CI runs) fails (TS2322). Verified by injection:
// widening the parameter to `ReadOutcome<T>` makes `npm run typecheck` FAIL.
type ReadFailedNotAcceptedByClaimGate = ReadFailed extends Parameters<
  typeof claimFromCompleteRead
>[0]
  ? never
  : true;
const _assertReadFailedNotAcceptedByClaimGate: ReadFailedNotAcceptedByClaimGate =
  true;
// Reference it so an unused-locals rule cannot strip the guard.
void _assertReadFailedNotAcceptedByClaimGate;

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
