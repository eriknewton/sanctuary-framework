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

/**
 * D10-DISC-1 (dry-bar round 10): a read-failure reason that has passed through
 * {@link sanitizeReason}. The brand exists so the SANITIZATION cannot be
 * bypassed: a plain `string` is NOT assignable to this type, so
 * `{ status: "read_failed", reason: someRawErrorMessage }` is a COMPILE error
 * and the ONLY way to build a {@link ReadFailed} is {@link readFailed}, which
 * sanitizes. Every read-failure reason reaches the firm-facing report and (on
 * the audit leg) the SIGNED manifest `coverage.reason`, so an unsanitized
 * reason is an over-disclosure defect in a document sent outside the firm.
 */
export type SanitizedReason = string & {
  readonly __brand: "SanitizedReason";
};

/** A source that could NOT be read. Carries a lay-reader reason for the report. */
export interface ReadFailed {
  readonly status: "read_failed";
  /**
   * Always SANITIZED (see {@link SanitizedReason}): no absolute path, home
   * directory, uid/gid, or raw syscall text can be carried here, because the
   * brand makes a raw `string` unassignable.
   */
  readonly reason: SanitizedReason;
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

// ── SOURCE-COMPILED DURABILITY GUARD (reason-sanitization vector) ────
//
// The disclosure chokepoint holds only while `ReadFailed.reason` stays BRANDED.
// If it is ever widened back to a plain `string`, every existing call site keeps
// compiling (a branded string IS a string), so the loosening would produce no
// error anywhere else and the raw-path leak would silently return. This guard
// lives in `src` (which `npm run typecheck` compiles and CI runs) for the same
// reason as the two above: `test/` is excluded from tsc, so a guard in a test
// file fires nowhere.
//
// Mechanism: a plain `string` must NOT be assignable to the reason field. If it
// becomes assignable, the conditional resolves to `never`, the initializer can
// no longer be `true`, and `tsc` errors (TS2322).
type ReasonFieldStaysBranded = string extends ReadFailed["reason"] ? never : true;
const _assertReasonFieldStaysBranded: ReasonFieldStaysBranded = true;
// Reference it so an unused-locals rule cannot strip the guard.
void _assertReasonFieldStaysBranded;

/** Construct a populated outcome. */
export const populated = <T>(value: T): Populated<T> => ({
  status: "populated",
  value,
});

/** Construct a verified-empty outcome (a read that genuinely found nothing). */
export const emptyVerified = (): EmptyVerified => ({ status: "empty_verified" });

// ── D10-DISC-1: THE READ-FAILURE DISCLOSURE CHOKEPOINT ───────────────
//
// Read-failure reasons are FREE TEXT, and free text is the one thing the #962
// manifest-coverage chokepoint cannot validate by construction: it checks every
// enum-shaped and numeric field, then copies `reason` through untouched. Round
// 10 rendered an absolute fortress path (revealing the operator's username and
// home-directory layout) into the SIGNED, firm-facing Markdown report through
// exactly that gap.
//
// The defence is two layers, both structural:
//
//  1. AT THE CAUSE (the real fix, an ALLOWLIST): `describeReadFailureCause`
//     never reads an error's free-text `message`. It maps the error to a COARSE
//     category drawn from a CLOSED set. Nothing host-specific can be selected
//     because nothing host-specific is ever consulted.
//  2. AT THE CONSTRUCTOR (defence in depth, a DENYLIST): `readFailed` routes
//     every reason through `sanitizeReason`, which scrubs path-shaped and
//     identity-shaped tokens. This catches any FUTURE call site that
//     interpolates raw text without going through layer 1.
//
// The `SanitizedReason` brand is what makes layer 2 unbypassable: `ReadFailed`
// cannot be built as an object literal, so `readFailed` is the only door.

/** Replacement token for a redacted host path. */
const REDACTED_PATH = "<path withheld>";

/**
 * Scrub host-identifying tokens out of a reason before it can reach a
 * firm-facing artifact. Defence in depth behind
 * {@link describeReadFailureCause}: absolute POSIX paths, Windows paths, home
 * (`~`) paths, and uid/gid pairs are replaced. Path matching requires TWO or
 * more segments so ordinary prose (`read/write`, `and/or`) is never mangled.
 */
export function sanitizeReason(raw: string): SanitizedReason {
  const scrubbed = raw
    // Home-relative paths first: `~/a/b` would otherwise leave a stray `~`.
    .replace(/~(?:\/[^\s/\\:"']+)+\/?/g, REDACTED_PATH)
    // Windows paths, e.g. `C:\Users\someone\file`.
    .replace(/[A-Za-z]:\\[^\s"']*/g, REDACTED_PATH)
    // Absolute POSIX paths with 2+ segments, not preceded by a word character
    // (so `read/write` and `and/or` are untouched).
    .replace(/(?<![A-Za-z0-9])(?:\/[^\s/\\:"']+){2,}\/?/g, REDACTED_PATH)
    // Numeric account identifiers.
    .replace(/\b(uid|gid)=\d+/gi, "$1=<withheld>")
    .replace(/\s{2,}/g, " ")
    .trim();
  return scrubbed as SanitizedReason;
}

/**
 * The CLOSED set of read-failure categories the artifact may disclose. Keyed by
 * `NodeJS.ErrnoException.code`. A cause outside this set collapses to the
 * generic category, so no host-specific text can ever be selected.
 */
const READ_FAILURE_CATEGORIES: Readonly<Record<string, string>> = {
  ENOENT: "the expected file or directory was not present",
  EACCES: "this process was not permitted to read it",
  EPERM: "the operation was not permitted at this privilege level",
  EISDIR: "a directory was found where a file was expected",
  ENOTDIR: "a path component was not a directory",
  ELOOP: "the path resolved through too many symbolic links",
  EMFILE: "too many files were already open",
  ENFILE: "too many files were already open on this machine",
  ENOSPC: "the storage volume was out of space",
  EROFS: "the storage volume was read-only",
  EBUSY: "the store was busy or locked by another process",
  EIO: "the storage volume reported a low-level I/O error",
};

/** What the artifact says when the cause is outside the closed set. */
const GENERIC_READ_FAILURE =
  "it could not be read (the local diagnostic is recorded in this run's " +
  "operator console output, not in this report, because it can contain " +
  "machine-specific detail)";

/**
 * Map a caught error to a COARSE, host-independent category for a firm-facing
 * artifact. This is the ALLOWLIST layer: the error's free-text `message` is
 * NEVER read, so an absolute path, username, hostname, or raw syscall string
 * cannot reach the report or the SIGNED manifest through this door. The raw
 * message stays available to the caller for operator-local logging.
 */
export function describeReadFailureCause(cause: unknown): string {
  const code = (cause as { code?: unknown } | null | undefined)?.code;
  if (typeof code === "string") {
    const known = READ_FAILURE_CATEGORIES[code];
    // The errno CODE itself is host-independent and useful to an auditor, so it
    // is disclosed alongside the plain-language category. An UNKNOWN code is
    // not echoed (it is not from the closed set).
    if (known !== undefined) return `${known} (${code})`;
  }
  return GENERIC_READ_FAILURE;
}

/**
 * Construct a read-failure outcome with a lay-reader reason. The reason is
 * ALWAYS sanitized (see {@link sanitizeReason}); because {@link ReadFailed}
 * carries a branded reason, this is the only way to build one, so no raw
 * `Error.message` can reach a firm-facing artifact without passing here.
 */
export const readFailed = (reason: string): ReadFailed => ({
  status: "read_failed",
  reason: sanitizeReason(reason),
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
