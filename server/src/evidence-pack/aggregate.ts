/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: quarter aggregation
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * The calendar-quarter aggregation and covered-window shortfall detection.
 * This is the main NEW computation the pack adds. It is pure over an injected
 * `AuditEntry[]` + retention facts, so tests exercise the real bucketing and
 * shortfall logic with synthetic fixtures and never touch `~/.sanctuary`.
 *
 * The decision-category mapping reads the shipped enforcement-gate operation
 * strings (`gate_allow:`, `gate_deny:`, `gate_approval_proof:`, etc., written
 * by `principal-policy/gate.ts`) and the cross-harness approval resolution op
 * (`cross_harness_approval_resolved`, written by the approval aggregator). It
 * never invents a decision the log did not record.
 */

import type { AuditEntry } from "../operational/audit-log.js";
import type {
  DecisionCategory,
  QuarterAggregation,
  QuarterWindow,
  RetentionFacts,
  ShortfallReport,
} from "./types.js";
import { daemonStoreExcludedFromCensus } from "./types.js";
import { isInWindow } from "./quarter.js";

/**
 * The operation string the approval aggregator writes when a cross-harness
 * Tier-1 approval is resolved. Mirrored here (not imported) so this pure layer
 * does not couple to the aggregator's internals; it is a wire-string constant,
 * not behavior. Kept in lockstep with `APPROVAL_AGGREGATOR_AUDIT_OPS.RESOLVED`.
 *
 * DE-DUP (sweep HIGH-1): this op is DELIBERATELY treated as observational
 * (`other`), NOT a human decision count. When the cross-harness approval inbox
 * is enabled (`approval_redirect.enabled`), a single human approval writes BOTH
 * `cross_harness_approval_resolved` (the aggregator) AND `gate_approve:` /
 * `gate_deny:` (the gate, which is written on EVERY gated Tier-1 path whether
 * redirect is on or off). Counting both would roughly DOUBLE the "human
 * reviewed" figure and inflate `total_in_window` and the denial rows. The gate
 * op is the single source of truth for a human control-point decision; the
 * aggregator op is a paired observation of the same decision, so it is not
 * counted a second time.
 */
const CROSS_HARNESS_APPROVAL_RESOLVED = "cross_harness_approval_resolved";

/** Every decision category, so `by_category` is always fully zero-filled. */
const ALL_CATEGORIES: DecisionCategory[] = [
  "allowed",
  "allowed_proxy",
  "human_approved",
  "human_denied",
  "denied",
  "injection_blocked",
  "unclassified",
  "uncategorized",
  "other",
];

/**
 * The EXPLICIT gate-decision op-prefix -> category map. This is the single
 * source of truth the exhaustiveness test checks against the ops actually
 * emitted by `principal-policy/gate.ts`: adding a new `gate_*` decision op to
 * the gate without adding it here fails that test, so a new op can never
 * silently vanish into `other` or a flattering bucket.
 *
 * These are the PRIMARY categories; at runtime `categorizeEntry` refines
 * `gate_approve`/`gate_deny` by `details.decided_by` (a "human" decision ->
 * `human_approved`/`human_denied`; otherwise `allowed`/`denied`). The map entries
 * exist so the exhaustiveness test sees every emitted `gate_*` op mapped to a
 * real bucket (never `uncategorized`/`other`). `gate_approval_proof` is a human
 * approval; the automated tiers are `gate_allow`/`gate_allow_proxy`/
 * `gate_injection_block`/`gate_unclassified`. There is no `gate_escalate`
 * producer.
 */
export const GATE_DECISION_OP_CATEGORIES: Readonly<
  Record<string, DecisionCategory>
> = {
  gate_allow: "allowed",
  gate_allow_proxy: "allowed_proxy",
  gate_approve: "human_approved",
  gate_approval_proof: "human_approved",
  gate_deny: "denied",
  gate_injection_block: "injection_blocked",
  gate_unclassified: "unclassified",
};

/**
 * Map one audit entry to a decision category. The gate encodes the decision in
 * the operation prefix before the first colon, refined by `details.decided_by`
 * for the human/automated split. The `cross_harness_approval_resolved` op is
 * NOT read from the entry `result`; it is routed to `other` unconditionally
 * (see the de-dup note below), because it is a paired observation of a decision
 * the gate already counted.
 *
 * UNMAPPED-OP GUARD: a `gate_`-shaped op NOT in {@link GATE_DECISION_OP_CATEGORIES}
 * is a control-point decision this version does not classify, so it returns
 * `uncategorized` (surfaced honestly for investigation) rather than falling
 * into `other` or inflating an automated count. Only genuine non-`gate_`
 * operations (identity ops, state writes, heartbeats) return `other`.
 */
export function categorizeEntry(entry: AuditEntry): DecisionCategory {
  // De-dup (HIGH-1): the cross-harness approval resolution is a paired
  // OBSERVATION of a decision the gate already recorded (gate_approve/gate_deny),
  // so it is `other`, never a second human-decision count.
  if (entry.operation === CROSS_HARNESS_APPROVAL_RESOLVED) {
    return "other";
  }
  const prefix = entry.operation.split(":", 1)[0] ?? "";
  // HUMAN vs AUTOMATED via the gate's own `details.decided_by` (round-2 N1 fix):
  // `principal-policy/gate.ts` writes `decided_by: response.decided_by` on
  // gate_approve/gate_deny, where "human" is a genuine control-point human
  // decision (inbox OR interactive) and every other value
  // (timeout/auto/stderr/channel_failure, or an invalid-proof deny with no
  // decided_by) is NOT human. This is the SINGLE counted source for a human
  // decision (the paired cross_harness op is observational), so one human
  // decision counts exactly once, in BOTH directions. gate_deny sourced this way
  // is the only unambiguous human-denial signal (the cross-harness aggregator op
  // was routed to `other` in round-1); without this, `human_denied` was
  // structurally always 0.
  const decidedByHuman = entry.details?.decided_by === "human";
  if (prefix === "gate_approve") {
    return decidedByHuman ? "human_approved" : "allowed";
  }
  if (prefix === "gate_deny") {
    return decidedByHuman ? "human_denied" : "denied";
  }
  const mapped = GATE_DECISION_OP_CATEGORIES[prefix];
  if (mapped !== undefined) return mapped;
  // A gate-shaped op we do not explicitly map is a decision we cannot classify:
  // surface it, never hide it in `other` or a flattering bucket.
  if (prefix.startsWith("gate_")) return "uncategorized";
  return "other";
}

/**
 * Bucket audit entries into a single calendar quarter and count them by
 * decision category. Entries outside the window are ignored. Boundaries are
 * inclusive-start / exclusive-end (see {@link isInWindow}).
 */
export function aggregateQuarter(
  entries: readonly AuditEntry[],
  window: QuarterWindow
): QuarterAggregation {
  const byCategory = {} as Record<DecisionCategory, number>;
  for (const category of ALL_CATEGORIES) byCategory[category] = 0;

  const identities = new Set<string>();
  let firstAtMs = Number.POSITIVE_INFINITY;
  let lastAtMs = Number.NEGATIVE_INFINITY;
  let firstAt: string | null = null;
  let lastAt: string | null = null;
  let total = 0;

  for (const entry of entries) {
    if (!isInWindow(entry.timestamp, window)) continue;
    total++;
    byCategory[categorizeEntry(entry)]++;
    identities.add(entry.identity_id);
    const t = new Date(entry.timestamp).getTime();
    if (t < firstAtMs) {
      firstAtMs = t;
      firstAt = entry.timestamp;
    }
    if (t > lastAtMs) {
      lastAtMs = t;
      lastAt = entry.timestamp;
    }
  }

  return {
    window,
    total_in_window: total,
    by_category: byCategory,
    unique_identities: Array.from(identities).sort(),
    first_entry_at: firstAt,
    last_entry_at: lastAt,
  };
}

/**
 * G-1(c): a short pointer appended to the ZERO-ENTRY operator-store explanations
 * when a root-owned daemon enforcement store IS present but excluded from the
 * census (unreadable at this privilege, or tamper-failed). Without it, an
 * operator-empty quarter reads as "no enforcement history exists" when the
 * daemon may have been enforcing and recording the whole time. Empty for a
 * daemon store that is absent (nothing to disclose) or included (already in the
 * counts). The full disclosure + remedy lives in the enforcement-summary and
 * definitive-count sections; this is a one-line signpost.
 */
function daemonPresentButExcludedSuffix(retention: RetentionFacts): string {
  // Defensive: a coverage read produced before this field existed (or a partial
  // test fixture) has no daemon disclosure -- treat as `absent` (nothing to add).
  const d = retention.daemon_store;
  if (!d) return "";
  if (d.status === "present_unreadable") {
    return (
      " NOTE: a separate root-owned daemon enforcement store (_audit-daemon) IS " +
      "present but was not readable here, so daemon-recorded enforcement " +
      "(automated Castle Wall gate decisions and egress denials) for this " +
      "quarter may exist that is NOT reflected above; see the enforcement-summary " +
      "section."
    );
  }
  if (d.status === "present_tampered") {
    return (
      " NOTE: a separate root-owned daemon enforcement store (_audit-daemon) IS " +
      "present but FAILED integrity verification, so daemon-recorded enforcement " +
      "for this quarter is not reflected above and the store shows tamper " +
      "evidence; see the enforcement-summary section."
    );
  }
  if (d.status === "missing") {
    return (
      " NOTE: audit-store writer-split evidence is present on this fortress but " +
      "the separate root-owned daemon enforcement store (_audit-daemon) it " +
      "references is ABSENT (deleted or renamed, or the split evidence is present " +
      "but unverifiable), so daemon-recorded enforcement for this quarter is not " +
      "reflected above. This is not a clean fresh fortress; see the " +
      "enforcement-summary section."
    );
  }
  return "";
}

/**
 * One contributing store's retention position as consumed by the at-cap
 * decision: the store's OWN caps against its OWN retained figures. A structural
 * subset of {@link PerStoreRetention} (no `store` tag) so the legacy top-level
 * single-store fallback can flow through the same chokepoint.
 */
export interface StoreRetentionPosition {
  max_entries: number;
  retained_total: number;
  max_total_size_bytes: number;
  retained_total_size_bytes: number | null;
}

/**
 * The at-cap determinability classification: either at-cap CAN be computed and
 * `contributing_stores` are the stores whose own caps drive it, or it CANNOT
 * (`contributing_stores` empty) and no surface may assert a definitive at-cap
 * or below-cap claim.
 */
export interface RetentionDeterminability {
  /** True when "at a retention cap" can honestly be computed from the facts. */
  at_cap_determinable: boolean;
  /**
   * The stores whose OWN caps drive the at-cap decision when determinable;
   * empty when not determinable (at-cap must never be asserted either way).
   */
  contributing_stores: readonly StoreRetentionPosition[];
}

/**
 * F2-R2 (Codex second-family review + Dry-8 sweep): a finite plain number --
 * the ONLY runtime shape the at-cap comparisons in `detectShortfall` can
 * honestly evaluate. Rejects `NaN`, `Infinity`, `undefined`, `null`, strings,
 * and every other type an untyped JS / `JSON.parse` caller can smuggle past
 * the compile-time `number` annotation.
 */
const isFiniteNumber = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v);

/**
 * F2-R2: runtime FIELD COMPLETENESS of one contributing store position. Row
 * PRESENCE alone is not determinability: a tags-only row like
 * `{ store: "operator" }` carries no cap evidence at all, yet the at-cap
 * comparison would silently evaluate its missing fields as "not at cap" and
 * let the pack SIGN a definitive flattering `retention_at_cap: false` (plus
 * the never-pruned reassurance). Every field the at-cap comparison reads must
 * be a finite number; `retained_total_size_bytes` may instead be the
 * documented `null` ("unread") -- but never `undefined` or any other type.
 */
const storePositionComplete = (s: StoreRetentionPosition): boolean =>
  isFiniteNumber(s.max_entries) &&
  isFiniteNumber(s.retained_total) &&
  isFiniteNumber(s.max_total_size_bytes) &&
  (s.retained_total_size_bytes === null ||
    isFiniteNumber(s.retained_total_size_bytes));

/**
 * D7-1 / Codex-F1+F2 (dry-bar round 7): the SINGLE chokepoint deciding whether
 * "the log is at a retention cap" is DETERMINABLE from a set of retention
 * facts, and if so which stores' own caps drive the decision. Both consumers
 * route through it: `detectShortfall` (every prose surface -- shortfall
 * explanation, exec-summary and section-7 coverage notices, the PDF) and, via
 * the `retention_at_cap_determinable` field it feeds, the SIGNED manifest
 * serialization in `generate.ts`. This replaces the P1-B `=== undefined` guard,
 * whose narrow keying let an INCOMPLETE/INCONSISTENT breakdown (empty `[]`, a
 * type-invalid `null` from a JS/`JSON.parse` caller, or an operator-only row
 * while the daemon store is `included`) fall back to the mismatched-scope
 * merged-total-vs-one-cap arithmetic and revive the flattering "never pruned /
 * below both caps" reassurance.
 *
 * Classification, fail-safe by default (mirrors the D5-3 rule: never assert a
 * definitive claim the present data cannot back):
 *  1. USABLE breakdown -- a present, non-empty, genuinely-Array
 *     `per_store_retention` whose EVERY row is a runtime-complete
 *     {@link PerStoreRetention} (a known `store` tag plus finite numeric
 *     `max_entries`, `retained_total`, `max_total_size_bytes`, and a
 *     null-or-finite `retained_total_size_bytes`), with EXACTLY ONE
 *     `store: "operator"` row (the operator store is part of EVERY census) and
 *     AT MOST ONE `store: "daemon"` row -- EXACTLY ONE whenever the census is
 *     MERGED (`daemon_store.status === "included"`) -> DETERMINABLE, judged
 *     per store against each store's own caps (the shipped path:
 *     `deriveAuditReadOutcome` always seeds a complete operator row and adds
 *     the daemon row when merged). A single complete daemon row on a
 *     NON-merged census stays usable: it can only widen the at-cap OR toward
 *     over-warning, never manufacture the flattering below-cap claim, and the
 *     pre-WATCH-1 D5-1 fixtures (no `daemon_store` disclosure) depend on it.
 *  2. Breakdown genuinely ABSENT (`undefined`) on a genuinely SINGLE-store
 *     census (daemon NOT `included`) -> DETERMINABLE via the top-level fields,
 *     which ARE that one store's own figures (the legacy pre-D5-1 caller) --
 *     but ONLY when those top-level fields are themselves runtime-complete
 *     under the same rule (F2-R2: the fallback row is a CONTRIBUTING row like
 *     any other; a non-finite/absent top-level figure from an untyped caller
 *     is no more evaluable than a field-free breakdown row).
 *  3. Everything else -> NOT DETERMINABLE:
 *     - daemon `included` with the breakdown absent, `null`, empty, or missing
 *       the daemon row: the top-level total is MERGED, so comparing it to one
 *       store's cap is the exact mismatched-scope arithmetic P1-B banned;
 *     - a breakdown missing the OPERATOR row (fix-round F1): every census
 *       includes the operator store, so a daemon-only breakdown left the
 *       operator store's own cap position unsupplied -- the exact mirror of
 *       the daemon-less case -- yet previously still earned the definitive
 *       below-cap claim and the flattering reassurance over the daemon row
 *       alone;
 *     - an explicitly-supplied empty `[]`, `null`, or non-Array breakdown on
 *       ANY census: the caller asserted a breakdown and delivered nothing
 *       usable, so the anomalous input never earns a definitive at-cap OR
 *       below-cap claim;
 *     - F2-R2 (second-family review): any row that is not a runtime-complete
 *       object -- a `null`/non-object element, an unknown `store` tag, a
 *       missing/`NaN`/`Infinity`/wrong-typed numeric field, or an `undefined`
 *       `retained_total_size_bytes` (the contract is null-or-finite). Row
 *       PRESENCE without field COMPLETENESS previously sailed through: the
 *       at-cap comparison evaluated the missing fields as "not at cap" and the
 *       pack SIGNED a definitive flattering `retention_at_cap: false` plus the
 *       never-pruned reassurance from rows carrying zero cap evidence;
 *     - F2-R2 / Dry-8 HIGH: DUPLICATE rows for the same store or UNKNOWN-store
 *       rows (e.g. `store: "archive"`). `contributing_stores` feeds the at-cap
 *       OR directly, so an invalid extra row could also SIGN a definitive
 *       `retention_at_cap: true` -- a signed falsehood in the OVER-claiming
 *       direction. An inconsistent census description forfeits determinability
 *       entirely (fail-safe: assert NEITHER direction).
 */
export function retentionDeterminability(
  retention: RetentionFacts
): RetentionDeterminability {
  const breakdown = retention.per_store_retention;
  const daemonIncluded = retention.daemon_store?.status === "included";
  // `Array.isArray` deliberately rejects `undefined`, a `null` smuggled past
  // the optional-array type by an untyped caller, AND any non-Array object.
  if (Array.isArray(breakdown) && breakdown.length > 0) {
    // F2-R2: every row must be a runtime-complete object with a KNOWN store
    // tag -- presence-only rows like `{ store: "operator" }` carry no cap
    // evidence and must never be evaluated as "not at cap".
    const rowsComplete = breakdown.every(
      (s) =>
        typeof s === "object" &&
        s !== null &&
        (s.store === "operator" || s.store === "daemon") &&
        storePositionComplete(s)
    );
    // The operator store is part of EVERY census (`types.ts` documents the
    // breakdown invariant as "Always includes the operator store"), so a
    // daemon-only breakdown is as incomplete as an operator-only one. F2-R2 /
    // Dry-8: DUPLICATE rows would feed the at-cap OR twice (an invalid extra
    // at-cap row signs a definitive over-claim), so exactly one operator row
    // and at most one daemon row -- exactly one when the census is MERGED.
    if (!rowsComplete) {
      return { at_cap_determinable: false, contributing_stores: [] };
    }
    const operatorCount = breakdown.filter((s) => s.store === "operator").length;
    const daemonCount = breakdown.filter((s) => s.store === "daemon").length;
    const usable =
      operatorCount === 1 &&
      (daemonIncluded ? daemonCount === 1 : daemonCount <= 1);
    if (usable) {
      return { at_cap_determinable: true, contributing_stores: breakdown };
    }
    return { at_cap_determinable: false, contributing_stores: [] };
  }
  if (!daemonIncluded && breakdown === undefined) {
    // F2-R2: the legacy fallback row is a CONTRIBUTING row like any other --
    // validate the top-level figures under the same completeness rule before
    // letting them drive a definitive at-cap/below-cap claim.
    const single: StoreRetentionPosition = {
      max_entries: retention.max_entries,
      retained_total: retention.retained_total,
      max_total_size_bytes: retention.max_total_size_bytes,
      retained_total_size_bytes: retention.retained_total_size_bytes,
    };
    if (storePositionComplete(single)) {
      return { at_cap_determinable: true, contributing_stores: [single] };
    }
  }
  return { at_cap_determinable: false, contributing_stores: [] };
}

/**
 * Detect a covered-window shortfall: whether the retained audit log
 * demonstrably covers the full quarter, on BOTH the start side and the end
 * side (HIGH-2 fix). A shortfall exists when either:
 *  - START: the earliest retained entry is later than the quarter start (so
 *    pre-existing entries are unavailable for this quarter), OR
 *  - END: the quarter had not ended at generation time, so the pack cannot
 *    attest coverage of the portion of the quarter after `generatedAt` (an
 *    in-progress quarter, the default one-command case).
 *
 * `covered_to_exclusive` is `min(quarter end, generation instant)` and is NEVER
 * unconditionally the quarter end: the pack can never attest coverage of a
 * period after the moment it was generated.
 *
 * The start-side disclosure distinguishes retention pruning (log at/above its
 * FIFO cap; early entries LIKELY dropped) from genuine inactivity (log below
 * cap; the fortress simply had no earlier activity), and always states the real
 * covered span. The real last-recorded entry is surfaced so an auditor sees the
 * true tail of activity rather than inferring coverage to the quarter end.
 */
export function detectShortfall(
  window: QuarterWindow,
  retention: RetentionFacts,
  params: { generatedAt: string; lastEntryAt: string | null }
): ShortfallReport {
  const quarterStartMs = new Date(window.start_inclusive).getTime();
  const quarterEndMs = new Date(window.end_exclusive).getTime();
  const generatedMs = new Date(params.generatedAt).getTime();
  const earliestMs =
    retention.earliest_retained_at === null
      ? null
      : new Date(retention.earliest_retained_at).getTime();
  // D5-1 (dry-bar round 5): "at a retention cap" is judged PER STORE against
  // each store's OWN independent cap, then OR-ed. Each contributing `AuditLog`
  // (operator + daemon) prunes on its own 100k-entry / 100 MB caps, so the
  // combined healthy capacity is 200k/200 MB; comparing the MERGED two-store
  // retained total against a SINGLE store's cap falsely reported "at cap" (and a
  // false `retention_at_cap: true` in the signed manifest) for a healthy split
  // fortress whose combined count crossed one store's cap while NEITHER store was
  // near its own.
  //
  // P1-B (round 6) -> D7-1/F2 (round 7): whether at-cap is even DETERMINABLE,
  // and over which stores, is decided by the `retentionDeterminability`
  // chokepoint above (usable breakdown -> per store; genuine legacy
  // single-store -> top-level fields; anything else -- a merged census with an
  // absent/`null`/empty/daemon-less breakdown, or an explicitly-supplied
  // empty/`null` breakdown -- fail-safe NOT determinable). When not
  // determinable, assert NEITHER at-cap NOR the flattering "never pruned /
  // below caps" reassurance.
  const atCapForStore = (s: StoreRetentionPosition): boolean => {
    // Either FIFO cap counts as "at cap" for a given store (sweep HIGH-5):
    // entries OR total size.
    const atEntryCap = s.max_entries > 0 && s.retained_total >= s.max_entries;
    const atSizeCap =
      s.max_total_size_bytes > 0 &&
      s.retained_total_size_bytes !== null &&
      s.retained_total_size_bytes >= s.max_total_size_bytes;
    return atEntryCap || atSizeCap;
  };
  // When not determinable, `retentionAtCap` stays false (never asserted) AND
  // the reassurance is gated off by `atCapDeterminable` below.
  const determinability = retentionDeterminability(retention);
  const atCapDeterminable = determinability.at_cap_determinable;
  const retentionAtCap =
    atCapDeterminable && determinability.contributing_stores.some(atCapForStore);

  // END SIDE: coverage can never extend past the moment the report was made.
  const inProgress = generatedMs < quarterEndMs;
  const coveredToExclusive = new Date(
    Math.min(quarterEndMs, generatedMs)
  ).toISOString();

  // G-1(c): `earliest_retained_at` is derived from the OPERATOR store only (the
  // daemon store is merged into the scan only when readable). When a root-owned
  // daemon store is present but EXCLUDED (unreadable/tampered), the operator
  // store can be empty while the daemon HAS been enforcing and recording, so an
  // unqualified "the audit log holds no history" would be a false completeness
  // claim -- scope it to the operator log and signpost the daemon store. When the
  // daemon store is absent/included, the operator count IS the whole census, so
  // keep the neutral wording (do not introduce a distinction that under-claims
  // the single-store case -- two-family gate follow-up).
  const daemonExcluded = daemonStoreExcludedFromCensus(retention.daemon_store);

  // START SIDE.
  let coveredFrom: string;
  let startShortfall: boolean;
  let startExplanation: string;
  let zeroOfQuarterCovered = false;
  if (earliestMs === null) {
    coveredFrom = window.start_inclusive;
    startShortfall = true;
    zeroOfQuarterCovered = true;
    startExplanation = daemonExcluded
      ? "The operator audit log holds no retained entries, so this quarter has " +
        "no covered access history in the operator store. Confirm the fortress " +
        "was recording during the reporting period." +
        daemonPresentButExcludedSuffix(retention)
      : "The audit log holds no retained entries, so this quarter has no " +
        "covered access history. Confirm the fortress was recording during " +
        "the reporting period.";
  } else if (earliestMs >= quarterEndMs) {
    // M1: the entire retained window post-dates the quarter (all in-quarter
    // entries pruned). Do NOT cite an out-of-quarter covered_from; state plainly
    // that zero of the quarter is covered.
    coveredFrom = window.start_inclusive;
    startShortfall = true;
    zeroOfQuarterCovered = true;
    startExplanation = daemonExcluded
      ? "NONE of this quarter is covered by the operator audit log: its earliest " +
        "retained entry (" +
        retention.earliest_retained_at! +
        ") is at or after the quarter end, so no operator-store entries from " +
        "this quarter survive in the retained log. The counts above are therefore " +
        "zero for this quarter (from the operator store). This almost always " +
        "means earlier entries were pruned by size/count (FIFO) retention; raise " +
        "the retention cap or export monthly snapshots." +
        daemonPresentButExcludedSuffix(retention)
      : "NONE of this quarter is covered: the earliest retained audit entry (" +
        retention.earliest_retained_at! +
        ") is at or after the quarter end, so no entries from this quarter " +
        "survive in the retained log. The counts above are therefore zero for " +
        "this quarter. This almost always means earlier entries were pruned by " +
        "size/count (FIFO) retention; raise the retention cap or export monthly " +
        "snapshots.";
  } else if (earliestMs > quarterStartMs) {
    coveredFrom = retention.earliest_retained_at!;
    startShortfall = true;
    // The DEFINITIVE discriminator is whether the log ever pruned (a rotation
    // anchor). Only affirm "genuine inactivity, not pruning" when we KNOW the
    // log never pruned AND it is DEFINITIVELY below both caps; otherwise do not
    // reassure. P1-B: when at-cap is not determinable (a merged census with no
    // per-store breakdown), `!retentionAtCap` is true only because at-cap was
    // never asserted, NOT because we proved below-cap -- so require
    // `atCapDeterminable` here to keep the flattering reassurance from firing
    // from an unknown cap position.
    const neverPruned =
      retention.ever_pruned === false && atCapDeterminable && !retentionAtCap;
    // C2 (dry-bar): `earliest_retained_at` / `ever_pruned` are the OPERATOR
    // store's facts (the daemon store merges into the scan only when readable).
    // When a root-owned daemon store is present but EXCLUDED, the "no recorded
    // activity before <coveredFrom>" reassurance is a completeness claim the
    // code cannot back -- the daemon may have been enforcing and recording
    // before that instant. Scope the reassurance to the operator store and
    // signpost the excluded daemon store; keep the neutral wording when the
    // operator count IS the whole census (absent/included).
    startExplanation = neverPruned
      ? daemonExcluded
        ? "The earliest retained entry in the operator audit log is after the " +
          "quarter start, and the operator log has never pruned entries (it is " +
          "below both its entry and size retention caps), so the operator store " +
          "records no activity before " +
          coveredFrom +
          "; operator-store coverage begins at that instant." +
          daemonPresentButExcludedSuffix(retention)
        : "The earliest retained audit entry is after the quarter start, and the " +
          "log has never pruned entries (it is below both its entry and size " +
          "retention caps), so this reflects that the fortress had no recorded " +
          "activity before " +
          coveredFrom +
          ", not that entries were pruned. Coverage begins at that instant."
      : "The retained audit window begins after the quarter start, and " +
        (retentionAtCap
          ? "the log is at a retention cap (entries or size), "
          : retention.ever_pruned === true
            ? "the log has pruned entries at least once, "
            : "size-based pruning of large early entries cannot be ruled out, ") +
        "so earlier-quarter entries may have been pruned by size/count (FIFO) " +
        "retention. This report covers access history from " +
        coveredFrom +
        " onward; whether the gap is pruning or genuine inactivity cannot be " +
        "affirmed here. Raise the retention cap or export monthly snapshots to " +
        "cover the full quarter." +
        (daemonExcluded ? daemonPresentButExcludedSuffix(retention) : "");
  } else {
    coveredFrom = window.start_inclusive;
    startShortfall = false;
    startExplanation =
      "The retained audit window reaches the quarter start: the earliest " +
      "retained entry precedes it.";
  }

  const parts: string[] = [];
  if (inProgress) {
    parts.push(
      "PARTIAL QUARTER: this report was generated before the quarter ended, " +
        "so it can only attest coverage through " +
        coveredToExclusive +
        " (the generation time), not the full quarter ending " +
        window.end_exclusive +
        ". Regenerate after the quarter closes for a complete report."
    );
  }
  parts.push(startExplanation);
  if (!inProgress && params.lastEntryAt) {
    // D5-4 (dry-bar round 5, C2-family residue): `lastEntryAt` is the maximum
    // in-window timestamp across the MERGED census, which excludes a daemon
    // store that was not read (present_unreadable/tampered/missing). When the
    // daemon store is excluded it may hold a LATER in-window enforcement entry,
    // so an unqualified "the last recorded audit entry ... is X" is a definitive
    // claim the code cannot back. Scope it to the operator store (its true
    // source) exactly like its sibling coverage sentences; when the daemon store
    // is absent/included the merged census IS the whole story, so keep the
    // neutral wording (no under-claim of the single-store case).
    parts.push(
      (daemonExcluded
        ? "The last recorded operator-store audit entry inside the covered window is "
        : "The last recorded audit entry inside the covered window is ") +
        params.lastEntryAt +
        "."
    );
  }

  return {
    shortfall: startShortfall || inProgress,
    covered_from: coveredFrom,
    covered_to_exclusive: coveredToExclusive,
    in_progress_quarter: inProgress,
    last_entry_at: params.lastEntryAt,
    retention_at_cap: retentionAtCap,
    // D7-1/F1 (round 7): carry determinability so the SIGNED manifest can
    // serialize a not-determinable marker instead of a definitive boolean.
    retention_at_cap_determinable: atCapDeterminable,
    zero_of_quarter_covered: zeroOfQuarterCovered,
    explanation: parts.join(" "),
    // WATCH-1: carry the daemon-store disclosure onto the coverage report so the
    // enforcement-summary section can state whether daemon-recorded enforcement
    // events are included in the counts.
    daemon_store: retention.daemon_store,
  };
}
