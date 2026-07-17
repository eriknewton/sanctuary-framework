/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: shared types
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared types for the quarterly law-firm evidence pack (slice 1, the
 * walking skeleton). The evidence pack is a human-readable PDF plus a signed
 * Markdown report and a signed manifest, which an office manager attaches to an
 * insurance renewal or an outside-counsel audit. Integrity lives in the signed
 * Markdown + manifest; the PDF itself is a render and is deliberately NOT
 * signed (see the CLI help and section 10). It reuses the shipped tamper-evident
 * audit log, the zero-dependency PDF writer, and the signed-manifest bundle
 * pattern; the NEW code here is the calendar-quarter aggregation layer plus
 * honest coverage/shortfall disclosure.
 *
 * NOT LEGAL ADVICE. This defines the shape of a technical evidence artifact.
 * It is not a legal interpretation of any professional-responsibility rule,
 * carrier questionnaire, or outside-counsel guideline.
 */

import type { ReadOutcome } from "./read-outcome.js";

/**
 * A calendar quarter, e.g. `{ year: 2026, quarter: 3 }` for 2026-Q3 (July,
 * August, September). Quarter is 1..4.
 */
export interface CalendarQuarter {
  year: number;
  quarter: 1 | 2 | 3 | 4;
}

/**
 * The concrete time window a calendar quarter maps to. `start_inclusive` is
 * the first instant of the quarter; `end_exclusive` is the first instant of
 * the following quarter. An audit entry belongs to the quarter iff
 * `start_inclusive <= timestamp < end_exclusive` (inclusive start, exclusive
 * end), so an entry on the exact quarter boundary lands in exactly one
 * quarter and is never double-counted.
 */
export interface QuarterWindow {
  quarter: CalendarQuarter;
  /** Canonical label, e.g. "2026-Q3". */
  label: string;
  /** ISO 8601 UTC timestamp of the first instant of the quarter. */
  start_inclusive: string;
  /** ISO 8601 UTC timestamp of the first instant of the NEXT quarter. */
  end_exclusive: string;
}

/**
 * Category an audit entry is bucketed into for the human-review and
 * access-log sections. Derived from the entry's `operation` prefix (the
 * `gate_*` families the enforcement gate writes), refined by the gate's own
 * `details.decided_by` for the human/automated split. `other` is every
 * operation that is not a counted enforcement-decision record (identity ops,
 * state writes, heartbeats) -- including the `cross_harness_approval_resolved`
 * op, which is deliberately routed to `other` (NOT read from the entry
 * `result`) because it is a paired OBSERVATION of a decision the gate already
 * counted; counting it again would double the human-review figure (see
 * `aggregate.ts`).
 *
 * HUMAN vs AUTOMATED via `details.decided_by` (round-2 N1 fix): the gate writes
 * `decided_by: response.decided_by` on `gate_approve:` and `gate_deny:` (see
 * `principal-policy/gate.ts`). A value of "human" is a genuine control-point
 * human decision (inbox OR interactive); every other value (timeout/auto/
 * stderr/channel_failure, or an invalid-proof deny with no decided_by) is NOT
 * human. So `gate_approve` + decided_by "human" -> `human_approved` (else the
 * action ran on an automated approval -> `allowed`), and `gate_deny` +
 * decided_by "human" -> `human_denied` (else automated policy/invalid-proof/
 * channel-failure -> `denied`). The two-phase `gate_approval_proof` maps to
 * `human_approved` unconditionally (its approval was made by a human at mint
 * time). This is the SINGLE counted source for a human decision; the paired
 * `cross_harness_approval_resolved` op is observational (`other`), so one human
 * decision through the inbox counts EXACTLY ONCE in both directions (no double
 * count of round-1, no structurally-zero `human_denied` of round-2). The
 * automated tiers write `gate_allow:` / `gate_allow_proxy:` /
 * `gate_injection_block:` / `gate_unclassified:` (no human). There is no
 * `escalated` category: no code path emits a `gate_escalate:` op (escalations
 * resolve to approve/deny), so a row for it would advertise a capability that
 * does not exist.
 *
 * UNMAPPED-OP GUARD (honesty chokepoint): a `gate_`-shaped control-point
 * decision operation that is NOT explicitly mapped must surface as
 * `uncategorized`, NEVER silently fall into `other` or a flattering allow/deny
 * bucket. This closes the slice-1 root cause (the live `gate_approve:` op was
 * unmapped and vanished into `other`): a future daemon that emits a new
 * `gate_*` decision op is surfaced as "uncategorized (N)" for investigation
 * rather than miscounted. `other` remains for genuine non-decision operations
 * (identity ops, state writes, heartbeats).
 *
 * HONESTY BOUND (spec risk #11): these counts reflect enforcement decisions
 * at the control point, not a supervising attorney's per-matter review. The
 * PDF wording says so and leans on the policy/attestation layer (a later
 * slice) for the professional-responsibility half.
 */
export type DecisionCategory =
  | "allowed"
  | "allowed_proxy"
  | "human_approved"
  | "human_denied"
  | "denied"
  | "injection_blocked"
  | "unclassified"
  | "uncategorized"
  | "other";

/**
 * The calendar-quarter aggregation of audit activity. This is the main NEW
 * computation the evidence pack adds: today's audit counting is size-based
 * (FIFO retention), never calendar-based.
 */
export interface QuarterAggregation {
  window: QuarterWindow;
  /** Total audit entries whose timestamp falls inside the quarter window. */
  total_in_window: number;
  /** Count per decision category (every category key is present, zero-filled). */
  by_category: Record<DecisionCategory, number>;
  /** Distinct agent/identity ids that appear in the window (sorted). */
  unique_identities: string[];
  /**
   * Earliest and latest entry timestamps actually observed INSIDE the window.
   * Null when the window contained no entries. Used to state the real covered
   * span rather than implying full-quarter coverage.
   */
  first_entry_at: string | null;
  last_entry_at: string | null;
}

/**
 * Facts about the audit log's retention posture, used to decide whether the
 * quarter is fully covered. Sanctuary's audit retention is size/count-based
 * FIFO, not time-based, so a busy fortress can prune early-quarter entries
 * before generation day (spec risk #6).
 */
/**
 * WATCH-1 (F2 audit-store split, 2026-07-15): the F2 migration moves
 * daemon-produced enforcement records (Castle Wall gate decisions, egress
 * denials, producer-signed daemon entries) out of the operator `_audit`
 * namespace into a separate root-owned `_audit-daemon` store. The evidence pack
 * reads the operator store; this descriptor makes the daemon store's
 * contribution EXPLICIT so the census is never a silent single-store false
 * count. Five honest states:
 *   - `absent`: no daemon store has ever been provisioned here AND the
 *     writer-split migration has NOT been established (a genuinely fresh /
 *     never-armed fortress). The operator store is the whole census. This is
 *     resolved against the split-established marker, NOT a bare directory
 *     stat, so a DELETED store is never mislabeled `absent` (see `missing`).
 *   - `missing` (C1): audit-store writer-split evidence is present (a split
 *     boundary and/or established marker referencing a daemon chain) but the
 *     daemon namespace is ABSENT. This is either genuine deletion/renaming of a
 *     migrated store OR present-but-unverifiable split evidence (the presence
 *     check is fail-closed on a raw boundary-file stat, so it does not assert
 *     the migration definitively "ran"); EITHER way it is NOT a never-armed
 *     fortress. The counts EXCLUDE it and the disclosure hedges accordingly,
 *     never the futile "re-run as root" (root cannot recreate a missing store).
 *     Mirrors `verifyFortressAuditFullPicture`'s `missing` verdict.
 *   - `included`: the daemon store was read at this privilege and its entries
 *     were MERGED into the census (its retention counted independently).
 *   - `present_unreadable`: a daemon store EXISTS but could not be read at this
 *     privilege (the expected operator-uid case on an armed box). Its records
 *     are NOT in the counts; the pack DISCLOSES the omission rather than
 *     presenting the operator-only view as complete. Re-run as root for a full
 *     census -- but ONLY when {@link DaemonStoreDisclosure.unreadable_reason} is
 *     `privilege` (a genuine I/O/corruption error does not clear by re-running
 *     as root; see G-3).
 *   - `present_tampered`: the daemon store WAS readable but FAILED integrity
 *     verification (round-5 two-family gate): tamper evidence, not a privilege
 *     limitation. Its records are NOT in the counts, and the disclosure says
 *     "tamper detected, investigate", never the futile "re-run as root".
 */
export interface DaemonStoreDisclosure {
  status:
    | "absent"
    | "missing"
    | "included"
    | "present_unreadable"
    | "present_tampered";
  /**
   * Daemon-store entries merged into the census (only when `included`). This is
   * the TOTAL retained daemon entries read, across all time -- NOT the subset
   * that falls in the reporting quarter. The rendered "N merged into the counts
   * above" figure uses {@link windowed_entry_count} instead, so an all-time
   * total never overstates the daemon contribution to the quarter's counts.
   */
  included_entry_count: number;
  /**
   * G-2: of {@link included_entry_count}, how many daemon entries fall INSIDE the
   * reporting quarter window and therefore actually contribute to the displayed
   * decision counts. Set by the generator, which owns the quarter window; the
   * pre-window read layer (`deriveAuditReadOutcome`) has no window and leaves it
   * `undefined`, in which case the renderer falls back to a windowed-agnostic
   * phrasing. Only meaningful when `status === "included"`.
   */
  windowed_entry_count?: number;
  /**
   * G-3: when `present_unreadable`, WHY the daemon store could not be read:
   *   - `privilege`: a permission limitation (the root-owned store the operator
   *     uid cannot read; the EXPECTED armed-box case). Re-running the pack as
   *     root reads the store, so the "re-run as root for a complete census"
   *     remedy is correct here.
   *   - `io`: a genuine I/O or corruption error that is NOT a privilege limit
   *     (the directory listed, but the read/decrypt failed for another reason).
   *     Running as root will NOT resolve it, so the disclosure must NOT advise
   *     "re-run as root"; it directs the operator to investigate the store.
   * Absent for the other statuses. When unset on a `present_unreadable`
   * disclosure (older fixtures / reports), the renderer defaults to `privilege`,
   * the dominant real cause.
   */
  unreadable_reason?: "privilege" | "io";
}

/**
 * The SINGLE predicate for "a daemon enforcement store is present on this
 * fortress but its records are NOT in the census" -- i.e. the counts/coverage
 * are an operator-store-only view and every definitive-census surface must
 * disclose that. True for `present_unreadable`, `present_tampered`, and
 * `missing` (split evidence present but the daemon store absent -- deleted or
 * unverifiable); false for `absent` (the operator store
 * IS the whole census) and `included` (the daemon entries are already merged).
 *
 * Centralised so a future status flows through ONE decision rather than N
 * inline `||` chains that can drift apart (the recurring-hole pattern). Every
 * count/coverage/CLI surface that scopes its wording to the operator store
 * derives that scoping from HERE.
 */
export function daemonStoreExcludedFromCensus(
  daemon: DaemonStoreDisclosure | undefined
): boolean {
  const status = daemon?.status;
  return (
    status === "present_unreadable" ||
    status === "present_tampered" ||
    status === "missing"
  );
}

export interface RetentionFacts {
  /** Configured maximum retained entry count (FIFO cap). */
  max_entries: number;
  /** Total entries currently retained across all time (all quarters). */
  retained_total: number;
  /**
   * Configured maximum total on-disk size in bytes (the OTHER FIFO cap). Audit
   * retention prunes on EITHER cap: 100,000 entries OR 100 MB by default (sweep
   * HIGH-5). A value `<= 0` means the size cap is not known to this reporter,
   * and (D8-1 Leg B) an UNKNOWN cap on any contributing row makes at-cap NOT
   * DETERMINABLE: it can prove neither "at cap" nor "below both caps", so no
   * definitive at-cap boolean is signed and no below-caps prose renders (the
   * pre-D8-1 "no size-cap judgment is made" allowance still earned the signed
   * definitive `retention_at_cap: false`, which was a claim over a cap
   * declared unknown). F2-R2: a non-finite or ABSENT value from an untyped
   * caller equally makes at-cap NOT DETERMINABLE.
   */
  max_total_size_bytes: number;
  /**
   * Total on-disk size in bytes of the retained audit log, or null if unread.
   * D8-1 Leg C: an UNREAD (`null`) size on any contributing row makes at-cap
   * NOT DETERMINABLE -- "below both its entry and size retention caps" cannot
   * be asserted over a size dimension nobody read, and `ever_pruned === false`
   * does not exclude `size == cap` (pruning fires only when the size EXCEEDS
   * the cap). This deliberately reverses the earlier null-is-usable allowance.
   */
  retained_total_size_bytes: number | null;
  /**
   * True when the audit log has EVER pruned entries (a rotation anchor exists).
   * This is the definitive discriminator between "genuine inactivity before the
   * earliest retained entry" (never pruned) and "earlier entries were pruned"
   * (sweep HIGH-5): pruning is FIFO-on-overflow, so a log that never pruned has
   * its true earliest entry retained. Null when this fact could not be read.
   */
  ever_pruned: boolean | null;
  /**
   * Timestamp of the EARLIEST retained audit entry across all time, or null
   * when the log is empty. If this is later than the quarter start, entries
   * from before it are not available for this quarter.
   */
  earliest_retained_at: string | null;
  /**
   * WATCH-1: whether the F2 daemon enforcement store (`_audit-daemon`) exists
   * and whether its records are in this census. See {@link DaemonStoreDisclosure}.
   */
  daemon_store: DaemonStoreDisclosure;
  /**
   * D5-1 (dry-bar round 5): the per-contributing-store retention breakdown so
   * "the log is at a retention cap" is evaluated PER STORE against each store's
   * OWN independent cap, then OR-ed -- never the MERGED two-store total compared
   * against a single store's cap (which falsely reports "at cap" on a healthy
   * split fortress whose combined count exceeds one store's cap while neither
   * store is near its own). The merged {@link retained_total} /
   * {@link retained_total_size_bytes} above stay as the all-time DISPLAY totals;
   * this array drives the at-cap decision. Always includes the operator store;
   * includes the daemon store only when it was merged (`included`). When absent
   * (a legacy fixture / a caller that predates this field), the shortfall
   * detector treats the merged top-level fields as a single conceptual store --
   * the correct single-store computation for a non-split fortress.
   */
  per_store_retention?: readonly PerStoreRetention[];
}

/**
 * D5-1: one contributing audit store's retention position, so at-cap is judged
 * against THIS store's own configured caps (each `AuditLog` prunes on its own
 * independent 100k-entry / 100 MB caps; two stores have 200k/200 MB combined
 * capacity). `retained_total` / `retained_total_size_bytes` are this store's
 * own retained figures, never the merged census total.
 */
export interface PerStoreRetention {
  /** Which contributing store these figures belong to. */
  store: "operator" | "daemon";
  /**
   * This store's configured maximum retained entry count (FIFO cap).
   * D8-1 Leg B: `<= 0` = cap unknown => at-cap NOT DETERMINABLE.
   */
  max_entries: number;
  /** This store's own retained entry count (across all time). */
  retained_total: number;
  /**
   * This store's configured maximum total on-disk size in bytes.
   * D8-1 Leg B: `<= 0` = cap unknown => at-cap NOT DETERMINABLE.
   */
  max_total_size_bytes: number;
  /**
   * This store's own retained on-disk size in bytes, or null if unread.
   * D8-1 Leg C: `null` (unread -- including a store whose usage read threw,
   * Leg A) => at-cap NOT DETERMINABLE; no surface may claim the size
   * dimension when the size was never read.
   */
  retained_total_size_bytes: number | null;
}

/**
 * The outcome of covered-window shortfall detection. A shortfall exists when
 * the retained audit window does not demonstrably cover the full quarter, so
 * the pack must disclose it rather than let an auditor discover it.
 */
export interface ShortfallReport {
  /**
   * True when the covered window does not demonstrably span the full quarter,
   * for EITHER reason: the start is uncovered (earliest retained entry is after
   * the quarter start) OR the end is uncovered (the quarter is still in
   * progress at generation time). Both must be disclosed, never silently
   * passed.
   */
  shortfall: boolean;
  /**
   * The instant from which coverage is demonstrable for this quarter: the
   * later of the quarter start and the earliest retained entry. Equal to the
   * quarter start when the start is fully covered.
   */
  covered_from: string;
  /**
   * The exclusive upper bound of DEMONSTRABLE coverage (HIGH-2 fix). This is
   * `min(quarter end, generation instant)`: the pack can never attest coverage
   * of a period after the moment it was generated, so an in-progress quarter
   * caps this at the generation time rather than the (future) quarter end. It
   * is NOT unconditionally the quarter end.
   */
  covered_to_exclusive: string;
  /**
   * True when the quarter had not ended at generation time (the report covers a
   * PARTIAL quarter). The default one-command CLI targets the current quarter,
   * so this is the common case and must be stamped prominently.
   */
  in_progress_quarter: boolean;
  /**
   * Timestamp of the last audit entry actually observed inside the covered
   * window, or null when the window held no entries. Surfaced so an auditor
   * sees the real tail of recorded activity rather than inferring coverage to
   * the quarter end.
   */
  last_entry_at: string | null;
  /**
   * True when the retained log is at or above its FIFO cap, which means
   * pruning is actively occurring and early-quarter entries were LIKELY
   * dropped (as opposed to the fortress simply having no earlier activity).
   * Distinguishing these two causes keeps the disclosure honest. When
   * {@link retention_at_cap_determinable} is false this stays `false` ONLY
   * because at-cap was never asserted, NOT because below-cap was proven.
   */
  retention_at_cap: boolean;
  /**
   * D7-1 / Codex-F1 (dry-bar round 7): whether {@link retention_at_cap} could
   * honestly be COMPUTED at all, decided by the single
   * `retentionDeterminability` chokepoint. False when the retention facts
   * carried no usable per-store breakdown (`per_store_retention` absent,
   * `null`, empty, or missing the daemon row while the daemon store is
   * `included`) for anything other than the genuine legacy single-store case,
   * or (F2-R2, second-family review) when any contributing row -- a breakdown
   * row or the legacy top-level fallback -- is runtime-INCOMPLETE (a
   * missing/`NaN`/`Infinity`/wrong-typed numeric field, an `undefined`
   * `retained_total_size_bytes`, an unknown `store` tag, a duplicate row for
   * the same store, or a non-object row): incomplete cap evidence must never
   * be evaluated as a definitive at-cap OR below-cap position.
   * D8-1 (Dry-8 sweep): ALSO false when any contributing row is complete but
   * not USABLE for a definitive verdict -- an entry or size cap `<= 0` (the
   * in-band "cap not known to this reporter" encoding, Leg B) or a `null`
   * (unread) `retained_total_size_bytes` (Leg C; including the shipped-CLI
   * state where `getRetentionUsage()` threw while `query()` succeeded, Leg A,
   * which previously substituted a filler size of 0 and SIGNED a definitive
   * `retention_at_cap: false` while the prose hedged).
   * When false, every surface must treat at-cap as NOT DETERMINABLE: the prose
   * suppresses both the definitive "at a retention cap" claim AND the
   * flattering "never pruned / below both caps" reassurance, and the SIGNED
   * manifest serializes an explicit not-determinable marker instead of a
   * definitive `retention_at_cap` boolean.
   */
  retention_at_cap_determinable: boolean;
  /**
   * True when the ENTIRE retained window post-dates the quarter, so ZERO of the
   * quarter is covered even though the nominal signed span reaches the quarter
   * start (round-2 N2). Lets the cover banner state "none of this quarter is
   * covered" precisely rather than the generic "does not reach the start".
   */
  zero_of_quarter_covered: boolean;
  /** A lay-reader explanation suitable for printing in the PDF. */
  explanation: string;
  /**
   * WATCH-1: the F2 daemon enforcement store's disclosure, carried onto the
   * coverage report so the enforcement-summary section can state honestly
   * whether daemon-recorded enforcement events are included in the counts.
   */
  daemon_store: DaemonStoreDisclosure;
}

/**
 * A single wrapped-harness / agent inventory row (CNA Q1). Sourced from the
 * hub agent registry's `LocalAgentRecord` in a later wiring slice; slice 1
 * accepts these as injected input so the rendering path is real and tested,
 * and the CLI renders the honest coverage-basis note when no rows are
 * supplied.
 */
export interface InventoryAgentRow {
  agent_id: string;
  harness: string;
  model_vendor?: string;
  model_id?: string;
  wrapped_at?: string;
  status?: string;
}

/**
 * A connected upstream MCP server row (from `GET /api/proxy/servers`).
 * Injected in slice 1; rendered when present.
 */
export interface InventoryMcpServerRow {
  name: string;
  transport?: string;
  enabled?: boolean;
  connection_state?: string;
  tool_count?: number;
}

/**
 * An observed egress destination (the deny-and-record observe engine).
 * Destination metadata only, never payloads. Injected in slice 1.
 */
export interface InventoryObservedDestinationRow {
  host: string;
  port?: number;
  protocol?: string;
  times_seen?: number;
  exfil_risk?: boolean;
}

/**
 * The inventory snapshot fed into the pack. Each source is a {@link ReadOutcome}
 * over its row list, so the renderer prints honest language PER SOURCE through
 * the typed chokepoint: a table when the read is `populated`, a genuine "none
 * configured/recorded" ONLY when the read is `empty_verified` (a definitive
 * negative gated on a Complete witness), and an explicit "could not be read;
 * this section is incomplete" (with the reason) on `read_failed`. Never present
 * the inventory as exhaustive (spec risk #1): browser ChatGPT, Copilot inside
 * Office, and phones are invisible to Sanctuary's inventory even on a clean
 * read.
 */
export interface InventorySnapshot {
  agents: ReadOutcome<InventoryAgentRow[]>;
  mcp_servers: ReadOutcome<InventoryMcpServerRow[]>;
  observed_destinations: ReadOutcome<InventoryObservedDestinationRow[]>;
  /**
   * R4-2 (round-4 sweep 2026-07-15; gate-hardened): true when the observe
   * store carried candidate rows but NO fold watermark at read time -- the
   * signature of a store that has NOT completed a reconciling refresh. That is
   * a legacy PRE-#931 additive store, OR the narrow window of a post-#931
   * recompute-heal that crashed after writing rows but before advancing the
   * watermark (refresh.ts advances the watermark non-atomically after the
   * rows, by design). Under that condition the rendered rows may not reflect a
   * reconciled state: the `Seen` counts may OVERSTATE the exactly-once "since
   * this candidate record was created" basis the egress legend asserts, AND
   * the listed set may still include a destination the current policy permits
   * or one previously promoted/discarded (the pre-#931 additive engine did not
   * prune allowed rows and could resurrect removed ones). The renderer
   * discloses this without attributing a specific cause and directs the
   * operator to regenerate after `castle-wall observe candidates` (which
   * completes the reconciling refresh). The blocked-only fold basis holds
   * regardless, so every listed row is still a recorded denied observation.
   * Absent/false whenever a watermark is present (a completed refresh) and
   * whenever the observe read was not populated. The pack stays NON-MUTATING
   * and offline: it detects and discloses rather than folding (which would add
   * an allowlist + lock dependency and could fail generation). The signal is
   * sound in the dangerous direction -- a reconciled store always carries a
   * watermark, so a genuinely un-reconciled store is never missed.
   */
  observed_destinations_pre_idempotency?: boolean;
}

/**
 * Per-install facts that make the custody statement concrete. Custody mode
 * distinguishes a passphrase-held master key from an OS-keychain-held one.
 */
export interface CustodyFacts {
  /** How the fortress master key is held. */
  custody_mode: "passphrase" | "keychain" | "unknown";
  /**
   * Whether OUTBOUND is denied by default FOR THIS INSTALL, as a
   * {@link ReadOutcome} (sweep HIGH-2). This must never be a hardcoded "yes":
   * on a Windows or wrap-only (un-walled) host no machine-level egress
   * enforcement is armed, so a definitive "yes" would be a false security fact
   * in a signed document. When the pack does not probe the install's actual
   * egress/wall posture, this is `read_failed` and renders "not determinable
   * for this install", never an affirmative claim.
   */
  outbound_denied_by_default: ReadOutcome<boolean>;
}

/** MIME type of an emitted pack file. */
export type EvidencePackContentType =
  | "text/markdown"
  | "application/json"
  | "application/jsonl";

/**
 * The discrete, independently-verifiable exports the evidence pack gathers so a
 * third party can confirm the recorded enforcement history WITHOUT contacting
 * the vendor: the signed transparency-checkpoint bundle (verifiable offline
 * with the shipped `verify-transparency` tool under the Castle Wall signer
 * key), the audit-chain JSONL export (verifiable with the audit-chain
 * verifier), and, where public anchoring is enabled, the Rekor anchor
 * evidence. Each is optional; an absent export carries a reason string so the
 * appendix states honestly why it is not included rather than implying it was
 * withheld.
 */
export interface EvidencePackDiscreteExports {
  /**
   * The `SANCTUARY_TRANSPARENCY_BUNDLE_V1` JSON as a {@link ReadOutcome}:
   * `populated` when checkpoints exist and a single-key bundle was assembled,
   * `empty_verified` when the fortress genuinely has no checkpoints yet, and
   * `read_failed` when the checkpoints could not be gathered.
   */
  transparency: ReadOutcome<string>;
  /** The audit-chain JSONL export (entry + checkpoint/anchor records). */
  audit_chain: ReadOutcome<string>;
  /** The public-anchor (Rekor) evidence JSON (opt-in; typically empty_verified). */
  anchor: ReadOutcome<string>;
}

/** Input to {@link buildEvidencePack}. */
export interface EvidencePackInput {
  /** Firm name for the cover page. */
  firm_name: string;
  /** The quarter to report on. */
  quarter: CalendarQuarter;
  /** Optional override for `generated_at` so fixtures produce stable output. */
  generated_at_override?: string;
  /** Optional inventory snapshot (see {@link InventorySnapshot}). */
  inventory?: InventorySnapshot;
  /**
   * Per-install custody facts for the data-boundary statement, as a
   * {@link ReadOutcome} so a future custody-detection read failure renders
   * incomplete-with-reason rather than a definitive claim.
   */
  custody?: ReadOutcome<CustodyFacts>;
  /**
   * Optional discrete third-party verification exports gathered alongside the
   * pack (slice 2). When present, each export is signed into the manifest and
   * the verification appendix references the concrete file plus exact
   * instructions instead of conditional language.
   */
  discrete_exports?: EvidencePackDiscreteExports;
}

/** One emitted file in the evidence pack. */
export interface EvidencePackFile {
  filename: string;
  content: string;
  content_type: EvidencePackContentType;
  /** Lowercase hex SHA-256 of the content bytes. */
  sha256: string;
  /** Base64url Ed25519 signature over the SHA-256 digest, signer's primary identity. */
  signature: string;
}

/** Signed manifest for the evidence pack (mirrors the EU AI Act bundle pattern). */
export interface EvidencePackManifest {
  pack_version: "0.1-preview";
  slice: "walking-skeleton-v1";
  product_name: string;
  firm_name: string;
  quarter_label: string;
  period_start: string;
  period_end_exclusive: string;
  generated_at: string;
  signer: {
    did: string;
    public_key_base64url: string;
  };
  files: Array<{
    filename: string;
    content_type: EvidencePackContentType;
    sha256: string;
    signature: string;
  }>;
  /**
   * The covered-window shortfall disclosure, machine-readable. It is a UNION
   * so a read failure can never serialize a false "shortfall: false" into the
   * SIGNED manifest: when the audit log could not be read, `determinable` is
   * `false` and only a reason is present. A reader/verifier that sees
   * `determinable: false` knows coverage could not be computed.
   */
  coverage:
    | {
        determinable: true;
        covered_from: string;
        /** Exclusive upper bound of demonstrable coverage = min(quarter end, generation instant). */
        covered_to_exclusive: string;
        shortfall: boolean;
        /** True when the quarter had not ended at generation time (partial quarter). */
        in_progress_quarter: boolean;
        /**
         * Codex-F1 (dry-bar round 7): present ONLY when at-cap was actually
         * computable ({@link ShortfallReport.retention_at_cap_determinable}).
         * Exactly ONE of `retention_at_cap` /
         * `retention_at_cap_determinable: false` is serialized: a definitive
         * boolean when at-cap was computed, the explicit marker when it was
         * not. A definitive `retention_at_cap: false` ("not at a retention
         * cap") must NEVER be signed for a state where at-cap could not be
         * determined (a merged census with no usable per-store breakdown).
         */
        retention_at_cap?: boolean;
        /**
         * Serialized as `false` ONLY when at-cap was NOT determinable (and
         * `retention_at_cap` is then omitted). Omitted entirely (never `true`)
         * when `retention_at_cap` is present, so the shipped CLI path's
         * manifest shape is unchanged. Mirrors the top-level
         * `determinable: false` convention: a machine consumer that sees this
         * marker knows the at-cap fact was not computed, not that it is false.
         */
        retention_at_cap_determinable?: false;
        /**
         * G-1 (two-family gate follow-up): the F2 daemon enforcement store's
         * disclosure, machine-readable, so a verifier reading `shortfall: false`
         * is never left believing the census was complete when a root-owned
         * daemon store was present but excluded. `absent`/`included` mean the
         * count is the whole census / already merged; `present_unreadable`,
         * `present_tampered`, and `missing` (split evidence present but the
         * daemon store absent -- deleted or unverifiable, C1) mean these
         * coverage facts reflect the OPERATOR store
         * only (never a silent single-store signal, even in the signed manifest).
         */
        daemon_store: {
          status: DaemonStoreDisclosure["status"];
          unreadable_reason?: "privilege" | "io";
        };
      }
    | { determinable: false; reason: string };
  manifest_signature: string;
  disclaimer: string;
}

/** The complete generated pack (in-memory; the CLI writes it to disk). */
export interface EvidencePack {
  manifest: EvidencePackManifest;
  /** The signed Markdown + JSON files (excludes the PDF, which is unsigned). */
  files: EvidencePackFile[];
  /** The rendered PDF bytes. NOT cryptographically signed; verify the manifest. */
  pdf: Uint8Array;
  /**
   * The quarter aggregation as a {@link ReadOutcome} (for programmatic callers
   * / tests). `read_failed` when the audit log could not be read.
   */
  aggregation: ReadOutcome<QuarterAggregation>;
  /**
   * The shortfall report as a {@link ReadOutcome}. `read_failed` when the audit
   * log could not be read, so the covered-window bound is indeterminable.
   */
  shortfall: ReadOutcome<ShortfallReport>;
}
