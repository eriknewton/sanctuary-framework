/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: shared types
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared types for the quarterly law-firm evidence pack (slice 1, the
 * walking skeleton). The evidence pack is a signed, human-readable PDF an
 * office manager attaches to an insurance renewal or an outside-counsel
 * audit. It reuses the shipped tamper-evident audit log, the zero-dependency
 * PDF writer, and the signed-manifest bundle pattern; the NEW code here is the
 * calendar-quarter aggregation layer plus honest coverage/shortfall
 * disclosure.
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
 * `gate_*` families the enforcement gate writes) and, for cross-harness
 * approvals, from the entry `result`. `other` is every operation that is not
 * an enforcement-decision record (identity ops, state writes, heartbeats).
 *
 * HUMAN vs AUTOMATED (honesty, HIGH-1 fix): the interactive control-point
 * approval channel writes `gate_approve:` (a human approved) and `gate_deny:`
 * (a human denied) via `principal-policy/gate.ts`, while the automated tiers
 * write `gate_allow:` / `gate_allow_proxy:` / `gate_injection_block:` /
 * `gate_unclassified:` (no human). `gate_approve` and the two-phase
 * `gate_approval_proof` both map to `human_approved`. `gate_deny:` is
 * DELIBERATELY a blended `denied`: the gate emits the SAME `gate_deny:` op
 * string for a human control-point denial, an invalid-proof denial, and an
 * approval-channel-failure denial, so this layer cannot separate them from the
 * operation alone and must NOT render `denied` as purely-automated policy
 * enforcement. The only unambiguous human denial is the cross-harness inbox
 * resolution (`human_denied`). There is no `escalated` category: no code path
 * emits a `gate_escalate:` op (escalations resolve to approve/deny), so a row
 * for it would advertise a capability that does not exist.
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
export interface RetentionFacts {
  /** Configured maximum retained entry count (FIFO cap). */
  max_entries: number;
  /** Total entries currently retained across all time (all quarters). */
  retained_total: number;
  /**
   * Configured maximum total on-disk size in bytes (the OTHER FIFO cap). Audit
   * retention prunes on EITHER cap: 100,000 entries OR 100 MB by default (sweep
   * HIGH-5). 0/absent means the size cap is not known to this reporter.
   */
  max_total_size_bytes: number;
  /** Total on-disk size in bytes of the retained audit log, or null if unread. */
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
   * Distinguishing these two causes keeps the disclosure honest.
   */
  retention_at_cap: boolean;
  /** A lay-reader explanation suitable for printing in the PDF. */
  explanation: string;
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
        retention_at_cap: boolean;
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
