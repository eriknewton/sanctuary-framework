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
  | "escalated"
  | "injection_blocked"
  | "unclassified"
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
  /** True when the covered window does not reach the quarter start. */
  shortfall: boolean;
  /**
   * The instant from which coverage is demonstrable for this quarter: the
   * later of the quarter start and the earliest retained entry. Equal to the
   * quarter start when there is no shortfall.
   */
  covered_from: string;
  /** The quarter end (exclusive) - coverage always reaches the generation-day tail within the window. */
  covered_to_exclusive: string;
  /**
   * True when the retained log is at or above its FIFO cap, which means
   * pruning is actively occurring and early-quarter entries were LIKELY
   * dropped (as opposed to the fortress simply having no earlier activity).
   * Distinguishing these two causes keeps the disclosure honest.
   */
  retention_at_cap: boolean;
  /** A one-line, lay-reader explanation suitable for printing in the PDF. */
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
 * The inventory snapshot fed into the pack. Every field is optional: slice 1's
 * CLI does not yet enumerate live sources (the server surface that exposes the
 * registry / proxy / observe stores is a follow-on), so the inventory section
 * renders the honest per-machine coverage-basis statement and a clearly
 * labeled placeholder when a source is absent. Never present the inventory as
 * exhaustive (spec risk #1): browser ChatGPT, Copilot inside Office, and
 * phones are invisible to Sanctuary's inventory.
 */
export interface InventorySnapshot {
  agents?: InventoryAgentRow[];
  mcp_servers?: InventoryMcpServerRow[];
  observed_destinations?: InventoryObservedDestinationRow[];
}

/**
 * Per-install facts that make the custody statement concrete. Custody mode
 * distinguishes a passphrase-held master key from an OS-keychain-held one.
 */
export interface CustodyFacts {
  /** How the fortress master key is held. */
  custody_mode: "passphrase" | "keychain" | "unknown";
  /** Whether outbound is denied by default (true today by architecture). */
  no_outbound_by_default: boolean;
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
  /** Per-install custody facts for the data-boundary statement. */
  custody?: CustodyFacts;
}

/** One emitted file in the evidence pack. */
export interface EvidencePackFile {
  filename: string;
  content: string;
  content_type: "text/markdown" | "application/json";
  /** Lowercase hex SHA-256 of the content bytes. */
  sha256: string;
  /** Base64url Ed25519 signature over the SHA-256 digest, signer's primary identity. */
  signature: string;
}

/** Signed manifest for the evidence pack (mirrors the EU AI Act bundle pattern). */
export interface EvidencePackManifest {
  pack_version: "1.0";
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
    content_type: "text/markdown" | "application/json";
    sha256: string;
    signature: string;
  }>;
  /** The covered-window shortfall disclosure, machine-readable. */
  coverage: {
    covered_from: string;
    covered_to_exclusive: string;
    shortfall: boolean;
    retention_at_cap: boolean;
  };
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
  /** The quarter aggregation (returned for programmatic callers / tests). */
  aggregation: QuarterAggregation;
  /** The shortfall report (returned for programmatic callers / tests). */
  shortfall: ShortfallReport;
}
