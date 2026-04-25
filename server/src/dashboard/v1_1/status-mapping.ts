/**
 * Sanctuary v1.1 Dashboard — Agent Status Mapping
 *
 * Backend `HubAgentStatus` is the canonical surface
 * (active / paused / restarting / locked_down / unwrapping / error / unknown).
 * The dashboard renders a stable subset of operator-friendly labels and
 * presence glyphs derived from it. Mapping is normative: changing it
 * requires a coordinator amendment to the binding addendum.
 *
 * No-em-dash rule: every operator-visible string here uses periods, commas,
 * colons, or parentheses.
 */

import type { HubAgentStatus } from "../../contracts/v1.1/constants.js";
import type { LocalAgentRecord } from "../../contracts/v1.1/local-agent-records.js";

/** UI presence glyph value space. Stable enum the CSS layer keys against. */
export type UiPresenceGlyph = "online" | "idle" | "offline" | "away" | "unknown";

export interface UiStatusEntry {
  /** Backend status the entry maps from. */
  backend: HubAgentStatus;
  /** Operator-readable label. */
  label: string;
  /** UI presence glyph. */
  glyph: UiPresenceGlyph;
}

/**
 * Canonical mapping table per the binding addendum section 1.3. Verifiers
 * (tests, code-review checklists) may treat this as fixed. Drift is a UI
 * regression.
 */
export const STATUS_MAPPING: Record<HubAgentStatus, UiStatusEntry> = {
  active: { backend: "active", label: "Running", glyph: "online" },
  paused: { backend: "paused", label: "Paused", glyph: "idle" },
  restarting: { backend: "restarting", label: "Restarting", glyph: "idle" },
  locked_down: {
    backend: "locked_down",
    label: "Locked down",
    glyph: "offline",
  },
  unwrapping: { backend: "unwrapping", label: "Unwrapping", glyph: "idle" },
  error: { backend: "error", label: "Error", glyph: "away" },
  unknown: { backend: "unknown", label: "Unknown", glyph: "unknown" },
};

/**
 * Resolve a backend status to a UI label + glyph pair. Unknown values fall
 * back to the "unknown" entry rather than throwing.
 */
export function resolveStatus(status: HubAgentStatus): UiStatusEntry {
  return STATUS_MAPPING[status] ?? STATUS_MAPPING.unknown;
}

/**
 * Reason-class human strings. Backends emit a coarse class via
 * `LocalAgentRecord.status_reason_class`; the dashboard renders these
 * labels in tooltips on the status pill.
 */
export const STATUS_REASON_LABELS: Record<
  NonNullable<LocalAgentRecord["status_reason_class"]>,
  string
> = {
  operator_lockdown: "Locked down by operator",
  policy_breach: "Policy breach detected",
  budget_hard_cap: "Budget hard-cap reached",
  harness_error: "Harness reported an error",
  harness_unreachable: "Harness is unreachable",
  passphrase_required: "Cocoon passphrase required",
  config_drift: "Configuration drift detected",
  other: "Other reason. See activity feed.",
};

/**
 * Two-step Tier 1 control state. Mirrors the addendum section 3 lifecycle.
 * `idle` is the resting state, `pending` is post-202 awaiting inbox
 * approval, `engaged` is post-controller-call landed.
 */
export type Tier1ButtonState = "idle" | "pending" | "engaged";

export interface Tier1ButtonCopy {
  idle: string;
  pending: string;
  engaged: string;
  cancelled: string;
}

/**
 * Microcopy table for the Tier 1 buttons. Keys correspond to the
 * `operation_category` enum on `HubApprovalPendingItem`.
 */
export const TIER1_BUTTON_COPY: Record<string, Tier1ButtonCopy> = {
  lockdown: {
    idle: "Lockdown",
    pending: "Awaiting approval",
    engaged: "Lockdown ON",
    cancelled: "Lockdown not engaged",
  },
  unwrap: {
    idle: "Unwrap",
    pending: "Approval pending",
    engaged: "Unwrapped",
    cancelled: "Unwrap denied",
  },
  policy_change: {
    idle: "Edit policy",
    pending: "Policy change pending",
    engaged: "Policy bound",
    cancelled: "Policy change denied",
  },
  exit_bundle_export: {
    idle: "Snapshot now",
    pending: "Awaiting approval",
    engaged: "Bundle ready",
    cancelled: "Export denied",
  },
};
