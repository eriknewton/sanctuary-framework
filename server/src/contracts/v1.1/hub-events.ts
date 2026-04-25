/**
 * Sanctuary v1.1 — Operator Hub Event Contracts
 *
 * Shared shapes for the unified inbox, the activity feed, and the per-agent
 * status panels. The operator hub API workstream (Prompt 5) emits these; the
 * dashboard UI workstream (Prompt 8) consumes them; the mobile-companion
 * planning workstream (Prompt 11) targets the same shapes for v1.2.
 *
 * Local-only invariant:
 * Every event in this file describes activity inside a single fortress on a
 * single operator's machine. Cross-fortress, fleet, and public-federation
 * events are out of scope.
 *
 * Safe-metadata invariant:
 * No raw sensitive content in any field. Inbox cards may carry display titles
 * and subtitles, but those titles MUST be derived from policy templates and
 * MUST NOT contain raw query text, tool args, filenames, client names,
 * passphrases, or secrets.
 */

import type {
  HubAgentStatus,
  HubInboxKind,
  SignatureScheme,
} from "./constants.js";

/**
 * Common header on every v1.1 hub inbox item.
 */
export interface HubInboxItemHeader {
  /** v1.1 event-shape version. */
  version: "1.1";
  /** Stable inbox-item id. SHOULD reference an audit-chain id where applicable. */
  item_id: string;
  /** Inbox kind discriminator. */
  kind: HubInboxKind;
  /** ISO8601 timestamp the item was created. */
  created_at: string;
  /** Wrapped agent id this item refers to, if applicable. */
  agent_id?: string;
  /** Operator identity id. */
  identity_id: string;
  /**
   * Display title for the dashboard card. MUST NOT contain raw sensitive content;
   * generated from a small set of templated strings.
   */
  display_title: string;
  /**
   * Optional one-line subtitle. Same constraints as display_title.
   */
  display_subtitle?: string;
  /** Whether the operator has resolved this inbox item. */
  resolved: boolean;
  /** ISO8601 timestamp of resolution, if resolved. */
  resolved_at?: string;
}

/**
 * A pending Tier 1 or Tier 2 approval surfaced to the operator inbox.
 */
export interface HubApprovalPendingItem extends HubInboxItemHeader {
  kind: "approval_pending";
  /** Policy tier the underlying operation falls under. */
  tier: "tier1" | "tier2";
  /**
   * Coarse operation category. Stable enum so the UI can group consistently;
   * does not reveal underlying tool args.
   */
  operation_category:
    | "state_export"
    | "state_import"
    | "key_rotate"
    | "identity_delete"
    | "reputation_import"
    | "exit_bundle_export"
    | "exit_bundle_import"
    | "rekey"
    | "policy_change"
    | "lockdown"
    | "unwrap"
    | "other";
  /** ISO8601 deadline after which the request will be auto-denied if applicable. */
  deadline?: string;
}

/**
 * Outbound traffic was blocked by the egress policy or the privacy filter.
 */
export interface HubBlockedEgressItem extends HubInboxItemHeader {
  kind: "blocked_egress";
  /**
   * Coarse destination category. Mirrors the privacy destination categories
   * for consistency in the unified inbox.
   */
  destination_category: string;
  /**
   * Why the egress was blocked. Coarse enum, not free text. Specific policy
   * rule names are NOT revealed.
   */
  block_reason_class:
    | "egress_policy_deny"
    | "budget_exceeded"
    | "privacy_fail_closed"
    | "privacy_deny_rule"
    | "lockdown_active"
    | "other";
}

/**
 * A privacy event surfaced to the inbox. References the underlying privacy
 * event id; the inbox card is a thin pointer, not a duplicate of the event.
 */
export interface HubPrivacyEventItem extends HubInboxItemHeader {
  kind: "privacy_event";
  /** Foreign key into the privacy-event chain. */
  privacy_event_id: string;
  /** Privacy event kind. */
  privacy_event_kind:
    | "filtered"
    | "allowed"
    | "denied"
    | "error"
    | "rehydrated";
}

/**
 * A budget threshold was crossed.
 */
export interface HubBudgetWarningItem extends HubInboxItemHeader {
  kind: "budget_warning";
  /** Budget bucket identifier (daily / monthly / per-agent / custom). */
  bucket: "daily" | "monthly" | "per_agent" | "custom";
  /** Soft-warn or hard-cap. Hard-cap usually requires operator unblock. */
  severity: "soft_warn" | "hard_cap";
  /** Percentage of budget used at event time. 0..1. */
  used_fraction: number;
}

/**
 * Recovery prompt — operator should run a recovery flow (passphrase reset,
 * keychain rebind, exit drill, etc.).
 */
export interface HubRecoveryPromptItem extends HubInboxItemHeader {
  kind: "recovery_prompt";
  /** Coarse recovery class. */
  recovery_class:
    | "passphrase_reset"
    | "keychain_rebind"
    | "config_backup_restore"
    | "exit_drill"
    | "other";
}

/**
 * Agent reported an internal error.
 */
export interface HubAgentErrorItem extends HubInboxItemHeader {
  kind: "agent_error";
  /** Stable error code class. Implementation-specific catalog. */
  error_class: string;
  /** Whether the agent is still serving traffic after the error. */
  agent_still_active: boolean;
}

/**
 * Discriminated union of every v1.1 hub inbox item.
 */
export type HubInboxItem =
  | HubApprovalPendingItem
  | HubBlockedEgressItem
  | HubPrivacyEventItem
  | HubBudgetWarningItem
  | HubRecoveryPromptItem
  | HubAgentErrorItem;

/**
 * Activity feed entry. The feed is a flat stream backed by the audit chain;
 * inbox items often reference a feed entry, but feed entries are not always
 * inbox items.
 */
export interface HubActivityFeedEntry {
  version: "1.1";
  /** Audit-chain entry id. */
  entry_id: string;
  /** ISO8601 timestamp. */
  emitted_at: string;
  /** Wrapped agent id, if applicable. */
  agent_id?: string;
  /** Identity id. */
  identity_id: string;
  /** Stable category enum. */
  category:
    | "policy_decision"
    | "approval"
    | "denial"
    | "egress"
    | "privacy"
    | "handoff"
    | "lifecycle"
    | "config"
    | "other";
  /**
   * Coarse summary text. Templated; no raw sensitive content.
   */
  summary: string;
  /** Underlying signature scheme on the source audit entry. */
  signature_scheme: SignatureScheme;
}

/**
 * Per-agent status snapshot returned by the hub API. Mirrors the agent
 * registry record but is computed-on-read; it does not flow through the
 * audit chain by itself.
 */
export interface HubAgentStatusSnapshot {
  version: "1.1";
  agent_id: string;
  status: HubAgentStatus;
  /** Reason text for the current status, when status is locked_down or error. */
  status_reason?: string;
  /** ISO8601 last-seen timestamp. */
  last_activity_at: string;
  /** Inbox-item ids currently unresolved against this agent. */
  open_inbox_item_ids: string[];
}

/**
 * Type guard for a hub inbox item with a specific kind.
 */
export function isHubInboxItemOfKind<K extends HubInboxItem["kind"]>(
  item: HubInboxItem,
  kind: K,
): item is Extract<HubInboxItem, { kind: K }> {
  return item.kind === kind;
}
