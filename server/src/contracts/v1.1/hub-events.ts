/**
 * Sanctuary v1.1 — Operator Hub Event Contracts
 *
 * Shared shapes for the unified inbox, the activity feed, and the per-agent
 * status panels. The operator hub API workstream (Prompt 5) emits these; the
 * dashboard UI workstream (Prompt 8) consumes them. v1.2 mobile companion
 * planning will evaluate these shapes when it scopes a phone surface, but
 * v1.1 does not commit to mobile compatibility — these contracts are
 * tuned for the local dashboard surface only.
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
  PrivacyDestinationCategory,
} from "./constants.js";

/**
 * Allowed value space for `display_template_args`. Only safe primitives plus
 * a small enumerated value set are permitted. Free-form strings ARE NOT
 * accepted; the dashboard rejects rendering on any value outside this union.
 *
 * The renderer treats every value as data to interpolate into a fixed
 * template registered under `template_id` — never as raw content. This
 * defends against secrets, query text, file paths, and client names leaking
 * into inbox cards via stringly-typed display fields.
 */
export type HubDisplayTemplateArg =
  | { kind: "agent_id"; value: string }
  | { kind: "identity_id"; value: string }
  | { kind: "policy_id"; value: string }
  | { kind: "destination_category"; value: PrivacyDestinationCategory }
  | { kind: "tier"; value: "tier1" | "tier2" | "tier3" }
  | { kind: "count"; value: number }
  | { kind: "iso8601"; value: string }
  | { kind: "duration_ms"; value: number };

/**
 * Common header on every v1.1 hub inbox item.
 *
 * Display rendering uses a `template_id` plus typed args, NOT free-form
 * strings. The dashboard owns the template registry; backends only emit the
 * id and the args. This makes secret-leakage into inbox copy structurally
 * impossible: a backend cannot smuggle raw query content into a card by
 * accident, because there is no free-text channel.
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
   * Display template id. Resolved by the dashboard against a registered
   * template catalog; the catalog owns the actual render strings. Backends
   * MUST NOT emit raw display copy. Template id space is namespaced per
   * inbox kind, e.g., "approval_pending.tier1.export".
   */
  display_template_id: string;
  /**
   * Typed args interpolated into the template. Every value MUST be a
   * `HubDisplayTemplateArg` instance — no free-form strings. Renderers
   * reject any arg outside this union, which structurally blocks secret
   * leakage via inbox copy.
   */
  display_template_args: HubDisplayTemplateArg[];
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
   * does not reveal underlying tool args. Names align with the canonical
   * Tier 1 / Tier 2 sets in `server/src/principal-policy/loader.ts`. Names
   * NOT in the canonical loader (e.g., `exit_bundle_export`, `policy_change`,
   * `lockdown`, `unwrap`) are v1.1-new and MUST be added to the loader's
   * Tier 1 set in the same PR that lands their behavior. Drift is a release
   * blocker.
   */
  operation_category:
    | "state_export"
    | "state_import"
    | "state_delete"
    | "identity_rotate"
    | "reputation_export"
    | "reputation_import"
    | "sanctuary_export_identity_bundle"
    | "exit_bundle_export"
    | "exit_bundle_import"
    | "exit_bundle_rekey"
    | "policy_change"
    | "lockdown"
    | "unwrap"
    | "other";
  /** ISO8601 deadline after which the request will be auto-denied if applicable. */
  deadline?: string;
  /**
   * Result fields surfaced after the Tier 1 handler runs. Empty until
   * resolution. Populated for fortress-scope `exit_bundle_export` so the
   * dashboard exit-drill page can advance the wizard from the inbox
   * resolution alone, without round-tripping through the activity feed.
   * Per-agent items leave it undefined. Producers MUST keep field values
   * to safe metadata only (paths and hex hashes); raw secrets MUST NOT
   * appear here.
   */
  resolution_payload?: {
    bundle_dir?: string;
    manifest_hash?: string;
    artifact_count?: number;
  };
}

/**
 * Outbound traffic was blocked by the egress policy or the privacy filter.
 */
export interface HubBlockedEgressItem extends HubInboxItemHeader {
  kind: "blocked_egress";
  /**
   * Destination category. Same enum as the privacy filter so unified inbox,
   * privacy panel, and egress dashboards group consistently. Drift is a
   * release blocker.
   */
  destination_category: PrivacyDestinationCategory;
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
 *
 * Activity feed entries are read-from-storage projections of audit-chain
 * entries. They are NOT signed envelopes themselves; integrity derives from
 * the underlying audit entry. Consumers that need to verify the feed entry
 * MUST resolve it to the source audit entry by `entry_id` and verify there.
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
   * Display template id. Resolved by the dashboard against the activity-feed
   * template catalog. Backends MUST NOT emit raw summary text — the template
   * id plus typed args is the only legitimate channel.
   */
  display_template_id: string;
  /** Typed args. Same constraints as `HubInboxItemHeader.display_template_args`. */
  display_template_args: HubDisplayTemplateArg[];
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
  /**
   * Reason class for the current status. Same enum as
   * `LocalAgentRecord.status_reason_class`. Stable, not free text. Present
   * only when status is `locked_down`, `error`, or `restarting`.
   */
  status_reason_class?:
    | "operator_lockdown"
    | "policy_breach"
    | "budget_hard_cap"
    | "harness_error"
    | "harness_unreachable"
    | "passphrase_required"
    | "config_drift"
    | "other";
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
