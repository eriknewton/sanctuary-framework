/**
 * Sanctuary v1.1. Operator Hub API Types
 *
 * Service-deps shapes + small payload types not already defined in the
 * v1.1 contracts. The contract surface (HubInboxItem, LocalAgentRecord,
 * HubActivityFeedEntry, HubAgentStatusSnapshot) is the source of truth for
 * everything that crosses the API boundary; types in this file are
 * implementation glue.
 */

import type { AuditLog } from "../l2-operational/audit-log.js";
import type {
  HubAgentStatus,
  HubInboxKind,
} from "../contracts/v1.1/constants.js";
import type {
  HubApprovalPendingItem,
  HubBlockedEgressItem,
  HubPrivacyEventItem,
  HubBudgetWarningItem,
  HubRecoveryPromptItem,
  HubAgentErrorItem,
  HubInboxItem,
  HubActivityFeedEntry,
} from "../contracts/v1.1/hub-events.js";
import type {
  LocalAgentRecord,
  LocalAgentRegistryFilter,
  LocalHarnessKind,
} from "../contracts/v1.1/local-agent-records.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";

// -----------------------------------------------------------------------
// Agent control
// -----------------------------------------------------------------------

/**
 * Result returned from a synchronous (non-Tier-1) agent control action.
 */
export interface HubAgentControlResult {
  agent_id: string;
  prior_status: HubAgentStatus;
  new_status: HubAgentStatus;
  applied_at: string;
}

/**
 * Result returned from a Tier-1 agent control action that has been
 * deferred to operator approval. The hub returns the inbox item id so the
 * caller can poll or subscribe; nothing executes until the operator
 * resolves the inbox item.
 */
export interface HubTier1ApprovalEnqueuedResult {
  agent_id: string;
  inbox_item_id: string;
  status: "approval_pending";
  /**
   * Same enum as
   * `HubApprovalPendingItem.operation_category`. Surfaced separately so
   * non-inbox callers (CLI scripts, test harnesses) can act on the
   * category without a second fetch.
   */
  operation_category: HubApprovalPendingItem["operation_category"];
}

/**
 * Generic capability check delegated to the underlying harness controller.
 * The hub never performs the harness-side action itself; it asks the
 * controller to apply a transition and reports the new status back.
 *
 * Each callback returns the agent's new status after the action lands.
 * The controller MUST throw if it cannot apply the action; the hub maps
 * those throws to HubCapabilityError or HubConflictError.
 */
export interface HubAgentController {
  pause(agentId: string): Promise<HubAgentStatus>;
  resume(agentId: string): Promise<HubAgentStatus>;
  restart(agentId: string): Promise<HubAgentStatus>;
  /**
   * Apply an operator-approved unwrap. Called only after a Tier 1
   * approval lands through the inbox flow. Implementations SHOULD treat
   * unwrap as durable (cocoon teardown + registry deregister).
   */
  unwrap(agentId: string): Promise<HubAgentStatus>;
  /**
   * Apply an operator-approved lockdown. Called only after a Tier 1
   * approval lands. Implementations SHOULD treat lockdown as a hard-stop
   * (deny all egress, freeze gates) until explicitly cleared.
   */
  lockdown(agentId: string): Promise<HubAgentStatus>;
  /**
   * Apply an operator-approved policy bind. Called only after a Tier 1
   * approval lands.
   */
  bindPolicy(agentId: string, policyId: string): Promise<void>;
  /**
   * Apply a non-Tier-1 channel-template binding. Channel templates are
   * compositions over the canonical four slots; binding does not require
   * Tier 1 approval at v1.1.
   */
  bindChannelTemplate(
    agentId: string,
    templateId: ChannelTemplateId,
  ): Promise<void>;
}

// -----------------------------------------------------------------------
// Inbox aggregator source callbacks
// -----------------------------------------------------------------------

/**
 * Source-side input shapes the inbox aggregator pulls from. Each callback
 * returns recent occurrences pre-shaped as the underlying contract type;
 * the aggregator wraps them into HubInboxItem header form.
 *
 * Source callbacks are deliberately narrow; the hub does not know how to
 * compute privacy events or budget thresholds. Other workstreams own those
 * computations and feed them in through these callbacks.
 */
export interface HubInboxSources {
  /**
   * Currently unresolved Tier 1 / Tier 2 approval requests. Items already
   * in the hub-side inbox store are deduplicated by `item_id` against these.
   */
  listPendingApprovals: () => HubApprovalPendingItem[];
  /**
   * Recent egress denials. The hub surfaces each as a blocked-egress inbox
   * card. The caller is responsible for trimming to the recent window.
   */
  listRecentBlockedEgress: () => HubBlockedEgressItem[];
  /**
   * Recent privacy events the operator should attend to. The hub does NOT
   * surface every privacy event; it surfaces the ones that the privacy
   * core has already promoted to operator attention (denied, error, plus
   * filtered events flagged by the bound policy).
   */
  listRecentPrivacyEvents: () => HubPrivacyEventItem[];
  /**
   * Active budget warnings (soft-warn or hard-cap). Closed warnings are
   * not returned.
   */
  listActiveBudgetWarnings: () => HubBudgetWarningItem[];
  /**
   * Active recovery prompts (passphrase reset due, exit drill recommended,
   * keychain rebind required, etc.).
   */
  listActiveRecoveryPrompts: () => HubRecoveryPromptItem[];
  /**
   * Recent agent-error events.
   */
  listRecentAgentErrors: () => HubAgentErrorItem[];
}

// -----------------------------------------------------------------------
// Activity feed source callbacks
// -----------------------------------------------------------------------

export interface HubActivitySources {
  /**
   * Underlying audit log the activity feed projects from.
   */
  auditLog: AuditLog;
  /**
   * Identity id the dashboard is currently scoped to. Activity entries are
   * filtered to this identity; v1.1 is single-operator; the parameter is
   * here so v1.2 can scope per-identity without breaking the API.
   */
  identityId: string;
}

// -----------------------------------------------------------------------
// Policy + budget summary source callbacks
// -----------------------------------------------------------------------

/**
 * Lightweight summary of a bound policy. Suitable for UI cards. Raw policy
 * bytes never appear here.
 */
export interface HubPolicySummary {
  policy_id: string;
  display_label: string;
  /** ISO8601 timestamp the policy was bound. */
  bound_at: string;
  /** Number of agents currently bound to this policy. */
  agent_count: number;
  /** Channel template id the policy was compiled from, if applicable. */
  channel_template_id?: ChannelTemplateId;
}

/**
 * Lightweight summary of a budget bucket. Suitable for UI cards.
 */
export interface HubBudgetSummary {
  bucket_id: string;
  /** Display label drawn from the policy compile step. */
  display_label: string;
  unit: string;
  cap: number;
  used: number;
  /** Soft-warn threshold fraction (0..1). */
  soft_warn?: number;
  /** ISO8601 timestamp of last refresh. */
  last_refreshed_at: string;
}

export interface HubPolicyAndBudgetSources {
  listPolicySummaries: () => HubPolicySummary[];
  listBudgetSummaries: () => HubBudgetSummary[];
}

// -----------------------------------------------------------------------
// Local agent registry source callbacks
// -----------------------------------------------------------------------

/**
 * Read interface for the local agent registry. The hub does not invent
 * agent records; it pulls them from this source. Backend implementations
 * may persist records to disk or recompute them per call.
 */
export interface HubAgentRegistrySource {
  list(filter?: LocalAgentRegistryFilter): LocalAgentRecord[];
  get(agentId: string): LocalAgentRecord | null;
  /**
   * Update a single field on a record. The hub uses this to flip status
   * after a synchronous control action lands. Returns the updated record;
   * throws if the agent does not exist.
   */
  updateStatus(
    agentId: string,
    status: HubAgentStatus,
    statusReasonClass?: LocalAgentRecord["status_reason_class"],
  ): LocalAgentRecord;
  /**
   * Bind a different policy on a record. Used after an approved Tier 1
   * policy_change action lands.
   */
  updatePolicyBinding(agentId: string, policyId: string): LocalAgentRecord;
  /**
   * Bind a different channel template on a record. Non-Tier-1.
   */
  updateChannelTemplateBinding(
    agentId: string,
    templateId: ChannelTemplateId,
  ): LocalAgentRecord;
}

// -----------------------------------------------------------------------
// HubService deps
// -----------------------------------------------------------------------

export interface HubServiceDeps {
  /** Operator identity id this hub is scoped to. */
  identityId: string;
  /** Stable fortress id. */
  fortressId: string;
  /** Local agent registry source. */
  agentRegistry: HubAgentRegistrySource;
  /** Inbox aggregation sources. */
  inboxSources: HubInboxSources;
  /** Activity feed sources. */
  activitySources: HubActivitySources;
  /** Policy + budget summary sources. */
  policyBudgetSources: HubPolicyAndBudgetSources;
  /** Underlying agent controller for control endpoints. */
  agentController: HubAgentController;
  /**
   * Clock override for deterministic timestamp emission in tests.
   * Defaults to `() => new Date()` when omitted.
   */
  now?: () => Date;
}

// -----------------------------------------------------------------------
// Re-exports for convenience
// -----------------------------------------------------------------------

export type {
  HubAgentStatus,
  HubInboxKind,
  HubInboxItem,
  HubActivityFeedEntry,
  LocalAgentRecord,
  LocalAgentRegistryFilter,
  LocalHarnessKind,
};
