/**
 * Sanctuary v1.1. Operator Hub API Types
 *
 * Service-deps shapes + small payload types not already defined in the
 * v1.1 contracts. The contract surface (HubInboxItem, LocalAgentRecord,
 * HubActivityFeedEntry, HubAgentStatusSnapshot) is the source of truth for
 * everything that crosses the API boundary; types in this file are
 * implementation glue.
 */

import type { AuditLog } from "../operational/audit-log.js";
import type { AuditAttributionOptionsResolver } from "../castle-wall/audit-attribution.js";
import type { HubAgentControlAction } from "./constants.js";
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
  HubAgentStatusSnapshot,
} from "../contracts/v1.1/hub-events.js";
import type {
  LocalAgentRecord,
  LocalAgentRegistryFilter,
  LocalHarnessKind,
} from "../contracts/v1.1/local-agent-records.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";
import type { OperatorChatService } from "../chat/operator-chat-service.js";
import type { ConciergeService } from "../concierge/index.js";

/** Minimal invalidation header; consumers refetch the admission-filtered inbox. */
export interface HubInboxStreamFrame {
  item_id: string;
  kind: HubInboxKind;
  identity_id: string;
  fortress_id: string;
  emitted_at: string;
  resolved: boolean;
}

/** Synchronous dashboard invalidation sink; delivery is best effort, without retries. */
export interface HubStreamPublisher {
  publishInbox(frame: HubInboxStreamFrame): void;
  publishAgentStatus(snapshot: HubAgentStatusSnapshot): void;
}

/** Post-mutation registry observation; null means the agent was removed. */
export type HubAgentRegistryChangeListener = (agentId: string, record: LocalAgentRecord | null) => void;

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

export interface HubTemplateBindingApprovalEnqueuedResult
  extends HubTier1ApprovalEnqueuedResult {
  current_template_id?: ChannelTemplateId;
  proposed_template_id: ChannelTemplateId;
  compiled_policy_id: string;
}

export interface HubAgentLockdownControllerResult {
  outcome: "engaged" | "partial";
  new_status?: HubAgentStatus;
  agent_uid?: number;
  revoked_rule_ids?: string[];
  residual_allow_count?: number;
  reload_confirmed?: boolean;
  reason_code?: string;
}

/**
 * Dashboard-safe lift evidence; snapshot paths stay inside Castle Wall.
 * Payload fields must match HubApprovalPendingItem.resolution_payload in contracts/v1.1/hub-events.ts.
 */
export interface HubAgentLockdownLiftControllerResult {
  outcome: "restored" | "partial";
  new_status?: "active";
  restored_rule_ids: string[];
  removed_rule_ids: string[];
  reload_confirmed: boolean;
  reason_code?: string;
}

/**
 * Result returned from a fortress-scope Tier-1 action that has been
 * deferred to operator approval. Distinguished from the per-agent shape by
 * the absence of `agent_id` and the presence of `fortress_scope: true`.
 * The Tier 1 handler iterates fortress-wide on approval; nothing executes
 * until the operator resolves the inbox item.
 */
export interface HubTier1FortressApprovalEnqueuedResult {
  inbox_item_id: string;
  status: "approval_pending";
  operation_category: HubApprovalPendingItem["operation_category"];
  /** Always true. Distinguishes from the per-agent shape. */
  fortress_scope: true;
}

/**
 * Result returned from `fortressExportBundle` after a fortress-scope
 * exit-bundle export approval lands. Surfaced both in the inbox item's
 * `resolution_payload` and (separately) in an activity feed entry.
 *
 * `state_entry_count` is always present (including 0) so the dashboard
 * can surface the honest count and prevent "Bundle ready" from masking
 * an empty-state export. Must match the `resolution_payload` field
 * in `hub-events.ts` `HubApprovalPendingItem`.
 */
// Must match the safe projection in dashboard/v1_1/wiring.ts; keys belong only to the response-only delivery channel.
export interface HubFortressExportResult {
  bundle_dir: string;
  manifest_hash: string;
  artifact_count: number;
  /** Number of encrypted state entries included in the bundle (0 when none). */
  state_entry_count: number;
  /** Non-fatal export advisories (e.g., audit-receipt truncation). Absent when none. */
  warnings?: string[];
}

/** Response-only sibling of the safe item; must match one_time_export in hub/api-router.ts. */
export interface HubOneTimeExport {
  state_rekey_key: string;
  bundle_dir: string;
  manifest_hash: string;
}

/** Invocation-local delivery port; never attach to an inbox item or retained handler. */
export interface HubExportDeliveryReceiver {
  isLive(): boolean;
  receive(delivery: HubOneTimeExport): void;
}

const MAX_EXPORT_PATH_CHARACTERS = 4 * 1024; // Four KiB of path characters bounds reusable metadata, independently of filesystem limits.

/** Copy validated export metadata; invalid counts/paths throw and arbitrary advisories become fixed copy. */
export function projectHubExportResult(value: HubFortressExportResult): HubFortressExportResult {
  // SHA-256 is 32 bytes rendered as two hex characters per byte; paths have an explicit metadata cap.
  if (typeof value.bundle_dir !== "string" || !value.bundle_dir.startsWith("/") || value.bundle_dir.length > MAX_EXPORT_PATH_CHARACTERS ||
      value.bundle_dir.includes("\0") || typeof value.manifest_hash !== "string" ||
      !/^[a-f0-9]{64}$/.test(value.manifest_hash) ||
      !Number.isSafeInteger(value.artifact_count) || value.artifact_count <= 0 ||
      !Number.isSafeInteger(value.state_entry_count) || value.state_entry_count < 0) {
    throw new Error("Export metadata unavailable.");
  }
  return {
    bundle_dir: value.bundle_dir,
    manifest_hash: value.manifest_hash,
    artifact_count: value.artifact_count,
    state_entry_count: value.state_entry_count,
    ...(value.warnings?.length ? { warnings: ["Export advisories are available in the bundle."] } : {}),
  };
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
  /**
   * Required executor-side support probe. Served control flags intersect stored
   * permission with this probe; an unsupported handler cannot be advertised
   * or queued as Tier 1 work.
   */
  supports(
    action: HubAgentControlAction,
    agentId: string,
  ): boolean | Promise<boolean>;
  pause(agentId: string): Promise<HubAgentStatus>;
  resume(agentId: string): Promise<HubAgentStatus>;
  restart(agentId: string): Promise<HubAgentStatus>;
  /**
   * Apply an operator-approved unwrap. Called only after a Tier 1
   * approval lands through the inbox flow. Implementations SHOULD treat
   * unwrap as durable (fortress teardown + registry deregister).
   */
  unwrap(agentId: string): Promise<HubAgentStatus>;
  /**
   * Apply an operator-approved lockdown. Called only after a Tier 1
   * approval lands. Implementations SHOULD report observed network-stop
   * effects, not intents.
   */
  lockdown(
    agentId: string,
  ): Promise<HubAgentStatus | HubAgentLockdownControllerResult>;
  /** Restore per-agent network access after Tier 1 approval; only confirmed reloads restore status. */
  liftLockdown(agentId: string): Promise<HubAgentLockdownLiftControllerResult>;
  /**
   * Apply an operator-approved policy bind. Called only after a Tier 1
   * approval lands.
   */
  bindPolicy(agentId: string, policyId: string): Promise<void>;
  /** Apply an operator-approved channel-template binding. */
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
   * Ids of every condition that holds now, before any emission cap. The
   * aggregator clears a stored card only when its id is absent from this set;
   * a source without this method is reconciled against its emitted ids.
   * `undefined` means the source could not see every condition this call (its
   * bounded registry read returned a full page), so absence is not evidence and
   * the aggregator clears nothing for that kind until a later complete read.
   * Must match reconcile() in inbox-aggregator.ts and the projections in inbox-sources.ts.
   */
  listPresentSourceIds?(kind: HubInboxItem["kind"]): ReadonlySet<string> | undefined;
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
   * Current agent-error conditions, ordered by activity time without ageing out.
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
  /**
   * Optional Castle Wall audit-producer key used to re-verify producer-signed
   * evidence before projecting agent attribution.
   */
  pinnedProducerKeyB64url?: string | null;
  /**
   * Local fortress id needed to resolve macOS signed audit-token subjects.
   */
  subjectFortressId?: string | null;
  /**
   * Optional live resolver for Castle Wall read-side attribution. Production
   * readers use this so an absent producer key is retried after provisioning
   * and a present key is cached, rather than freezing legitimate signed rows
   * into an unknown-agent state at construction time.
   */
  resolveAuditAttribution?: AuditAttributionOptionsResolver;
  /**
   * Optional local agent registry snapshot used to translate verified
   * protection subjects back to the wrapped agent id for public hub surfaces.
   */
  listLocalAgents?: () => LocalAgentRecord[];
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
  /** Optional single-owner change subscription; return the disposer to detach it. */
  subscribe?(listener: HubAgentRegistryChangeListener): () => void;
  /**
   * Insert or replace a record. Used by wrap-side registration and by
   * read-side persistence refresh to merge records written after dashboard
   * boot.
   */
  put(record: LocalAgentRecord): void;
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
  /** Optional live dashboard sink; absence installs no store listeners. */
  streamPublisher?: HubStreamPublisher;
  /** Operator identity id this hub is scoped to. */
  identityId: string;
  /** Stable fortress id. */
  fortressId: string;
  /** Local agent registry source. */
  agentRegistry: HubAgentRegistrySource;
  /**
   * Optional best-effort persisted agent reader. When supplied, list
   * operations merge records written after hub construction before
   * returning the in-memory projection.
   */
  readPersistedLocalAgents?: () => LocalAgentRecord[];
  /**
   * Optional persisted agent writer. Used when approved hub actions mutate
   * registry-local fields that should survive refresh and restart.
   */
  writePersistedLocalAgents?: (records: LocalAgentRecord[]) => void;
  /**
   * Optional fortress storage path. When supplied, fortress-scope lockdown
   * approval writes a plaintext posture marker so read-only CLI surfaces can
   * signal LOCKED state without decrypting tenant data.
   */
  storagePath?: string;
  /** Inbox aggregation sources. */
  inboxSources: HubInboxSources;
  /** Activity feed sources. */
  activitySources: HubActivitySources;
  /** Policy + budget summary sources. */
  policyBudgetSources: HubPolicyAndBudgetSources;
  /** Underlying agent controller for control endpoints. */
  agentController: HubAgentController;
  /**
   * Optional fortress-scope exit-bundle export callback. Invoked only
   * after a fortress-scope Tier 1 approval lands. The callback owns its
   * own dependency wiring (storage, masterKey, identityManager, auditLog,
   * policy, reputationStore, state namespaces); the hub layer remains
   * crypto-agnostic. When omitted, the fortress export endpoint returns
   * `HubCapabilityError`.
   *
   * The hub passes the inbox item's id as `approvalAuditId` so the
   * callback can thread it into `exportExitBundle({ exportApprovalAuditId })`,
   * tying the manifest's `export_approval_audit_id` to the operator's
   * actual approval flow rather than an internally-generated value
   * (closes v1.0.2 backlog item (j)). The argument is optional for
   * backwards compatibility with existing callbacks.
   */
  fortressExportBundle?: (
    approvalAuditId?: string,
    receiver?: HubExportDeliveryReceiver,
  ) => Promise<HubFortressExportResult>;
  /**
   * Clock override for deterministic timestamp emission in tests.
   * Defaults to `() => new Date()` when omitted.
   */
  now?: () => Date;
  /**
   * Optional operator-chat service. When supplied, the hub exposes the
   * concierge chat endpoints; when omitted, those routes return
   * HubCapabilityError. Construction-time injection lets the dashboard
   * wiring layer build the chat service against the same audit log +
   * master key + storage backend as the rest of the v1.1 hub without
   * forcing the chat-service constructor through a circular import.
   * The direct-agent chat surface was removed in the v1.2 reshape
   * (2026-04-30); the field name is retained for source compatibility.
   */
  operatorChat?: OperatorChatService;
  /** Optional operator-only concierge service. This is hub/CLI only, never MCP-exposed. */
  concierge?: ConciergeService;
}

/**
 * Click-to-inspect panel returned by `openAgentInspectPanel`. The panel
 * surfaces the agent's recent activity, pending approvals routed through
 * this agent, and policy summary at a glance, repurposing the click-
 * to-chat wire-up shipped in PR #98 + PR #100. The direct-agent chat
 * surface was removed in the v1.2 reshape; this panel is the operational
 * destination for the click.
 */
export interface HubAgentInspectPanel {
  /** The agent the panel was opened on. */
  agent_id: string;
  /** ISO8601 timestamp the panel was opened. */
  opened_at: string;
  /** Recent activity-feed entries for this agent, oldest first. */
  recent_activity: HubActivityFeedEntry[];
  /**
   * Open Tier 1 inbox items routed through this agent. Empty when the
   * agent has no pending approvals.
   */
  pending_approvals: HubInboxItem[];
  /**
   * Bound policy summary for this agent. Null when the agent has no
   * channel-template binding (e.g. immediately after wrap, before the
   * operator picks a template).
   */
  policy_summary: HubPolicySummary | null;
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
