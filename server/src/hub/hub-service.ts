/**
 * Sanctuary v1.1. Operator Hub Service
 *
 * Public API the router calls. Owns no domain logic: it composes the
 * agent registry source, the inbox aggregator + store, the activity feed
 * projection, and the agent controller.
 *
 * Tier 1 enforcement contract:
 * Hub control endpoints for `unwrap`, `lockdown`, and `policy_change` MUST
 * NOT execute synchronously. The hub enqueues an `approval_pending` inbox
 * item carrying the operation_category and binds the controller call to
 * the inbox-store resolution handler. Only operator approval through the
 * inbox path causes the controller call to fire. The dashboard never
 * auto-approves Tier 1 work.
 */

import { randomUUID } from "node:crypto";

import type {
  HubAgentStatusSnapshot,
  HubApprovalPendingItem,
  HubInboxItem,
  HubActivityFeedEntry,
} from "../contracts/v1.1/hub-events.js";
import type {
  LocalAgentRecord,
  LocalAgentRegistryFilter,
} from "../contracts/v1.1/local-agent-records.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";
import { CHANNEL_TEMPLATE_IDS } from "../policy-engine/constants.js";
import { applyChannelTemplate } from "../policy-engine/channel-templates.js";

import {
  HUB_AGENT_CONTROL_ACTIONS,
  HUB_INBOX_TEMPLATE_NAMESPACES,
  HUB_TIER_1_AGENT_CONTROL_ACTIONS,
  type HubAgentControlAction,
  type HubInboxAction,
  type HubTier1AgentControlAction,
} from "./constants.js";
import {
  HubCapabilityError,
  HubConflictError,
  HubLocalOnlyError,
  HubNotFoundError,
  HubValidationError,
} from "./errors.js";
import { aggregateInbox } from "./inbox-aggregator.js";
import { HubInboxStore } from "./inbox-store.js";
import { aggregateActivity } from "./activity-feed.js";
import type {
  HubAgentControlResult,
  HubBudgetSummary,
  HubDirectAgentSessionRequestResult,
  HubFortressExportResult,
  HubPolicySummary,
  HubServiceDeps,
  HubTier1ApprovalEnqueuedResult,
  HubTier1FortressApprovalEnqueuedResult,
  HubTemplateBindingApprovalEnqueuedResult,
} from "./types.js";
import type {
  ConciergeResponse,
  DirectAgentSendResponse,
  OperatorChatMessage,
  OperatorChatSession,
} from "../chat/operator-chat-types.js";

function isTier1ControlAction(
  action: HubAgentControlAction,
): action is HubTier1AgentControlAction {
  return (HUB_TIER_1_AGENT_CONTROL_ACTIONS as readonly string[]).includes(
    action,
  );
}

function checkChannelTemplateId(value: unknown): ChannelTemplateId {
  if (
    typeof value === "string" &&
    (CHANNEL_TEMPLATE_IDS as readonly string[]).includes(value)
  ) {
    return value as ChannelTemplateId;
  }
  throw new HubValidationError(
    `channel_template_id must be one of: ${CHANNEL_TEMPLATE_IDS.join(", ")}`,
  );
}

function snapshotForRecord(
  record: LocalAgentRecord,
  openInboxItemIds: string[],
): HubAgentStatusSnapshot {
  const snap: HubAgentStatusSnapshot = {
    version: "1.1",
    agent_id: record.agent_id,
    status: record.status,
    last_activity_at: record.last_activity_at,
    open_inbox_item_ids: openInboxItemIds,
  };
  if (record.status_reason_class) {
    snap.status_reason_class = record.status_reason_class;
  }
  return snap;
}

export class HubService {
  private deps: HubServiceDeps;
  private inboxStore: HubInboxStore;

  constructor(deps: HubServiceDeps) {
    this.deps = deps;
    this.inboxStore = new HubInboxStore();
  }

  // ── Internal helpers ────────────────────────────────────────────────

  private now(): Date {
    return this.deps.now ? this.deps.now() : new Date();
  }

  private nowIso(): string {
    return this.now().toISOString();
  }

  private refreshPersistedLocalAgents(): void {
    const readPersistedLocalAgents = this.deps.readPersistedLocalAgents;
    if (!readPersistedLocalAgents) return;
    for (const record of readPersistedLocalAgents()) {
      this.deps.agentRegistry.put(record);
    }
  }

  // ── Inbox ───────────────────────────────────────────────────────────

  listInbox(): HubInboxItem[] {
    const items = aggregateInbox(this.deps.inboxSources, this.inboxStore);
    return items.filter((i) => i.identity_id === this.deps.identityId);
  }

  async resolveInboxItem(
    itemId: string,
    action: HubInboxAction,
  ): Promise<HubInboxItem> {
    // Aggregate first so source-pulled items (egress, privacy, budget,
    // recovery, agent_error) are present in the store before we resolve.
    // Tier 1 hub-enqueued items already live in the store regardless.
    aggregateInbox(this.deps.inboxSources, this.inboxStore);
    return this.inboxStore.resolve(itemId, action, this.nowIso());
  }

  // ── Agents ──────────────────────────────────────────────────────────

  listAgents(filter?: LocalAgentRegistryFilter): LocalAgentRecord[] {
    this.refreshPersistedLocalAgents();
    const safeFilter: LocalAgentRegistryFilter = {
      ...(filter ?? {}),
      identity_id: this.deps.identityId,
    };
    return this.deps.agentRegistry.list(safeFilter);
  }

  getAgent(agentId: string): LocalAgentRecord {
    const record = this.deps.agentRegistry.get(agentId);
    if (!record) throw new HubNotFoundError(`agent ${agentId}`);
    if (record.identity_id !== this.deps.identityId) {
      // Records bound to other identities are out of scope; v1.2 multi-
      // identity work will revisit; v1.1 single-operator denies.
      throw new HubLocalOnlyError(
        "agent belongs to a different operator identity",
      );
    }
    return record;
  }

  getAgentStatusSnapshot(agentId: string): HubAgentStatusSnapshot {
    const record = this.getAgent(agentId);
    const openIds = this.listInbox()
      .filter((i) => !i.resolved && i.agent_id === record.agent_id)
      .map((i) => i.item_id);
    return snapshotForRecord(record, openIds);
  }

  // ── Agent control ──────────────────────────────────────────────────

  async controlAgent(
    agentId: string,
    action: HubAgentControlAction,
  ): Promise<HubAgentControlResult | HubTier1ApprovalEnqueuedResult> {
    if (!(HUB_AGENT_CONTROL_ACTIONS as readonly string[]).includes(action)) {
      throw new HubValidationError(`unknown control action: ${action}`);
    }
    const record = this.getAgent(agentId);
    this.assertCapability(record, action);

    if (isTier1ControlAction(action)) {
      return this.enqueueTier1ControlAction(record, action);
    }

    const prior = record.status;
    let next: LocalAgentRecord;
    switch (action) {
      case "pause": {
        const status = await this.deps.agentController.pause(agentId);
        next = this.deps.agentRegistry.updateStatus(agentId, status);
        break;
      }
      case "resume": {
        const status = await this.deps.agentController.resume(agentId);
        next = this.deps.agentRegistry.updateStatus(agentId, status);
        break;
      }
      case "restart": {
        const status = await this.deps.agentController.restart(agentId);
        next = this.deps.agentRegistry.updateStatus(agentId, status);
        break;
      }
      default:
        throw new HubValidationError(`unhandled control action: ${action}`);
    }
    return {
      agent_id: agentId,
      prior_status: prior,
      new_status: next.status,
      applied_at: this.nowIso(),
    };
  }

  /**
   * Capability gate. Returns silently when the action is supported by the
   * harness; throws HubCapabilityError when not.
   */
  private assertCapability(
    record: LocalAgentRecord,
    action: HubAgentControlAction,
  ): void {
    const c = record.capabilities;
    const supports: Record<HubAgentControlAction, boolean> = {
      pause: c.can_pause,
      resume: c.can_resume,
      restart: c.can_restart,
      unwrap: c.can_unwrap,
      lockdown: c.can_lockdown,
    };
    if (!supports[action]) throw new HubCapabilityError(action);
  }

  /**
   * Build a Tier 1 inbox item for an unwrap/lockdown/policy_change action
   * and bind the controller call to its resolution.
   */
  private enqueueTier1ControlAction(
    record: LocalAgentRecord,
    action: HubTier1AgentControlAction,
  ): HubTier1ApprovalEnqueuedResult {
    const operationCategory: HubApprovalPendingItem["operation_category"] =
      action;
    const itemId = `tier1.${action}.${record.agent_id}.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      agent_id: record.agent_id,
      identity_id: record.identity_id,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.${action}`,
      display_template_args: [
        { kind: "agent_id", value: record.agent_id },
        { kind: "identity_id", value: record.identity_id },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: operationCategory,
    };

    this.inboxStore.enqueueTier1(item, async (approvedItem, decision) => {
      if (decision === "deny") return;
      switch (action) {
        case "unwrap": {
          const status = await this.deps.agentController.unwrap(
            approvedItem.agent_id ?? record.agent_id,
          );
          this.deps.agentRegistry.updateStatus(
            record.agent_id,
            status,
            "operator_lockdown",
          );
          this.deps.activitySources.auditLog.append(
            "l2",
            "agent_unwrap_engaged",
            this.deps.identityId,
            {
              agent_id: record.agent_id,
              identity_id: record.identity_id,
              operator_audit_id: itemId,
            },
          );
          return;
        }
        case "lockdown": {
          const status = await this.deps.agentController.lockdown(
            approvedItem.agent_id ?? record.agent_id,
          );
          this.deps.agentRegistry.updateStatus(
            record.agent_id,
            status,
            "operator_lockdown",
          );
          this.deps.activitySources.auditLog.append(
            "l2",
            "agent_lockdown_engaged",
            this.deps.identityId,
            {
              agent_id: record.agent_id,
              identity_id: record.identity_id,
              operator_audit_id: itemId,
            },
          );
          return;
        }
      }
    });

    return {
      agent_id: record.agent_id,
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: operationCategory,
    };
  }

  /**
   * Bind a different policy on an agent. Tier 1: enqueues an approval
   * pending inbox item rather than executing synchronously.
   */
  bindAgentPolicy(
    agentId: string,
    policyId: string,
  ): HubTier1ApprovalEnqueuedResult {
    if (!policyId || typeof policyId !== "string") {
      throw new HubValidationError("policy_id required");
    }
    const record = this.getAgent(agentId);
    const itemId = `tier1.policy_change.${record.agent_id}.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      agent_id: record.agent_id,
      identity_id: record.identity_id,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.policy_change`,
      display_template_args: [
        { kind: "agent_id", value: record.agent_id },
        { kind: "policy_id", value: policyId },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "policy_change",
    };

    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") return;
      await this.deps.agentController.bindPolicy(record.agent_id, policyId);
      this.deps.agentRegistry.updatePolicyBinding(record.agent_id, policyId);
      this.deps.activitySources.auditLog.append(
        "l2",
        "agent_policy_change_engaged",
        this.deps.identityId,
        {
          agent_id: record.agent_id,
          identity_id: record.identity_id,
          operator_audit_id: itemId,
          policy_id: policyId,
        },
      );
    });

    return {
      agent_id: record.agent_id,
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "policy_change",
    };
  }

  /**
   * Bind a different channel template. Tier 1: enqueues a policy_change
   * approval item and only applies the binding after operator approval.
   */
  bindAgentChannelTemplate(
    agentId: string,
    rawTemplateId: unknown,
  ): HubTemplateBindingApprovalEnqueuedResult {
    const templateId = checkChannelTemplateId(rawTemplateId);
    const record = this.getAgent(agentId);
    const currentTemplate =
      typeof record.channel_template_id === "string" &&
      (CHANNEL_TEMPLATE_IDS as readonly string[]).includes(record.channel_template_id)
        ? (record.channel_template_id as ChannelTemplateId)
        : undefined;
    const compiled = applyChannelTemplate(templateId, {
      agent_id: record.agent_id,
      counterparty: this.deps.identityId,
      fortress_id: this.deps.fortressId,
      policy_version: Date.now(),
    });
    const compiledPolicyId = `${record.agent_id}:${templateId}:v${compiled.policy_version}`;
    const itemId = `tier1.policy_change.template.${record.agent_id}.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      agent_id: record.agent_id,
      identity_id: record.identity_id,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.policy_change_template`,
      display_template_args: [
        { kind: "agent_id", value: record.agent_id },
        { kind: "policy_id", value: templateId },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "policy_change",
    };

    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") {
        this.deps.activitySources.auditLog.append(
          "l2",
          "agent_policy_change_denied",
          this.deps.identityId,
          {
            agent_id: record.agent_id,
            identity_id: record.identity_id,
            operator_audit_id: itemId,
            current_template: currentTemplate ?? null,
            proposed_template: templateId,
          },
        );
        return;
      }
      await this.deps.agentController.bindChannelTemplate(record.agent_id, templateId);
      this.deps.agentRegistry.updateChannelTemplateBinding(record.agent_id, templateId);
      this.deps.agentRegistry.updatePolicyBinding(record.agent_id, compiledPolicyId);
      this.deps.writePersistedLocalAgents?.(this.deps.agentRegistry.list());
      this.deps.activitySources.auditLog.append(
        "l2",
        "agent_policy_change_engaged",
        this.deps.identityId,
        {
          agent_id: record.agent_id,
          identity_id: record.identity_id,
          operator_audit_id: itemId,
          current_template: currentTemplate ?? null,
          proposed_template: templateId,
          policy_id: compiledPolicyId,
        },
      );
    });

    return {
      agent_id: record.agent_id,
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "policy_change",
      ...(currentTemplate ? { current_template_id: currentTemplate } : {}),
      proposed_template_id: templateId,
      compiled_policy_id: compiledPolicyId,
    };
  }

  // ── Fortress-scope Tier 1 actions ──────────────────────────────────

  /**
   * Enqueue a fortress-scope Tier 1 lockdown. One inbox item is created;
   * on operator approval the handler iterates `agentController.lockdown`
   * over every wrapped agent for the bound identity, captures partial
   * failures as per-agent `agent_error` inbox items, and emits a single
   * `lifecycle` activity entry. Stacked fortress lockdowns are rejected
   * with `HubConflictError` until the prior pending item resolves.
   */
  enqueueFortressLockdown(): HubTier1FortressApprovalEnqueuedResult {
    this.assertNoPendingFortressTier1("lockdown");

    const itemId = `tier1.fortress.lockdown.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      identity_id: this.deps.identityId,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.fortress_lockdown`,
      display_template_args: [
        { kind: "identity_id", value: this.deps.identityId },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "lockdown",
    };

    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") return;
      const records = this.deps.agentRegistry.list({
        identity_id: this.deps.identityId,
      });
      const failed: Array<{ agent_id: string; error: string }> = [];
      for (const record of records) {
        try {
          const status = await this.deps.agentController.lockdown(
            record.agent_id,
          );
          this.deps.agentRegistry.updateStatus(
            record.agent_id,
            status,
            "operator_lockdown",
          );
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          failed.push({ agent_id: record.agent_id, error: msg });
        }
      }
      // One fortress-level activity entry, regardless of partial-failure
      // count. Per-agent failures surface as individual agent_error items
      // below.
      this.deps.activitySources.auditLog.append(
        "l2",
        "fortress_lockdown_engaged",
        this.deps.identityId,
        {
          fortress_id: this.deps.fortressId,
          locked_count: records.length - failed.length,
          failed_count: failed.length,
        },
      );
      // One agent_error inbox item per per-agent failure; the operator
      // sees both the fortress success AND the failed agents.
      for (const f of failed) {
        const errId = `fortress.lockdown.error.${f.agent_id}.${randomUUID()}`;
        this.inboxStore.upsertFromSource({
          version: "1.1",
          item_id: errId,
          kind: "agent_error",
          created_at: this.nowIso(),
          identity_id: this.deps.identityId,
          agent_id: f.agent_id,
          display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.agent_error}.E_FORTRESS_LOCKDOWN_FAILED`,
          display_template_args: [
            { kind: "agent_id", value: f.agent_id },
          ],
          resolved: false,
          error_class: "E_FORTRESS_LOCKDOWN_FAILED",
          agent_still_active: true,
        });
      }
    });

    return {
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "lockdown",
      fortress_scope: true,
    };
  }

  /**
   * Enqueue a fortress-scope Tier 1 exit-bundle export. One inbox item is
   * created; on operator approval the handler invokes
   * `fortressExportBundle()` once at fortress scope, attaches
   * `bundle_dir` + `manifest_hash` + `artifact_count` to the inbox item's
   * `resolution_payload`, and emits a `lifecycle` activity entry.
   * Stacked exports are rejected with `HubConflictError`.
   */
  enqueueFortressExportBundle(): HubTier1FortressApprovalEnqueuedResult {
    if (!this.deps.fortressExportBundle) {
      throw new HubCapabilityError("fortress_exit_bundle_export");
    }
    this.assertNoPendingFortressTier1("exit_bundle_export");

    const itemId = `tier1.fortress.exit_bundle_export.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      identity_id: this.deps.identityId,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.fortress_exit_bundle_export`,
      display_template_args: [
        { kind: "identity_id", value: this.deps.identityId },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "exit_bundle_export",
    };

    const fortressExportBundle = this.deps.fortressExportBundle;
    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") return;
      // Thread the inbox item id into the callback as the approval audit
      // id so `exportExitBundle()` can embed it in the manifest's
      // `export_approval_audit_id` field (v1.0.2 (j)).
      const result: HubFortressExportResult = await fortressExportBundle(
        itemId,
      );
      this.deps.activitySources.auditLog.append(
        "l2",
        "exit_bundle_exported",
        this.deps.identityId,
        {
          fortress_id: this.deps.fortressId,
          bundle_dir: result.bundle_dir,
          manifest_hash: result.manifest_hash,
          artifact_count: result.artifact_count,
        },
      );
      return {
        resolution_payload: {
          bundle_dir: result.bundle_dir,
          manifest_hash: result.manifest_hash,
          artifact_count: result.artifact_count,
        },
      };
    });

    return {
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "exit_bundle_export",
      fortress_scope: true,
    };
  }

  /**
   * Reject stacked fortress-scope Tier 1 items. The check scans the inbox
   * store for an unresolved `approval_pending` item with the same
   * `operation_category` and no `agent_id` (the fortress-scope marker).
   */
  private assertNoPendingFortressTier1(
    operationCategory: HubApprovalPendingItem["operation_category"],
  ): void {
    for (const item of this.inboxStore.list()) {
      if (item.kind !== "approval_pending") continue;
      if (item.resolved) continue;
      if (item.agent_id !== undefined) continue;
      if (item.operation_category !== operationCategory) continue;
      throw new HubConflictError(
        `fortress-scope ${operationCategory} already pending; resolve the existing inbox item first`,
      );
    }
  }

  // ── Activity feed ───────────────────────────────────────────────────

  async listActivity(filter: {
    since?: string;
    limit?: number;
    agent_id?: string;
    category?: HubActivityFeedEntry["category"];
  }): Promise<HubActivityFeedEntry[]> {
    return aggregateActivity(this.deps.activitySources, filter);
  }

  // ── Policy + budget summaries ──────────────────────────────────────

  listPolicySummaries(): HubPolicySummary[] {
    return this.deps.policyBudgetSources.listPolicySummaries();
  }

  listBudgetSummaries(): HubBudgetSummary[] {
    return this.deps.policyBudgetSources.listBudgetSummaries();
  }

  // ── Local-only enforcement helpers ─────────────────────────────────

  /**
   * Validate that a caller-supplied filter does not request cross-fortress
   * scope; v1.1 hub is single-fortress; the filter rejects fortress-bridging
   * fields outright; v1.3 federation will introduce an alternate surface.
   */
  static assertLocalOnlyFilter(filter: Record<string, unknown> | null): void {
    if (!filter) return;
    for (const key of Object.keys(filter)) {
      if (
        key === "fortress_id" ||
        key === "peer_id" ||
        key === "remote_fortress_id"
      ) {
        throw new HubLocalOnlyError(
          `filter field '${key}' is not supported at v1.1 (cross-fortress reach)`,
        );
      }
    }
  }

  /**
   * Test/inspection helper. Not part of the public service surface.
   */
  inboxStoreSize(): number {
    return this.inboxStore.size();
  }

  // ── Operator chat (WP-V1.2-4) ──────────────────────────────────────

  private requireOperatorChat(): NonNullable<HubServiceDeps["operatorChat"]> {
    if (!this.deps.operatorChat) {
      throw new HubCapabilityError("operator_chat_not_wired");
    }
    return this.deps.operatorChat;
  }

  /**
   * Operator submit on the concierge chat surface. Pass-through to the
   * operator-chat-service which owns substrate-selector routing, PII
   * filtering, persistence, and audit emission.
   */
  async sendConcierge(query: string): Promise<ConciergeResponse> {
    const chat = this.requireOperatorChat();
    return chat.sendConcierge(query);
  }

  /**
   * Read the persisted concierge thread.
   */
  async getConciergeHistory(): Promise<OperatorChatMessage[]> {
    const chat = this.requireOperatorChat();
    return chat.getConciergeHistory();
  }

  /**
   * Request a direct-agent chat session on a wrapped agent. Tier 1:
   * enqueues an inbox approval item. On approve, the operator-chat-
   * service opens the session via `openDirectAgentSession` and emits
   * `direct_agent_session_open`.
   *
   * The returned `inbox_item_id` is the same id the chat surface polls
   * (or subscribes to via SSE) until the session is approved or denied.
   * On approval the session_id surfaces through the
   * `direct_agent_session_open` audit event; the dashboard's chat
   * surface listens for that event to swap into the active-session UI.
   */
  requestDirectAgentSession(
    agentId: string,
    expiresAtIsoOverride?: string,
  ): HubDirectAgentSessionRequestResult {
    const chat = this.requireOperatorChat();
    const record = this.getAgent(agentId);
    const itemId = `tier1.direct_agent_session_open.${record.agent_id}.${randomUUID()}`;
    const channelTemplateId =
      typeof record.channel_template_id === "string"
        ? record.channel_template_id
        : null;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      agent_id: record.agent_id,
      identity_id: record.identity_id,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.direct_agent_session_open`,
      display_template_args: [
        { kind: "agent_id", value: record.agent_id },
        { kind: "identity_id", value: record.identity_id },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "direct_agent_session_open",
    };

    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") {
        this.deps.activitySources.auditLog.append(
          "l2",
          "direct_agent_session_denied",
          this.deps.identityId,
          {
            agent_id: record.agent_id,
            identity_id: record.identity_id,
            operator_audit_id: itemId,
          },
        );
        return;
      }
      // The chat-service emits `direct_agent_session_open` itself with
      // the assigned session_id; this hub layer leaves the activity
      // entry shape to the chat-service so audit event payloads stay
      // co-located with the surface that owns them.
      await chat.openDirectAgentSession({
        agentId: record.agent_id,
        approvalInboxItemId: itemId,
        channelTemplateId,
        ...(expiresAtIsoOverride !== undefined
          ? { expiresAtIsoOverride }
          : {}),
      });
    });

    const result: HubDirectAgentSessionRequestResult = {
      agent_id: record.agent_id,
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "direct_agent_session_open",
    };
    if (expiresAtIsoOverride !== undefined) {
      result.requested_expires_at = expiresAtIsoOverride;
    }
    return result;
  }

  /**
   * Operator submit on a direct-agent chat session. The operator-chat-
   * service owns persistence + audit; the hub validates session
   * membership belongs to the correct identity at the routing layer.
   */
  async sendDirectAgentMessage(
    sessionId: string,
    body: string,
  ): Promise<DirectAgentSendResponse> {
    const chat = this.requireOperatorChat();
    const session = chat.getSession(sessionId);
    if (!session) {
      throw new HubNotFoundError(`chat session ${sessionId}`);
    }
    // Verify the session's bound agent belongs to this identity. The
    // chat-service is identity-scoped at construction so this is a
    // belt-and-suspenders check; defense in depth against future
    // multi-identity wiring drift.
    this.getAgent(session.agent_id);
    return chat.sendToAgent({ sessionId, body });
  }

  /**
   * Read the persisted direct-agent chat history for a wrapped agent.
   * Returns an empty array when no thread exists yet.
   */
  async getDirectAgentHistory(
    agentId: string,
  ): Promise<OperatorChatMessage[]> {
    const chat = this.requireOperatorChat();
    this.getAgent(agentId);
    return chat.getDirectAgentHistory(agentId);
  }

  /**
   * Operator-driven session close. Returns null when the session is
   * already closed or unknown. Emits `direct_agent_session_close`
   * through the chat-service.
   */
  async closeDirectAgentSession(
    sessionId: string,
  ): Promise<OperatorChatSession | null> {
    const chat = this.requireOperatorChat();
    return chat.closeDirectAgentSession(sessionId, "operator_close");
  }

  /**
   * Snapshot of in-memory active direct-agent sessions for this
   * fortress. Used by the dashboard to repaint the chat header on page
   * refresh and by the hub routes' GET /sessions endpoint.
   */
  listActiveDirectAgentSessions(): OperatorChatSession[] {
    if (!this.deps.operatorChat) return [];
    return this.deps.operatorChat.listActiveSessions();
  }
}

export {
  HubConflictError,
  HubCapabilityError,
  HubLocalOnlyError,
  HubNotFoundError,
  HubValidationError,
};
